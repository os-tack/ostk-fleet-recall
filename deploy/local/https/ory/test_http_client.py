"""Offline tests for credential transport and cookie proof boundaries."""

import importlib.util
import io
import json
import ssl
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError

LOCAL = Path(__file__).resolve().parents[2]
REPO = LOCAL.parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


smoke = load("ory_smoke_test", LOCAL / "bin" / "oauth-headless-smoke.py")
http = smoke._http


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(302 if self.path == "/redirect" else 200)
        if self.path == "/redirect":
            self.send_header("Location", "https://outside.invalid/credentials")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(307)
        self.send_header("Location", "https://outside.invalid/credentials")
        self.send_header("Content-Length", "0")
        self.end_headers()


class HttpPolicyTests(unittest.TestCase):
    def test_profiles_keep_legacy_api_and_require_https_for_secure_profile(self):
        self.assertEqual(http.Profile().issuer, "http://localhost:4444/")
        self.assertEqual(http.Profile("https").issuer, "https://auth.fleet.test:8443/")
        for value in ("http://auth.fleet.test/", "https://user:password@auth.fleet.test/",
                      "https://auth.fleet.test/?token=x", "https://auth.fleet.test/#x",
                      "https://auth.fleet.test/path", "https://auth.fleet.test:0/",
                      "https://auth.fleet.test/\n"):
            with self.subTest(value=value), self.assertRaises(http.SmokeFailure):
                http.Profile("https", issuer=value)
        with self.assertRaises(http.SmokeFailure):
            http.Profile("https", issuer="http://localhost:4444/")

    def test_request_origin_guard_rejects_redirect_or_userinfo_confusion(self):
        profile = http.Profile("https")
        profile.check_request(profile.ui + "/login?flow=abc")
        for value in ("https://outside.invalid/", "https://user@login.fleet.test:8443/",
                      profile.ui + "/login#fragment", profile.ui + "/login?x=\nsecret"):
            with self.subTest(value=value), self.assertRaises(http.SmokeFailure):
                profile.check_request(value)
        for callback in ("https://outside.invalid/callback", "http://localhost/callback",
                         "http://localhost:43110/callback?code=x"):
            with self.subTest(value=callback), self.assertRaises(http.SmokeFailure):
                http.Profile(callback=callback)

    def test_secure_cookie_proof_rejects_each_missing_attribute_and_omits_values(self):
        headers = [f"{name}=secret-value; Path=/; Secure; HttpOnly; SameSite=Lax" for name in
                   ("ory_kratos_session", "__Host-fleet-recall-csrf")]
        attributes = smoke.cookie_attributes(headers)
        smoke.verify_secure_cookies(attributes)
        self.assertNotIn("secret-value", str(attributes))
        for key, value in (("secure", False), ("http_only", False), ("domain", ".fleet.test"),
                           ("path", "/login"), ("same_site", "None")):
            changed = [dict(item) for item in attributes]
            changed[0][key] = value
            with self.subTest(key=key), self.assertRaises(http.SmokeFailure):
                smoke.verify_secure_cookies(changed)
        with self.assertRaises(http.SmokeFailure):
            smoke.verify_secure_cookies(attributes[:1])

    def test_real_tls_requires_ca_and_redirects_never_replay_credentials(self):
        fixture = REPO / "tests" / "fixtures" / "tls"
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(fixture / "server-first.pem", fixture / "server-first-key.pem")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"https://localhost:{server.server_port}"
        try:
            with self.assertRaises(URLError):
                http.Profile(issuer=url).opener().open(url, timeout=3)
            profile = http.Profile(issuer=url, ca_path=fixture / "ca-first.pem")
            with profile.opener().open(url, timeout=3) as response:
                self.assertEqual(response.read(), b"ok")
            with self.assertRaises(HTTPError) as caught:
                profile.opener().open(url + "/redirect", timeout=3)
            caught.exception.close()
            self.assertEqual(caught.exception.code, 302)
            with tempfile.TemporaryDirectory(prefix="ory-http-test-") as directory:
                browser = smoke.Browser(Path(directory), profile)
                with self.assertRaisesRegex(http.SmokeFailure, "cross-origin"):
                    browser.follow(url, b"password=do-not-forward")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_existing_identity_requires_a_pre_cutover_subject(self):
        with (tempfile.TemporaryDirectory(prefix="ory-identity-test-") as directory,
              self.assertRaisesRegex(http.SmokeFailure, "expected-subject")):
            smoke.run(Path(directory), http.Profile("https"), Path("unused-account.json"))

    def test_browser_logout_requires_canonical_session_url_and_actual_session_removal(self):
        profile = http.Profile("https")

        class Browser:
            def __init__(self):
                self.profile = profile
                self.logout_url = profile.kratos + "/self-service/logout?token=fixture"
                self.whoami = 401
                self.followed = False

            def request(self, url, **kwargs):
                if url.endswith("/logout/browser"):
                    return 200, {}, json.dumps({"logout_url": self.logout_url, "logout_token": "fixture"})
                return self.whoami, {}, "{}"

            def follow(self, url):
                self.followed = True
                return profile.ui + "/login?flow=fixture", "login"

        browser = Browser()
        with redirect_stdout(io.StringIO()):
            smoke.logout_browser(browser, profile)
        for url in (profile.issuer + "self-service/logout?token=fixture",
                    profile.kratos + "/self-service/logout?token=wrong",
                    "https://outside.invalid/self-service/logout?token=fixture"):
            browser = Browser()
            browser.logout_url = url
            with self.subTest(url=url), self.assertRaises(smoke.SmokeFailure):
                smoke.logout_browser(browser, profile)
            self.assertFalse(browser.followed)
        browser = Browser()
        browser.whoami = 200
        with self.assertRaisesRegex(smoke.SmokeFailure, "remained active"):
            smoke.logout_browser(browser, profile)


if __name__ == "__main__":
    unittest.main()
