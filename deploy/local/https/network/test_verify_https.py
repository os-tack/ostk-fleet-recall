"""Offline verifier tests, including real TLS identity and trust failures."""

import http.server
import importlib.util
import ssl
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location("verify_https", ROOT / "deploy/local/bin/verify-https.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)
FIXTURES = ROOT / "tests/fixtures/tls"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://unrelated.invalid/private")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *_args):
        pass


class HttpsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(FIXTURES / "server-first.pem", FIXTURES / "server-first-key.pem")
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_tls_verifies_sni_while_dialing_explicit_ip(self):
        client = VERIFY.Client(VERIFY.tls_context(FIXTURES / "ca-first.pem"), "127.0.0.1")
        response = client.request(f"https://localhost:{self.port}/")
        self.assertEqual(VERIFY.json_object(response, "fixture"), {"ok": True})
        with self.assertRaises(ssl.SSLCertVerificationError):
            client.request(f"https://wrong-name.invalid:{self.port}/")

    def test_wrong_ca_is_rejected(self):
        client = VERIFY.Client(VERIFY.tls_context(FIXTURES / "ca-second.pem"), "127.0.0.1")
        with self.assertRaises(ssl.SSLCertVerificationError):
            client.request(f"https://localhost:{self.port}/")

    def test_redirect_is_returned_without_following(self):
        client = VERIFY.Client(VERIFY.tls_context(FIXTURES / "ca-first.pem"), "127.0.0.1")
        response = client.request(f"https://localhost:{self.port}/redirect")
        self.assertEqual(response[0], 302)
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.json_object(response, "discovery")

    def test_response_bound_applies_before_json_decode(self):
        previous = VERIFY.MAX_RESPONSE
        VERIFY.MAX_RESPONSE = 3
        try:
            client = VERIFY.Client(VERIFY.tls_context(FIXTURES / "ca-first.pem"), "127.0.0.1")
            with self.assertRaises(VERIFY.VerificationError):
                client.request(f"https://localhost:{self.port}/")
        finally:
            VERIFY.MAX_RESPONSE = previous

    def test_challenge_must_preserve_identity_and_cache_controls(self):
        metadata = "https://recall.fleet.test:8443/.well-known/oauth-protected-resource/mcp"
        headers = {"www-authenticate": f'Bearer resource_metadata="{metadata}"',
                   "cache-control": "no-store", "x-content-type-options": "nosniff"}
        VERIFY.check_auth_response((401, headers, b"ignored private body"), metadata, "fixture")
        for changed in ({"location": "https://login.fleet.test/"},
                        {"www-authenticate": 'Bearer resource_metadata="http://localhost/mcp"'},
                        {"cache-control": "public"}):
            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.check_auth_response((401, dict(headers, **changed), b""), metadata, "fixture")

    def test_url_and_ca_input_boundaries(self):
        for url in ("http://recall.fleet.test/mcp", "https://user:secret@recall.fleet.test/mcp",
                    "https://recall.fleet.test/mcp#fragment", "https://recall.fleet.test/mcp?token=secret"):
            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.origin(url)
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.tls_context(FIXTURES / "server-first-key.pem")


if __name__ == "__main__":
    unittest.main()
