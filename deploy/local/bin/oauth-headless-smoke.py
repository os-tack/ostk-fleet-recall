#!/usr/bin/env python3
"""Exercise the local Ory browser forms and a PKCE authorization-code flow.

Use --profile https --ca-path PATH for the canonical HTTPS deployment. Add
--account-file PATH --expected-subject UUID to prove an existing identity was
preserved. Credentials and responses stay in private local state.
"""

import argparse
import base64
import hashlib
import http.cookiejar
import importlib.util
import json
import os
import secrets
import sys
import time
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from urllib.request import HTTPCookieProcessor, Request

_helper = Path(__file__).resolve().parents[1] / "https" / "ory" / "http_client.py"
_spec = importlib.util.spec_from_file_location("fleet_ory_http", _helper)
_http = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_http)
SmokeFailure = _http.SmokeFailure
Profile = _http.Profile
SCOPES = {"openid", "offline_access", "fleet-recall"}


class Forms(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.forms = []
        self.current = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = {"attrs": attrs, "controls": []}
            self.forms.append(self.current)
        elif self.current is not None and tag in {"input", "button"}:
            if attrs.get("name") and "disabled" not in attrs:
                self.current["controls"].append(attrs)

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


class Browser:
    def __init__(self, directory, profile=None):
        self.directory = directory
        self.profile = profile or Profile()
        self.cookies = http.cookiejar.CookieJar()
        self.opener = self.profile.opener(HTTPCookieProcessor(self.cookies))
        self.response_number = 0
        self.cookie_attributes = []

    def request(self, url, data=None, headers=None):
        self.profile.check_request(url)
        request = Request(url, data=data, headers=headers or {})
        try:
            with self.opener.open(request, timeout=15) as response:
                return self.record_response(url, response)
        except HTTPError as error:
            with error:
                return self.record_response(url, error)

    def record_response(self, url, response):
        body = response.read(1048577)
        if len(body) > 1048576:
            raise SmokeFailure("Public response exceeds 1 MiB")
        body = body.decode("utf-8")
        attributes = cookie_attributes(response.headers.get_all("Set-Cookie", []))
        self.cookie_attributes.extend(attributes)
        self.response_number += 1
        private_json(
            self.directory / f"response-{self.response_number:03d}.json",
            {"url": url, "status": response.status, "body": body,
             "location": response.headers.get("Location"),
             "cookie_attributes": attributes},
        )
        return response.status, response.headers, body

    def follow(self, url, data=None, headers=None):
        for _ in range(20):
            if urlsplit(url)._replace(query="").geturl() == self.profile.callback:
                return url, ""
            status, response_headers, body = self.request(url, data, headers)
            if status in {301, 302, 303, 307, 308}:
                location = response_headers.get("Location")
                if not location:
                    raise SmokeFailure("Redirect had no Location header")
                next_url = urljoin(url, location)
                if data is not None and status in {307, 308} and _http.origin(url) != _http.origin(next_url):
                    raise SmokeFailure("Refusing a cross-origin redirect that replays a POST")
                url = next_url
                if status not in {307, 308}:
                    data, headers = None, None
                continue
            if status != 200:
                raise SmokeFailure(
                    f"Public endpoint {urlsplit(url).path} returned HTTP {status}"
                )
            return url, body
        raise SmokeFailure("Too many browser redirects")

    def submit(self, page_url, html, required, overrides=None, scopes=False):
        return self.follow(*self.form_submission(page_url, html, required, overrides, scopes))

    def form_submission(self, page_url, html, required, overrides=None, scopes=False):
        matches = [
            form for form in Forms(html).forms
            if required <= {item["name"] for item in form["controls"]}
        ]
        if len(matches) != 1:
            raise SmokeFailure(f"Expected one form containing {sorted(required)}")
        form = matches[0]
        if form["attrs"].get("method", "get").lower() != "post":
            raise SmokeFailure("Expected a POST form")
        fields = []
        for item in form["controls"]:
            name, value = item["name"], item.get("value", "")
            if name in (overrides or {}):
                continue
            if (item.get("type") in {"checkbox", "radio"}
                    and not (scopes and name == "grant_scope") and "checked" not in item):
                continue
            if name == "consent_action" and value != "accept":
                continue
            fields.append((name, value))
        fields.extend((overrides or {}).items())
        if scopes:
            granted = {value for name, value in fields if name == "grant_scope"}
            if granted != SCOPES:
                raise SmokeFailure("Consent form did not offer all expected scopes")
        action = urljoin(page_url, form["attrs"].get("action", ""))
        origin = urlsplit(page_url)
        return (
            action,
            urlencode(fields).encode(),
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": f"{origin.scheme}://{origin.netloc}",
                "Referer": page_url,
            },
        )


def cookie_attributes(headers):
    """Record attributes only: cookie values never appear in the proof summary."""
    result = []
    for header in headers:
        cookies = SimpleCookie()
        cookies.load(header)
        if not cookies:
            raise SmokeFailure("Server returned an unparseable cookie")
        for name, cookie in cookies.items():
            result.append({"name": name, "secure": bool(cookie["secure"]),
                           "http_only": bool(cookie["httponly"]),
                           "domain": cookie["domain"], "path": cookie["path"],
                           "same_site": cookie["samesite"],
                           "deleted": cookie["max-age"] == "0"})
    return result


def verify_secure_cookies(attributes):
    cookies = [cookie for cookie in attributes if not cookie["deleted"]]
    names = {cookie["name"] for cookie in cookies}
    if not {"ory_kratos_session", "__Host-fleet-recall-csrf"} <= names:
        raise SmokeFailure("HTTPS flow did not establish the expected session and UI CSRF cookies")
    for cookie in cookies:
        if (not cookie["secure"] or not cookie["http_only"] or cookie["domain"]
                or cookie["path"] != "/" or cookie["same_site"].lower() != "lax"):
            raise SmokeFailure("HTTPS flow issued a cookie without the required Secure/HttpOnly/host-only/Lax attributes")


def logout_browser(browser, profile):
    """Clear this Kratos browser session; OAuth token revocation is separate."""
    status, _, body = browser.request(profile.kratos + "/self-service/logout/browser",
                                      headers={"Accept": "application/json"})
    flow = parse_json(body)
    if status != 200 or not isinstance(flow, dict) or not isinstance(flow.get("logout_url"), str):
        raise SmokeFailure("Kratos did not create a browser logout flow")
    url = flow["logout_url"]
    browser.profile.check_request(url)
    parsed = urlsplit(url)
    if (_http.origin(url) != profile.kratos or parsed.path != "/self-service/logout"
            or parse_qs(parsed.query) != {"token": [flow.get("logout_token")]}):
        raise SmokeFailure("Logout URL did not match the canonical browser session endpoint")
    returned, _ = browser.follow(url)
    if _http.origin(returned) != profile.ui or urlsplit(returned).path != "/login":
        raise SmokeFailure("Logout did not return to the configured login UI")
    status, _, _ = browser.request(profile.kratos + "/sessions/whoami",
                                    headers={"Accept": "application/json"})
    if status != 401:
        raise SmokeFailure("Kratos browser session remained active after logout")
    print("PASS browser logout, canonical login redirect, and session whoami401", flush=True)


def private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def parse_json(body):
    try:
        return json.loads(body)
    except json.JSONDecodeError as error:
        raise SmokeFailure("Public endpoint returned invalid JSON") from error


def wait_ready(timeout, profile=None):
    profile = profile or Profile()
    opener = profile.opener()
    endpoints = [
        (profile.issuer + ".well-known/openid-configuration", {200}),
        (profile.kratos + "/sessions/whoami", {200, 401}),
        (profile.ui + "/theme.css", {200}),
    ]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready = True
        for url, statuses in endpoints:
            try:
                with opener.open(url, timeout=3) as response:
                    ready = ready and response.status in statuses
                    if url == profile.issuer + ".well-known/openid-configuration":
                        discovery = response.read(262145)
                        ready = ready and len(discovery) <= 262144
                        ready = ready and parse_json(discovery).get("issuer") == profile.issuer
            except HTTPError as error:
                with error:
                    ready = ready and error.code in statuses
            except (SmokeFailure, URLError, TimeoutError, OSError, ValueError):
                ready = False
                break
        if ready:
            return
        time.sleep(min(5, max(0, deadline - time.monotonic())))
    raise SmokeFailure("Ory public endpoints did not become ready before the deadline")


def run(directory, profile=None, account_file=None, expected_subject=None):
    profile = profile or Profile()
    if account_file is not None and not expected_subject:
        raise SmokeFailure("An existing account requires --expected-subject")
    account = parse_json(_http.private_read(account_file)) if account_file else {
        "email": f"oauth-smoke-{secrets.token_hex(8)}@example.test",
        "password": secrets.token_urlsafe(36),
    }
    if not isinstance(account, dict) or any(
            not isinstance(account.get(key), str) or not 1 <= len(account[key]) <= 1024
            for key in ("email", "password")):
        raise SmokeFailure("Account file requires bounded email and password strings")
    private_json(directory / "account.json", account)
    identity_id = expected_subject
    if account_file is None:
        identity_id = register_account(directory, profile, account)

    oauth_dir = directory / "oauth"
    oauth_dir.mkdir(mode=0o700)
    browser = Browser(oauth_dir, profile)  # A new jar forces a real password login.
    return authorize(directory, profile, browser, account, identity_id)


def register_account(directory, profile, account):
    registration_dir = directory / "registration"
    registration_dir.mkdir(mode=0o700)
    registration = Browser(registration_dir, profile)
    url, html = registration.follow(profile.ui + "/registration")
    # Current Kratos versions ask for traits before showing credential setup.
    if not any(
        item["name"] == "password"
        for form in Forms(html).forms for item in form["controls"]
    ):
        url, html = registration.submit(
            url, html, {"traits.email", "csrf_token"},
            {"traits.email": account["email"]},
        )
    registration.submit(
        url, html, {"password", "csrf_token"},
        {"traits.email": account["email"], "password": account["password"]},
    )
    status, _, whoami = registration.request(profile.kratos + "/sessions/whoami")
    if status != 200:
        raise SmokeFailure("Registration did not establish a browser session")
    identity_id = parse_json(whoami)["identity"]["id"]
    print("PASS public browser registration and session", flush=True)
    return identity_id


def authorize(directory, profile, browser, account, identity_id):
    status, _, discovery_body = browser.request(profile.issuer + ".well-known/openid-configuration")
    discovery = parse_json(discovery_body)
    expected = {"issuer": profile.issuer, "registration_endpoint": profile.issuer + "oauth2/register",
                "authorization_endpoint": profile.issuer + "oauth2/auth",
                "token_endpoint": profile.issuer + "oauth2/token",
                "jwks_uri": profile.issuer + ".well-known/jwks.json"}
    if status != 200 or any(discovery.get(key) != value for key, value in expected.items()):
        raise SmokeFailure("Discovery did not advertise the expected canonical public endpoints")
    if not SCOPES.issubset(discovery.get("scopes_supported", [])):
        raise SmokeFailure("Discovery did not advertise all expected scopes")
    status, _, client_body = browser.request(
        discovery["registration_endpoint"],
        json.dumps({
            "client_name": "Fleet Recall headless browser smoke",
            "redirect_uris": [profile.callback],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": " ".join(sorted(SCOPES)),
        }).encode(),
        {"Content-Type": "application/json"},
    )
    if status != 201:
        raise SmokeFailure(f"Dynamic registration returned HTTP {status}")
    client = parse_json(client_body)
    private_json(directory / "client.json", client)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    url, html = browser.follow(profile.issuer + "oauth2/auth?" + urlencode({
        "client_id": client["client_id"], "response_type": "code",
        "scope": " ".join(sorted(SCOPES)), "redirect_uri": profile.callback,
        "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
        "resource": profile.resource,
    }))
    # Kratos exposes an explicit CSRF error; the pinned UI's error renderer
    # masks its own bad-consent-CSRF failure as an indistinguishable HTTP 500.
    action, fields, headers = browser.form_submission(
        url, html, {"identifier", "password", "csrf_token"},
        {"identifier": account["email"], "password": account["password"],
         "csrf_token": "invalid-smoke-csrf"})
    status, _, rejected = browser.request(action, fields, {**headers, "Accept": "application/json"})
    if status != 403 or parse_json(rejected).get("error", {}).get("id") != "security_csrf_violation":
        raise SmokeFailure("Password login did not explicitly reject an invalid CSRF token")
    url, html = browser.submit(
        url, html, {"identifier", "password", "csrf_token"},
        {"identifier": account["email"], "password": account["password"]},
    )
    if urlsplit(url).path != "/consent":
        raise SmokeFailure("Password login did not reach the public consent UI")
    status, _, whoami = browser.request(profile.kratos + "/sessions/whoami")
    if status != 200 or parse_json(whoami)["identity"]["id"] != identity_id:
        raise SmokeFailure("Password login changed the expected identity subject")
    print("PASS public password login with OAuth challenge", flush=True)
    callback_url, _ = browser.submit(
        url, html, {"consent_challenge", "consent_action", "_csrf"}, scopes=True,
    )
    query = parse_qs(urlsplit(callback_url).query)
    if query.get("state") != [state] or len(query.get("code", [])) != 1:
        raise SmokeFailure("OAuth callback lacked the expected state and authorization code")
    if "iss" in query and query["iss"] != [profile.issuer]:
        raise SmokeFailure("OAuth callback contained an unexpected issuer")
    print("PASS public consent form and OAuth callback state", flush=True)
    status, _, token_body = browser.request(
        profile.issuer + "oauth2/token",
        urlencode({
            "grant_type": "authorization_code", "client_id": client["client_id"],
            "code": query["code"][0], "redirect_uri": profile.callback,
            "code_verifier": verifier,
        }).encode(),
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status != 200:
        raise SmokeFailure(f"PKCE token exchange returned HTTP {status}")
    token = parse_json(token_body)
    private_json(directory / "token.json", token)
    if not token.get("refresh_token") or not token.get("id_token"):
        raise SmokeFailure("Token response omitted refresh or ID token")
    claims = jwt_payload(token["access_token"])
    id_claims = jwt_payload(token["id_token"])
    scope = claims.get("scope", claims.get("scp", []))
    scope = scope.split() if isinstance(scope, str) else scope
    if claims.get("iss") != profile.issuer or claims.get("sub") != identity_id:
        raise SmokeFailure("Access token issuer or subject mismatch")
    if set(scope) != SCOPES or claims.get("exp", 0) <= time.time():
        raise SmokeFailure("Access token scopes or expiration mismatch")
    id_audience = id_claims.get("aud")
    id_audience = [id_audience] if isinstance(id_audience, str) else id_audience
    if (id_claims.get("nonce") != nonce or id_claims.get("sub") != identity_id
            or id_claims.get("iss") != profile.issuer or not isinstance(id_audience, list)
            or client["client_id"] not in id_audience or id_claims.get("exp", 0) <= time.time()):
        raise SmokeFailure("ID token nonce, subject, issuer, audience, or expiration mismatch")
    if profile.secure:
        verify_secure_cookies(browser.cookie_attributes)
        print("PASS Secure/HttpOnly/host-only/Lax cookies and explicit login CSRF rejection", flush=True)
    logout_browser(browser, profile)
    if profile.secure:
        verify_secure_cookies(browser.cookie_attributes)
    private_json(directory / "result.json", {
        "passed": True, "identity_id": identity_id, "client_id": client["client_id"],
        "issuer": claims["iss"], "scopes": sorted(scope),
        "access_token_audience": claims.get("aud"), "expires_at": claims["exp"],
        "resource": profile.resource, "secure_cookies": profile.secure,
        "csrf_rejected": True, "cookie_attributes": browser.cookie_attributes,
        "browser_session_logged_out": True,
    })
    print("PASS PKCE token exchange, claim consistency, ID nonce, and refresh token issuance", flush=True)


def jwt_payload(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise SmokeFailure("Expected a JWT")
    return parse_json(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    _http.add_arguments(parser)
    parser.add_argument("--wait-seconds", type=int, default=600)
    parser.add_argument("--state", type=Path, default=os.environ.get("FLEET_LOCAL_STATE"))
    parser.add_argument("--account-file", type=Path)
    parser.add_argument("--expected-subject")
    args = parser.parse_args()
    os.umask(0o077)
    state = args.state or Path(__file__).resolve().parents[1] / ".state"
    directory = state / "oauth-smoke" / (
        time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
    )
    directory.mkdir(parents=True, mode=0o700)
    print(f"Protected smoke artifacts: {directory}", flush=True)
    try:
        profile = Profile.from_args(args)
        wait_ready(args.wait_seconds, profile)
        run(directory, profile, args.account_file, args.expected_subject)
    except (SmokeFailure, HTTPError, URLError, OSError, ValueError, KeyError) as error:
        private_json(directory / "failure.json", {"type": type(error).__name__, "detail": str(error)})
        detail = str(error) if isinstance(error, SmokeFailure) else type(error).__name__
        print(f"FAIL {detail}; diagnostic responses saved in protected artifacts", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
