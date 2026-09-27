#!/usr/bin/env python3
"""Exercise the local Ory browser forms and a PKCE authorization-code flow.

Only localhost public endpoints are used. Credentials, response bodies, and
tokens are saved with private permissions beneath deploy/local/.state/.
"""

import argparse
import base64
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import sys
import time
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)


ISSUER = "http://localhost:4444/"
KRATOS = "http://localhost:4433"
UI = "http://localhost:4455"
CALLBACK = "http://localhost:43110/callback"
SCOPES = {"openid", "offline_access", "fleet-recall"}
ALLOWED_ORIGINS = {ISSUER.rstrip("/"), KRATOS, UI}


class SmokeFailure(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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
    def __init__(self, directory):
        self.directory = directory
        self.cookies = http.cookiejar.CookieJar()
        self.opener = build_opener(
            ProxyHandler({}), HTTPCookieProcessor(self.cookies), NoRedirect()
        )
        self.response_number = 0

    def request(self, url, data=None, headers=None):
        parsed = urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in ALLOWED_ORIGINS:
            raise SmokeFailure("Refusing a request outside the local public endpoints")
        request = Request(url, data=data, headers=headers or {})
        try:
            with self.opener.open(request, timeout=15) as response:
                return self.record_response(url, response)
        except HTTPError as error:
            with error:
                return self.record_response(url, error)

    def record_response(self, url, response):
        body = response.read().decode("utf-8")
        self.response_number += 1
        private_json(
            self.directory / f"response-{self.response_number:03d}.json",
            {"url": url, "status": response.status, "body": body},
        )
        return response.status, response.headers, body

    def follow(self, url, data=None, headers=None):
        for _ in range(20):
            if urlsplit(url)._replace(query="", fragment="").geturl() == CALLBACK:
                return url, ""
            status, response_headers, body = self.request(url, data, headers)
            if status in {301, 302, 303, 307, 308}:
                location = response_headers.get("Location")
                if not location:
                    raise SmokeFailure("Redirect had no Location header")
                url = urljoin(url, location)
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
            if item.get("type") in {"checkbox", "radio"}:
                if not (scopes and name == "grant_scope") and "checked" not in item:
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
        return self.follow(
            action,
            urlencode(fields).encode(),
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": f"{origin.scheme}://{origin.netloc}",
                "Referer": page_url,
            },
        )


def private_json(path, value):
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")
    path.chmod(0o600)


def parse_json(body):
    try:
        return json.loads(body)
    except json.JSONDecodeError as error:
        raise SmokeFailure("Public endpoint returned invalid JSON") from error


def wait_ready(timeout):
    opener = build_opener(ProxyHandler({}))
    endpoints = [
        ISSUER + ".well-known/openid-configuration",
        KRATOS + "/health/ready",
        UI + "/health/ready",
    ]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready = True
        for url in endpoints:
            try:
                with opener.open(url, timeout=3) as response:
                    ready = ready and response.status == 200
            except (HTTPError, URLError, TimeoutError, OSError):
                ready = False
                break
        if ready:
            return
        time.sleep(min(5, max(0, deadline - time.monotonic())))
    raise SmokeFailure("Ory public endpoints did not become ready before the deadline")


def run(directory):
    account = {
        "email": f"oauth-smoke-{secrets.token_hex(8)}@example.test",
        "password": secrets.token_urlsafe(36),
    }
    private_json(directory / "account.json", account)
    registration_dir = directory / "registration"
    registration_dir.mkdir(mode=0o700)
    registration = Browser(registration_dir)
    url, html = registration.follow(UI + "/registration")
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
    status, _, whoami = registration.request(KRATOS + "/sessions/whoami")
    if status != 200:
        raise SmokeFailure("Registration did not establish a browser session")
    identity_id = parse_json(whoami)["identity"]["id"]
    print("PASS public browser registration and session", flush=True)

    oauth_dir = directory / "oauth"
    oauth_dir.mkdir(mode=0o700)
    browser = Browser(oauth_dir)  # New cookie jar forces a real password login.
    status, _, discovery_body = browser.request(ISSUER + ".well-known/openid-configuration")
    discovery = parse_json(discovery_body)
    if status != 200 or discovery.get("registration_endpoint") != ISSUER + "oauth2/register":
        raise SmokeFailure("Discovery did not advertise the public registration endpoint")
    if not SCOPES <= set(discovery.get("scopes_supported", [])):
        raise SmokeFailure("Discovery did not advertise all expected scopes")
    status, _, client_body = browser.request(
        discovery["registration_endpoint"],
        json.dumps({
            "client_name": "Fleet Recall headless browser smoke",
            "redirect_uris": [CALLBACK],
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
    url, html = browser.follow(ISSUER + "oauth2/auth?" + urlencode({
        "client_id": client["client_id"], "response_type": "code",
        "scope": " ".join(sorted(SCOPES)), "redirect_uri": CALLBACK,
        "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
        "resource": "http://localhost:8080/mcp",
    }))
    url, html = browser.submit(
        url, html, {"identifier", "password", "csrf_token"},
        {"identifier": account["email"], "password": account["password"]},
    )
    if urlsplit(url).path != "/consent":
        raise SmokeFailure("Password login did not reach the public consent UI")
    print("PASS public password login with OAuth challenge", flush=True)
    callback_url, _ = browser.submit(
        url, html, {"consent_challenge", "consent_action", "_csrf"}, scopes=True,
    )
    query = parse_qs(urlsplit(callback_url).query)
    if query.get("state") != [state] or len(query.get("code", [])) != 1:
        raise SmokeFailure("OAuth callback lacked the expected state and authorization code")
    print("PASS public consent form and OAuth callback state", flush=True)
    status, _, token_body = browser.request(
        ISSUER + "oauth2/token",
        urlencode({
            "grant_type": "authorization_code", "client_id": client["client_id"],
            "code": query["code"][0], "redirect_uri": CALLBACK,
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
    if claims.get("iss") != ISSUER or claims.get("sub") != identity_id:
        raise SmokeFailure("Access token issuer or subject mismatch")
    if set(scope) != SCOPES or claims.get("exp", 0) <= time.time():
        raise SmokeFailure("Access token scopes or expiration mismatch")
    if id_claims.get("nonce") != nonce or id_claims.get("sub") != identity_id:
        raise SmokeFailure("ID token nonce or subject mismatch")
    private_json(directory / "result.json", {
        "passed": True, "identity_id": identity_id, "client_id": client["client_id"],
        "issuer": claims["iss"], "scopes": sorted(scope),
        "access_token_audience": claims.get("aud"), "expires_at": claims["exp"],
    })
    print("PASS PKCE token exchange, JWT claims, ID nonce, and refresh token issuance", flush=True)


def jwt_payload(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise SmokeFailure("Expected a JWT")
    return parse_json(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wait-seconds", type=int, default=600)
    args = parser.parse_args()
    os.umask(0o077)
    directory = Path(__file__).resolve().parents[1] / ".state" / "oauth-smoke" / (
        time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
    )
    directory.mkdir(parents=True, mode=0o700)
    print(f"Protected smoke artifacts: {directory}", flush=True)
    try:
        wait_ready(args.wait_seconds)
        run(directory)
    except (SmokeFailure, HTTPError, URLError, OSError, ValueError, KeyError) as error:
        private_json(directory / "failure.json", {"type": type(error).__name__, "detail": str(error)})
        detail = str(error) if isinstance(error, SmokeFailure) else type(error).__name__
        print(f"FAIL {detail}; diagnostic responses saved in protected artifacts", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
