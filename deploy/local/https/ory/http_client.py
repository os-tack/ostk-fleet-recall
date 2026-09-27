"""Shared bounded TLS/origin policy for the local Ory operator helpers."""

import importlib.util
import ipaddress
import os
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, build_opener

# Reuse the same PEM-only, bounded, additive trust loader as the launcher proof.
_path = Path(__file__).resolve().parents[2] / "bin" / "sandbox-smoke.py"
_spec = importlib.util.spec_from_file_location("fleet_sandbox_tls", _path)
_sandbox = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_sandbox)
SmokeFailure = _sandbox.SmokeFailure
NoRedirect = _sandbox.NoRedirect
client_tls = _sandbox.client_tls
private_read = _sandbox.private_read


def checked_url(value, *, root=False, callback=False):
    if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise SmokeFailure("Endpoint URL contains whitespace or control characters")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise SmokeFailure("Endpoint has an invalid port") from error
    if (not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.fragment or parsed.query or parsed.scheme not in {"http", "https"}
            or (port is not None and not 1 <= port <= 65535)):
        raise SmokeFailure("Endpoint must be an HTTP(S) URL without credentials, query, or fragment")
    loopback = parsed.hostname == "localhost"
    with suppress(ValueError):
        loopback = loopback or ipaddress.ip_address(parsed.hostname).is_loopback
    if parsed.scheme == "http" and not loopback:
        raise SmokeFailure("Plain HTTP is permitted only for literal loopback endpoints")
    if callback and (not loopback or parsed.scheme != "http" or not port):
        raise SmokeFailure("Native callback must use HTTP on a loopback host and explicit port")
    if root and parsed.path not in {"", "/"}:
        raise SmokeFailure("This Ory profile requires origins without a path prefix")
    return value


def origin(value):
    parsed = urlsplit(value)
    return f"{parsed.scheme}://{parsed.netloc}"


class Profile:
    def __init__(self, name="loopback", *, issuer=None, kratos=None, ui=None,
                 resource=None, callback=None, ca_path=None):
        if name not in {"loopback", "https"}:
            raise SmokeFailure("Unknown Ory profile")
        defaults = ({"issuer": "https://auth.fleet.test:8443/",
                     "kratos": "https://login.fleet.test:8443",
                     "ui": "https://login.fleet.test:8443",
                     "resource": "https://recall.fleet.test:8443/mcp"}
                    if name == "https" else
                    {"issuer": "http://localhost:4444/", "kratos": "http://localhost:4433",
                     "ui": "http://localhost:4455", "resource": "http://localhost:8080/mcp"})
        self.issuer = checked_url(issuer or defaults["issuer"], root=True).rstrip("/") + "/"
        self.kratos = checked_url(kratos or defaults["kratos"], root=True).rstrip("/")
        self.ui = checked_url(ui or defaults["ui"], root=True).rstrip("/")
        self.resource = checked_url(resource or defaults["resource"])
        self.callback = checked_url(callback or "http://localhost:43110/callback", callback=True)
        self.ca_path = ca_path
        urls = (self.issuer, self.kratos, self.ui, self.resource)
        if name == "https" and any(urlsplit(value).scheme != "https" for value in urls):
            raise SmokeFailure("The HTTPS profile requires HTTPS for every public service")
        self.secure = all(urlsplit(value).scheme == "https" for value in urls)
        self.allowed_origins = {origin(value) for value in (self.issuer, self.kratos, self.ui)}

    @classmethod
    def from_args(cls, args):
        return cls(args.profile, issuer=args.issuer_url, kratos=args.kratos_url,
                   ui=args.ui_url, resource=args.resource_url, callback=args.callback_url,
                   ca_path=args.ca_path)

    def opener(self, *handlers):
        return build_opener(ProxyHandler({}), NoRedirect(),
                            HTTPSHandler(context=client_tls(self.ca_path)), *handlers)

    def check_request(self, url):
        # Requests may have query strings, unlike configured origins.
        if any(ord(c) <= 32 or ord(c) == 127 for c in url):
            raise SmokeFailure("Request URL contains whitespace or control characters")
        parsed = urlsplit(url)
        checked_url(parsed._replace(query="").geturl())
        if origin(url) not in self.allowed_origins:
            raise SmokeFailure("Refusing a request outside the configured public origins")


def add_arguments(parser):
    parser.add_argument("--profile", choices=("loopback", "https"), default="loopback")
    parser.add_argument("--issuer-url")
    parser.add_argument("--kratos-url")
    parser.add_argument("--ui-url")
    parser.add_argument("--resource-url")
    parser.add_argument("--callback-url")
    parser.add_argument("--ca-path", type=Path, default=os.environ.get("FLEET_RECALL_CA_PATH"))
