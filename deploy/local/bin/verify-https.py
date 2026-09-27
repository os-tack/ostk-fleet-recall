#!/usr/bin/env python3
"""Read-only HTTPS/identity checks. Never accepts or prints bearer credentials.

Authenticated OAuth, transcript and NetworkPolicy packet probes are separate
acceptance checks: a healthy listener or a policy object is not proof of either.
"""

import argparse
import http.client
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

MAX_RESPONSE = 1024 * 1024
MAX_CA = 256 * 1024
TIMEOUT = 15


class VerificationError(Exception):
    """A bounded check failed; response bodies are deliberately not reported."""


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def origin(url):
    parsed = urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname is not None,
            "canonical URLs must use HTTPS")
    require(not parsed.username and not parsed.password and not parsed.fragment
            and not parsed.query, "canonical URLs cannot carry credentials, query or fragment")
    require(not any(ord(char) < 33 for char in url), "invalid URL whitespace")
    return f"https://{parsed.netloc}"


def tls_context(ca_path):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_path:
        path = Path(ca_path)
        require(path.is_file() and not path.is_symlink(), "CA bundle must be a regular file")
        with path.open("rb") as source:
            data = source.read(MAX_CA + 1)
        require(0 < len(data) <= MAX_CA, "CA bundle must be 1..256 KiB")
        require(b"PRIVATE KEY" not in data, "CA bundle must not contain a private key")
        context.load_verify_locations(cadata=data.decode("ascii"))
    return context


class Client:
    def __init__(self, context, resolve_address=None):
        self.context = context
        self.resolve_address = resolve_address
        if resolve_address:
            ipaddress.ip_address(resolve_address)

    def request(self, url, method="GET", headers=None, body=None):
        origin(url)
        parsed = urlsplit(url)
        connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
                                                  timeout=TIMEOUT, context=self.context)
        try:
            if self.resolve_address:
                # The dial address changes; certificate identity, SNI and Host do not.
                raw = socket.create_connection((self.resolve_address, parsed.port or 443), TIMEOUT)
                try:
                    connection.sock = self.context.wrap_socket(raw, server_hostname=parsed.hostname)
                except Exception:
                    raw.close()
                    raise
            connection.request(method, parsed.path or "/", body=body, headers=headers or {})
            response = connection.getresponse()
            payload = response.read(MAX_RESPONSE + 1)
            require(len(payload) <= MAX_RESPONSE, "HTTP response exceeded 1 MiB")
            # No redirects, cookies, proxy settings or credentials are retained.
            return response.status, {key.lower(): value for key, value in response.getheaders()}, payload
        finally:
            connection.close()


def json_object(response, label):
    status, headers, body = response
    require(status == 200, f"{label}: expected HTTP 200, received {status}")
    require(headers.get("content-type", "").split(";", 1)[0].strip() == "application/json",
            f"{label}: expected JSON content type")
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError) as error:
        raise VerificationError(f"{label}: invalid JSON") from error
    require(isinstance(value, dict), f"{label}: expected a JSON object")
    return value


def check_auth_response(response, metadata_url, label):
    status, headers, _ = response
    require(status == 401, f"{label}: expected HTTP 401, received {status}")
    require("location" not in headers, f"{label}: authentication must not redirect")
    challenge = headers.get("www-authenticate", "")
    require(challenge.startswith("Bearer ") and f'resource_metadata="{metadata_url}"' in challenge,
            f"{label}: canonical Bearer challenge was not preserved")
    require("no-store" in headers.get("cache-control", "").lower(),
            f"{label}: authenticated responses must not be cached")
    require(headers.get("x-content-type-options") == "nosniff", f"{label}: missing nosniff")


def verify_public(client, resource, issuer, login):
    resource_origin, issuer_origin, login_origin = map(origin, (resource, issuer, login))
    require(urlsplit(resource).path == "/mcp", "resource URL must end in /mcp")
    require(issuer == issuer_origin + "/", "issuer must be its canonical HTTPS origin plus /")
    require(login in (login_origin, login_origin + "/"), "login URL must be an origin")
    metadata_url = resource_origin + "/.well-known/oauth-protected-resource/mcp"
    for path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
        response = client.request(resource_origin + path)
        metadata = json_object(response, "protected-resource metadata")
        require(metadata.get("resource") == resource, "metadata resource identity differs")
        require(metadata.get("authorization_servers") == [issuer],
                "metadata must advertise only the canonical human issuer")
        scopes = metadata.get("scopes_supported")
        require(isinstance(scopes, list) and "fleet-recall" in scopes
                and len(scopes) == len(set(scopes)), "metadata scopes are missing or duplicated")
        require(metadata.get("bearer_methods_supported") == ["header"], "Bearer method must be header")
        require("no-store" in response[1].get("cache-control", ""), "metadata is unexpectedly cacheable")
    discovery = json_object(client.request(issuer + ".well-known/openid-configuration"), "OIDC discovery")
    require(discovery.get("issuer") == issuer, "OIDC issuer identity differs")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "revocation_endpoint"):
        endpoint = discovery.get(key)
        require(isinstance(endpoint, str), f"OIDC discovery lacks {key}")
        require(origin(endpoint) == issuer_origin, f"OIDC {key} leaves the canonical issuer origin")
    jwks = json_object(client.request(discovery["jwks_uri"]), "OIDC JWKS")
    require(isinstance(jwks.get("keys"), list) and jwks["keys"], "OIDC JWKS has no keys")
    for key in jwks["keys"]:
        require(isinstance(key, dict) and not any(field in key for field in ("d", "p", "q", "k")),
                "OIDC JWKS contains non-public key material")
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": {"protocolVersion": "2026-07-28", "capabilities": {},
                                     "clientInfo": {"name": "https-verifier", "version": "1"}}}).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2026-07-28", "Origin": resource_origin}
    check_auth_response(client.request(resource, "POST", headers, request), metadata_url, "unauthenticated MCP")
    bad_headers = dict(headers, Authorization="Bearer verifier-deliberately-invalid")
    check_auth_response(client.request(resource, "POST", bad_headers, request), metadata_url, "invalid Bearer MCP")
    status, _, _ = client.request(resource, "POST", dict(headers, Origin="https://unrelated.invalid"), request)
    require(status == 403, "disallowed Origin must return HTTP 403")
    for method, path in (("POST", "/v1/grants"),
                         ("DELETE", "/v1/grants/00000000-0000-0000-0000-000000000001"),
                         ("GET", "/v1/transcripts/00000000-0000-0000-0000-000000000001/probe.jsonl"),
                         ("PUT", "/v1/transcripts/00000000-0000-0000-0000-000000000001/probe.jsonl")):
        check_auth_response(client.request(resource_origin + path, method,
                                           {"Content-Type": "application/json"}, b"{}"),
                            metadata_url, f"protected {method} route")
    for base, paths in (
        (resource_origin, ("/healthz", "/readyz", "/metrics", "/v1/enroll")),
        (issuer_origin, ("/admin/clients", "/clients", "/admin/oauth2/auth/requests/login", "/health/ready", "/metrics")),
        (login_origin, ("/admin/identities", "/identities", "/health/ready", "/metrics")),
    ):
        for path in paths:
            status, headers, _ = client.request(base + path)
            require(status in (403, 404), f"private path {path}: expected edge denial, received {status}")
            require("location" not in headers, f"private path {path}: unexpected redirect")
    status, headers, _ = client.request(login_origin + "/login")
    require(status == 200 or (status in (302, 303, 307) and
            headers.get("location", "").startswith(login_origin + "/")),
            "login UI must respond or redirect within its canonical origin")


def kube_json(kubeconfig, namespace, resource):
    environment = dict(os.environ, KUBECONFIG=str(kubeconfig))
    result = subprocess.run(["kubectl", "--request-timeout=15s", "-n", namespace,
                             "get", resource, "-o", "json"], env=environment,
                            capture_output=True, timeout=20, check=False)
    require(result.returncode == 0, f"cannot read {namespace}/{resource}")
    require(len(result.stdout) <= 4 * MAX_RESPONSE, "kubectl response exceeds limit")
    return json.loads(result.stdout)


def verify_runtime(kubeconfig, resource, issuer):
    deployment = kube_json(kubeconfig, "fleet-recall", "deployment/recall")
    spec = deployment["spec"]
    require(spec.get("replicas") == 1 and spec.get("strategy", {}).get("type") == "Recreate",
            "Recall spool requires one replica and Recreate strategy")
    containers = spec["template"]["spec"]["containers"]
    recall = next((container for container in containers if container["name"] == "recall"), None)
    require(recall is not None, "Recall container is missing")
    env = {item["name"]: item.get("value") for item in recall.get("env", [])}
    require(env.get("FLEET_RECALL_RESOURCE_URL") == resource, "runtime resource differs from metadata")
    issuers = dict(item.split("=", 1) for item in env.get("FLEET_RECALL_OIDC_ISSUERS", "").split(",") if "=" in item)
    require(issuers.get("hydra") == issuer and issuers.get("k8s") == "https://kubernetes.default.svc",
            "runtime human or machine issuer differs")
    require(env.get("FLEET_RECALL_OAUTH_ADVERTISED_ANCHORS") == "hydra", "runtime advertises a machine anchor")
    require(not env.get("FLEET_RECALL_OIDC_LOCAL_TRANSPORTS"), "HTTPS runtime retains an issuer transport override")
    require(env.get("FLEET_RECALL_OIDC_CA_PATH"), "runtime issuer CA bundle is missing")
    for namespace, names in (("fleet-recall", ("recall", "embed")),
                             ("ory", ("hydra-public", "hydra-admin", "kratos-public", "kratos-admin",
                                      "hydra-nodeport", "kratos-nodeport", "kratos-ui-nodeport"))):
        services = kube_json(kubeconfig, namespace, "services")["items"]
        by_name = {service["metadata"]["name"]: service for service in services}
        for name in names:
            if name.endswith("nodeport") and name not in by_name:
                continue
            require(name in by_name, f"missing service {namespace}/{name}")
            service = by_name[name]["spec"]
            require(service.get("type", "ClusterIP") == "ClusterIP" and not service.get("externalIPs")
                    and not any(port.get("nodePort") for port in service.get("ports", [])),
                    f"private service {namespace}/{name} remains externally exposed")
    for namespace in ("fleet-recall", "ory", "fleet-edge"):
        policies = kube_json(kubeconfig, namespace, "networkpolicies")["items"]
        require(any(policy["metadata"]["name"] == "https-default-deny-ingress"
                    and policy["spec"].get("podSelector") == {}
                    and "Ingress" in policy["spec"].get("policyTypes", [])
                    and not policy["spec"].get("ingress") for policy in policies),
                f"{namespace}: namespace ingress isolation is absent")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resource-url", default="https://recall.fleet.test:8443/mcp")
    parser.add_argument("--issuer-url", default="https://auth.fleet.test:8443/")
    parser.add_argument("--login-url", default="https://login.fleet.test:8443")
    parser.add_argument("--ca-path", type=Path, default=os.environ.get("FLEET_RECALL_CA_PATH"))
    parser.add_argument("--resolve-address", help="Dial this IP while preserving canonical TLS SNI and Host")
    parser.add_argument("--kubeconfig", type=Path, help="Also check deployment, service and policy consistency")
    args = parser.parse_args()
    try:
        client = Client(tls_context(args.ca_path), args.resolve_address)
        verify_public(client, args.resource_url, args.issuer_url, args.login_url)
        print("PASS: verified TLS, canonical discovery, protected routes, Origin rejection, private edge paths")
        if args.kubeconfig:
            verify_runtime(args.kubeconfig, args.resource_url, args.issuer_url)
            print("PASS: runtime URL, private services, singleton spool and ingress policy consistency")
        print("Authenticated OAuth/sandbox probes and NetworkPolicy packet tests remain separate checks.")
        return 0
    except VerificationError as error:
        print(f"HTTPS verification failed: {error}", file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError, StopIteration, http.client.HTTPException,
            subprocess.SubprocessError):
        # Do not echo raw HTTP/kubectl bodies, URLs containing credentials or TLS
        # material through exception messages.
        print("HTTPS verification failed: connection, TLS, configuration or response error", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
