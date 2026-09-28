#!/usr/bin/env python3
"""Fixed, credential-free local dependency probes for node-exporter textfiles.

No response, URL, key identifier or exception text is logged or exported.
This is reachability/schema monitoring, not authentication or inference proof.
"""

import argparse
import contextlib
import fcntl
import http.client
import json
import os
import re
import signal
import ssl
import stat
import time
from pathlib import Path
from urllib.parse import urlsplit

ISSUER = "https://auth.fleet.test:8443/"
DISCOVERY = ISSUER + ".well-known/openid-configuration"
JWKS = ISSUER + ".well-known/jwks.json"
EMBED = "http://embed.fleet-recall.svc.cluster.local:8090/v1/descriptor"
TARGETS = ("issuer_discovery", "issuer_jwks", "embedding_transport")
MAX_BODY = 64 * 1024
REQUEST_SECONDS = 8


@contextlib.contextmanager
def deadline(seconds):
    """An absolute deadline also bounds DNS and a peer trickling response bytes."""
    def expire(_signum, _frame):
        raise TimeoutError("probe deadline")

    prior_handler = signal.signal(signal.SIGALRM, expire)
    prior_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *prior_timer)
        signal.signal(signal.SIGALRM, prior_handler)


def tls_context(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("CA is not a regular file")
        content = source.read(256 * 1024 + 1)
    if not content or len(content) > 256 * 1024:
        raise ValueError("CA exceeds bound")
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", content)
    remainder = re.sub(rb"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", b"", content)
    if not blocks or remainder.strip():
        raise ValueError("CA must contain certificates only")
    context = ssl.create_default_context()
    context.load_verify_locations(cadata=content.decode("ascii"))
    return context


def request_json(url, context):
    # Fresh Pod networking/policy programming may lag process startup.
    # Retry only refused/reset connections, within ONE total request deadline.
    # TLS, HTTP status, JSON and schema failures remain immediately visible.
    with deadline(REQUEST_SECONDS):
        for attempt in range(8):
            try:
                return request_json_once(url, context)
            except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError):
                if attempt == 7:
                    raise
                time.sleep(1)
    raise TimeoutError("probe deadline")


def request_json_once(url, context):
    parsed = urlsplit(url)
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("unexpected request authority")
    if parsed.scheme == "https" and context is not None:
        connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
                                                  timeout=REQUEST_SECONDS, context=context)
    elif url == EMBED:
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=REQUEST_SECONDS)
    else:
        raise ValueError("unexpected request scheme")
    try:
        # http.client does not use proxy environment variables or follow redirects.
        connection.request("GET", parsed.path or "/", headers={"Accept": "application/json"})
        response = connection.getresponse()
        expected = 401 if url == EMBED else 200
        if response.status != expected:
            raise ValueError("unexpected HTTP status")
        if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ValueError("unexpected content type")
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError("response exceeds bound")
        value = json.loads(body)
        if not isinstance(value, dict):
            raise ValueError("response is not an object")
        return value
    finally:
        connection.close()


def discovery_valid(value):
    # Exact issuer AND exact configured JWKS: never follow a returned URL.
    return value.get("issuer") == ISSUER and value.get("jwks_uri") == JWKS


def jwks_valid(value):
    keys = value.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= 32:
        return False
    required = {"RSA": ("n", "e"), "EC": ("crv", "x", "y"), "OKP": ("crv", "x")}
    for key in keys:
        if not isinstance(key, dict) or not isinstance(key.get("kty"), str):
            return False
        if key["kty"] not in required or {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}.intersection(key):
            return False
        if not all(isinstance(key.get(name), str) and 0 < len(key[name]) <= 8192
                   for name in required[key["kty"]]):
            return False
    return True


def probe(fetch):
    checks = (
        ("issuer_discovery", DISCOVERY, discovery_valid),
        ("issuer_jwks", JWKS, jwks_valid),
        ("embedding_transport", EMBED, lambda value: value == {"error": "invalid_token"}),
    )
    observations = {}
    for name, url, validate in checks:
        started = time.monotonic()
        try:
            success = bool(validate(fetch(url)))
        except (OSError, ValueError, http.client.HTTPException, TimeoutError, RecursionError):
            success = False
        observations[name] = (success, time.time(), time.monotonic() - started)
    return observations


def render(observations):
    if set(observations) != set(TARGETS):
        raise ValueError("unexpected probe targets")
    lines = []
    for metric, field, help_text in (
        ("success", 0, "Fixed dependency probe success, not authorization or inference proof."),
        ("completed_timestamp_seconds", 1, "Unix time when the latest probe completed, including failures."),
        ("duration_seconds", 2, "Wall duration of the latest bounded dependency probe."),
    ):
        name = "fleet_dependency_probe_" + metric
        lines.extend([f"# HELP {name} {help_text}", f"# TYPE {name} gauge"])
        for target in TARGETS:
            value = observations[target][field]
            if field == 0:
                value = int(value)
            lines.append(f'{name}{{target="{target}"}} {value}')
    return "\n".join(lines) + "\n"


def write_snapshot(directory, content):
    path = directory / ".remote-probe.next"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        metadata = os.fstat(output.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("unsafe snapshot file")
        output.truncate(0)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    os.replace(path, directory / "remote-probe.prom")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    directory = args.output_directory.resolve(strict=True)
    lock = os.open(directory / ".remote-probe.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock, "w") as lock_file:
        metadata = os.fstat(lock_file.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("unsafe lock file")
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            context = tls_context(args.ca_file)
        except (OSError, ValueError):
            context = None
        observations = probe(lambda url: request_json(url, context))
        write_snapshot(directory, render(observations))
    print(json.dumps({"targets": len(TARGETS), "healthy": sum(int(item[0]) for item in observations.values())}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError):
        print("FAIL dependency probe snapshot; prior snapshot remains available")
        raise SystemExit(1) from None
