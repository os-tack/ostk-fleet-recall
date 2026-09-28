"""Dependency monitor contract: fixed targets, real TLS and bounded failure."""

import importlib.util
import os
import ssl
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("remote_probe", Path(__file__).with_name("remote_probe.py"))
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
FIXTURES = Path(__file__).resolve().parents[2] / "tests/fixtures/tls"


class Reply(BaseHTTPRequestHandler):
    status = 200
    payload = b'{"issuer":"fixture"}'
    delay = 0
    requests = 0

    def log_message(self, _format, *_args):
        return

    def do_GET(self):
        type(self).requests += 1
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.payload)))
        self.send_header("Location", "https://must-not-be-contacted.invalid/secret")
        self.end_headers()
        if self.delay:
            time.sleep(self.delay)
        try:
            self.wfile.write(self.payload)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            return


class ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Reply)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(FIXTURES / "server-first.pem", FIXTURES / "server-first-key.pem")
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"https://localhost:{cls.server.server_port}/discovery"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        Reply.status, Reply.payload, Reply.delay, Reply.requests = 200, b'{"issuer":"fixture"}', 0, 0

    def test_tls_trust_hostname_and_response_size(self):
        context = PROBE.tls_context(FIXTURES / "ca-first.pem")
        self.assertEqual(PROBE.request_json(self.url, context), {"issuer": "fixture"})
        with self.assertRaises(ssl.SSLError):
            PROBE.request_json(self.url, PROBE.tls_context(FIXTURES / "ca-second.pem"))
        with self.assertRaises(ssl.SSLError):
            PROBE.request_json(self.url.replace("localhost", "127.0.0.1"), context)
        Reply.payload = b"x" * (PROBE.MAX_BODY + 1)
        with self.assertRaises(ValueError):
            PROBE.request_json(self.url, context)

    def test_redirect_is_not_followed_and_absolute_deadline_is_enforced(self):
        context = PROBE.tls_context(FIXTURES / "ca-first.pem")
        Reply.status = 302
        with self.assertRaises(ValueError):
            PROBE.request_json(self.url, context)
        self.assertEqual(Reply.requests, 1)
        Reply.status, Reply.delay = 200, 0.4
        started = time.monotonic()
        with patch.object(PROBE, "REQUEST_SECONDS", 0.05), self.assertRaises(TimeoutError):
            PROBE.request_json(self.url, context)
        self.assertLess(time.monotonic() - started, 0.3)

    def test_fresh_pod_connection_refusal_retries_without_weakening_tls(self):
        context = PROBE.tls_context(FIXTURES / "ca-first.pem")
        once = PROBE.request_json_once
        attempts = []

        def transient(url, trust):
            attempts.append(url)
            if len(attempts) == 1:
                raise ConnectionRefusedError(111, "fixture connection not programmed yet")
            return once(url, trust)

        with patch.object(PROBE, "request_json_once", side_effect=transient):
            self.assertEqual(PROBE.request_json(self.url, context), {"issuer": "fixture"})
        self.assertEqual(len(attempts), 2)
        with patch.object(PROBE, "request_json_once", wraps=once) as call, self.assertRaises(ssl.SSLError):
            PROBE.request_json(self.url, PROBE.tls_context(FIXTURES / "ca-second.pem"))
        self.assertEqual(call.call_count, 1)

    def test_persistent_connection_failure_has_one_total_deadline(self):
        started = time.monotonic()
        with patch.object(PROBE, "REQUEST_SECONDS", 0.05), \
                patch.object(PROBE, "request_json_once", side_effect=ConnectionRefusedError()), \
                self.assertRaises(TimeoutError):
            PROBE.request_json(self.url, None)
        self.assertLess(time.monotonic() - started, 0.3)

    def test_discovery_cannot_redirect_jwks_and_one_failure_preserves_other_probes(self):
        calls = []

        def fetch(url):
            calls.append(url)
            if url == PROBE.DISCOVERY:
                return {"issuer": PROBE.ISSUER, "jwks_uri": "https://other.invalid/secret"}
            if url == PROBE.JWKS:
                return {"keys": [{"kty": "RSA", "n": "public", "e": "AQAB"}]}
            return {"error": "invalid_token"}

        observed = PROBE.probe(fetch)
        self.assertEqual(calls, [PROBE.DISCOVERY, PROBE.JWKS, PROBE.EMBED])
        self.assertEqual([observed[name][0] for name in PROBE.TARGETS], [False, True, True])
        rendered = PROBE.render(observed)
        for excluded in ("auth.fleet.test", "other.invalid", "public", "invalid_token"):
            self.assertNotIn(excluded, rendered)
        self.assertIn('fleet_dependency_probe_success{target="issuer_discovery"} 0', rendered)

    def test_malformed_or_private_jwks_fail_and_correct_issuer_is_required(self):
        for value in ({}, {"keys": []}, {"keys": [None]}, {"keys": [{"kty": []}]},
                      {"keys": [{"kty": "RSA", "n": "n", "e": "e", "d": "private"}]},
                      {"keys": [{"kty": "RSA", "n": "n", "e": 3}]}):
            self.assertFalse(PROBE.jwks_valid(value))
        self.assertFalse(PROBE.discovery_valid({"issuer": "https://wrong.invalid/", "jwks_uri": PROBE.JWKS}))
        self.assertTrue(PROBE.discovery_valid({"issuer": PROBE.ISSUER, "jwks_uri": PROBE.JWKS}))
        for name in ("d", "p", "q", "dp", "dq", "qi", "oth", "k"):
            self.assertFalse(PROBE.jwks_valid({"keys": [{"kty": "RSA", "n": "n", "e": "e", name: "private"}]}))

    def test_deep_json_failure_does_not_block_other_targets(self):
        context = PROBE.tls_context(FIXTURES / "ca-first.pem")
        Reply.payload = b'{"nested":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}"

        def fetch(url):
            if url == PROBE.DISCOVERY:
                return PROBE.request_json(self.url, context)
            if url == PROBE.JWKS:
                return {"keys": [{"kty": "RSA", "n": "n", "e": "e"}]}
            return {"error": "invalid_token"}

        observed = PROBE.probe(fetch)
        self.assertEqual([observed[name][0] for name in PROBE.TARGETS], [False, True, True])
        self.assertTrue(all(item[1] > 0 for item in observed.values()))

    def test_failed_requests_still_publish_fresh_bounded_categories(self):
        def fail(_url):
            raise TimeoutError("private diagnostic must not be exported")

        observed = PROBE.probe(fail)
        self.assertTrue(all(not value[0] and value[1] > 0 for value in observed.values()))
        self.assertNotIn("private diagnostic", PROBE.render(observed))
        with self.assertRaises(ValueError):
            PROBE.render({"private-user": (True, 1, 1)})

    def test_snapshot_is_atomic_private_and_does_not_overwrite_worker(self):
        directory = Path(tempfile.mkdtemp(prefix="fleet-probe-test-"))
        (directory / "worker.prom").write_text("retained worker snapshot\n")
        PROBE.write_snapshot(directory, "first\n")
        PROBE.write_snapshot(directory, "second\n")
        self.assertEqual((directory / "remote-probe.prom").read_text(), "second\n")
        self.assertEqual(os.stat(directory / "remote-probe.prom").st_mode & 0o777, 0o600)
        self.assertEqual((directory / "worker.prom").read_text(), "retained worker snapshot\n")
        (directory / ".remote-probe.next").symlink_to(directory / "worker.prom")
        with self.assertRaises(OSError):
            PROBE.write_snapshot(directory, "must not overwrite\n")
        self.assertEqual((directory / "worker.prom").read_text(), "retained worker snapshot\n")


if __name__ == "__main__":
    unittest.main()
