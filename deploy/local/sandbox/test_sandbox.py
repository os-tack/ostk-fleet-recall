"""No-provider checks for the sandbox's configuration and argument boundary."""
import base64
import importlib.util
import io
import json
import os
import ssl
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError
from urllib.request import HTTPSHandler, ProxyHandler, build_opener

import tomllib

SPEC = importlib.util.spec_from_file_location("sandbox_entry", Path(__file__).with_name("entrypoint.py"))
ENTRY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENTRY)
SHIM_SPEC = importlib.util.spec_from_file_location("sandbox_shim", Path(__file__).with_name("recall-shim.py"))
SHIM = importlib.util.module_from_spec(SHIM_SPEC)
SHIM_SPEC.loader.exec_module(SHIM)
SMOKE_SPEC = importlib.util.spec_from_file_location("sandbox_smoke", Path(__file__).parent.parent / "bin/sandbox-smoke.py")
SMOKE = importlib.util.module_from_spec(SMOKE_SPEC)
SMOKE_SPEC.loader.exec_module(SMOKE)
TLS_FIXTURES = Path(__file__).resolve().parents[3] / "tests/fixtures/tls"


class SandboxTests(unittest.TestCase):
    def test_only_transcript_subdirectories_are_shared(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            transcripts = Path(directory) / "transcripts"
            home.mkdir()
            transcripts.mkdir()
            env = {"FLEET_RECALL_TOKEN": "agent-token", "FLEET_RECALL_URL": "http://recall/mcp",
                   "FLEET_RECALL_CA_PATH": "/etc/fleet-recall/ca.pem", "FLEET_RECALL_ALLOW_HTTP": "true",
                   "FLEET_SANDBOX_CODEX_AUTH_B64": base64.b64encode(b'{"tokens":{"access_token":"provider-token"}}').decode()}
            work = ENTRY.configure(home, transcripts, env)
            self.assertNotIn("FLEET_SANDBOX_CODEX_AUTH_B64", env)
            self.assertEqual((home / ".codex/sessions").resolve(), (transcripts / "codex").resolve())
            self.assertEqual((home / ".claude/projects").resolve(), (transcripts / "claude").resolve())
            self.assertEqual(list(transcripts.rglob("*.json")), [])
            self.assertIn("provider-token", (home / ".codex/auth.json").read_text())
            self.assertNotIn("provider-token", (home / ".codex/config.toml").read_text())
            codex_config = tomllib.loads((home / ".codex/config.toml").read_text())
            recall = codex_config["mcp_servers"]["recall"]
            self.assertEqual(list(codex_config["mcp_servers"]), ["recall"])
            self.assertEqual(set(recall["env_vars"]), set(ENTRY.RECALL_ENVIRONMENT))
            self.assertEqual(recall["enabled_tools"], ["recall", "remember"])
            self.assertEqual(recall["default_tools_approval_mode"], "prompt")
            self.assertEqual(recall["tools"], {"recall": {"approval_mode": "approve"},
                                              "remember": {"approval_mode": "approve"}})
            self.assertNotIn("agent-token", (work / ".mcp.json").read_text())
            config = json.loads((work / ".mcp.json").read_text())
            self.assertEqual(list(config["mcpServers"]), ["recall"])
            self.assertEqual(config["mcpServers"]["recall"]["env"],
                             {key: "${" + key + "}" for key in ENTRY.RECALL_ENVIRONMENT})

    def test_recall_ca_does_not_forward_provider_keys_or_trust_overrides_to_shim(self):
        source = {"FLEET_RECALL_TOKEN": "agent-token", "FLEET_RECALL_URL": "https://recall.test/mcp",
                  "FLEET_RECALL_CA_PATH": "/etc/fleet-recall/ca.pem", "FLEET_SANDBOX_HARNESS": "codex",
                  "CODEX_API_KEY": "codex-provider-key", "ANTHROPIC_API_KEY": "other-provider-key",
                  "CODEX_CA_CERTIFICATE": "/provider-ca.pem", "SSL_CERT_FILE": "/global-ca.pem",
                  "FLEET_RECALL_DATABASE_URL": "private-database", "AWS_SECRET_ACCESS_KEY": "aws-key"}
        environment = ENTRY.harness_environment(source)
        self.assertEqual(environment["CODEX_API_KEY"], "codex-provider-key")
        for key in ("ANTHROPIC_API_KEY", "CODEX_CA_CERTIFICATE", "SSL_CERT_FILE",
                    "FLEET_RECALL_DATABASE_URL", "AWS_SECRET_ACCESS_KEY"):
            self.assertNotIn(key, environment)
        args, shim_environment = SHIM.command(environment)
        self.assertEqual(args[-2:], ["--ca-path", "/etc/fleet-recall/ca.pem"])
        self.assertNotIn("--allow-http", args)
        self.assertEqual(shim_environment, {"PATH": "/usr/local/bin:/usr/bin:/bin",
                                            "FLEET_RECALL_TOKEN": "agent-token"})
        source["FLEET_SANDBOX_HARNESS"] = "claude"
        environment = ENTRY.harness_environment(source)
        self.assertEqual(environment["ANTHROPIC_API_KEY"], "other-provider-key")
        self.assertNotIn("CODEX_API_KEY", environment)

    def test_http_requires_exact_explicit_opt_in_even_for_loopback(self):
        for url in ("http://localhost:8080/mcp", "http://recall/mcp"):
            environment = {"FLEET_RECALL_TOKEN": "agent-token", "FLEET_RECALL_URL": url}
            for value in (None, "false", "TRUE", "1", "true "):
                if value is not None:
                    environment["FLEET_RECALL_ALLOW_HTTP"] = value
                with self.assertRaises(ValueError):
                    SHIM.command(environment)
            environment["FLEET_RECALL_ALLOW_HTTP"] = "true"
            self.assertIn("--allow-http", SHIM.command(environment)[0])
        with self.assertRaises(ValueError):
            ENTRY.harness_environment({"FLEET_RECALL_ALLOW_HTTP": "1"})

    def test_smoke_transport_defaults_and_explicit_flags(self):
        with patch.dict(os.environ, {}, clear=True):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                SMOKE.arguments(["--image", "sandbox:test"])
            development = SMOKE.arguments(["--image", "sandbox:test", "--allow-http"])
            self.assertEqual(SMOKE.transport_arguments(development), ["--allow-http"])
            self.assertEqual(development.docker_url, "http://host.docker.internal:8080/mcp")
            secure = SMOKE.arguments(["--image", "sandbox:test", "--url", "https://recall.test:8443/mcp",
                                      "--ca-path", "/etc/fleet-recall/ca.pem"])
            self.assertEqual(secure.docker_url, secure.url)
            self.assertEqual(secure.kubernetes_url, secure.url)
            self.assertEqual(SMOKE.transport_arguments(secure),
                             ["--ca-path", str(Path("/etc/fleet-recall/ca.pem").resolve())])
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                SMOKE.arguments(["--image", "sandbox:test", "--url", secure.url,
                                 "--docker-url", "http://host.docker.internal:8080/mcp"])
        with patch.dict(os.environ, {"FLEET_RECALL_ALLOW_HTTP": "true",
                                      "FLEET_RECALL_CA_PATH": str(TLS_FIXTURES / "ca-first.pem")}, clear=True):
            explicit_environment = SMOKE.arguments(["--image", "sandbox:test"])
            self.assertEqual(SMOKE.transport_arguments(explicit_environment),
                             ["--allow-http", "--ca-path", str(TLS_FIXTURES / "ca-first.pem")])
        with (patch.dict(os.environ, {"FLEET_RECALL_ALLOW_HTTP": "1"}, clear=True),
              redirect_stderr(io.StringIO()), self.assertRaises(SystemExit)):
            SMOKE.arguments(["--image", "sandbox:test"])

    def test_smoke_ca_bundle_bounds_types_and_original_roots(self):
        original = ssl.create_default_context()
        certificate = (TLS_FIXTURES / "ca-first.pem").read_text()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "ca.pem"
            bundle.write_text(certificate + (TLS_FIXTURES / "ca-second.pem").read_text())
            context = SMOKE.client_tls(bundle)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
            self.assertGreaterEqual(context.cert_store_stats()["x509_ca"], original.cert_store_stats()["x509_ca"] + 2)
            link = root / "projected-ca.pem"
            link.symlink_to(bundle)
            self.assertTrue(SMOKE.client_tls(link).check_hostname)
            for name, contents in (("empty", ""), ("oversized", " " * 262145),
                                   ("key", certificate + "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")):
                invalid = root / name
                invalid.write_text(contents)
                with self.assertRaises(SMOKE.SmokeFailure):
                    SMOKE.client_tls(invalid)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(SMOKE.SmokeFailure):
                SMOKE.client_tls(fifo)

    def test_smoke_https_trust_name_and_expiry(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"verified")

            def log_message(self, *_args):
                pass

        for certificate in ("server-first.pem", "server-expired.pem"):
            with self.subTest(certificate=certificate), HTTPServer(("127.0.0.1", 0), Handler) as server:
                server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server_context.load_cert_chain(TLS_FIXTURES / certificate, TLS_FIXTURES / "server-first-key.pem")
                server.socket = server_context.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    for bundle, host in (("ca-first.pem", "localhost"), ("ca-second.pem", "localhost"),
                                         ("ca-first.pem", "127.0.0.1"), (None, "localhost")):
                        context = SMOKE.client_tls(TLS_FIXTURES / bundle if bundle else None)
                        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
                        url = f"https://{host}:{server.server_port}/"
                        if certificate == "server-first.pem" and bundle == "ca-first.pem" and host == "localhost":
                            with opener.open(url, timeout=3) as response:
                                self.assertEqual(response.read(), b"verified")
                        else:
                            with self.assertRaises(URLError) as failure:
                                opener.open(url, timeout=3)
                            self.assertIsInstance(failure.exception.reason, ssl.SSLCertVerificationError)
                finally:
                    server.shutdown()
                    thread.join(timeout=5)
                    self.assertFalse(thread.is_alive())

    def test_tasks_stay_single_argv_values_and_cannot_add_flags(self):
        task = "--model injected; $(touch /tmp/never)\nsecond line"
        for harness in ["codex", "claude"]:
            args = ENTRY.harness_argv(harness, task, None, Path("/home/sandbox/work"))
            self.assertEqual(args[-2:], ["--", task])
            self.assertNotIn("sh", args)
            self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", args)
            self.assertNotIn("--dangerously-skip-permissions", args)
        claude = ENTRY.harness_argv("claude", "task", None, Path("/work"))
        self.assertIn("--max-turns", claude)
        self.assertIn("--strict-mcp-config", claude)
        self.assertIn("--bare", claude)

    def test_delayed_start_cannot_invoke_harness_after_grant_deadline(self):
        for harness in ("synthetic", "codex", "claude"):
            for now in (100, 100.1, 1000):
                with self.subTest(harness=harness, now=now):
                    environment = ENTRY.harness_environment({
                        "FLEET_SANDBOX_HARNESS": harness,
                        "FLEET_SANDBOX_START_BEFORE_UNIX": "100"})
                    args = ENTRY.harness_argv(harness, "task", None, Path("/work"))
                    with patch.object(ENTRY.time, "time", return_value=now), patch.object(ENTRY.subprocess, "Popen") as spawn:
                        with self.assertRaises(ValueError):
                            ENTRY.start_harness(args, Path("/work"), environment, io.BytesIO())
                        spawn.assert_not_called()
                    self.assertNotIn("FLEET_SANDBOX_START_BEFORE_UNIX", environment)

    def test_start_deadline_is_bounded_and_not_forwarded_to_provider(self):
        for raw in ("", "0", "-1", "+100", "100.0", " 100", "100 ", "0100", "１２３",
                    "99999999999999999999", "253402300800", "nan"):
            with self.subTest(raw=raw), patch.object(ENTRY.subprocess, "Popen") as spawn:
                environment = {"FLEET_SANDBOX_START_BEFORE_UNIX": raw}
                with self.assertRaises(ValueError):
                    ENTRY.start_harness(["codex"], Path("/work"), environment, io.BytesIO())
                spawn.assert_not_called()
        for raw in (None, "100"):
            environment = {"CODEX_API_KEY": "provider-key"}
            if raw is not None:
                environment["FLEET_SANDBOX_START_BEFORE_UNIX"] = raw
            with patch.object(ENTRY.time, "time", return_value=99.999), patch.object(ENTRY.subprocess, "Popen") as spawn:
                ENTRY.start_harness(["codex"], Path("/work"), environment, io.BytesIO())
                spawn.assert_called_once()
                self.assertEqual(spawn.call_args.kwargs["env"], {"CODEX_API_KEY": "provider-key"})

    def test_unknown_harness_fails_closed(self):
        with self.assertRaises(ValueError):
            ENTRY.harness_argv("bash", "task", None, Path("/work"))


if __name__ == "__main__":
    unittest.main()
