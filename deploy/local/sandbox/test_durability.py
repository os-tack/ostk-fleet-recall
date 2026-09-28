"""Safety and byte-level sequencing for the optional receiver restart proof."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SPEC = importlib.util.spec_from_file_location("sandbox_smoke", Path(__file__).resolve().parents[1] / "bin/sandbox-smoke.py")
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)


class DurabilityTests(unittest.TestCase):
    def smoke(self, directory):
        smoke = SMOKE.Smoke.__new__(SMOKE.Smoke)
        smoke.args = SimpleNamespace(url="https://recall.example.test:8443/mcp", ca_path=None,
                                     receiver="recall", worker="worker")
        smoke.directory = directory
        smoke.count = 0
        return smoke

    def test_prefix_restart_retry_and_both_duplicate_windows_are_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            smoke = self.smoke(Path(temporary))
            original = b"original acknowledged bytes\n"
            manifest = {"sandbox_id": "fixture", "source": "original.jsonl", "format": "claude-code",
                        "first_line_sha256": hashlib.sha256(original).hexdigest()}
            stored = b""
            methods = []

            def request(_token, *, path, headers, body=None, method=None, timeout=40):
                nonlocal stored
                methods.append(method)
                offset = int(path.split("offset=", 1)[1])
                replay = False
                if body is not None:
                    if offset < len(stored):
                        self.assertEqual(stored[offset:offset + len(body)], body)
                        replay = True
                    else:
                        self.assertEqual(offset, len(stored))
                        stored += body
                return 200, {"length": len(stored), "replayed": replay}

            def restart(_token, path, _headers, body):
                self.assertEqual(int(path.split("offset=", 1)[1]), len(stored))
                self.assertTrue(body.endswith(b"\n"))
                return {"before_pod_uid": "old", "after_pod_uid": "new", "partial_transport_outcome": "TimeoutError"}

            smoke.http = request
            smoke.spool_bytes = lambda item: original if item["source"] == "original.jsonl" else stored
            smoke.interrupted_upload = restart
            result, pending, expected = smoke.receiver_durability({"shipper": "test-token"}, manifest, original)
            self.assertEqual(methods, ["PUT", None, "PUT", "PUT", "PUT"])
            self.assertNotEqual(pending["source"], manifest["source"])
            self.assertIn(expected.encode(), stored)
            self.assertTrue(result["duplicate_windows_replayed"])
            self.assertEqual(result["final_sha256"], hashlib.sha256(stored).hexdigest())

    def test_raw_upload_uses_receiver_content_type_and_preserves_exact_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            smoke = self.smoke(Path(temporary))
            response = mock.MagicMock(status=200)
            response.__enter__.return_value = response
            response.read.return_value = b'{"length":8,"replayed":false}'
            smoke.opener = mock.Mock()
            smoke.opener.open.return_value = response
            smoke.http("test-token", path="/v1/transcripts/fixture?offset=0", body=b'{"a":1}\n', method="PUT")
            request = smoke.opener.open.call_args.args[0]
            self.assertEqual(request.get_header("Content-type"), "application/octet-stream")
            self.assertEqual(request.data, b'{"a":1}\n')
            self.assertEqual(request.method, "PUT")

    def test_edge_recovery_retries_only_transient_failures_with_bounded_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            smoke = self.smoke(Path(temporary))
            smoke.http = mock.Mock(side_effect=[SMOKE.URLError("connection reset"), (503, None),
                                               (200, {"length": 42, "replayed": False})])
            with mock.patch.object(SMOKE.time, "sleep"):
                result = smoke.receiver_progress_after_restart("test-token", "/fixture", {})
            self.assertEqual(result[1]["length"], 42)
            self.assertEqual(smoke.http.call_count, 3)
            self.assertTrue(all(0 < call.kwargs["timeout"] <= 5 for call in smoke.http.call_args_list))
            smoke.http = mock.Mock(return_value=(401, {}))
            with self.assertRaisesRegex(SMOKE.SmokeFailure, "rejected"):
                smoke.receiver_progress_after_restart("test-token", "/fixture", {})
            smoke.http.assert_called_once()

    def test_edge_recovery_cannot_outlive_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            smoke = self.smoke(Path(temporary))
            smoke.http = mock.Mock(return_value=(503, None))
            with mock.patch.object(SMOKE.time, "monotonic", side_effect=[0, 0, 61]), \
                    self.assertRaisesRegex(SMOKE.SmokeFailure, "did not recover"):
                smoke.receiver_progress_after_restart("test-token", "/fixture", {})
            smoke.http.assert_called_once()

    def test_gateway_html_is_retryable_but_malformed_success_is_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            smoke = self.smoke(Path(temporary))
            response = mock.MagicMock(status=503)
            response.__enter__.return_value = response
            response.read.return_value = b'<html>unavailable</html>'
            smoke.opener = mock.Mock()
            smoke.opener.open.return_value = response
            self.assertEqual(smoke.http("test-token"), (503, None))
            response.status = 200
            with self.assertRaisesRegex(SMOKE.SmokeFailure, "not JSON"):
                smoke.http("test-token")

    def test_premature_success_acknowledgement_is_rejected_and_connection_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            smoke = self.smoke(Path(temporary))
            smoke.restart_receiver = mock.Mock(return_value={})
            connection = mock.Mock()
            connection.getresponse.return_value.status = 200
            with mock.patch.object(SMOKE.http.client, "HTTPSConnection", return_value=connection) as factory, \
                    mock.patch.object(SMOKE, "client_tls", return_value="verified-context"):
                with self.assertRaisesRegex(SMOKE.SmokeFailure, "success acknowledgement"):
                    smoke.interrupted_upload("test-token", "/v1/transcripts/fixture?offset=20", {"x-transcript-format": "claude-code"}, b"next window\n")
            factory.assert_called_once_with("recall.example.test", 8443, timeout=4, context="verified-context")
            connection.putheader.assert_any_call("Content-Length", str(len(b"next window\n")))
            connection.endheaders.assert_called_once_with(b"next window")
            connection.close.assert_called_once()

    def test_restart_failure_also_closes_incomplete_upload(self):
        with tempfile.TemporaryDirectory() as temporary:
            smoke = self.smoke(Path(temporary))
            smoke.restart_receiver = mock.Mock(side_effect=SMOKE.SmokeFailure("rollout failed"))
            connection = mock.Mock()
            with mock.patch.object(SMOKE.http.client, "HTTPSConnection", return_value=connection), \
                    mock.patch.object(SMOKE, "client_tls", return_value="verified-context"):
                with self.assertRaisesRegex(SMOKE.SmokeFailure, "rollout failed"):
                    smoke.interrupted_upload("test-token", "/v1/transcripts/fixture?offset=20", {}, b"next\n")
            connection.close.assert_called_once()
            connection.getresponse.assert_not_called()

    def test_non_singleton_or_rolling_receiver_is_not_mutated(self):
        with tempfile.TemporaryDirectory() as temporary:
            for replicas, strategy in ((2, "Recreate"), (1, "RollingUpdate"), (0, "Recreate")):
                smoke = self.smoke(Path(temporary))
                smoke.object = mock.Mock(return_value={"spec": {"replicas": replicas, "strategy": {"type": strategy}}})
                smoke.kubectl = mock.Mock()
                with self.subTest(replicas=replicas, strategy=strategy), self.assertRaises(SMOKE.SmokeFailure):
                    smoke.restart_receiver()
                smoke.kubectl.assert_not_called()

    def test_restart_uses_revision_guard_preserves_annotations_and_requires_new_ready_pod(self):
        with tempfile.TemporaryDirectory() as temporary:
            smoke = self.smoke(Path(temporary))
            deployment = {"metadata": {"uid": "deployment", "resourceVersion": "42"}, "spec": {
                "replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": {"app": "recall"}},
                "template": {"metadata": {"annotations": {"prometheus.io/scrape": "true"}}}}}
            smoke.object = mock.Mock(side_effect=[deployment, {"spec": {"suspend": True}}, deployment])
            pod_count = 0
            calls = []

            def kubectl(*argv, **_kwargs):
                nonlocal pod_count
                calls.append(argv)
                if argv[:2] == ("get", "pods"):
                    pod_count += 1
                    return 0, json.dumps({"items": [{"metadata": {"uid": "old" if pod_count == 1 else "new"},
                           "status": {"conditions": [{"type": "Ready", "status": "True"}]}}]}).encode()
                return 0, b""

            smoke.kubectl = kubectl
            result = smoke.restart_receiver()
            patch = next(call for call in calls if call[0] == "patch")
            operations = json.loads(patch[-1])
            self.assertEqual(operations[0], {"op": "test", "path": "/metadata/resourceVersion", "value": "42"})
            self.assertEqual(operations[1]["value"]["prometheus.io/scrape"], "true")
            self.assertEqual(result, {"before_pod_uid": "old", "after_pod_uid": "new"})


if __name__ == "__main__":
    unittest.main()
