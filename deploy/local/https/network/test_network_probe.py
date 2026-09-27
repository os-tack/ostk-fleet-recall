"""Network proof regressions; no live Pods or cluster writes."""

import contextlib
import errno
import importlib.util
import io
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location("verify_https_network", ROOT / "deploy/local/bin/verify-https-network.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.service = {"metadata": {"namespace": "ory", "name": "kratos-admin"},
                        "spec": {"ports": [{"name": "http", "port": 80, "targetPort": "http-admin"}]}}
        self.slices = {"items": [{"metadata": {"labels": {"kubernetes.io/service-name": "kratos-admin"}},
                                   "ports": [{"name": "http", "port": 4434}],
                                   "endpoints": [{"addresses": ["10.244.0.22"], "conditions": {"ready": True}}]}]}

    def test_probe_uses_ready_endpoint_target_port_not_service_port(self):
        targets = PROBE.ready_targets(self.service, self.slices, 80, "ory")
        self.assertEqual(targets, [{"target": "ory/kratos-admin", "address": "10.244.0.22",
                                    "port": 4434, "role": "ory"}])

    def test_dead_missing_or_terminating_backend_is_inconclusive(self):
        for conditions in ({"ready": False}, {}, {"ready": True, "terminating": True}):
            self.slices["items"][0]["endpoints"][0]["conditions"] = conditions
            with self.assertRaisesRegex(RuntimeError, "no ready TCP backend"):
                PROBE.ready_targets(self.service, self.slices, 80, "ory")
        self.slices["items"] = []
        with self.assertRaisesRegex(RuntimeError, "no ready TCP backend"):
            PROBE.ready_targets(self.service, self.slices, 80, "ory")

    def test_unrelated_slices_or_non_ip_backends_are_rejected(self):
        self.slices["items"][0]["metadata"]["labels"]["kubernetes.io/service-name"] = "other-service"
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            PROBE.ready_targets(self.service, self.slices, 80, "ory")
        self.slices["items"][0]["metadata"]["labels"]["kubernetes.io/service-name"] = "kratos-admin"
        self.slices["items"][0]["endpoints"][0]["addresses"] = ["unresolved.invalid"]
        with self.assertRaises(ValueError):
            PROBE.ready_targets(self.service, self.slices, 80, "ory")

    def test_unready_control_slice_with_null_ports_does_not_mask_ready_backend(self):
        self.slices["items"].append({
            "metadata": {"labels": {"kubernetes.io/service-name": "kratos-admin"}},
            "ports": None,
            "endpoints": [{"addresses": ["10.244.0.88"], "conditions": {"ready": False}}],
        })
        targets = PROBE.ready_targets(self.service, self.slices, 80, "ory")
        self.assertEqual([(target["address"], target["port"]) for target in targets], [("10.244.0.22", 4434)])
        self.slices["items"][0]["ports"] = None
        with self.assertRaisesRegex(RuntimeError, "no ready TCP backend"):
            PROBE.ready_targets(self.service, self.slices, 80, "ory")

    def test_control_pods_cannot_become_ready_or_receive_credentials(self):
        for namespace, labels in PROBE.CONTROLS.values():
            pod = PROBE.pod_manifest("proof", namespace, "sandbox:test", "import time; time.sleep(1)", labels)
            spec = pod["spec"]
            container = spec["containers"][0]
            self.assertFalse(spec["automountServiceAccountToken"])
            self.assertFalse(spec["enableServiceLinks"])
            self.assertEqual(spec["readinessGates"], [{"conditionType": "fleet-recall.dev/proof-never-ready"}])
            self.assertEqual(container["readinessProbe"]["exec"]["command"][-1], "raise SystemExit(1)")
            self.assertLessEqual(spec["activeDeadlineSeconds"], 240)
            self.assertNotIn("env", container)
            self.assertNotIn("envFrom", container)
            self.assertNotIn("volumes", spec)
            self.assertNotIn("ports", container)
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])

    def test_ca_is_validated_before_any_pod_receives_it(self):
        fixtures = ROOT / "tests/fixtures/tls"
        self.assertIn("BEGIN CERTIFICATE", PROBE.read_ca_bundle(fixtures / "ca-first.pem"))
        with self.assertRaisesRegex(RuntimeError, "only complete public PEM"):
            PROBE.read_ca_bundle(fixtures / "server-first-key.pem")

    def test_services_publishing_unready_controls_are_rejected_before_creation(self):
        labels = PROBE.CONTROLS["ory"][1]
        service = {"spec": {"selector": dict(labels), "publishNotReadyAddresses": True}}
        with self.assertRaisesRegex(RuntimeError, "cannot safely run"):
            PROBE.validate_control_services({"items": [service]}, labels)
        service["spec"]["publishNotReadyAddresses"] = False
        PROBE.validate_control_services({"items": [service]}, labels)
        service["spec"] = {"selector": {"unrelated": "service"}, "publishNotReadyAddresses": True}
        PROBE.validate_control_services({"items": [service]}, labels)

    def execute_tcp(self, allow, error=None):
        target = {"target": "fixture/service", "address": "127.0.0.1", "port": 12345, "role": "edge"}
        with mock.patch("socket.create_connection", side_effect=error) as connection, \
                contextlib.redirect_stdout(io.StringIO()):
            exec(PROBE.tcp_script([target], allow), {})
        return connection

    def test_closed_backend_never_passes_positive_control(self):
        for error in (ConnectionRefusedError(), TimeoutError(), OSError(errno.EHOSTUNREACH, "unreachable")):
            with self.subTest(error=type(error).__name__), self.assertRaises(OSError):
                self.execute_tcp(True, error)
            self.execute_tcp(False, error)

    def test_successful_private_connection_fails_denial_test(self):
        with self.assertRaisesRegex(RuntimeError, "reachable"):
            self.execute_tcp(False)
        connection = self.execute_tcp(True)
        connection.return_value.close.assert_called_once()

    def test_unexpected_socket_failures_do_not_count_as_denial(self):
        with self.assertRaises(OSError):
            self.execute_tcp(False, OSError(errno.EMFILE, "file descriptor exhaustion"))


if __name__ == "__main__":
    unittest.main()
