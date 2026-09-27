"""Workstation-only PKI safety checks; no Kubernetes context or mutations."""

import base64
import copy
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "bin" / "prepare-https-edge.py"
SPEC = importlib.util.spec_from_file_location("prepare_https_edge", SCRIPT)
EDGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EDGE)


class PkiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.previous_umask = os.umask(0o077)
        cls.directory = Path(tempfile.mkdtemp(prefix="fleet-edge-pki-test-"))
        cls.original = cls.directory / "original"
        logs = cls.directory / "initial-logs"
        EDGE.private_dir(logs)
        EDGE.ensure_pki(cls.original, True, EDGE.Runner(logs))

    @classmethod
    def tearDownClass(cls):
        # Retain local test evidence; no cleanup of workstation files.
        os.umask(cls.previous_umask)

    def setUp(self):
        self.case = self.directory / self.id().split(".")[-1]
        EDGE.private_dir(self.case)
        self.pki = self.case / "pki"
        shutil.copytree(self.original, self.pki)
        self.runner = EDGE.Runner(self.case)

    def test_repeat_preserves_keys_and_pins(self):
        before = {p.name: EDGE.digest(p) for p in self.pki.iterdir()}
        EDGE.ensure_pki(self.pki, True, self.runner)
        after = {p.name: EDGE.digest(p) for p in self.pki.iterdir()}
        self.assertEqual(before, after)

    def test_partial_initialization_is_not_replaced(self):
        partial = self.case / "partial"
        EDGE.private_dir(partial)
        (partial / "root-key.pem").write_text("retained interrupted initialization")
        with self.assertRaises(EDGE.Failure):
            EDGE.ensure_pki(partial, True, self.runner)
        self.assertEqual((partial / "root-key.pem").read_text(),
                         "retained interrupted initialization")
        self.assertEqual(len(list(partial.iterdir())), 1)

    def test_changed_certificate_pin_is_rejected(self):
        pins = json.loads((self.pki / "pins.json").read_text())
        pins["root_sha256"] = "0" * 64
        (self.pki / "pins.json").write_text(json.dumps(pins))
        with self.assertRaisesRegex(EDGE.Failure, "pins/profile mismatch"):
            EDGE.validate_pki(self.pki, self.runner)

    def test_wrong_private_key_is_rejected(self):
        (self.pki / "intermediate-key.pem").write_bytes((self.pki / "root-key.pem").read_bytes())
        with self.assertRaisesRegex(EDGE.Failure, "does not match"):
            EDGE.validate_pki(self.pki, self.runner)

    def test_cluster_secret_has_only_intermediate_private_key(self):
        secret = EDGE.intermediate_secret(self.pki)
        self.assertTrue(secret["immutable"])
        self.assertEqual(secret["metadata"]["namespace"], "fleet-pki")
        self.assertEqual(base64.b64decode(secret["data"]["tls.key"]),
                         (self.pki / "intermediate-key.pem").read_bytes())
        self.assertNotEqual(base64.b64decode(secret["data"]["tls.key"]),
                            (self.pki / "root-key.pem").read_bytes())

    def test_installer_namespaces_survive_private_rbac_checks(self):
        versions = json.loads((EDGE.SOURCE / "versions.json").read_text())
        calls = []

        class FakeRunner:
            def run(self, argv, **_kwargs):
                calls.append(argv)
                if argv[:2] == ["helm", "list"]:
                    return json.dumps([{"name": "fleet-edge", "namespace": "fleet-pki",
                                        "chart": "traefik-" + versions["traefik"]["version"],
                                        "status": "uninstalled"}]).encode()
                if "can-i" in argv:
                    return b"no\n"
                if "jsonpath={.spec.clusterIP}" in argv:
                    return b"10.96.0.20"
                return b""

        with patch.object(EDGE, "prepared_assets", return_value=(EDGE.SOURCE, versions)), \
                patch.object(EDGE, "wait_routing"):
            address = EDGE.apply(self.case, EDGE.SOURCE, self.case / "kubeconfig", FakeRunner())
        self.assertEqual(address, "10.96.0.20")
        installs = [argv for argv in calls if argv[:3] == ["helm", "upgrade", "--install"]]
        self.assertEqual([(argv[3], argv[argv.index("--namespace") + 1]) for argv in installs],
                         [("cert-manager", "fleet-pki"), ("fleet-edge", "fleet-edge")])
        denied = [argv for argv in calls if "can-i" in argv]
        self.assertEqual(len(denied), 9)
        self.assertEqual({argv[argv.index("-n") + 1] for argv in denied},
                         {"ory", "fleet-recall", "fleet-pki"})
        for argv in denied:
            self.assertEqual({arg for arg in argv if arg.startswith("--as-group=")},
                             {"--as-group=system:serviceaccounts",
                              "--as-group=system:serviceaccounts:fleet-edge",
                              "--as-group=system:authenticated"})

    def test_active_release_conflict_fails_before_mutation(self):
        versions = json.loads((EDGE.SOURCE / "versions.json").read_text())
        calls = []

        class FakeRunner:
            def run(self, argv, **_kwargs):
                calls.append(argv)
                if argv[:2] == ["helm", "list"]:
                    return json.dumps([{"name": "fleet-edge", "namespace": "fleet-pki",
                                        "chart": "traefik-" + versions["traefik"]["version"],
                                        "status": "pending-install"}]).encode()
                return b""

        with patch.object(EDGE, "prepared_assets", return_value=(EDGE.SOURCE, versions)), \
                self.assertRaisesRegex(EDGE.Failure, "existing Helm release"):
            EDGE.apply(self.case, EDGE.SOURCE, self.case / "kubeconfig", FakeRunner())
        self.assertFalse(any("apply" in argv or "create" in argv or "upgrade" in argv for argv in calls))

    def test_intermediate_rejects_other_dns_suffix(self):
        key, csr, cert = (self.case / item for item in ("leaf-key.pem", "leaf.csr", "leaf.pem"))
        ext = self.case / "leaf.ext"
        ext.write_text("basicConstraints=CA:FALSE\nsubjectAltName=DNS:outside.example\n")
        self.runner.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt",
                         "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(key),
                         "-out", str(csr), "-subj", "/CN=outside.example"])
        self.runner.run(["openssl", "x509", "-req", "-in", str(csr),
                         "-CA", str(self.pki / "intermediate.pem"),
                         "-CAkey", str(self.pki / "intermediate-key.pem"),
                         "-set_serial", "17", "-days", "1", "-extfile", str(ext), "-out", str(cert)])
        with self.assertRaises(EDGE.Failure):
            self.runner.run(["openssl", "verify", "-CAfile", str(self.pki / "root.pem"),
                             "-untrusted", str(self.pki / "intermediate.pem"), str(cert)])
        diagnostic = (self.case / "command-003.stderr").read_text()
        self.assertIn("permitted subtree violation", diagnostic)


class RoutingTests(unittest.TestCase):
    def setUp(self):
        conditions = [{"type": name, "status": "True", "observedGeneration": 2}
                      for name in ("Accepted", "Programmed", "ResolvedRefs")]
        gateway = {"kind": "Gateway", "metadata": {"name": "fleet-edge", "generation": 2},
                   "status": {"conditions": conditions,
                              "listeners": [{"name": "https", "conditions": conditions}]}}
        routes = [{"kind": "HTTPRoute", "metadata": {"name": name, "generation": 2},
                   "status": {"parents": [{"controllerName": "traefik.io/gateway-controller",
                                            "parentRef": {"name": "fleet-edge"},
                                            "conditions": copy.deepcopy(conditions)}]}}
                  for name in ("fleet-recall", "fleet-auth", "fleet-login-kratos", "fleet-login-ui")]
        self.inventory = {"items": [gateway, *routes]}

    def test_current_complete_routes_are_ready(self):
        self.assertTrue(EDGE.routing_ready(self.inventory))

    def test_old_route_success_cannot_satisfy_new_generation(self):
        self.inventory["items"][1]["metadata"]["generation"] = 3
        self.assertFalse(EDGE.routing_ready(self.inventory))

    def test_gateway_success_does_not_hide_unresolved_backend(self):
        self.inventory["items"][2]["status"]["parents"][0]["conditions"][2]["status"] = "False"
        self.assertFalse(EDGE.routing_ready(self.inventory))

    def test_different_gateway_success_is_not_accepted(self):
        self.inventory["items"][3]["status"]["parents"][0]["parentRef"]["name"] = "unrelated"
        self.assertFalse(EDGE.routing_ready(self.inventory))


if __name__ == "__main__":
    unittest.main()
