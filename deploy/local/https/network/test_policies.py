"""Policy graph regression checks (kubectl client dry-run; never applies).

Requires KUBECONFIG for read-only API schema discovery. Packet enforcement must
still be tested separately after applying the policies to the real CNI.
"""

import json
import os
import subprocess
import unittest
from pathlib import Path


def labels_match(selector, labels):
    if any(labels.get(key) != value for key, value in selector.get("matchLabels", {}).items()):
        return False
    for expression in selector.get("matchExpressions", []):
        if expression["operator"] != "In":
            raise AssertionError("test must model new selector operators before policies use them")
        if labels.get(expression["key"]) not in expression["values"]:
            return False
    return True


def allows(policies, source_namespace, source_labels, namespace, labels, port):
    selected = [policy["spec"] for policy in policies
                if policy["metadata"]["namespace"] == namespace
                and "Ingress" in policy["spec"]["policyTypes"]
                and labels_match(policy["spec"]["podSelector"], labels)]
    if not selected:
        return True
    for spec in selected:
        for rule in spec.get("ingress", []):
            if not any(item["port"] == port and item.get("protocol", "TCP") == "TCP"
                       for item in rule.get("ports", [])):
                continue
            if "from" not in rule:
                return True
            for peer in rule["from"]:
                if "namespaceSelector" in peer:
                    if not labels_match(peer["namespaceSelector"], {"kubernetes.io/metadata.name": source_namespace}):
                        continue
                elif namespace != source_namespace:
                    continue
                if labels_match(peer.get("podSelector", {}), source_labels):
                    return True
    return False


@unittest.skipUnless(os.environ.get("KUBECONFIG") or os.environ.get("NETWORK_POLICIES_JSON"),
                     "set KUBECONFIG for read-only schema discovery or NETWORK_POLICIES_JSON to a client dry-run output")
class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("NETWORK_POLICIES_JSON"):
            remaining = Path(os.environ["NETWORK_POLICIES_JSON"]).read_text()
        else:
            result = subprocess.run(["kubectl", "create", "--dry-run=client", "-k",
                                     str(Path(__file__).parent), "-o", "json"],
                                    check=True, capture_output=True, timeout=30)
            remaining = result.stdout.decode()
        # kubectl serializes multiple resources as adjacent JSON documents.
        cls.policies = []
        while remaining.strip():
            document, end = json.JSONDecoder().raw_decode(remaining.lstrip())
            cls.policies.append(document)
            remaining = remaining.lstrip()[end:]

    def permit(self, source_namespace, source_labels, namespace, labels, port):
        return allows(self.policies, source_namespace, source_labels, namespace, labels, port)

    def test_unrelated_pods_cannot_reach_private_services_or_spoof_cross_namespace_labels(self):
        targets = [("fleet-recall", {"app": "recall"}, 8080),
                   ("fleet-recall", {"app": "embed"}, 8090),
                   ("fleet-recall", {"app": "cockroach"}, 26257),
                   ("fleet-recall", {"app": "demo"}, 8080),
                   ("fleet-recall", {"app": "ingress"}, 8787),
                   ("fleet-recall", {"app": "recall"}, 9100),
                   ("ory", {"app.kubernetes.io/name": "hydra", "app.kubernetes.io/instance": "hydra"}, 4445),
                   ("ory", {"app.kubernetes.io/name": "kratos", "app.kubernetes.io/instance": "kratos"}, 4434)]
        for source_namespace in ("default", "fleet-recall", "ory"):
            for namespace, labels, port in targets:
                self.assertFalse(self.permit(source_namespace, {"app": "unrelated"}, namespace, labels, port))
        self.assertFalse(self.permit("default", {"app": "recall"}, "fleet-recall", {"app": "cockroach"}, 26257))
        self.assertFalse(self.permit("default", {"fleet-recall.dev/component": "https-edge"},
                                     "fleet-recall", {"app": "recall"}, 8080))

    def test_gateway_reaches_public_ports_only(self):
        edge = {"fleet-recall.dev/component": "https-edge"}
        for name, instance, public, admin in (("hydra", "hydra", 4444, 4445), ("kratos", "kratos", 4433, 4434)):
            labels = {"app.kubernetes.io/name": name, "app.kubernetes.io/instance": instance}
            self.assertTrue(self.permit("fleet-edge", edge, "ory", labels, public))
            self.assertFalse(self.permit("fleet-edge", edge, "ory", labels, admin))
        self.assertTrue(self.permit("fleet-edge", edge, "fleet-recall", {"app": "recall"}, 8080))
        for app, port in (("embed", 8090), ("cockroach", 26257), ("recall", 9100)):
            self.assertFalse(self.permit("fleet-edge", edge, "fleet-recall", {"app": app}, port))
        self.assertTrue(self.permit("default", {}, "fleet-edge", edge, 8443))
        self.assertFalse(self.permit("default", {}, "fleet-edge", edge, 9100))

    def test_database_embedding_and_telemetry_dependencies_are_preserved(self):
        for app in ("writer", "recall", "worker", "demo", "ingress", "enrollment"):
            self.assertTrue(self.permit("fleet-recall", {"app": app}, "fleet-recall", {"app": "cockroach"}, 26257))
        for app in ("recall", "worker", "enrollment"):
            self.assertTrue(self.permit("fleet-recall", {"app": app}, "fleet-recall", {"app": "embed"}, 8090))
        for app, port in (("recall", 9100), ("embed", 9100), ("demo", 9091), ("ingress", 9091)):
            self.assertTrue(self.permit("fleet-observability", {"app.kubernetes.io/name": "prometheus"},
                                        "fleet-recall", {"app": app}, port))
            self.assertFalse(self.permit("fleet-observability", {"app.kubernetes.io/name": "grafana"},
                                         "fleet-recall", {"app": app}, port))
        for app in ("hydra", "hydra-automigrate", "kratos", "kratos-automigrate"):
            self.assertTrue(self.permit("ory", {"app.kubernetes.io/name": app},
                                        "fleet-recall", {"app": "cockroach"}, 26257))

    def test_ui_can_use_admin_apis_but_cannot_reach_sql(self):
        ui = {"app.kubernetes.io/name": "kratos-selfservice-ui-node", "app.kubernetes.io/instance": "kratos-ui"}
        for app, port in (("hydra", 4445), ("kratos", 4433), ("kratos", 4434)):
            self.assertTrue(self.permit("ory", ui, "ory", {"app.kubernetes.io/name": app,
                                                          "app.kubernetes.io/instance": app}, port))
        self.assertFalse(self.permit("ory", ui, "fleet-recall", {"app": "cockroach"}, 26257))


if __name__ == "__main__":
    unittest.main()
