#!/usr/bin/env python3
"""Prove public HTTPS access and private-service denial from an unrelated pod.

Creates one unrelated Pod plus three policy-authorized TCP control Pods. All
are tokenless and retained for audit. Controls never become Ready or listen on
ports, so their labels cannot make them receive real Service traffic. They
expire automatically. Only the unrelated Pod receives a public CA certificate.
Run after authenticated acceptance; this proves TCP isolation, not application
authorization, and leaves existing workloads untouched.
"""

import argparse
import ipaddress
import json
import os
import secrets
import ssl
import stat
import subprocess
import time
from pathlib import Path

TARGETS = (
    ("fleet-recall", "recall", 8080, "edge"),
    ("fleet-recall", "embed", 8090, "runtime"),
    ("fleet-recall", "cockroach", 26257, "runtime"),
    ("ory", "hydra-public", 4444, "edge"),
    ("ory", "hydra-admin", 4445, "ory"),
    ("ory", "kratos-public", 80, "edge"),
    ("ory", "kratos-admin", 80, "ory"),
    ("ory", "kratos-ui-kratos-selfservice-ui-node", 80, "edge"),
)
CONTROLS = {
    "edge": ("fleet-edge", {"fleet-recall.dev/component": "https-edge"}),
    "runtime": ("fleet-recall", {"app": "worker"}),
    "ory": ("ory", {"app.kubernetes.io/name": "kratos-selfservice-ui-node",
                     "app.kubernetes.io/instance": "kratos-ui"}),
}


def read_ca_bundle(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise RuntimeError("CA bundle must be a regular file")
        data = source.read(262145)
    if not 0 < len(data) <= 262144:
        raise RuntimeError("CA bundle must contain 1..256 KiB of public certificates")
    text = data.decode("ascii")
    remaining = text.strip()
    context = ssl.create_default_context()
    while remaining:
        end = remaining.find("-----END CERTIFICATE-----")
        if not remaining.startswith("-----BEGIN CERTIFICATE-----") or end < 0:
            raise RuntimeError("CA bundle must contain only complete public PEM certificates")
        end += len("-----END CERTIFICATE-----")
        context.load_verify_locations(cadata=remaining[:end])
        remaining = remaining[end:].lstrip()
    if not text.strip():
        raise RuntimeError("CA bundle is empty")
    return text


def ready_targets(service, slices, service_port, role):
    """Resolve Service ports to every ready endpoint, never a dead ClusterIP."""
    ports = [port for port in service["spec"]["ports"]
             if port["port"] == service_port and port.get("protocol", "TCP") == "TCP"]
    if len(ports) != 1:
        raise RuntimeError("expected one private Service TCP port")
    namespace, name = service["metadata"]["namespace"], service["metadata"]["name"]
    if role == "ory" and service["spec"].get("publishNotReadyAddresses"):
        raise RuntimeError("Ory Services must not publish NotReady control Pods")
    result = set()
    for item in slices["items"]:
        if item["metadata"].get("labels", {}).get("kubernetes.io/service-name") != name:
            raise RuntimeError("EndpointSlice does not match its requested Service")
        matching = [port for port in (item.get("ports") or [])
                    if port.get("name", "") == ports[0].get("name", "")
                    and port.get("protocol", "TCP") == "TCP" and port.get("port")]
        for endpoint in item.get("endpoints", []):
            conditions = endpoint.get("conditions", {})
            if conditions.get("ready") is not True or conditions.get("terminating"):
                continue
            for address in endpoint.get("addresses", []):
                ipaddress.ip_address(address)
                for port in matching:
                    result.add((address, port["port"]))
    if not result:
        raise RuntimeError(f"no ready TCP backend for {namespace}/{name}; denial would be inconclusive")
    return [{"target": f"{namespace}/{name}", "address": address, "port": port, "role": role}
            for address, port in sorted(result)]


def validate_control_services(services, labels):
    for service in services["items"]:
        selector = service["spec"].get("selector")
        if (selector and all(labels.get(key) == value for key, value in selector.items())
                and service["spec"].get("publishNotReadyAddresses")):
            raise RuntimeError("a Service publishes NotReady control Pods; cannot safely run the proof")


TCP_SCRIPT = '''import errno, json, socket
for target in TARGETS:
    try:
        connection = socket.create_connection((target["address"], target["port"]), timeout=3)
    except OSError as error:
        if ALLOW or (not isinstance(error, (TimeoutError, ConnectionRefusedError))
                     and error.errno not in (errno.EHOSTUNREACH, errno.ENETUNREACH)):
            raise
    else:
        connection.close()
        if not ALLOW:
            raise RuntimeError("private backend reachable from unrelated Pod: " + target["target"])
    print(json.dumps({"target": target["target"], "address": target["address"],
                      "port": target["port"], "allowed": ALLOW}), flush=True)
'''


def tcp_script(targets, allow):
    return "TARGETS=" + repr(targets) + "\nALLOW=" + repr(allow) + "\n" + TCP_SCRIPT


def pod_manifest(name, namespace, image, script, labels):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace,
            "labels": {"fleet-recall.dev/proof": "https-network", **labels}},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "enableServiceLinks": False, "activeDeadlineSeconds": 240,
                     "readinessGates": [{"conditionType": "fleet-recall.dev/proof-never-ready"}],
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "proof", "image": image, "imagePullPolicy": "Never",
                                     "command": ["python3", "-c", script],
                                     "readinessProbe": {"exec": {"command": ["python3", "-c", "raise SystemExit(1)"]},
                                                        "periodSeconds": 2, "timeoutSeconds": 1},
                                     "resources": {"requests": {"cpu": "20m", "memory": "32Mi"},
                                                   "limits": {"cpu": "200m", "memory": "128Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}}}]}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", type=Path, required=True)
    parser.add_argument("--ca-path", type=Path, required=True)
    parser.add_argument("--image", required=True, help="already imported sandbox image with Python3")
    args = parser.parse_args()
    data = read_ca_bundle(args.ca_path)
    kube = ["kubectl", "--kubeconfig", str(args.kubeconfig), "--request-timeout=30s"]
    name = "https-network-proof-" + time.strftime("%H%M%S") + "-" + secrets.token_hex(3)

    def command(arguments, *, data=None, timeout=40):
        output = subprocess.run(kube + arguments, input=data, capture_output=True, check=False, timeout=timeout)
        if output.returncode:
            # No workload environment, Secret or bearer token is fetched.
            raise RuntimeError("kubectl proof operation failed; inspect retained Pods with prefix " + name)
        if len(output.stdout) > 1024 * 1024:
            raise RuntimeError("proof response exceeded 1 MiB")
        return output.stdout

    def snapshot():
        targets = []
        for namespace, service, port, role in TARGETS:
            value = json.loads(command(["-n", namespace, "get", "service", service, "-o", "json"]))
            # The Ory UI control duplicates Service labels; fail before creating
            # it if any Ory Service publishes nonready endpoints.
            if namespace == "ory" and value["spec"].get("publishNotReadyAddresses"):
                raise RuntimeError("Ory Services must not publish NotReady control Pods")
            slices = json.loads(command(["-n", namespace, "get", "endpointslices", "-l",
                                         "kubernetes.io/service-name=" + service, "-o", "json"]))
            targets.extend(ready_targets(value, slices, port, role))
        if len(targets) > 24:
            raise RuntimeError("local network proof is limited to 24 backend sockets")
        return targets

    def create(pod):
        command(["create", "-f", "-"], data=json.dumps(pod).encode())

    def wait_pod(namespace, pod_name, *, finished):
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            current = json.loads(command(["-n", namespace, "get", "pod", pod_name, "-o", "json"]))
            phase = current.get("status", {}).get("phase")
            if any(condition.get("type") == "Ready" and condition.get("status") == "True"
                   for condition in current.get("status", {}).get("conditions", [])):
                raise RuntimeError("proof Pod unexpectedly became Ready")
            if phase in ("Succeeded", "Failed"):
                if phase != "Succeeded" or not finished:
                    raise RuntimeError("proof Pod failed; inspect " + namespace + "/" + pod_name)
                print(command(["-n", namespace, "logs", pod_name]).decode(), end="")
                return
            if not finished and phase == "Running":
                return
            time.sleep(1)
        raise RuntimeError("proof timed out; retained Pod " + namespace + "/" + pod_name)

    targets = snapshot()
    for namespace, labels in CONTROLS.values():
        services = json.loads(command(["-n", namespace, "get", "services", "-o", "json"]))
        validate_control_services(services, labels)
    for role, (namespace, labels) in CONTROLS.items():
        create(pod_manifest(name + "-" + role, namespace, args.image,
                            "import time; time.sleep(210)", labels))
    for role, (namespace, _) in CONTROLS.items():
        wait_pod(namespace, name + "-" + role, finished=False)

    def positive_controls():
        for role, (namespace, _) in CONTROLS.items():
            selected = [target for target in targets if target["role"] == role]
            result = command(["-n", namespace, "exec", name + "-" + role, "-c", "proof", "--",
                              "python3", "-c", tcp_script(selected, True)], timeout=85)
            print(result.decode(), end="")

    positive_controls()
    script = '''import json, ssl, urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None
context = ssl.create_default_context(cadata=CA)
client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
with client.open("https://recall.fleet.test:8443/.well-known/oauth-protected-resource", timeout=10) as response:
    body = response.read(65537)
    if len(body) > 65536: raise RuntimeError("metadata response too large")
    metadata = json.loads(body)
    if response.status != 200 or metadata["resource"] != "https://recall.fleet.test:8443/mcp":
        raise RuntimeError("canonical metadata differs")
print("PASS canonical HTTPS with CA validation from unrelated pod", flush=True)
'''.replace("cadata=CA", "cadata=" + repr(data))
    create(pod_manifest(name, "default", args.image, script + tcp_script(targets, False), {}))
    wait_pod("default", name, finished=True)
    positive_controls()
    if snapshot() != targets:
        raise RuntimeError("ready backends changed during proof; rerun against a stable deployment")
    print("PASS private TCP denial bracketed by live backend controls; retained Pod prefix: " + name)


if __name__ == "__main__":
    main()
