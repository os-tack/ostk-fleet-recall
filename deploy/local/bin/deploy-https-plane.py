#!/usr/bin/env python3
"""Prepare or apply the existing M3 plane's local HTTPS identity cutover.

Stage the edge, CA, Lima forward and split DNS first. Application is gated on
working Mac DNS/TLS, an encrypted checkpoint, no running sandbox, and no live
delegation. Existing database authority, registry, content keys and Ory Secrets
are preserved. A failed cutover leaves the worker suspended for recovery.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import time
from pathlib import Path

PROTECTED_SECRETS = {
    "fleet-recall": ("fleet-pins", "fleet-content-kek", "fleet-remote"),
    "ory": ("hydra-secrets", "kratos-secrets", "kratos-ui-kratos-selfservice-ui-node"),
}


def secret_fingerprint(data):
    if not isinstance(data, dict) or not data or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in data.items()):
        raise RuntimeError("protected Secret has no valid data")
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def backup_secret_fingerprints(namespace, plaintext):
    document = json.loads(plaintext)
    expected = set(PROTECTED_SECRETS[namespace])
    result = {}
    for item in document["items"]:
        metadata = item.get("metadata", {})
        name = metadata.get("name")
        if item.get("kind") != "Secret" or name not in expected:
            continue
        key = namespace + "/" + name
        if metadata.get("namespace") != namespace or key in result:
            raise RuntimeError("protected Secret namespace or uniqueness differs in backup")
        result[key] = secret_fingerprint(item.get("data"))
    if len(result) != len(expected):
        raise RuntimeError("authenticated backup is missing protected Secrets")
    return result


def verify_backup(directory, state, cluster_uid):
    """Authenticate every recovery input and bind it to this installation."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    directory = directory.resolve(strict=True)
    manifest = json.loads((directory / "manifest.json").read_text())
    if (manifest.get("version") != 1 or not manifest.get("complete")
            or manifest.get("state") != str(state) or manifest.get("cluster_uid") != cluster_uid
            or not 0 <= time.time() - manifest.get("created_at", 0) <= 86400):
        raise RuntimeError("backup must be complete, less than a day old, and from this cluster/state")
    cipher = AESGCM(bytes.fromhex((directory / "recovery-key.hex").read_text().strip()))
    names = set()
    fingerprints = {}
    for artifact in manifest["artifacts"]:
        name = artifact["name"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name in names:
            raise RuntimeError("invalid recovery artifact name")
        names.add(name)
        data = (directory / (name + ".aesgcm")).read_bytes()
        if hashlib.sha256(data).hexdigest() != artifact["sha256"]:
            raise RuntimeError("recovery artifact checksum changed")
        plaintext = cipher.decrypt(data[:12], data[12:], name.encode())
        if len(plaintext) != artifact["bytes"]:
            raise RuntimeError("recovery artifact size changed")
        for namespace in PROTECTED_SECRETS:
            if name == namespace + "-resources.json":
                fingerprints.update(backup_secret_fingerprints(namespace, plaintext))
    required = {"database.tar", "database-location.json", "database-backup.tsv", "database-check-files.tsv",
                "spool.tar", "workstation-state.tar.gz", "fleet-recall-resources.json", "ory-resources.json",
                "hydra-helm-values.yaml", "kratos-helm-values.yaml", "kratos-ui-helm-values.yaml", "lima.json"}
    if not required <= names:
        raise RuntimeError("recovery checkpoint is missing required artifacts")
    return fingerprints


def drain_workers(kube, run, cron_uid, directory):
    """Drain scheduled and manual workers without deleting retained Jobs/pods."""
    deadline = time.monotonic() + 300
    watched_jobs = set()
    idle_observations = 0
    first = True
    while time.monotonic() < deadline:
        raw = run(kube + ["-n", "fleet-recall", "get", "jobs,pods", "-o", "json"], timeout=40)
        (directory / "worker-drain-latest.json").write_bytes(raw)
        if first:
            (directory / "worker-drain-before.json").write_bytes(raw)
            first = False
        items = json.loads(raw)["items"]
        active_jobs = set()
        active_pods = set()
        for item in items:
            metadata = item["metadata"]
            name = metadata["name"]
            labels = metadata.get("labels", {})
            status = item.get("status", {})
            if item["kind"] == "Job":
                template_labels = item["spec"]["template"]["metadata"].get("labels", {})
                owned = any(owner.get("uid") == cron_uid for owner in metadata.get("ownerReferences", []))
                if not owned and labels.get("app") != "worker" and template_labels.get("app") != "worker":
                    continue
                terminal = {condition["type"] for condition in status.get("conditions", [])
                            if condition.get("status") == "True"}
                if "Failed" in terminal and name in watched_jobs:
                    raise RuntimeError("worker Job failed while draining; inspect private worker-drain-latest.json")
                if not terminal.intersection({"Complete", "Failed"}) or status.get("active", 0):
                    active_jobs.add(name)
            elif item["kind"] == "Pod" and labels.get("app") == "worker":
                if status.get("phase") not in ("Succeeded", "Failed"):
                    active_pods.add(name)
        watched_jobs.update(active_jobs)
        if not active_jobs and not active_pods:
            idle_observations += 1
            if idle_observations >= 2:
                return
        else:
            idle_observations = 0
        time.sleep(2)
    raise RuntimeError("worker drain exceeded 300 seconds; worker remains suspended")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--image-tag", required=True)
    parser.add_argument("--ca-path", type=Path, required=True)
    parser.add_argument("--trusted-proxy-cidr", required=True)
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", args.image_tag):
        parser.error("invalid image tag")
    network = ipaddress.ip_network(args.trusted_proxy_cidr, strict=True)
    if network.version != 4 or network.prefixlen < 16 or not network.is_private:
        parser.error("trusted proxy CIDR must be a narrow private IPv4 pod subnet")
    here = Path(__file__).resolve().parents[1]
    state = args.state.resolve(strict=True)
    os.umask(0o077)
    run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(4)
    directory = state / ("https-cutover-" + run_id)
    directory.mkdir(mode=0o700)
    environment = dict(os.environ, KUBECONFIG=str(state / "kubeconfig"))
    kube = ["kubectl", "--request-timeout=30s"]
    phase = "prepare"

    def run(argv, data=None, timeout=120):
        result = subprocess.run(argv, input=data, env=environment, capture_output=True,
                                timeout=timeout, check=False)
        if result.returncode:
            (directory / "failure.log").write_bytes(result.stdout + result.stderr)
            raise RuntimeError("command failed; see private failure.log")
        return result.stdout

    def obj(namespace, kind, name):
        return json.loads(run(kube + ["-n", namespace, "get", kind, name, "-o", "json"]))

    def apply(value):
        run(kube + ["apply", "-f", "-"], json.dumps(value).encode())

    def fingerprints():
        result = {}
        for namespace, names in PROTECTED_SECRETS.items():
            for name in names:
                data = obj(namespace, "secret", name)["data"]
                result[namespace + "/" + name] = secret_fingerprint(data)
        return result

    try:
        digest = (state / "model.sha256").read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError("invalid retained model digest")
        bundle = state.parents[2] / ".models/potion-retrieval-32M-6fc8051fab2a1e0ee76689cf08c853792ac285e7"
        rendered = run(["kubectl", "kustomize", str(here / "kustomize/overlays/m4-https"),
                        "--load-restrictor", "LoadRestrictionsNone"]).decode()
        for name, value in {"__IMAGE_TAG__": args.image_tag, "__MODEL_SHA256__": digest,
                            "__MODEL_BUNDLE_DIR__": str(bundle), "__RUN_ID__": run_id}.items():
            rendered = rendered.replace(name, value)
        manifest = directory / "runtime.yaml"
        manifest.write_text(rendered)
        ory = here / "https/ory"
        hydra = directory / "hydra-values.yaml"
        hydra.write_text((ory / "hydra-values.yaml.in").read_text().replace("__TRUSTED_PROXY_CIDR__", str(network)))
        for selector in ("remote", "ory-nodeports"):
            run(kube + ["apply", "--dry-run=server", "-f", str(manifest), "-l", "fleet-recall.dev/phase=" + selector])
        before = fingerprints()
        (directory / "key-fingerprints-before.json").write_text(json.dumps(before, indent=2) + "\n")
        if not args.apply:
            print("Prepared and server-validated: " + str(directory))
            return
        if args.backup is None:
            raise RuntimeError("--apply requires a complete encrypted --backup checkpoint")
        cluster_uid = obj("", "namespace", "kube-system")["metadata"]["uid"]
        backup_fingerprints = verify_backup(args.backup, state, cluster_uid)
        (directory / "key-fingerprints-backup.json").write_text(json.dumps(backup_fingerprints, indent=2) + "\n")
        if before != backup_fingerprints:
            raise RuntimeError("current keys differ from the authenticated backup; refusing a new retry baseline")
        nodes = json.loads(run(kube + ["get", "nodes", "-o", "json"]))["items"]
        if str(network) not in [node["spec"].get("podCIDR") for node in nodes]:
            raise RuntimeError("trusted proxy CIDR does not match an installed node pod subnet")
        expected_image = "docker.io/library/ostk-fleet-recall:" + args.image_tag
        if not any(expected_image in image.get("names", []) for node in nodes for image in node["status"].get("images", [])):
            raise RuntimeError("import the selected service image into k0s before cutover")
        context = ssl.create_default_context(cafile=str(args.ca_path.resolve(strict=True)))
        for hostname in ("recall.fleet.test", "auth.fleet.test", "login.fleet.test"):
            with socket.create_connection((hostname, 8443), timeout=10) as connection, \
                    context.wrap_socket(connection, server_hostname=hostname):
                pass
        if run(["docker", "ps", "-q", "--filter", "label=fleet-recall.launch=true"]).strip():
            raise RuntimeError("stop Docker sandboxes using launch down before cutover")
        pods = json.loads(run(kube + ["get", "pods", "-A", "-l", "app.kubernetes.io/managed-by=fleet-recall-launch", "-o", "json"]))
        if any(pod.get("status", {}).get("phase") not in ("Succeeded", "Failed") for pod in pods["items"]):
            raise RuntimeError("stop Kubernetes sandboxes using launch down before cutover")
        for path in state.rglob("launch-state.json"):
            launch = json.loads(path.read_text())
            if (launch.get("runtime_started") and not launch.get("runtime_stopped")) or any(not grant.get("revoked") for grant in launch.get("grants", [])):
                raise RuntimeError("a retained launch still needs cleanup through its recorded URL")
        sql = ["docker", "run", "--rm", "-i", "--network", "host", "-v", f"{state}/certs:/certs:ro",
               "cockroachdb/cockroach:v26.2.3", "sql", "--certs-dir=/certs", "--host=127.0.0.1:26258",
               "--database=fleet_recall", "--format=tsv"]
        query = b"SELECT count(*) FROM memory_session_grants_v1 WHERE revoked_at IS NULL AND expires_at > now();"
        if run(sql, query).decode().splitlines()[-1] != "0":
            raise RuntimeError("revoke live grants through the old endpoint before cutover")
        cron = obj("fleet-recall", "cronjob", "worker")
        recall_before = obj("fleet-recall", "deployment", "recall")
        (directory / "worker-before.json").write_text(json.dumps(cron, indent=2) + "\n")
        phase = "quiesce"
        run(kube + ["-n", "fleet-recall", "patch", "cronjob", "worker", "--type=merge", "-p", '{"spec":{"suspend":true}}'])
        drain_workers(kube, run, cron["metadata"]["uid"], directory)
        run(kube + ["-n", "fleet-recall", "scale", "deploy/recall", "--replicas=0"])
        run(kube + ["-n", "fleet-recall", "wait", "--for=delete", "pod", "-l", "app=recall", "--timeout=120s"], timeout=130)
        if run(sql, query).decode().splitlines()[-1] != "0":
            # Close the minting race before touching any issuer configuration.
            replicas = str(recall_before["spec"]["replicas"])
            run(kube + ["-n", "fleet-recall", "scale", "deploy/recall", "--replicas=" + replicas])
            run(kube + ["-n", "fleet-recall", "rollout", "status", "deploy/recall", "--timeout=120s"], timeout=130)
            original = json.dumps({"spec": {"suspend": cron["spec"].get("suspend", False)}})
            run(kube + ["-n", "fleet-recall", "patch", "cronjob", "worker", "--type=merge", "-p", original])
            raise RuntimeError("new grants appeared during drain; old endpoint restored for launch down")
        cluster_ca = obj("fleet-recall", "configmap", "kube-root-ca.crt")["data"]["ca.crt"]
        apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "fleet-oidc-ca", "namespace": "fleet-recall"},
               "data": {"ca.pem": cluster_ca.rstrip() + "\n" + args.ca_path.read_text()}})
        phase = "identity"
        for release, chart, values in [("kratos-ui", "kratos-selfservice-ui-node", ory / "kratos-ui-values.yaml"),
                                       ("kratos", "kratos", ory / "kratos-values.yaml"), ("hydra", "hydra", hydra)]:
            run(["helm", "upgrade", release, chart, "--repo", "https://k8s.ory.sh/helm/charts", "--version", "0.64.0",
                 "-n", "ory", "--reuse-values", "-f", str(values), "--wait", "--timeout", "5m"], timeout=330)
        phase = "runtime"
        run(kube + ["apply", "-f", str(manifest), "-l", "fleet-recall.dev/phase=remote"])
        # The HTTPS overlay holds the CronJob suspended throughout this apply.
        for deployment in ("embed", "recall"):
            run(kube + ["-n", "fleet-recall", "rollout", "status", "deploy/" + deployment, "--timeout=240s"], timeout=250)
        run(kube + ["apply", "-f", str(manifest), "-l", "fleet-recall.dev/phase=ory-nodeports"])
        run(kube + ["apply", "-k", str(here / "https/network")])
        if fingerprints() != backup_fingerprints:
            raise RuntimeError("persisted key material changed; keep worker suspended and investigate")
        phase = "verify"
        run(["python3", str(here / "bin/verify-https.py"), "--ca-path", str(args.ca_path), "--kubeconfig", str(state / "kubeconfig")])
        # Authenticated acceptance is a separate, explicit final gate. Leave the
        # schedule suspended; its original value is retained for the operator.
        print("HTTPS cutover applied; key material preserved. Worker remains suspended for authenticated acceptance.")
        print("Private evidence and original worker state: " + str(directory))
        phase = "awaiting-authenticated-acceptance"
    finally:
        (directory / "phase.json").write_text(json.dumps({"phase": phase}) + "\n")


if __name__ == "__main__":
    main()
