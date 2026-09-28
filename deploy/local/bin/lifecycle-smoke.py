#!/usr/bin/env python3
"""Rehearse a bounded local lifecycle fault and restore the running deployment.

Every mode requires an authenticated checkpoint, no active sandboxes/grants,
and a private human OAuth token file. The worker stays suspended until dependency
restoration, TLS/authentication, key, revocation and spool checks all pass. This
does not restore a database snapshot or rotate any key. Evidence stays private.
"""

import argparse
import base64
import copy
import csv
import datetime
import fcntl
import hashlib
import http.client
import importlib.util
import io
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import tarfile
import time
from contextlib import contextmanager
from pathlib import Path, PurePosixPath


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CUTOVER = load("deploy-https-plane")
SMOKE = load("sandbox-smoke")
HTTPS = load("verify-https")
MODES = ("deploy", "restart", "db-outage", "embed-outage", "issuer-outage", "vm-restart", "rollback", "worker-exclusion")
MAX_OUTPUT = 64 * 1024 * 1024
REVOCATIONS_SQL = "SELECT jti, revoked_at, revoked_by FROM public.memory_session_grants_v1 WHERE revoked_at IS NOT NULL ORDER BY jti;"


class LifecycleFailure(RuntimeError):
    pass


class WorkerExclusionFailure(LifecycleFailure):
    """An observed overlap/identity violation must never be retried away."""


def require(condition, message):
    if not condition:
        raise LifecycleFailure(message)


def require_worker(condition, message):
    if not condition:
        raise WorkerExclusionFailure(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def revoked_rows(raw):
    rows = list(csv.reader(io.StringIO(raw.decode(), newline="")))
    require(rows and rows[0] == ["jti", "revoked_at", "revoked_by"]
            and all(len(row) == 3 and row[0] and row[1] for row in rows[1:]), "invalid revocation snapshot")
    require(len({row[0] for row in rows[1:]}) == len(rows) - 1, "duplicate revoked grant identity")
    return {"count": len(rows) - 1, "sha256": hashlib.sha256(raw).hexdigest()}


def timestamp(value):
    require(isinstance(value, str), "missing controller timestamp")
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def owned(item, kind, uid):
    return any(owner.get("kind") == kind and owner.get("uid") == uid and owner.get("controller") is True
               for owner in item["metadata"].get("ownerReferences", []))


def terminal_job(item):
    return any(condition.get("status") == "True" and condition.get("type") in ("Complete", "Failed")
               for condition in item.get("status", {}).get("conditions", []))


def spool_hashes(raw):
    """Hash regular file bytes without extraction, ignoring harmless tar metadata."""
    require(len(raw) <= MAX_OUTPUT, "spool snapshot exceeds 64 MiB rehearsal bound")
    result = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and path.parts
                    and path.parts[0] == "transcripts", "spool archive leaves the transcript root")
            require(member.isdir() or member.isfile(), "spool archive contains a link or special file")
            if member.isdir():
                continue
            total += member.size
            require(total <= MAX_OUTPUT and str(path) not in result, "spool snapshot is oversized or duplicates a file")
            with archive.extractfile(member) as source:
                content = source.read(MAX_OUTPUT + 1)
            require(len(content) == member.size, "spool snapshot member length changed")
            result[str(path)] = {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    return result


def recall_container(deployment):
    metadata, spec = deployment["metadata"], deployment["spec"]
    require(metadata.get("namespace") == "fleet-recall" and metadata.get("name") == "recall"
            and spec.get("replicas") == 1 and spec.get("strategy", {}).get("type") == "Recreate",
            "Recall must be the single-replica Recreate deployment")
    containers = spec["template"]["spec"]["containers"]
    matches = [(index, container) for index, container in enumerate(containers) if container["name"] == "recall"]
    require(len(matches) == 1, "Recall container is missing or ambiguous")
    return matches[0]


def rollback_values(saved, current, url):
    """Select only image/probe; saved auth configuration can never be applied."""
    _, old = recall_container(saved)
    _, new = recall_container(current)
    require(saved["metadata"].get("uid") == current["metadata"].get("uid"),
            "rollback deployment belongs to another installation")
    for container in (old, new):
        env = {item["name"]: item.get("value") for item in container.get("env", [])}
        require(env.get("FLEET_RECALL_RESOURCE_URL") == url
                and env.get("FLEET_RECALL_OIDC_ISSUERS") == "hydra=https://auth.fleet.test:8443/,k8s=https://kubernetes.default.svc"
                and not env.get("FLEET_RECALL_OIDC_LOCAL_TRANSPORTS"), "rollback canonical URL set differs")
        require(container.get("image") and container.get("readinessProbe", {}).get("httpGet", {}).get("path")
                in ("/healthz", "/readyz"), "rollback image or readiness probe is missing")
        require(container["readinessProbe"]["httpGet"].get("port") in ("mcp", 8080),
                "rollback readiness port differs")
    require(old["image"] != new["image"], "rollback proof needs a different previous image")
    return {key: copy.deepcopy(old[key]) for key in ("image", "readinessProbe")}


def deployment_probe():
    """Use the checked-in probe only after verifying the lifecycle contract."""
    import yaml

    path = Path(__file__).resolve().parents[1] / "kustomize/overlays/m2-remote-plane/remote.yaml"
    documents = list(yaml.safe_load_all(path.read_text()))
    deployments = [item for item in documents if item and item.get("kind") == "Deployment"
                   and item.get("metadata", {}).get("name") == "recall"]
    require(len(deployments) == 1, "checked-in Recall deployment is missing or ambiguous")
    _, container = recall_container(deployments[0])
    probe = container.get("readinessProbe")
    require(probe == {"httpGet": {"path": "/readyz", "port": "mcp"}, "periodSeconds": 5,
                      "timeoutSeconds": 1, "failureThreshold": 1}, "checked-in readiness probe differs from the tested contract")
    return copy.deepcopy(probe)


class Lifecycle:
    def __init__(self, args, directory):
        self.args, self.directory, self.count = args, directory, 0
        self.environment = {name: os.environ[name] for name in
                            ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "LIMA_HOME")
                            if name in os.environ}
        self.environment["KUBECONFIG"] = str(args.state / "kubeconfig")
        self.kube = ["kubectl", "--request-timeout=30s"]
        self.client = HTTPS.Client(SMOKE.client_tls(args.ca_path))
        token_document = json.loads(SMOKE.private_read(args.token_file))
        self.token = token_document.get("access_token")
        require(isinstance(self.token, str) and 0 < len(self.token) <= 16384
                and re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", self.token),
                "invalid private OAuth token file")
        parts = self.token.split(".")
        require(len(parts) == 3, "lifecycle probe needs a human OAuth JWT")
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        # Claims are only an early lifetime/fixture check, never authorization;
        # the baseline HTTPS MCP call must verify the signature and enrollment.
        require(claims.get("iss") == "https://auth.fleet.test:8443/"
                and isinstance(claims.get("exp"), (int, float))
                and claims["exp"] - time.time() >= 900, "obtain a human OAuth token with at least 15 minutes remaining")
        self.cron = None
        self.suspended = False
        self.scaled = []
        self.vm_restart_pending = False
        self.rollback_restore = None
        self.worker_restore_spec = None
        self.deploy_values = None
        self.deployment_before = None
        self.ready_path = "/readyz"
        self.baseline = None
        self.claim_hash = None
        self.events = []

    def artifact(self, name):
        self.count += 1
        return self.directory / f"{self.count:04d}-{name}"

    def save(self, name, value):
        SMOKE.private_json(self.artifact(name), value)

    def command(self, argv, data=None, timeout=120):
        path = self.artifact("command")
        with path.with_suffix(".stdout").open("xb") as stdout, path.with_suffix(".stderr").open("xb") as stderr:
            result = subprocess.run(argv, input=data, env=self.environment, stdout=stdout,
                                    stderr=stderr, timeout=timeout, check=False)
        require(result.returncode == 0, "command failed; inspect the private command files")
        require(path.with_suffix(".stdout").stat().st_size <= MAX_OUTPUT
                and path.with_suffix(".stderr").stat().st_size <= MAX_OUTPUT, "command output exceeds rehearsal bound")
        return path.with_suffix(".stdout").read_bytes()

    def kubectl(self, namespace, *arguments, **kwargs):
        return self.command(self.kube + (["-n", namespace] if namespace else []) + list(arguments), **kwargs)

    def obj(self, namespace, kind, name):
        return json.loads(self.kubectl(namespace, "get", kind, name, "-o", "json"))

    def wait(self, check, message, seconds=180):
        deadline = time.monotonic() + seconds
        while True:
            try:
                if check():
                    return
            except WorkerExclusionFailure:
                raise
            except (LifecycleFailure, HTTPS.VerificationError, OSError, http.client.HTTPException):
                pass
            require(time.monotonic() < deadline, message)
            time.sleep(2)

    def fingerprint(self):
        keys = self.secret_fingerprints()
        local_keys = {}
        for name in ("launcher-key.hex", "remote-grant-signing-key.hex", "https-edge/pki/root-key.pem",
                     "https-edge/pki/intermediate-key.pem", "https-edge/pki/root.pem"):
            data = SMOKE.private_read(self.args.state / name, limit=262144)
            local_keys[name] = hashlib.sha256(data).hexdigest()
        spool = self.command(["limactl", "shell", self.args.vm, "sudo", "tar", "-C",
                              "/var/lib/fleet-recall", "-cf", "-", "transcripts"])
        corefile = self.obj("kube-system", "configmap", "coredns")["data"]["Corefile"]
        begin, end = "# BEGIN fleet-recall HTTPS split DNS\n", "# END fleet-recall HTTPS split DNS\n"
        require(corefile.count(begin) == 1 and corefile.count(end) == 1, "managed Fleet split DNS block is missing")
        block = corefile.split(begin)[1].split(end)[0]
        service = self.obj("fleet-edge", "service", "fleet-edge")
        require(service["spec"]["clusterIP"] in block and all(name in block for name in
                ("recall.fleet.test", "auth.fleet.test", "login.fleet.test")), "Fleet split DNS differs from gateway Service")
        return {"secrets": keys, "local_keys": local_keys, "spool": spool_hashes(spool), "dns": digest(block),
                "revocations": self.revocation_fingerprint(),
                "cluster_uid": self.obj("", "namespace", "kube-system")["metadata"]["uid"]}

    def revocation_fingerprint(self):
        sql = ["docker", "run", "--rm", "-i", "--network", "host", "-v", f"{self.args.state}/certs:/certs:ro",
               "cockroachdb/cockroach:v26.2.3", "sql", "--certs-dir=/certs", "--host=127.0.0.1:26258",
               "--database=fleet_recall", "--format=csv"]
        # Both the plan and exact ordered CSV remain in private command files.
        self.command(sql, ("EXPLAIN " + REVOCATIONS_SQL).encode())
        return revoked_rows(self.command(sql, REVOCATIONS_SQL.encode()))

    def secret_fingerprints(self):
        return {namespace + "/" + name: CUTOVER.secret_fingerprint(self.obj(namespace, "secret", name)["data"])
                for namespace, names in CUTOVER.PROTECTED_SECRETS.items() for name in names}

    def no_sandboxes(self):
        require(not self.command(["docker", "ps", "-q", "--filter", "label=fleet-recall.launch=true"]).strip(),
                "stop Docker sandboxes through launch down first")
        pods = json.loads(self.kubectl("", "get", "pods", "-A", "-l", "app.kubernetes.io/managed-by=fleet-recall-launch", "-o", "json"))
        require(all(pod.get("status", {}).get("phase") in ("Succeeded", "Failed") for pod in pods["items"]),
                "stop Kubernetes sandboxes through launch down first")
        for path in self.args.state.rglob("launch-state.json"):
            launch = json.loads(SMOKE.private_read(path))
            require(not ((launch.get("runtime_started") and not launch.get("runtime_stopped"))
                    or any(not grant.get("revoked") for grant in launch.get("grants", []))),
                    "a retained launch still requires launch down")
        sql = ["docker", "run", "--rm", "-i", "--network", "host", "-v", f"{self.args.state}/certs:/certs:ro",
               "cockroachdb/cockroach:v26.2.3", "sql", "--certs-dir=/certs", "--host=127.0.0.1:26258",
               "--database=fleet_recall", "--format=tsv"]
        raw = self.command(sql, b"SELECT count(*) FROM memory_session_grants_v1 WHERE revoked_at IS NULL AND expires_at > now();")
        require(raw.decode().splitlines()[-1] == "0", "revoke all live session grants before lifecycle rehearsal")

    def preflight(self):
        uid = self.obj("", "namespace", "kube-system")["metadata"]["uid"]
        expected = CUTOVER.verify_backup(self.args.backup, self.args.state, uid)
        require(self.secret_fingerprints() == expected, "current protected keys differ from the authenticated checkpoint")
        vm_cluster = json.loads(self.command(["limactl", "shell", self.args.vm, "sudo", "k0s", "kubectl",
                                             "get", "namespace", "kube-system", "-o", "json"]))
        require(vm_cluster["metadata"]["uid"] == uid, "selected VM does not own this Kubernetes installation")
        self.no_sandboxes()
        current = self.obj("fleet-recall", "deployment", "recall")
        recall_container(current)
        if self.args.mode == "deploy":
            self.prepare_deploy(current)
        self.healthy()
        self.cron = self.obj("fleet-recall", "cronjob", "worker")
        require(self.cron["spec"].get("concurrencyPolicy") == "Forbid", "worker must forbid overlapping ticks")
        self.save("worker-before.json", self.cron)
        # Retain intent before a possibly ambiguous write timeout.
        self.suspended = True
        patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": self.cron["metadata"]["resourceVersion"]},
                 {"op": "add", "path": "/spec/suspend", "value": True}]
        self.kubectl("fleet-recall", "patch", "cronjob", "worker", "--type=json", "-p", json.dumps(patch))
        CUTOVER.drain_workers(self.kube, self.command, self.cron["metadata"]["uid"], self.directory)
        self.no_sandboxes()
        self.baseline = self.fingerprint()
        self.save("baseline.json", self.baseline)
        require(self.baseline["secrets"] == expected, "current protected keys differ from the authenticated checkpoint")

    def pod(self):
        items = json.loads(self.kubectl("fleet-recall", "get", "pods", "-l", "app=recall", "-o", "json"))["items"]
        active = [pod for pod in items if not pod["metadata"].get("deletionTimestamp")
                  and pod.get("status", {}).get("phase") == "Running"]
        require(len(active) == 1, "expected exactly one running Recall pod")
        return active[0]

    @contextmanager
    def forward(self, pod):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        path = self.artifact("port-forward.log")
        with path.open("xb") as output:
            process = subprocess.Popen(self.kube + ["-n", "fleet-recall", "port-forward", "--address=127.0.0.1",
                                       "pod/" + pod["metadata"]["name"], f"{port}:8080"], env=self.environment,
                                       stdout=output, stderr=subprocess.STDOUT)
            try:
                def connected():
                    require(process.poll() is None, "pod port-forward exited")
                    return self.probe(port, "/healthz")[0] == 200
                self.wait(connected, "pod port-forward did not become available", seconds=20)
                yield port
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)

    def probe(self, port, path):
        require(path in ("/healthz", "/readyz"), "only uncredentialed health probes may use loopback HTTP")
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            body = response.read(4097)
            require(len(body) <= 4096 and response.status in (200, 503), "unexpected or oversized pod probe")
            value = json.loads(body)
            self.save("probe.json", {"path": path, "status": response.status, "body": value})
            return response.status, value
        finally:
            connection.close()

    def ready(self):
        pod = self.pod()
        with self.forward(pod) as port:
            require(self.probe(port, self.ready_path)[0] == 200, "Recall pod is not ready")
        return True

    def tool(self, arguments, expected=200):
        body = json.dumps({"jsonrpc": "2.0", "id": self.count + 1, "method": "tools/call",
                           "params": {"name": "recall", "arguments": arguments}}).encode()
        status, headers, raw = self.client.request(self.args.url, "POST", {
            "Authorization": "Bearer " + self.token, "Content-Type": "application/json"}, body)
        require("location" not in headers, "authenticated request attempted a redirect")
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError) as error:
            self.save("mcp-invalid.json", {"status": status, "body_sha256": hashlib.sha256(raw).hexdigest()})
            raise LifecycleFailure("MCP returned a non-JSON response") from error
        self.save("mcp.json", {"status": status, "body": value})
        require(status == expected, "MCP response status differs from the expected fault outcome")
        if expected != 200:
            return value
        require(isinstance(value, dict) and "error" not in value and not value.get("result", {}).get("isError"),
                "MCP operation failed")
        result = value.get("result", {}).get("structuredContent")
        require(isinstance(result, dict) and isinstance(result.get("data"), dict), "MCP result lacks structured data")
        return result

    def claim(self):
        claim = self.tool({"action": "get", "kind": "claim", "id": self.args.claim_id})["data"].get("claim")
        require(isinstance(claim, dict) and str(claim.get("id")) == str(self.args.claim_id), "expected claim is unavailable")
        current = digest(claim)
        if self.claim_hash is None:
            self.claim_hash = current
        require(current == self.claim_hash, "claim content changed during rehearsal")
        return True

    def healthy(self):
        self.ready()
        status = self.tool({"action": "status"})["data"]
        require(status.get("status") == "ready" and status.get("embedding_tier", {}).get("status") == "ready",
                "Recall or embedding has not recovered")
        self.claim()
        response = self.client.request("https://auth.fleet.test:8443/.well-known/openid-configuration")
        require(HTTPS.json_object(response, "restored issuer").get("issuer") == "https://auth.fleet.test:8443/",
                "canonical issuer did not recover")
        code, headers, _ = self.client.request("https://login.fleet.test:8443/login")
        require(code == 200 or (code in (302, 303) and headers.get("location", "").startswith("https://login.fleet.test:8443/")),
                "canonical login did not recover")
        return True

    def restart(self, namespace, deployment):
        before = self.obj(namespace, "deployment", deployment)
        require(before["spec"].get("replicas") == 1, "restart target must have exactly one replica")
        self.kubectl(namespace, "rollout", "restart", "deployment/" + deployment)
        self.kubectl(namespace, "rollout", "status", "deployment/" + deployment, "--timeout=240s", timeout=250)
        self.events.append({"restart": namespace + "/" + deployment})

    def release_deployment(self, release):
        names = {"hydra": "hydra", "kratos": "kratos", "kratos-ui": "kratos-selfservice-ui-node"}
        require(release in names, "unknown Ory release")
        selector = "app.kubernetes.io/instance=" + release + ",app.kubernetes.io/name=" + names[release]
        items = json.loads(self.kubectl("ory", "get", "deployments", "-l", selector, "-o", "json"))["items"]
        items = [item for item in items if item["metadata"].get("labels", {}).get("app.kubernetes.io/instance") == release
                 and item["metadata"].get("labels", {}).get("app.kubernetes.io/name") == names[release]]
        require(len(items) == 1, "Ory release deployment is missing or ambiguous")
        return items[0]["metadata"]["name"]

    def scale_down(self, namespace, kind, name):
        resource = self.obj(namespace, kind, name)
        require(resource["spec"].get("replicas") == 1, "fault target must have exactly one replica")
        selector = resource["spec"]["selector"].get("matchLabels")
        require(selector and not resource["spec"]["selector"].get("matchExpressions"), "fault target needs exact labels")
        self.scaled.append((namespace, kind, name))
        self.kubectl(namespace, "scale", kind + "/" + name, "--replicas=0")
        self.kubectl(namespace, "wait", "--for=delete", "pod", "-l",
                     ",".join(key + "=" + value for key, value in sorted(selector.items())), "--timeout=150s", timeout=160)
        self.events.append({"stopped": namespace + "/" + name})

    def restore_dependencies(self):
        self.restore_worker_template()
        if self.vm_restart_pending:
            self.command(["limactl", "start", self.args.vm, "--tty=false"], timeout=360)
            self.vm_restart_pending = False
            def nodes_ready():
                nodes = json.loads(self.kubectl("", "get", "nodes", "-o", "json"))["items"]
                return bool(nodes) and all(any(condition.get("type") == "Ready" and condition.get("status") == "True"
                           for condition in node.get("status", {}).get("conditions", [])) for node in nodes)
            self.wait(nodes_ready, "Kubernetes API/nodes did not recover after VM start", seconds=240)
        for namespace, kind, name in reversed(self.scaled):
            self.kubectl(namespace, "scale", kind + "/" + name, "--replicas=1")
            self.kubectl(namespace, "rollout", "status", kind + "/" + name, "--timeout=240s", timeout=250)
        if self.rollback_restore:
            self.patch_image_probe(self.rollback_restore)
            self.ready_path = self.rollback_restore["readinessProbe"]["httpGet"]["path"]
        self.scaled.clear()
        self.rollback_restore = None

    def restore_worker_template(self):
        if self.worker_restore_spec is None:
            return
        current = self.obj("fleet-recall", "cronjob", "worker")
        require(current["metadata"]["uid"] == self.cron["metadata"]["uid"], "worker CronJob identity changed")
        patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
                 {"op": "add", "path": "/spec/suspend", "value": True}]
        patch += [{"op": "replace", "path": "/spec/" + name, "value": self.worker_restore_spec[name]}
                  for name in ("schedule", "jobTemplate")]
        self.kubectl("fleet-recall", "patch", "cronjob", "worker", "--type=json", "-p", json.dumps(patch))
        CUTOVER.drain_workers(self.kube, self.command, self.cron["metadata"]["uid"], self.directory)
        self.worker_restore_spec = None

    def worker_snapshot(self):
        items = json.loads(self.kubectl("fleet-recall", "get", "jobs,pods", "-o", "json"))["items"]
        jobs = [item for item in items if item["kind"] == "Job" and (
            owned(item, "CronJob", self.cron["metadata"]["uid"])
            or item["metadata"].get("labels", {}).get("app") == "worker"
            or item["spec"]["template"]["metadata"].get("labels", {}).get("app") == "worker")]
        job_ids = {item["metadata"]["uid"] for item in jobs}
        pods = [item for item in items if item["kind"] == "Pod" and (
            item["metadata"].get("labels", {}).get("app") == "worker"
            or any(owned(item, "Job", uid) for uid in job_ids))
            and item.get("status", {}).get("phase") not in ("Succeeded", "Failed")]
        active = [item for item in jobs if not terminal_job(item) or item.get("status", {}).get("active", 0)]
        require_worker(len(active) <= 1 and len(pods) <= 1, "overlapping worker Jobs or pods observed")
        return jobs, active, pods

    def exclusion_events(self):
        items = json.loads(self.kubectl("fleet-recall", "get", "events", "--field-selector",
                         "involvedObject.uid=" + self.cron["metadata"]["uid"], "-o", "json"))["items"]
        result = {}
        for item in items:
            if item.get("involvedObject", {}).get("uid") != self.cron["metadata"]["uid"] or item.get("reason") != "JobAlreadyActive":
                continue
            series = item.get("series") or {}
            last = series.get("lastObservedTime") or item.get("lastTimestamp") or item.get("eventTime")
            result[item["metadata"]["uid"]] = {"count": series.get("count") or item.get("count", 1), "last": timestamp(last)}
        return result

    def worker_exclusion(self):
        current = self.obj("fleet-recall", "cronjob", "worker")
        require(current["metadata"]["uid"] == self.cron["metadata"]["uid"]
                and current["spec"].get("suspend") is True
                and current["spec"].get("concurrencyPolicy") == "Forbid", "worker exclusion needs the paused original Forbid CronJob")
        for name in ("schedule", "jobTemplate"):
            require(current["spec"][name] == self.cron["spec"][name], "worker configuration changed after preflight")
        jobs, active, pods = self.worker_snapshot()
        require(not active and not pods, "worker exclusion requires a drained worker")
        before_ids = {item["metadata"]["uid"] for item in jobs}
        previous_events = self.exclusion_events()
        template = copy.deepcopy(current["spec"]["jobTemplate"])
        pod_spec = template["spec"]["template"]["spec"]
        require(pod_spec.get("restartPolicy") == "Never" and template["spec"].get("backoffLimit") == 0,
                "worker proof requires one attempt without restart")
        images = [item["image"] for item in pod_spec.get("initContainers", []) if item["name"] == "prepare-metrics"]
        require(len(images) == 1 and images[0] in ("busybox:1.37.0", "docker.io/library/busybox:1.37.0"),
                "worker proof requires the installed BusyBox init image")
        require(all(item["name"] != "lifecycle-hold" for item in pod_spec.get("initContainers", [])), "worker already has a hold init")
        hold = {"name": "lifecycle-hold", "image": images[0], "imagePullPolicy": "IfNotPresent", "command": ["sleep", "150"],
                "securityContext": {"runAsUser": 10001, "runAsGroup": 10001, "runAsNonRoot": True,
                                    "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}},
                "resources": {"requests": {"cpu": "1m", "memory": "4Mi"}, "limits": {"cpu": "10m", "memory": "8Mi"}}}
        pod_spec["initContainers"] = [hold] + pod_spec.get("initContainers", [])
        self.worker_restore_spec = copy.deepcopy(current["spec"])
        patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
                 {"op": "replace", "path": "/spec/schedule", "value": "* * * * *"},
                 {"op": "replace", "path": "/spec/jobTemplate", "value": template},
                 {"op": "add", "path": "/spec/suspend", "value": False}]
        self.kubectl("fleet-recall", "patch", "cronjob", "worker", "--type=json", "-p", json.dumps(patch))
        proof = {}

        def held():
            observed, active, pods = self.worker_snapshot()
            new = [item for item in observed if item["metadata"]["uid"] not in before_ids]
            require_worker(len(new) <= 1, "more than one worker Job was created during exclusion proof")
            if not active or not pods:
                return False
            job, pod = active[0], pods[0]
            uid = job["metadata"]["uid"]
            require_worker(uid not in before_ids and owned(job, "CronJob", self.cron["metadata"]["uid"])
                    and owned(pod, "Job", uid), "worker proof lost controller ownership")
            require_worker(not terminal_job(job) and not pod["metadata"].get("deletionTimestamp"), "held worker terminated early")
            require_worker(job["spec"]["template"]["spec"]["containers"] == pod_spec["containers"], "worker process configuration changed")
            cron = self.obj("fleet-recall", "cronjob", "worker")
            tracked = {item["uid"] for item in cron.get("status", {}).get("active", [])}
            require_worker(tracked <= {uid}, "CronJob tracks overlapping worker Jobs")
            if tracked != {uid}:
                return False
            statuses = pod.get("status", {}).get("initContainerStatuses", [])
            running = [item["state"]["running"] for item in statuses if item["name"] == "lifecycle-hold" and "running" in item.get("state", {})]
            if not running:
                require_worker(not proof, "worker hold ended before two scheduling refusals")
                return False
            require_worker(all("running" not in item.get("state", {}) and "terminated" not in item.get("state", {})
                        and item.get("restartCount", 0) == 0 for item in pod.get("status", {}).get("containerStatuses", [])),
                    "worker process started before exclusion proof completed")
            identity = {"job_name": job["metadata"]["name"], "job_uid": uid, "pod_uid": pod["metadata"]["uid"],
                        "started": timestamp(running[0]["startedAt"])}
            require_worker(not proof or proof == identity, "worker Job or pod changed during exclusion proof")
            proof.update(identity)
            return True

        self.wait(held, "controller did not start and track the held worker", seconds=100)
        boundaries = [int(proof["started"] // 60) * 60 + offset for offset in (60, 120)]
        event_count = 0
        for boundary in boundaries:
            def refused():
                nonlocal event_count
                require_worker(held(), "held worker became unavailable")
                events = self.exclusion_events()
                delta = sum(max(0, item["count"] - previous_events.get(uid, {}).get("count", 0)) for uid, item in events.items())
                if delta <= event_count or not any(item["last"] >= boundary for item in events.values()):
                    return False
                event_count = delta
                return True
            self.wait(refused, "controller did not refuse both overlapping scheduled ticks", seconds=75)
        self.save("worker-exclusion.json", {**proof, "scheduled_boundaries": boundaries, "forbid_events": event_count})
        # Stop new scheduling and restore the template before the init releases;
        # the already-created Job then runs the unmodified worker to completion.
        self.restore_worker_template()
        finished = self.obj("fleet-recall", "job", proof["job_name"])
        require(finished["metadata"]["uid"] == proof["job_uid"] and finished.get("status", {}).get("succeeded") == 1
                and any(item.get("type") == "Complete" and item.get("status") == "True"
                        for item in finished.get("status", {}).get("conditions", [])), "real worker tick did not complete successfully")
        self.no_sandboxes()
        self.events.append({"worker_exclusion": "two_scheduled_ticks_refused_then_worker_succeeded", **proof})

    def patch_image_probe(self, values):
        current = self.obj("fleet-recall", "deployment", "recall")
        index, _ = recall_container(current)
        patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]}]
        patch += [{"op": "replace", "path": f"/spec/template/spec/containers/{index}/{key}", "value": values[key]}
                  for key in ("image", "readinessProbe")]
        self.kubectl("fleet-recall", "patch", "deployment", "recall", "--type=json", "-p", json.dumps(patch))
        self.kubectl("fleet-recall", "rollout", "status", "deployment/recall", "--timeout=240s", timeout=250)

    def prepare_deploy(self, current):
        _, old = recall_container(current)
        probe = old.get("readinessProbe", {}).get("httpGet", {})
        require(probe.get("path") in ("/healthz", "/readyz") and probe.get("port") in ("mcp", 8080),
                "existing Recall readiness probe is not a supported HTTP probe")
        require(old["image"] != self.args.image, "deploy proof requires a different selected image")
        # A local image must be present wherever the singleton can be scheduled.
        nodes = json.loads(self.kubectl("", "get", "nodes", "-o", "json"))["items"]
        eligible = [node for node in nodes if not node.get("spec", {}).get("unschedulable", False)]
        names = {self.args.image, "docker.io/library/" + self.args.image}
        require(eligible and all(any(names.intersection(image.get("names", []))
                    for image in node.get("status", {}).get("images", [])) for node in eligible),
                "import the selected local image into every schedulable node first")
        self.deploy_values = {"image": self.args.image, "readinessProbe": deployment_probe()}
        self.deployment_before = copy.deepcopy(current)
        SMOKE.private_json(self.directory / "deployment-before.json", current)
        self.ready_path = probe["path"]

    def exercise(self):
        mode = self.args.mode
        if mode == "worker-exclusion":
            self.worker_exclusion()
        elif mode == "deploy":
            require(self.deploy_values is not None, "deploy mode requires a successful preparation gate")
            current = self.obj("fleet-recall", "deployment", "recall")
            require(self.deployment_before is not None
                    and current["metadata"].get("uid") == self.deployment_before["metadata"].get("uid")
                    and current["spec"] == self.deployment_before["spec"],
                    "Recall deployment changed after the preparation gate")
            _, container = recall_container(current)
            self.rollback_restore = {key: copy.deepcopy(container[key]) for key in ("image", "readinessProbe")}
            self.save("deployment-restore.json", self.rollback_restore)
            self.patch_image_probe(self.deploy_values)
            self.ready_path = "/readyz"
            self.wait(self.healthy, "new deployment failed readiness/authentication acceptance", seconds=180)
            after = self.fingerprint()
            self.save("deployment-after.json", after)
            require(after == self.baseline, "deployment changed protected keys, revocations, DNS, or spool")
            # The new image passed every acceptance gate. Recovery still verifies
            # health/preservation before restoring the original worker schedule.
            self.rollback_restore = None
            self.events.append({"deployment": "accepted", "image": self.deploy_values["image"]})
        elif mode == "restart":
            self.restart("fleet-recall", "recall")
            self.wait(self.healthy, "Recall restart did not recover through the HTTPS edge", seconds=120)
            for release in ("hydra", "kratos", "kratos-ui"):
                self.restart("ory", self.release_deployment(release))
                self.wait(self.healthy, "Ory restart did not recover", seconds=120)
        elif mode == "db-outage":
            pod = self.pod()
            counts = {container["name"]: container["restartCount"] for container in pod["status"]["containerStatuses"]}
            with self.forward(pod) as port:
                self.scale_down("fleet-recall", "statefulset", "cockroach")
                self.wait(lambda: self.probe(port, "/readyz")[0] == 503, "DB outage did not remove readiness", seconds=30)
                require(self.probe(port, "/healthz")[0] == 200, "DB outage broke process liveness")
                def withdrawn():
                    current = self.obj("fleet-recall", "pod", pod["metadata"]["name"])
                    require(current["metadata"]["uid"] == pod["metadata"]["uid"] and counts == {
                        item["name"]: item["restartCount"] for item in current["status"]["containerStatuses"]},
                        "Recall restarted during database outage")
                    return any(item["type"] == "Ready" and item["status"] == "False" for item in current["status"].get("conditions", []))
                self.wait(withdrawn, "Kubernetes did not withdraw the unready pod", seconds=30)
                def endpoint_withdrawn():
                    slices = json.loads(self.kubectl("fleet-recall", "get", "endpointslices", "-l",
                                                   "kubernetes.io/service-name=recall", "-o", "json"))
                    endpoints = [endpoint for item in slices["items"] for endpoint in item.get("endpoints", [])
                                 if endpoint.get("targetRef", {}).get("uid") == pod["metadata"]["uid"]]
                    return all(endpoint.get("conditions", {}).get("ready") is False for endpoint in endpoints)
                self.wait(endpoint_withdrawn, "Recall Service still routes to the unready pod", seconds=30)
                self.events.append({"db_outage": "ready503_live200_no_restart", "pod_uid": pod["metadata"]["uid"]})
        elif mode == "embed-outage":
            self.scale_down("fleet-recall", "deployment", "embed")
            self.wait(self.lexical_only, "embedding outage did not retain lexical service", seconds=120)
            self.restart("fleet-recall", "recall")
            self.wait(self.lexical_only, "restarted Recall did not retain lexical service", seconds=120)
        elif mode == "issuer-outage":
            # Force a new cache and immediately warm exactly the provided token's key.
            self.restart("fleet-recall", "recall")
            self.wait(self.claim, "issuer proof could not warm the restarted Recall key cache", seconds=120)
            self.scale_down("ory", "deployment", self.release_deployment("hydra"))
            self.wait(self.claim, "warmed token failed during the bounded issuer outage", seconds=120)
            self.ready()
            self.restart("fleet-recall", "recall")
            self.ready()
            def cold_refused():
                result = self.tool({"action": "get", "kind": "claim", "id": self.args.claim_id}, expected=503)
                require(result == {"error": "identity_provider_unavailable"}, "cold issuer outage did not fail with the fixed safe code")
                return True
            self.wait(cold_refused, "cold issuer outage did not fail safely through the HTTPS edge", seconds=120)
            self.events.append({"issuer_outage": "warm_cache_accepted_cold_cache_refused"})
        elif mode == "vm-restart":
            self.vm_restart_pending = True
            self.command(["limactl", "stop", self.args.vm, "--tty=false"], timeout=180)
            self.restore_dependencies()
            self.wait(self.healthy, "VM restart did not recover canonical DNS/TLS/authentication", seconds=240)
            self.events.append({"vm_restart": "recovered"})
        elif mode == "rollback":
            current = self.obj("fleet-recall", "deployment", "recall")
            saved = json.loads(SMOKE.private_read(self.args.rollback_deployment_file, limit=1024 * 1024))
            values = rollback_values(saved, current, self.args.url)
            _, container = recall_container(current)
            self.rollback_restore = {key: copy.deepcopy(container[key]) for key in ("image", "readinessProbe")}
            self.save("rollback-restore.json", self.rollback_restore)
            self.patch_image_probe(values)
            self.ready_path = values["readinessProbe"]["httpGet"]["path"]
            # The previous binary may predate /readyz; its successful deployment
            # probe plus authenticated reads qualify the old image only.
            self.wait(self.healthy, "previous image did not recover authenticated serving", seconds=120)
            self.events.append({"rollback": "previous_image_authenticated_read", "image": values["image"]})

    def lexical_only(self):
        self.ready()
        status = self.tool({"action": "status"})["data"]
        require(status.get("embedding_tier", {}).get("status") == "degraded", "embedding outage was not reported")
        self.claim()
        result = self.tool({"action": "search", "query": self.args.query, "limit": 10})
        require(result["data"].get("hits") and result.get("diagnostics", {}).get("retrieval", {}).get("lanes") == ["lexical"]
                and any(item.get("code") == "query_not_embedded" for item in result.get("warnings", [])),
                "embedding outage did not preserve verified lexical results")
        self.events.append({"embedding_outage": "degraded_lexical_hits_ready200"})
        return True

    def recover(self):
        """Always restore dependencies; restore worker only after all evidence gates."""
        self.restore_dependencies()
        if not self.suspended:
            return
        self.wait(self.healthy, "restored deployment failed its health/authentication gates", seconds=180)
        require(self.baseline is not None, "baseline was not established; worker remains suspended for inspection")
        after = self.fingerprint()
        self.save("after.json", after)
        require(after == self.baseline, "protected keys, revocations, DNS, or spool changed; worker remains suspended")
        current = self.obj("fleet-recall", "cronjob", "worker")
        require(current["metadata"]["uid"] == self.cron["metadata"]["uid"], "worker CronJob identity changed")
        patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
                 {"op": "add", "path": "/spec/suspend", "value": self.cron["spec"].get("suspend", False)}]
        self.kubectl("fleet-recall", "patch", "cronjob", "worker", "--type=json", "-p", json.dumps(patch))
        self.suspended = False


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--ca-path", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--claim-id", type=int, required=True)
    parser.add_argument("--query", required=True, help="Words known to match an existing indexed chunk")
    parser.add_argument("--url", default="https://recall.fleet.test:8443/mcp")
    parser.add_argument("--vm", default="k0s")
    parser.add_argument("--rollback-deployment-file", type=Path)
    parser.add_argument("--image", help="Deploy mode: installed local ostk-fleet-recall image tag")
    args = parser.parse_args(argv)
    require(args.url == "https://recall.fleet.test:8443/mcp", "local lifecycle rehearsal requires the canonical HTTPS resource")
    require(0 < args.claim_id <= 9007199254740991 and 0 < len(args.query.strip()) <= 4096, "invalid claim or lexical query")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", args.vm), "invalid Lima VM name")
    require((args.mode == "rollback") == (args.rollback_deployment_file is not None), "rollback mode alone requires --rollback-deployment-file")
    require((args.mode == "deploy") == (args.image is not None), "deploy mode alone requires --image")
    if args.image is not None:
        require(re.fullmatch(r"ostk-fleet-recall:[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", args.image), "image must name a local ostk-fleet-recall tag")
    args.state = args.state.resolve(strict=True)
    return args


def main():
    args = arguments()
    os.umask(0o077)
    directory = args.state / ("lifecycle-" + args.mode + "-" + time.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(4))
    directory.mkdir(mode=0o700)
    lock_dir = args.state / "sandbox-smoke"
    lock_dir.mkdir(mode=0o700, exist_ok=True)
    failures, smoke = [], None
    def interrupted(_signum, _frame):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    with os.fdopen(os.open(lock_dir / "worker.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            smoke = Lifecycle(args, directory)
            smoke.preflight()
            smoke.exercise()
        except (Exception, KeyboardInterrupt) as error:
            failures.append({"phase": "exercise", "type": type(error).__name__,
                             "detail": str(error) if isinstance(error, LifecycleFailure) else "see private command evidence"})
        finally:
            if smoke:
                try:
                    with SMOKE.cleanup_signals():
                        smoke.recover()
                except Exception as error:
                    failures.append({"phase": "recovery", "type": type(error).__name__,
                                     "detail": str(error) if isinstance(error, LifecycleFailure) else "see private command evidence"})
    SMOKE.private_json(directory / "result.json", {"mode": args.mode, "passed": not failures,
                       "events": smoke.events if smoke else [], "worker_suspended": smoke.suspended if smoke else None,
                       "failures": failures})
    print(("FAIL" if failures else "PASS") + " lifecycle rehearsal; private evidence: " + str(directory), flush=True)
    return int(bool(failures))


if __name__ == "__main__":
    sys.exit(main())
