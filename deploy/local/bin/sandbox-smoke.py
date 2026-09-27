#!/usr/bin/env python3
"""Run the synthetic M3 sandbox proof on Docker, Kubernetes, or both.

Requires an already deployed M3 plane and sandbox images in both runtimes.
All command output, credentials, responses, and recovery coordinates stay in
private local state. Launches are stopped and grants revoked even after failure.
The worker CronJob is suspended under a local lock, existing ticks are drained,
and its original suspension state is restored. Test Jobs are not deleted.
"""

import argparse
import base64
from contextlib import contextmanager
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid


class SmokeFailure(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def private_bytes(path, data):
    with path.open("xb") as output:
        output.write(data)


def private_json(path, value):
    private_bytes(path, (json.dumps(value, indent=2) + "\n").encode())


def private_read(path, limit=65536):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and not stat.S_IMODE(metadata.st_mode) & 0o077,
                "credential/state file must be regular and private")
        data = source.read(limit + 1)
        require(len(data) <= limit, "private file exceeds size bound")
        return data


def finished(job):
    return any(condition.get("status") == "True" and condition.get("type") in
               {"Complete", "Failed"} for condition in job.get("status", {}).get("conditions", []))


@contextmanager
def cleanup_signals():
    """Let bounded revocation and schedule restoration finish on first signal."""
    previous = {number: signal.signal(number, signal.SIG_IGN)
                for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


class Smoke:
    def __init__(self, args, directory):
        self.args, self.directory, self.count = args, directory, 0
        self.environment = {key: os.environ[key] for key in
                            ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG")
                            if key in os.environ}
        self.environment["KUBECONFIG"] = str(args.state / "kubeconfig")
        key = private_read(args.state / "launcher-key.hex").decode().strip()
        require(re.fullmatch(r"[0-9a-f]{64}", key), "invalid launcher key file")
        self.launch_environment = dict(self.environment, FLEET_RECALL_LAUNCHER_KEY_HEX=key)
        self.kube = ["kubectl", "--request-timeout=30s", "-n", args.namespace]
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.cronjob = None
        self.worker_job = None
        self.suspended = False

    def artifact(self, name):
        self.count += 1
        return self.directory / f"{self.count:04d}-{name}"

    def command(self, argv, *, data=None, timeout=60, launch=False, check=True):
        path = self.artifact("command")
        with path.with_suffix(".stdout").open("xb") as stdout, path.with_suffix(".stderr").open("xb") as stderr:
            result = subprocess.run(argv, input=data, stdout=stdout, stderr=stderr,
                                    env=self.launch_environment if launch else self.environment,
                                    timeout=timeout, check=False)
        require(not check or result.returncode == 0, "command failed; see private output")
        require(path.with_suffix(".stdout").stat().st_size <= 8 * 1024 * 1024,
                "command response exceeds proof size bound")
        return result.returncode, path.with_suffix(".stdout").read_bytes()

    def kubectl(self, *arguments, **kwargs):
        return self.command(self.kube + list(arguments), **kwargs)

    def object(self, kind, name):
        return json.loads(self.kubectl("get", kind, name, "-o", "json")[1])

    def http(self, token, *, path=None, headers=None, message=None):
        request_headers = {"Authorization": "Bearer " + token, **(headers or {})}
        body = None
        if message is not None:
            request_headers["Content-Type"] = "application/json"
            body = json.dumps(message).encode()
        endpoint = self.args.url
        if path is not None:
            parsed = urlsplit(endpoint)
            endpoint = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        request = Request(endpoint, data=body, headers=request_headers)
        try:
            response = self.opener.open(request, timeout=40)
        except HTTPError as error:
            response = error
        with response:
            raw = response.read(2 * 1024 * 1024 + 1)
            require(len(raw) <= 2 * 1024 * 1024, "HTTP response exceeds bound")
            value = json.loads(raw) if raw else None
            private_json(self.artifact("http.json"), {"status": response.status, "body": value})
            return response.status, value

    def tool(self, token, arguments, *, check=True):
        status, body = self.http(token, message={"jsonrpc": "2.0", "id": self.count + 1,
            "method": "tools/call", "params": {"name": "recall", "arguments": arguments}})
        if not check:
            return status, body
        require(status == 200 and isinstance(body, dict) and "error" not in body
                and not body.get("result", {}).get("isError"), "Recall operation failed")
        return body["result"]["structuredContent"]

    def suspend_worker(self):
        cron = self.object("cronjob", self.args.worker)
        require(cron["spec"].get("concurrencyPolicy") == "Forbid", "worker must forbid overlapping ticks")
        self.cronjob = cron
        private_json(self.directory / "cronjob-before.json", cron)
        config = self.object("configmap", "fleet-env")["data"]
        require(config["FLEET_RECALL_TENANT_ID"] == self.args.tenant
                and config["FLEET_RECALL_PROJECT"] == self.args.project,
                "requested scope does not match installed worker scope")
        patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": cron["metadata"]["resourceVersion"]},
                 {"op": "add", "path": "/spec/suspend", "value": True}]
        # Record intent before the request, including the ambiguous timeout case.
        self.suspended = True
        self.kubectl("patch", "cronjob", self.args.worker, "--type=json", "-p", json.dumps(patch))
        deadline = time.monotonic() + self.args.worker_timeout
        while True:
            jobs = json.loads(self.kubectl("get", "jobs", "-o", "json")[1])["items"]
            active = [job for job in jobs if not finished(job) and any(
                owner.get("uid") == cron["metadata"]["uid"]
                for owner in job["metadata"].get("ownerReferences", []))]
            if not active:
                return
            require(time.monotonic() < deadline, "existing worker tick did not drain")
            time.sleep(3)

    def restore_worker(self):
        if not self.suspended:
            return
        for _ in range(4):
            current = self.object("cronjob", self.args.worker)
            require(current["metadata"]["uid"] == self.cronjob["metadata"]["uid"],
                    "worker was replaced during smoke; refusing to overwrite its schedule")
            original = self.cronjob["spec"]
            if current["spec"].get("suspend") is not True:
                require(current["spec"].get("suspend", False) == original.get("suspend", False),
                        "worker suspension changed externally")
                self.suspended = False
                return
            operation = {"op": "replace", "path": "/spec/suspend", "value": original["suspend"]} if "suspend" in original else {"op": "remove", "path": "/spec/suspend"}
            patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]}, operation]
            status, _ = self.kubectl("patch", "cronjob", self.args.worker, "--type=json", "-p", json.dumps(patch), check=False)
            if status == 0:
                restored = self.object("cronjob", self.args.worker)
                private_json(self.directory / "cronjob-restored.json", restored)
                require(restored["spec"].get("suspend", False) == original.get("suspend", False),
                        "worker suspension restoration failed")
                self.suspended = False
                return
        raise SmokeFailure("worker suspension restoration conflicted; saved original state is private")

    def launch_tokens(self, backend, state_path, name):
        result = {}
        for kind in ("agent", "shipper"):
            if backend == "docker":
                values = dict(line.split("=", 1) for line in private_read(state_path.parent / f"{kind}.env").decode().splitlines())
                token = values["FLEET_RECALL_TOKEN"]
            else:
                value = self.object("secret", name + f"-{kind}-env")
                token = base64.b64decode(value["data"]["FLEET_RECALL_TOKEN"], validate=True).decode()
            require(token and len(token) <= 16384 and token.isascii() and token.isprintable(), "invalid grant token")
            result[kind] = token
        return result

    def wait_synthetic(self, backend, name, instance):
        deadline = time.monotonic() + self.args.timeout + 180
        while True:
            if backend == "docker":
                state = json.loads(self.command(["docker", "inspect", "--format", "{{json .State}}", name])[1])
                exit_code = state["ExitCode"] if state["Status"] in {"exited", "dead"} else None
            else:
                pod = self.object("pod", name)
                state = next((item["state"] for item in pod.get("status", {}).get("containerStatuses", []) if item["name"] == "agent"), {})
                exit_code = state.get("terminated", {}).get("exitCode")
            if exit_code is not None:
                logs = self.command(["docker", "logs", "--tail", "100", name])[1] if backend == "docker" else self.kubectl("logs", name, "-c", "agent", "--tail=100")[1]
                require(exit_code == 0, "synthetic harness failed")
                summaries = []
                for line in logs.splitlines():
                    try:
                        summaries.append(json.loads(line))
                    except ValueError:
                        pass
                require(any(isinstance(item, dict) and item.get("harness") == "synthetic"
                            and item.get("exit_code") == 0 and item.get("instance") == instance
                            for item in summaries), "missing successful synthetic harness summary")
                return
            require(time.monotonic() < deadline, "synthetic harness did not terminate")
            time.sleep(2)

    def wait_spool(self, instance, agent):
        # Only reads the exact configured scope and this launch's manifest/body.
        # User values are positional parameters, never interpolated shell code.
        script = '''for f in "$1"/*.jsonl.meta; do
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  if grep -F -q -- "\\\"sandbox_id\\\":\\\"$2\\\"" "$f"; then
    head -c 65536 "$f"; printf '\\n'
    [ ! -L "${f%.meta}" ] || exit 2
    head -c 1048577 "${f%.meta}"; exit
  fi
done'''
        path = f"{self.args.spool}/{self.args.tenant}/{self.args.project}/claude-code"
        deadline = time.monotonic() + 180
        expected = f"Synthetic sandbox {instance} listed tools, checked status, and recorded and recalled claim "
        while True:
            _, raw = self.kubectl("exec", "deployment/" + self.args.receiver, "-c", "recall", "--", "/bin/sh", "-c", script, "sandbox-smoke", path, instance)
            if raw:
                manifest_line, _, transcript = raw.partition(b"\n")
                manifest = json.loads(manifest_line)
                require(manifest["sandbox_id"] == instance and manifest["agent"] == agent
                        and manifest["tenant_id"] == self.args.tenant and manifest["project"] == self.args.project,
                        "spool provenance differs from grant scope")
                require(len(transcript) <= 1024 * 1024, "synthetic transcript unexpectedly large")
                if transcript.endswith(b"\n"):
                    records = [json.loads(line) for line in transcript.splitlines() if line]
                    texts = [block["text"] for record in records if record.get("type") == "assistant"
                             for block in record.get("message", {}).get("content", []) if block.get("type") == "text"]
                    matches = [text for text in texts if text.startswith(expected)]
                    if matches:
                        require(len(matches) == 1, "synthetic completion turn is ambiguous")
                        claim = matches[0][len(expected):].removesuffix(".")
                        require(re.fullmatch(r"[1-9][0-9]{0,18}", claim)
                                and int(claim) <= 9223372036854775807, "synthetic claim ID is malformed")
                        claim = int(claim)
                        first = hashlib.sha256(transcript.splitlines(keepends=True)[0]).hexdigest()
                        require(first == manifest["first_line_sha256"], "spool first-line digest mismatch")
                        private_bytes(self.artifact("transcript.jsonl"), transcript)
                        private_json(self.artifact("manifest.json"), manifest)
                        return manifest, transcript, matches[0], claim
            require(time.monotonic() < deadline, "completed synthetic turn was not shipped")
            time.sleep(2)

    @staticmethod
    def receiver_request(manifest):
        fields = ["transcript-spool-v1", manifest["sandbox_id"], manifest["format"], manifest["source"], manifest["first_line_sha256"]]
        name = hashlib.sha256(b"".join(value.encode() + b"\0" for value in fields)).hexdigest() + ".jsonl"
        path = "/v1/transcripts/" + manifest["sandbox_id"] + "/" + name + "?offset=0"
        headers = {"x-transcript-source": base64.urlsafe_b64encode(manifest["source"].encode()).decode().rstrip("="),
                   "x-transcript-format": manifest["format"], "x-transcript-first-line-sha256": manifest["first_line_sha256"]}
        return path, headers

    def worker_tick(self, backend):
        cron = self.object("cronjob", self.args.worker)
        require(cron["spec"].get("suspend") is True, "worker schedule resumed during smoke")
        name = "sandbox-smoke-" + backend[:1] + "-" + secrets.token_hex(6)
        job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {
            "name": name, "namespace": self.args.namespace,
            "labels": {"fleet-recall.dev/smoke": self.directory.name},
            # Forbid also protects against overlap if cleanup resumes the CronJob
            # after a lost API response while this bounded Job remains active.
            "ownerReferences": [{"apiVersion": "batch/v1", "kind": "CronJob",
                "name": self.args.worker, "uid": cron["metadata"]["uid"], "controller": True}]},
            "spec": copy.deepcopy(cron["spec"]["jobTemplate"]["spec"])}
        job["spec"].update(activeDeadlineSeconds=self.args.worker_timeout, backoffLimit=0)
        job["spec"].pop("ttlSecondsAfterFinished", None)
        worker = next(container for container in job["spec"]["template"]["spec"]["containers"] if container["name"] == "worker")
        require("ingest,project,embed" in worker.get("args", []), "worker must run ingest,project,embed")
        private_json(self.artifact("worker-job.json"), job)
        self.worker_job = name
        self.kubectl("create", "-f", "-", data=json.dumps(job).encode())
        deadline = time.monotonic() + self.args.worker_timeout + 90
        while True:
            current = self.object("job", name)
            if finished(current):
                self.kubectl("logs", "job/" + name, "--all-containers=true", "--tail=500", check=False)
                require(any(c.get("type") == "Complete" and c.get("status") == "True" for c in current["status"]["conditions"]), "scope worker Job failed")
                return name
            require(time.monotonic() < deadline, "scope worker Job exceeded its deadline")
            time.sleep(3)

    def evidence(self, token, instance, expected):
        deadline = time.monotonic() + 90
        while True:
            found = self.tool(token, {"action": "search", "kind": "evidence", "source": "sessions",
                                      "query": instance, "limit": 20})
            matches = [hit for hit in found["data"]["hits"] if instance in hit.get("snippet", "")]
            for hit in matches:
                body = self.tool(token, {"action": "get", "kind": "evidence", "id": hit["id"]})
                evidence = body["data"].get("evidence")
                if evidence and expected in evidence.get("text", ""):
                    return hit["id"]
            require(time.monotonic() < deadline, "Recall evidence did not return the unique synthetic completion turn")
            time.sleep(3)

    def cleanup_launch(self, launch_dir, tokens, receiver):
        cleanup_errors = []
        for path in launch_dir.glob("*/launch-state.json"):
            try:
                # Kubernetes may use 210s to stop the Pod, 10s for Secrets,
                # followed by two bounded HTTP revocations. Retain ample margin.
                self.command([str(self.args.bin), "launch", "down", "--state", str(path)], timeout=420, launch=True)
                stopped = json.loads(private_read(path))
                require((not stopped["runtime_started"] or stopped["runtime_stopped"])
                        and all(grant["revoked"] for grant in stopped["grants"]), "launch cleanup did not revoke grants and stop runtime")
            except Exception as error:
                cleanup_errors.append(type(error).__name__ + ": " + str(error))
        if tokens and receiver:
            time.sleep(6)  # exceeds the five-second grant verification cache
            try:
                require(self.tool(tokens["agent"], {"action": "status"}, check=False)[0] == 401,
                        "revoked agent grant did not return 401")
                require(self.http(tokens["shipper"], path=receiver[0], headers=receiver[1])[0] == 401,
                        "revoked shipper grant did not return 401")
            except Exception as error:
                cleanup_errors.append(type(error).__name__ + ": " + str(error))
        if cleanup_errors:
            private_json(self.artifact("cleanup-errors.json"), cleanup_errors)
            raise SmokeFailure("cleanup or grant replay proof failed")

    def backend(self, backend):
        launch_dir = self.directory / backend
        launch_dir.mkdir(mode=0o700)
        agent = "sandbox-smoke-" + secrets.token_hex(8)
        sandbox_url = self.args.docker_url if backend == "docker" else self.args.kubernetes_url
        anchor = ["--anchor", "local-key", "--key-id", "launcher"]
        if backend == "kubernetes":
            _, projected = self.kubectl("create", "token", "launcher", "--audience=" + (self.args.resource_url or self.args.url), "--duration=1h")
            token_path = launch_dir / "launcher-service-account.jwt"
            private_bytes(token_path, projected)
            anchor = ["--anchor", "kubernetes", "--service-account-token-file", str(token_path)]
        argv = [str(self.args.bin), "launch", "up", "--backend", backend, *anchor,
                "--scope", self.args.tenant + "/" + self.args.project,
                "--agent", agent, "--image", self.args.image, "--url", self.args.url,
                "--resource-url", self.args.resource_url or self.args.url, "--sandbox-url", sandbox_url,
                "--harness", "synthetic", "--timeout-seconds", str(self.args.timeout),
                "--ttl-seconds", "3600", "--state-dir", str(launch_dir), "--namespace", self.args.namespace]
        if self.args.shipper_image:
            argv += ["--shipper-image", self.args.shipper_image]
        if self.args.runtime_class and backend == "kubernetes":
            argv += ["--runtime-class", self.args.runtime_class]
        tokens, receiver, result = None, None, None
        try:
            self.command(argv, timeout=300, launch=True)
            files = list(launch_dir.glob("*/launch-state.json"))
            require(len(files) == 1, "missing or ambiguous launch state")
            state = json.loads(private_read(files[0]))
            name = state["handle"]["name"]
            instance = str(uuid.UUID(name.removeprefix("recall-")))
            require(name == "recall-" + instance and len(state["grants"]) == 2, "invalid launch identity")
            tokens = self.launch_tokens(backend, files[0], name)
            self.wait_synthetic(backend, name, instance)
            manifest, transcript, expected, claim = self.wait_spool(instance, agent)
            receiver = self.receiver_request(manifest)
            status, progress = self.http(tokens["shipper"], path=receiver[0], headers=receiver[1])
            require(status == 200 and progress["length"] == len(transcript), "receiver length did not match durable spool")
            self.tool(tokens["agent"], {"action": "status"})
            recalled = self.tool(tokens["agent"], {"action": "get", "kind": "claim", "id": claim})
            require(recalled["data"]["claim"]["id"] == claim, "synthetic recorded claim did not round trip")
            job = self.worker_tick(backend)
            evidence = self.evidence(tokens["agent"], instance, expected)
            result = {"backend": backend, "instance": instance, "agent": agent,
                      "claim_id": claim, "evidence_id": evidence, "spool_bytes": len(transcript), "worker_job": job}
        finally:
            with cleanup_signals():
                self.cleanup_launch(launch_dir, tokens, receiver)
        result["both_grants_replay_401"] = True
        private_json(self.directory / f"{backend}-result.json", result)
        return result


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    repo = Path(__file__).resolve().parents[3]
    parser.add_argument("--backend", choices=("docker", "kubernetes", "both"), default="both")
    parser.add_argument("--image", required=True, help="sandbox image already loaded into each selected runtime")
    parser.add_argument("--shipper-image")
    parser.add_argument("--bin", type=Path, default=Path(os.environ.get("FLEET_RECALL_BIN", repo / "target/debug/ostk-fleet-recall")))
    parser.add_argument("--state", type=Path, default=Path(os.environ.get("FLEET_LOCAL_STATE", repo / "deploy/local/.state")))
    parser.add_argument("--url", default="http://localhost:8080/mcp")
    parser.add_argument("--resource-url")
    parser.add_argument("--docker-url", default="http://host.docker.internal:8080/mcp")
    parser.add_argument("--kubernetes-url", default="http://recall.fleet-recall.svc.cluster.local:8080/mcp")
    parser.add_argument("--namespace", default="fleet-recall")
    parser.add_argument("--runtime-class")
    parser.add_argument("--worker", default="worker")
    parser.add_argument("--receiver", default="recall")
    parser.add_argument("--spool", default="/var/lib/recall/transcripts")
    parser.add_argument("--scope", default="0198a849-f6ae-7d61-9800-000000000001/local-k0s")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--worker-timeout", type=int, default=600)
    args = parser.parse_args()
    args.state, args.bin = args.state.resolve(), args.bin.resolve()
    try:
        args.tenant, args.project = args.scope.split("/", 1)
        require(str(uuid.UUID(args.tenant)) == args.tenant and re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", args.project), "invalid scope")
        require(30 <= args.timeout <= 600 and 60 <= args.worker_timeout <= 1200, "timeouts out of bounds")
        for value in (args.namespace, args.worker, args.receiver):
            require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", value), "invalid Kubernetes name")
        for value in (args.url, args.resource_url or args.url, args.docker_url, args.kubernetes_url):
            parsed = urlsplit(value)
            require(parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username
                    and not parsed.password and parsed.path == "/mcp" and not parsed.query and not parsed.fragment, "invalid MCP URL")
    except (ValueError, SmokeFailure) as error:
        parser.error(str(error))
    return args


def main():
    args = arguments()
    os.umask(0o077)
    directory = args.state / "sandbox-smoke" / (time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4))
    directory.mkdir(parents=True, mode=0o700)
    smoke = None
    failures = []
    results = []
    # SIGTERM follows the same cleanup as Ctrl-C, then cleanup itself is allowed
    # to finish without another signal interrupting grant revocation.
    def interrupted(_signum, _frame):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    lock_path = args.state / "sandbox-smoke" / "worker.lock"
    with os.fdopen(os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            smoke = Smoke(args, directory)
            smoke.suspend_worker()
            for backend in ("docker", "kubernetes") if args.backend == "both" else (args.backend,):
                results.append(smoke.backend(backend))
        except (Exception, KeyboardInterrupt) as error:
            failures.append({"type": type(error).__name__, "detail": str(error)})
        finally:
            if smoke:
                try:
                    with cleanup_signals():
                        smoke.restore_worker()
                except Exception as error:
                    failures.append({"type": type(error).__name__, "detail": str(error), "restoration": "inspect cronjob-before.json"})
    private_json(directory / "result.json", {"passed": not failures, "runs": results, "failures": failures})
    if failures:
        print(f"FAIL sandbox smoke; protected proof and recovery state: {directory}", file=sys.stderr)
        return 1
    print(f"PASS {', '.join(result['backend'] for result in results)}: synthetic status/record/get, shipped transcript, worker evidence, both grants revoked. Proof: {directory}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
