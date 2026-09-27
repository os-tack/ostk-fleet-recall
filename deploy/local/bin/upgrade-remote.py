#!/usr/bin/env python3
"""Upgrade an existing M1 k0s database for the Mac-hosted M2 service.

Retain workloads and data. Quiesce runtime connections during the policy audit;
on failure leave workloads stopped and preserve the log/restore coordinates.
No enrollment credential is installed in a Kubernetes Secret or workload.
"""
import datetime
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
from urllib.parse import urlencode

REPO = Path(__file__).resolve().parents[3]
STATE = Path(os.environ.get("FLEET_LOCAL_STATE", REPO / "deploy/local/.state")).resolve()
BINARY = Path(os.environ.get("FLEET_RECALL_BIN", REPO / "target/debug/ostk-fleet-recall")).resolve()
MODEL = Path(os.environ.get("FLEET_RECALL_MODEL_BUNDLE", STATE.parents[2] / ".models/potion-retrieval-32M-6fc8051fab2a1e0ee76689cf08c853792ac285e7")).resolve()
IMAGE = "cockroachdb/cockroach:v26.2.3"


def main():
    if len(sys.argv) > 1:
        print("Usage: deploy/local/bin/upgrade-remote.py")
        print("Uses FLEET_LOCAL_STATE, FLEET_RECALL_BIN, FLEET_RECALL_MODEL_BUNDLE.")
        return 0 if sys.argv[1] in {"--help", "-h"} else 2
    for required in [BINARY, STATE / "kubeconfig", STATE / "certs/ca.crt", STATE / "certs/client.root.crt", STATE / "certs/client.root.key", STATE / "model.sha256", MODEL / "model.safetensors", MODEL / "config.json", MODEL / "tokenizer.json"]:
        if not required.is_file():
            sys.exit(f"Required local artifact missing: {required}")
    os.umask(0o077)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_dir = STATE / ("m2-upgrade-" + stamp + "-" + secrets.token_hex(3))
    run_dir.mkdir(mode=0o700)
    environment = {name: os.environ[name] for name in ["PATH", "HOME"] if name in os.environ}
    environment["KUBECONFIG"] = str(STATE / "kubeconfig")
    kube = ["kubectl", "-n", "fleet-recall"]
    docker = ["docker", "run", "--rm", "-i", "--network", "host", "-v", f"{STATE}/certs:/certs:ro"]
    sql = docker + [IMAGE, "sql", "--certs-dir=/certs", "--host=127.0.0.1:26258", "--database=fleet_recall"]
    with (run_dir / "upgrade.log").open("w") as log:
        def run(command, *, text=None, env=None):
            return subprocess.run(command, input=text, text=True, env=env or environment,
                                  stdout=log, stderr=log, check=True, timeout=900)

        def get_json(command):
            result = subprocess.run(command, env=environment, capture_output=True, text=True, check=True, timeout=60)
            return json.loads(result.stdout)

        try:
            workloads = get_json(kube + ["get", "deploy/writer", "deploy/demo", "deploy/ingress", "cronjob/worker", "-o", "json"])
            (run_dir / "workloads-before.json").write_text(json.dumps(workloads, indent=2) + "\n")
            passwords_path = STATE / "passwords.env"
            passwords = dict(line.split("=", 1) for line in passwords_path.read_text().splitlines() if "=" in line)
            if not passwords.get("ENROLLMENT_PASSWORD"):
                passwords["ENROLLMENT_PASSWORD"] = secrets.token_hex(24)
                with passwords_path.open("a") as output:
                    output.write("ENROLLMENT_PASSWORD=" + passwords["ENROLLMENT_PASSWORD"] + "\n")
            for name in ["ENROLLMENT_PASSWORD", "MIGRATOR_PASSWORD"]:
                if not re.fullmatch(r"[0-9a-f]{48}", passwords[name]):
                    raise ValueError("invalid local password format")
            model_digest = (STATE / "model.sha256").read_text().strip()
            if not re.fullmatch(r"[0-9a-f]{64}", model_digest):
                raise ValueError("invalid model digest")
            model_check = subprocess.run([str(BINARY), "model-digest", str(MODEL)], env=environment, capture_output=True, text=True, check=True, timeout=120)
            if model_check.stdout.strip() != model_digest:
                raise ValueError("pinned model digest changed")
            print("Quiescing local runtime connections for the M2 boundary audit", flush=True)
            run(kube + ["patch", "cronjob/worker", "--type=merge", "-p", '{"spec":{"suspend":true}}'])
            jobs = get_json(kube + ["get", "jobs", "-o", "json"])
            for job in jobs["items"]:
                if job.get("status", {}).get("active", 0) and any(owner.get("name") == "worker" for owner in job["metadata"].get("ownerReferences", [])):
                    run(kube + ["wait", "--for=condition=complete", "job/" + job["metadata"]["name"], "--timeout=600s"])
            run(kube + ["scale", "deploy/writer", "deploy/demo", "deploy/ingress", "--replicas=0"])
            for app in ["writer", "demo", "ingress"]:
                run(kube + ["wait", "--for=delete", "pod", "-l", "app=" + app, "--timeout=120s"])
            # Additional Mac/manual clients must be stopped too; role NOLOGIN
            # alone would leave their existing sessions alive during the audit.
            run(sql, text="SELECT CASE WHEN count(*) = 0 THEN 'true' ELSE concat('stop external fleet sessions before upgrade: ', count(*)) END::BOOL FROM [SHOW CLUSTER SESSIONS] WHERE user_name IN ('fleet_writer','fleet_publication','fleet_ingress','fleet_enrollment');\n")
            try:
                run(sql, text="ALTER USER fleet_migrator WITH LOGIN; GRANT admin TO fleet_migrator;\n")
                query = urlencode({"sslmode": "verify-full", "sslrootcert": str(STATE / "certs/ca.crt")})
                runtime = {key: value for key, value in environment.items() if key != "KUBECONFIG"}
                runtime.update({
                    "FLEET_RECALL_DATABASE_URL": f"postgresql://fleet_migrator:{passwords['MIGRATOR_PASSWORD']}@127.0.0.1:26258/fleet_recall?{query}",
                    "FLEET_RECALL_TENANT_ID": "0198a849-f6ae-7d61-9800-000000000001",
                    "FLEET_RECALL_PROJECT": "local-k0s", "FLEET_RECALL_AGENT": "migrate",
                    "FLEET_RECALL_EMBEDDING_MODEL": "minishlab/potion-retrieval-32M",
                    "FLEET_RECALL_EMBEDDING_MODEL_PATH": str(MODEL),
                    "FLEET_RECALL_EMBEDDING_MODEL_SHA256": model_digest,
                })
                print("Applying additive migrations 38 and 39 over verify-full", flush=True)
                run([str(BINARY), "migrate"], env=runtime)
            finally:
                run(sql, text="ALTER USER fleet_migrator WITH NOLOGIN NOCREATEDB NOCREATEROLE; REVOKE admin FROM fleet_migrator; REVOKE SYSTEM ALL FROM fleet_migrator;\n")
            print("Auditing runtime, publication, ingress, and enrollment role policies", flush=True)
            run(docker + ["-v", f"{REPO}/deploy/cockroach:/policies:ro", "-v", f"{REPO}/deploy/local/kustomize/base/jobs/boundary.sh:/boundary.sh:ro", "-e", "CRDB_HOST=127.0.0.1:26258", "--entrypoint", "/bin/sh", IMAGE, "/boundary.sh"])
            run(sql, text=f"ALTER USER fleet_enrollment WITH PASSWORD '{passwords['ENROLLMENT_PASSWORD']}' LOGIN NOCREATEDB NOCREATEROLE;\n")
            for workload in workloads["items"]:
                name = workload["metadata"]["name"]
                if workload["kind"] == "Deployment":
                    run(kube + ["scale", "deploy/" + name, "--replicas=" + str(workload["spec"].get("replicas", 1))])
                    run(kube + ["rollout", "status", "deploy/" + name, "--timeout=300s"])
                else:
                    patch = json.dumps({"spec": {"suspend": workload["spec"].get("suspend", False)}})
                    run(kube + ["patch", "cronjob/" + name, "--type=merge", "-p", patch])
            print(f"PASS M2 migrations and audited boundaries; original workloads restored. Evidence: {run_dir}", flush=True)
            return 0
        except (OSError, ValueError, KeyError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            print(f"FAIL upgrade stopped; inspect protected diagnostics and saved workload settings at {run_dir}. Runtime may remain quiesced.", file=sys.stderr)
            return 1


if __name__ == "__main__":
    sys.exit(main())
