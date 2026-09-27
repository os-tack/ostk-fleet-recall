#!/usr/bin/env python3
"""Deploy M3 onto the existing secure local cluster without changing its schema.

Build/import is explicit. Keys and generated manifests remain in private state;
only public enrollment identities and launch instructions are printed.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
from urllib.parse import urlencode
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-tag", required=True)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--prepare-only", action="store_true", help="render and validate without applying workloads")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", args.image_tag):
        parser.error("invalid image tag")
    os.umask(0o077)
    here = Path(__file__).resolve().parents[1]
    repo = here.parents[1]
    state = Path(os.environ.get("FLEET_LOCAL_STATE", here / ".state")).resolve()
    if state.is_relative_to(repo) and not state.is_relative_to(here / ".state"):
        parser.error("custom FLEET_LOCAL_STATE must be outside the build context or under deploy/local/.state")
    vm = os.environ.get("FLEET_LOCAL_VM", "k0s")
    bundle = Path(os.environ.get("FLEET_RECALL_MODEL_BUNDLE", state.parents[2] / ".models" / "potion-retrieval-32M-6fc8051fab2a1e0ee76689cf08c853792ac285e7")).resolve()
    environment = dict(os.environ, KUBECONFIG=str(state / "kubeconfig"))
    run_id = time.strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    directory = state / ("m3-deploy-" + run_id)
    directory.mkdir(mode=0o700)

    def run(argv, *, data=None, timeout=120):
        result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=timeout)
        if result.returncode:
            # kubectl can include submitted Secret material in errors.
            (directory / "command-failure.log").write_bytes(result.stdout + result.stderr)
            raise RuntimeError(f"{argv[0]} failed; private diagnostics: {directory}")
        return result.stdout

    def private_hex(path, length):
        if not path.exists():
            with path.open("x") as file:
                file.write(secrets.token_hex(length // 2) + "\n")
        if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise ValueError("key must be a regular private file")
        value = path.read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value):
            raise ValueError("invalid key")
        return value

    def apply(value):
        return run(["kubectl", "apply", "-f", "-"], data=json.dumps(value).encode())

    def object_(kind, name, data):
        result = {"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "namespace": "fleet-recall"}}
        result["stringData" if kind == "Secret" else "data"] = data
        return result

    try:
        if not (state / "kubeconfig").is_file():
            raise ValueError("bootstrap the local cluster first")
        digest = (state / "model.sha256").read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid model digest")
        password_path = state / "passwords.env"
        if password_path.is_symlink() or stat.S_IMODE(password_path.stat().st_mode) & 0o077:
            raise ValueError("password file must be private")
        passwords = dict(line.split("=", 1) for line in password_path.read_text().splitlines() if "=" in line)
        enrollment_password = passwords.get("ENROLLMENT_PASSWORD", "")
        if not re.fullmatch(r"[0-9a-f]{48}", enrollment_password):
            raise ValueError("complete the M2 upgrade and enrollment policy first")
        launcher_seed = private_hex(state / "launcher-key.hex", 64)
        grant_seed = private_hex(state / "remote-grant-signing-key.hex", 64)
        tier_token = private_hex(state / "embedding-tier-token.hex", 64)
        der = bytes.fromhex("302e020100300506032b657004220420" + launcher_seed)
        public = run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], data=der)
        if len(public) != 44 or public[:12].hex() != "302a300506032b6570032100":
            raise ValueError("unexpected Ed25519 public key encoding")
        keys = {"launcher": public[12:].hex()}
        (state / "launcher-keys.json").write_text(json.dumps(keys) + "\n")
        tenant = "0198a849-f6ae-7d61-9800-000000000001"
        declarations = {"principals": []}
        for anchor, subject in [("local-key", "launcher"), ("k8s", "system:serviceaccount:fleet-recall:launcher")]:
            declarations["principals"].append({"principal_id": str(uuid.uuid5(uuid.NAMESPACE_URL, "fleet-recall-local-m3/" + anchor)), "anchor_id": anchor, "subject_pattern": subject, "role": "launcher", "tenant_id": tenant, "project": "local-k0s", "ceiling": "project", "agent_pattern": "sandbox-*"})
        (directory / "registry.json").write_text(json.dumps(declarations, indent=2) + "\n")
        rendered = run(["kubectl", "kustomize", str(here / "kustomize/overlays/m2-remote-plane"), "--load-restrictor", "LoadRestrictionsNone"]).decode()
        for key, value in {"__IMAGE_TAG__": args.image_tag, "__MODEL_SHA256__": digest, "__MODEL_BUNDLE_DIR__": str(bundle), "__RUN_ID__": run_id}.items():
            rendered = rendered.replace(key, value)
        manifest = directory / "rendered.yaml"
        manifest.write_text(rendered)
        run(["kubectl", "apply", "--dry-run=server", "-f", str(manifest), "-l", "fleet-recall.dev/phase=remote"])
        run(["kubectl", "apply", "--dry-run=server", "-f", str(manifest), "-l", "fleet-recall.dev/phase=remote-enroll"])
        if args.prepare_only:
            print(f"M3 manifest validated: {manifest}")
            return 0
        if args.build:
            print("Building the M3 service image…", flush=True)
            with (directory / "image-build.log").open("wb") as log:
                result = subprocess.run(["docker", "buildx", "build", "--platform", "linux/arm64", "--target", "production", "-t", "ostk-fleet-recall:" + args.image_tag, "--load", str(repo)], stdout=log, stderr=log, env=environment, timeout=2400)
            if result.returncode:
                raise RuntimeError(f"image build failed; see {directory / 'image-build.log'}")
            archive = directory / "recall-image.tar"
            run(["docker", "save", "-o", str(archive), "ostk-fleet-recall:" + args.image_tag], timeout=180)
            run(["limactl", "shell", vm, "sudo", "k0s", "ctr", "images", "import", str(archive)], timeout=180)
        run(["limactl", "shell", vm, "sudo", "install", "--directory", "--owner=10001", "--group=10001", "--mode=0700", "/var/lib/fleet-recall/transcripts"])
        query = urlencode({"sslmode": "verify-full", "sslrootcert": "/etc/crdb/ca.crt"})
        apply(object_("Secret", "fleet-remote", {"FLEET_RECALL_GRANT_SIGNING_KEY_HEX": grant_seed, "FLEET_RECALL_EMBEDDING_TIER_TOKEN": tier_token}))
        apply(object_("Secret", "db-url-enrollment", {"FLEET_RECALL_ENROLLMENT_DATABASE_URL": f"postgresql://fleet_enrollment:{enrollment_password}@cockroach.fleet-recall.svc.cluster.local:26257/fleet_recall?{query}"}))
        apply(object_("ConfigMap", "fleet-launcher-keys", {"launcher-keys.json": json.dumps(keys)}))
        apply(object_("ConfigMap", "fleet-sandbox-registry", {"registry.json": json.dumps(declarations)}))
        run(["kubectl", "apply", "-f", str(manifest), "-l", "fleet-recall.dev/phase=remote"])
        for deployment in ["embed", "recall"]:
            run(["kubectl", "-n", "fleet-recall", "rollout", "status", "deployment/" + deployment, "--timeout=240s"], timeout=250)
        run(["kubectl", "apply", "-f", str(manifest), "-l", "fleet-recall.dev/phase=remote-enroll"])
        run(["kubectl", "-n", "fleet-recall", "wait", "--for=condition=Complete", "job/enroll-sandbox-" + run_id, "--timeout=120s"], timeout=130)
        print(f"M3 recall, embedding tier, spool, worker, and launcher enrollment ready. Evidence: {directory}")
        print("Launcher key: " + str(state / "launcher-key.hex") + " (private; keep out of command arguments)")
        print("Restore the Lima 8080 forward after stopping the Mac M2 service to use the cluster at localhost:8080.")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print("M3 deployment stopped: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
