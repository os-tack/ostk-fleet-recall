#!/usr/bin/env python3
"""Retain encrypted local recovery inputs before the HTTPS identity cutover.

Requires Python cryptography. Uses the existing verified local CockroachDB
root client, never rotates keys or changes authorization data. This is a local
checkpoint, not an off-device backup or a successful restore rehearsal.
"""

import argparse
import hashlib
import io
import json
import os
import secrets
import subprocess
import tarfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--vm", default="k0s")
    args = parser.parse_args()
    os.umask(0o077)
    state = args.state.resolve(strict=True)
    directory = state / ("https-backup-" + time.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(4))
    directory.mkdir(mode=0o700)
    environment = dict(os.environ, KUBECONFIG=str(state / "kubeconfig"))
    key = AESGCM.generate_key(bit_length=256)
    key_path = directory / "recovery-key.hex"
    key_path.write_text(key.hex() + "\n")
    cipher = AESGCM(key)
    manifest = {"version": 1, "format": "AES-256-GCM; 12-byte nonce prefix; filename AAD",
                "state": str(state), "created_at": time.time(), "artifacts": []}

    def retain(name, data):
        nonce = secrets.token_bytes(12)
        encrypted = nonce + cipher.encrypt(nonce, data, name.encode())
        (directory / (name + ".aesgcm")).write_bytes(encrypted)
        if cipher.decrypt(nonce, encrypted[12:], name.encode()) != data:
            raise RuntimeError("encrypted recovery artifact failed its round trip check")
        manifest["artifacts"].append({"name": name, "bytes": len(data),
                                      "sha256": hashlib.sha256(encrypted).hexdigest()})

    def run(argv, data=None, timeout=120):
        result = subprocess.run(argv, input=data, env=environment, capture_output=True,
                                timeout=timeout, check=False)
        if result.returncode:
            retain("failure-" + str(len(manifest["artifacts"])), result.stdout + result.stderr)
            raise RuntimeError("backup command failed; encrypted diagnostic retained")
        return result.stdout

    try:
        cluster = json.loads(run(["kubectl", "get", "namespace", "kube-system", "-o", "json"]))
        manifest["cluster_uid"] = cluster["metadata"]["uid"]
        for namespace in ("fleet-recall", "ory"):
            retain(namespace + "-resources.json", run([
                "kubectl", "-n", namespace, "get",
                "deployment,statefulset,cronjob,service,configmap,secret,serviceaccount,role,rolebinding,pvc,networkpolicy",
                "-o", "json",
            ]))
        for release in ("hydra", "kratos", "kratos-ui"):
            retain(release + "-helm-values.yaml", run(["helm", "get", "values", release, "-n", "ory", "--all"]))
        retain("lima.json", run(["limactl", "list", "--json"]))
        retain("spool.tar", run(["limactl", "shell", args.vm, "sudo", "tar", "-C", "/var/lib/fleet-recall", "-cf", "-", "transcripts"]))
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name in ("passwords.env", "authority.json", "launcher-key.hex", "launcher-keys.json",
                         "remote-grant-signing-key.hex", "embedding-tier-token.hex", "model.sha256", "certs"):
                archive.add(state / name, arcname=name)
            for path in state.rglob("launch-state.json"):
                archive.add(path, arcname=str(path.relative_to(state)))
            if (state / "https-edge/pki/pins.json").is_file():
                archive.add(state / "https-edge/pki", arcname="https-edge/pki")
        retain("workstation-state.tar.gz", buffer.getvalue())
        sql = ["docker", "run", "--rm", "-i", "--network", "host", "-v", f"{state}/certs:/certs:ro",
               "cockroachdb/cockroach:v26.2.3", "sql", "--certs-dir=/certs", "--host=127.0.0.1:26258", "--format=tsv"]
        location = "nodelocal://1/" + directory.name
        passphrase = secrets.token_hex(32)
        retain("database-location.json", json.dumps({"uri": location, "encryption_passphrase": passphrase}).encode())
        query = f"BACKUP INTO '{location}' WITH encryption_passphrase = '{passphrase}';"
        # EXPLAIN is read-only; retain its result even on versions that cannot
        # explain administrative statements. The BACKUP itself is the gate.
        explanation = subprocess.run(sql, input=("EXPLAIN " + query).encode(), env=environment,
                                     capture_output=True, timeout=60, check=False)
        retain("database-explain.txt", explanation.stdout + explanation.stderr)
        retain("database-backup.tsv", run(sql, query.encode(), timeout=900))
        verify = f"SHOW BACKUP LATEST IN '{location}' WITH encryption_passphrase = '{passphrase}', check_files;"
        retain("database-check-files.tsv", run(sql, verify.encode(), timeout=300))
        # Move a copy off the VM disk. The native backup files are encrypted too.
        retain("database.tar", run(["limactl", "shell", args.vm, "sudo", "tar", "-C",
                                   "/var/lib/fleet-recall/crdb/extern", "-cf", "-", directory.name], timeout=300))
        manifest["complete"] = True
    finally:
        (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print("Private recovery checkpoint: " + str(directory), flush=True)
    print("PASS encrypted checkpoint and native backup file validation; restore rehearsal remains separate.")


if __name__ == "__main__":
    main()
