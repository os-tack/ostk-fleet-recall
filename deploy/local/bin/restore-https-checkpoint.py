#!/usr/bin/env python3
"""Authenticate and rehearse a checkpoint in a new, network-disabled SQL container.

No production SQL, Kubernetes, or Lima command is issued. The default only
authenticates and validates inputs. --apply creates a private recovery directory
and a NEW Docker container with no published ports and no network. It restores
the full cluster, verifies schema/authority, and revokes every previously live
grant in the restored copy. The container is stopped on success or failure;
its disk and diagnostics are retained. This is not an application promotion.
"""

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import tarfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

IMAGE = "cockroachdb/cockroach:v26.2.3"
MAX_ARTIFACT = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
REQUIRED = {"database.tar", "database-location.json", "database-backup.tsv",
            "database-check-files.tsv", "spool.tar", "workstation-state.tar.gz",
            "fleet-recall-resources.json", "ory-resources.json", "hydra-helm-values.yaml",
            "kratos-helm-values.yaml", "kratos-ui-helm-values.yaml", "lima.json"}
PROTECTED = {"fleet-recall": ("fleet-pins", "fleet-content-kek", "fleet-remote"),
             "ory": ("hydra-secrets", "kratos-secrets", "kratos-ui-kratos-selfservice-ui-node")}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


@contextmanager
def interruption_signals():
    """Convert the first termination signal into normal Python unwinding."""
    def interrupted(_number, _frame):
        for number in (signal.SIGINT, signal.SIGTERM):
            signal.signal(number, signal.SIG_IGN)
        raise KeyboardInterrupt

    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


@contextmanager
def cleanup_signals():
    """Finish bounded cleanup even if another termination signal arrives."""
    previous = {number: signal.signal(number, signal.SIG_IGN) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def regular_bytes(path, bound):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= bound, "recovery input is not a bounded regular file")
    return path.read_bytes()


def authenticate(backup, state, cluster_uid, max_age_hours=24):
    """Validate every declared artifact before returning any plaintext."""
    manifest = json.loads(regular_bytes(backup / "manifest.json", 1024 * 1024))
    require(manifest.get("version") == 1 and manifest.get("complete") is True,
            "checkpoint is incomplete or unsupported")
    require(manifest.get("state") == str(state) and manifest.get("cluster_uid") == cluster_uid,
            "checkpoint does not match the explicitly selected source installation")
    created = manifest.get("created_at")
    require(isinstance(created, (int, float)) and 0 <= time.time() - created <= max_age_hours * 3600,
            "checkpoint is outside the selected backup age bound")
    key = bytes.fromhex(regular_bytes(backup / "recovery-key.hex", 128).decode().strip())
    require(len(key) == 32, "recovery key is not AES-256")
    cipher = AESGCM(key)
    plaintext = {}
    total = 0
    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, list) and len(artifacts) <= 64, "invalid artifact inventory")
    for artifact in artifacts:
        name = artifact.get("name", "")
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", name)
                and name not in plaintext, "duplicate or invalid artifact name")
        size = artifact.get("bytes")
        require(isinstance(size, int) and 0 <= size <= MAX_ARTIFACT, "artifact exceeds recovery size bound")
        total += size
        require(total <= MAX_TOTAL, "checkpoint exceeds recovery size bound")
        encrypted = regular_bytes(backup / (name + ".aesgcm"), MAX_ARTIFACT + 28)
        require(len(encrypted) == size + 28 and hashlib.sha256(encrypted).hexdigest() == artifact.get("sha256"),
                "artifact checksum or size changed")
        plaintext[name] = cipher.decrypt(encrypted[:12], encrypted[12:], name.encode())
    require(REQUIRED <= plaintext.keys(), "checkpoint lacks required recovery artifacts")
    return manifest, plaintext


def archive_members(data, *, required_root=None):
    """Preflight all paths/types before extracting even the first archive entry."""
    entries = []
    seen = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(member.name and not path.is_absolute() and ".." not in path.parts
                    and "\\" not in member.name and "\x00" not in member.name
                    and str(path) != ".", "unsafe archive path")
            require(member.isfile() or member.isdir(), "archive links and special files are forbidden")
            require(str(path) not in seen, "duplicate archive path")
            require(required_root is None or path.parts[0] == required_root, "unexpected archive root")
            total += member.size
            require(0 <= member.size <= MAX_ARTIFACT and total <= MAX_TOTAL and len(entries) < 100000,
                    "archive exceeds recovery size bound")
            seen[str(path)] = member.isdir()
            entries.append((member, path))
        for _, path in entries:
            require(all(seen.get(str(parent), True) for parent in path.parents), "archive file is also a parent")
    return entries


def extract_private(data, destination, *, required_root=None):
    entries = archive_members(data, required_root=required_root)
    destination.mkdir(mode=0o700)
    hashes = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member, path in entries:
            target = destination / str(path)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = archive.extractfile(member)
                require(source is not None, "archive regular file cannot be read")
                content = source.read(MAX_ARTIFACT + 1)
                require(len(content) == member.size, "archive file size changed")
                with target.open("xb") as output:
                    output.write(content)
                target.chmod(0o600)
                hashes[str(path)] = hashlib.sha256(content).hexdigest()
    return hashes


def resource(items, kind, name, namespace):
    found = [item for item in items if item.get("kind") == kind
             and item.get("metadata", {}).get("name") == name
             and item.get("metadata", {}).get("namespace") == namespace]
    require(len(found) == 1, "recovery resource missing or duplicated")
    return found[0]


def secret_data(item):
    data = item.get("data", {})
    require(isinstance(data, dict) and bool(data), "protected Secret has no data")
    return {name: base64.b64decode(value, validate=True).decode() for name, value in data.items()}


def recovery_inputs(plaintext):
    location = json.loads(plaintext["database-location.json"])
    uri = location.get("uri", "")
    require(re.fullmatch(r"nodelocal://1/https-backup-[A-Za-z0-9-]+", uri) is not None,
            "backup URI is not a bounded local checkpoint path")
    require(re.fullmatch(r"[0-9a-f]{64}", location.get("encryption_passphrase", "")) is not None,
            "invalid encrypted backup passphrase format")
    archive_members(plaintext["database.tar"], required_root=uri.rsplit("/", 1)[1])
    archive_members(plaintext["spool.tar"], required_root="transcripts")
    archive_members(plaintext["workstation-state.tar.gz"])
    fingerprints = {}
    resources = {}
    for namespace, names in PROTECTED.items():
        items = json.loads(plaintext[namespace + "-resources.json"])["items"]
        resources[namespace] = items
        for name in names:
            item = resource(items, "Secret", name, namespace)
            secret_data(item)
            fingerprints[namespace + "/" + name] = hashlib.sha256(
                json.dumps(item["data"], sort_keys=True).encode()).hexdigest()
    scope = resource(resources["fleet-recall"], "ConfigMap", "fleet-env", "fleet-recall")["data"]
    uuid.UUID(scope["FLEET_RECALL_TENANT_ID"])
    project = scope["FLEET_RECALL_PROJECT"]
    require(isinstance(project, str) and 1 <= len(project.encode()) <= 256, "invalid restored scope")
    pins = secret_data(resource(resources["fleet-recall"], "Secret", "fleet-pins", "fleet-recall"))
    return location, fingerprints, scope, pins


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def csv_rows(data):
    return list(csv.DictReader(io.StringIO(data.decode())))


def verify_isolation(item, container_id, directory):
    require(item.get("Id") == container_id and item["HostConfig"].get("NetworkMode") == "none"
            and not item["HostConfig"].get("PortBindings") and not item["HostConfig"].get("Privileged")
            and item["Config"].get("Labels", {}).get("fleet-recall.dev/recovery") == directory.name,
            "restore container lost its isolation boundary")
    mounts = {mount["Destination"]: mount for mount in item.get("Mounts", [])}
    for target, source, writable in (("/store", directory / "crdb", True),
                                     ("/certs", directory / "workstation/certs", False),
                                     ("/recovery", directory / "database", False)):
        require(target in mounts and Path(mounts[target]["Source"]).resolve() == source.resolve()
                and mounts[target]["RW"] is writable, "restore container mount differs from private recovery inputs")
    require(len(mounts) == 3, "restore container has unexpected mounts")


def restore(directory, plaintext, inputs):
    location, secret_hashes, scope, pins = inputs
    container_id = None
    started = time.monotonic()
    result = {"version": 1, "phase": "extract", "complete": False, "application_qualified": False,
              "network": "none", "published_ports": [], "protected_secret_sha256": secret_hashes}
    sequence = 0

    def run(argv, data=None, timeout=60, *, allow_failure=False):
        nonlocal sequence
        sequence += 1
        response = subprocess.run(argv, input=data, capture_output=True, timeout=timeout, check=False)
        # SQL diagnostics can include credentials or data. They remain private.
        (directory / (f"command-{sequence:03d}.log")).write_bytes(response.stdout + response.stderr)
        require(allow_failure or response.returncode == 0, "restore command failed; inspect private command logs")
        return response

    def sql(query, *, database="defaultdb", timeout=60, explain=True):
        url = (f"postgresql://root@localhost:26257/{database}?sslmode=verify-full"
               "&sslrootcert=/certs/ca.crt&sslcert=/certs/client.root.crt&sslkey=/certs/client.root.key")
        argv = ["docker", "exec", "-i", container_id, "/cockroach/cockroach", "sql", "--url", url, "--format=csv"]
        # EXPLAIN is required for executable query plans; administrative
        # statements have no plan on this pin, but keep their attempted EXPLAIN.
        run(argv, ("EXPLAIN " + query).encode(), timeout=60, allow_failure=not explain)
        return run(argv, query.encode(), timeout=timeout).stdout

    def inspect():
        item = json.loads(run(["docker", "inspect", container_id]).stdout)[0]
        verify_isolation(item, container_id, directory)

    try:
        result["spool_file_sha256"] = extract_private(plaintext["spool.tar"], directory / "spool", required_root="transcripts")
        result["workstation_file_sha256"] = extract_private(plaintext["workstation-state.tar.gz"], directory / "workstation")
        extract_private(plaintext["database.tar"], directory / "database", required_root=location["uri"].rsplit("/", 1)[1])
        private = directory / "resources"
        private.mkdir(mode=0o700)
        result["resource_artifact_sha256"] = {}
        for name, value in plaintext.items():
            if not name.endswith((".tar", ".tar.gz")):
                (private / name).write_bytes(value)
                result["resource_artifact_sha256"][name] = hashlib.sha256(value).hexdigest()
        authority = json.loads((directory / "workstation/authority.json").read_text())
        require(authority.get("generation") == 3 and re.fullmatch(r"[0-9a-f]{64}", authority.get("activation_id", "")),
                "checkpoint is not the supported generation-3 authority")
        require(authority.get("pins") == pins, "workstation and deployment authority pins differ")
        for name in ("ca.crt", "node.crt", "node.key", "client.root.crt", "client.root.key"):
            regular_bytes(directory / "workstation/certs" / name, 1024 * 1024)
        remote = secret_data(resource(json.loads(plaintext["fleet-recall-resources.json"])["items"],
                                      "Secret", "fleet-remote", "fleet-recall"))
        require((directory / "workstation/remote-grant-signing-key.hex").read_text().strip()
                == remote["FLEET_RECALL_GRANT_SIGNING_KEY_HEX"], "workstation and deployment signing keys differ")
        (directory / "crdb").mkdir(mode=0o700)
        result["phase"] = "create"
        command = ["docker", "create", "--pull=never", "--name", directory.name, "--network=none", "--restart=no",
                   "--label", "fleet-recall.dev/recovery=" + directory.name,
                   "--mount", f"type=bind,src={directory / 'crdb'},dst=/store",
                   "--mount", f"type=bind,src={directory / 'workstation/certs'},dst=/certs,readonly",
                   "--mount", f"type=bind,src={directory / 'database'},dst=/recovery,readonly",
                   "--entrypoint", "/cockroach/cockroach", IMAGE, "start-single-node", "--certs-dir=/certs",
                   "--listen-addr=127.0.0.1:26257", "--http-addr=127.0.0.1:8080", "--advertise-addr=localhost:26257",
                   "--store=path=/store", "--external-io-dir=/recovery", "--cache=256MiB", "--max-sql-memory=256MiB"]
        container_id = run(command).stdout.decode().strip()
        require(re.fullmatch(r"[0-9a-f]{64}", container_id) is not None, "invalid new container identity")
        result["container_id"] = container_id
        inspect()
        run(["docker", "start", container_id])
        deadline = time.monotonic() + 90
        while True:
            response = run(["docker", "exec", container_id, "/cockroach/cockroach", "sql", "--certs-dir=/certs",
                            "--host=localhost:26257", "--execute=SELECT 1", "--format=csv"], timeout=15, allow_failure=True)
            if response.returncode == 0:
                break
            require(time.monotonic() < deadline, "new isolated SQL cluster did not start in 90 seconds")
            time.sleep(2)
        fresh = csv_rows(sql("SELECT database_name FROM [SHOW DATABASES] ORDER BY database_name;"))
        require({row["database_name"] for row in fresh} == {"defaultdb", "postgres", "system"},
                "restore destination is not a fresh empty cluster")
        result["phase"] = "restore"
        # Administrative RESTORE/SHOW BACKUP do not support EXPLAIN on this pin;
        # preserve that diagnostic, but validate the actual check_files and restore.
        phrase = literal(location["encryption_passphrase"])
        uri = literal(location["uri"])
        sql(f"SHOW BACKUP LATEST IN {uri} WITH encryption_passphrase={phrase}, check_files;", timeout=300, explain=False)
        sql(f"RESTORE FROM LATEST IN {uri} WITH encryption_passphrase={phrase};", timeout=900, explain=False)
        result["phase"] = "verify"
        rows = csv_rows(sql("SELECT version, success, encode(checksum, 'hex') AS checksum FROM public._sqlx_migrations ORDER BY version;",
                            database="fleet_recall"))
        migrations = Path(__file__).resolve().parents[3] / "migrations"
        expected = {int(path.name.split("_", 1)[0]): hashlib.sha384(path.read_bytes()).hexdigest()
                    for path in migrations.glob("*.sql")}
        require({int(row["version"]): row["checksum"] for row in rows} == expected
                and all(row["success"] in ("true", "t") for row in rows), "restored migration checksums or success flags differ")
        result["schema_version"] = max(expected)
        where = "tenant_id=" + literal(scope["FLEET_RECALL_TENANT_ID"]) + "::UUID AND project=" + literal(scope["FLEET_RECALL_PROJECT"])
        authority_rows = csv_rows(sql("SELECT generation, encode(activation_id,'hex') AS activation_id, contract_tenant_namespace, "
                                     "contract_project_namespace FROM public.memory_registry_current_heads_v2 WHERE " + where + ";",
                                     database="fleet_recall"))
        require(len(authority_rows) == 1 and int(authority_rows[0]["generation"]) == authority["generation"]
                and authority_rows[0]["activation_id"] == authority["activation_id"]
                and authority_rows[0]["contract_tenant_namespace"] == pins["FLEET_RECALL_CONTRACT_TENANT_NAMESPACE"]
                and authority_rows[0]["contract_project_namespace"] == pins["FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE"],
                "restored scope/authority does not match authenticated deployment pins")
        bootstrap = csv_rows(sql("SELECT encode(receipt_digest,'hex') AS digest FROM public.memory_control_bootstraps WHERE " + where + ";",
                                 database="fleet_recall"))
        require(len(bootstrap) == 1 and bootstrap[0]["digest"] == pins["FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST"],
                "restored bootstrap receipt differs from deployment pin")
        result["generation"] = authority["generation"]
        for database in ("hydra", "kratos"):
            count = csv_rows(sql("SELECT count(*) AS tables FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE';",
                                 database=database))[0]["tables"]
            require(int(count) > 0, "restored Ory database contains no application tables")
            result[database + "_tables"] = int(count)
        result["phase"] = "quarantine"
        grant_query = ("SELECT jti, revoked_at, revoked_by FROM public.memory_session_grants_v1 "
                       "WHERE revoked_at IS NOT NULL ORDER BY jti;")
        revoked_before = sql(grant_query, database="fleet_recall")
        (directory / "revoked-before.csv").write_bytes(revoked_before)
        # Quarantine ALL formerly unrevoked rows, including expired ones. There
        # is no FK on revoked_by; a per-rehearsal UUID identifies the ceremony.
        operator = str(uuid.uuid4())
        sql("UPDATE public.memory_session_grants_v1 SET revoked_at=now(), revoked_by=" + literal(operator)
            + "::UUID WHERE revoked_at IS NULL RETURNING NOTHING;", database="fleet_recall")
        revoked_after = csv_rows(sql(grant_query, database="fleet_recall"))
        indexed = {row["jti"]: row for row in revoked_after}
        require(all(indexed.get(row["jti"]) == row for row in csv_rows(revoked_before)),
                "restore quarantine changed a previously revoked grant")
        remaining = csv_rows(sql("SELECT count(*) AS count FROM public.memory_session_grants_v1 WHERE revoked_at IS NULL;",
                                database="fleet_recall"))[0]["count"]
        require(remaining == "0", "restored unrevoked grants remain")
        result["preserved_revocations"] = len(csv_rows(revoked_before))
        result["quarantined_grants"] = len(revoked_after) - result["preserved_revocations"]
        result["revocation_operator"] = operator
        inspect()
        result.update(phase="complete", complete=True)
    except KeyboardInterrupt:
        result.update(interrupted=True, complete=False)
        raise
    finally:
        with cleanup_signals():
            if container_id is not None:
                try:
                    run(["docker", "stop", "--time=30", container_id], timeout=45)
                    result["container_stopped"] = True
                except (OSError, RuntimeError, subprocess.TimeoutExpired):
                    result["container_stopped"] = False
                    result["complete"] = False
            result["elapsed_seconds"] = round(time.monotonic() - started, 2)
            (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    require(result.get("container_stopped"), "restore finished but container stop needs attention")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True, help="original source state path, never modified")
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--source-cluster-uid", required=True, help="known source kube-system namespace UID")
    parser.add_argument("--destination-parent", type=Path, required=True, help="existing private directory for a NEW recovery child")
    parser.add_argument("--max-backup-age-hours", type=int, default=24)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    require(1 <= args.max_backup_age_hours <= 24 * 365, "invalid backup age bound")
    os.umask(0o077)
    # The source may have been lost. Its path is an identity in the checkpoint,
    # not a live filesystem or cluster connection requirement.
    state = args.state.expanduser().resolve()
    backup = args.backup.resolve(strict=True)
    parent = args.destination_parent.resolve(strict=True)
    require(parent.is_dir() and stat.S_IMODE(parent.stat().st_mode) & 0o077 == 0,
            "recovery destination parent must be a private directory (0700)")
    manifest, plaintext = authenticate(backup, state, args.source_cluster_uid, args.max_backup_age_hours)
    inputs = recovery_inputs(plaintext)
    print("PASS authenticated checkpoint, archive safety, and protected-key inventory", flush=True)
    if not args.apply:
        print("Plan: new private store; Docker network none; no ports; restore SQL, spool, keys; verify and quarantine; stop.")
        return
    directory = parent / ("fleet-restore-" + time.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(4))
    directory.mkdir(mode=0o700)
    print("Private recovery rehearsal: " + str(directory), flush=True)
    (directory / "source.json").write_text(json.dumps({"backup": str(backup), "source_cluster_uid": args.source_cluster_uid,
                                                       "created_at": manifest["created_at"], "started_at": time.time()}, indent=2) + "\n")
    restore(directory, plaintext, inputs)
    print("PASS isolated SQL/Ory data, authority, spool/key recovery, and grant quarantine; container stopped.")
    print("Application OAuth/Recall qualification and pending-work replay remain separate gates.")


if __name__ == "__main__":
    try:
        with interruption_signals():
            main()
    except (Exception, KeyboardInterrupt):
        # Command errors and JSON values can contain secrets. Keep stdout terse;
        # private artifacts identify the failed phase without a secret traceback.
        raise SystemExit("FAIL restore checkpoint rehearsal; inspect the private result and command logs") from None
