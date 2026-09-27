#!/usr/bin/env bash
# Run the M2 HTTP service on the Mac against secure k0s CockroachDB and Ory.
# With `enroll ...`, run the enrollment ceremony using only its own credential.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
repo=$(cd "$here/../.." && pwd)
exec python3 - "$repo" "${FLEET_LOCAL_STATE:-$here/.state}" \
    "${FLEET_RECALL_BIN:-$repo/target/debug/ostk-fleet-recall}" \
    "${FLEET_RECALL_MODEL_BUNDLE:-}" "$@" <<'PY'
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from urllib.parse import urlencode

repo, state, binary = (Path(value).resolve() for value in sys.argv[1:4])
bundle_override, *arguments = sys.argv[4:]
if arguments in [["--help"], ["-h"]]:
    print("Usage: deploy/local/bin/serve-remote.sh [enroll {apply --file FILE [--bootstrap-scopes]|list|revoke UUID}]")
    print("Defaults to serve --http 127.0.0.1:8080; resource URL is http://localhost:8080/mcp.")
    print("Overrides: FLEET_LOCAL_STATE, FLEET_RECALL_BIN, FLEET_RECALL_MODEL_BUNDLE.")
    print("Telemetry: FLEET_RECALL_LOG_FORMAT (default json); HTTP service optionally inherits FLEET_RECALL_METRICS_LISTEN and FLEET_RECALL_METRICS_ALLOW_NON_LOOPBACK.")
    sys.exit(0)
if arguments and arguments[0] != "enroll":
    sys.exit("Only the enroll subcommand is accepted; no arguments starts the HTTP service.")

def fail(message):
    sys.exit("remote plane: " + message)

def regular_file(path):
    if path.is_symlink() or not path.is_file():
        fail(f"required regular file is missing or a symlink: {path}")
    return path

def hex_value(value, length, label):
    if not re.fullmatch(r"[0-9a-fA-F]{" + str(length) + "}", value):
        fail(label + " must be a valid hexadecimal value")
    return value

if not binary.is_file() or not os.access(binary, os.X_OK):
    fail("build the binary first with cargo build --locked --bin ostk-fleet-recall, or set FLEET_RECALL_BIN")
try:
    password_file = regular_file(state / "passwords.env")
    passwords = dict(line.split("=", 1) for line in password_file.read_text().splitlines() if "=" in line)
    ca = regular_file(state / "certs" / "ca.crt")
    digest = hex_value(regular_file(state / "model.sha256").read_text().strip(), 64, "model digest")
    bundle = Path(bundle_override).resolve() if bundle_override else state.parents[2] / ".models" / "potion-retrieval-32M-6fc8051fab2a1e0ee76689cf08c853792ac285e7"
    for name in ["config.json", "model.safetensors", "tokenizer.json"]:
        regular_file(bundle / name)

    # Build a fresh environment instead of inheriting PG*, other database
    # credentials, cloud credentials, or unrelated ceremony configuration.
    environment = {name: os.environ[name] for name in ["PATH", "HOME"] if name in os.environ}
    environment.update({
        "RUST_LOG": "ostk_fleet_recall=info",
        "FLEET_RECALL_LOG_FORMAT": os.environ.get("FLEET_RECALL_LOG_FORMAT", "json"),
        "FLEET_RECALL_MAX_CONNECTIONS": "4",
        "FLEET_RECALL_EMBEDDING_MODEL": "minishlab/potion-retrieval-32M",
        "FLEET_RECALL_EMBEDDING_MODEL_PATH": str(bundle),
        "FLEET_RECALL_EMBEDDING_MODEL_SHA256": digest,
    })
    query = urlencode({"sslmode": "verify-full", "sslrootcert": str(ca)})
    if arguments:
        password = hex_value(passwords.get("ENROLLMENT_PASSWORD", ""), 48, "enrollment password (run the updated secrets phase)")
        environment["FLEET_RECALL_ENROLLMENT_DATABASE_URL"] = f"postgresql://fleet_enrollment:{password}@127.0.0.1:26258/fleet_recall?{query}"
    else:
        # Explicit telemetry opt-ins apply only to the long-running service.
        # Never inherit the scheduled worker's textfile destination.
        for name in ["FLEET_RECALL_METRICS_LISTEN", "FLEET_RECALL_METRICS_ALLOW_NON_LOOPBACK"]:
            if name in os.environ:
                environment[name] = os.environ[name]
        password = hex_value(passwords.get("WRITER_PASSWORD", ""), 48, "writer password")
        report = json.loads(regular_file(state / "authority.json").read_text())
        pins = report.get("pins", {})
        if report.get("generation", 0) < 3 or report.get("package") != "collected_items_generation3" or pins.get("FLEET_RECALL_CONTRACT_TENANT_NAMESPACE") != "tenant.local" or pins.get("FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE") != "project.local":
            fail("authority report does not contain the expected generation-3 local scope")
        receipt = hex_value(pins.get("FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST", ""), 64, "bootstrap receipt digest")
        signing_path = state / "remote-grant-signing-key.hex"
        if not signing_path.exists():
            try:
                descriptor = os.open(signing_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(descriptor, "w") as output:
                    output.write(secrets.token_hex(32) + "\n")
        regular_file(signing_path)
        if stat.S_IMODE(signing_path.stat().st_mode) & 0o077:
            fail("grant signing key permissions must be 0600 or stricter")
        signing_key = hex_value(signing_path.read_text().strip(), 64, "grant signing key")
        environment.update({
            "FLEET_RECALL_DATABASE_URL": f"postgresql://fleet_writer:{password}@127.0.0.1:26258/fleet_recall?{query}",
            "FLEET_RECALL_TENANT_ID": "0198a849-f6ae-7d61-9800-000000000001",
            "FLEET_RECALL_PROJECT": "local-k0s",
            "FLEET_RECALL_AGENT": "k0s",
            "FLEET_RECALL_CONTRACT_TENANT_NAMESPACE": "tenant.local",
            "FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE": "project.local",
            "FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST": receipt,
            "FLEET_RECALL_CONTENT_KEK_HEX": hex_value(passwords.get("CONTENT_KEK_HEX", ""), 64, "content key"),
            "FLEET_RECALL_RESOURCE_URL": "http://localhost:8080/mcp",
            "FLEET_RECALL_OIDC_ISSUERS": "hydra=http://localhost:4444/",
            "FLEET_RECALL_OAUTH_ADVERTISED_ANCHORS": "hydra",
            "FLEET_RECALL_OAUTH_SCOPES": "openid,offline_access,fleet-recall",
            "FLEET_RECALL_OIDC_SCOPE_SUBSTITUTES": "hydra=fleet-recall",
            "FLEET_RECALL_GRANT_SIGNING_KEY_HEX": signing_key,
        })
        arguments = ["serve", "--http", "127.0.0.1:8080"]
except (OSError, ValueError, TypeError):
    fail("could not read valid local state; run bootstrap and verify its generated files")

# Credentials stay in the environment and never appear in process arguments.
os.execve(binary, [str(binary), *arguments], environment)
PY
