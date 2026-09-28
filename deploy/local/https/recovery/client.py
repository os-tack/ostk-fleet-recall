"""Run inside the restore SQL network namespace; credentials remain private."""

import hashlib
import importlib.util
import json
import os
import secrets
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request

ROOT = Path("/proof")
SPEC = importlib.util.spec_from_file_location("ory_smoke", ROOT / "helpers/bin/oauth-headless-smoke.py")
ORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORY)
PROFILE = ORY.Profile("https", ca_path=ROOT / "tls/root.pem")
OPENER = PROFILE.opener()
COUNTER = 0


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def tool(token, name, arguments, *, success=True):
    global COUNTER
    COUNTER += 1
    data = json.dumps({"jsonrpc": "2.0", "id": COUNTER, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments}}).encode()
    request = Request(PROFILE.resource, data=data, headers={"Authorization": "Bearer " + token,
                      "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    try:
        response = OPENER.open(request, timeout=45)
    except HTTPError as error:
        response = error
    with response:
        value = json.loads(response.read(4 * 1024 * 1024))
        (ROOT / f"mcp-{sys.argv[1]}-{COUNTER:03d}.json").write_text(json.dumps({"status": response.status, "body": value}))
        if not success:
            return response.status, value
        require(response.status == 200 and "error" not in value and not value.get("result", {}).get("isError"),
                "restored authenticated MCP operation failed")
        return value["result"]["structuredContent"]


def oauth(subject, known_claim):
    directory = ROOT / "oauth"
    directory.mkdir(mode=0o700)
    ORY.wait_ready(150, PROFILE)
    ORY.run(directory, PROFILE, ROOT / "account.json", subject)
    token = json.loads((directory / "token.json").read_text())["access_token"]
    deadline = time.monotonic() + 90
    while True:
        try:
            status = tool(token, "recall", {"action": "status"})
            break
        except (OSError, RuntimeError, URLError):
            require(time.monotonic() < deadline, "restored Recall failed to become ready")
            time.sleep(2)
    authority = json.loads((ROOT / "authority.json").read_text())
    runtime = status["data"]["remember_assert"]
    require(runtime.get("served") is True and runtime["registry"]["generation"] == authority["generation"]
            and runtime["registry"]["activation_id"] == authority["activation_id"],
            "restored runtime did not verify the pinned writer authority")
    # A known pre-backup claim proves recovered SQL/body decryption with the
    # restored KEK, rather than testing only a post-restore write/read pair.
    prior = tool(token, "recall", {"action": "get", "kind": "claim", "id": known_claim})
    require(prior["data"]["claim"]["id"] == known_claim and prior["data"]["claim"].get("text"), "pre-backup claim body not recovered")
    marker = "restore-replay-" + secrets.token_hex(8)
    created = tool(token, "remember", {"action": "record", "kind": "note", "text": "Isolated recovery " + marker,
                                      "idempotency_key": marker})
    claim = created["data"]["claim"]["id"]
    recalled = tool(token, "recall", {"action": "get", "kind": "claim", "id": claim})
    require(recalled["data"]["claim"]["id"] == claim, "restored write/read did not round trip")
    require(tool(token, "recall", {"action": "status", "scope": {"project": "forbidden-restore-scope"}}, success=False)[0] == 403,
            "restored cross-project authorization gate did not refuse")
    # Stage a pending turn in the isolated working copy only. The immutable
    # recovered spool remains unchanged. A second worker tick proves replay.
    candidates = sorted((ROOT / "spool/transcripts").glob("*/*/claude-code/*.jsonl.meta"))
    require(bool(candidates), "checkpoint has no recoverable Claude transcript")
    meta_path = candidates[0]
    metadata = json.loads(meta_path.read_text())
    path = meta_path.with_suffix("")
    before = path.read_bytes()
    require(before.endswith(b"\n") and hashlib.sha256(before.splitlines(keepends=True)[0]).hexdigest() == metadata["first_line_sha256"],
            "restored spool first-line/provenance gate differs")
    first = json.loads(before.splitlines()[0])
    turn = {"type": "assistant", "sessionId": first["sessionId"], "uuid": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": {"role": "assistant", "content": [{"type": "text", "text": "Isolated pending recovery turn " + marker}]}}
    with path.open("ab") as stream:
        stream.write(json.dumps(turn).encode() + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    result = {"passed": True, "identity_subject": subject, "prior_claim_id": known_claim, "new_claim_id": claim,
              "scope_denied": True, "writer_authority_verified": True, "pending_marker": marker, "pending_file": str(path.relative_to(ROOT)),
              "recovered_prefix_sha256": hashlib.sha256(before).hexdigest(), "recovered_prefix_bytes": len(before),
              "staged_bytes": path.stat().st_size}
    (ROOT / "client-oauth.json").write_text(json.dumps(result, indent=2))


def verify():
    first = json.loads((ROOT / "client-oauth.json").read_text())
    token = json.loads((ROOT / "oauth/token.json").read_text())["access_token"]
    marker = first["pending_marker"]
    found = tool(token, "recall", {"action": "search", "kind": "evidence", "source": "sessions", "query": marker, "limit": 20})
    matches = [row for row in found["data"]["hits"] if marker in row.get("snippet", "")]
    require(len(matches) == 1, "pending transcript turn did not produce exactly one Recall evidence match")
    evidence = tool(token, "recall", {"action": "get", "kind": "evidence", "id": matches[0]["id"]})
    require(marker in evidence["data"]["evidence"]["text"], "replayed evidence body differs")
    restored_file = ROOT / first["pending_file"]
    body = restored_file.read_bytes()
    require(len(body) == first["staged_bytes"]
            and hashlib.sha256(body[:first["recovered_prefix_bytes"]]).hexdigest() == first["recovered_prefix_sha256"],
            "worker replay changed acknowledged recovered spool bytes")
    (ROOT / "client-verify.json").write_text(json.dumps({"passed": True, "evidence_id": matches[0]["id"],
        "recovered_prefix_preserved": True, "worker_ticks": 2, "evidence_matches": len(matches)}, indent=2))


if __name__ == "__main__":
    os.umask(0o077)
    try:
        if sys.argv[1] == "oauth":
            oauth(sys.argv[2], int(sys.argv[3]))
        elif sys.argv[1] == "verify":
            verify()
        else:
            raise RuntimeError("unknown proof stage")
    except Exception as error:
        (ROOT / ("client-" + sys.argv[1] + "-failure.json")).write_text(json.dumps({"error_type": type(error).__name__, "detail": str(error)}))
        raise SystemExit("isolated recovery client failed; inspect private failure artifact") from None
