#!/usr/bin/env python3
"""Exercise the real stdio shim without using a provider or an API key."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import uuid


def run():
    instance = os.environ["FLEET_SANDBOX_INSTANCE"]
    uuid.UUID(instance)
    session = str(uuid.uuid4())
    directory = Path("/transcripts/claude/synthetic")
    directory.mkdir(mode=0o750)
    transcript = directory / f"{session}.jsonl"
    process = subprocess.Popen(["/usr/local/bin/recall-shim"], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    counter = 0

    def request(method, params=None):
        nonlocal counter
        counter += 1
        payload = {"jsonrpc": "2.0", "id": counter, "method": method}
        if params is not None:
            payload["params"] = params
        process.stdin.write(json.dumps(payload).encode() + b"\n")
        process.stdin.flush()
        if not selector.select(timeout=40):
            raise RuntimeError("shim response timeout")
        line = process.stdout.readline(1_048_577)
        if len(line) > 1_048_576 or not line.endswith(b"\n"):
            raise RuntimeError("invalid or oversized shim frame")
        result = json.loads(line)
        if result.get("id") != counter or "error" in result or result["result"].get("isError"):
            raise RuntimeError("synthetic MCP operation failed")
        return result["result"]

    def turn(role, text):
        with transcript.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"type": role, "sessionId": session, "uuid": str(uuid.uuid4()),
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "message": {"role": role, "content": [{"type": "text", "text": text}]}}) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    try:
        turn("user", f"Synthetic sandbox {instance}: verify Recall, remember a note, and read it back.")
        request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "fleet-sandbox-synthetic", "version": "1"}})
        tools = request("tools/list")
        if {tool["name"] for tool in tools["tools"]} != {"recall", "remember"}:
            raise RuntimeError("unexpected tool surface")
        request("tools/call", {"name": "recall", "arguments": {"action": "status"}})
        receipt = request("tools/call", {"name": "remember", "arguments": {
            "action": "record", "kind": "note", "text": f"M3 synthetic sandbox {instance} used isolated Recall grants.",
            "idempotency_key": f"sandbox-{instance}",
        }})
        claim = receipt["structuredContent"]["data"]["claim"]["id"]
        recalled = request("tools/call", {"name": "recall", "arguments": {"action": "get", "kind": "claim", "id": claim}})
        if recalled["structuredContent"]["data"]["claim"]["id"] != claim:
            raise RuntimeError("claim did not round trip")
        turn("assistant", f"Synthetic sandbox {instance} listed tools, checked status, and recorded and recalled claim {claim}.")
        print(json.dumps({"passed": True, "instance": instance, "claim_id": claim}))
    finally:
        selector.close()
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=5)


if __name__ == "__main__":
    try:
        run()
    except (OSError, ValueError, KeyError, RuntimeError):
        print("synthetic Recall check failed", file=sys.stderr)
        sys.exit(1)
