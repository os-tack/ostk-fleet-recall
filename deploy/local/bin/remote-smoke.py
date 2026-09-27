#!/usr/bin/env python3
"""Prove public Ory OAuth -> enrolled HTTP memory -> immediate revocation.

Creates a disposable local Ory identity and one clearly labelled claim. Keeps
credentials, HTTP responses, enrollment declarations and evidence private.
"""
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener
import uuid


def main():
    here = Path(__file__).resolve().parent
    state = Path(os.environ.get("FLEET_LOCAL_STATE", here.parent / ".state"))
    os.umask(0o077)
    directory = state / "remote-smoke" / (time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4))
    directory.mkdir(parents=True, mode=0o700)
    spec = importlib.util.spec_from_file_location("ory_smoke", here / "oauth-headless-smoke.py")
    ory = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ory)
    opener = build_opener(ProxyHandler({}))
    count = 0

    def request(path, *, token=None, message=None):
        nonlocal count
        headers = {"content-type": "application/json"}
        if token:
            headers["authorization"] = "Bearer " + token
        body = None if message is None else json.dumps(message).encode()
        req = Request("http://localhost:8080" + path, data=body, headers=headers)
        try:
            response = opener.open(req, timeout=40)
        except HTTPError as error:
            response = error
        with response:
            data = json.loads(response.read()) if response.status != 202 else None
            count += 1
            ory.private_json(directory / f"mcp-{count:02d}.json", {"status": response.status, "body": data})
            return response.status, dict(response.headers), data

    def require(condition, message):
        if not condition:
            raise ory.SmokeFailure(message)

    def tool(token, name, arguments):
        return request("/mcp", token=token, message={"jsonrpc": "2.0", "id": count + 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}})

    def successful(response):
        status, _, body = response
        require(status == 200 and "error" not in body and not body["result"].get("isError"), "MCP operation did not succeed")
        return body["result"]["structuredContent"]

    def enroll(*arguments):
        with (directory / "enrollment.log").open("a") as output:
            subprocess.run([str(here / "serve-remote.sh"), "enroll", *arguments], check=True, stdout=output, stderr=output, timeout=120)

    try:
        status, headers, _ = request("/mcp")
        require(status == 401 and "resource_metadata=" in headers.get("WWW-Authenticate", headers.get("www-authenticate", "")), "Missing bearer challenge")
        metadata = request("/.well-known/oauth-protected-resource/mcp")
        require(metadata[0] == 200 and metadata[2]["resource"] == "http://localhost:8080/mcp", "Wrong protected resource metadata")
        ory.wait_ready(60)
        ory.run(directory)
        token = json.loads((directory / "token.json").read_text())["access_token"]
        identity = json.loads((directory / "result.json").read_text())["identity_id"]
        require(tool(token, "recall", {"action": "status"})[0] == 403, "Unenrolled identity was not refused")
        principal_id = str(uuid.uuid4())
        declaration = {"principals": [{"principal_id": principal_id, "anchor_id": "hydra", "subject_pattern": identity, "role": "operator", "tenant_id": "0198a849-f6ae-7d61-9800-000000000001", "project": "local-k0s", "ceiling": "project", "agent_pattern": "human-smoke"}]}
        declaration_path = directory / "principal.json"
        ory.private_json(declaration_path, declaration)
        try:
            enroll("apply", "--file", str(declaration_path), "--bootstrap-scopes")
            initialize = request("/mcp", token=token, message={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "remote-smoke", "version": "1"}}})
            require(initialize[0] == 200 and "error" not in initialize[2], "Legacy initialization failed")
            successful(tool(token, "recall", {"action": "status"}))
            record = successful(tool(token, "remember", {"action": "record", "kind": "note", "text": "Local M2 OAuth smoke: enrolled human can record and recall.", "idempotency_key": "remote-smoke-" + principal_id}))
            claim = record["data"]["claim"]["id"]
            recalled = successful(tool(token, "recall", {"action": "get", "kind": "claim", "id": claim}))
            require(recalled["data"]["claim"]["id"] == claim, "Recorded claim did not round trip")
            require(tool(token, "recall", {"action": "status", "scope": {"project": "forbidden"}})[0] == 403, "Cross-project request was not denied")
        finally:
            enroll("revoke", principal_id)
        require(tool(token, "recall", {"action": "status"})[0] == 401, "Revoked identity remained authorized")
        ory.private_json(directory / "remote-result.json", {"passed": True, "principal_id": principal_id, "claim_id": claim, "revoked": True})
        print(f"PASS OAuth, enrollment, recall, remember, scope denial and immediate revocation. Evidence: {directory}")
        return 0
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ory.SmokeFailure) as error:
        ory.private_json(directory / "remote-failure.json", {"type": type(error).__name__, "detail": str(error)})
        print(f"FAIL remote smoke; protected diagnostics: {directory}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
