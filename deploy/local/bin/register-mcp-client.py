#!/usr/bin/env python3
"""Register a public native Claude MCP client, retaining credentials privately.

The pinned Hydra returns optional empty DCR metadata rejected by strict clients.
Supplying the returned public client ID uses standard pre-registration instead.
Only that non-secret ID is printed; registration tokens stay in local state.
"""
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener


def main():
    here = Path(__file__).resolve().parents[1]
    state = Path(os.environ.get("FLEET_LOCAL_STATE", here / ".state"))
    if not (state / "kubeconfig").is_file():
        sys.exit("Run the local environment bootstrap first, or set FLEET_LOCAL_STATE.")
    os.umask(0o077)
    registration = {
        "client_name": "Claude Code local Recall",
        "redirect_uris": ["http://localhost:43110/callback", "http://127.0.0.1:43110/callback"],
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "token_endpoint_auth_method": "none", "scope": "openid offline_access fleet-recall",
    }
    request = Request("http://localhost:4444/oauth2/register", data=json.dumps(registration).encode(), headers={"content-type": "application/json"})
    try:
        with build_opener(ProxyHandler({})).open(request, timeout=15) as response:
            client = json.loads(response.read(262145))
        client_id = client["client_id"]
        if not isinstance(client_id, str) or not client_id or len(client_id) > 256 or any(c.isspace() for c in client_id):
            raise ValueError("invalid client ID")
        directory = state / "mcp-clients"
        directory.mkdir(exist_ok=True, mode=0o700)
        # Use a locally generated filename, never provider content as a path.
        import secrets
        path = directory / (secrets.token_hex(12) + ".json")
        with path.open("x", encoding="utf-8") as output:
            json.dump(client, output)
        print(client_id)
        return 0
    except (OSError, ValueError, KeyError, HTTPError, URLError):
        print("Local Ory client registration failed; no credential was printed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
