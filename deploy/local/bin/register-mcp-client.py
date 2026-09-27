#!/usr/bin/env python3
"""Register a public native MCP client, retaining credentials privately.

The pinned Hydra returns optional empty DCR metadata rejected by strict clients.
Supplying the returned public client ID uses standard pre-registration instead.
Only that non-secret ID is printed; registration tokens stay in local state.
"""
import argparse
import importlib.util
import json
import os
import secrets
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request

_helper = Path(__file__).resolve().parents[1] / "https" / "ory" / "http_client.py"
_spec = importlib.util.spec_from_file_location("fleet_ory_http", _helper)
_http = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_http)


def main():
    here = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    _http.add_arguments(parser)
    parser.add_argument("--state", type=Path,
                        default=Path(os.environ.get("FLEET_LOCAL_STATE", here / ".state")))
    parser.add_argument("--client-name", default="Claude Code local Recall")
    parser.add_argument("--redirect-uri", action="append")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        profile = _http.Profile.from_args(args)
        redirects = args.redirect_uri or ([args.callback_url] if args.callback_url else
                                          ["http://localhost:43110/callback", "http://127.0.0.1:43110/callback"])
        for value in redirects:
            _http.checked_url(value, callback=True)
        if not 1 <= len(args.client_name) <= 128 or any(ord(c) < 32 for c in args.client_name):
            raise ValueError("invalid client name")
        registration = {
            "client_name": args.client_name, "redirect_uris": redirects,
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
            "token_endpoint_auth_method": "none", "scope": "openid offline_access fleet-recall",
        }
        request = Request(profile.issuer + "oauth2/register", data=json.dumps(registration).encode(),
                          headers={"content-type": "application/json"})
        with profile.opener().open(request, timeout=15) as response:
            data = response.read(262145)
            if response.status != 201 or len(data) > 262144:
                raise ValueError("invalid registration response")
            client = json.loads(data)
        if not isinstance(client, dict):
            raise ValueError("invalid registration object")
        client_id = client["client_id"]
        if (not isinstance(client_id, str) or not client_id or len(client_id) > 256
                or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in client_id)):
            raise ValueError("invalid client ID")
        directory = args.state / "mcp-clients"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Use a locally generated filename, never provider content as a path.
        path = directory / (secrets.token_hex(12) + ".json")
        with path.open("x", encoding="utf-8") as output:
            json.dump(client, output)
        print(client_id)
        return 0
    except (_http.SmokeFailure, OSError, ValueError, KeyError, HTTPError, URLError):
        print("Local Ory client registration failed; no credential was printed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
