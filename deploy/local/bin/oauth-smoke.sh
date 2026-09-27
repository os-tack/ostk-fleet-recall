#!/usr/bin/env bash
# PKCE authorization-code smoke test against local Hydra + Kratos. Registers
# a public client, receives the browser callback, exchanges the code and checks
# the issued JWT's issuer, expiry, subject and fleet-recall scope. Tokens and
# authorization codes are never printed. Recall accepts these tokens from M2.
set -euo pipefail
issuer=${HYDRA_ISSUER:-http://localhost:4444}
issuer=${issuer%/}
port=${CALLBACK_PORT:-43110}
redirect="http://localhost:$port/callback"

# Discovery is the authority for the exact issuer, including its trailing slash.
expected_issuer=$(curl -sf --max-time 30 "$issuer/.well-known/openid-configuration" | jq -er '.issuer | select(type == "string" and length > 0)')
response=$(curl -sS --max-time 30 -w '\n%{http_code}' -X POST "$issuer/oauth2/register" -H 'content-type: application/json' -d "{
  \"client_name\": \"fleet-recall oauth smoke\",
  \"redirect_uris\": [\"$redirect\"],
  \"grant_types\": [\"authorization_code\", \"refresh_token\"],
  \"response_types\": [\"code\"],
  \"token_endpoint_auth_method\": \"none\",
  \"scope\": \"openid offline_access fleet-recall\"
}")
if [ "${response##*$'\n'}" != 201 ]; then
    echo "dynamic client registration did not return 201" >&2
    exit 1
fi
client=${response%$'\n'*}
client_id=$(printf '%s' "$client" | jq -er '.client_id | select(type == "string" and length > 0)')
printf '%s' "$client" | jq -e '.token_endpoint_auth_method == "none"' >/dev/null
echo "registered a public client (201)"

# 32 random bytes encode to 43 PKCE characters, with no deletion bias.
verifier=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')
challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
stateval=$(openssl rand -hex 16)
enc() { printf '%s' "$1" | jq -sRr @uri; }
auth_url="$issuer/oauth2/auth?client_id=$(enc "$client_id")&response_type=code&scope=$(enc 'openid offline_access fleet-recall')&redirect_uri=$(enc "$redirect")&state=$stateval&code_challenge=$challenge&code_challenge_method=S256&resource=$(enc 'http://localhost:8080/mcp')"

# Bind before launching the browser: an existing login/consent session may
# redirect immediately. Only the code is stdout; prompts go directly to stderr.
code=$(python3 - "$port" "$stateval" "$auth_url" <<'PY'
import hmac
import http.server
import os
import subprocess
import sys
import time
import urllib.parse

port, expected, auth_url = int(sys.argv[1]), sys.argv[2], sys.argv[3]
result = {}

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(url.query)
        if url.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return
        states = query.get("state", [])
        if len(states) != 1 or not hmac.compare_digest(states[0], expected):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"state mismatch")
            return
        codes = query.get("code", [])
        if "error" in query or len(codes) != 1 or not codes[0]:
            result["error"] = True
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"authorization failed; see the terminal")
            return
        result["code"] = codes[0]
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"authorization received; you can close this tab")

    def log_message(self, *args):
        pass

with http.server.HTTPServer(("127.0.0.1", port), Handler) as server:
    server.timeout = 1
    print("open this URL, register or log in, and approve:", file=sys.stderr, flush=True)
    print(f"  {auth_url}", file=sys.stderr, flush=True)
    if os.environ.get("OAUTH_SMOKE_NO_OPEN") != "1":
        try:
            subprocess.Popen(["open", auth_url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            pass
    deadline = time.monotonic() + 600
    while not result and time.monotonic() < deadline:
        server.handle_request()
if "code" not in result:
    sys.exit("authorization failed or callback timed out after 10 minutes")
print(result["code"])
PY
)

token=$(curl -sf --max-time 30 -X POST "$issuer/oauth2/token" \
  --data-urlencode grant_type=authorization_code --data-urlencode "client_id=$client_id" \
  --data-urlencode "code=$code" --data-urlencode "redirect_uri=$redirect" \
  --data-urlencode "code_verifier=$verifier" --data-urlencode 'resource=http://localhost:8080/mcp')
# Decode the JWT returned by the trusted token endpoint, without putting the
# access token in process arguments or printing it (or identity claims).
printf '%s' "$token" | python3 -c '
import base64
import json
import sys
import time

try:
    token = json.load(sys.stdin)
    access = token["access_token"]
    parts = access.split(".")
    if len(parts) != 3 or not all(parts):
        raise ValueError("access token is not a compact JWT")
    def decode(part):
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    header, claims = decode(parts[0]), decode(parts[1])
    if header.get("alg") not in ("RS256", "ES256", "EdDSA"):
        raise ValueError("unexpected JWT signing algorithm")
    if claims.get("iss") != sys.argv[1]:
        raise ValueError("access-token issuer differs from discovery")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise ValueError("access token has no subject")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= time.time():
        raise ValueError("access token is expired or has no expiry")
    scopes = claims.get("scp", claims.get("scope", []))
    if isinstance(scopes, str):
        scopes = scopes.split()
    if not isinstance(scopes, list) or "fleet-recall" not in scopes:
        raise ValueError("access token lacks the fleet-recall scope")
    if str(token.get("token_type", "")).lower() != "bearer":
        raise ValueError("token response is not Bearer")
except (KeyError, TypeError, ValueError) as error:
    sys.exit("OAuth token check failed: " + str(error))
print("PASS: PKCE login yielded an unexpired JWT with the Hydra issuer and fleet-recall scope")
print(json.dumps({"issuer": claims["iss"], "scopes": scopes, "expires_at": claims["exp"]}, indent=2))
' "$expected_issuer"
