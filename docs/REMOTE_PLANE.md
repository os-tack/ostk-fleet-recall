# Remote HTTP MCP

The M2 remote plane serves one authenticated `/mcp` endpoint and resolves each
request into a tenant, project, agent, role, and visibility ceiling. The stdio
server continues to use its deployment identity. M3 adds a pinned embedding
service, stdio shim, Docker/Kubernetes launcher, and scoped transcript spool
for Claude Code and Codex. Local in-process embedding remains supported.

## Prepare the database and enrollment login

Apply migrations through 39 with the one-shot migrator, retire that login,
then apply `deploy/cockroach/runtime-role-grants.sql` and
`deploy/cockroach/enrollment-role-grants.sql` as the deployment administrator.
Follow each policy's quiescence and cross-database audit preconditions. The
fixed login `fleet_enrollment` inherits only `fleet_enrollment_manager`.
Enable LOGIN after the policy passes, and keep its password on the enrollment
workstation. Runtime deployments receive only `fleet_writer` credentials.

Enrollment can SELECT/INSERT/UPDATE the principal registry and SELECT/INSERT
the corpus model registry. It cannot read claims, evidence, content, or grants,
delete rows, or run DDL. The runtime can read principals and
SELECT/INSERT/UPDATE grants, but cannot change principal bindings.

Create a JSON file with stable principal IDs:

```json
{
  "principals": [{
    "principal_id": "0198a849-f6ae-7d61-9800-000000000101",
    "anchor_id": "human",
    "subject_pattern": "exact-verified-issuer-subject",
    "role": "operator",
    "tenant_id": "0198a849-f6ae-7d61-9800-000000000001",
    "project": "local-k0s",
    "ceiling": "project",
    "agent_pattern": "human-*"
  }]
}
```

Run enrollment in a separate environment with
`FLEET_RECALL_ENROLLMENT_DATABASE_URL` and no other database URL or content key:

```sh
ostk-fleet-recall enroll apply --file principals.json --bootstrap-scopes
ostk-fleet-recall enroll list
ostk-fleet-recall enroll revoke 0198a849-f6ae-7d61-9800-000000000101
```

`--bootstrap-scopes` additionally requires the runtime's pinned model name and
digest, plus either its local bundle path or embedding tier URL. It initializes each distinct tenant/project
without replacing an existing active model. Apply validates the complete
document before writes; unchanged declarations preserve their revisions.
`--prune` revokes every principal omitted from the file, so use it only for a
complete registry document. Revocation preserves audit history.

Exact subjects take precedence over trailing-`*` prefixes; the longest prefix
wins, and ties deny access. A revoked exact match never falls through to an
active wildcard. Operator/shipper wildcard agents derive a stable 32-hex
identity digest, with at most 96 prefix characters. Launcher agent patterns
constrain the agent supplied when minting grants. Agent identifiers use the
lowercase contract-ID alphabet. `private` and `trusted` ceilings are refused
until owner/tier visibility is enforced; `public` is read-only through the
existing publication composition, including its asserted-claim withholding.

## Run and connect

Configure the ordinary writer URL, model, and pinned default scope, plus:

```sh
export FLEET_RECALL_RESOURCE_URL=http://localhost:8080/mcp
export FLEET_RECALL_OIDC_ISSUERS=human=http://localhost:4444/
export FLEET_RECALL_OIDC_SCOPE_SUBSTITUTES=human=fleet-recall
# Supply FLEET_RECALL_GRANT_SIGNING_KEY_HEX from a private secret store.
ostk-fleet-recall serve --http 127.0.0.1:8080
claude mcp add --transport http --callback-port 43110 recall http://localhost:8080/mcp
```

Then use Claude Code's `/mcp` authentication flow. Discovery is available at
`/.well-known/oauth-protected-resource/mcp` and its root alias. An
unauthenticated `/mcp` request returns a Bearer challenge naming that metadata.
An identity must both verify at a configured anchor and have an enrolled row.
The stock client may negotiate legacy initialization; the server also accepts
modern `server/discover` and validates the protocol metadata and mirrored
headers before dispatch. Responses use JSON, without SSE or HTTP sessions.
Modern discovery and tool lists carry `ttlMs:0` and `cacheScope:"private"`,
because the advertised capabilities depend on the authenticated binding.
For the pinned local Hydra, follow the [local client registration
instructions](../deploy/local/README.md#m2-http-service-and-human-enrollment):
its optional DCR metadata requires the standard `--client-id` path in current
Claude Code.

Codex supports native HTTP MCP and can register directly with local Hydra:

```sh
codex mcp add recall-remote --url http://localhost:8080/mcp
codex mcp login recall-remote --scopes openid,offline_access,fleet-recall
```

The first command may start OAuth immediately. `--no-browser` on `mcp login`
supports a pasted callback for headless workstations. Codex's desktop app,
CLI, and IDE share the MCP configuration on that host. See the
[official Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp).
The verified Ory subject must be enrolled before tools are accessible.

The scope substitute above is an explicit exception for local Hydra, which
issues access tokens without resource audiences. It applies only when the
audience is empty; a nonempty wrong audience is always refused. Other issuers
require the exact resource audience by default. Issuer and JWKS fetches require
HTTPS except literal loopback development, reject redirects, and have bounded
response sizes/timeouts. JWKS cache lifetime is ten minutes, with unknown-key
refreshes limited to once per minute.

The local Kubernetes overlay routes Hydra discovery through
`FLEET_RECALL_OIDC_LOCAL_TRANSPORTS=hydra=http://hydra-public.ory.svc.cluster.local:4444/`.
This explicit development setting is accepted only for a loopback issuer.
JWT and discovery issuer checks retain `http://localhost:4444/`; only URLs
with that exact original origin can be routed. It cannot redirect a production
issuer or an issuer-supplied cross-origin JWKS URL. Production uses reachable
HTTPS issuer URLs directly.

An issuer that authenticates discovery or JWKS requests can use
`FLEET_RECALL_OIDC_DISCOVERY_TOKEN_PATHS=k8s=/var/run/recall-oidc/token`.
Each configured file is bounded to 16 KiB and reread on fetch, supporting
projected-token rotation. Its bearer is sent only to the configured issuer's
origin; redirects, cross-origin JWKS URLs, and combining this credential with
a local transport override are refused. This credential reads verification
metadata and grants no Recall access. The local overlay uses a dedicated
`recall-oidc` service account with GET permission only for discovery and JWKS,
and keeps automatic service-account mounts disabled.

HTTP binds loopback unless `--allow-non-loopback` is passed. Production needs
TLS termination and a matching HTTPS resource URL. Set
`FLEET_RECALL_HTTP_ALLOWED_ORIGINS` to explicit allowed browser origins;
the resource's own origin is also allowed. Requests without Origin are accepted,
and other unlisted origins are refused.
The default inflight cap is 64 and deadline is 30 seconds. Mutation timeouts
preserve the existing unknown-outcome receipt and idempotency semantics.

## Operational visibility

The HTTP server uses the process telemetry runtime described in
[Operating telemetry](TELEMETRY.md). JSON completion events go to stderr by
default. `http_mcp` measures each HTTP response, including origin, capacity,
and authentication rejections; `mcp` measures the nested protocol dispatch.
These are separate boundaries, so summing their counters double-counts
dispatched requests. Generated operation IDs correlate their event spans
without recording bearer tokens, request IDs, scopes, or payloads.

For the local Mac launcher, explicitly enable a separate loopback metrics port:

```sh
FLEET_RECALL_METRICS_LISTEN=127.0.0.1:9091 \
  deploy/local/bin/serve-remote.sh
```

Scrape `http://127.0.0.1:9091/metrics` from the host. The launcher preserves
`FLEET_RECALL_LOG_FORMAT` (default `json`) and, only for HTTP serving, the
metrics listen and non-loopback opt-in settings. It does not inherit the
worker textfile destination. Enrollment commands retain JSON events without
starting the HTTP service's metrics listener.

This process runs on the Mac, outside Kubernetes. The k0s stack discovers
annotated application pods and collects pod stdout/stderr through the API;
it does not automatically scrape this host endpoint or collect its stderr.
Configure a private host scrape target or forwarding path and a host log
collector to include it. The VM's loopback address is not the Mac's loopback
address. Keep the metrics listener private; opening the application listener
does not expose metrics, and no public metrics listener is enabled by this
launcher.

## Other anchors and grants

`FLEET_RECALL_LOCAL_KEY_ANCHOR_PATH` names a JSON object mapping `kid` to a
32-byte Ed25519 public key in hex. Assertions use issuer
`fleet-recall-local-key`, subject equal to `kid`, the resource audience, `jti`,
and at most five minutes of remaining lifetime. Enroll them under `local-key`.

Optional AWS authentication uses `POST /v1/auth/aws` with
`iam_http_request_method:"POST"`, standard padded base64 `iam_request_url`
and `iam_request_body`, plus `iam_request_headers` as a map of header names
to string arrays for a signed STS GetCallerIdentity request. Configure
`FLEET_RECALL_AWS_STS_ENDPOINT`, `FLEET_RECALL_AWS_IAM_SERVER_ID`, and
`FLEET_RECALL_AWS_ALLOWED_ACCOUNTS` together. The proof must bind the server ID
and exact allowed request; the server forwards only to its configured endpoint.
Successful enrolled identities receive a 15-minute identity token. Assumed-role
identities normalize to the IAM role ARN; enroll under `aws-iam`. The local
environment can omit AWS/LocalStack completely.

Only launcher principals can `POST /v1/grants`:

```json
{"kind":"agent","agent":"sandbox-one","sandbox_id":"box-one","ttl_seconds":3600}
```

The reply contains `token` and the persisted grant. `kind:"shipper"` permits
only `remember(capture)` and `recall(status|brief)`; capture still requires a
served capture capability. A sandbox-bound shipper grant can also upload its
own transcripts; a direct shipper principal or agent grant cannot. Agent grants cannot mint further grants. The
issuer or an operator in the same tenant/project can
`DELETE /v1/grants/{jti}`. Tokens default to one hour and are capped at one day.

Grant rows are inserted with a live principal/revision check before signing.
Every bearer request checks the row, expiry, principal revocation/revision,
scope, ceiling, and agent pattern. Positive checks are cached for at most five
seconds (`FLEET_RECALL_GRANT_CHECK_CACHE_SECONDS=0` disables it); direct
principals are resolved on every request. Principal edits invalidate previous
grants. Rotate the signing key to invalidate all outstanding self-issued tokens.

## Scope caches and validation

One process shares a bounded tenant/project cache (default 64) and per-agent
service cache (default 256). Failed startup probes retry after 30 seconds.
An unbootstrapped or model-mismatched scope returns 503. Assert and capture are
enabled only for the default scope with this process's writer-authority pins;
other scopes report those capabilities unavailable. Request bodies cannot
override tenant, project, agent, or privacy tier.

Run `cargo test --locked --all-targets`, then connected tests with
`FLEET_RECALL_TEST_DATABASE_URL` pointing to a **disposable** CockroachDB.
`enroll_live` proves database roles, revisions, pruning, and grants;
`remote_plane_live` exercises real HTTP authentication and scoped memory.
Provider unit tests use fake OIDC/JWKS and STS servers, including key rotation,
wrong claims, redirects, XML responses, and signed-request validation. A fake
STS result is not evidence of a live AWS deployment.

## M3 embedding tier

Start `ostk-fleet-recall embed serve 127.0.0.1:8090` with the model name,
bundle path and SHA256 pin. It needs no database credentials. The tier serves
`GET /v1/descriptor` and `POST /v1/embed` (`{"texts":["example"]}`), with at
most 64 texts of 256 KiB each. Set `FLEET_RECALL_EMBEDDING_TIER_TOKEN` on both
the tier and consumers to require a static bearer. Keep non-loopback HTTP on
a private development network; production should use HTTPS.

Consumers set `FLEET_RECALL_EMBEDDING_TIER_URL` and keep their model name and
digest pin; the bundle path becomes optional. Startup checks the complete
512-dimensional descriptor, and every embedding response must match it.
`FLEET_RECALL_EMBEDDING_TIER_TIMEOUT_MS` defaults to 2000. Only connection
failures retry once within that budget. Redirects and environment proxies
are disabled.

`recall(status)` includes `embedding_tier.status` (`ready` or `degraded`).
An outage removes the dense read lane while sparse retrieval remains
available. Claim writes refuse `Unavailable`, and dense projection stops at
the affected row; zero-vector outage sentinels are never persisted. Restoring
the same pinned tier recovers without restarting Recall.

## M3 sandboxes and transcripts

See [sandbox image and launch instructions](../deploy/local/sandbox/README.md)
and the [local M3 deployment](../deploy/local/README.md#m3-sandbox-plane).
`launch up` creates separate agent/shipper grants and Docker containers or a
Kubernetes pod with a native shipper sidecar. `launch down --state PATH`
stops the runtime and revokes both grants; failed cleanup remains retryable
in private state. The launcher identity and provider credential stay out of
the Recall plane. Only the selected model harness receives provider auth.

`shim --url URL` forwards bounded JSONL over HTTP using `FLEET_RECALL_TOKEN`,
preserving initialization, IDs and notifications. It mirrors the protocol,
method and encoded name headers and emits diagnostics only on stderr. It
never retries a mutation after an ambiguous transport failure. Use
`--allow-http` explicitly for a private non-loopback development endpoint.

With `FLEET_RECALL_TRANSCRIPT_SPOOL_DIR` set, the remote server accepts
`PUT /v1/transcripts/{sandbox_uuid}/{file}?offset=N` from a matching shipper
grant. `ship transcripts --dir DIR --url URL --instance UUID --format codex`
(or `claude-code`) tails complete records, retries temporary outages, and
flushes on termination. The same token environment variable is used for this
separate shipper process. Uploads bind the sandbox, source path, format and
first-line digest to an immutable manifest. Exact byte replays succeed;
gaps, changed prefixes and cross-sandbox writes are refused. Default limits
are 4 MiB/window, 64 MiB/file and 1 GiB/scope.

The worker automatically adds the current scope's spool groups when the same
spool variable is set; run `--steps ingest,project,embed`. Uploaded transcripts
use `connector.transcript.sandbox`, pass through normal redaction and admission,
and retain source byte spans. The Codex parser consumes native
`$CODEX_HOME/sessions/**/*.jsonl`, with a distinct frozen parser identity;
it does not consume the different `codex exec --json` stdout event stream.
Unknown content formats fail closed and need a parser revision.
