# Configuration reference

[Documentation index](../README.md) · [Deployment profiles](DEPLOYMENT_PROFILES.md)
· [Operating guide](../guides/OPERATING.md)

Use this page to identify **which process owns a setting**, its default, and
where to find the procedure that establishes it. It covers normal serving,
workers and clients. Private activation ceremonies have their own inputs in
[control bootstrap](../CONTROL_BOOTSTRAP.md) and [CLI reference](CLI.md).

The binary reads its process environment; it does not automatically load a
repository `.env`. Some deployment helpers read specific files themselves
(for example, the local bootstrap reads a LocalStack token from `.env`).
Shell variables in the tutorials must be exported when a child process needs
them. Flags with an environment fallback, such as `--url`, take precedence
over that fallback; `--help` shows the supported flags for each command.

## Choose the configuration owner

| Process or task | Configuration belongs here | Credentials it needs |
| --- | --- | --- |
| Existing local HTTPS service | Installed Kubernetes configuration and mounted Secrets; change through the HTTPS deployment/maintenance procedures | Writer SQL login, server identity/grant settings, embedding access; preserve installed keys |
| Local worker | Worker CronJob, sources ConfigMap and its mounted Secrets | Writer SQL login, authority pins, content key and only the configured collectors' credentials |
| Standalone developer `serve`, `health`, `ingest` | The process environment created by the developer tutorial | Writer SQL login and pinned scope/model; feature-specific settings below |
| Schema migration or authority installation | A separate maintenance environment | Migrator login while explicitly enabled; never the normal serving environment |
| Human enrollment | A separate enrollment workstation/process | Enrollment SQL login; no writer URL or content key |
| Native Codex or Claude client | That client's MCP configuration, OAuth store and public CA trust | The user's OAuth login; no SQL password or server signing key |
| Sandbox launcher | The launcher process and its private launch-state directory | Enrolled local-key seed or projected Kubernetes identity; explicit provider login/key only when selected |
| Shim and transcript shipper | Environment generated for each launch | Separate scoped agent/shipper grants and public CA certificates |
| Public demo | Publication process/task configuration | Publication-reader SQL login; private database credentials are rejected |

Exporting variables in a Mac terminal does not change a running Kubernetes pod,
another shell, or an already running GUI client. The checked-in
[HTTPS profiles](../../deploy/remote/profiles/README.md) are nonsecret examples,
not complete configurations or installers. Do not source all server and client
settings into every process.

## Database, scope and model

These are read by the ordinary writer configuration in
[`src/config.rs`](../../src/config.rs). Specialized commands use the credential
boundaries in the first table.

| Variable | Required/default | Meaning |
| --- | --- | --- |
| `FLEET_RECALL_DATABASE_URL` | Required for writer/migrator commands; **secret** | `fleet_writer` for serving/worker/ingestion; `fleet_migrator` for `migrate` and authority installation. These are different process identities despite using the same variable name. |
| `FLEET_RECALL_PUBLICATION_DATABASE_URL` | Required by `demo`; **secret** | Fixed publication login; never substitute the writer URL. |
| `FLEET_RECALL_ENROLLMENT_DATABASE_URL` | Required by `enroll`; **secret** | Fixed enrollment login; enrollment rejects other database URLs and the content key. |
| `FLEET_RECALL_INGRESS_DATABASE_URL` | Required by `ingress`; **secret** | Private webhook-hint login; separate from writer/publication/enrollment. |
| `FLEET_RECALL_TENANT_ID` | Required | Non-nil UUID identifying physical scope. |
| `FLEET_RECALL_PROJECT` | Required | Project in that tenant; must match the established scope. |
| `FLEET_RECALL_AGENT` | Required by writer configuration | Trusted stdio/worker identity and HTTP default configuration. Authenticated HTTP requests receive their effective binding from enrollment/grants. |
| `FLEET_RECALL_MAX_CONNECTIONS` | `16` for writer configuration; positive integer | Per-process database pool limit. Multiple processes create separate pools. |
| `FLEET_RECALL_EMBEDDING_MODEL` | `minishlab/potion-retrieval-32M` | Logical model name; not the filesystem path. |
| `FLEET_RECALL_EMBEDDING_MODEL_SHA256` | Required | 64-character digest from `model-digest`; the database's active model must agree. |
| `FLEET_RECALL_EMBEDDING_MODEL_PATH` | Required for local embedding | Directory containing the pinned, regular model files. A remote embedding client can omit the path, but still needs model identity/digest. |
| `FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE` | Unset; only `1` opts in | Disposable local-development escape for permitted local hosts. It does not permit insecure cloud SQL or relax activation ceremony TLS requirements. |

Database-using commands reject ambient `PG*` overrides. Use the exact role,
database, TLS and application-name configuration from the selected deployment
guide; an arbitrary working PostgreSQL URL is not sufficient. Role setup and
migrations are covered by [migration operations](../MIGRATIONS.md).

The HTTPS reference deployment uses SQL `sslmode=verify-full`. Model replacement
requires a new empty or fully re-embedded corpus generation; changing the path
or digest alone does not upgrade stored vectors.

## Writer authority and content

| Variable | Required/default | Meaning |
| --- | --- | --- |
| `FLEET_RECALL_CONTRACT_TENANT_NAMESPACE` | Part of the complete pin set | Semantic tenant namespace returned by authority installation. |
| `FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE` | Part of the complete pin set | Semantic project namespace for that same installed authority. |
| `FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST` | Part of the complete pin set | Installed receipt digest; obtain it from the authenticated installer result. |
| `FLEET_RECALL_EXPECTED_ACTIVATION_ID` | Optional, only with the complete pin set | Additional exact activation pin; not a mechanism for changing the registry head. |
| `FLEET_RECALL_CONTENT_KEK_HEX` | Feature dependent; **secret**, 32 bytes encoded as hex | Required by content-admitting/decrypting worker and ceremony paths. Keep it stable and recoverable; generating a replacement does not decrypt existing content. |
| `FLEET_RECALL_REMEMBER_LIFECYCLE` | `enabled` | `enabled` or `disabled`; runtime schema/grants still decide which lifecycle actions can be served. |
| `FLEET_RECALL_CONFLICT_ADJUDICATION` | `disabled` | `enabled` permits eligible non-author adjudicators to dismiss/waive; it does not bypass lifecycle/authority checks. |
| `FLEET_RECALL_COLLECTED_CAPTURE` | `disabled` | `stage_only` queues capture for the worker; `enabled` admits/projects in the call and needs the content key in the serving process. |
| `FLEET_RECALL_COLLECTED_CAPTURE_SCOPES` | `[]` when capture is enabled | JSON provider/scope/container allowlist; see [capture reference](COLLECTION.md#capturing-items-an-agent-read). |

The first three authority settings must be present together or all absent.
Partial pins are a configuration error. Event-first append processes such as
the worker, `ostk-spec`, and `ostk-observer-run` fail startup; `serve` logs the
error and stays available with `remember(assert)` disabled. Process readiness
alone therefore does not prove authority is configured. Absent pins do not
grant event-first authority.
Keep semantic namespaces distinct from the physical tenant UUID/project.
The [event-first operating procedure](../guides/EVENT_FIRST_OPERATIONS.md)
explains installation, verification, worker scheduling and feature order.
Content-key protection is not encryption of every projection; see the
[security boundary](../SECURITY.md#event-first-writers-and-the-content-key).

## HTTP server identity and limits

[`src/remote.rs`](../../src/remote.rs) loads these for `serve --http`.
The [remote plane reference](../REMOTE_PLANE.md) defines the enrollment and
audience rules; the [local HTTPS runbook](../../deploy/local/https/README.md)
establishes actual canonical names, certificates and routing.

| Variable | Required/default | Meaning |
| --- | --- | --- |
| `FLEET_RECALL_RESOURCE_URL` | Required for HTTP | Canonical external MCP URL, including `/mcp`; used as the resource audience. |
| `FLEET_RECALL_OIDC_ISSUERS` | Empty by default | Comma-separated `anchor=https://issuer/` mappings. HTTP needs at least one OIDC, local-key or AWS anchor. |
| `FLEET_RECALL_OAUTH_ADVERTISED_ANCHORS` | Explicit with multiple OIDC anchors | Human-login anchors to advertise; an empty value advertises none. Machine anchors can still verify without appearing in human discovery. |
| `FLEET_RECALL_OAUTH_SCOPES` | `fleet-recall` | Advertised OAuth scopes. The Hydra/Codex profile uses `openid,offline_access,fleet-recall`; scopes do not enroll a principal. |
| `FLEET_RECALL_OIDC_SCOPE_SUBSTITUTES` | Empty | Explicit `anchor=scope` exception only for an empty token audience; a nonempty wrong audience remains denied. |
| `FLEET_RECALL_OIDC_CA_PATH` | Optional | Public certificate bundle for the server's issuer/JWKS connections; local HTTPS includes Fleet and Kubernetes issuer trust. |
| `FLEET_RECALL_OIDC_DISCOVERY_TOKEN_PATHS` | Empty | `anchor=/absolute/token/file` for authenticated issuer metadata. Not an operator token or Recall grant. |
| `FLEET_RECALL_OIDC_LOCAL_TRANSPORTS` | Empty | Development-only route mapping for loopback issuers. Do not carry the old HTTP mapping into canonical HTTPS. |
| `FLEET_RECALL_LOCAL_KEY_ANCHOR_PATH` | Optional | JSON map of enrolled key IDs to public Ed25519 keys; this is not the launcher's private seed. |
| `FLEET_RECALL_GRANT_SIGNING_KEY_HEX` | Required for HTTP; **secret** | Server grant-signing key; preserve across restarts and recoveries. |
| `FLEET_RECALL_GRANT_TTL_SECONDS` | `3600`; range `1..86400` | Server grant lifetime bound. Launcher deadlines must fit the effective issued grants. |
| `FLEET_RECALL_GRANT_CHECK_CACHE_SECONDS` | `5`; range `0..5` | Maximum configured grant-check cache interval; revocation is not necessarily visible instantly. |
| `FLEET_RECALL_SCOPE_CACHE_MAX` | `64`; range `1..4096` | Maximum cached tenant/project services. |
| `FLEET_RECALL_AGENT_CACHE_MAX` | `256`; range `1..16384` | Maximum agent services per scope. |
| `FLEET_RECALL_HTTP_MAX_INFLIGHT` | `64`; range `1..1024` | Request admission cap; health/readiness bypass it. |
| `FLEET_RECALL_HTTP_ALLOWED_ORIGINS` | Empty | Additional comma-separated browser origins; the resource's origin is allowed, as are requests without an Origin header. |
| `FLEET_RECALL_TRANSCRIPT_SPOOL_DIR` | Unset | Enables the receiver on a durable local POSIX spool directory. Receiver and worker need the same retained data, with one receiver writer. |

The HTTP deadline is fixed at 30 seconds. Core readiness checks run every five
seconds with a three-second deadline and expire after ten seconds; these are
code constants, not environment knobs. A private `/readyz` success does not
prove issuer or embedding availability. See [health checks](../guides/OPERATING.md).

AWS identity requires all three of `FLEET_RECALL_AWS_STS_ENDPOINT`,
`FLEET_RECALL_AWS_IAM_SERVER_ID` and comma-separated
`FLEET_RECALL_AWS_ALLOWED_ACCOUNTS` together. Leave them unset for an OIDC/local-key
deployment that does not use AWS identities; LocalStack is not required for it.

## Embedding, clients and telemetry

| Variable | Owner / default | Meaning |
| --- | --- | --- |
| `FLEET_RECALL_EMBEDDING_TIER_URL` | Writer/worker; unset selects local embedding | Remote embedding endpoint; it is private in the reference deployment. |
| `FLEET_RECALL_EMBEDDING_TIER_TOKEN` | Embedding server and its clients; **secret** | Shared service credential; no database credential belongs in the embedding process. |
| `FLEET_RECALL_EMBEDDING_TIER_TIMEOUT_MS` | Embedding client; `2000`, range `1..30000` | Bounded remote request timeout. |
| `FLEET_RECALL_URL` | Launcher, shim, shipper | Reachable MCP URL; distinct from the server's `RESOURCE_URL` setting. |
| `FLEET_RECALL_CA_PATH` | Fleet launcher, shim, shipper | Additional public PEM CA bundle, at most 256 KiB/256 certificates; copied into launch state for runtime and teardown trust. |
| `FLEET_RECALL_ALLOW_HTTP` | Fleet clients; false/unset | Explicit development transport opt-in, equivalent to `--allow-http`; keep off for HTTPS. |
| `FLEET_RECALL_TOKEN` | Shim or shipper; **secret** | Its own scoped grant. Do not interchange the agent and shipper tokens. |
| `FLEET_RECALL_LAUNCHER_KEY_HEX` | Local-key launcher; **secret** | Enrolled Ed25519 seed used to obtain grants; not passed to sandbox processes. |
| `CODEX_CA_CERTIFICATE` | Native Codex process | Public CA path for native client trust; separate from Fleet client trust and from provider authentication inside a sandbox. |
| `FLEET_RECALL_METRICS_LISTEN` | Serving process; unset disables listener | Separate private IP:port; opening MCP does not expose metrics. |
| `FLEET_RECALL_METRICS_ALLOW_NON_LOOPBACK` | `false` | Requires explicit `true` for a private non-loopback scrape listener. |
| `FLEET_RECALL_METRICS_TEXTFILE` | Worker; unset | Atomic `.prom` snapshot destination for short-lived ticks. |
| `FLEET_RECALL_LOG_FORMAT` | `json` | `json` or `text`, written to stderr. |
| `RUST_LOG` | `ostk_fleet_recall=info` fallback | Tracing filter; follow the [telemetry guide](../TELEMETRY.md) when diagnosing a process. |

Collector token/signing-secret names are selected by each worker sources file,
not a universal set of `FLEET_RECALL_*` variables. See the
[worker sources reference](WORKER.md) and [collection reference](COLLECTION.md).
Provider keys or a copied Codex login are explicit launcher inputs, isolated to
the agent container; see [sandbox operations](../../deploy/local/sandbox/README.md).

## Local helper inputs and retained state

`FLEET_LOCAL_STATE` selects the original installation's private state for the
helpers that support it; Python maintenance commands take `--state` explicitly.
`KUBECONFIG` must point to that same installation. Set both using the
[operator session setup](../guides/OPERATING.md), especially from another
worktree. A new checkout's empty `.state` is not a copy of the running system.

`FLEET_LOCAL_SKIP_LOCALSTACK=1` skips optional bootstrap/verification AWS checks.
`FLEET_OBSERVABILITY_REMOTE=true` selects the HTTPS monitoring additions.
These are helper switches, not Rust runtime variables. Do not rerun the legacy
bootstrap to change a live HTTPS deployment.

Retain authority reports/pins, content and grant keys, SQL/Ory credentials,
public/private PKI material, launch-state directories and encrypted recovery
inputs with their intended permissions. Public CA certificates may be shared
with clients; private CA keys, database URLs, OAuth tokens and recovery keys
must not be put in checked-in profiles, troubleshooting output or tickets.
The [recovery runbook](../../deploy/local/https/RECOVERY.md) defines what a
checkpoint restores and what must be reconciled before public promotion.
