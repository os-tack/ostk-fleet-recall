# ADR 0009: The remote plane

- Status: accepted; M1, M2, and M3 are implemented. M3 is verified with Docker,
  Kubernetes service-account launches, and real Codex transcript recall. See
  `deploy/local/README.md` for checkpoint evidence and the Claude usage-limit
  qualification. Nothing here changes a frozen registry generation.
- Follow-on: [M4 implementation plan](../M4_REMOTE_ACCESS_PLAN.md) proposes
  dependable HTTPS access in local and cloud deployments. M4.1 client and
  discovery changes are implemented; deployment qualification remains pending.
- Date: 2026-09-27
- Scope: where the recall process, the embedding model, the writer credential,
  and the scope binding run relative to the agent; how an agent in an
  ephemeral container or microVM authenticates against the correct tenant and
  scope; how an operator authenticates from a laptop; how transcripts of
  ephemeral agents reach the ledger; and which of these are configuration
  rather than code. It builds on ADR 0005 (writer authority and the
  installer), ADR 0006 (the worker and evidence recall), and ADR 0008
  (collected items and the private ingress). A visual sketch of the design
  discussed while writing this ADR is at
  https://claude.ai/artifact/N7PYioaxr5qR36yFXLDyrK.

## Context

Today the Recall MCP server is a stdio process launched by the agent's
harness. That process carries the 125 MB potion model bundle and verifies its
digest at startup, holds the `fleet_writer` database URL, and takes its
tenant, project, and agent from its own environment (`FleetConfig.default_scope`,
`src/config.rs`). Every SQL statement leads with tenant and project, and the
service, the ledger, and the store each re-check the scope by equality
(`docs/ARCHITECTURE.md`, invariants 1 and 2).

The static embedder was chosen for portability: an agent in an ephemeral
container has no inference capability. But stored content is already embedded
by the worker's project and embed steps, not by the agent-side process; the
only embedding that happens next to the agent is the query vector at recall
time. The agent-side process is therefore a fat client that ships a model, a
writer credential, and a scope binding in order to turn one query string into
512 floats, and every one of those three things is a liability in a container
on infrastructure the operator does not control.

Fleet Recall's future is agents as thin clients: a harness in a container or
microVM (Docker, Fargate, Firecracker, whatever the deployment chooses) that
holds a URL and a token, speaks the stock MCP protocol, and either ships its
logs or uses the recall tools to operate the memory plane. Everything else
runs where it can be hosted, scaled, and changed independently.

The MCP specification revision 2026-07-28 is current: a stateless core with no
`initialize` handshake and no session, one HTTP POST per JSON-RPC message with
`MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` headers mirroring the
body, RFC 9728 protected resource metadata for authorization-server discovery,
RFC 8707 resource indicators on every token request, and client registration
by pre-registration, Client ID Metadata Documents, or the deprecated dynamic
client registration.

## D1 — Agents are thin clients; the recall service is an HTTP MCP resource server

**Decision.** The recall service is served over Streamable HTTP (revision
2026-07-28, legacy `initialize` still answered for older clients) from a
process on the private plane. An agent's container holds `FLEET_RECALL_URL`
and `FLEET_RECALL_TOKEN` and nothing else: no model bundle, no database
credential, no scope in its environment. Stock harnesses (Claude Code, Codex,
OpenCode) keep speaking stdio through a shim subcommand
(`ostk-fleet-recall shim --url …`) that adds the bearer and the 2026-07-28
headers; harnesses that speak HTTP natively connect directly. The shim is where
proof of possession and token refresh land later without touching any harness.

**Why.** The stdio protocol loop is hand-written and transport-agnostic at
`McpServer::handle_value` (`src/mcp/server.rs`), so an HTTP binding is a
router around one seam. TLS terminates in front of the process, as it does
for the demo today.

**Consequence.** One process serves many scopes. Scope stays fixed per
request, never per process: the HTTP layer resolves a verified principal to a
`FleetScope`, and a per-scope service cache runs exactly the startup probes
`build_memory_service` runs today. Every existing equality check stays.
Writer-authority pins remain one environment group per process, so
`remember(assert)` and `remember(capture)` are served only for the pinned
scope in the first slice and reported off elsewhere.

## D2 — Identity is configuration; authorization never leaves the recall plane

**Decision.** The identity provider is deployment configuration, not code:
Ory Hydra locally, AWS IAM or Cognito, Keycloak, Authentik, or a Kubernetes
cluster issuer in production. The recall plane holds a small set of *identity
anchors* that only prove who is asking, each yielding `(anchor_id, subject)`:

| Anchor | Proves | Covers |
|---|---|---|
| OIDC issuer | a JWT's issuer, audience, expiry, signature via discovery and JWKS | Hydra, Cognito, Keycloak, Authentik, Kubernetes service-account tokens |
| AWS IAM | a presigned `sts:GetCallerIdentity` forwarded to STS (LocalStack locally) | hosts with an instance role, no key to enrol |
| Local key | an assertion signed by an enrolled Ed25519 key | laptops, the quickstart, break-glass |

What an identity may do lives in a **principal registry** inside the plane:
`(anchor, subject pattern) → role {operator, launcher, shipper}, tenant,
project, visibility ceiling, allowed agent-name pattern`. Only the enrolment
ceremony writes it, as a subcommand over a declarative file
(`ostk-fleet-recall enroll apply --file …`) so Pulumi, Terraform, or CI can own
it; threshold approvals reuse the activation-policy types, and in
infrastructure-as-code the review is the second approver. No token claim is
ever the source of authorization.

**Why.** Every provider expresses custom claims differently and some cannot
express them at all. Keeping scope in a token means either trusting each
provider's mapper or owning the issuer, and the owner decided the issuer is
configuration. The registry is the same posture the worker's sources file
already takes: nothing outside the plane is authority, it can only offer
material for the plane to judge.

**Cadence.** Enrolment happens once per launcher identity or when its allowed
scopes change (an IAM row is a role pattern, an OIDC row is one orchestrator,
a local key is one laptop; a row may allow several write scopes). A grant is
issued once per sandbox launch, by the launcher, automatically. Verification
runs on every tool call against cached keys, the registry, and revocations.
Only the first is a ceremony.

## D3 — Sandboxes hold a session grant the recall plane signs itself

**Decision.** A launcher proves its identity through an anchor and exchanges
it at the plane's grant endpoint for a short session grant for one sandbox:
a JWT signed with the plane's own Ed25519 key carrying issuer = the resource
URL, audience = the resource URL, the launcher's `(anchor, subject)`, exactly
one write scope copied from the registry row (never requested), the agent
name, a ceiling at most the row's, an expiry equal to the sandbox's lifetime
budget (stock harnesses do not refresh static bearers), and a `jti`. Grants are
logged; the launcher revokes them at teardown; revocation is checked on every
request behind a bounded cache. A second grant of kind `shipper` is issued for
the transcript shipper. The recall service accepts either an IdP token
(humans, the way every stock harness expects) or a session grant (sandboxes)
and dispatches on the issuer claim.

**Why.** This is the Vault and Teleport pattern: the auth method is
configuration, the system still issues its own short-lived credentials. A
sandbox never holds an IdP credential, per-sandbox lifetime and revocation
never depend on the provider, and the request path verifies one of two key
sets.

## D4 — Writes are single-scope; cross-scope reads are a service concern

**Decision.** A grant carries exactly one write scope. Cross-scope reads need
two-sided consent: the grant (or the operator's registry row) lists a readable
scope, and the source scope's operator has recorded a publication making it
readable by that reader. The service issues one tenant-prefixed query per
scope, fuses the ranked lists in process with reciprocal-rank fusion, and every
hit keeps its scope coordinate. No SQL statement ever crosses a tenant.

**Why.** The physical scope invariant on the ledger stays untouched, and the
publication record stays in the data plane, so an identity provider can say
what a token may ask for but never what a corpus allows.

## D5 — Embedding is its own tier; one model per scope stays for now

**Decision.** Embedding moves to a stateless tier (`ostk-fleet-recall embed
serve`) that the service calls for query vectors and the worker calls for
content vectors, batched. Every reply carries the model descriptor (digest,
dimensions, metric, versions); a process configured with the tier verifies at
startup that the tier's digest equals its pinned
`FLEET_RECALL_EMBEDDING_MODEL_SHA256` and fails closed otherwise, and
`admit_embedding` still refuses a vector whose descriptor does not match. The
tier keeps nothing and logs no input; it sits on the private plane because a
query arrives unredacted.

The corpus keeps exactly one model identity of dimension 512 per scope.
Models-as-lanes (one dense lane per model digest, a corpus identity row per
lane, shadow lanes filled but not served, per-kind policy choosing lanes and a
reranker) is recorded as the schema-evolution requirement for future model
introductions, not built now: the immediate use is development and there is
no corpus to protect from a rebuild.

Synchronous embedding on `remember` is taken now behind a latency budget: if
the tier does not answer within it, the write takes the tick path and the
receipt says so.

**Consequence.** The verdict thresholds in `src/evidence_recall/verdict.rs`
were calibrated against potion and become per-lane configuration when lanes
arrive. Until the sync `ChunkEmbedder` call sites are made async, the remote
embedder bridges with `block_in_place`; a tier failure yields an all-zero
vector, which reads already treat as "no dense lane", surfaces as `degraded` in
`recall(status)`, and is refused on the claim write path so zeros are never
persisted.

## D6 — Transcripts are shipped from outside the agent process, into a spool

**Decision.** A transcript is a source observed by a connector principal,
never something an agent asserts about itself. A shipper that runs beside the
harness (a sidecar container, or a host-side tailer where the host can see the
sandbox's disk) tails each harness JSONL file by byte offset, cuts at line
boundaries, debounces, and flushes at teardown, authenticating with the
launcher-issued shipper grant. It pushes windows to a **transcript receiver**
on the recall service: `PUT /v1/transcripts/{instance}/{file}?offset=N`
appends only when `N` equals the file's current length, answers an identical
re-send as an idempotent replay, and refuses a gap or regression. The receiver
reconstructs the session file on a spool volume, and the worker's transcript
group simply lists the spool directory.

**Why.** The transcript connector reads a file from byte zero to the window
end, keys its cursor on the file name, and treats a re-staged fact under a new
source id as a `PreimageDisagreement` that fails the source
(`src/connectors/transcript/`). Reconstructing the file leaves the parser, the
cursor, redaction (profile 3, still applied in the worker before anything
durable), and replay classification untouched, and the instance id stays
stable. ADR 0008 D12 rejected content-bearing webhooks under the ingress role;
the receiver is not the ingress role, holds no ledger privilege, and writes
bytes to a volume, so that decision stands. Sidecar-shipped transcripts use a
distinct connector principal (`connector.transcript.sandbox`) so provenance is
distinguishable from host-side shipping; a separate "reported transcript"
trust channel would need a generation-4 registry (ADR 0008) and is not
attempted.

**Follow-ups.** A generic JSONL adapter beside the Claude Code parser in a
closed registry (each adapter with its own frozen parser key and a `format`
field on the transcript group); retiring a closed session explicitly so a
finished sandbox stops holding absence verdicts at `unknown`; an object-store
spool for deployments where the receiver and the worker share no volume.

## D7 — Sandbox runtime is a backend chosen by configuration

**Decision.** The launcher (`ostk-fleet-recall launch`) creates a sandbox
through a backend trait. The first two backends are `docker` and
`kubernetes` (a pod with two containers sharing the transcript volume,
optionally with a VM-isolating runtime class). `firecracker` and `fargate` are
later implementations of the same trait. The launcher mints the two grants,
injects `FLEET_RECALL_URL` and `FLEET_RECALL_TOKEN`, and revokes the grants on
teardown. A demo sandbox runs real Claude Code headless on the cheapest model
with capped turns; automated checks use a synthetic MCP client through the
shim so no model credential is needed. A model credential enters only the
sandbox's environment from the operator's shell, never the recall plane.

**Local note.** Kata's Firecracker handler ships for amd64 only, so on an
Apple Silicon host Firecracker runs directly on the Lima host outside
Kubernetes, and Kubernetes VM isolation uses Kata with QEMU.

## D8 — Issuer-specific audience substitute for Hydra

**Decision.** The MCP specification requires the resource server to validate
that a token was issued for it. Hydra does not implement RFC 8707, so a token
obtained by a stock harness arrives with an empty audience. The OIDC anchor
carries a per-issuer audience policy: `aud_required` (default) or
`scope_substitute: <scope>`, which accepts an empty audience only when the
token's granted scopes include a scope that names this resource. Locally,
Hydra's dynamic-registration default scope and the protected resource
metadata's `scopes_supported` both carry `fleet-recall`, so every client
requests it. This is recorded as issuer-specific and is removed for an issuer
once it supports resource indicators.

## D9 — Maintenance ceremonies stay off the MCP surface

**Decision.** Supersession, reconciliation, registry activation, and model
rotation remain private binaries run against the database with their own role
credential and, where the policy requires it, a second approver. An
authenticated operator gets recall and ordinary remember across the scopes
they administer, plus status, and nothing destructive over the wire. An
observation is a governed write, and so is a rotation.

## Consequences

- New subcommands: `serve --http`, `embed serve`, `shim`, `launch`, `enroll`,
  `ship transcripts`. New migrations for the principal registry and the grant
  log; the runtime role policy and a new enrolment role policy carry the
  grants. No new registry generation.
- The container image no longer needs the model bundle except for the
  embedding tier.
- The local environment under `deploy/local/` (Lima → k0s → CockroachDB, Ory
  Hydra and Kratos, LocalStack) is the reference deployment the production
  Pulumi or Terraform program is derived from.
- Recorded follow-ups: generic JSONL transcript adapter; Firecracker and
  Fargate backends; the Pulumi program; object-store spool; closed-session
  retirement; models-as-lanes; proof of possession in the shim; Client ID
  Metadata Documents once Hydra ships them; async `ChunkEmbedder` call sites;
  TLS on the local plane; assert and capture for non-pinned scopes through a
  per-project pin directory (`AuthenticatedProjectScopeV1::from_trusted_context`).
