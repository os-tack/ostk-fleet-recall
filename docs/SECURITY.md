# Security and supply-chain policy

## Trust boundaries

Fleet Recall binds tenant, project, and agent identity from deployment
configuration. MCP callers may select a session subdivision, but neither
session nor the currently fixed project privacy tier is an authorization
principal. Privacy refinement is deliberately rejected until owner/tier
visibility is persisted and enforced. Every repository reapplies the trusted
tenant/project coordinates at SQL execution; request bodies, recalled rows,
and canonical artifacts cannot reroute a process.

Corpus chunks, claims, transcripts, tool output, telemetry, conflict text, and
recalled Markdown are untrusted content. They are evidence to quote, cite, and
validate, not instructions or authorization. A consumer must not execute a
command, call a tool, change policy, disclose a secret, or infer an identity
merely because recalled content asks it to. Agent policy and operator approval
remain outside the corpus. Source coordinates, digests, typed conflict state,
and exact re-reads can strengthen evidence; they do not turn text into
authority.

The public HTTP router exposes only `/`, `/healthz`, `/api/status`, and the
non-mutating `POST /api/recall`. It has no MCP, ingest, remember, control
bootstrap, registry activation, or other mutation route. The submitted
CloudFront distribution is therefore a read-only recall surface, even though
recall uses POST. CloudFront-to-ALB transport and viewer-TLS limitations are
documented without stronger claims in the
[AWS runbook](../deploy/aws/README.md).

## Offline authority and append-only control state

The private control plane is deliberately absent from normal serving
configuration. Stage 2 verifies an out-of-band-pinned bootstrap receipt against
the supplied genesis package. Stage 3 additionally verifies the
deployment-pinned conformance result and runner artifact/configuration
digests, then verifies a canonical activation statement and its freshly signed
approval set. CLI arguments provide only
bounded canonical artifact paths. Physical scope, semantic scope,
receipt/result and runner digests, and principal bindings come only from
dedicated environment configuration.

The raw receipt digest is checked before its profile or scope is trusted.
Artifacts must be exact canonical records with no unknown fields and must name
the canonicalization profile and vector suite frozen into the binary. A signed
or pinned artifact cannot select a new parser or profile implementation simply
by naming another digest. Replays re-read and revalidate the persisted
canonical bytes and their database projections; partial, orphaned, or
mismatched state is corruption, never an implicit repair opportunity.

The implemented first-successor process preserves the same offline-authority
shape. Its workstation CLI accepts only eight bounded canonical artifact paths;
the dedicated `FLEET_RECALL_SUCCESSOR_*` environment binds its physical and
semantic scopes, bootstrap/genesis/target/runner/bridge pins, principals, and
strict-TLS database URL. It verifies the artifact graph before connecting, then
the repository reauthenticates the one-time bridge and candidate against the
locked durable genesis root inside the serializable generation-0-to-1
transition. This repository/CLI is source capability, not deployed SQL
authority: no successor writer role or grant bundle exists.

Accepted control and activation events are append-only and source-positioned.
Bootstrap/activation transactions use one database acceptance time, scoped
head locking and compare-and-swap, exact event positions and chain digests, and
complete durable predecessor audits. Compound writes execute in one
serializable transaction; only CockroachDB SQLSTATE `40001` retries the whole
operation. Application claim, support, conflict, event, and receipt mutations
follow the same bounded idempotent/serializable rule.

Current source embeds migrations 1 through 17. Migrations 3 through 9 add and
harden the private control and genesis-activation projections; migrations 10
through 14 add exact genesis-root indexes and three durable successor tables;
and migrations 15 through 17 version conflict uniqueness by detector and add
the exact reconciliation/current-projection indexes. Current release completion
requires exactly the seventeen successful rows 1 through 17. Normal recall,
remember, ingest, MCP, health, and public-demo paths require an uninterrupted
successful prefix of at least 17 and remain compatible with later additive
migrations. The private compatibility gates remain control 3, genesis 9,
successor repository 14, and conflict reconciliation 16. A later successful row
cannot mask a missing or failed prerequisite in any gate.

Versions 1 through 11 are nontransactional schema changes; v10 and v11 recover
an interrupted exact index through `IF NOT EXISTS` plus a fail-closed catalog
shape assertion. Versions 12 through 14 run with SQLx bookkeeping in one
transaction on a dedicated session with `autocommit_before_ddl = false`.
Versions 15 through 17 return to resumable nontransactional online DDL: v15
admits only its exact detector-index transition states and rewrites no conflict
data; v16/v17 commit one covering backfill and assert its exact catalog shape.
The dedicated session is closed rather than returned to the runtime pool.
These mechanics establish durable shape, not an application authorization
boundary.

## Identities, URLs, and secrets

The current AWS Terraform has exactly two database credential paths: a
least-privilege runtime URL and a distinct DDL-capable migrator URL, each from
its own secret input. It has no control-bootstrap, genesis-activation,
successor, or conflict-reconciliation secret, IAM role, task definition, route,
or startup hook. When a private local ceremony is actually run, Stage 2 uses a
third SQL principal and dedicated control URL; genesis Stage 3 uses a fourth
SQL principal and dedicated registry URL. Those one-shot credentials are never
fallbacks for runtime or migration credentials and should be disabled or
removed after the ceremony.

The successor repository and workstation apply/inspect CLI exist, but there is
no successor SQL writer principal/logical role, write-grant RBAC bundle, AWS
task, production-image binary, startup hook, or public/runtime route. The
checked-in
[quarantine policy](../deploy/cockroach/successor-schema-quarantine-grants.sql)
is deny-only: after prefix 1 through 14 it revokes every successor-table
privilege from `public`, runtime, bootstrap, and genesis activation and grants
nothing. Until the SQL authorization and deployment surface is implemented and
reviewed together,
`memory_registry_transitions`,
`memory_registry_genesis_bridge_consumptions`, and
`memory_registry_current_heads_v2` remain migrator/schema-owner only. Neither
the runtime user nor either existing one-shot role may receive access merely
because the migrations and contracts exist.

Conflict reconciliation has a different, explicitly implemented one-shot
boundary. Only a cluster admin may apply the database-local policy; database
ownership alone is insufficient. Apply the
[`fleet_conflict_reconciliation` policy](../deploy/cockroach/conflict-reconciliation-role-grants.sql)
after successful prefix 1 through 16 and the three prior logical roles are
hardened. A separately provisioned login may temporarily receive
membership only in that `NOLOGIN` logical role for the apply-only workstation
CLI. Before every apply and use, an external operator audit must enumerate all
other databases for direct grants/ownership and account separately for
inherited `public` authority under a role/grant/schema-DDL change freeze. The
SQL file cannot perform that cross-database audit. Remove membership or disable
the login afterward. No Terraform, runtime, image, ECS, MCP, or HTTP wiring
exists.

All database URL surfaces require `postgres`/`postgresql`, a hostname, and a
closed parameter set. Serving and Stage-2 control require exactly
`sslmode=verify-full` outside the explicit local escape; that escape requires
`FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1` and a loopback or Compose-only
`cockroach` host. Genesis Stage-3, successor, and reconciliation URLs ignore the
escape and always require exactly `sslmode=verify-full`. Each private process
uses only its dedicated variable and never falls back to a serving, migrator,
or other ceremony URL. The only additional accepted query parameter is one
bounded absolute `sslrootcert` path. Fragments, duplicate parameters, aliases
such as `options`, routing overrides, relative certificate paths, and unknown
parameters fail closed. Do not set the local escape in cloud or shared
environments. Debug output redacts database URLs, authority pins, and bound
reconciliation scope.

Apply the exact current-object/PUBLIC policies and normalized grant proofs in
[MIGRATIONS.md](MIGRATIONS.md) and
[CONTROL_BOOTSTRAP.md](CONTROL_BOOTSTRAP.md). Runtime has no control-table
privilege. The private logical roles are non-login, have no admin or SYSTEM
privileges, and receive only the table operations required by their reviewed
one-shot repositories. Re-audit actual migrator default privileges after every
migration; broad `ALL TABLES` or future-object grants would defeat this
boundary.

## Conflict-detector lineage

`same_key_functional_value_v2` is an immutable, proposition-aware contract for
one functional `subject::predicate` key over overlapping half-open intervals.
Different affirmative values conflict; affirmation and negation conflict only
when they name the same exact JSONB value; two negations are compatible. This
is typed proposition comparison, not natural-language inference or a general
set-valued predicate rule.

Rows written by the original `same_key_typed_value` detector keep their
original meaning. Normal v2 writes fail closed on an unreconciled legacy
lineage rather than append to it or relabel it. The reconciliation repository
locks one exact legacy conflict revision, preserves the legacy row and
memberships byte-for-byte, derives a complete bounded v2 pair graph, and
appends a distinct v2 lineage, idempotency receipt, audit event, and any
claim-state transitions atomically. A compatible graph produces a durable
dismissed v2 lineage; it never deletes the legacy evidence.

## Residual SQL authority and recovery

CockroachDB grants table operations, not prepared-statement identities. A
holder of a private writer URL can issue SQL outside the reviewed binary. The
bootstrap role's required raw inserts can occupy an immutable singleton or
plant a detached future offset. The activation role can occupy immutable
activation/head rows or misuse its table-level shard-head update. The unique
predecessor index prevents one class of fork but cannot prove a new event is
the head-authorized append. These credentials are therefore exclusive
ceremony capabilities, not operator shells or general service accounts.

The existing genesis-activation credential is genesis-only. It has no authority
over the successor tables. Although the successor repository and workstation
CLI are implemented, the absence of a dedicated SQL writer role/grant policy
means they are not an enabled production successor runtime. The migrator/schema
owner retains technical authority and must not be repurposed as that missing
application credential.

The reconciliation role necessarily has a bounded mix of
`SELECT`/`INSERT`/`UPDATE` on its exact legacy-ledger table set and `USAGE` on
the conflict-ID sequence; CockroachDB also requires table-level `UPDATE` for
its `FOR UPDATE` locks. RBAC cannot restrict a credential holder to the
repository's prepared statements. Keep its login quiesced except for one
reviewed apply, preserve the external cross-database audit/change freeze, and
treat direct-SQL misuse or a partial projection as corruption requiring an
audited forward repair.

The one-shot roles intentionally lack delete and broad repair authority, so an
invalid direct write can wedge a scope. Stop the writer, preserve rows and
logs, inspect canonical bytes, constraints, positions, migration history, and
schema-change jobs, then design a separately reviewed forward repair for the
exact observed state and prove it on a copy. Never silently delete evidence,
rewrite migration history, or teach replay to accept a partial shape.

## Dependency and artifact integrity

The embedding bundle is local, content-addressed, and restricted to three
regular non-symlink files. The runtime verifies the same domain-separated
digest before use and does not resolve a model remotely. Release container
images and release source-linked corpus records use immutable revisions;
Secrets Manager values, database URLs, raw cloud logs, and Terraform state are
not publication-safe artifacts.

## Dependency audit exception

`RUSTSEC-2023-0071` affects `rsa 0.9`, which appears in Cargo's lockfile through
SQLx's optional MySQL driver. This application enables only SQLx PostgreSQL;
`cargo tree --target <deployment-target> -i rsa` and `-i sqlx-mysql` must both
remain empty in CI. There is no fixed `rsa` release listed by the advisory.
The exception is therefore confined to an inactive optional package, not a
linked runtime dependency, and should be removed as soon as SQLx's graph no
longer records it.

Warnings for unmaintained `number_prefix` and `paste` currently arrive through
the disclosed upstream model2vec embedding stack. They contain no published
vulnerability; upgrades remain tracked upstream.
