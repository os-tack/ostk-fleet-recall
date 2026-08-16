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
recall uses POST. That historical live observation does not attest its database
principal or grant matrix. In the current checked-in source, the public process
instead authenticates as exactly the fixed external `fleet_publication` login,
whose only membership is the logical `fleet_publication_reader` role; router
shape is not treated as the database authorization boundary. That current
boundary is locally proved but unapplied to the historical AWS stack.
CloudFront-to-ALB transport and viewer-TLS limitations are documented without
stronger claims in the
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
authority. Its checked-in `fleet_registry_successor_activation` policy creates
only a hardened, database-local `NOLOGIN` logical role; an exclusive login,
temporary membership, and the complete operator audit/enable/use/disable
ceremony remain external and have no AWS or serving path.

Accepted control and activation events are append-only and source-positioned.
Bootstrap/activation transactions use one database acceptance time, scoped
head locking and compare-and-swap, exact event positions and chain digests, and
complete durable predecessor audits. Compound writes execute in one
serializable transaction; only CockroachDB SQLSTATE `40001` retries the whole
operation. Application claim, support, conflict, event, and receipt mutations
follow the same bounded idempotent/serializable rule.

Current source embeds migrations 1 through 18. Migrations 3 through 9 add and
harden the private control and genesis-activation projections; migrations 10
through 14 add exact genesis-root indexes and three durable successor tables;
migrations 15 through 17 version conflict uniqueness by detector and add
the exact reconciliation/current-projection indexes; and migration 18 adds the
Stage-4 evidence plane, governed content store, relation projection, and the
migrator-owned writer-authority view (ADR 0002). Current release completion
requires exactly the eighteen successful rows 1 through 18. Normal recall,
remember, ingest, MCP, health, and public-demo paths require an uninterrupted
successful prefix of at least 18 and remain compatible with later additive
migrations. The private compatibility gates remain control 3, genesis 9,
successor repository 14, and conflict reconciliation 16. A later successful row
cannot mask a missing or failed prerequisite in any gate.

Versions 1 through 11 are nontransactional schema changes; v10 and v11 recover
an interrupted exact index through `IF NOT EXISTS` plus a fail-closed catalog
shape assertion. Versions 12 through 14 run with SQLx bookkeeping in one
transaction on a dedicated session with `autocommit_before_ddl = false`.
Versions 15 through 18 return to resumable nontransactional online DDL: v15
admits only its exact detector-index transition states and rewrites no conflict
data; v16/v17 commit one covering backfill and assert its exact catalog shape;
v18 creates every new relation with `IF NOT EXISTS`, commits, and then fails
closed with SQLSTATE `55000` unless each one -- including the authority view's
owner and exact definition, and the complete committed constraint set of every
table it creates, so the D1 governance-exclusion CHECK and the event-id UNIQUE
cannot be dropped by an adopted same-name table -- has the shape this migration
defines, so a same-name object is never silently adopted as a successful
version 18.
The dedicated session is closed rather than returned to the runtime pool.
These mechanics establish durable shape, not an application authorization
boundary.

## Identities, URLs, and secrets

The current AWS Terraform defines exactly three planned database credential
paths: a publication-reader URL for the public application task, a private
writer URL for seed/reference/MCP DML, and a distinct DDL-capable migrator URL.
Their three concrete secret ARNs must be pairwise distinct. The public task has
distinct publication execution and task roles and receives only the
publication secret. Its execution policy permits exactly
`secretsmanager:GetSecretValue` on that ARN. When customer-managed encryption
is configured, `kms:Decrypt` is limited to concrete publication-specific CMK
ARNs, `kms:ViaService` is bound to Secrets Manager in the deployment region,
and `kms:EncryptionContext:SecretARN` is bound to the exact publication secret;
those CMKs must be disjoint from the writer/migrator CMK list. The publication
task role can read only the three exact model object ARNs, with no bucket list,
write, or wildcard access.

Terraform does not create CockroachDB identities, memberships, grants, or
authentication material. The externally provisioned `fleet_publication` login
is a member only of the logical `fleet_publication_reader` role, which is
forced to `NOLOGIN`. Its complete positive SQL grant surface is `CONNECT` on
`fleet_recall`, `USAGE` on schema `public`, and `SELECT` on exactly these eight
objects: `_sqlx_migrations`, `memory_corpus_models`, `memory_chunks`,
`memory_claim_embeddings`, `memory_claim_support`, `memory_claims`,
`memory_conflict_members`, and `memory_conflicts`. It has no DML, DDL,
sequence, SYSTEM, private-table, ownership, grant-option, or future-default
authority.

Before every publication-policy apply or reapply, drain the external login and
set it to exact `NOLOGIN`. A cluster admin must audit both publication
principals and inherited PUBLIC authority across every database, freeze role,
grant, default, ownership, and schema-DDL changes, apply
[`publication-reader-role-grants.sql`](../deploy/cockroach/publication-reader-role-grants.sql),
repeat the external audit if the freeze was not continuous, and reapply the
policy immediately before the separate exact authentication-enable operation.
Quiesce and repeat that sequence after every migration or grant change.

The Terraform module has no control-bootstrap, genesis-activation, successor,
or conflict-reconciliation secret, IAM role, task definition, route, or startup
hook. When a private local ceremony runs, each uses a separate SQL login and
dedicated URL; those one-shot credentials are never fallbacks for any deployed
credential and should be disabled or removed afterward.

The successor repository and workstation apply/inspect CLI have a separately
checked-in one-shot
[`fleet_registry_successor_activation` policy](../deploy/cockroach/successor-activation-role-grants.sql).
Only a cluster admin may apply it in the exact `fleet_recall` database after
successful prefix 1 through 14 and after the runtime, control-bootstrap, and
genesis-activation roles are hardened to exact `NOLOGIN`; database ownership
alone is insufficient. The policy creates a `NOLOGIN` logical role with only
`CONNECT`, public-schema `USAGE`, and the exact read/write table surface used by
the successor repository. It grants no sequence, `DELETE`, DDL, SYSTEM,
ownership, grant-option, or unrelated-object authority.

The companion
[quarantine policy](../deploy/cockroach/successor-schema-quarantine-grants.sql)
remains deny-only: after prefix 1 through 14 it revokes every successor-table
privilege from `public`, runtime, bootstrap, and genesis activation and grants
nothing. It does not conflict with the separate successor boundary. Before
every successor-policy apply and use, a cluster admin must drain members and
freeze role, grant, default, ownership, and schema-DDL changes. Clean forbidden
future defaults, including an optional reconciliation role's creator-scoped
PUBLIC routine default, and remove either-direction successor/reconciliation
membership edges. Then enumerate every other database for direct successor-role
grants and ownership and separately inventory inherited PUBLIC authority.
Reapply the successor policy immediately before granting an externally
provisioned login exclusive membership, run the reviewed CLI ceremony, then
revoke membership and disable the login. The SQL file cannot perform the
cross-database audit or provision the login. No AWS task, production-image
binary, startup hook, or public/runtime route exists.

Conflict reconciliation has a different, explicitly implemented one-shot
boundary. Only a cluster admin may apply the database-local policy; database
ownership alone is insufficient. Apply the
[`fleet_conflict_reconciliation` policy](../deploy/cockroach/conflict-reconciliation-role-grants.sql)
after successful prefix 1 through 16 and the three prior logical roles are
hardened. A separately provisioned login may temporarily receive
membership only in that `NOLOGIN` logical role for the apply-only workstation
CLI. The successor role is optional, not an additional prerequisite. Before every
reconciliation apply and use, quiesce members and freeze authority changes. If
the successor role exists, explicitly remove its creator-scoped PUBLIC routine
default and either direction of successor/reconciliation membership. Then
enumerate all other databases for direct reconciliation grants/ownership and
account separately for inherited PUBLIC authority before applying the
reconciliation policy. The reciprocal cleanup-before-audit order is required
before a successor policy apply when reconciliation exists. Both edge shapes
fail closed before policy mutation, but neither SQL file can perform the other
role's conditional default cleanup or the cross-database audit. Remove
membership and disable the login afterward. No Terraform, runtime, image, ECS,
MCP, or HTTP wiring exists.

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

The publication process additionally requires the decoded URL username and
the connected CockroachDB `current_user` to be exactly `fleet_publication`;
private database URL variables are rejected from its environment. The official
local CockroachDB v26.2.3 TLS wrapper passes that connected PUBLIC-03 boundary.
A separate clean-checkout LocalStack run at commit `cd6ecfc` passes the current
three-secret image/config/database denial and replacement lane, with its
[receipt](evidence/localstack-publication-cd6ecfc-20260816.json) explicitly
marking AWS apply, IAM enforcement, TLS, database-password authentication, and
Fargate as unproved. Terraform's 21 configuration tests pass, but the current
Terraform remains unapplied; none of these local results is an AWS deployment
or activation claim.

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
publication reader has no write table operation or sequence authority. The
bootstrap role's required raw inserts can occupy an immutable singleton or
plant a detached future offset. The activation role can occupy immutable
activation/head rows or misuse its table-level shard-head update. The unique
predecessor index prevents one class of fork but cannot prove a new event is
the head-authorized append. These credentials are therefore exclusive
ceremony capabilities, not operator shells or general service accounts.

The existing genesis-activation credential is genesis-only. It has no authority
over the successor tables. The successor repository, workstation CLI, and
dedicated logical-role policy are implemented, but they are not an enabled
production successor runtime: there is no deployed login, AWS secret or task,
image binary, startup hook, or route. The migrator/schema owner retains
technical authority and must not be repurposed as the ceremony credential.

The successor role necessarily has raw `INSERT` and `UPDATE` table authority,
including table-level `UPDATE` for its `FOR UPDATE`/compare-and-swap paths.
CockroachDB RBAC cannot limit that credential to the repository's prepared
statements. Keep its login quiesced outside the exclusive ceremony, repeat the
external audit and policy immediately before membership/use, and treat direct
SQL misuse or a partial projection as corruption requiring an audited forward
repair.

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
