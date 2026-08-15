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

Accepted control and activation events are append-only and source-positioned.
Bootstrap/activation transactions use one database acceptance time, scoped
head locking and compare-and-swap, exact event positions and chain digests, and
complete durable predecessor audits. Compound writes execute in one
serializable transaction; only CockroachDB SQLSTATE `40001` retries the whole
operation. Application claim, support, conflict, event, and receipt mutations
follow the same bounded idempotent/serializable rule.

Current source embeds migrations 1 through 9. Migrations 3 through 9 add and
harden the private control and genesis-activation projections. Normal recall,
ingest, MCP, and public-demo health intentionally retain an additive minimum
schema requirement of version 2; that serving compatibility check is not a
release-completion or private-ceremony authorization gate. Stage 2 requires
the complete successful prefix 1 through 3, and Stage 3 requires 1 through 9.

## Identities, URLs, and secrets

The current AWS Terraform has exactly two database credential paths: a
least-privilege runtime URL and a distinct DDL-capable migrator URL, each from
its own secret input. It has no bootstrap or registry-activation secret, task
definition, route, or startup hook. When a private local ceremony is
actually run, Stage 2 uses a third SQL principal and dedicated control URL;
Stage 3 uses a fourth SQL principal and dedicated registry URL. Those one-shot
credentials are never fallbacks for runtime or migration credentials and
should be disabled or removed after the ceremony.

All database URL surfaces require `postgres`/`postgresql`, a hostname, and a
closed parameter set. Serving and Stage-2 control require exactly
`sslmode=verify-full` outside the explicit local escape; that escape requires
`FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1` and a loopback or Compose-only
`cockroach` host. Stage-3 activation ignores the escape and always requires
exactly `sslmode=verify-full`. The only additional accepted query parameter is
one bounded absolute `sslrootcert` path. Fragments, duplicate parameters,
aliases such as `options`, routing overrides, relative certificate paths, and
unknown parameters fail closed. Do not set the local escape in cloud or shared
environments. Debug output redacts database URLs and authority pins.

Apply the exact current-object/PUBLIC policies and normalized grant proofs in
[MIGRATIONS.md](MIGRATIONS.md) and
[CONTROL_BOOTSTRAP.md](CONTROL_BOOTSTRAP.md). Runtime has no control-table
privilege. The private logical roles are non-login, have no admin or SYSTEM
privileges, and receive only the table operations required by their reviewed
one-shot repositories. Re-audit actual migrator default privileges after every
migration; broad `ALL TABLES` or future-object grants would defeat this
boundary.

## Residual SQL authority and recovery

CockroachDB grants table operations, not prepared-statement identities. A
holder of a private writer URL can issue SQL outside the reviewed binary. The
bootstrap role's required raw inserts can occupy an immutable singleton or
plant a detached future offset. The activation role can occupy immutable
activation/head rows or misuse its table-level shard-head update. The unique
predecessor index prevents one class of fork but cannot prove a new event is
the head-authorized append. These credentials are therefore exclusive
ceremony capabilities, not operator shells or general service accounts.

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
