# CockroachDB migration policy

The embedded schema migrations live in [`migrations/`](../migrations), and
`ostk-fleet-recall migrate` applies them in order; each file's header comment
describes it. Migration 1 creates the distributed corpus, claim and conflict
ledgers, audit tables, vector indexes, and lexical inverted index; migration 2
adds the scoped support lookup; migration 3 adds the private control-event
ledger; migration 4 adds the immutable genesis-registry activation ledger and
singleton active head; migration 5 adds the scoped unique control-event
predecessor index; and migrations 6 through 9 remove the implicit clock
defaults from the bootstrap, epoch, shard-head, and event projections,
respectively. Migrations 10 and 11 add the exact immutable genesis-head and
genesis-activation root indexes needed by successor foreign keys. Migrations 12
through 14 add, respectively, the append-only registry transition history,
one-shot genesis-bridge consumption, and successor current-head projection.
Migration 15 replaces conflict uniqueness by `(tenant, project, claim key)`
with detector-versioned uniqueness; migration 16 adds the covering
claim-transition provenance index required by legacy reconciliation; migration
17 adds the covering current-conflict detector/state projection index required
by normal serving; and migration 18 adds the Stage-4 runtime foundations
recorded in [ADR 0002](adr/0002-stage4-runtime-foundations.md): the general
accepted-event ledger (`memory_evidence_events` plus
`memory_evidence_shard_heads`, which carries no foreign key to any control or
registry table), the quarantine, governed-content, and relation-projection
tables, the nullable `accepted_event_id` columns on `memory_claims` and
`memory_mutation_receipts`, and the read-only `memory_writer_authority_v1`
head-witness view.

Migrations 19 through 28 add private-plane tables for the dynamic-memory
runtimes: the content-addressed body projection, the coverage runtime, the
recall projection and its per-row visibility class, transcript and CI
connector state, normative activation, the discrepancy ledger, and the
bootstrap-manifest import rows. Version 25 is a deliberate, permanent gap.
Migrations 29 through 31 add the conflict lifecycle log, the worker source
status, and spec conformance (described below and under
[Privilege separation](#privilege-separation)). Migration 32 adds no table:
it widens migration 24's normative-log record-kind check to admit `rebase`
rows, which the writer-authority installer appends when it moves a scope to
generation 3 ([ADR 0008](adr/0008-collected-items.md) D3). Migration 33 adds
the collected-item sink (ADR 0008 D4 to D6): the staging outbox, the
append-only item history and its links, the current-view heads, container
audiences, collector status, per-domain cursors, and digest-only dead
letters. Migration 34 adds its withdrawals (ADR 0008 D5 and D6): the trust
tier of each container observation, containers recorded withdrawn before
anything was admitted through them, and items whose own audience narrowed.
The two ship together, and the collector runtime needs both.

Each private runtime uses its own part of these tables:

- The memory worker writes the tables of migrations 19 through 22, 26, 30,
  33, and 34, and migration 23's body-visibility table. Its `collect` step
  runs the configured collectors (the documents directory; ADR 0008 D8),
  which stage into migration 33's outbox and write its containers, item
  withdrawals, status, cursors, and dead letters, drains the outbox into the
  item history, links, and heads, and records each reconciliation pass in
  migration 20's coverage tables. No migration or grant is added for it.
  `ostk-fleet-recall collect`, as the writer, writes the same tables when it
  imports a file (ADR 0008 D9), and the step records the snapshot of an
  import staged with `--no-drain`. It reads `memory_worker_sources_v1` to keep
  an import off a worker source's instance, and adds no migration or grant.
- `ostk-spec` writes the tables of migrations 24, 27, and 31.
  `ostk-authority-install apply --target generation-3`, as the migrator,
  appends migration 32's `rebase` rows to migration 24's log and moves those
  families' heads.
- `serve` reads the tables of migrations 19 through 22 and 30 (with the
  visibility class migration 23 adds to the recall tiers), and from migration 34
  on the collector outbox, items, heads, containers, item withdrawals, and
  collector status, for `recall(kind=evidence)`; those tables, the item links,
  and migration 20's coverage cursors for `recall(kind=item)`; and those of
  migrations 24, 27, and 31 for `recall(action="discrepancies")`. The
  `evidence` and `spec_conformance` blocks of `recall(status)` read the same
  tables, and the evidence block's `collectors` count also reads the
  collector dead letters. `serve` writes none of them unless agent capture is
  turned on (ADR 0008 D10): then `remember(capture)` stages into migration
  33's outbox and writes its capture instance's status row and dead letters,
  and, when `enabled`, drains its own rows into the item history, links, and
  heads as the worker's step does. Of the other tables from migration 19
  onward, it writes only migration 29's lifecycle log. Capture adds no
  migration or grant.
- Only the private import CLI writes migration 28's rows. No served path
  reads them or migration 23's publication views.

The runtime role policy grants `fleet_runtime` the tables of migrations 19
through 24, 26, and 27, as it does those of 29 through 31, 33, and 34. It grants
nothing on migration 23's publication views or migration 28's import rows.

Serving requires none of these migrations: `MINIMUM_RECALL_SCHEMA_VERSION`
stays 18. `serve` serves each surface built on them only when its startup
probe finds the schema version and the runtime grants on every table the
surface reads. Migration 29 gates the conflict lifecycle, 30 gates
`recall(kind=evidence)`, 31 gates `recall(action="discrepancies")`, and 34
gates `recall(kind=item)` (ADR 0008 D7); migration 32 gates nothing served.
Evidence recall reads its collector state (migrations 33 and 34) when it
finds it readable, and is still served, fail-closed, when it does not; until
it is readable it checks again on every read, so they need no restart for
it (ADR 0008 D5). `recall(kind=item)` is probed at startup like the others. A
surface whose probe fails is left out of `tools/list`, and `serve` logs why;
every other surface is unchanged. The probes run only at startup, so
roll each of these migrations out the same way:

1. Deploy the new binary. The probe finds nothing and the surface is not
   served.
2. Run `migrate`.
3. Drain `fleet_writer` and re-apply the runtime policy.
4. Restart `serve` so the probe sees the grants.

An older `migrate` binary refuses the database with `VersionMissing` for the
first applied version it does not embed (`VersionMissing(29)` for one built
before migration 29), so a rollback runs the older `serve` binary only.

Migration 29 adds `memory_conflict_lifecycle_events_v1`, the append-only
per-conflict lifecycle log that the serving writer reads and appends
([ADR 0004](adr/0004-serving-conflict-lifecycle.md)). It carries no foreign
key, so bulk deletes of `memory_conflicts` are unaffected, and it changes no
existing table. Without it, or without the runtime grants on it, the writer
serves the claim lifecycle alone: no `acknowledge`, concession `resolve`, or
lifecycle overlay.

## Transaction policy: versions 1–11, 12–14, and 15 onward

CockroachDB 26.2 runs vector-index creation through its declarative schema
changer and rejects that operation inside an explicit multi-statement
transaction. Versions 1 through 11 are therefore registered with
`no_tx = true`. Migration files 1 and 3 through 11 also carry the explicit
`-- no-transaction` marker; migration 2 is registered with the same policy.
Migration 4 starts three online secondary-index backfills before it creates the
genesis activation projections. Migration 5 is one unique-index backfill, and
each of migrations 6 through 9 is exactly one `DROP DEFAULT` column schema
change. A failure in versions 1 through 9 can therefore leave committed DDL or
a completed schema-change job without a successful SQLx row.

The schema-locked migration-4 tables also prevent migrations 10 and 11 from
sharing an explicit transaction with SQLx bookkeeping. Those two migrations
are deliberately resumable: each uses `CREATE UNIQUE INDEX IF NOT EXISTS`,
commits the schema change, and then checks the exact public
`pg_catalog.pg_indexes.indexdef`. The same-name exact index is accepted on a
retry; a missing, non-public, non-unique, differently ordered, or otherwise
wrong-shape object raises SQLSTATE `55000` before SQLx can record success.

Migrations 12 through 14 each create exactly one table and are registered with
`no_tx = false`. `CockroachStore::migrate` first validates every applied
version and checksum, runs versions 1 through 11 with
`autocommit_before_ddl = true`, then runs the transactional phase through 14 on
the same dedicated connection with `autocommit_before_ddl = false`. That
CockroachDB session setting is required: its default would commit DDL before
SQLx inserts the matching history row even inside SQLx's transaction. The
dedicated connection is closed on success or failure, so the override never
returns to the shared runtime pool. A live CockroachDB test forces the history
insert to fail after DDL and requires both the new table and history row to be
absent.

Every migrator session pins `search_path = public, pg_temp`. The writer pins
`pg_catalog, public, pg_temp`, and the migrator cannot use that path. The
migrations, like SQLx's own `_sqlx_migrations`, create objects without a schema
name, and a database creates such an object in the first schema that
`search_path` names. Under the writer's path that schema is `pg_catalog`, and
CockroachDB refuses it with SQLSTATE `42501`. An unnamed `pg_catalog` is still
searched before every named schema, so names resolve in the same order as for
the writer. On every new and reused connection, the migrator pin checks both
facts: the session creates objects in `public`, and it resolves names in
`pg_catalog` first. A live test runs `migrate` on a newly created database over
sessions pinned this way.

Versions 15 onward form a third phase with
`autocommit_before_ddl = true` and `no_tx = true`. Migration 15 accepts only the
exact old-only, old-plus-new, or new-only detector-index transition states. It
creates and commits the new detector-versioned unique index, verifies both
catalog shapes, drops the legacy constraint-backed index with `CASCADE`,
commits, and verifies the exact final state; it rewrites no conflict rows.
Migrations 16 and 17 each use `CREATE INDEX IF NOT EXISTS`, commit the online
backfill, and assert the complete public catalog definition including stored
columns. Same-name drift fails with SQLSTATE `55000` before SQLx can record
success. Migration 18 belongs to this phase because its two `ALTER TABLE ADD
COLUMN` steps run against schema-locked tables. Every object it creates uses
`IF NOT EXISTS`, and each new column's CHECK is installed by a separate `ADD
CONSTRAINT IF NOT EXISTS` rather than inline: an inline named CHECK is not
resumable, because a re-run skips the existing column and still rejects the
duplicate constraint name with SQLSTATE `42710`. Migration 18 then commits and
asserts the committed public catalog exactly like v15 through v17: the exact
ordered column shape of all six new tables and the view, the authority view's
kind, owner, and complete `pg_get_viewdef` definition, the complete committed
constraint set of every table it creates -- every CHECK, the primary key, every
UNIQUE (including `UNIQUE (tenant_id, project, event_id)` and
`memory_evidence_events_predecessor_unique_idx`, which CockroachDB records as
`pg_constraint.contype = 'u'`) and every foreign key, as an exact ordered
`contype:name:pg_get_constraintdef` fingerprint -- the exact definition of both
`accepted_event_id` CHECK constraints it adds to pre-existing tables, the
absence of any foreign key on the evidence head table, and the exact
events-to-heads foreign-key definition. `IF NOT EXISTS` alone would silently
ADOPT an unrelated object that merely shares a name -- a forged
`memory_writer_authority_v1`, a `memory_evidence_quarantine` carrying a payload
column, or a `memory_evidence_events` with the exact fifteen columns and the
exact head foreign key but WITHOUT the governance-exclusion CHECK and without
the event-id UNIQUE -- and record it as a successful version 18; every one of
those cases now fails with SQLSTATE `55000` before SQLx can write its history
row. The constraint fingerprint filters no `contype`, so an ADDED constraint
drifts as loudly as a missing one.

Migrations 19 onward follow the same resumable pattern: each carries the
`-- no-transaction` marker, creates its objects with `IF NOT EXISTS`, and most
close with catalog-shape assertions that fail with SQLSTATE `55000` on a
same-name object of another shape.

Resumability is an operational constraint, not permission to run migration
casually:

- run one migrator only;
- keep every application service at zero during the initial migration;
- use a dedicated DDL credential;
- wait for success and inspect schema-change jobs before starting the service;
- for versions 1 through 11, never assume an error rolled back DDL;
- for versions 12 through 14, treat non-atomic state as evidence of an
  unreviewed runner/session or catalog drift;
- for versions 15 onward, wait for online jobs and use only the reviewed
  resumable catalog transitions; and
- follow the version-specific recovery rules below instead of editing SQLx
  history.

The Terraform deployment provides separate migration, private-writer seed,
and publication-reader task capability paths and defaults the
application service and autoscaling minimum to zero.

## Cloud bootstrap

1. Create a dedicated, empty CockroachDB database named `fleet_recall`.
2. Create three separate database capability paths: a DDL-capable migrator, a
   private writer for seed/MCP DML, and the fixed external
   `fleet_publication` login for the public demo. Store their strict-TLS URLs as
   three distinct raw AWS Secrets Manager values. Provision
   `fleet_publication` outside Terraform in the exact quiesced `NOLOGIN` state;
   Terraform does not create CockroachDB identities, memberships, or grants.
3. Apply `deploy/aws` with `service_desired_count = 0` and
   `autoscaling_min_capacity = 0`.
4. Confirm no other migration task is running in ECS.
5. Run `./deploy/aws/run-migration.sh` once.
6. Inspect the task's CloudWatch logs and confirm exit code zero.
7. Separately, with the migrator/security-operator procedure, verify that
   `_sqlx_migrations` has a successful row for every file in `migrations/` and
   inspect all schema-change jobs. The private compatibility gates remain
   intentionally distinct: Stage-2 control requires prefix 1 through 3,
   genesis Stage-3 requires 1 through 9, the first-successor repository
   requires 1 through 14, and conflict-detector reconciliation requires 1
   through 16. None is a substitute for the serving floor.
8. While `fleet_publication` remains quiesced, perform the required
   cross-database/default/ownership/PUBLIC audit and apply
   [`publication-reader-role-grants.sql`](../deploy/cockroach/publication-reader-role-grants.sql).
   Freeze role, grant, default, ownership, and schema-DDL changes; repeat the
   external audit if necessary and reapply the policy immediately before the
   exact login-enable operation described below.
9. Run `health` and the one-off seed with the private writer credential.
   Recall, remember, ingest, MCP, health, and the public demo require an
   uninterrupted successful prefix through at least version 18
   (`MINIMUM_RECALL_SCHEMA_VERSION`), the exact current indexes, cosine
   support, and the configured model identity. Later additive rows remain
   compatible, but cannot mask a missing or failed row in 1–18.
10. Enable only the externally managed `fleet_publication` authentication,
    then set the desired/minimum service count to at least one and apply again.
    The public task receives only its publication-reader secret.

The migration command also initializes the immutable project/model registry.
Use the same logical model name and bundle digest for migration, ingestion,
MCP, and demo tasks.

None of the Stage-2 control-bootstrap, genesis Stage-3 activation,
first-successor, or conflict-reconciliation commands/credentials is wired into
the current AWS Terraform or CloudFront serving path. They remain separate
local/private operator gates.

Migrations 12 through 14 and the versioned successor contracts install the
durable schema. A first-successor repository and workstation apply/inspect CLI
are implemented with a database-local, cluster-admin-only one-shot logical-role
policy. The policy creates no login, AWS secret or task, production-image
binary, startup hook, or runtime route. Consequently no production credential
is authorized to populate or advance
`memory_registry_transitions`,
`memory_registry_genesis_bridge_consumptions`, or
`memory_registry_current_heads_v2`; the migrator/schema owner retains technical
authority, and all three tables remain quarantined from normal application
roles. Only a separately provisioned, exclusive local ceremony login may
temporarily inherit the reviewed successor role.

Conflict reconciliation is likewise private: it has an apply-only workstation
CLI and a database-local one-shot role policy
applied by a cluster admin only; database ownership alone is insufficient. That
policy requires its external cross-database grant/ownership audit; neither the
policy nor its credential/CLI is wired into Terraform, the runtime role, an AWS
task, or the production image.

## Local bootstrap

Use an empty local CockroachDB database and export the variables in
`.env.example`, replacing the URL and model digest:

```bash
cargo run --locked -- model-digest /absolute/path/to/model-bundle
cargo run --locked -- migrate
cargo run --locked -- health
```

Do not run two `migrate` processes against the same database. The connected
test suite uses an isolated database and runs schema setup serially before
exercising concurrent application behavior.

## Privilege separation

Use a dedicated database so grants do not accidentally include unrelated
application tables. Exact syntax should be checked against the selected
CockroachDB Cloud version and existing role policy before execution.

Database ownership is not sufficient to apply the checked-in security
policies. Their deterministic hardening performs `ALTER ROLE`, removes role
membership (including accidental `admin` inheritance), and revokes SYSTEM
privileges. Run them as a cluster admin, or as a dedicated security operator
with `CREATEROLE`, every required role admin option and SYSTEM grant option,
plus grant authority on the database, schema, tables, and sequences.

The migration principal needs database/schema creation privileges for tables,
sequences, secondary indexes, and SQLx's migration bookkeeping table. A
separately provisioned private-writer login is a member only of the hardened
`NOLOGIN` `fleet_runtime` logical role. That seed/MCP grant bundle needs:

- `CONNECT` on the Fleet Recall database;
- `USAGE` on its schema and sequences;
- only the documented DML privileges on legacy corpus, claim, and projection
  tables;
- append, head-advance, quarantine and relation-projection privileges on the
  Stage-4 evidence plane (`memory_evidence_events`,
  `memory_evidence_shard_heads`, `memory_evidence_quarantine`,
  `memory_content_objects`, `memory_relation_projection_v1`,
  `memory_relation_projection_watermarks_v1`), with no `UPDATE` or `DELETE`
  on the accepted envelope, no `DELETE` anywhere, and no privilege on any
  `memory_control_*` or `memory_registry_*` base table;
- append and advance privileges on the body, coverage, recall, transcript,
  and CI connector tables, normative activation, the discrepancy ledger, the
  conflict lifecycle log, worker source status, spec conformance, and the
  collected-item sink (the tables of migrations 19 through 24, 26, 27, 29
  through 31, 33, and 34), described below;
- `SELECT` on the migrator-owned `memory_writer_authority_v1` view, which is
  the writer's only registry/bootstrap read path;
- read access to SQLx migration metadata for health checks;
- no `CREATE`, `DROP`, role-management, cluster-setting, or external-connection
  privileges.

Never grant private-writer privileges with `ON ALL TABLES IN SCHEMA public`: migration
3 deliberately puts control tables in that schema, and future private tables
must not become reachable through defaults. The reviewed grant matrix is
[`deploy/cockroach/runtime-role-grants.sql`](../deploy/cockroach/runtime-role-grants.sql);
apply that file as an authorized administrator rather than hand-writing grants.
It is deliberately narrower than the reusable library surface: per-table verbs
only (for example `memory_chunk_history` receives `SELECT`/`DELETE` only, and
`memory_attention` and `memory_claim_link_events` receive nothing), `USAGE` on
only the claim, claim-support, and conflict ID sequences, and `SELECT` on
`_sqlx_migrations`. The SQL file is the row-by-row reference.

Migrations 30 and 31 add the last tables this policy covers. Migration 30
(ADR 0006) creates `memory_worker_sources_v1`: one row per configured worker
connector instance, recording when the worker last attempted the source, when
it last completed a check (`ok` or `unchanged`), the outcome, a bounded error,
and how long a completed check stays current. Evidence recall reads it to
tell a source that failed, went stale, or never reported from one that is
current. Migration 31 (ADR 0007) creates `memory_normative_statements_v1`,
the canonical normative proposal and typed expectation each spec statement
was activated with, and `memory_spec_checks_v1`, one content-addressed record
per spec check with its verdict (`nonconforming`, `conforming`, or
`unknown`) and the discrepancy episode it opened or joined. Both are read and
written through `spec_conformance::CockroachSpecRepository`, which re-derives
each row's identity from its canonical bytes on every read, so a row edited in
place is refused rather than re-interpreted. All three are
private-plane tables with no foreign key; each migration follows the
resumable pattern above and closes with a same-name drift guard (the column
shape, plus migration 31's two indexes).

Migration 33 (ADR 0008 D4 to D6) adds eight private-plane tables, none with a
foreign key and none ever granted to the publication reader:
`memory_collector_outbox_v1` (one row per staged part, keyed by its stage id,
holding the redacted canonical envelope only while it is pending: a CHECK ties
`state = 'pending'` to a non-NULL envelope, so settling a row drops its text
and keeps its SHA-256), `memory_collected_items_v1` (append-only history, one
row per admitted part, keyed by its accepted event),
`memory_collected_item_links_v1`, `memory_collected_item_heads_v1` (one head
per item and trust tier, with a partial unique index that keeps exactly one
presented head per item), `memory_collector_containers_v1` (the audience a
container was admitted on, and whether it was withdrawn),
`memory_collector_sources_v1` (collector status, apart from the worker's own
table), `memory_collector_cursors_v1`, and `memory_collector_dead_letters_v1`
(a closed reason, digests, and a static diagnostic, never content). It closes
with a drift guard over every table's column shape and the presented-head
index.

Migration 34 (ADR 0008 D5 and D6) changes one table and adds one, again with
no foreign key and nothing for the publication reader.
`memory_collector_containers_v1` gains a nullable `observed_tier`, the trust
tier of the observation that last set a row's access (NULL, a row from before
the migration, reads as verified), and its audience check is widened to admit
basis `none` on a withdrawn row, so a container refused before anything was
admitted through it can be recorded withdrawn. The widened check is added and
committed before migration 33's is dropped.
`memory_collected_item_withdrawals_v1` holds, per item and trust tier, whether
the item is withdrawn and the provider order of the observation that last
decided it; a lifted withdrawal is updated, never deleted. It closes with a
drift guard over both tables' column shapes, the two new constraints, and the
absence of the old one.

For the tables from migration 19 onward the policy grants one of three
shapes, and never `DELETE`:

- **Append-only (`SELECT`, `INSERT`):** the Stage-5 body objects, chunk
  occurrences and their spans, parse-run manifests, source-commit membership,
  and coverage receipts; the CI connector's measured windows; the normative
  and discrepancy logs; migration 29's conflict lifecycle log; migration 31's normative
  statements and spec checks; and migration 33's collected item history, item
  links, and collector dead letters. The runtime can add a logged event,
  receipt, statement, check, history row, or dead letter but never rewrite or
  remove one.
- **Advanced state (`SELECT`, `INSERT`, `UPDATE`):** generation pointers, the
  body projection watermarks, body visibility, coverage cursors, the lexical
  and dense recall projections and their cursors, the transcript outbox and
  cursors, the normative and discrepancy heads and projections, migration
  30's worker source status, migration 33's collector outbox, item heads,
  collector status, cursors, and containers, and migration 34's item
  withdrawals. None of these rows is a logged event or a receipt: they are
  heads, cursors, pointers, projections, the outboxes' drain state, container
  audiences and withdrawals, and operational status. `UPDATE` covers each
  compare-and-set advance or upsert, and the `SELECT ... FOR UPDATE` that
  locks a head or cursor.
- **Read-only (`SELECT`):** `memory_discrepancy_relations_v1`. Nothing served
  appends a relation yet.

One more row is on a Stage-4 table: `UPDATE` on `memory_content_objects`.
CockroachDB v26.2.3 requires `UPDATE` for `SELECT ... FOR UPDATE`, and the
governed content store takes that lock whenever an append deduplicates onto
an existing content object, to compare it with the admitted bytes
(`LOCK_CONTENT_OBJECT_SQL` in `src/evidence_ledger/content_store.rs`). The
lock is deliberate (EVID-01): it reads the latest committed version of the
row, not the append transaction's snapshot, so a stored row whose identity
columns were altered after that snapshot fails the append instead of passing
it. No runtime statement updates that table, but the grant is table-wide: a
holder of the writer login can rewrite any content row in any tenant
directly, including its ciphertext, wrapped key, and retention annotations.
Without the deployment KEK, a rewritten ciphertext or wrapped key fails to
open, because both are sealed with the scope and storage identity as
associated data and opening re-checks the content digest. The retention
annotations are not authority, because each accepted event carries its own.
Treat such a rewrite as corruption, like any other direct-SQL misuse of the
writer login (see
[SECURITY.md](SECURITY.md#residual-sql-authority-and-recovery)). The policy
grants nothing on migration 23's publication views or on migration 28's
bootstrap-import rows, and the publication reader gains nothing from any of
these rows. The policy closes by
checking the exact 139-row matrix: database `CONNECT`, schema `USAGE`, 134
table-privilege rows, and three sequence-`USAGE` rows. Migration 33 added 21
of them: `SELECT` and `INSERT` on its three append-only tables, and `SELECT`,
`INSERT`, and `UPDATE` on its five advanced-state tables (the matrix was 115
rows, 110 of them on tables, before it). Migration 34 added three: `SELECT`,
`INSERT`, and `UPDATE` on the item withdrawals.

A single gate guards all of it. Before any change, the policy requires a
successful SQLx row for every migration from 1 through 34 (version 25 is
permanently unused); a later successful migration cannot mask a missing or
failed one in that prefix. Migration 32 adds no table and needs no grant (the
runtime already holds `INSERT` on the normative log); it is inside the gate only
because migrations 33 and 34 are. When a later migration adds tables a runtime
needs, extend the policy in one edit: the gate, the grants, and the closing
count together. The writer probes its grants only at startup, so after
`migrate`, drain `fleet_writer`, reapply this policy, and then restart `serve`.

Grant the external private-writer login only membership in `fleet_runtime`; do
not copy these DML/sequence grants onto the fixed publication login.

Do not add the three successor tables from migrations 12 through 14 to this
runtime grant. They remain unavailable to runtime and the earlier application
roles. The existence of their schema, canonical contracts, and one-shot
successor role does not create runtime or cloud successor authority.

The public service has a narrower and independently enforced SQL boundary.
The fixed externally provisioned login `fleet_publication` is a member only of
the logical `fleet_publication_reader` role, which is forced to `NOLOGIN`. Its
entire positive grant surface is `CONNECT` on `fleet_recall`, `USAGE` on schema
`public`, and `SELECT` on exactly these eight objects:

- `_sqlx_migrations`;
- `memory_corpus_models`;
- `memory_chunks`;
- `memory_claim_embeddings`;
- `memory_claim_support`;
- `memory_claims`;
- `memory_conflict_members`; and
- `memory_conflicts`.

It has zero DML, DDL, sequence, system, private-table, ownership, grant-option,
or future-default authority. Apply
[`publication-reader-role-grants.sql`](../deploy/cockroach/publication-reader-role-grants.sql)
only as a cluster admin after prefix 1 through 17 (the policy's own gate;
later migrations remain compatible), with `fleet_publication` already drained
and set to exact `NOLOGIN`. Audit both principals and inherited PUBLIC
authority across every database, freeze role,
grant, default, ownership, and schema-DDL dependencies, reapply the policy
under that freeze, and only then perform the separate exact authentication
enable. Quiesce/drain the login and repeat the audit/reapply sequence after
every migration or grant change. The SQL policy intentionally does not create
the external login or its password/identity-provider binding.

Then apply and verify the exact control-plane exclusions and one-shot bootstrap
grants in [the private control bootstrap policy](CONTROL_BOOTSTRAP.md). The
base policy can first run after migration 3 and remains valid at that stage.
Once the database is past migration 14, create/harden both frozen private
logical roles by applying or reapplying the control and genesis-activation
policies, then apply the
[quarantine policy](../deploy/cockroach/successor-schema-quarantine-grants.sql).
That deny-only policy retains its own complete-successful-prefix-1-through-14 gate,
then revokes every privilege and grant option on the three successor tables
from `public`, runtime, bootstrap, and genesis activation; it grants nothing.
Later migrations add no successor tables, so they do not change that
quarantine's object set. Runtime and `public` have no control-table privilege.
The logical runtime and bootstrap bundles are forced to `NOLOGIN`,
`NOCREATEROLE`, and `NOCREATEDB`; the policy removes their direct SYSTEM
grants, inherited admin, and both runtime/bootstrap membership directions. It
also re-revokes `public` grants on all current tables and sequences and resets
the bootstrap role's complete current-object surface before adding back its
exact ledger grants.

These scripts reset current objects; they do not establish a universal
future-object rule for an unknown schema creator. Run `SHOW DEFAULT PRIVILEGES`
as the actual migrator and require no table/sequence default that grants
`public` or an application logical role. Re-audit defaults and reapply both
current-object policies after every migration. Review all expanded grants and
revoke unnecessary defaults.

All three planned database URLs must use TLS verification. Keep credentials
out of Terraform state, image layers, ECS environment literals, logs, and demo
responses.

### Stage-3 pre-activation gate

The current `deploy/aws` Terraform does not accept a registry-activation secret
or define a registry-activation task. The following is therefore a local/private
pre-activation gate, not an executable step in the cloud-bootstrap sequence
above. Before enabling a cloud activation path, provision a separate
registry-activation SQL principal and TLS secret out of band, or add separately
reviewed Terraform/task wiring that preserves the same isolation.

After the complete successful migration prefix 1 through 9 (later migrations
are compatible) and the reapplied Stage-2 control-role policy, apply
[`registry-activation-role-grants.sql`](../deploy/cockroach/registry-activation-role-grants.sql)
as the cluster-admin/delegated security operator described above, not merely as
the database owner. The genesis Stage-3 repository's compatibility preflight
remains prefix 1 through 9; it accepts later additive release migrations but
does not authorize their successor tables. The private activation login must
be a member only of the `fleet_registry_activation` logical role; disable it or
remove its secret when activation is not in progress. Its complete DML surface
is:

| Object | Privileges |
| --- | --- |
| `_sqlx_migrations` | `SELECT` for the complete successful-prefix-1-through-9 preflight |
| `memory_control_bootstraps` | `SELECT` |
| `memory_control_log_epochs` | `SELECT` |
| `memory_control_shard_heads` | `SELECT`, `UPDATE` |
| `memory_control_events` | `SELECT`, `INSERT` |
| `memory_registry_activations` | `SELECT`, `INSERT` |
| `memory_registry_heads` | `SELECT`, `INSERT` |

After that base role exists on a database containing the successful prefix
through 14, apply the successor-schema quarantine policy linked above. The
quarantine is mandatory even when no activation login is enabled and must
remain exact after the separately reviewed successor logical-role policy is
applied: quarantine excludes the prior roles, while the successor policy owns
its distinct one-shot grant surface.

The logical role is forced to `NOLOGIN`, `NOCREATEROLE`, and `NOCREATEDB`. Its
database/schema surface is only `CONNECT` on the database and `USAGE` on
`public`. It has no bootstrap, epoch, or shard-head `INSERT`; no immutable-row
`UPDATE` or `DELETE`; no legacy corpus, DDL, role administration, direct system
privilege, or grant option.

Because this is a dedicated database, the policy re-revokes all `public`
database and `public`-schema privileges plus every `public` grant on all current
tables and sequences in that schema. It then removes direct Stage-3 access from
`fleet_runtime` and `fleet_control_bootstrap`. Reapplication breaks both known
membership directions: activation cannot inherit admin/runtime/bootstrap, and
runtime/bootstrap cannot inherit activation. The policy creates no
future-object default grant; the separate exact `SHOW DEFAULT PRIVILEGES` gate
above remains mandatory. Reapply it after future migrations create tables or
sequences so those objects enter the current-object reset.

CockroachDB 26.2 exposes `UPDATE` only at table granularity: its `GRANT` grammar
has no column target, and `GRANT UPDATE (column_name) ...` is a syntax error.
Therefore the shard-head grant cannot be narrowed to
`last_committed_offset`, `chain_digest`, and `advanced_at` in RBAC alone. Keep
the activation credential exclusive to the reviewed private repository and
unavailable to runtime, bootstrap, interactive users, and general operators.
The repository's only shard-head `UPDATE` sets exactly those three columns and
scopes the compare-and-swap by tenant, project,
epoch, shard, prior offset, and prior chain digest. Changes to epoch, shard, or
shard count are not part of the credential's reviewed application path.

RBAC cannot distinguish the reviewed prepared statements from arbitrary SQL
issued with the same credential. The bootstrap role's required raw `INSERT`
surface can occupy a singleton/unique key with invalid canonical bytes or plant
a detached future control offset; the activation role can likewise plant a
detached event or occupy the immutable activation/head projections. The scoped
unique index `memory_control_events_predecessor_unique_idx` rejects two events
that claim the same immediate predecessor, but it cannot compare a new
immutable event with the mutable shard head in another row. Any such write can
wedge the scope because these roles intentionally lack repair/delete authority.
Keep both login secrets exclusive to their reviewed commands, disable them
outside the ceremony, and treat a wedge as corruption requiring an audited
forward repair.

### First-successor activation gate

Migration 4 and the checked-in genesis-activation role install only the genesis
head. That role has no `UPDATE` on `memory_registry_heads`. Migrations 12
through 14, the separately versioned contracts, the
`CockroachSuccessorActivationRepository`, and the
`ostk-registry-successor-activate` workstation CLI now implement the bounded
first transition from generation 0 to 1. The repository requires the complete
successful prefix through 14 and revalidates its bound canonical artifacts and
durable roots inside the serializable transition.

The checked-in
[`successor-activation-role-grants.sql`](../deploy/cockroach/successor-activation-role-grants.sql)
creates and hardens the database-local
`fleet_registry_successor_activation` `NOLOGIN` logical role. It requires the
exact successful prefix 1 through 14 and the runtime, control-bootstrap, and
genesis-activation roles already hardened to exact `NOLOGIN`; later migration
rows are compatible. The reconciliation role is optional, not an additional
prerequisite. The successor role receives only database `CONNECT`, public
schema `USAGE`, and 16 non-grantable table rows: migration-history and
read-only witness access plus the exact `SELECT`/`INSERT`/`UPDATE` operations
reachable from the repository. It receives no sequence, `DELETE`, DDL, SYSTEM,
ownership, grant-option, or unrelated-object authority.

This policy is intentionally database-local and cluster-admin-only; database
ownership alone is insufficient. Before every apply/reapply and use, quiesce
all member credentials and freeze role, grant, default, ownership, and
schema-DDL changes. Clean every forbidden non-target PUBLIC routine default,
including the reconciliation role's creator-scoped row if that optional role
exists, and remove either direction of successor/reconciliation membership.
Then audit every other database for direct successor-role grants and ownership
and separately inventory inherited PUBLIC authority. Those conditions fail
closed and require explicit operator cleanup; neither SQL policy is a
self-contained composition mechanism. Reapply the successor policy immediately
before giving one externally provisioned workstation login exclusive
membership, run the reviewed CLI, then revoke membership and restore
`NOLOGIN`/clear the login credential. The SQL file cannot perform the
cross-database audit or provision that login.

Implementation is not deployment authority. There is no successor AWS secret
or task, production-image binary, startup hook, or runtime/public route. Never
overwrite the genesis row, grant the genesis-activation credential access to
the three successor tables, or operate the successor CLI with
migrator/runtime authority.

### Generic `N -> N+1` activation gate (`N >= 1`)

Every generation after the one-time `0 -> 1` step is handled by the separate
`CockroachGenericSuccessorRepository` and the
`ostk-registry-generic-successor-activate` workstation CLI. That runtime
requires the complete successful prefix through 17 and reuses the same
`fleet_registry_successor_activation` role and the same
`FLEET_RECALL_SUCCESSOR_*` process namespace; it needs **no new grant**, because
it touches only relations that role already holds. It has no key bridge: the
keys that authorize the step are the ones the currently active package
installed, so the operator supplies that active package as an artifact and the
repository independently rebuilds the same policy from durable bytes under the
`registry.activation` control-shard head lock.

Reverting means activating an earlier package digest as a later generation; the
new activation ID makes it a forward transition and rewrites no prior interval.
Contested-set recording and contested-set resolution have **no runtime yet** —
no durable table exists — so the repository fails closed whenever the current
head is absent, duplicated, or not `active`, and it never selects between rival
successors.

The live suites `tests/registry_activation_live.rs`,
`tests/successor_activation_live.rs`, and
`tests/generic_successor_activation_live.rs` exercise these repositories
against a real CockroachDB database.

### Generation-3 rollout order ([ADR 0008](adr/0008-collected-items.md) D2)

The generation-3 collected-items package is a `2 -> 3` generic successor. The
package itself needs no new grant, and a binary that does not compile it in
refuses any head that activates it as `UnknownActivePackage`. So the order is fixed, per
physical scope that is to collect items:

1. Ship a binary that recognizes generation 3 to every process that verifies
   a head for that scope: every event-first writer, every `serve`, the worker
   on its ingest host, and the projector container.
2. Apply the release's migrations, then re-apply the grant files. Migration 32
   lets a spec family be rebased and adds no grant; migrations 33 and 34 add the
   collected-item tables and their withdrawals, which the runtime policy grants
   (its gate is now migrations 1 through 34). A worker whose schema predates
   migration 34 skips its `collect` step, and fails it, naming `migrate`, when a
   collector is configured. A `serve` started before this step needs no restart:
   its evidence recall checks the collector state again on every read until it
   is readable, and withholds every collected body until then.
3. Run `ostk-authority-install apply --target generation-3` as the schema
   owner/migrator login. The printed pins are unchanged, so no writer is
   reconfigured. The run then rebases every normative binding family onto
   the new head (ADR 0008 D3) and lists each in the report's
   `normative_families`: `rebased`, `already_current`, or `stranded` with the
   reason. A re-run is a no-op, and the default `--target generation-2` never
   moves a generation-3 head back. The installer refuses, before any write, to
   rebase a scope that holds families without migration 32;
   `--no-normative-rebase` skips the rebase and leaves every family stranded
   (ADR 0007 D11).
4. Only then configure collectors, agent capture, or webhook ingress.

Moving a scope re-keys what is read afterwards (a re-read source fact becomes
a second representation under the new head). A spec draft names the exact
head it was made under, so redraft any draft made before the move.

### Conflict-detector reconciliation gate

The steady-state v2 detector is proposition-aware for one functional claim key
over overlapping half-open intervals: two affirmations conflict when their
exact JSONB values differ; affirmation and negation conflict only for the same
value; two negations are compatible. The original
`same_key_typed_value` lineage is immutable. Reconciliation never relabels,
updates, or deletes that legacy conflict or its memberships. It locks one exact
legacy ID/revision, derives the complete bounded current-claim pair graph, and
appends a separately versioned `same_key_functional_value_v2` lineage, durable
receipt, audit event, and any claim-state transitions in one serializable
transaction. If no v2 incompatibility remains, the new lineage is appended as
`dismissed` rather than erasing history.

The repository and role policy both require the complete successful prefix 1
through 16; a later successful migration 17 is compatible but cannot mask a
missing or failed prerequisite. Before applying
[`conflict-reconciliation-role-grants.sql`](../deploy/cockroach/conflict-reconciliation-role-grants.sql),
apply the control and genesis-activation role policies and confirm their three
logical roles are hardened. Run the reconciliation policy in the dedicated
`fleet_recall` database as a cluster admin only; database ownership alone is
insufficient. The successor role is optional and is not an additional reconciliation
prerequisite.

That SQL policy intentionally audits and repairs only the current
`fleet_recall.public` boundary. Before every apply and use, the operator must
quiesce members and freeze concurrent role, grant, default, ownership, and
schema-DDL changes through member enable/use/disable. Clean every forbidden
non-target PUBLIC routine default (including the successor role's
creator-scoped row when that role exists) and reject either direction of
successor/reconciliation membership. Then enumerate every other database and
reject or revoke all direct grants and ownership held there by
`fleet_conflict_reconciliation` and separately inventory inherited `public`
authority. The cross-database audit and conditional cleanup cannot be delegated
to the database-local SQL file; the two policies do not compose without this
explicit operator preflight.

Provision a separate login externally and grant it membership only in the
`NOLOGIN` `fleet_conflict_reconciliation` role while every other member
credential and concurrent authority change is quiesced. Remove membership or
disable the login immediately afterward.
The CLI reads only its dedicated reconciliation URL, tenant ID, and project
from `FLEET_RECALL_RECONCILIATION_*`; it never falls back to serving, migrator,
control, registry, or successor configuration and always requires TLS
verification. Apply exactly one immutable legacy revision with a dedicated
replay key:

```bash
cargo run --locked --bin ostk-conflict-reconcile -- apply \
  --legacy-conflict-id LEGACY_ID \
  --expected-legacy-revision LEGACY_REVISION \
  --idempotency-key UNIQUE_RECONCILIATION_KEY
```

The command is apply-only and reports `materialized` or `exact_replay`. It has
no inspect/server mode, Terraform secret, ECS task, production-image binary,
runtime credential, MCP method, or HTTP route. The successor and
reconciliation policies do not self-compose: the cluster admin still performs
the conditional cleanup and cross-database/PUBLIC audit before each policy
apply and exclusive member window.

## Failure and interruption recovery

Versions 1 through 11 execute without a wrapping SQL transaction. Versions 12
through 14 execute transactionally only through the reviewed application
migrator and its dedicated CockroachDB session. Versions 15 onward return to
nontransactional, resumable online schema changes. Never synthesize, update,
or delete a SQLx history row merely to bypass a gate. Recovery depends on the
exact failed version:

- v1, v3, and v4 contain multiple schema changes and can leave a partial
  schema. Migration 4 can leave any subset of its three control-ledger index
  backfills before the registry tables and foreign keys.
- v2 and v5 each create one named index. Migration 5 intentionally omits
  `IF NOT EXISTS`: a wrong-shape object with
  `memory_control_events_predecessor_unique_idx` must fail with name drift
  instead of being accepted. Duplicate legacy predecessors must fail its unique
  backfill before any of migrations 6 through 9 remove a timestamp default.
- v6 through v9 each contain exactly one `DROP DEFAULT`, which is idempotent
  when its DDL committed but SQLx success-row insertion was interrupted.
  Resume only after catalog inspection confirms the expected column and no
  unrelated drift.
- v10 and v11 each create one schema-locked unique-index backfill, commit it,
  then assert its exact public catalog definition. If the exact index committed
  but SQLx history did not, the normal migrator retry is the reviewed recovery:
  `IF NOT EXISTS` preserves the index, the assertion verifies every ordered
  key, and SQLx records success. A same-name wrong-shape object fails closed
  with SQLSTATE `55000`.
- v12 through v14 each create one table in the same transaction as the SQLx
  history insert. With the reviewed runner, an error rolls both back. An object
  without its history row, or a history row without its exact object, means the
  SQL ran through an unreviewed client/session or the catalog drifted; do not
  normalize that state by hand.
- v15 is a two-commit catalog transition. It accepts an exact legacy index
  alone, both exact legacy and detector-versioned indexes, or the exact new
  index alone. A retry completes or re-proves those states without rewriting
  conflict data. Any other presence/shape combination fails with `55000`.
- v16 and v17 each create one covering online index, commit, and assert its
  exact `indexdef`. If the exact backfill committed without a history row, the
  normal migrator retry preserves it and records success. A missing index is
  rebuilt; a same-name wrong-shape index fails closed.
- v18 creates six tables, one unique index, one view, two nullable columns,
  and two named CHECK constraints, every one of them with `IF NOT EXISTS`, and
  then proves each object's committed catalog shape and complete committed
  constraint set. Any
  prefix of that file may already be committed after an interruption; the
  reviewed recovery is the normal migrator retry, which is a no-op for every
  object that already exists. It rewrites no existing row and drops nothing.
  A `55000` from its closing assertions is not an interruption: it means an
  object with one of those names is not the object this migration defines, and
  it requires a separately reviewed forward repair rather than a retry.
- v19 onward follow the v18 pattern: every object uses `IF NOT EXISTS`, the
  normal migrator retry is the reviewed recovery after an interruption, and a
  `55000` from a closing assertion means a same-name object has another shape
  and needs a separately reviewed forward repair.
- v32 is two committed constraint changes on `memory_normative_log_v1`: it
  adds `memory_normative_log_kind_v2` (admitting `rebase`), then drops
  migration 24's `memory_normative_log_kind`. Either interruption point leaves
  a kind check in force, and while both exist a `rebase` row is still refused.
  The normal migrator retry resumes it: `ADD CONSTRAINT IF NOT EXISTS` keeps a
  committed new constraint and `DROP CONSTRAINT IF EXISTS` skips a dropped
  old one. Its closing assertion requires the exact committed definition of
  the new constraint and the absence of the old one; a `55000` means a
  same-name constraint of another definition and needs a separately reviewed
  forward repair.
- v33 creates eight tables and their indexes with `IF NOT EXISTS`, commits,
  and then asserts every table's exact column shape and the exact definition
  of the partial unique index that keeps one presented head per item. The
  normal migrator retry resumes an interrupted run; a `55000` means a
  same-name table or index of another shape and needs a separately reviewed
  forward repair. It rewrites no existing row.
- v34 adds `observed_tier` to `memory_collector_containers_v1`, then its tier
  check, then the widened audience check
  (`memory_collector_container_audience_v2`), then drops migration 33's
  `memory_collector_container_audience`, then creates
  `memory_collected_item_withdrawals_v1`, each committed on its own and each
  `IF NOT EXISTS` (the drop `IF EXISTS`). Every interruption point leaves an
  audience check in force, and while both exist a `none` row is still
  refused. The normal migrator retry resumes it. Its closing assertion
  requires both tables' exact column shapes, the exact definitions of the two
  new constraints, and the absence of the old one; a `55000` means a
  same-name object of another shape and needs a separately reviewed forward
  repair. It rewrites no existing row: the new column is NULL on every row
  migration 33's runtime wrote.

1. Leave the application service at zero.
2. Preserve the migration task logs and exact CockroachDB error.
3. Inspect `_sqlx_migrations`, `SHOW TABLES`, `SHOW CONSTRAINTS`, `SHOW INDEXES`,
   and relevant `SHOW JOBS` output using the migrator account. Record job IDs,
   status, errors, and whether backfills are still running before changing
   anything.
4. Compare the observed state with the exact failed file: v1's corpus/vector
   objects; v2's support lookup index; v3's control tables and foreign keys;
   v4's three control-ledger index backfills plus activation/head tables and
   foreign keys; v5's exact five-column scoped unique predecessor index; or the
   one exact column default owned by v6, v7, v8, or v9. For v10 or v11, compare
   the complete `pg_catalog.pg_indexes.indexdef` and job state, not merely the
   index name. For v12 through v14, compare the exact table, constraints,
   foreign keys, and matching SQLx row. For v15, inspect both the retired
   `memory_conflicts_tenant_id_project_claim_key_key` index and the new
   `memory_conflicts_scope_key_detector_unique_idx`. For v16 and v17, compare
   the complete covering index definition and job state. For v18, compare the
   six new tables, `memory_evidence_events_predecessor_unique_idx`, the
   `memory_writer_authority_v1` view and its owner, the complete constraint set
   of each new table (`SHOW CONSTRAINTS` plus `pg_get_constraintdef`, not the
   relation names alone), and both `accepted_event_id` columns with their named
   CHECK constraints. The migration's own closing assertions report the drifted
   relation by name.
5. If this is a brand-new empty demo database, the safest recovery is to create
   another empty database and run the complete migrator once against that
   replacement. Deleting the partial database is a separate destructive
   operator decision.
6. If durable data exists after a v1–v5 failure, do not drop partial objects,
   delete conflicting ledger rows, replay migration text blindly, or mark the
   version successful merely to bypass the gate. Author a separately reviewed
   forward-repair procedure for the exact observed catalog/data state and prove
   it on a copy. An interrupted v5 after its exact index committed needs this
   reconciliation because replay correctly rejects the existing name.
7. For v6–v9 only, if the expected default is already absent, no SQLx success
   row exists, and no other drift is present, resume the normal single migrator;
   its repeated `DROP DEFAULT` is the reviewed recovery path. Never create or
   update migration history by hand as a shortcut.
8. For v10 or v11, wait for any running schema-change job to finish before
   retrying. If the exact public index exists and no success row does, rerun the
   normal single migrator; its catalog assertion is the recovery gate. If the
   index is absent and no job remains, the same rerun creates it. If the
   assertion reports `55000`, a job failed, or any same-name object differs,
   stop and design a separately reviewed forward repair on a copy. Do not drop,
   rename, or recreate a durable index merely to make the migration pass.
9. For v12–v14, address the reported cause and rerun the normal migrator only
   when both the failed version's table and history row are absent, as required
   by the transactional runner. Any one-sided state requires a separately
   reviewed catalog/history repair; first determine what client changed
   `autocommit_before_ddl` or ran the SQL outside the application migrator.
10. For v15, wait for every create/drop schema-change job to settle, then rerun
    only when the observed catalog is one of its three exact admitted states.
    The normal migration is the reviewed path through its intentional
    legacy-index drop. Do not manually drop, rename, recreate, or relabel
    conflict data to force a state through the gate. Any wrong-shape object or
    unrecognized combination requires a separately reviewed forward repair on
    a copy.
11. For v16 onward, wait for the online job to finish. If the exact
    object exists without its success row, rerun the normal migrator so
    `IF NOT EXISTS` and the catalog assertion record it. If the object is
    absent and no job remains, the same rerun rebuilds it. Stop on `55000`, job
    failure, or same-name drift; do not replace a durable index, table, or view
    merely to make history pass.
12. Reconcile SQLx bookkeeping only through these reviewed paths after the
    schema and completed jobs match the target. Keep serving and ceremony
    credentials disabled until every embedded migration has a successful row
    and the object/grant audit passes. The intentionally narrower private
    floors remain control 3, genesis 9, successor 14, and reconciliation 16;
    none grants another role's authority.

There is no automatic down migration. ECS image rollback and database schema
rollback are separate concerns: old binaries must remain compatible during a
roll-forward schema rollout.

## Future migration checklist

- Prefer additive, backward-compatible changes and explicit migration files.
- Verify CockroachDB support and syntax against a real target cluster.
- Run `EXPLAIN` for every changed critical query and preserve representative
  plan tests.
- Estimate index backfill storage and monitor schema-change jobs.
- Deploy compatible readers before writers when changing stored shapes.
- Keep transactions and backfill batches bounded; never embed or call remote
  services inside a SQL transaction.
- Back up important data and record the roll-forward recovery procedure before
  apply.
- Do not change an already-applied migration checksum.
