# CockroachDB migration policy

Fleet Recall currently has seventeen embedded schema migrations. Migration 1
creates the distributed corpus, claim and conflict ledgers, audit tables,
vector indexes, and lexical inverted index; migration 2 adds the scoped support
lookup; migration 3 adds the private control-event ledger; migration 4 adds the
immutable genesis-registry activation ledger and singleton active head;
migration 5 adds the scoped unique control-event predecessor index; and
migrations 6 through 9 remove the implicit clock defaults from the bootstrap,
epoch, shard-head, and event projections, respectively. Migrations 10 and 11
add the exact immutable genesis-head and genesis-activation root indexes needed
by successor foreign keys. Migrations 12 through 14 add, respectively, the
append-only registry transition history, one-shot genesis-bridge consumption,
and successor current-head projection. Migration 15 replaces conflict
uniqueness by `(tenant, project, claim key)` with detector-versioned uniqueness;
migration 16 adds the covering claim-transition provenance index required by
legacy reconciliation; and migration 17 adds the covering current-conflict
detector/state projection index required by normal serving.

## Transaction policy: versions 1–11, 12–14, and 15–17

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
returns to the shared runtime pool. Official CockroachDB v26.2.3 tests force the
history insert to fail after DDL and require both the new table and history row
to be absent.

Versions 15 through 17 form a third phase with
`autocommit_before_ddl = true` and `no_tx = true`. Migration 15 accepts only the
exact old-only, old-plus-new, or new-only detector-index transition states. It
creates and commits the new detector-versioned unique index, verifies both
catalog shapes, drops the legacy constraint-backed index with `CASCADE`,
commits, and verifies the exact final state; it rewrites no conflict rows.
Migrations 16 and 17 each use `CREATE INDEX IF NOT EXISTS`, commit the online
backfill, and assert the complete public catalog definition including stored
columns. Same-name drift fails with SQLSTATE `55000` before SQLx can record
success.

Those are database correctness guarantees. The recorded LocalStack
Docker/Compose application-image smoke predates migrations 10 through 17 and
must be rerun before claiming current container parity.

That is an operational constraint, not permission to run migration casually:

- run one migrator only;
- keep every application service at zero during the initial migration;
- use a dedicated DDL credential;
- wait for success and inspect schema-change jobs before starting the service;
- for versions 1 through 11, never assume an error rolled back DDL;
- for versions 12 through 14, treat non-atomic state as evidence of an
  unreviewed runner/session or catalog drift;
- for versions 15 through 17, wait for online jobs and use only the reviewed
  resumable catalog transitions; and
- follow the version-specific recovery rules below instead of editing SQLx
  history.

The Terraform deployment provides a separate
`ostk-fleet-recall-migration` task definition and defaults the application
service and autoscaling minimum to zero.

## Cloud bootstrap

1. Create a dedicated, empty CockroachDB database for Fleet Recall.
2. Create separate migrator and runtime SQL principals. Store their TLS URLs as
   raw values in the two distinct AWS Secrets Manager secrets accepted by the
   current Terraform; neither may fall back to the other principal's secret.
3. Apply `deploy/aws` with `service_desired_count = 0` and
   `autoscaling_min_capacity = 0`.
4. Confirm no other migration task is running in ECS.
5. Run `./deploy/aws/run-migration.sh` once.
6. Inspect the task's CloudWatch logs and confirm exit code zero.
7. Run the application's `health` command with the runtime credential. Current
   recall, remember, ingest, health, and public-demo paths require an
   uninterrupted successful prefix of at least 17, including the exact current
   indexes, cosine support, and configured model identity. Later additive rows
   remain compatible, but cannot mask a missing or failed row in 1–17.
8. Separately, with the migrator/security-operator procedure, verify the exact
   seventeen successful rows for prefix 1 through 17 and inspect all
   schema-change jobs. The private compatibility gates remain intentionally
   distinct: Stage-2 control requires prefix 1 through 3, genesis Stage-3
   requires 1 through 9, the first-successor repository requires 1 through 14,
   and conflict-detector reconciliation requires 1 through 16. None is a
   substitute for the current release gate or serving floor.
9. Set the desired/minimum service count to at least one and apply again.

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
plus grant authority on the database, schema, tables, and sequences. The
disposable proofs create a database-owner-only user and require those hardening
statements to be denied.

The migration principal needs database/schema creation privileges for tables,
sequences, secondary indexes, and SQLx's migration bookkeeping table. The
runtime principal needs:

- `CONNECT` on the Fleet Recall database;
- `USAGE` on its schema and sequences;
- only the documented DML privileges on legacy corpus, claim, and projection
  tables;
- read access to SQLx migration metadata for health checks;
- no `CREATE`, `DROP`, role-management, cluster-setting, or external-connection
  privileges.

Never grant runtime privileges with `ON ALL TABLES IN SCHEMA public`: migration
3 deliberately puts control tables in that schema, and future private tables
must not become reachable through defaults. For example, after connecting as
an authorized administrator and substituting the actual database/role names,
grant the bounded legacy table set explicitly:

```sql
GRANT CONNECT ON DATABASE fleet_recall TO fleet_runtime;
GRANT USAGE ON SCHEMA public TO fleet_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
    memory_corpus_models,
    memory_chunks,
    memory_chunk_history,
    memory_claims,
    memory_claim_support,
    memory_claim_embeddings,
    memory_claim_events,
    memory_conflicts,
    memory_conflict_members,
    memory_claim_links,
    memory_claim_link_events,
    memory_mutation_receipts,
    memory_events,
    memory_attention
TO fleet_runtime;
GRANT SELECT ON TABLE _sqlx_migrations TO fleet_runtime;
GRANT USAGE, SELECT ON SEQUENCE
    memory_claim_id_seq,
    memory_claim_support_id_seq,
    memory_conflict_id_seq,
    memory_claim_link_id_seq
TO fleet_runtime;
```

Do not add the three successor tables from migrations 12 through 14 to this
runtime grant. They remain unavailable to runtime and the earlier application
roles. The existence of their schema, canonical contracts, and one-shot
successor role does not create runtime or cloud successor authority.

Then apply and verify the exact control-plane exclusions and one-shot bootstrap
grants in [the private control bootstrap policy](CONTROL_BOOTSTRAP.md). The
base policy can first run after migration 3 and remains valid at that stage. At
the current post-v17 release, create/harden both frozen private logical roles by
applying or reapplying the control and genesis-activation policies, then apply
[quarantine policy](../deploy/cockroach/successor-schema-quarantine-grants.sql).
That deny-only policy retains its own complete-successful-prefix-1-through-14
gate, then revokes every privilege and grant option on the three successor
tables from `public`, runtime, bootstrap, and genesis activation; it grants
nothing. Migrations 15 through 17 add or replace indexes, not successor tables,
so they do not change that quarantine's object set.
The base policy's checked-in grant proof machine-compares the normalized
`SHOW GRANTS` result;
runtime and `public` have no control-table privilege. The logical runtime and
bootstrap bundles are forced to `NOLOGIN`, `NOCREATEROLE`, and `NOCREATEDB`;
the policy removes their direct SYSTEM grants, inherited admin, and both
runtime/bootstrap membership directions. It also re-revokes `public` grants on
all current tables and sequences and resets the bootstrap role's complete
current-object surface before adding back its exact ledger grants.

These scripts reset current objects; they do not establish a universal
future-object rule for an unknown schema creator. Run `SHOW DEFAULT PRIVILEGES`
as the actual migrator and require no table/sequence default that grants
`public` or an application logical role. The pinned proofs freeze that exact
empty result for their schema creator. Re-audit defaults and reapply both
current-object policies after every migration. Review all expanded grants and
revoke unnecessary defaults.

The runtime URL must use TLS verification. Keep credentials out of Terraform
state, image layers, ECS environment literals, logs, and demo responses.

### Stage-3 pre-activation gate

The current `deploy/aws` Terraform does not accept a registry-activation secret
or define a registry-activation task. The following is therefore a local/private
pre-activation gate, not an executable step in the cloud-bootstrap sequence
above. Before enabling a cloud activation path, provision a fourth, distinct
registry-activation SQL principal and TLS secret out of band, or add separately
reviewed Terraform/task wiring that preserves the same isolation.

After the current release has the complete successful migration prefix 1
through 17 and the reapplied Stage-2 control-role policy, apply
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
The grant proof freezes that repository's only shard-head `UPDATE`: it sets
exactly those three columns and scopes the compare-and-swap by tenant, project,
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
rows are compatible. The reconciliation role is optional, not a fourth
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

Run the dedicated secondary Docker RBAC proof before a ceremony:

```bash
./deploy/cockroach/tests/successor-activation-role-grants.sh
```

It freezes the exact policy/grant matrix, fail-closed preconditions, allowed and
denied SQL operations, drift repair, external-audit shape, and reapplication on
CockroachDB v26.2.3. It is packaging/RBAC parity, not the authoritative
connected correctness result and not AWS evidence.

Separately, run the pinned genesis-activation Docker RBAC proof before
deployment:

```bash
./deploy/cockroach/tests/registry-activation-role-grants.sh
```

It machine-compares normalized database, schema, migration, control, registry,
system, role-option, and bidirectional role-membership results after injecting
and repairing direct, inherited, and `public` database/schema/table/sequence
drift. It also proves a database owner cannot perform the cluster-security
hardening and freezes an empty relevant `SHOW DEFAULT PRIVILEGES` result for
the schema creator. It freezes the repository's sole exact shard-head CAS and
event kind, pins and exercises the complete successful-prefix-1-through-9
genesis preflight, and proves failed versions 4, 5, and 9 cannot be masked by
the other successful rows. It exercises each allowed operation with valid
foreign-key-bound rows and requires authorization failures for every forbidden
table, sequence, DDL, and delegation path. The proof uses CockroachDB 26.2.3 by
default and removes its isolated container afterward. This Docker RBAC lane
owns the complete allow/deny/grant-option drift matrix, including successor
quarantine. The authoritative official-binary correctness lane separately
applies the complete migration chain through 17 and exercises the successor
repository plus the successor workstation CLI's offline binding, readiness,
inserted, accepted, exact-replay, and stale matrix under two bounded membership
windows. It does not replace the separate Docker RBAC matrix or prove image,
AWS, or deployment authority.

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
insufficient. The successor role is optional and is not a fourth reconciliation
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
runtime credential, MCP method, or HTTP route. Run the dedicated secondary
Docker RBAC proof before use:

```bash
./deploy/cockroach/tests/conflict-reconciliation-role-grants.sh
```

That proof also exercises the optional-successor creator-default cleanup and
exact role-edge preflights. It must not be cited as proof that the two policies
self-compose: the cluster admin still performs the conditional cleanup and
cross-database/PUBLIC audit before the policy and exclusive member window.

## Failure and interruption recovery

Versions 1 through 11 execute without a wrapping SQL transaction. Versions 12
through 14 execute transactionally only through the reviewed application
migrator and its dedicated CockroachDB session. Versions 15 through 17 return
to nontransactional, resumable online schema changes. Never synthesize, update,
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
- v6 through v9 each contain exactly one `DROP DEFAULT`. The pinned
  CockroachDB 26.2.3 proof verifies each statement is idempotent when its DDL
  committed but SQLx success-row insertion was interrupted. Resume only after
  catalog inspection confirms the expected column and no unrelated drift.
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
   the complete covering index definition and job state.
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
11. For v16 or v17, wait for the online job to finish. If the exact index exists
    without its success row, rerun the normal migrator so `IF NOT EXISTS` and
    the catalog assertion record it. If the index is absent and no job remains,
    the same rerun rebuilds it. Stop on `55000`, job failure, or same-name
    drift; do not replace a durable index merely to make history pass.
12. Reconcile SQLx bookkeeping only through these reviewed paths after the
    schema and completed jobs match the target. For the current release, keep
    serving and ceremony credentials disabled until the database has exactly
    the seventeen successful rows 1 through 17 and the object/grant audit
    passes. Serving remains compatible with a later additive uninterrupted
    prefix. The intentionally narrower private floors remain control 3,
    genesis 9, successor 14, and reconciliation 16; none substitutes for the
    current release-completion gate or grants another role's authority.

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
