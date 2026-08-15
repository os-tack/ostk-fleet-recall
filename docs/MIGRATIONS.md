# CockroachDB migration policy

Fleet Recall currently has nine embedded schema migrations. Migration 1
creates the distributed corpus, claim and conflict ledgers, audit tables,
vector indexes, and lexical inverted index; migration 2 adds the scoped support
lookup; migration 3 adds the private control-event ledger; migration 4 adds the
immutable genesis-registry activation ledger and singleton active head;
migration 5 adds the scoped unique control-event predecessor index; and
migrations 6 through 9 remove the implicit clock defaults from the bootstrap,
epoch, shard-head, and event projections, respectively.

## Why all nine migrations execute without a SQL transaction

CockroachDB 26.2 runs vector-index creation through its declarative schema
changer and rejects that operation inside an explicit multi-statement
transaction. The embedded migrator registers every version with `no_tx = true`;
migration files 1 and 3 through 9 also carry the explicit
`-- no-transaction` marker. Migration 2 is a single index creation but is
registered with the same CockroachDB execution policy. Migration 4 starts three
online secondary-index backfills before it creates the genesis activation
projections. Migration 5 is one unique-index backfill, and each of migrations 6
through 9 is exactly one `DROP DEFAULT` column schema change. A failure can
therefore leave a committed object or completed schema-change job without a
successful SQLx row.

That is an operational constraint, not permission to run migration casually:

- run one migrator only;
- keep every application service at zero during the initial migration;
- use a dedicated DDL credential;
- wait for success and inspect schema-change jobs before starting the service;
- never assume any failed migration rolled itself back, and follow the
  version-specific recovery rules below instead of editing SQLx history.

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
7. Run the application's `health` command with the runtime credential. Serving
   intentionally accepts an uninterrupted successful migration prefix of at
   least version 2, including the vector/lexical indexes, cosine support, and
   exact configured model identity. Health is not an exact-version-9 release
   gate and remains compatible with additive later migrations.
8. Separately, with the migrator/security-operator procedure, verify exactly
   nine successful rows for the uninterrupted prefix 1 through 9 and inspect
   all schema-change jobs. The Stage-2 bootstrap command deliberately accepts
   the complete successful prefix 1 through 3; the Stage-3 activation
   repository requires the complete successful prefix 1 through 9. A later
   successful row must not mask a missing or failed prerequisite.
9. Set the desired/minimum service count to at least one and apply again.

The migration command also initializes the immutable project/model registry.
Use the same logical model name and bundle digest for migration, ingestion,
MCP, and demo tasks.

Neither the Stage-2 control-bootstrap command/secret nor the Stage-3 activation
command/secret is wired into the current AWS Terraform or CloudFront serving
path. They remain separate local/private operator gates.

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

Then apply and verify the exact control-plane exclusions and one-shot bootstrap
grants in [the private control bootstrap policy](CONTROL_BOOTSTRAP.md). The
policy can first run after migration 3, but the current post-v9 deployment must
reapply it after all migrations have created their objects. Its
checked-in grant proof machine-compares the normalized `SHOW GRANTS` result;
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

After the complete successful migration prefix 1 through 9 and the reapplied
Stage-2 control-role policy, apply
[`registry-activation-role-grants.sql`](../deploy/cockroach/registry-activation-role-grants.sql)
as the cluster-admin/delegated security operator described above, not merely as
the database owner. The private activation login must be a member only of the
`fleet_registry_activation` logical role; disable it or remove its secret when
activation is not in progress. Its complete DML surface is:

| Object | Privileges |
| --- | --- |
| `_sqlx_migrations` | `SELECT` for the complete successful-prefix-1-through-9 preflight |
| `memory_control_bootstraps` | `SELECT` |
| `memory_control_log_epochs` | `SELECT` |
| `memory_control_shard_heads` | `SELECT`, `UPDATE` |
| `memory_control_events` | `SELECT`, `INSERT` |
| `memory_registry_activations` | `SELECT`, `INSERT` |
| `memory_registry_heads` | `SELECT`, `INSERT` |

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

Migration 4 and the checked-in activation role install only the first genesis
head. The role has no `UPDATE` on `memory_registry_heads`, and the genesis
contract/schema defines no successor. Rotation or supersession requires an
additive migration, a separately versioned successor contract/repository, and a
new reviewed RBAC surface; never overwrite the genesis row or broaden this
credential to simulate that future stage.

Run the pinned disposable-cluster proof before deployment:

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
preflight, and proves failed versions 4, 5, and 9 cannot be masked by the other
successful rows. It exercises each allowed operation with valid
foreign-key-bound rows and requires authorization failures for every forbidden
table, sequence, DDL, and delegation path. The proof uses CockroachDB 26.2.3 by
default and removes its isolated container afterward.

## Failure and interruption recovery

Every version executes without a wrapping SQL transaction. Do not assume an
error rolled back its DDL, and do not synthesize a successful SQLx row merely
to bypass a gate. Recovery depends on the exact failed version:

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
   one exact column default owned by v6, v7, v8, or v9.
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
8. Reconcile SQLx bookkeeping only through the reviewed recovery procedure
   after the resulting schema and completed jobs match the target. Keep private
   bootstrap/activation credentials disabled until the current database has
   exactly nine successful prefix rows and the object audit passes. The
   Stage-2 binary's prefix-1-through-3 compatibility gate is not a current
   release-completion gate.

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
