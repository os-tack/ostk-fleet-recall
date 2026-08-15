# CockroachDB migration policy

Fleet Recall currently has three embedded schema migrations. Migration 1
creates the distributed corpus, claim and conflict ledgers, audit tables,
vector indexes, and lexical inverted index; migration 2 adds the scoped support
lookup; migration 3 adds the private control-event ledger.

## Why migration v1 is non-transactional

CockroachDB 26.2 runs vector-index creation through its declarative schema
changer and rejects that operation inside an explicit multi-statement
transaction. The migration therefore begins with SQLx's `-- no-transaction`
directive.

That is an operational constraint, not permission to run migration casually:

- run one migrator only;
- keep every application service at zero during the initial migration;
- use a dedicated DDL credential;
- wait for success and inspect schema-change jobs before starting the service;
- never assume a failed v1 execution rolled itself back.

The Terraform deployment provides a separate
`ostk-fleet-recall-migration` task definition and defaults the application
service and autoscaling minimum to zero.

## Cloud bootstrap

1. Create a dedicated, empty CockroachDB database for Fleet Recall.
2. Create separate migrator, runtime, and control-bootstrap SQL principals.
   Store their TLS URLs as raw values in three distinct AWS Secrets Manager
   secrets; none may fall back to another principal's secret.
3. Apply `deploy/aws` with `service_desired_count = 0` and
   `autoscaling_min_capacity = 0`.
4. Confirm no other migration task is running in ECS.
5. Run `./deploy/aws/run-migration.sh` once.
6. Inspect the task's CloudWatch logs and confirm exit code zero.
7. Run the application's `health` command with the runtime credential. Health
   must report schema version 3, vector and lexical indexes, cosine support, and
   the exact configured model identity.
8. Set the desired/minimum service count to at least one and apply again.

The migration command also initializes the immutable project/model registry.
Use the same logical model name and bundle digest for migration, ingestion,
MCP, and demo tasks.

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
grants in [the private control bootstrap policy](CONTROL_BOOTSTRAP.md). Its
checked-in grant proof machine-compares the normalized `SHOW GRANTS` result;
runtime and `public` have no control-table privilege. Review all expanded grants
and revoke unnecessary defaults.
The runtime URL must use TLS verification. Keep credentials out of Terraform
state, image layers, ECS environment literals, logs, and demo responses.

## Failure and interruption recovery

If v1 fails, **do not immediately rerun it**. Because it is non-transactional,
some objects or asynchronous index jobs may exist even though SQLx did not mark
the version complete.

1. Leave the application service at zero.
2. Preserve the migration task logs and exact CockroachDB error.
3. Inspect `_sqlx_migrations`, `SHOW TABLES`, `SHOW INDEXES`, and relevant
   `SHOW JOBS` output using the migrator account.
4. Compare actual objects with `0001_fleet_memory.sql`.
5. If this is a brand-new empty demo database, the safest recovery is to create
   another empty database and run v1 once there. Deleting the partial database
   is a separate destructive operator decision.
6. If any durable data exists, do not drop objects or edit migration history.
   Write and review a forward repair migration that reconciles the observed
   state, then validate it on a copy first.

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
