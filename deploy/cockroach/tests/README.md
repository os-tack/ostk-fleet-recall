# Connected CockroachDB proof substrates

## Authoritative official process

Connected correctness is authoritative only when it runs against the official
CockroachDB `v26.2.3` binary. CI downloads the Linux AMD64 archive, verifies the
frozen SHA-256
`3eca6d7bc6fefa3ba0847e89733fc69f61226c80b8fab0af6578e1be672f27d3`,
and requires `cockroach version --build-tag` to equal `v26.2.3` exactly.
`registry-activation-cli.sh` repeats the build-tag check and owns one secure
local CockroachDB server process for the complete proof.

Every opt-in Rust test is first found by an exact line match in the applicable
`cargo test --locked ... -- --list` output. The wrapper then invokes only that
name with `--exact` and binds the required live URL on that same command. A
renamed, filtered, zero-test, or environment-skipped invocation therefore
cannot count as connected success.

| Connected surface | Exact test target | Required live URL |
| --- | --- | --- |
| Stage-2 control repository | `--test control_log_live` / `live_stage2_genesis_repository_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Genesis Stage-3 repository | `--test registry_activation_live` / `live_genesis_registry_activation_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Successor repository | `--test successor_activation_live` / `live_first_successor_activation_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Current-projection whole-unit retry | `--lib` / `ledger::cockroach::tests::live_current_projection_whole_unit_retry_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Current-projection snapshot race | `--lib` / `ledger::cockroach::tests::live_current_projection_snapshot_race_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Functional-polarity conflict matrix | `--lib` / `ledger::cockroach::tests::live_conflict_polarity_matrix_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Conflict-detector reconciliation | `--lib` / `ledger::reconciliation::tests::live_reconciliation_is_inert_without_its_exact_database_url` | `FLEET_RECONCILIATION_TEST_DATABASE_URL` |
| Online-index interruption recovery and drift rejection | `--lib` / `store::cockroach::tests::live_online_index_migrations_recover_and_reject_drift_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Transactional-DDL rollback | `--lib` / `store::cockroach::tests::live_transactional_migration_rolls_back_ddl_on_history_conflict_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |

The same isolated server also exercises the inspect/apply/replay state machines
of both currently wired private CLIs. It requires exactly 17 successful SQLx
rows with versions 1 through 17, the three successor authority tables, the two
genesis-root indexes, and the exact indexes introduced by migrations 15, 16,
and 17. The retired pre-v15 conflict uniqueness index must be absent. The proof
replays the resumable index-transition bytes, exercises online recovery, and
shows that failed migration 12 is not masked by successful migration 17.
Migrations 15 through 17 add or replace indexes rather than successor tables,
so the exact successor table set remains the three tables introduced by
migrations 12 through 14.

These current-release assertions do not widen the private compatibility gates:
Stage 2 still requires the complete successful prefix through 3, genesis Stage
3 through 9, and the successor repository through 14.

Run the authoritative proof with an already checksum-verified binary:

```bash
FLEET_RECALL_CRDB_BINARY=/absolute/path/to/cockroach \
  ./deploy/cockroach/tests/registry-activation-cli.sh
```

## Result accounting and Docker parity

The complete official matrix above shares one CockroachDB server process and
produces one authoritative official-binary result. Its individual test rows are
not separate server results, and neither the process nor its result may be
counted as Docker evidence.

| Reported result | Substrate and scope | Relationship to authority |
| --- | --- | --- |
| Official-binary correctness | One checksum-pinned, build-tag-pinned TLS `v26.2.3` server running the complete matrix and both private CLIs | The single authoritative connected result |
| Control RBAC parity | `control-role-grants.sh` in its own Docker container | Secondary packaging/RBAC result only |
| Activation RBAC parity | `registry-activation-role-grants.sh` in its own Docker container | Secondary packaging/RBAC result only |
| Control bootstrap CLI parity | `control-bootstrap-cli.sh` in its own Docker container | Secondary packaging/CLI result only |

Each Docker proof requires the running server's build tag to equal `v26.2.3`.
That confirms image-version parity, but Docker parity cannot substitute for the
checksum-pinned official-binary correctness proof. Report the authoritative
result and each Docker parity result separately; do not summarize one substrate
as evidence that another passed. Every script owns bounded temporary state and
cleans it on success, failure, or interruption.

Both RBAC proofs apply migrations 3 through 14 over explicit stand-ins for the
legacy v1/v2 objects, then synthesize the complete successful SQLx history 1
through 14. They retain the private commands' narrower semantic preflights
(bootstrap through 3, genesis activation through 9), inject successor-table
privilege and grant-option drift, then apply and reapply
`successor-schema-quarantine-grants.sql`. That dedicated policy first requires
all migration rows 1 through 14 to exist and be successful; only then does it
statically revoke every privilege on the three new authority tables from
`public`, runtime, bootstrap, and genesis activation. It is separate because
CockroachDB v26.2 cannot conditionally execute privilege DDL inside PL/pgSQL,
while the two base role policies must remain applicable at their original v3/v9
deployment stages. These Docker policy-compatibility proofs do not claim the
current exact prefix through 17.
