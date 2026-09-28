# Development workflow

[Documentation](README.md) · [Local development tutorial](tutorials/LOCAL_DEVELOPMENT.md)

Run these commands from the repository root. The tutorial supplies a disposable
development database and pinned model; deployed local HTTPS state is separate
and must not be used for destructive live tests. See
[`CLAUDE.md`](../CLAUDE.md) for repository conventions.

CI runs these checks (Rust 1.94):

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo deny check
python3 deploy/local/sandbox/test_sandbox.py
node --test demo/tests/source-card-order.test.mjs
```

Database tests are named `live_*` and skip unless
`FLEET_RECALL_TEST_DATABASE_URL` points at a disposable CockroachDB 26.2
database. Each test migrates the schema it needs, some create roles, and the
plan test writes more than 10,000 fixture rows, so use a throwaway database and
a user with admin rights, never shared or valuable data. The conflict
reconciliation tests read `FLEET_RECONCILIATION_TEST_DATABASE_URL` instead. Run
the live tests serially:

```bash
export FLEET_RECALL_TEST_DATABASE_URL='postgresql://USER:PASSWORD@HOST:26257/DATABASE?sslmode=verify-full'
export FLEET_RECONCILIATION_TEST_DATABASE_URL="$FLEET_RECALL_TEST_DATABASE_URL"
cargo test --locked --all-targets -- live_ --test-threads=1
```

CI runs the same command against a single-node CockroachDB v26.2.3 container;
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) shows the exact setup.
`store::cockroach::tests::live_cockroach_dense_plan_uses_vector_index_when_configured`
asserts that representative dense, source-prefixed dense, and lexical queries
select their intended CockroachDB indexes. Two suites need more than the
database URL: `tests/dogfood_live.rs` also skips unless its
`FLEET_RECALL_DOGFOOD_*` inputs are set, and `tests/publication_reader_live.rs`
is `#[ignore]` and documents its environment at the top of the file.

## Deployment and documentation checks

The [CI workflow](../.github/workflows/ci.yml) also validates observability
configuration and alerts, the production container and AWS publication-demo
Terraform. Local HTTPS lifecycle, recovery and network checks have separate
Python suites and live qualification scripts documented in the
[qualification record](../deploy/local/https/LIFECYCLE_QUALIFICATION.md#automated-checks-and-scope).
A passing unit suite is not evidence that a deployment fault exercise or a
restore ran.

When changing behavior, update its task guide and reference together. Keep the
root README as a short entry point. Put runnable learning sequences in
`docs/tutorials/`, operator procedures in `docs/guides/` or the relevant
`deploy/` runbook, field/command contracts in `docs/reference/`, and rationale
in an ADR. Validate relative links after moving material; examples that rely
on an earlier shell environment must say so.

The binary's `tutorials_run_each_command_as_an_enabled_login_of_its_identity`
test reads all three tutorial files and checks their SQL identity/role sequence.
Run it after changing those commands:

```bash
cargo test --locked --bin ostk-fleet-recall tutorials_run_each_command_as_an_enabled_login_of_its_identity
```
