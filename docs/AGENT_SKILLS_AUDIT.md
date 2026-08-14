# CockroachDB Agent Skills implementation audit

Fleet Recall used CockroachDB's official Agent Skills as a development-time
engineering input, not merely as a submission label. The actor was the coding
agent used to implement and review this repository under entrant direction. Its
action was to invoke the pinned, machine-executable `SKILL.md` instructions,
apply their transaction and SQL review guidance to the implementation, and add
or check the code/tests traced below.

The application does not import or execute these skills. They are not an ECS,
AWS, CockroachDB Cloud, Fleet Recall runtime, or end-user dependency; the coding
agent did not use them to operate a cloud deployment. This audit proves
development-time use and inspectable effects only, not a completed hosted run.

## Provenance

- Repository: <https://github.com/cockroachlabs/cockroachdb-skills>
- Reviewed commit: [`e14e86d23ce8ee2e7e40a34ce2944c2502b6eadd`](https://github.com/cockroachlabs/cockroachdb-skills/tree/e14e86d23ce8ee2e7e40a34ce2944c2502b6eadd)
- Review date: 2026-08-13
- Skills applied:
  - [`designing-application-transactions`](https://github.com/cockroachlabs/cockroachdb-skills/blob/e14e86d23ce8ee2e7e40a34ce2944c2502b6eadd/skills/cockroachdb-application-development/designing-application-transactions/SKILL.md), including its monitoring and concurrency-testing reference.
  - [`cockroachdb-sql`](https://github.com/cockroachlabs/cockroachdb-skills/blob/e14e86d23ce8ee2e7e40a34ce2944c2502b6eadd/skills/cockroachdb-query-and-schema-design/cockroachdb-sql/SKILL.md), including fundamental, schema, DML, query, optimization, and operational rule references.

The audit covered `migrations/0001_fleet_memory.sql`, the corpus and ledger SQL,
transaction retry implementation, health/capability probes, live-database
tests, deployment pooling, and the migration runbook.

## Pinned invocation-to-evidence map

| Machine-executable skill invoked by the coding agent | Development action | Resulting code/test trace |
|---|---|---|
| `designing-application-transactions` at `e14e86d` | Reviewed transaction boundaries, moved embedding work outside the retryable unit, restricted retries to fresh `40001` transactions, and required idempotency/concurrency checks. | `src/ledger/cockroach.rs` record/replay path; `src/store/cockroach.rs` retry classifier; replay, retry, and concurrent at-most-one-commit tests |
| `cockroachdb-sql` at `e14e86d` | Reviewed DDL, scoped access paths, parameterized DML, vector/lexical query shapes, health capabilities, and representative `EXPLAIN` gates. | `migrations/0001_fleet_memory.sql`; SQL in `src/store/cockroach.rs` and `src/ledger/cockroach.rs`; schema, scope-isolation, health, and live plan tests |

The commit and direct skill permalinks above pin the exact instructions. The
repository paths and named tests below show what the coding agent changed or
validated after invoking them; they do not imply that an agent skill runs in
production or that AWS/CockroachDB Cloud evidence already exists.

## Guidance-to-implementation trace

| Official guidance applied | Fleet Recall implementation | Evidence / validation |
|---|---|---|
| Keep expensive work outside short transactions | Claim passage embedding completes before opening the claim transaction. Container model download and verification complete before the process starts. | `CockroachClaimLedger::record_claim`; `deploy/container-entrypoint.sh` |
| Retry an entire fresh transaction only for `40001`, with backoff | `with_serializable_retry` begins a new SQLx transaction on each attempt, explicitly selects `SERIALIZABLE`, and refuses to classify other SQLSTATEs as safely retryable. | Retry classifier/unit tests in `src/store/cockroach.rs`; concurrent live ledger test |
| Make client retries idempotent | Tenant-wide idempotency receipts reserve a key inside the transaction, bind it to the full trusted-scope request, and store the response. A pre-transaction lookup accelerates known replays without weakening the in-transaction check. | `memory_mutation_receipts`; replay and concurrent at-most-one-commit assertions in `src/ledger/cockroach.rs` |
| Push invariants into SQL | `NOT NULL`, `CHECK`, `UNIQUE`, composite foreign keys, typed state vocabularies, validity windows, fixed vector dimensions, and active-model foreign keys reject invalid states at the database boundary. | `migrations/0001_fleet_memory.sql`; schema constraint tests |
| Prefer atomic UPSERT/guarded DML over read-modify-write | Corpus/history writes use `INSERT ... ON CONFLICT DO UPDATE`; model initialization and receipt reservation use conflict-safe inserts; conflict state transitions are guarded. | SQL constants in `src/store/cockroach.rs`; ledger DML and replay tests |
| Parameterize SQL and project only needed columns | Runtime queries bind all caller data through SQLx parameters. Hydration and ledger reads name columns rather than using `SELECT *`. | Query constants and row decoders under `src/store` and `src/ledger` |
| Keep pools bounded across horizontally scaled instances | Default process pool is 16; the ECS module lowers the demo default to 8 per task and documents `max tasks × pool size` capacity planning. Acquire, idle, and lifetime limits are explicit. | `PoolConfig`; `FLEET_RECALL_MAX_CONNECTIONS`; Terraform variables |
| Keep transaction payloads bounded | MCP frames are capped at 1 MiB and results below 768 KiB; ingestion caps line, record, text, total, facet, and link sizes; claim passages and conflict hydration are capped. | Constants and negative tests in `src/main.rs`, `src/mcp/server.rs`, and `src/ledger` |
| Design explicit keys and access-path indexes | Every table has an explicit composite primary key. Tenant/project lead corpus and ledger access paths; event IDs are random UUIDs; project and source C-SPANN indexes mirror equality predicates. | Migration DDL and scope-isolation tests |
| Use `EXPLAIN` whenever validating connected CockroachDB SQL | Live acceptance tests seed a representative corpus and assert vector-search operators/indexes for project/source ANN paths and the lexical inverted path. Full-scan guards protect bounded hydration. | `live_cockroach_dense_plan_uses_vector_index_when_configured` and live store tests in `src/store/cockroach.rs` |
| Test under concurrency, not only single-user execution | The live ledger suite races identical idempotency keys and asserts at most one durable claim/event plus stable replay. Retry backoff and conflict transitions have deterministic unit coverage. | Live ledger test and retry unit tests |
| Treat online schema change as an operational workflow | CockroachDB 26.2 vector indexes cannot be created inside SQLx's migration transaction, so migration v1 is explicitly `-- no-transaction`, service count defaults to zero, and one dedicated ECS task runs the migration. | Migration header, separate Terraform task definition, `docs/MIGRATIONS.md` |

## CockroachDB-specific query review

The SQL skill's rule set led to these concrete checks:

- `VECTOR(512)` uses cosine operator classes consistently for both chunks and
  claim passages.
- ANN queries bind every equality prefix declared by the selected vector index:
  `(tenant_id, project)` or `(tenant_id, project, source)`.
- Stale and archive-parent rows live in a separate history table so eligibility
  logic does not become an approximate post-filter on the active vector index.
- Time filters use a bounded ANN candidate window followed by primary-key
  hydration; the service reports the bounded mode instead of implying an exact
  corpus scan.
- Lexical search uses a stored `TSVECTOR` and an inverted index, with scoped
  predicates and deterministic tie-breaking.
- Health rejects a schema without v1, both vector indexes, the lexical index,
  and working cosine distance support. It also rejects a different active model
  identity.

## Accepted deviations and follow-up work

The skills also exposed real trade-offs; this document intentionally does not
hide them.

1. **JavaScript-safe numeric claim IDs are sequential.** Recall's public claim
   contract currently uses numeric IDs, so Fleet Recall caps sequences at
   `2^53-1` instead of replacing them with UUIDs. Composite tenant/project
   prefixes distribute different fleets, but one very hot project may still
   concentrate writes. Before production scale, run Key Visualizer/contention
   tests and add hash-sharded lookup indexes or version the public ID contract.
2. **Trusted NDJSON ingestion upserts rows individually.** This keeps each
   write small and independently retryable for the demo, but leaves network
   efficiency on the table. A future backend API should batch bounded rows via
   `UNNEST`/set-based SQL without combining embedding work with transactions.
3. **The public demo has broad outbound network egress.** Terraform narrows
   inbound traffic and IAM resources, but a production VPC should use AWS
   service endpoints/prefix lists and private CockroachDB connectivity.
4. **Operational monitoring is scaffolded, not yet baselined in AWS.**
   CloudWatch application logs are enabled with 60-day retention. Terraform
   supports optional ECS Container Insights, but the cost-constrained live
   candidate leaves it disabled. Production promotion still requires
   retry-rate, p99 latency, long-transaction, contention, and hot-range alert
   thresholds measured under representative load.

## Reproduction gate

The implementation evidence is reproducible without relying on this prose:

```bash
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Connected CockroachDB tests are opt-in through
`FLEET_RECALL_TEST_DATABASE_URL`; they create the schema, exercise concurrent
ledger behavior, seed the plan-test corpus, and inspect actual CockroachDB
plans. AWS deployment and hosted URL remain separate release gates in
`docs/SUBMISSION.md`; this audit does not claim they have occurred.
