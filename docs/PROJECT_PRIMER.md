# Fleet Recall project primer

For setup and operating tasks, start with the [documentation index](README.md).
The current qualified service runs locally on Lima/k0s; AWS publication-demo
infrastructure and the planned AWS remote stack are distinct
[deployment profiles](reference/DEPLOYMENT_PROFILES.md).

## Why Fleet Recall exists

An inference call is temporary, but the decisions made around it can govern work for days or weeks. Fleet Recall gives replaceable agents a shared memory plane where evidence, decisions, corrections, and disagreements survive the process that produced them. It exists so a new worker can recover not only what was decided, but who asserted it, what source supported it, and whether another agent still disagrees.

## What survives replacement

Corpus chunks, typed claims, support records, idempotency receipts, conflicts,
and action history live in CockroachDB rather than an agent process. The local
installation preserves SQL and acknowledged transcript files on the Lima disk
across pod and VM restarts. The AWS publication design uses CockroachDB Cloud
with replaceable ECS/Fargate tasks. Losing a VM disk or Mac still needs backup
recovery; neither process replacement nor durable SQL protects unshipped sandbox
transcript bytes.

## Why CockroachDB is the memory plane

Fleet Recall needs shared SQL transactions for concurrent writers, durable provenance and conflict ledgers, and semantic retrieval over the same scoped records. CockroachDB supplies serializable transactions, distributed `VECTOR(512)` C-SPANN indexes, a stored `TSVECTOR` lexical index, and ordinary relational constraints in one system. That lets horizontally scaled agents share memory without turning conflict detection or idempotency into client-side conventions.

## Which libraries write to the datastore

The Rust libraries used to write to the CockroachDB datastore are SQLx 0.8 with its PostgreSQL driver, the Tokio async runtime, and Rustls TLS support. `PgPool` manages bounded connections; all runtime values are bound as SQL parameters. Mutations run in fresh serializable transactions and retry only CockroachDB serialization failures with SQLSTATE `40001`. Embedded SQLx migrations are executed by a separate one-off migrator task before serving begins. The public pool is constructed separately and witnesses its fixed login, database, application name, and canonical search path on both connection creation and reuse.

## How recall finds an answer

The pinned model2vec embedder produces 512-dimensional vectors. CockroachDB runs both dense cosine search through project- and source-prefixed C-SPANN indexes and lexical search through an inverted `TSVECTOR` index. Fleet Recall combines the two ranked lanes with reciprocal-rank fusion, keeps tenant and project scope in every SQL query, and returns source coordinates rather than presenting the fused rank as a confidence score.

## How a source carries a conflict

A typed claim can cite an exact corpus chunk using its source coordinate and content SHA-256. When that source appears in recall, Fleet Recall follows only the current hash-matching support edge to the claim and then to any open same-key conflict. If the source later changes, the stale hash no longer projects the old conflict. The public demo renders a disagreement only when the response identifies the exact retrieved claim or source evidence that triggered it.

## What runs on AWS

CloudFront provides the public HTTPS viewer endpoint and forwards uncached read-only requests to a restricted Application Load Balancer. Private-subnet ECS/Fargate tasks run the Rust service, pull the immutable image from ECR, load the pinned embedding model from a private S3 prefix, and send bounded operational logs to CloudWatch. The current checked-in Terraform gives the public task a distinct publication secret, execution role, task role, and customer-managed KMS key scope; writer and migrator credentials remain on private task paths. That plan is validated but not yet applied. CockroachDB Cloud remains the durable data plane when any individual AWS task stops.

## What the public demo can and cannot do

The public surface exposes health, capability status, and bounded recall only. It accepts only `FLEET_RECALL_PUBLICATION_DATABASE_URL` and rejects private writer/control/test database variables. That URL must authenticate the fixed `fleet_publication` login to `fleet_recall`; the login inherits the `NOLOGIN` logical role `fleet_publication_reader`. Its complete grant is database `CONNECT`, public-schema `USAGE`, and `SELECT` on exactly `_sqlx_migrations`, `memory_corpus_models`, `memory_chunks`, `memory_claim_embeddings`, `memory_claim_support`, `memory_claims`, `memory_conflict_members`, and `memory_conflicts`, with no sequence, DML, DDL, system, delegation, or private-table authority. Tenant, project, agent identity, and privacy tier come from trusted deployment configuration rather than request JSON. Writes and the canonical `remember` tool remain behind deployment-bound MCP processes, so a visitor can inspect real fleet memory without acquiring mutation authority.
