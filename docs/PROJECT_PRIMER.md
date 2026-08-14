# Fleet Recall project primer

## Why Fleet Recall exists

An inference call is temporary, but the decisions made around it can govern work for days or weeks. Fleet Recall gives replaceable agents a shared memory plane where evidence, decisions, corrections, and disagreements survive the process that produced them. It exists so a new worker can recover not only what was decided, but who asserted it, what source supported it, and whether another agent still disagrees.

## What survives replacement

The ECS/Fargate application tasks are deliberately stateless. Corpus chunks, typed claims, support records, idempotency receipts, conflicts, and action history live in CockroachDB Cloud, so a complete serving-task replacement does not erase memory. The release verifier replaces the whole running task set and then recalls the exact same action and escalation claim IDs through lexical and vector retrieval.

## Why CockroachDB is the memory plane

Fleet Recall needs shared SQL transactions for concurrent writers, durable provenance and conflict ledgers, and semantic retrieval over the same scoped records. CockroachDB supplies serializable transactions, distributed `VECTOR(512)` C-SPANN indexes, a stored `TSVECTOR` lexical index, and ordinary relational constraints in one system. That lets horizontally scaled agents share memory without turning conflict detection or idempotency into client-side conventions.

## Which libraries write to the datastore

The Rust libraries used to write to the CockroachDB datastore are SQLx 0.8 with its PostgreSQL driver, the Tokio async runtime, and Rustls TLS support. `PgPool` manages bounded connections; all runtime values are bound as SQL parameters. Mutations run in fresh serializable transactions and retry only CockroachDB serialization failures with SQLSTATE `40001`. Embedded SQLx migrations are executed by a separate one-off migrator task before serving begins.

## How recall finds an answer

The pinned model2vec embedder produces 512-dimensional vectors. CockroachDB runs both dense cosine search through project- and source-prefixed C-SPANN indexes and lexical search through an inverted `TSVECTOR` index. Fleet Recall combines the two ranked lanes with reciprocal-rank fusion, keeps tenant and project scope in every SQL query, and returns source coordinates rather than presenting the fused rank as a confidence score.

## How a source carries a conflict

A typed claim can cite an exact corpus chunk using its source coordinate and content SHA-256. When that source appears in recall, Fleet Recall follows only the current hash-matching support edge to the claim and then to any open same-key conflict. If the source later changes, the stale hash no longer projects the old conflict. The public demo renders a disagreement only when the response identifies the exact retrieved claim or source evidence that triggered it.

## What runs on AWS

CloudFront provides the public HTTPS viewer endpoint and forwards uncached read-only requests to a restricted Application Load Balancer. Private-subnet ECS/Fargate tasks run the Rust service, pull the immutable image from ECR, load the pinned embedding model from a private S3 prefix, read database URLs from Secrets Manager, and send bounded operational evidence to CloudWatch Logs. CockroachDB Cloud remains the durable data plane when any individual AWS task stops.

## What the public demo can and cannot do

The public surface exposes health, capability status, and bounded recall only. Tenant, project, agent identity, and privacy tier come from trusted deployment configuration rather than request JSON. Writes and the canonical `remember` tool remain behind deployment-bound MCP processes, so a visitor can inspect real fleet memory without acquiring mutation authority.
