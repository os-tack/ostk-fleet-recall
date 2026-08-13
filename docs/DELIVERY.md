# Hackathon delivery plan

Deadline: 2026-08-18 17:00 EDT / 16:00 CDT.

## Critical path

1. Cockroach schema, migrations, retry policy, and capability check.
2. Scoped chunk ingestion plus indexed dense and lexical retrieval.
3. Recall-compatible RRF, ranking attribution, and MCP `recall(search)`.
4. Transactional `remember(record)` with claim retrieval and conflict surface.
5. Reproducible, separately bound agent processes exercising shared MCP memory;
   a read-only AWS ECS/Fargate demo over the same CockroachDB cluster.
6. Restart/failure demonstration, cloud query-plan evidence, public repository, README,
   architecture diagram, and sub-three-minute video.

## Guardrails

- Submission work wins over non-blocking upstream elegance.
- Every query includes tenant and project equality constraints.
- Runtime processes use a least-privilege SQL identity. CockroachDB Cloud
  Managed MCP is not part of this submission unless separately integrated and
  evidenced; the qualifying second CockroachDB tool is Agent Skills.
- Mutation retries are idempotent and bounded.
- Ranking and transaction behavior receive backend-conformance tests.
- Full-corpus migration is not required for the demo; use a representative,
  reproducible subset and publish the selection method.

## Review gates

- Schema review: index usability, key distribution, isolation, migrations.
- Retrieval review: rank parity and `EXPLAIN` evidence.
- Ledger review: atomicity, idempotency, conflict lifecycle, retry safety.
- Security review: tenant escape tests, secret handling, least privilege.
- Submission review: requirements matrix and reproducible demo runbook.
