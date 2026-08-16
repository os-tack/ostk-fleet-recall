# Hackathon delivery plan

Deadline: 2026-08-18 17:00 EDT / 16:00 CDT.

Judging availability hold: keep the submitted project free, unrestricted, and
operational through **2026-09-15 17:00 EDT / 16:00 CDT**. Do not tear down or
scale the judging deployment to zero before that time.

## Critical path

1. Cockroach schema, migrations, retry policy, and capability check.
2. Scoped chunk ingestion plus indexed dense and lexical retrieval.
3. Recall-compatible RRF, ranking attribution, and MCP `recall(search)`.
4. Transactional `remember(record)` with claim retrieval and conflict surface.
5. The standalone deterministic reference policy agent running as four
   sequential, separately bound one-off ECS/Fargate tasks over the same
   CockroachDB Cloud memory plane. Its verified memory/action/conflict JSON is
   the default AWS agent proof; it uses neither OSTK nor an LLM.
6. A route-level read-only public AWS ECS/Fargate demo, restart/failure
   demonstration, cloud query-plan evidence, public repository, README,
   architecture diagram, and sub-three-minute video. The historical live route
   does not attest the current checked-in PUBLIC-03 database grants.
7. Keep the verified submission stack and testing URL available through the end
   of judging; teardown happens only after the hold expires and explicit
   destructive approval is granted.

## Guardrails

- Submission work wins over non-blocking upstream elegance.
- Every query includes tenant and project equality constraints.
- Historical live runtime processes use a non-admin, writer-capable SQL
  identity; that does not establish the current publication-reader boundary.
  CockroachDB Cloud Managed MCP is not part of this submission unless
  separately integrated and evidenced; the qualifying second CockroachDB tool
  is Agent Skills.
- Current source fixes the public identity to `fleet_publication` through one
  `NOLOGIN` `fleet_publication_reader` role with only database `CONNECT`,
  public-schema `USAGE`, and `SELECT` on the exact eight public recall
  tables; it has no sequence, DML, or DDL authority. The exact-v26.2.3 TLS
  wrapper and Docker RBAC proof passed locally, and the accepted
  [LocalStack receipt](evidence/localstack-publication-cd6ecfc-20260816.json)
  passed at clean commit `cd6ecfca2c1a6d112ba058aad899a21aa34bb0f4`.
  None of those local results proves that this role matrix is deployed on AWS.
- The 21 current PUBLIC-03 Terraform tests passed locally, but the planned
  changes remain unapplied.
- The default agent proof is the deterministic Fleet Recall reference policy
  agent. OSTK is a strictly optional adapter, not an install, runtime, AWS, or
  video dependency. Do not claim autonomous LLM reasoning or a model run.
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
- Evidence review: label disposable CockroachDB and LocalStack results as local;
  reserve AWS, CockroachDB Cloud, public URL, and restart claims for artifacts
  captured from the real judging deployment. Preserve the accepted LocalStack
  receipt's explicit false claims for TLS, database-password authentication,
  IAM enforcement, Fargate, and AWS apply.
- Availability review: monitor the public URL and retain the ECS,
  CockroachDB Cloud, S3, Secrets Manager, DNS/TLS, logs, and supporting network
  resources through 2026-09-15 17:00 EDT. Keep 60-day CloudWatch retention and
  ALB deletion protection enabled; after judging, disable protection in a
  separately reviewed apply before planning teardown.
