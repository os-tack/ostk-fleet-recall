# Submission requirements matrix

This matrix is the release gate for the CockroachDB AI Agents Hackathon. The
official rules require an agentic application that uses CockroachDB as its
persistent memory layer, is deployed on AWS, uses at least two listed
CockroachDB tools and one AWS service, and remains available free of charge and
without restriction through the end of judging. Repository and local evidence
do not by themselves prove deployment; the live results below combine the
revision-10 deployment observations with an explicitly historical revision-7
public-relevance receipt and historical revision-6 AWS/CockroachDB Cloud
receipts. The revision-10 public observations prove only a read-only HTTP route
surface; they do not attest which database principal or grants the task used.
The current PUBLIC-03 reader boundary is checked-in source with accepted local
official-binary, Docker, and LocalStack evidence, not a deployed-AWS claim.

| Requirement | Fleet Recall evidence | Status |
|---|---|---|
| New project created during the contest | This repository; Recall and OSTK are disclosed as pre-existing foundations | Public initial history published and boundary documented |
| Agentic application | The standalone deterministic reference policy agent recalls fleet state, applies an explicit rollout-safety policy, and persists cited actions; separately deployment-bound A/B/C identities exercise the full memory/action/conflict chain | Historical revision-6 run `devpost-final6-20260814T143523Z` proved decision/action/incompatible/escalation claims 15/16/17/18 and open conflict 5 across four one-off Fargate tasks; the separate revision-6 self-audit proved source-backed claims 9/10 and open conflict 3. These agent proofs were not rerun for revision 10. OSTK is strictly optional, and no LLM decision or live model run is claimed |
| CockroachDB persistent memory layer | Corpus, claim ledger, source support, conflicts, receipts, actions, and events in CockroachDB | The live revision-10 idempotent rich-seed task exited zero and upserted exactly 552 rows: 346 documentation, 2 code, and 204 operations chunks. The public API returned repository-backed hits with the exact release revision and source-line ranges, and the final seven-query smoke gate passed. The public status surface reports CockroachDB Cloud 26.2.5 with schema version 2 and the required capabilities; the checked-in seven-query receipt remains historical revision-7 evidence |
| PUBLIC-03 publication boundary | Current source fixes `fleet_publication` to one `NOLOGIN` `fleet_publication_reader` role with database `CONNECT`, public-schema `USAGE`, and `SELECT` on exactly `_sqlx_migrations`, `memory_corpus_models`, `memory_chunks`, `memory_claim_embeddings`, `memory_claim_support`, `memory_claims`, `memory_conflict_members`, and `memory_conflicts`; no sequence, DML, or DDL authority | The exact official-v26.2.3 TLS local wrapper and separate Docker RBAC proof passed. The accepted [clean-commit LocalStack receipt](evidence/localstack-publication-cd6ecfc-20260816.json) passed prefix 1–17, production-image status/recall, writer denial, replacement persistence, and zero residue. It explicitly proves no TLS, database-password authentication, IAM enforcement, Fargate, or AWS apply. The 21 Terraform tests passed locally, but those changes remain unapplied |
| Distributed Vector Indexing | Prefix-scoped `VECTOR(512)` indexes for chunks and claim passages | Live status confirms the vector, lexical, conflict-membership, and claim-support-chunk indexes plus cosine distance and dimension 512; lexical/dense RRF returned the expected claims and projected an exact source-backed conflict. The [publication-safe Cloud `EXPLAIN`](evidence/cockroach-cloud-explain.txt) verifies both C-SPANN indexes and the lexical inverted index with the exact production SQL shapes on 10,001 disposable rows; all assertions passed |
| Second CockroachDB tool | The coding agent invoked the pinned official Agent Skills to review and shape transactions, SQL, tests, and runbooks; see `AGENT_SKILLS_AUDIT.md` | Implemented and audited with a skill-to-code/test trace |
| AWS service | ECS/Fargate behind ALB and CloudFront, private S3 model delivery, immutable ECR image, Secrets Manager database URLs, CloudWatch evidence, plus the LocalStack contract harness | Serving, migration, seed, and reference-agent task-definition families are revision 10; the service is 1/1 healthy, the 552-row rich seed succeeded, and final desktop/390px mobile QA verified safe Markdown, immutable line links, a code-styled relative repository anchor, and no overflow. The self-audit, four-task reference run, and full serving-task replacement remain historical revision-6 proofs and were not rerun for revision 10. Current PUBLIC-03 Terraform changes are tested but unapplied |
| Public open-source repository | Public GitHub repository with explicit pre-existing-code disclosure | Published and anonymously verified |
| Working demo URL | Public route-level read-only status/demo surface at <https://d13zrqfh66r7ub.cloudfront.net> | Live and browser-verified through CloudFront at desktop and 390px mobile sizes; the revision-10 service is 1/1 healthy, current API results carry exact immutable source coordinates, and the final seven-query smoke gate passed. This does not attest a deployed PUBLIC-03 database identity or grant matrix |
| Public video under three minutes | Live AWS UI plus reviewed cloud agent/replacement receipts by default; standalone Fleet Recall is optional local terminal footage, and OSTK is an optional alternate | 46-second 1600×900 sanitized rehearsal rendered; final cloud footage, narration, and public upload pending |
| Judging availability | Functional demo and testing access must remain free and unrestricted through **September 15, 2026 at 5:00 PM EDT / 4:00 PM CDT** | Live operational hold is now required; do not scale down, destroy, revoke access, or tear down the submission stack before judging ends |

Official references:

- Hackathon: <https://cockroachdb-ai.devpost.com/>
- Rules: <https://cockroachdb-ai.devpost.com/rules>
- Schedule: <https://cockroachdb-ai.devpost.com/details/dates>
- CockroachDB vector indexes: <https://www.cockroachlabs.com/docs/stable/vector-indexes>
- CockroachDB Cloud MCP: <https://www.cockroachlabs.com/docs/cockroachcloud/connect-to-the-cockroachdb-cloud-mcp-server>

## Acceptance scenarios

1. An agent in project A cannot retrieve project B or another tenant's rows,
   even when it injects scope-like values into MCP arguments.
2. Agent A records a typed decision with an idempotency key; replay returns the
   original receipt and creates no duplicate claim or event.
3. Agent B semantically recalls the decision through vector plus lexical RRF.
   It records a changed rollout plan based on that memory.
4. Agent C records an overlapping, incompatible typed value; both claims become
   disputed and an explainable conflict is surfaced. Agent B pauses rollout
   and records an operator escalation.
5. `deploy/aws/run-reference-agent.sh` starts four sequential, independently
   deployment-bound Fargate tasks and emits one verified JSON summary only when
   the search-to-exact-get claim, reread action, exact disputed A/C conflict, and
   reread escalation citations form one correlated chain. Project-hashed
   idempotency namespaces prevent cross-project tenant-wide key collisions.
   This deterministic policy path uses neither OSTK nor an LLM.
6. An ECS task can be terminated and replaced without losing durable memory.
7. The publication-safe Cockroach Cloud `EXPLAIN` artifact demonstrates use of
   both scoped vector indexes and the lexical inverted index on the 10,001-row
   disposable fixture with the exact production SQL shapes.
8. A semantic source search resolves exact hash-bound claim support, surfaces
   the relevant documentation and implementation chunks, and projects their
   exact open conflict without applying corpus-wide natural-language inference.

## Evidence boundary

- **Current local PUBLIC-03 evidence:** the exact official-v26.2.3 TLS wrapper
  passed its absolute-final publication phase and real recall/deny product test;
  the independently packaged publication-reader Docker RBAC proof passed; and
  the accepted
  [LocalStack receipt](evidence/localstack-publication-cd6ecfc-20260816.json)
  binds clean commit `cd6ecfca2c1a6d112ba058aad899a21aa34bb0f4`, exact prefix
  1 through 17, production/private image digests, reader status/recall, writer
  denial, replacement persistence, and zero residue. The LocalStack database
  was deliberately insecure, so that receipt records false for TLS, database
  password authentication, IAM enforcement, Fargate, and AWS apply. The
  current PUBLIC-03 Terraform suite passed 21/21 locally and remains unapplied.
- **Other local evidence:** unit/integration tests, disposable CockroachDB
  tests, LocalStack contracts, checked-in sanitized rehearsal JSON, and a fresh
  standalone MCP video capture. These prove application behavior but not AWS or
  CockroachDB Cloud operation.
- **Current cloud release:** immutable ARM64 image tag `git-56b577c82b9c` at
  source commit `56b577c82b9c5a5c80d73103f7f6b56d51698872` runs with all four
  task-definition families at revision 10, and the service is 1/1 healthy. The
  idempotent rich-seed task exited zero and upserted exactly 552 rows (346 documentation,
  2 code, and 204 operations). Public API results exposed the exact release
  revision and inclusive source-line ranges. Final desktop and 390px mobile QA
  verified safe inline Markdown, immutable exact `#Lx-Ly` links, a relative
  repository link rendered as a code-styled anchor, and no horizontal overflow.
  The final seven-query smoke gate passed. The ECR Basic OS-package scan completed with an empty
  finding-severity count; it does not cover Rust, Go, or application
  dependencies. These live observations establish the route-level read-only
  surface only; they do not identify the deployed database role or prove that
  the current PUBLIC-03 source was applied.
- **Historical revision-7 public relevance evidence:** the checked-in
  [seven-query receipt](evidence/public-relevance-efe6fbf-20260814.json) records
  both exact conflict mappings, four relevant conflict-free answers, and zero
  results/zero conflicts for nonsense against the prior 548-row release. It was
  not regenerated for revision 10 and is not the revision-10 smoke receipt.
- **Historical revision-6 cloud evidence:** the checked-in, publication-safe
  [self-audit receipt](evidence/self-audit-devpost-self-audit-20260814T133640Z-rev6.json)
  proves semantic recall surfaced the exact documentation/code sources behind
  claims 9 and 10 and projected open conflict 3. Fresh release-bound run
  `devpost-final6-20260814T143523Z` produced the checked-in
  [reference-agent](evidence/reference-agent-devpost-final6-20260814T143523Z.json),
  [replacement](evidence/replacement-devpost-final6-20260814T143523Z.json), and
  [validation](evidence/publication-validation-devpost-final6-20260814T143523Z.json)
  receipts. They correlate decision claim 15, cited action claim 16,
  incompatible claim 17, and escalation claim 18 citing open conflict 5, then
  prove a fully disjoint revision-6 serving-task replacement preserved exact
  public claims 16 and 18 through lexical/dense RRF. The public HTTPS surface
  reported CockroachDB 26.2.5/schema 2 and all required capabilities. These
  reference-agent and replacement receipts were not rerun for revision 10 and
  must not be presented as revision-10 proof. The publication-safe
  [Cloud `EXPLAIN`](evidence/cockroach-cloud-explain.txt) used the exact
  production SQL shapes against a separate 10,001-row database and selected
  `memory_chunks_semantic_idx`, `memory_chunks_source_semantic_idx`, and
  `memory_chunks_lexical_idx`; all assertions passed. Production data was
  untouched, the disposable database was dropped, and the temporary
  workstation network rule was removed; that plan capture was also not rerun
  during the revision-10 cutover. Viewer HTTPS uses CloudFront's default
  certificate and
  TLSv1-minimum policy; the restricted CloudFront-to-ALB origin hop is HTTP, so
  this is neither end-to-end TLS nor a TLS 1.2 viewer-minimum claim.
- **Optional integration evidence:** an explicitly authorized OSTK adapter run
  may supplement the submission, but it is not the default agent proof path and
  must never be used to imply that Fleet Recall requires OSTK or an LLM.
