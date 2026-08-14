# Submission requirements matrix

This matrix is the release gate for the CockroachDB AI Agents Hackathon. The
official rules require an agentic application that uses CockroachDB as its
persistent memory layer, is deployed on AWS, uses at least two listed
CockroachDB tools and one AWS service, and remains available free of charge and
without restriction through the end of judging. Repository and local evidence
do not by themselves prove deployment; the live results below come from the
sanitized AWS/CockroachDB Cloud reference and replacement receipts.

| Requirement | Fleet Recall evidence | Status |
|---|---|---|
| New project created during the contest | This repository; Recall and OSTK are disclosed as pre-existing foundations | Public initial history published and boundary documented |
| Agentic application | The standalone deterministic reference policy agent recalls fleet state, applies an explicit rollout-safety policy, and persists cited actions; separately deployment-bound A/B/C identities exercise the full memory/action/conflict chain | Fresh release-bound run `devpost-final6-20260814T143523Z` proved decision/action/incompatible/escalation claims 15/16/17/18 and open conflict 5 across four one-off Fargate tasks using reference-agent task definition revision 6. The separate self-audit proved source-backed claims 9/10 and open conflict 3. OSTK is strictly optional, and no LLM decision or live model run is claimed |
| CockroachDB persistent memory layer | Corpus, claim ledger, source support, conflicts, receipts, actions, and events in CockroachDB | Revision-6 cloud evidence verifies CockroachDB Cloud 26.2.5 with schema version 2; migration, the three-record bootstrap, the verifier-gated 536-chunk rich corpus, both live agent proofs, and post-replacement exact recall succeeded. The current source generator deterministically emits 548 rows and passes local verification; those rows remain pending a release-bound seed receipt and are not yet a cloud deployment claim |
| Distributed Vector Indexing | Prefix-scoped `VECTOR(512)` indexes for chunks and claim passages | Live status confirms the vector, lexical, conflict-membership, and claim-support-chunk indexes plus cosine distance and dimension 512; lexical/dense RRF returned the expected claims and projected an exact source-backed conflict. The [publication-safe Cloud `EXPLAIN`](evidence/cockroach-cloud-explain.txt) verifies both C-SPANN indexes and the lexical inverted index with the exact production SQL shapes on 10,001 disposable rows; all assertions passed |
| Second CockroachDB tool | The coding agent invoked the pinned official Agent Skills to review and shape transactions, SQL, tests, and runbooks; see `AGENT_SKILLS_AUDIT.md` | Implemented and audited with a skill-to-code/test trace |
| AWS service | ECS/Fargate behind ALB and CloudFront, private S3 model delivery, immutable ECR image, Secrets Manager database URLs, CloudWatch evidence, plus the LocalStack contract harness | All four task-definition families reached revision 6; live migration and both seed tasks succeeded; the two-task self-audit and four-task reference run verified their chains; a forced deployment replaced the complete serving task set and preserved exact claims 16 and 18 through hybrid recall |
| Public open-source repository | Public GitHub repository with explicit pre-existing-code disclosure | Published and anonymously verified |
| Working demo URL | Public read-only status/demo surface at <https://d13zrqfh66r7ub.cloudfront.net> | Live and healthy through CloudFront; `/healthz`, `/api/status`, and bounded hybrid recall succeeded |
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

- **Local evidence:** unit/integration tests, disposable CockroachDB tests,
  LocalStack contracts, checked-in sanitized rehearsal JSON, and a fresh
  standalone MCP video capture. These prove application behavior but not AWS or
  CockroachDB Cloud operation.
- **Cloud evidence:** the checked-in, publication-safe
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
  reported CockroachDB 26.2.5/schema 2 and all required capabilities. The
  deployed ARM64 image is immutable tag `git-ba884f24858a` at source commit
  `ba884f24858a58b09a915e0358e60e7fcc7e2c34`; all five CI jobs passed in run
  `31808620621`. An earlier completed proof remains historical because it
  predates this schema and image boundary; the fresh run ID prevents mixing its
  deployment coordinates with the current claims and replacement. The publication-safe
  [Cloud `EXPLAIN`](evidence/cockroach-cloud-explain.txt) used the exact
  production SQL shapes against a separate 10,001-row database and selected
  `memory_chunks_semantic_idx`, `memory_chunks_source_semantic_idx`, and
  `memory_chunks_lexical_idx`; all assertions passed. Production data was
  untouched, the disposable database was dropped, and the temporary
  workstation network rule was removed. Viewer HTTPS uses CloudFront's default
  certificate and
  TLSv1-minimum policy; the restricted CloudFront-to-ALB origin hop is HTTP, so
  this is neither end-to-end TLS nor a TLS 1.2 viewer-minimum claim.
- **Optional integration evidence:** an explicitly authorized OSTK adapter run
  may supplement the submission, but it is not the default agent proof path and
  must never be used to imply that Fleet Recall requires OSTK or an LLM.
