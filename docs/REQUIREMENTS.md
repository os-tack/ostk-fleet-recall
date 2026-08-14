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
| Agentic application | The standalone deterministic reference policy agent recalls fleet state, applies an explicit rollout-safety policy, and persists cited actions; separately deployment-bound A/B/C identities exercise the full memory/action/conflict chain | Verified pre-polish revision 3 cloud evidence run `devpost-final-20260814T021819Z` proved decision/action/incompatible/escalation claims 5/6/7/8 and open conflict 2 across four one-off Fargate tasks using reference-agent task definition revision 3. OSTK is strictly optional, and no LLM decision or live model run is claimed |
| CockroachDB persistent memory layer | Corpus, claim ledger, conflicts, receipts, actions, and events in CockroachDB | Live on CockroachDB Cloud 26.2.5 with schema version 1; migration, three-record seed, four-task policy chain, and post-replacement exact recall succeeded |
| Distributed Vector Indexing | Prefix-scoped `VECTOR(512)` indexes for chunks and claim passages | Live status confirms the vector, lexical, and conflict-membership indexes plus cosine distance and dimension 512; lexical/dense RRF returned the expected claims. The [publication-safe Cloud `EXPLAIN`](evidence/cockroach-cloud-explain.txt) verifies both C-SPANN indexes and the lexical inverted index with the exact production SQL shapes on 10,001 disposable rows; all assertions passed |
| Second CockroachDB tool | The coding agent invoked the pinned official Agent Skills to review and shape transactions, SQL, tests, and runbooks; see `AGENT_SKILLS_AUDIT.md` | Implemented and audited with a skill-to-code/test trace |
| AWS service | ECS/Fargate behind ALB and CloudFront, private S3 model delivery, immutable ECR image, Secrets Manager database URLs, CloudWatch evidence, plus the LocalStack contract harness | Live migration and seed tasks succeeded; four reference-agent Fargate tasks verified the policy chain; a forced deployment replaced the complete serving task set and preserved exact hybrid recall |
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

## Evidence boundary

- **Local evidence:** unit/integration tests, disposable CockroachDB tests,
  LocalStack contracts, checked-in sanitized rehearsal JSON, and a fresh
  standalone MCP video capture. These prove application behavior but not AWS or
  CockroachDB Cloud operation.
- **Cloud evidence:** verified pre-polish revision 3 cloud evidence run
  `devpost-final-20260814T021819Z` produced a verified four-task ECS/Fargate
  chain against CockroachDB Cloud: decision claim 5, cited action claim 6,
  incompatible claim 7, and escalation claim 8 citing open conflict 2. The
  public HTTPS surface reported version 26.2.5/schema 1 and all required
  capabilities; a fully disjoint serving-task replacement preserved exact
  public action/escalation claims 6 and 8 through lexical/dense RRF. The
  receipts are operator-held and sanitized for publication. The currently
  deployed revision 4 serving image adds the conflict-first UI and bounded API
  polish from `97eba7d` and passed CI plus separate public smoke checks; the
  four-task and replacement receipts were not rerun on revision 4. The
  publication-safe
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
