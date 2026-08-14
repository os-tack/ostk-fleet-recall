# Submission requirements matrix

This matrix is the release gate for the CockroachDB AI Agents Hackathon. The
official rules require an agentic application that uses CockroachDB as its
persistent memory layer, is deployed on AWS, uses at least two listed
CockroachDB tools and one AWS service, and remains available free of charge and
without restriction through the end of judging. Repository and local evidence
do not by themselves prove deployment; the live results below combine the
revision-7 cutover and public smoke verification with explicitly historical
revision-6 AWS/CockroachDB Cloud receipts.

| Requirement | Fleet Recall evidence | Status |
|---|---|---|
| New project created during the contest | This repository; Recall and OSTK are disclosed as pre-existing foundations | Public initial history published and boundary documented |
| Agentic application | The standalone deterministic reference policy agent recalls fleet state, applies an explicit rollout-safety policy, and persists cited actions; separately deployment-bound A/B/C identities exercise the full memory/action/conflict chain | Historical revision-6 run `devpost-final6-20260814T143523Z` proved decision/action/incompatible/escalation claims 15/16/17/18 and open conflict 5 across four one-off Fargate tasks; the separate revision-6 self-audit proved source-backed claims 9/10 and open conflict 3. These agent proofs were not rerun on revision 7. OSTK is strictly optional, and no LLM decision or live model run is claimed |
| CockroachDB persistent memory layer | Corpus, claim ledger, source support, conflicts, receipts, actions, and events in CockroachDB | The live revision-7 rich-seed task exited zero and upserted exactly 548 rows: 342 documentation, 2 code, and 204 operations chunks. Public smoke verification returned both exact conflict mappings, four relevant conflict-free answers, and zero results/zero conflicts for nonsense. The public status surface reports CockroachDB Cloud 26.2.5 with schema version 2 and the required capabilities |
| Distributed Vector Indexing | Prefix-scoped `VECTOR(512)` indexes for chunks and claim passages | Live status confirms the vector, lexical, conflict-membership, and claim-support-chunk indexes plus cosine distance and dimension 512; lexical/dense RRF returned the expected claims and projected an exact source-backed conflict. The [publication-safe Cloud `EXPLAIN`](evidence/cockroach-cloud-explain.txt) verifies both C-SPANN indexes and the lexical inverted index with the exact production SQL shapes on 10,001 disposable rows; all assertions passed |
| Second CockroachDB tool | The coding agent invoked the pinned official Agent Skills to review and shape transactions, SQL, tests, and runbooks; see `AGENT_SKILLS_AUDIT.md` | Implemented and audited with a skill-to-code/test trace |
| AWS service | ECS/Fargate behind ALB and CloudFront, private S3 model delivery, immutable ECR image, Secrets Manager database URLs, CloudWatch evidence, plus the LocalStack contract harness | Serving, migration, seed, and reference-agent task-definition families are revision 7; the rich seed succeeded and the UI/public API were browser- and smoke-verified. The self-audit, four-task reference run, and full serving-task replacement remain historical revision-6 proofs and were not rerun on revision 7 |
| Public open-source repository | Public GitHub repository with explicit pre-existing-code disclosure | Published and anonymously verified |
| Working demo URL | Public read-only status/demo surface at <https://d13zrqfh66r7ub.cloudfront.net> | Live and browser-verified through CloudFront; `/healthz`, `/api/status`, and the seven-query bounded hybrid-recall smoke check succeeded |
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
- **Current cloud release:** immutable ARM64 image tag `git-efe6fbf4e2f1` at
  source commit `efe6fbf4e2f1c5b9daab2c5f4f65ebf38a49770f` runs with all four
  task-definition families at revision 7. The rich-seed task exited zero and
  upserted exactly 548 rows (342 documentation, 2 code, and 204 operations).
  The browser-verified UI and seven-query public smoke check confirmed exact
  specification/code and migration conflict mappings, relevant conflict-free
  CockroachDB, Rust, project-purpose, and datastore-library results, and zero
  results/zero conflicts for nonsense. All five CI jobs passed in run
  [`31821458425`](https://github.com/os-tack/ostk-fleet-recall/actions/runs/31821458425).
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
  reference-agent and replacement receipts were not rerun on revision 7 and
  must not be presented as revision-7 proof. The publication-safe
  [Cloud `EXPLAIN`](evidence/cockroach-cloud-explain.txt) used the exact
  production SQL shapes against a separate 10,001-row database and selected
  `memory_chunks_semantic_idx`, `memory_chunks_source_semantic_idx`, and
  `memory_chunks_lexical_idx`; all assertions passed. Production data was
  untouched, the disposable database was dropped, and the temporary
  workstation network rule was removed; that plan capture was also not rerun
  during the revision-7 cutover. Viewer HTTPS uses CloudFront's default
  certificate and
  TLSv1-minimum policy; the restricted CloudFront-to-ALB origin hop is HTTP, so
  this is neither end-to-end TLS nor a TLS 1.2 viewer-minimum claim.
- **Optional integration evidence:** an explicitly authorized OSTK adapter run
  may supplement the submission, but it is not the default agent proof path and
  must never be used to imply that Fleet Recall requires OSTK or an LLM.
