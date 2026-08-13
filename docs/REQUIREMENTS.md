# Submission requirements matrix

This matrix is the release gate for the CockroachDB AI Agents Hackathon. The
official rules require an agentic application that uses CockroachDB as its
persistent memory layer, is deployed on AWS, uses at least two listed
CockroachDB tools and one AWS service, and remains available free of charge and
without restriction through the end of judging. Repository and local evidence
do not by themselves prove the pending AWS/CockroachDB Cloud deployment.

| Requirement | Fleet Recall evidence | Status |
|---|---|---|
| New project created during the contest | This repository; Recall and OSTK are disclosed as pre-existing foundations | Public initial history published and boundary documented |
| Agentic application | The standalone deterministic reference policy agent recalls fleet state, applies an explicit rollout-safety policy, and persists cited actions; separately deployment-bound A/B/C identities exercise the full memory/action/conflict chain | Local scenario passes and the one-off Fargate task/wrapper path is implemented; real AWS execution is pending. OSTK is strictly optional, and no LLM decision or live model run is claimed |
| CockroachDB persistent memory layer | Corpus, claim ledger, conflicts, receipts, actions, and events in CockroachDB | Implemented and tested locally on CockroachDB 26.2; CockroachDB Cloud verification pending |
| Distributed Vector Indexing | Prefix-scoped `VECTOR(512)` indexes for chunks and claim passages | Implemented and locally plan-tested; cloud plan capture pending |
| Second CockroachDB tool | The coding agent invoked the pinned official Agent Skills to review and shape transactions, SQL, tests, and runbooks; see `AGENT_SKILLS_AUDIT.md` | Implemented and audited with a skill-to-code/test trace |
| AWS service | ECS/Fargate/ALB Terraform, a one-off Fargate reference-agent task and verifier, plus the LocalStack S3/Secrets contract harness | Infrastructure and wrapper are implemented and statically tested; the combined LocalStack migration/ingest/fleet/replacement smoke passes, but real AWS execution and capture remain pending |
| Public open-source repository | Public GitHub repository with explicit pre-existing-code disclosure | Published and anonymously verified |
| Working demo URL | Public status/demo surface or reproducible hosted endpoint | Local HTTP healthy with recall hits; public URL pending |
| Public video under three minutes | Default standalone Fleet Recall capture/render plus scripted architecture, isolation, AWS, and restart evidence; optional OSTK render is an alternate only | 46-second 1600×900 sanitized rehearsal rendered; fresh standalone capture, final cloud footage, narration, and public upload pending |
| Judging availability | Functional demo and testing access must remain free and unrestricted through **September 15, 2026 at 5:00 PM EDT / 4:00 PM CDT** | Operational hold required after deployment; do not scale down, destroy, revoke access, or tear down the submission stack before judging ends |

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
7. Cockroach `EXPLAIN` demonstrates use of the scoped vector and inverted
   indexes on the representative corpus.

## Evidence boundary

- **Local evidence:** unit/integration tests, disposable CockroachDB tests,
  LocalStack contracts, checked-in sanitized rehearsal JSON, and a fresh
  standalone MCP video capture. These prove application behavior but not AWS or
  CockroachDB Cloud operation.
- **Cloud evidence (pending):** a successful correlated
  `run-reference-agent.sh` result from ECS/Fargate, CockroachDB Cloud health and
  `EXPLAIN`, the public HTTPS URL, and recall after ECS task replacement. Do not
  replace the release placeholders or describe these as complete until the
  corresponding live captures exist.
- **Optional integration evidence:** an explicitly authorized OSTK adapter run
  may supplement the submission, but it is not the default agent proof path and
  must never be used to imply that Fleet Recall requires OSTK or an LLM.
