# Submission requirements matrix

This matrix is the release gate for the CockroachDB AI Agents Hackathon.

| Requirement | Fleet Recall evidence | Status |
|---|---|---|
| New project created during the contest | This repository; Recall and OSTK are disclosed as pre-existing foundations | Implemented locally; public history pending |
| Agentic application | Multiple OSTK agents read and deliberately mutate shared semantic memory over MCP | Implemented and tested locally |
| CockroachDB persistent memory layer | Corpus, claim ledger, conflicts, receipts, and events in CockroachDB | Implemented and tested on CockroachDB 26.2 |
| Distributed Vector Indexing | Prefix-scoped `VECTOR(512)` indexes for chunks and claim passages | Implemented; cloud plan capture pending |
| Second CockroachDB tool | Official Agent Skills shaped transactions, SQL, tests, and runbooks; see `AGENT_SKILLS_AUDIT.md` | Implemented and audited |
| Optional third CockroachDB tool | Managed MCP inspection of the submission cluster | Stretch; do not claim until captured |
| AWS service | ECS/Fargate/ALB Terraform plus LocalStack S3/Secrets contract harness | LocalStack contract, Rust 1.94 image, migration, ingest, recall, and app-replacement persistence passed; real AWS deploy pending |
| Public open-source repository | Public GitHub repository with explicit pre-existing-code disclosure | Planned |
| Working demo URL | Public status/demo surface or reproducible hosted endpoint | Local HTTP healthy with recall hits; public URL pending |
| Public video under three minutes | Scripted shared-memory, conflict, isolation, and restart demonstration | Planned |

Official references:

- Hackathon: <https://cockroachdb-ai.devpost.com/>
- Rules: <https://cockroachdb-ai.devpost.com/rules>
- CockroachDB vector indexes: <https://www.cockroachlabs.com/docs/stable/vector-indexes>
- CockroachDB Cloud MCP: <https://www.cockroachlabs.com/docs/cockroachcloud/connect-to-the-cockroachdb-cloud-mcp-server>

## Acceptance scenarios

1. An agent in project A cannot retrieve project B or another tenant's rows,
   even when it injects scope-like values into MCP arguments.
2. Agent A records a typed decision with an idempotency key; replay returns the
   original receipt and creates no duplicate claim or event.
3. Agent B semantically recalls the decision through vector plus lexical RRF.
4. Agent C records an overlapping, incompatible typed value; both claims become
   disputed and an explainable conflict is surfaced.
5. An ECS task can be terminated and replaced without losing durable memory.
6. Cockroach `EXPLAIN` demonstrates use of the scoped vector and inverted
   indexes on the representative corpus.
