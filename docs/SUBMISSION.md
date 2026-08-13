# Hackathon submission packet

This is a working, copy-ready submission packet for the CockroachDB AI Agents
Hackathon. Bracketed fields are release blockers, not claims. Replace them only
after the linked artifact is public and verified. Until the cloud gates pass,
deployment-specific narrative below describes the submission target rather
than an already-running service; the release-state table is authoritative.

Submission deadline: **August 18, 2026 at 5:00 PM ET / 4:00 PM CT**.

## Devpost fields

**Project name**

OSTK Fleet Recall

**Tagline**

Durable, conflict-aware semantic memory for fleets of AI agents.

**Repository**

<https://github.com/os-tack/ostk-fleet-recall>

**Working demo**

`[PUBLIC_HTTPS_DEMO_URL]`

**Demo video (under three minutes)**

`[PUBLIC_YOUTUBE_OR_VIMEO_URL]`

## Inspiration

A strong agent can remember locally, but a fleet has a different problem:
workers restart, run on different hosts, and can simultaneously learn
incompatible things. A shared vector database alone finds similar text; it does
not establish scope, provenance, correction, replay safety, or honest conflict
semantics. We wanted Recall's local-first memory quality to remain intact while
giving an OSTK fleet one durable place to coordinate.

## What it does

Fleet Recall is a distributed memory backend and MCP service for OSTK agents.
It combines CockroachDB's scoped C-SPANN vector indexes with lexical retrieval,
then hydrates Recall-compatible chunks and fuses candidates. Agents can also
record deliberate typed claims with provenance. If two active claims make
incompatible assertions about the same key, Fleet Recall marks them disputed
and returns an explainable conflict instead of silently overwriting one.

Every process is bound to a trusted tenant/project scope. Mutations are
serializable and idempotent, so concurrent agents and client retries produce
one claim, one receipt, and one audit trail. ECS workers are disposable;
CockroachDB Cloud remains the memory source of truth after every task is
replaced.

## How we built it

- **Rust 1.94** application and MCP protocol with bounded inputs/outputs. The
  production Dockerfile's `rust:1.94-bookworm` release build has completed
  locally; this is build evidence, not a hosted-deployment claim.
- **CockroachDB Cloud** for corpus chunks, typed claims, passage vectors,
  conflicts, idempotency receipts, and events.
- **Distributed Vector Indexing** with project- and source-prefixed
  `VECTOR(512)` cosine indexes, plus a stored `TSVECTOR` inverted index for
  hybrid recall.
- **CockroachDB Agent Skills** pinned at commit `e14e86d`: transaction guidance
  shaped the fresh `40001` retry loop, embedding-outside-transaction boundary,
  SQL invariants, connection pooling, concurrency tests, and EXPLAIN plan gates.
  The full trace is in `docs/AGENT_SKILLS_AUDIT.md`.
- **AWS ECS/Fargate and Application Load Balancer** for a replaceable public
  demo task, **S3** for private content-addressed model delivery, **Secrets
  Manager** for Cockroach TLS URLs, **ECR** for scanned immutable images, and
  **CloudWatch** for logs/Container Insights.
- Backend-neutral corpus traits extracted into upstream `ostk-recall`, pinned
  by immutable Git revision so the local and fleet stores share retrieval
  contracts without making local Recall depend on CockroachDB.

Do not add CockroachDB Managed MCP to this list unless the final team actually
uses it against the submission cluster and captures the inspection evidence.
The qualifying tool pair is Distributed Vector Indexing plus Agent Skills.

## Challenges

CockroachDB vector indexes reward a schema designed around their execution
shape. Range predicates cannot become equality prefixes for ANN, so active
recall rows are physically separated from history and source-specific dense
search gets its own prefixed index. Time filtering is explicitly bounded and
diagnosed rather than disguised as exact.

The harder semantic problem was contradictory memory. We made claims,
provenance, conflict membership, transitions, and request receipts one atomic
serializable unit. Embeddings are computed before the transaction, while the
entire database unit is retried only on `40001`. That keeps transactions short
and makes contention a normal, tested path.

## Accomplishments

- One model generation per project, pinned by a digest of the exact local files.
- Tenant/project predicates and keys on every data path, including adversarial
  request tests that reject authority smuggling.
- Hybrid vector/lexical Recall semantics without linking the local LanceDB
  implementation into the fleet backend.
- Explainable, coverage-aware conflicts and at-most-one durable claim mutation
  with idempotent replay under concurrency.
- Real CockroachDB capability and query-plan tests, including representative
  C-SPANN and inverted-index evidence.
- A dormant-by-default AWS deployment that separates one-off DDL credentials
  from the least-privilege runtime secret.

## What we learned

Distributed memory is primarily a correctness and trust problem, not an ANN API
swap. The vector index determines important table boundaries; serializable
retries determine application orchestration; and model identity is part of the
data contract. CockroachDB's transaction and SQL Agent Skills were particularly
useful because they turned those distributed-system concerns into reviewable
code and test gates.

## What's next

- Package Fleet Recall as an optional OSTK Recall plugin/backend.
- Add authenticated workload identity and dynamic multi-project routing without
  trusting MCP parameters.
- Add set-based bounded ingestion, changefeed-driven projections, and
  multi-region locality policies.
- Load-test numeric claim-ID access paths and introduce hash sharding or a
  versioned UUID public contract where needed.
- Add private AWS/Cockroach connectivity, WAF/rate limiting, operational SLOs,
  and contention/hot-range alerts.

## Pre-existing work disclosure

OSTK and `ostk-recall` existed before the hackathon and remain independently
useful local-first projects. The Fleet Recall CockroachDB schema/store, claim
and conflict persistence, fleet MCP adaptation, deployment, demo, and the
backend-neutral upstream extraction used here were built for this project.
Git history and pinned revisions make that boundary inspectable.

## Tool-use evidence

| Requirement | Evidence to show judges | Release state |
|---|---|---|
| CockroachDB persistent memory | Local 26.2 schema/round-trip/conflict tests; cloud health and restart capture | Local ready; `[VERIFY_ON_CLOUD]` |
| Distributed Vector Indexing | DDL and local representative `EXPLAIN`; cloud plan capture | Local ready; `[CAPTURE_CLOUD_PLAN]` |
| CockroachDB Agent Skills | Pinned audit mapping guidance to code/tests and accepted deviations | Ready in repository |
| AWS service | ECS/ALB/S3/Secrets/ECR/CloudWatch Terraform; LocalStack contract harness | LocalStack contract, Rust 1.94 image, migration, ingest, recall, and app-replacement persistence passed; `[DEPLOY_AND_CAPTURE]` in real AWS pending |
| Public open source | Source, licenses, locked dependencies, setup and sample data | Published and anonymously verified at <https://github.com/os-tack/ostk-fleet-recall> |
| Functional URL | HTTPS landing page, bounded recall, `/healthz` | Local HTTP healthy with recall hits; `[DEPLOY_AND_SMOKE_TEST]` pending |
| Public video <3 min | YouTube/Vimeo link and final duration | `[RECORD_AND_UPLOAD]` |

## Video script (target 2:45)

**0:00-0:18 — problem and promise**

Show three agent terminals and say: “A fleet needs more than similar text. It
needs shared memory that survives workers, isolates projects, handles retries,
and admits when agents disagree.”

**0:18-0:38 — architecture**

Show the architecture diagram. Point to ECS tasks, S3-pinned model, CockroachDB
Cloud, scoped vector/lexical indexes, and the separate migration task.

**0:38-1:10 — durable shared recall**

Agent A records a typed deployment decision through MCP. Agent B recalls the
idea using different wording through MCP. Capture the MCP JSON response in the
terminal; that authenticated surface, not the public HTTP UI, exposes the typed
claim and provenance. Use the public demo only to find the persisted chunk
through its read-only HTTP search. Replace or stop the serving ECS task, let ECS
restore it, then repeat recall to demonstrate that memory stayed in
CockroachDB.

**1:10-1:42 — conflict, not overwrite**

Agent C records an incompatible typed value under the same claim key. Show both
claims becoming disputed, the conflict rationale/member values, and complete
coverage metadata. Replay the same idempotency key and show that counts do not
increase.

**1:42-2:08 — isolation and execution evidence**

Attempt to inject another project in an MCP request and show the request being
rejected or remaining in the trusted deployment scope. Then show CockroachDB
`EXPLAIN` selecting the scoped vector index and the lexical inverted index.

**2:08-2:30 — qualifying technology**

Show the Agent Skills audit beside the fresh-transaction retry code and schema
constraints. Show the live ECS service and S3 model prefix without exposing
account IDs, secret ARNs, URLs with credentials, or tenant-sensitive logs.

**2:30-2:45 — close**

“Local Recall for one agent; CockroachDB Fleet Recall when the whole fleet has
to remember—and disagree—together.” End on the public demo URL and repository.

## Final release checklist

- [x] Public repository URL works in a logged-out browser.
- [x] Licenses, dependency lockfile, sample NDJSON, setup, architecture, and
      pre-existing-work disclosure are present.
- [x] CI passes from a clean clone on Rust 1.94.
- [ ] CockroachDB Cloud uses TLS, a non-admin runtime user, backups, and an
      allowlist/private route.
- [ ] Run one migration task, then verify `health` and all required indexes.
- [ ] Capture Cloud `EXPLAIN` evidence with a representative corpus.
- [ ] Push an immutable ECR image and run at least one healthy ECS task.
- [ ] Public URL supports landing page, bounded recall, and `/healthz`; mutation
      remains unavailable or authenticated/rate-limited.
- [ ] HTTPS certificate is valid and no secrets appear in HTML, API output,
      CloudWatch screenshots, shell history, or video.
- [ ] Stop/replace a task and verify the same memory remains.
- [ ] Video is public, under three minutes, legible at 1080p, and explicitly
      names CockroachDB tools and AWS services.
- [ ] Devpost fields replace every bracketed placeholder and identify how each
      qualifying tool/service is used.
- [ ] Submit before August 18, 2026 at 5:00 PM ET / 4:00 PM CT.
