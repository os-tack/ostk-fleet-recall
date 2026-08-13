# Hackathon submission packet

This is a working, copy-ready submission packet for the CockroachDB AI Agents
Hackathon. Bracketed fields are release blockers, not claims. Replace them only
after the linked artifact is public and verified. Until the cloud gates pass,
deployment-specific narrative below describes the submission target rather
than an already-running service; the release-state table is authoritative.

Submission deadline: **August 18, 2026 at 5:00 PM EDT / 4:00 PM CDT**.
The submitted project must remain available free of charge and without
restriction through the end of judging: **September 15, 2026 at 5:00 PM EDT /
4:00 PM CDT**. Do not tear down or scale the judging deployment to zero before
that hold expires.

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

**Project thumbnail**

`docs/assets/devpost-thumbnail-v2.png` — 1536×1024 PNG (3:2, under 5 MB).

**Built-with tags**

`Rust`, `CockroachDB`, `Vector Search`, `Agent Skills`, `AWS`, `Amazon ECS`,
`AWS Fargate`, `Amazon S3`, `Application Load Balancer`, `Amazon ECR`,
`AWS Secrets Manager`, `Amazon CloudWatch`, `Terraform`, `MCP`, `model2vec`,
`Axum`, `SQLx`. Add `OSTK` only if the optional adapter is actually used in a
final captured artifact; it is not part of the default proof path.

**Qualifying checkboxes**

- CockroachDB: **Distributed Vector Indexing** and **Agent Skills Repo**.
- AWS: **Amazon ECS / EKS** and **Amazon S3**. Mention ALB, ECR, Secrets
  Manager, and CloudWatch in the narrative or “Other” field if available.
- Do not select CockroachDB Cloud Managed MCP Server unless it is separately
  used against the final cluster and captured.

**Subjective form answers to confirm with the entrant**

- Learning level: suggested **Significant**.
- AI value usable in your career: suggested **Yes**.
- Team members: `[CONFIRM_DEVPOST_TEAM]`.

**Gallery plan**

1. Project thumbnail: ready at `docs/assets/devpost-thumbnail-v2.png`.
2. Architecture: ready at `docs/assets/architecture.png`, generated from the
   validated deployment topology in `docs/ARCHITECTURE.md`; regenerate it only
   if the hosted topology changes.
3. Proof: capture the agent action/conflict result and post-replacement cloud
   recall without account IDs, secret ARNs, credentials, or tenant-sensitive
   logs.

## Inspiration

A strong agent can remember locally, but a fleet has a different problem:
workers restart, run on different hosts, and can simultaneously learn
incompatible things. A shared vector database alone finds similar text; it does
not establish scope, provenance, correction, replay safety, or honest conflict
semantics. We wanted Recall's local-first memory quality to remain intact while
giving any agent fleet one durable place to coordinate, with OSTK available as
an optional orchestrator rather than a runtime dependency.

## What it does

Fleet Recall is a distributed memory backend and MCP service for agent fleets,
including OSTK.
It combines CockroachDB's scoped C-SPANN vector indexes with lexical retrieval,
then hydrates Recall-compatible chunks and fuses candidates. Agents can also
record deliberate typed claims with provenance. If two active claims make
incompatible assertions about the same key, Fleet Recall marks them disputed
and returns an explainable conflict instead of silently overwriting one.

Every Fleet Recall process is bound to a trusted tenant/project scope. Mutations are
serializable and idempotent: an identical canonical request retried with the
same tenant-wide key produces at most one durable claim, receipt, and audit
trail, while independent incompatible writes remain distinct and become an
explicit conflict. ECS workers are disposable;
the final deployment will keep CockroachDB Cloud as the memory source of truth
after every task is replaced. That cloud persistence claim remains gated until
the real deployment and replacement capture pass.

The submission core does not depend on OSTK or an LLM. Its default AWS agent is
a standalone deterministic reference policy implemented in Fleet Recall. Four
separately deployment-bound one-off Fargate tasks observe durable memory, apply
an explicit rollout-safety policy, and persist cited actions; the wrapper emits
a verified summary only when their claim, action, exact conflict, and escalation
identifiers form one correlated chain. The policy agent resolves search results
through exact get and rereads each durable action before attesting it. That is
agentic policy execution, not a claim of autonomous LLM reasoning. An optional
OSTK adapter can run the same chain with bounded model sessions through a
checked-in Bash bridge; it remains opt-in and unclaimed until an explicitly
authorized live run produces verified evidence. Its boundary is documented in
`docs/OSTK_DEMO.md`.

## How we built it

- **Rust 1.94** application and MCP protocol with bounded inputs/outputs. The
  production Dockerfile's `rust:1.94-bookworm` release build has completed
  locally; this is build evidence, not a hosted-deployment claim.
- **CockroachDB Cloud** is the final deployment target for corpus chunks, typed
  claims, passage vectors, conflicts, idempotency receipts, and events. The
  corresponding live verification remains pending.
- **Distributed Vector Indexing** with project- and source-prefixed
  `VECTOR(512)` cosine indexes, plus a stored `TSVECTOR` inverted index for
  hybrid recall.
- **CockroachDB Agent Skills** pinned at commit `e14e86d`: the coding agent
  invoked the transaction and SQL skills, then used their guidance to shape the
  fresh `40001` retry loop, embedding-outside-transaction boundary, SQL
  invariants, connection pooling, concurrency tests, and EXPLAIN plan gates.
  The full skill-to-code/test trace is in `docs/AGENT_SKILLS_AUDIT.md`.
- The checked-in **AWS ECS/Fargate and Application Load Balancer** deployment
  targets a replaceable public demo task, **S3** for private content-addressed
  model delivery, **Secrets Manager** for Cockroach TLS URLs, **ECR** for
  scanned immutable images, and **CloudWatch** for logs/Container Insights. A
  dedicated one-off Fargate task definition runs the deterministic reference
  policy agent under A/B/C deployment identities;
  `deploy/aws/run-reference-agent.sh` verifies their correlated durable-memory
  chain. Real AWS execution remains a release gate.
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
- A dormant-by-default AWS Terraform deployment definition that separates
  one-off DDL credentials from the least-privilege runtime secret; live AWS
  deployment remains pending.

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
| CockroachDB persistent memory | Local 26.2 schema/round-trip/conflict tests; cloud reference-agent, health, and restart capture | Local ready; `[VERIFY_ON_CLOUD]` |
| Distributed Vector Indexing | DDL and local representative `EXPLAIN`; cloud plan and reference-agent lexical+dense RRF capture | Local ready; `[CAPTURE_CLOUD_PLAN]` |
| CockroachDB Agent Skills | Pinned coding-agent invocation audit mapping each skill to decisions, code/tests, and accepted deviations | Ready in repository |
| AWS service | ECS/ALB/S3/Secrets/ECR/CloudWatch Terraform; one-off reference-agent task/wrapper; LocalStack contract harness | Combined LocalStack migration/ingest/fleet/replacement smoke passed; `[DEPLOY_AND_CAPTURE]` in real AWS remains pending |
| Public open source | Source, licenses, locked dependencies, setup and sample data | Published and anonymously verified at <https://github.com/os-tack/ostk-fleet-recall> |
| Functional URL | HTTPS landing page, bounded recall, `/healthz` | Local HTTP healthy with recall hits; `[DEPLOY_AND_SMOKE_TEST]` pending |
| Public video <3 min | Fresh standalone Fleet Recall capture/render by default, cloud proof footage, then YouTube/Vimeo link and final duration; OSTK is an optional alternate | 46-second 1600×900 sanitized rehearsal rendered; `[RENDER_LIVE_NARRATE_AND_UPLOAD]` |

## Judging-criteria evidence map

The [official judging criteria](https://cockroachdb-ai.devpost.com/rules) are
equally weighted. This table keeps the final story balanced instead of
treating successful vector search as the whole project.

| Criterion | Strongest repository evidence | Final proof still to capture |
|---|---|---|
| Agentic Memory Design | Hybrid lexical/vector recall, typed claims, provenance, correction-aware conflict membership, and the deterministic A → B → C policy-agent chain | Run `deploy/aws/run-reference-agent.sh` against the submission stack and show its correlated CockroachDB-backed result |
| Technological Implementation | Prefix-scoped C-SPANN and inverted indexes, backend-neutral Recall extraction, short serializable retries, immutable model identity, conformance and adversarial tests | Capture representative Cloud `EXPLAIN` plans and the deployed image digest |
| Real-World Impact | A recalled schema-migration decision changes the next agent's rollout action; an incompatible memory stops rollout and produces a cited operator handoff | Explain how the same pattern applies to long-running coding, operations, and research fleets |
| Product Readiness | Trusted deployment scope, bounded input/output and hydration, least-privilege runtime/migrator separation, health gates, idempotent receipts, redacted failures, Terraform and restart harness | Show TLS, healthy ECS tasks, CloudWatch, and recall after task replacement without exposing identifiers or secrets |
| Creativity & Originality | Local Recall stays local-first while Fleet Recall adds a distributed memory plane; disagreement is durable first-class state rather than an overwrite or a hidden rank choice | Make the conflict-aware memory-to-action transition the visual center of the final video |

## Video script (target 2:45)

The four-terminal memory/action/conflict sequence is reproducibly rendered by
`demo/video/render.sh`; see `docs/VIDEO_DEMO.md`. Rehearsal mode is visibly
labelled and uses sanitized checked-in evidence. The submitted cut should use
a fresh verified standalone Fleet Recall MCP capture for the agent evidence
and keep cloud proof as a separate captured gate. A verified OSTK render is an
optional alternate take, not a submission dependency.

The local standalone capture proves the displayed application chain but is not
AWS evidence. The cloud segment must use the real public URL and the verified
`fleet-reference-agent-run-v1` output from the Fargate wrapper; both remain
pending until deployment. Do not describe the policy decisions as LLM output.

**0:00-0:18 — problem and promise**

Show three agent terminals and say: “A fleet needs more than similar text. It
needs shared memory that survives workers, isolates projects, handles retries,
and admits when agents disagree.”

**0:18-0:38 — architecture**

Show the architecture diagram. Point to ECS tasks, S3-pinned model, CockroachDB
Cloud, scoped vector/lexical indexes, and the separate migration task.

**0:38-1:10 — durable shared recall**

The deterministic Agent A policy step records a typed deployment decision.
Agent B recalls the idea using different wording through lexical+dense RRF,
applies the explicit rollout-safety policy, and records the resulting execution
plan: hold application workers until the dedicated migrator completes. Show the
standalone video evidence, then the correlated AWS wrapper receipt and public
read-only recall from the real deployment. Replace or stop the serving ECS
task, let ECS restore it, then repeat recall to demonstrate that memory stayed
in CockroachDB.

**1:10-1:42 — conflict, not overwrite**

The deterministic Agent C policy step records an incompatible typed value under
the same claim key. Show both claims becoming disputed, the exact conflict
membership, and complete coverage metadata. The same deployment-bound B
identity then reads that conflict, applies the explicit pause-and-escalate
policy, and persists an operator handoff citing it. Replay the same idempotency
key and show that counts do not increase.

**1:42-2:08 — isolation and execution evidence**

Attempt to inject another project in an MCP request and show the request being
rejected or remaining in the trusted deployment scope. Then show CockroachDB
`EXPLAIN` selecting the scoped vector index and the lexical inverted index.

**2:08-2:30 — qualifying technology**

Show the pinned Agent Skills invocation-to-evidence trace beside the
fresh-transaction retry code, its concurrency test, and schema constraints.
Show the live ECS service and S3 model prefix without exposing
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
- [ ] Run `deploy/aws/run-reference-agent.sh` against the healthy submission
      stack; preserve its verified correlated JSON and redacted public-demo
      recall evidence. Do not substitute a local or handcrafted result.
- [ ] Video is public, under three minutes, legible at 1080p, and explicitly
      names CockroachDB tools and AWS services.
- [ ] Devpost fields replace every bracketed placeholder and identify how each
      qualifying tool/service is used.
- [ ] Submit before August 18, 2026 at 5:00 PM EDT / 4:00 PM CDT.
- [ ] Keep the working project free and unrestricted through September 15, 2026
      at 5:00 PM EDT / 4:00 PM CDT; retain 60-day logs and ALB deletion
      protection, with no early scale-to-zero or teardown.
