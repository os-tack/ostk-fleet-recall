# Hackathon submission packet

This is a working, copy-ready submission packet for the CockroachDB AI Agents
Hackathon. Bracketed fields are release blockers, not claims. Replace them only
after the linked artifact is public and verified. The AWS/CockroachDB Cloud
deployment, reference-agent run, replacement proof, and representative Cloud
`EXPLAIN` are now verified. The final public video and entrant-controlled
Devpost fields remain release blockers. The release-state table is
authoritative.

Submission deadline: **August 18, 2026 at 5:00 PM EDT / 4:00 PM CDT**.
The submitted project must remain available free of charge and without
restriction through the end of judging: **September 15, 2026 at 5:00 PM EDT /
4:00 PM CDT**. Do not tear down or scale the judging deployment to zero before
that hold expires.

## Devpost fields

**Project name**

OSTK Fleet Recall

**Tagline**

Agents are replaceable. Their memory shouldn't be—and when two disagree,
memory should say so.

**Repository**

<https://github.com/os-tack/ostk-fleet-recall>

**Working demo**

<https://d13zrqfh66r7ub.cloudfront.net>

**Testing instructions**

Open the working-demo URL without signing in. Its default question leads with
the differentiator: “How are conflicting migration strategies represented and
escalated?” Submit it and confirm the page visibly reports two agents
disagreeing, the open typed conflict, the operator escalation, three readable
supporting-memory cards, and measured server/round-trip time. Expand “View raw
evidence envelope” to inspect the bounded CockroachDB-backed result. Then open
<https://d13zrqfh66r7ub.cloudfront.net/healthz> and confirm
`{"status":"ready"}`. The public
surface is intentionally read-only: `/`, `/healthz`, `/api/status`, and bounded
`POST /api/recall`; no mutation credential is needed or exposed.

The public URL uses CloudFront's default certificate. Its generated-hostname
viewer policy has a TLSv1 minimum and may negotiate newer TLS; CloudFront uses
restricted HTTP to the ALB origin. The origin accepts only the CloudFront
origin-facing prefix list plus a secret header. Do not describe this topology
as end-to-end TLS or as enforcing TLS 1.2 at the viewer.

**Demo video (under three minutes)**

`[PUBLIC_YOUTUBE_OR_VIMEO_URL]`

**Project thumbnail**

`docs/assets/devpost-thumbnail-v2.png` — 1536×1024 PNG (3:2, under 5 MB).

**Built-with tags**

`Rust`, `CockroachDB`, `Vector Search`, `Agent Skills`, `AWS`, `Amazon ECS`,
`AWS Fargate`, `Amazon S3`, `Application Load Balancer`, `Amazon CloudFront`,
`Amazon ECR`, `AWS Secrets Manager`, `Amazon CloudWatch`, `Terraform`, `MCP`,
`model2vec`, `Axum`, `SQLx`. Add `OSTK` only if the optional adapter is actually
used in a final captured artifact; it is not part of the default proof path.

The listed AWS services were exercised by the live deployment and evidence
capture, not merely declared in Terraform. Remove a tag before submission if
its live integration is later removed or cannot be shown safely.

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

Run `./docs/assets/verify-media.sh` before uploading the gallery. The script
checks the committed image formats, dimensions, and conservative 5 MB limit;
the manual visual acceptance checks live in `docs/assets/README.md`.

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
explicit conflict. ECS workers are disposable; the live deployment keeps
CockroachDB Cloud as the memory source of truth after every task is replaced.
A forced deployment changed the complete serving task set to a fully disjoint
set, while public lexical/dense RRF continued to return the exact action and
escalation claims 6 and 8.

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

- **Rust 1.94** application and MCP protocol with bounded inputs/outputs,
  running as the immutable ARM64 production image on ECS/Fargate.
- **CockroachDB Cloud 26.2.5** is the live memory plane for corpus chunks,
  typed claims, passage vectors, conflicts, idempotency receipts, and events.
  Migration and the three-record seed completed; `/api/status` reports schema
  version 1 and the required database capabilities.
- **Distributed Vector Indexing** with project- and source-prefixed
  `VECTOR(512)` cosine indexes, plus a stored `TSVECTOR` inverted index for
  hybrid recall.
- **CockroachDB Agent Skills** pinned at commit `e14e86d`: the coding agent
  invoked the transaction and SQL skills, then used their guidance to shape the
  fresh `40001` retry loop, embedding-outside-transaction boundary, SQL
  invariants, connection pooling, concurrency tests, and EXPLAIN plan gates.
  The full skill-to-code/test trace is in `docs/AGENT_SKILLS_AUDIT.md`.
- The checked-in **AWS ECS/Fargate, Application Load Balancer, and CloudFront**
  deployment targets a replaceable public demo task, **S3** for private
  content-addressed model delivery, **Secrets Manager** for Cockroach TLS URLs,
  **ECR** for scanned immutable images, and **CloudWatch** for logs/Container
  Insights. A
  dedicated one-off Fargate task definition runs the deterministic reference
  policy agent under A/B/C deployment identities;
  `deploy/aws/run-reference-agent.sh` verifies their correlated durable-memory
  chain. Verified pre-polish revision 3 cloud evidence run
  `devpost-final-20260814T021819Z`, using reference-agent task definition
  revision 3, verified decision/action/incompatible/escalation claims 5/6/7/8
  and open conflict 2 across all four tasks. The replacement wrapper verified
  exact claims 6 and 8 after a fully disjoint serving-task-set change. The
  current revision 4 serving image adds the conflict-first UI and bounded API
  polish from `97eba7d`; it passed CI and separate public smoke checks, but the
  four-task and replacement receipts were not rerun on revision 4.
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
  one-off DDL credentials from the least-privilege runtime secret, now proven
  through live migration, seed, serving, four-task agent, and replacement runs.

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
| CockroachDB persistent memory | Local 26.2 schema/round-trip/conflict tests; cloud reference-agent, health, and restart capture | Live Cloud 26.2.5/schema 1; migration, seed, four-task chain, and exact post-replacement recall verified |
| Distributed Vector Indexing | DDL and local representative `EXPLAIN`; cloud plan and reference-agent lexical+dense RRF capture | Live capability flags, cosine operation, dimension 512, and lexical/dense RRF verified. The [publication-safe Cloud `EXPLAIN`](evidence/cockroach-cloud-explain.txt) selects both C-SPANN indexes and the lexical inverted index for the exact production SQL shapes on 10,001 disposable rows; all assertions passed |
| CockroachDB Agent Skills | Pinned coding-agent invocation audit mapping each skill to decisions, code/tests, and accepted deviations | Ready in repository |
| AWS service | ECS/ALB/CloudFront/S3/Secrets/ECR/CloudWatch Terraform; one-off reference-agent task/wrapper; LocalStack contract harness | Live AWS migration/seed, healthy service, four reference-agent Fargate tasks, and complete serving-task replacement verified |
| Public open source | Source, licenses, locked dependencies, setup and sample data | Published and anonymously verified at <https://github.com/os-tack/ostk-fleet-recall> |
| Functional URL | HTTPS landing page, bounded recall, `/healthz` | Live at <https://d13zrqfh66r7ub.cloudfront.net>; health, status, and hybrid recall verified |
| Public video <3 min | Live AWS UI plus reviewed cloud agent/replacement receipts by default, then YouTube/Vimeo link and final duration; standalone Fleet Recall is optional local footage and OSTK is an optional alternate | 46-second 1600×900 sanitized rehearsal rendered; `[RENDER_LIVE_NARRATE_AND_UPLOAD]` |

## Judging-criteria evidence map

The [official judging criteria](https://cockroachdb-ai.devpost.com/rules) are
equally weighted. This table keeps the final story balanced instead of
treating successful vector search as the whole project.

| Criterion | Strongest repository evidence | Final proof still to capture |
|---|---|---|
| Agentic Memory Design | Hybrid lexical/vector recall, typed claims, provenance, correction-aware conflict membership, and verified revision 3 cloud evidence run `devpost-final-20260814T021819Z` across four Fargate tasks | Show a reviewed, redacted excerpt of the correlated CockroachDB-backed result in the final video |
| Technological Implementation | Prefix-scoped C-SPANN and inverted indexes, backend-neutral Recall extraction, short serializable retries, immutable model identity, conformance and adversarial tests, plus the publication-safe Cloud plan artifact | Show a reviewed excerpt of the three passing Cloud plans and current revision 4 image identity in the final video; label the revision 3 receipts separately |
| Real-World Impact | A recalled schema-migration decision changes the next agent's rollout action; an incompatible memory stops rollout and produces a cited operator handoff | Explain how the same pattern applies to long-running coding, operations, and research fleets |
| Product Readiness | Trusted deployment scope, bounded input/output and hydration, least-privilege runtime/migrator separation, live HTTPS health, idempotent receipts, four-task proof, and exact recall after full task replacement | Capture final publication-safe footage without exposing identifiers or secrets; explain the CloudFront-to-ALB HTTP boundary accurately |
| Creativity & Originality | Local Recall stays local-first while Fleet Recall adds a distributed memory plane; disagreement is durable first-class state rather than an overwrite or a hidden rank choice | Make the conflict-aware memory-to-action transition the visual center of the final video |

## Final video plan (target 2:40)

[`VIDEO_DEMO.md`](VIDEO_DEMO.md) is the single authoritative recording plan.
It opens on the live conflict-first interface and follows three acts: **ASK →
DISAGREE → SURVIVE**, followed by a short local-first-to-fleet coda. Do not use
an older architecture-first timeline or replace serving tasks manually while
filming.

The current revision 4 public UI and the verified pre-polish revision 3 cloud
receipts are separate evidence sources and must stay visibly labeled. Local or
rehearsal terminal footage is supporting material, never AWS evidence. The
final export needs narration or another accessible audio track; the silent
rehearsal is not submission-ready.

## Final release checklist

- [x] Public repository URL works in a logged-out browser.
- [x] Licenses, dependency lockfile, sample NDJSON, setup, architecture, and
      pre-existing-work disclosure are present.
- [x] CI completed green for `97eba7d` on Rust 1.94, including the CloudFront
      front door, patched Go builder image, and conflict-first UI/API release.
- [x] CockroachDB Cloud uses TLS, a non-admin runtime user, backups, and an
      allowlist/private route.
- [x] Run one migration task, then verify `health` and all required indexes.
- [x] Capture publication-safe Cloud `EXPLAIN` evidence with the exact
      production project-vector, source-vector, and lexical SQL shapes on a
      10,001-row disposable fixture; all three index assertions pass,
      production was untouched, the fixture database was dropped, and the
      temporary workstation network rule was removed.
- [x] Push an immutable ECR image and run at least one healthy ECS task.
- [x] Public URL supports landing page, bounded recall, and `/healthz`; mutation
      remains unavailable or authenticated/rate-limited.
- [x] CloudFront's default HTTPS certificate is valid; the TLSv1-minimum viewer
      policy and restricted HTTP origin hop are documented without overclaim.
- [ ] Review every final screenshot, shell excerpt, and video frame for secrets
      and infrastructure identifiers before publication.
- [x] Stop/replace the complete serving task set and verify the same exact
      memory remains through lexical/dense RRF.
- [x] Run `deploy/aws/run-reference-agent.sh` against the healthy submission
      stack; preserve its verified correlated JSON and redacted public-demo
      recall evidence. Do not substitute a local or handcrafted result.
- [ ] Video is public, under three minutes, legible at 1080p, and explicitly
      names CockroachDB tools and AWS services.
- [ ] `./docs/assets/verify-media.sh --final-video <final.mp4>` passes; captions
      are accurate, playback/embedding works from a logged-out browser, and the
      Devpost preview plays without authentication.
- [ ] Devpost fields replace every bracketed placeholder and identify how each
      qualifying tool/service is used.
- [ ] Submit before August 18, 2026 at 5:00 PM EDT / 4:00 PM CDT.
- [ ] Keep the working project free and unrestricted through September 15, 2026
      at 5:00 PM EDT / 4:00 PM CDT; retain 60-day logs and ALB deletion
      protection, with no early scale-to-zero or teardown.
