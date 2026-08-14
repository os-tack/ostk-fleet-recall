# Local and cloud evidence

`local-fleet-scenario.json` is the checked-in, sanitized rehearsal form of
`deploy/localstack/fleet-demo.sh --json` output. The underlying scenario ran
against a fresh CockroachDB 26.2.3 node and the repository's release container
on August 13, 2026. It proves the deterministic application contract:

- Agent identity A records a decision and an identical retry returns its
  stored receipt.
- Identity B finds A's projected chunk through lexical+dense RRF, rejects a
  cross-project request, and records a rollout action that cites A's claim.
- Identity C records an incompatible value under the same typed key.
- Both decision claims become the exact two members of one open conflict.
- Identity B records a pause/escalation action that cites that conflict.

The fixture's local receipt-format version is 1 and explicitly records its
source, CockroachDB backend, MCP transport, and `ostk_used`, `llm_used`, and
`cloud_used` provenance booleans. Its `capture` value is
`sanitized-rehearsal`; it deliberately omits a generation timestamp so it
cannot be mistaken for fresh evidence.

For a new standalone run, `demo/video/capture-fleet.sh <run-id>` writes the
same schema with `capture: "live"`, a UTC timestamp, and the requested run ID
to ignored `target/fleet-demo/<run-id>/final.json`. The capture is published
atomically only after `demo/video/verify.sh` confirms all displayed invariants
and correlations. This is optional local terminal footage, not the default
final-cut path or cloud evidence, and it does not use OSTK or an LLM. The final
cut instead leads with the live AWS UI and reviewed cloud receipts as specified
in [`VIDEO_DEMO.md`](../VIDEO_DEMO.md).

These are separately deployment-bound MCP processes, not evidence of an LLM
making an autonomous choice. The opt-in adapter in `docs/OSTK_DEMO.md` is a
separate integration for users who explicitly choose real OSTK-orchestrated
model sessions; its evidence has a different schema and is accepted only by
the explicit `--ostk-live` video mode.

The full `deploy/localstack/smoke.sh` additionally validates S3 and Secrets
Manager contracts plus stateless application replacement. LocalStack license
activation is an external prerequisite, so failure to reach its licensing
server must not be presented as application evidence.

## Cloud release evidence

The current live release runs immutable image tag `git-56b577c82b9c` at source
commit `56b577c82b9c5a5c80d73103f7f6b56d51698872`, with the serving,
migration, seed, and reference-agent task-definition families all at revision
10 and the service 1/1 healthy. Its idempotent rich-seed task exited zero and upserted
exactly 552 rows: 346 documentation chunks, 2 code chunks, and 204 operations
chunks. Public API results returned the exact release revision and inclusive
source-line ranges. Final desktop and 390px mobile QA verified safe inline
Markdown, immutable exact `#Lx-Ly` links, a relative repository link rendered
as a code-styled anchor, and no horizontal overflow. The final seven-query smoke
gate passed. The ECR Basic OS-package scan is `COMPLETE` with an empty
finding-severity count; this
does not claim Rust, Go, or application-dependency coverage. GitHub Actions run
[`31832684235`](https://github.com/os-tack/ostk-fleet-recall/actions/runs/31832684235)
completed all five jobs successfully.

The sanitized, **historical**
[revision-7 public relevance receipt](public-relevance-efe6fbf-20260814.json)
records the seven bounded queries, ordered top sources, exact query-local
conflict associations, retrieval bounds, release identity, and narrowly scoped
ECR Basic OS-package scan result. It is public HTTP smoke evidence—not a fresh
revision-10 smoke receipt, write-chain, or replacement proof. The accompanying
[`verify-public-relevance.sh`](verify-public-relevance.sh) cross-checks the
receipt against the ignored operator captures when those private files are
available.

### Historical revision-6 receipts

`deploy/aws/run-self-audit-proof.sh` produces the source-backed documentation/
code conflict receipt, `deploy/aws/run-reference-agent.sh` produces the
correlated policy-agent receipt, and `deploy/aws/run-replacement-proof.sh`
produces the full-serving-task-set replacement/persistence receipt. Run
`deploy/aws/verify-publication-receipts.sh REFERENCE_JSON REPLACEMENT_JSON` to
validate and cross-correlate them before publication. The verifier rejects
common secret and AWS-account leaks, but chosen run/project/service names and
the public hostname still require human review.

The historical revision-6 publication set is checked in here. Its
reference-agent and replacement proofs were not rerun for revision 10:

- [source-conflict self-audit](self-audit-devpost-self-audit-20260814T133640Z-rev6.json);
- [reference-agent run](reference-agent-devpost-final6-20260814T143523Z.json);
- [full serving-task replacement](replacement-devpost-final6-20260814T143523Z.json); and
- [cross-receipt validation](publication-validation-devpost-final6-20260814T143523Z.json).

The self-audit receipt proves that semantic recall surfaced the exact
`examples/README.md`, `src/mcp/tools.rs`, and `src/application.rs` chunks behind
incompatible Boolean claims 9 and 10, then projected their exact open conflict
3. The receipt records two matched supported claims, all three surfaced source
chunks, lexical+dense RRF, and no support truncation.

Historical release-bound run `devpost-final6-20260814T143523Z` used
reference-agent task definition revision 6 and correlated four one-off Fargate
tasks: decision claim 15, action claim 16 citing it, incompatible claim 17,
open conflict 5, and escalation claim 18 citing that conflict. The public check
observed exact action/escalation claims 16 and 18. The replacement receipt
exercised serving task definition revision 6 and recorded a fully disjoint
task-set change; both before and after observations returned those same exact
claims through lexical/dense RRF. The validation receipt cross-checked the two
artifacts.

Those historical receipts use immutable ARM64 image tag `git-ba884f24858a`,
digest
`sha256:7d154a37fff589d2e68ec71c230025f3324cea96f85f7b51158f2d3097f2320b`,
and source revision `ba884f24858a58b09a915e0358e60e7fcc7e2c34`. Serving,
migration, seed, and reference-agent task definitions are all revision 6. The
schema-2 migration, three-record bootstrap, and verifier-gated 536-chunk rich
seed completed before proof capture. These facts describe the revision-6
receipt boundary, not the current revision-10 deployment.

The historical sanitized status proof reports CockroachDB 26.2.5, schema
version 2, enabled vector, lexical, conflict-membership, and
claim-support-chunk indexes, working cosine distance, and embedding dimension
512. Raw receipts and
operational logs remain in the ignored operator evidence directory; the four
reviewed JSON files above contain no task ARN, account ID, secret ARN,
credential, or database URL.

CloudFront's default certificate protects the viewer connection. Its generated
hostname uses AWS's TLSv1-minimum viewer policy, and the origin hop to the ALB
is restricted HTTP rather than end-to-end TLS. Do not claim a TLS 1.2 viewer
minimum or end-to-end encryption for this topology.

The wrappers' mock tests alone remain capture-tooling evidence, not cloud
evidence. Index-presence status and RRF diagnostics likewise do not prove
physical plan selection, so the separate publication-safe
[CockroachDB Cloud `EXPLAIN` artifact](cockroach-cloud-explain.txt) records that
historical proof. It was not rerun during the revision-10 cutover. Its SHA-256 is
`0ec1fb873b2305adaf7f83a39c09e1132a7f1916d0c962a153823dd1bcff28f2`.

The capture ran the exact production project-vector, source-vector, and lexical
SQL shapes through SQLx on CockroachDB Cloud Basic in AWS `us-east-1`, version
26.2.5, using a disposable 10,001-row fixture. The sanitized plans select:

- `vector search` with `memory_chunks_semantic_idx`;
- `vector search` with `memory_chunks_source_semantic_idx`; and
- `scan` with `memory_chunks_lexical_idx`.

All three assertions passed. The first lexical plan ran immediately after
`ANALYZE` and briefly saw stale zero-row statistics. The unchanged query
selected the inverted index after the fresh statistics became visible roughly
two minutes later; the evidence does not use or imply `FORCE_INDEX`. The
production database was neither queried nor modified, the disposable database
was dropped, and the temporary workstation network rule was removed after
capture.

The final public video and Devpost-controlled fields are still pending.
