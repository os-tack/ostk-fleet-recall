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

The fixture uses evidence schema version 1 and explicitly records its source,
CockroachDB backend, MCP transport, and `ostk_used`, `llm_used`, and
`cloud_used` provenance booleans. Its `capture` value is
`sanitized-rehearsal`; it deliberately omits a generation timestamp so it
cannot be mistaken for fresh evidence.

For a new standalone run, `demo/video/capture-fleet.sh <run-id>` writes the
same schema with `capture: "live"`, a UTC timestamp, and the requested run ID
to ignored `target/fleet-demo/<run-id>/final.json`. The capture is published
atomically only after `demo/video/verify.sh` confirms all displayed invariants
and correlations. This is the primary live video path and does not use OSTK or
an LLM.

These are separately deployment-bound MCP processes, not evidence of an LLM
making an autonomous choice. The opt-in adapter in `docs/OSTK_DEMO.md` is a
separate integration for users who explicitly choose real OSTK-orchestrated
model sessions; its evidence has a different schema and is accepted only by
the explicit `--ostk-live` video mode.

The full `deploy/localstack/smoke.sh` additionally validates S3 and Secrets
Manager contracts plus stateless application replacement. LocalStack license
activation is an external prerequisite, so failure to reach its licensing
server must not be presented as application evidence.

## Live cloud receipts

`deploy/aws/run-reference-agent.sh` produces the correlated agent receipt and
`deploy/aws/run-replacement-proof.sh` produces the full-serving-task-set
replacement/persistence receipt. Run
`deploy/aws/verify-publication-receipts.sh REFERENCE_JSON REPLACEMENT_JSON` to
validate and cross-correlate them before publication. The verifier rejects
common secret and AWS-account leaks, but chosen run/project/service names and
the public hostname still require human review.

The final-image submission run `devpost-final-20260814T021819Z` produced both
verified receipts against <https://d13zrqfh66r7ub.cloudfront.net> and
CockroachDB Cloud. Migration and the three-record seed had already succeeded.
The reference receipt used task definition revision 3 and correlated four
one-off Fargate tasks: decision claim 5, action claim 6 citing it, incompatible
claim 7, open conflict 2, and escalation claim 8 citing that conflict. The
public check observed exact action/escalation claims 6 and 8. The replacement
receipt exercised serving task definition revision 3 and recorded a fully
disjoint task-set change; both before and after observations returned those
same exact claims through lexical/dense RRF.

The sanitized status proof reports CockroachDB 26.2.5, schema version 1,
enabled vector, lexical, and conflict-membership indexes, working cosine
distance, and embedding dimension 512. The receipts and operational logs are
kept in the ignored operator evidence directory; no raw log, task ARN, account
ID, secret ARN, credential, or database URL is checked in here.

CloudFront's default certificate protects the viewer connection. Its generated
hostname uses AWS's TLSv1-minimum viewer policy, and the origin hop to the ALB
is restricted HTTP rather than end-to-end TLS. Do not claim a TLS 1.2 viewer
minimum or end-to-end encryption for this topology.

The wrappers' mock tests alone remain capture-tooling evidence, not cloud
evidence. Index-presence status and RRF diagnostics likewise do not prove
physical plan selection, so the separate publication-safe
[CockroachDB Cloud `EXPLAIN` artifact](cockroach-cloud-explain.txt) records that
proof. Its SHA-256 is
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

The final public video and Devpost-controlled fields are still pending. CI is
green at `19e626b`, including the CloudFront front door and the follow-up
patched Go builder image.
