# Local evidence

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
