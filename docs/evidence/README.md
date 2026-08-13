# Local evidence

`local-fleet-scenario.json` is the sanitized output of
`deploy/localstack/fleet-demo.sh --json` against a fresh CockroachDB 26.2.3
node and the repository's release container on August 13, 2026. It proves the
deterministic application contract:

- Agent identity A records a decision and an identical retry returns its
  stored receipt.
- Identity B finds A's projected chunk through lexical+dense RRF, rejects a
  cross-project request, and records a rollout action that cites A's claim.
- Identity C records an incompatible value under the same typed key.
- Both decision claims become members of one open conflict.
- Identity B records a pause/escalation action that cites that conflict.

These are separately deployment-bound MCP processes, not evidence of an LLM
making an autonomous choice. The opt-in OSTK demo in `docs/OSTK_DEMO.md` adds
real OSTK-orchestrated model sessions; its evidence must be captured only after
that explicit, potentially billable run succeeds.

The full `deploy/localstack/smoke.sh` additionally validates S3 and Secrets
Manager contracts plus stateless app replacement. LocalStack license
activation is an external prerequisite, so failure to reach its licensing
server must not be presented as application evidence.
