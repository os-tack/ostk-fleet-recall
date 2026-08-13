# ADR 0001: Local Recall and Fleet Recall are sibling providers

- Status: accepted
- Date: 2026-08-13

## Decision

`ostk-recall` remains local-first. `ostk-fleet-recall` is a new sibling daemon
that implements the same agent-facing `recall`/`remember` MCP contract using a
CockroachDB durable substrate.

The plugin boundary is a typed semantic service contract, not a dynamically
loaded Rust library and not a generic SQL abstraction. OSTK can select either
executable as its Recall driver. Shared Rust crates supply stable domain,
embedding, retrieval-ranking, and wire types.

Every fleet operation executes inside a trusted `tenant_id` plus caller scope:
`project`, `agent`, `session_id`, and `privacy_tier`. The tenant is deployment
configuration and cannot be overridden by MCP arguments.

## Consequences

- Local users do not acquire a network service or CockroachDB dependency.
- Fleet Recall can deploy and version independently.
- Cockroach transactions implement semantic operations atomically; database
  transaction handles never leak into the shared API.
- Initial development may duplicate a small amount of orchestration while
  upstream backend-neutral interfaces are extracted.
- The shared corpus is durable; transient attention may remain task-local until
  an explicit persistence policy is implemented.

## Submission boundary

The hackathon submission is this new repository and its Cockroach/AWS
adaptation. Existing Recall and OSTK code are disclosed as pre-existing
frameworks.
