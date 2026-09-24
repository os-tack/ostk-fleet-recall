# ADR 0004: Serving conflict lifecycle on the legacy ledger

- Status: accepted. The first slice is implemented: `remember(retract)`,
  detector-verified conflict close with member restore, `recall(get)` with
  `kind=conflict`, and private search hiding retired claims' synthetic chunks.
  Supersede, acknowledgement, concession resolve, and adjudication are later
  slices and are not served.
- Date: 2026-09-24
- Scope: how the serving writer lets agents retire their own claims and how a
  `same_key_functional_value_v2` conflict leaves the `open` state. Decisions
  D4, D5, and D7 are reserved for the later slices (lifecycle log and
  acknowledgement, adjudication, and rollout).

## Context

The served ledger could record claims and open, join, and reopen conflicts,
but nothing could close one. A `disputed` claim stayed disputed even after its
author knew it was wrong, and `recall(conflicts)` accumulated open conflicts
that no agent could act on. The target discrepancy model
(`docs/DYNAMIC_MEMORY_ARCHITECTURE.md`, DISC-01..05 and AUTH-03) and its
0027 ledger describe the full lifecycle, and ADR 0003's addendum fixes the
read-side mapping: a conflict may read `Clear` only when no live
incompatibility remains.

## D1 — A native lifecycle on the served ledger

**Decision.** The lifecycle runs on `memory_claims`, `memory_conflicts`, and
`memory_conflict_members`, inside the same serializable, receipt-guarded
transactions as `remember(record)`. The 0027 discrepancy ledger stays unwired.

**Why.** Writing the 0027 ledger requires accepted-event ids (the fenced
`assert` route, ADR 0002 D3/D4), registry-resolvable policy and lineage
bodies, the D4 writer-authority witness in `serve`, a mapping from deployment
agents to contract principals, and runtime grants on the 0027 tables. None of
that exists in serving today. The first slice needs no migration, no grant,
and no change to `MINIMUM_RECALL_SCHEMA_VERSION`, so it can ship on its own. A
later bridge can map served lifecycle transitions onto the discrepancy
contracts once those prerequisites land.

## D2 — Retirement is owner-only

**Decision.** `remember(retract)` changes a claim only when the locked row
names the trusted `FLEET_RECALL_AGENT` as its actor, has
`operator_asserted` origin, is `active` or `disputed`, and is at the
caller's expected revision. The `UPDATE` repeats every predicate. A claim with
no recorded actor is retired by no one. Retraction changes the claim's state
only: its synthetic chunk, embeddings, support, and conflict memberships
remain as history.

**Why.** DISC-03 forbids changing another agent's claim applicability. The
revision check turns a lost update into a correctable refusal instead of a
silent overwrite.

## D3 — Resolution is detector-verified only

**Decision.** No request names a conflict outcome. After a lifecycle change,
the server recomputes the key's incompatible pairs over the locked
lifecycle-current claims, once in Rust and once in SQL with the record
detector's exact predicate. Only when both agree that no pair remains does the
server set the v2 conflict to `resolved`, bump its revision, and write
`resolution_kind = no_current_incompatibility` with a fixed-template reason.
A disagreement leaves the conflict open and reports `divergent`. The close then
restores each disputed member to `active` unless another open conflict still
holds it. The legacy `same_key_typed_value` row on the same key is not such a
conflict: a key gains a v2 lineage beside a legacy row only through
reconciliation, which preserves that row unchanged, never closes it, and hands
the key's disputes to v2, and every current-facing read already prefers v2
over it. Any other open membership, of any detector, still holds the claim.
There is no `suppressed` outcome and no partial restore.

The locks follow the record path's order (the key's lineage rows, then its
current claims in ascending id order), so lifecycle and record calls serialize
on one lock, and SSI conflicts surface as `40001` and retry. Record keeps
reopening a resolved lineage when a new incompatible value arrives; lineage
membership is historical, so `Claim.conflict_ids` keeps listing it.

**Why.** ADR 0003's addendum allows `Clear` only when no live incompatibility
remains, and AUTH-03 lets anyone trigger a check whose outcome depends on data
alone. The invariants this preserves are: every disputed claim belongs to at
least one open current lineage (its key's v2 lineage when one exists,
otherwise an unreconciled legacy one), and every open v2 conflict keeps at
least one incompatible current pair.

## D6 — Refusals are typed and roll back

**Decision.** A lifecycle precondition failure is a typed refusal with a
closed code (`not_found`, `not_owner`, `not_operator_asserted`,
`not_current`, `stale_revision`, `legacy_lineage`, `bound_exceeded`,
`lifecycle_unavailable`, and codes reserved for later slices), a message, and
bounded details. It is returned from inside the serializable closure, so the
transaction and its receipt reservation roll back: nothing is committed and
the idempotency key stays free. MCP reports it as JSON-RPC `invalid_params`
with `data.outcome = "not_applied"`, never through the outcome-unknown path.
A committed request replays before any precondition, so retrying a
committed retract returns its stored result rather than `not_current`. That
includes the surface check: a writer that no longer serves `retract` (for
example after `FLEET_RECALL_REMEMBER_LIFECYCLE=disabled`) reads the key's
receipt before refusing. It replays a committed identical retract, reports any
other use of the key as an idempotency conflict, and refuses with
`lifecycle_unavailable` only when no receipt holds the key, so the refusal's
promise that the key was not consumed stays true.

## Clarification of ADR 0002 D3

`remember(record)` wire acceptance, SQL, responses, and stored receipts are
unchanged; new response fields are omitted when empty. The MCP server derives
`tools/list` from the service's remember surface. The record-only surface,
which the public demo always uses and `FLEET_RECALL_REMEMBER_LIFECYCLE=disabled`
restores on the private writer, emits the historical tool list byte for byte.

## Consequences

- Agents can withdraw their own mistakes, and conflicts close when the data no
  longer supports them.
- Authority is only as strong as `FLEET_RECALL_AGENT` over the shared
  `fleet_writer` credential; authenticated workload identity remains future
  work (see `docs/SECURITY.md`).
- Closes are audited in `memory_events` and `memory_claim_events` only; a
  per-conflict lifecycle log is a later slice.
- Publication reads are unchanged: the public demo still returns retired
  claims' synthetic chunks and does not serve conflict lookup by id.
