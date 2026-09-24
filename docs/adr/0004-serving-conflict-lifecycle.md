# ADR 0004: Serving conflict lifecycle on the legacy ledger

- Status: accepted. Three slices are implemented: `remember(retract)`,
  detector-verified conflict close with member restore, `recall(get)` with
  `kind=conflict`, private search hiding retired claims' synthetic chunks,
  `remember(supersede)`, and, with migration 29, the per-conflict lifecycle
  log, `remember(acknowledge)`, concession `remember(resolve)`, logged
  closes, and the lifecycle overlay and history on reads. Adjudication
  (`dismiss` and `waive`) is a later slice and is not served.
- Date: 2026-09-24
- Scope: how the serving writer lets agents retire their own claims and how a
  `same_key_functional_value_v2` conflict leaves the `open` state. Decision
  D5 is reserved for the adjudication slice.

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

**Supersede.** `remember(supersede)` retires a claim under the same owner
checks and writes its successor in the same transaction. The successor must
keep the predecessor's `kind`, its normalized `claim_key` (both may be absent),
and its `conflict_eligible` flag. Otherwise the request is refused as
`successor_kind_mismatch`, `successor_key_mismatch`, or
`successor_eligibility_mismatch`. The predecessor moves to `superseded` first,
so the successor goes through record's own claim-writing and detection steps
against only the claims that stay current, and may open, reopen, or join the
key's v2 conflict. Its actor is the trusted agent, its origin must be
`operator_asserted`, and its `recorded` claim event names the predecessor.
The predecessor's `superseded_by` then points at the successor. After that,
the key's lineage and current claims are locked again and re-evaluated under
D3: a successor compatible with the rest lets the conflict close, and an
incompatible one keeps it open as a member in its predecessor's place. The
predecessor keeps its historical memberships. The response returns the
successor as `claim` and the predecessor as `superseded`, and the one keyed
event is `claim_superseded`. The successor's own `claim_recorded` event is
unkeyed. The embedding is computed before the transaction, after a fast
receipt lookup, exactly as for record. The record path's SQL and statement
order are shared through extracted helpers and are unchanged.

Keeping kind, key, and eligibility is what makes a supersede safe to serve.
Without it an agent could end a dispute by moving its claim to another key,
downgrading it to a `note`, or dropping its value, which would retire one side
of a live incompatibility without the detector ever seeing the change. Within
those limits, a supersede may change the value, polarity, validity window,
text, confidence, and support.

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

## D4 — Acknowledgements and closes are events; `memory_conflicts` stays byte-stable

**Decision.** Migration 29 adds one append-only table,
`memory_conflict_lifecycle_events_v1`, keyed by `(tenant_id, project,
conflict_id, event_seq)` with no foreign key. It admits four event kinds:
`acknowledged` and `waived`, which leave the conflict row alone
(`result_revision = episode_revision`), and `resolved` and `dismissed`, which
record a close that moved the row one revision on. An episode is one
`(conflict_id, revision)` of an open conflict, so a `record` reopen, which
bumps the revision, starts a new episode with no acknowledgements. The table,
its CHECK constraints, and three indexes (one event per mutation and conflict,
one acknowledgement per actor and episode, and a covering per-episode read
index) are the only schema change; `memory_conflicts`,
`memory_conflict_members`, and migrations 1 through 28 are unchanged.

`remember(acknowledge)` appends an `acknowledged` event for the caller's view
of an open v2 conflict (revision checked under the lineage lock) and never
updates `memory_conflicts`. An agent's second acknowledgement of the same
episode commits with `applied = false`. `remember(resolve)` is a concession:
it takes the conflict's revision and member count, retracts only the caller's
own current member claims it names (D2), and closes the conflict only through
D3's verification. If any incompatible pair remains, or the Rust and SQL pair
sets disagree, the whole request is refused (`still_incompatible`,
`verification_divergence`) and the retractions roll back. With no claims
named it only re-verifies, which anyone may ask for. Every close by the
serving writer (retract, supersede, or resolve) appends a `resolved` event
attributed to the detector (`actor_kind = detector`, actor
`same_key_functional_value_v2`, reason kind `no_current_incompatibility`),
with the triggering operation, idempotency key, and a `cause` payload naming
the agent and the claims it retracted or superseded.

Reads attach a `lifecycle` overlay derived from the episode's newest events
with a separate autocommit statement after the main read, so a failure only
degrades coverage to `lifecycle_overlay: unavailable`. Its `read_side` follows
ADR 0003's addendum exactly: `open` and `acknowledged` read `open`, an active
unexpired waiver whose member count still matches reads `waived`, and
`resolved` and `dismissed` read `clear`. `recall(get, kind=conflict)` also
returns the log (at most 256 events) and reports the revision ranges no event
covers as `unlogged_transitions`. `record` still opens and reopens conflicts
without logging, and closes made before migration 29 were not logged; both
show up there, and a close without its event reads `closed_unlogged`.

**Why.** Acknowledgement is triage metadata that must not change severity or
surfacing, and ADR 0003 keeps `memory_conflicts` byte-stable. An append-only
log gives every transition an attributed, replay-safe record without touching
the record hot path or the publication tables. No foreign key keeps bulk
deletes of `memory_conflicts` working and means no new parent grant. A
concession that could leave an incompatible pair behind would let one agent
declare a dispute over; refusing it keeps `resolved` meaning "no live
incompatibility".

## D6 — Refusals are typed and roll back

**Decision.** A lifecycle precondition failure is a typed refusal with a
closed code (`not_found`, `not_owner`, `not_operator_asserted`,
`not_current`, `stale_revision`, `stale_member_count`, `not_open`,
`not_member`, `still_incompatible`, `verification_divergence`,
`legacy_lineage`, `bound_exceeded`, `successor_kind_mismatch`,
`successor_key_mismatch`, `successor_eligibility_mismatch`,
`lifecycle_unavailable`, and codes reserved for adjudication), a message, and
bounded details. It is returned from inside the serializable closure, so the
transaction and its receipt reservation roll back: nothing is committed and
the idempotency key stays free. MCP reports it as JSON-RPC `invalid_params`
with `data.outcome = "not_applied"`, never through the outcome-unknown path.
A committed request replays before any precondition, so retrying a
committed lifecycle request returns its stored result rather than
`not_current` or `not_open`. That includes the surface check: a writer that
no longer serves an action (for example after
`FLEET_RECALL_REMEMBER_LIFECYCLE=disabled`, or after a restart whose probe
found no lifecycle grants) reads the key's receipt before refusing. It replays a committed identical request, reports any
other use of the key as an idempotency conflict, and refuses with
`lifecycle_unavailable` only when no receipt holds the key, so the refusal's
promise that the key was not consumed stays true.

## D7 — The conflict lifecycle is gated on a startup capability

**Decision.** `MINIMUM_RECALL_SCHEMA_VERSION` stays 18. At startup the private
writer checks that the schema prefix reaches 29 and runs an
`INSERT ... SELECT ... WHERE false` on the lifecycle log in a transaction it
rolls back. Privileges are checked when the statement is planned, including
ones held through role membership, and nothing is written. Only a pass mints
the capability that lets the ledger serve `acknowledge` and `resolve`, log
closes, and read the overlay and history; SQLSTATE 42501 means "not served",
and any other error stops startup. The runtime policy gains a separate
migration-29 gate and `SELECT`/`INSERT` on the log, so its exact grant matrix
grows from 47 to 49 rows. The publication policy, its eight tables, and
`PUBLICATION_READ_TABLES` do not change.

The rollout is four independently safe steps: deploy the binary (the probe
finds nothing and only the claim lifecycle is served), `migrate`, drain
`fleet_writer` and re-apply the runtime policy, then restart `serve`. The
probe runs only at startup, so a restart must follow any later grant change.
Rolling back means running the previous `serve` binary; an older `migrate`
binary refuses the database with `VersionMissing(29)`.

**Why.** Coupling every binary to migration 29 would make a missing grant
fail every conflicting `record` as an unknown outcome. Gating on a probed
capability keeps `record` and the claim lifecycle byte-for-byte unchanged on
every schema and grant state, and a writer never advertises an action its
role cannot perform.

## Clarification of ADR 0002 D3

`remember(record)` wire acceptance, SQL, responses, and stored receipts are
unchanged; new response fields are omitted when empty. The MCP server derives
`tools/list` from the service's remember surface. The record-only surface,
which the public demo always uses and `FLEET_RECALL_REMEMBER_LIFECYCLE=disabled`
restores on the private writer, emits the historical tool list byte for byte.

## Consequences

- Agents can withdraw or correct their own mistakes, and conflicts close when
  the data no longer supports them.
- Authority is only as strong as `FLEET_RECALL_AGENT` over the shared
  `fleet_writer` credential; authenticated workload identity remains future
  work (see `docs/SECURITY.md`).
- Closes are audited in `memory_events` and `memory_claim_events`, and, once
  the capability is present, in the per-conflict lifecycle log. `record`
  opens and reopens are not logged; history reports them as unlogged
  transitions.
- Agents can acknowledge a conflict and concede their own side of it, but no
  agent can yet close a conflict whose remaining sides it did not author;
  that needs adjudication by a non-implicated agent (D5, a later slice).
- Publication reads are unchanged: the public demo still returns retired
  claims' synthetic chunks, does not serve conflict lookup by id, and never
  reads the lifecycle log.
