# ADR 0003: Consolidation derives durable memory; conflict tolerance is durable policy

- Status: proposed
- Date: 2026-08-16

## Context

The service contract reserves `RememberAction::Consolidate` and
`RecallAction::Synthesize`, and the schema reserves the `summarizes`,
`derived_from`, `part_of`, and `continues` link relations, but no consolidation
semantics are defined or implemented. Without them, episodic claims accumulate
without a governed path to durable semantic memory, and any future summarization
feature would be designed ad hoc against EVID-01, REPLAY-01, and DISC-03.

Separately, the implemented conflict lifecycle admits only `open`, `resolved`,
and `dismissed`. A real and recurring operational state — "this incompatibility
is verified and known, but we deliberately decline to resolve it now" — has no
honest representation. Leaving the conflict `open` makes triaged risk
indistinguishable from untriaged findings; `dismissed` falsely asserts the
finding is not real. The target architecture already names the missing
mechanism (DISC-05 waivers; `acknowledged` and `waived` lifecycle states); the
implemented slice has not caught up.

## Decision

### Consolidation is derivation, never mutation

Consolidation mints a new claim from an explicit candidate set of source
claims. It never rewrites, merges in place, or deletes its sources. The first
implementation is the deliberate `remember(consolidate)` mutation:

1. The request names the exact source claim IDs and their expected revisions
   within one tenant/project scope.
2. One serializable transaction verifies the compare-and-swap revision set,
   evaluates the consolidation policy, inserts the new claim with
   `origin = 'source_derived'`, writes `summarizes`/`derived_from` link rows,
   support rows citing exact chunk coordinates, and claim/audit event rows, and
   records the mutation receipt under the caller's idempotency key.
3. Source claims are optionally superseded (`superseded_by` the new claim) in
   the same transaction when policy says the derivative replaces them for
   retrieval; otherwise sources remain `active` and the derivative is additive.
4. A `conflict_eligible` derivative re-enters conflict detection in the
   committing transaction.

A later nominating projector may cluster claims by key, subject, and embedding
and emit consolidation *proposals*. Proposals are candidate-only observations
under the observer-admission rules; activation still requires the deliberate
action. Semantic similarity nominates; it never consolidates by itself
(PRED-01).

Consolidation identity is a digest over scope, the sorted source claim
ID+revision set, consolidator identity and version, and policy version.
Generated summary text is versioned enrichment, exactly like an embedding
vector: regenerable, never part of semantic identity, conflict fingerprints, or
replay correctness (REPLAY-01).

### Consolidation invariant family

The stable invariant registry gains a `CONS` family:

- **CONS-01 — Consolidation is derivation, never mutation.** It appends new
  claims, links, support, and lifecycle events. Replacement is supersession,
  which preserves history.
- **CONS-02 — Exact, atomic lineage.** Every derivative binds the exact sorted
  source claim ID+revision set, consolidator identity/version, registry digest,
  and derivation receipt. Claim, links, support, events, and receipt commit in
  one transaction. A consolidation that cannot record full lineage does not
  commit.
- **CONS-03 — No authority promotion.** Output kind, modality, and confidence
  are computed by a versioned policy and are never stronger than the weakest
  input. Consolidation cannot create normativity, verify the unverified, or
  close an `open_question`.
- **CONS-04 — Conflicts are non-launderable.** If any source is a member of a
  conflict in `open` or `waived` state, the run either fails closed or produces
  a `disputed` claim that preserves the disagreement and references the
  conflict. Consolidation never resolves, dismisses, waives, or hides a
  conflict. A waived conflict is still an open incompatibility for this rule.
- **CONS-05 — Deterministic identity, idempotent replay.** Re-running with the
  same inputs and idempotency key is a no-op. The same inputs under a new
  consolidator version produce an explicitly superseding derivation, not a
  duplicate.
- **CONS-06 — Scope containment.** Output tenant, project, and visibility are
  the server-derived intersection of input scopes. Cross-scope candidate sets
  fail closed. Private inputs never reach the publication projection through a
  summary.
- **CONS-07 — Erasure dominates derivatives.** Derivatives are indexed as
  materializations of every source. Source erasure or retention expiry forces
  re-derivation or tombstoning before the derivative is served; a derivative
  whose only reproducible support is gone becomes `unsupported` or
  `unverifiable`, and dependent conflicts are recomputed (EVID-08, EVID-09).
- **CONS-08 — Lifecycle coupling.** Supersession, retraction, or expiry of a
  source emits a re-evaluation event for its derivatives. A derivative whose
  entire live support is gone cannot silently remain `active`.
- **CONS-09 — Acyclic, depth-accounted lineage.** The derivation graph rejects
  cycles. Claims beyond a registered consolidation depth are excluded from
  candidate nomination unless a versioned policy explicitly permits deeper
  derivation.
- **CONS-10 — Detector re-entry.** A same-key relationship between a derivative
  and its own sources is governed by a registered comparator rule —
  transaction-atomic supersession or an explicit derivation exemption — never
  an ad-hoc detector skip.

### Conflict tolerance is durable policy

The conflict lifecycle gains `acknowledged` and `waived` states with distinct
semantics:

- **Acknowledge** records that an actor has seen and triaged the finding. It
  changes nothing about severity, verification, or surfacing, and is freely
  reversible.
- **Waive** records a scoped risk acceptance: attributed actor, structured
  reason kind (for example `capacity_deferred`, `cost_exceeds_risk`,
  `upstream_blocked`), rationale, applicability scope, and an expiry or
  review-by time. A waiver is a signed lifecycle event under the active policy
  (DISC-05). It does not rewrite evidence, reduce severity, edit member claims,
  or deactivate the underlying expectation. For conflicts involving normative
  propositions, the waiving actor must be distinct from the conflicted claim's
  author, under the same separation-of-duty pattern as binding activation; an
  agent never waives a nonconformance it caused.
- **Dismiss** asserts the finding is not real. It requires justification and,
  where the conflict implicates an actor's own claims, a different actor
  (AUTH-03).

A tolerated conflict remains visible. Retrieval that surfaces a member claim
attaches the waiver context — state, actor, reason, expiry — and may
de-emphasize waived conflicts relative to open ones, but does not suppress them
by default (DISC-04). Waiver expiry returns the same continuing episode to
`open` with its full history; it does not open a new conflict. When a waiver
expires while a consolidated derivative referencing that conflict is live, the
derivative's dispute surfacing reactivates through the CONS-08 re-evaluation
event.

Recurring waivers of one conflict family are themselves evidence. Repeated
`capacity_deferred` waivers on the same family nominate a
`documentation_drift` candidate against the expectation's normative binding;
the nomination follows the standard candidate-only path and never modifies the
binding by itself.

### Schema evolution

`memory_conflicts` gains `acknowledged` and `waived` states plus waiver
columns: `waiver_actor`, `waiver_reason_kind`, `waiver_reason`,
`waiver_scope`, `waiver_expires_at`. The change is an additive migration under
the existing prefix rules; prior `open`/`resolved`/`dismissed` rows keep their
meaning. Consolidation requires no new claim states: it composes existing
`origin`, `superseded_by`, link relations, support rows, and event tables.

## Consequences

- Episodic memory acquires a governed, replayable path to durable semantic
  memory without weakening immutability, provenance, or conflict honesty.
- Consolidated claims are leakage amplifiers: erasure indexing must cover
  derivatives before the first consolidation ships (CONS-07).
- Agents can defer real conflicts honestly, and the deferral itself becomes
  auditable, expiring policy rather than a silent gap.
- Waiver and acknowledgment writes are deliberate mutations under the existing
  receipt and idempotency rules; the public read plane gains no mutation route
  (PUBLIC-01, PUBLIC-02).
- The v2 conflict detector contract is unchanged; derivation exemptions are new
  registered comparator rules, not detector special cases.
- Recall-time `synthesize`, when implemented, remains ephemeral and labeled and
  never persists to the ledger; stored memory changes only through
  `remember(consolidate)`.
