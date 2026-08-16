# Canonical erasure v1 contract vectors

These fixtures freeze the contract-only boundary for `src/memory_contracts/erasure.rs` (EVID-01, EVID-05, EVID-08, EVID-09). Every `.jsonl` file contains one canonical record plus exactly one repository-framing LF; the LF is excluded from every contract digest. None of these fixtures carries runtime authority: `ErasureEventV1` is a public candidate shape, not proof that anything named in it may be erased, and the atomic effect of accepting one (`ErasureAcceptanceEffectV1`) has no production constructor anywhere in this module.

## Why erasure and evidence share one scope type

`ErasureScope` is a type alias for `super::evidence::ErasureScopeReferenceV1` — the exact same `{kind, target_digest}` pair every evidence representation already carries in its `erasure_scopes` field. `kind` is the closed four-member enum the architecture document names directly: `representation`, `source_fact`, `resource`, `privacy_subject`. Sharing the type means an erasure event's declared target and a representation's indexed scope compare without a lossy conversion, and a parent-scope erasure (a `privacy_subject` tombstone) and a child-scope erasure (a `representation` tombstone) are just two entries in one closed enum rather than a hierarchy this module has to model and get wrong. `erasure-event-representation.jsonl` and `erasure-event-privacy-subject.jsonl` are deliberately the same event shape aimed at the two ends of that hierarchy — see `erasure_event_shape_and_identity` and `acceptance_effect_ties_tombstone_fence_and_generation_atomically` in `erasure.rs` for the parent/child race those two vectors support.

## The five closed digest domains

`ErasureEventV1` ("erasure.accepted"), `ErasureTombstoneV1`, `ErasureFenceV1`, `ErasureReceiptV1`, and `LegalHoldV1` are the five `DigestDomain` variants this workstream owns in `src/memory_contracts/digest.rs`, and each type has a matching identity method — `accepted_event_id()`, `tombstone_id()`, `fence_id()`, `receipt_id()`, `hold_id()` — so all five are actually exercised, not merely reserved. `ErasureEventV1`'s accepted-event ID is:

`SHA-256("ostk-erasure-event-v1" || 0x00 || canonical_erasure_event_bytes)`

Receipt state, fence position, and append coordinates are not fields in that preimage, so none of them can affect an erasure event's identity. Every one of these five is a *record* identity, not a *mutation* identity: `erasure-receipt-pending.jsonl` and `erasure-receipt-complete.jsonl` have different `receipt_id()`s because a `pending` -> `complete` transition is a new record, never an in-place edit of the old one — the same is true of `fence_id()` across `erasure-fence-genesis.jsonl`/`erasure-fence-advanced.jsonl` and of `tombstone_id()` across `erasure-tombstone-digest-only.jsonl`/`erasure-tombstone-with-metadata.jsonl`. `ErasureGenerationV1` deliberately has no digest domain: it is a plain `{scope, value}` counter compared by ordinary field equality and `advances()`, never hashed as an artifact.

## The unconstructible accepted-form typestates

Two types have no production constructor in this contract-only stage, matching the pattern in `remember_v2.rs`'s `AdmittedRememberStatementV2`:

- `AdmittedErasureEventV1` — the opaque capability a future append repository would consume. Only `AdmittedErasureEventV1::from_test_witness`, gated by `#[cfg(test)]`, can build one.
- `ErasureAcceptanceEffectV1` — the atomic bundle the architecture document describes as one indivisible act: "acceptance atomically installs a retrieval-deny tombstone and increments every indexed target epoch plus a monotonic tenant/project erasure generation." Its `#[cfg(test)]`-only constructor cross-checks that the tombstone's `erasure_event_id` and `target` match the admitted event, that at least one advanced fence entry covers the event's own scope kind, and that the generation strictly increased — so a caller cannot assemble an "acceptance" out of three unrelated values.

Deserializing or structurally validating `ErasureEventV1` cannot create either type. Untrusted input can propose an erasure; it cannot manufacture the accepted effect of one.

## The composite fence is coarse on purpose

`ErasureFenceV1` tracks exactly one epoch counter per `ErasureScopeKind` — four entries, one per kind, never more or fewer (`negative-fence-missing-scope.jsonl` proves the four-entry requirement fails closed) — rather than one counter per exact target digest. Any erasure of a given kind in a tenant/project advances that kind's shared counter. `erasure-fence-genesis.jsonl` (all four epochs at `0`, generation `0`) and `erasure-fence-advanced.jsonl` (the `representation` epoch at `1`, generation `1`) are the two ends of `ErasureFenceCasV1::may_commit`'s central scenario: work that captured the genesis fence as `expected` and later CASes against the advanced fence as `current` must fail closed, because *some* representation-kind erasure landed in between — the CAS does not need to know, and does not ask, whether it was the exact same target. This is EVID-09 made mechanical: "work begun before a parent, subject, or child tombstone cannot commit afterward."

## Tombstones cannot carry payload bytes

`ErasureTombstoneV1` and `TombstoneLifecycleV1` are both `#[serde(deny_unknown_fields)]`, and neither has a field wide enough to hold canonical text, a raw payload, or an embedding — only a digest, a policy reference, `TombstoneDenyModeV1::RetrievalDeny` (a closed single-variant enum pinning the retrieval-deny semantic into the digest preimage, not a boolean any input could flip), and, when policy permits, `installed_at`/`superseded_by` lifecycle metadata. `negative-tombstone-payload-bytes.jsonl` is `erasure-tombstone-digest-only.jsonl` with an extra `payload_bytes` key spliced in; it fails to deserialize at all, which is the point — there is no field for a reviewer to accidentally widen into a payload carrier without it becoming a new, separately reviewed contract version.

## Receipts: key destruction alone is not erasure

`ErasureReceiptV1.state = complete` requires every `residual_inventory` entry to show `residual_present: false` *and* `key_destroyed: true`. `erasure-receipt-pending.jsonl` has one store still showing a residual and `key_destroyed: false`; `erasure-receipt-complete.jsonl` has every residual cleared and the key destroyed, with one store's `deletion_actor` marked `fleet_recall` and the other `authoritative_provider` to exercise that distinction. `negative-receipt-complete-with-residual.jsonl` is the pending receipt with only its `state` flipped to `complete`; validation rejects it because a residual is still present — key destruction alone, with plaintext or a derived copy still resident anywhere in the inventory, is not sufficient evidence of erasure.

## Legal hold defers removal, never publishes

`legal-hold-active.jsonl` has `released_at: null` and `visibility_ceiling: "private"`. `LegalHoldV1::permits_removal` returns `false` for any timestamp before a recorded release. `visibility_ceiling` can never be `publication_approved` — `negative-legal-hold-publication-visibility.jsonl` is the active hold with that one field flipped, and validation rejects it: a legal hold can defer removal, but it can never make held private content public.

## Checkpoints: erasure dominates, old is never advanced in place

`checkpoint-erasure-rule.jsonl` mints a new checkpoint digest at generation `1` from a previous checkpoint at generation `0`. `negative-checkpoint-same-digest.jsonl` reuses the previous checkpoint's digest as the new one; validation rejects it, because "new checkpoint at a higher erasure epoch" is meaningless if the checkpoint identity itself did not change — the old object is never redacted or advanced in place, only superseded by a new, separately addressed one.

## Dependent propositions: the recompute list must match the transition

`dependent-support-transition-unverifiable.jsonl` downgrades from `verified` support to `unverifiable` with `sufficient_redacted_evidence_remains: false` and a non-empty `recompute_targets`. `negative-dependent-transition-contradiction.jsonl` is the same record with `next_state` flipped back to `verified` while `sufficient_redacted_evidence_remains` stays `false` and `recompute_targets` stays non-empty — a direct contradiction (insufficient evidence but no downgrade, and a recompute list attached to a transition that supposedly recomputes nothing) that validation rejects.

## Retainable matcher and restore gate are pure decision rules

`retainable-matcher-forbidden.jsonl` pins `RetainableMatcherPolicyV1::PseudonymousMatcherForbidden`, whose `required_scope_action()` always returns `Ok(disable_and_purge)`: if policy forbids retaining even a pseudonymous matcher needed to suppress late redelivery, the system must not promise replay-safe suppression while continuing to accept an event it can no longer recognize. `required_scope_action()` first calls `validate()` on the policy itself — for `PseudonymousMatcherAllowed`, that means the `matcher_policy` registry reference (version, entry digest) must validate — so an unverifiable matcher policy can never report `Retain`; it errors instead. `restore-gate-quarantined.jsonl` pins a gate with `schema_version: 1`, `tombstone_tail_applied: true`, `covered_by_tombstone: true`, `quarantine_preferred: true`; its `outcome()` returns `Ok(quarantined)`. Flipping `quarantine_preferred` yields `suppressed`; flipping `covered_by_tombstone` yields `serve`; flipping `tombstone_tail_applied` to `false` makes `outcome()` fail closed regardless of the other two fields — an un-applied tombstone tail cannot prove absence of coverage, so `covered_by_tombstone: false` must never be read as "not covered" before the tail is actually loaded. `outcome()` also rejects any `schema_version` other than the current one before it reads either boolean, so a future, differently-shaped restore-gate record can never be decided under this version's truth table — in particular it can never be silently read as `serve`.

## `negative-event-effective-before-policy-basis.jsonl`

`erasure-event-representation.jsonl` with its `effective.effective_from` moved to a date before `policy_basis_effective_from`. An erasure cannot claim effect under a policy basis before that basis itself took effect; `ErasureEventV1::validate_shape` rejects it.

## The erasure-event binding cannot be the zero digest

`ErasureTombstoneV1::validate`, `ErasureReceiptV1::validate`, and `DependentSupportTransitionV1::validate` all reject `erasure_event_id.digest() == Sha256Digest::ZERO`, matching the sentinel discipline already applied to `target_digest`, the policy `entry_digest`, and the optional `superseded_by`. A tombstone, a completion receipt, or a support-recompute record that names no erasure event at all is not evidence of anything; `DependentSupportTransitionV1::validate` extends the same check to every entry in `recompute_targets`.

## Re-consent and retainable-matcher policy references must themselves validate

`ErasureEventV1::validate_shape` (and therefore `accepted_event_id()`, since shape-validity is a precondition of that identity) runs the same `validate_policy_reference` check against `re_consent`'s `consent_policy` that it already runs against `policy_basis`: version zero or a zero entry digest makes the whole candidate shape-invalid, not just the re-consent claim. `re_consent_permits_new_source_fact` independently re-checks the consent-policy reference it is handed, so a caller cannot bypass the guard by constructing the function's arguments directly instead of going through `validate_shape`. The doc's "separately authorized prospective re-consent semantics" means separately *authorized*, not separately *unverified* — an unauthorized or unverifiable policy basis must never unlock re-consent.

## What Rust tests pin

`src/memory_contracts/erasure.rs`'s `hard_coded_contract_vectors_match_independent_ids` test raw-SHA-256-pins every positive fixture, every negative fixture, and `vector-suite.jsonl` byte-for-byte via `include_bytes!`; the positives and `vector-suite.jsonl` are additionally round-tripped through `encode_canonical`/`require_canonical`. The test cross-checks `ErasureEventV1::accepted_event_id()` for both the `representation`- and `privacy_subject`-scoped events against hard-coded digests. Every negative fixture is exercised in its own focused test both via `decode_strict` plus an exact `ContractError` match *and* an assertion on the specific structural property that fixture is supposed to demonstrate (e.g. the missing-scope fence decodes to exactly three entries; the residual-with-complete receipt decodes with `state: complete` and a `residual_present: true` entry) — so an edit that silently swapped in a differently-broken fixture satisfying only the shared error string would fail the pin, the structural assertion, or both. `vector-suite.jsonl` is `ErasureVectorSuiteV1`: schema version, both accepted-event IDs, and the sorted list of every negative case name this directory proves closed. Changing any canonical record, prefix, fixed event kind, expected digest, or ordering rule here is a contract-version change.
