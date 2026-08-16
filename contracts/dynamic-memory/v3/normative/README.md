# Canonical normative binding v2 contract vectors

These fixtures freeze the contract-only boundary for [`normative_v2.rs`](../../../../src/memory_contracts/normative_v2.rs), the v2 successor to the frozen v1 shapes in `normative.rs`. Every `.jsonl` file (except `vector-suite.jsonl`, described below) contains one canonical JSON record plus exactly one trailing LF; the LF is excluded from every contract digest. None of these fixtures carries runtime authority: every type here proves shape and internal consistency only, never signature verification, live registry-head membership, or the server's actually-current eligible-signer set.

## Why v2, and why it does not touch v1

`normative.rs` (v1) is frozen: this workstream must not modify it. `normative_v2.rs` reuses its unchanged, purely structural pieces — `SourceByteSpanV1` (exact byte range plus selected-byte digest), `NormativePropositionV1` (predicate-schema reference plus proposition fingerprint), and `ApprovalAttestationV1` (the unsigned attestation wire shape) — because those shapes did not need to change. What v2 adds is the registry-head-bound composite CAS, a re-derived (not merely trusted) separation-of-duty verdict, explicit lifecycle events, contested-evidence recording, and the retroactive-correction hook. `digest.rs` allocates four new domains for this workstream (`NormativeBindingStatementV2`, `NormativeBindingReceiptV2`, `NormativeLifecycleEventV1`, `NormativeContestedV1`); none of them collides with the frozen v1 `NormativeBindingStatement`/`NormativeBindingReceipt` domains, and `statement_identity_does_not_reuse_v1_domain` in `normative_v2.rs` proves the two hash functions diverge even over identical bytes.

## `NormativeBindingProposalV2` — exact source binding (AUTH-04, APPL-01)

`proposal-positive.jsonl` binds a stable `binding_family_id`, the exact `repository_entity_id`/`repository_version_id`/`blob_id`/`exact_path_bytes`, one or more non-overlapping, strictly sorted `source_spans` (byte range plus selected-byte digest), the extractor/parser artifact and its configuration digest, one or more strictly sorted `propositions` (predicate-schema reference plus fingerprint), an `applicability_evaluator` plus a concrete object-shaped `applicability_selector` (APPL-01: a missing or non-object selector fails closed rather than defaulting to `any`), an effective interval, and a `registry_head: RegistryHeadBindingV1` — reused unchanged from `evidence_v2.rs` — that carries the active registry package digest, activation ID, and activation-policy digest this proposal was built against.

`statement_identity_changes_with_exact_source_span` and the fixture pair implied by `a_document_edit_produces_new_evidence_but_does_not_disturb_the_prior_binding` demonstrate AUTH-04's "a document edit creates new evidence but leaves the previously active version normative" rule at the contract layer: shifting one byte of `source_spans[0].start` mints an entirely different `statement_id`. This module has no operation that retires or overwrites a prior statement as a side effect of proposing a new one — retirement is only ever a separate, explicitly kinded `NormativeLifecycleEventV1`.

Negative fixtures:
- `proposal-negative-unsorted-propositions.jsonl` — `propositions` given as `[z, a]` instead of strictly sorted. Structurally valid canonical JSON; semantically rejected by `validate()` so a set field is never silently re-sorted into something the caller didn't assert.
- `proposal-negative-overlapping-spans.jsonl` — a second span `[79, 90)` overlapping the first span's `[10, 80)` end. Byte-exact evidence coordinates may not overlap ambiguously.
- `proposal-negative-wrong-resource-form.jsonl` — `repository_version_id` uses the `entity` URI form instead of the required `version` form. A version coordinate is not interchangeable with its parent entity's continuing identity.

## `NormativeActivationReceiptV2` — separation of duty (AUTH-03)

`NormativeActivationReceiptV2::validate` does not merely check a trusted `separation_of_duty_satisfied` boolean: it re-derives the verdict from `source_author_principal_id` and the declared `eligible_approvals`' principal IDs via `NormativeActivationSeparationOfDutyV2::IndependentApprovalFromSourceAuthor`, and rejects the receipt if the declared flag disagrees with that re-derivation. This directly encodes AUTH-03/AUTH-04's "the document author or affected agent cannot be the sole ratifier" — the author *may* approve, but at least one other eligible principal must also approve, and the threshold must still be met by the total count.

- `receipt-positive-author-plus-independent.jsonl` — `principal.author` and `principal.independent` both approve against a threshold of 2; SoD is satisfied because an independent principal is present.
- `receipt-negative-author-only.jsonl` — only `principal.author` approves (with `separation_of_duty_satisfied` falsely asserted `true`). Rejected: no eligible approval comes from any principal other than the author, so the declared flag cannot possibly be true, and the receipt fails closed regardless of what it claims.

`duplicate_principal_or_key_is_rejected` and `threshold_not_met_is_rejected_even_with_independent_approval` (inline, not fixture-based — they mutate the shared `receipt()` builder) cover the remaining structural guards: no principal or signer key may repeat across `eligible_approvals`, and an independent approval alone does not excuse an unmet numeric threshold.

## Stale composite CAS

`stale_composite_head_after_activation_policy_change_is_rejected` proves `NormativeBindingProposalV2::require_current_composite` compares all three composite components — `expected_active_binding_set_digest`, the registry package digest, and the activation-policy digest (both taken from the embedded `registry_head`) — independently. A policy change alone, with the registry package and binding-family revision otherwise unchanged, is sufficient to make an outstanding proposal stale (`ContractError::StaleRegistryHead`), matching the doc's "a policy or key change makes the proposal stale and requires reauthorization."

## Supersession vs. incompatible overlap

`NormativeBindingProposalV2::require_non_conflicting_activation` is exercised inline (not via fixtures, since it is a two-binding relational check rather than a single wire shape): an explicit `explicitly_supersedes_statement_id` naming the active binding's statement permits an otherwise-overlapping effective interval; the identical overlap without that explicit target is rejected; a non-overlapping interval or a different `binding_family_id` never conflicts regardless of supersession.

## `NormativeLifecycleEventV1` — activation, retirement, retraction, expiry, supersession

`lifecycle-activation.jsonl` and `lifecycle-supersession.jsonl` are positive vectors for two of the five closed `NormativeLifecycleKindV1` variants; `retirement`, `retraction`, and `expiry` share the identical shape (proven by `every_lifecycle_kind_produces_a_distinct_event_id`, which is inline because it enumerates all five kinds against one base statement and asserts pairwise-distinct `event_id`s). Every event embeds a `registry_head: RegistryHeadBindingV1` so the active policy the event was accepted under is part of its own preimage. `supersedes_statement_id` is required exactly when `kind == Supersession` and forbidden otherwise.

- `lifecycle-negative-missing-supersedes-target.jsonl` — `kind: supersession` with `supersedes_statement_id: null`. A supersession event without an explicit target is invalid shape, mirroring "a known incompatible overlap fails unless the activation explicitly supersedes the active binding."

`waiver_reference_digest` is present on every lifecycle event and on `ContestedBindingV1` as a reference-only pointer into the separate, durable waiver system (DISC-05, owned elsewhere); this module never interprets it and a present waiver reference does not change `validate()`'s outcome, matching "waivers are separate ... and do not deactivate the underlying expectation."

## `ContestedBindingV1` — unestablishable ordering

`contested-positive.jsonl` names two independently accepted statement IDs for one binding family with `reason: independently_accepted_unestablishable_ordering`. `ContestedBindingV1::dependent_comparison_is_unknown` always returns `true` while such a record exists for a family — a contested state is never silently resolved by this contract layer; only an explicit, separately authorized resolution event (outside this module's scope) can close it. `contested-negative-single-statement.jsonl` proves a single statement ID (even duplicated) cannot be "contested" — contest requires two or more genuinely distinct, independently accepted statement IDs, strictly sorted and unique.

## `RetroactiveCorrectionV1` — the bitemporal-append hook

Normal policy is enforced by the free function `require_effective_not_before_accepted`: any `effective_from` strictly earlier than `accepted_at` is rejected outright, with no fixture needed since it operates on two bare timestamps rather than a wire shape.

`retroactive-correction-positive.jsonl` is the exceptional path: it is a **distinct** `statement_id` from `superseded_as_known_statement_id`, its own `effective_from` (2026-01-01) genuinely precedes its own `accepted_at` (2026-08-15), and it names a separate, higher-threshold `authorizing_policy` reference. `RetroactiveCorrectionV1::validate` never touches, dereferences, or invalidates `superseded_as_known_statement_id` — the prior as-known conclusion's bytes and identity remain exactly as they were; this record only appends a new bitemporal interpretation alongside it. `retroactive-correction-negative-not-retroactive.jsonl` swaps the timestamps (`effective_from` after `accepted_at`) to prove the hook itself refuses to be used when nothing is actually retroactive — a self-referential correction (`statement_id == superseded_as_known_statement_id`) is rejected by the same guard, covered inline.

## Vector suite format

`vector-suite.jsonl` deliberately departs from the single-record convention used by every other file in this directory: it is genuine JSON Lines, one compact record per line, each naming a `vector_id`, the exact `fixture_path` it covers (or `"inline"` for relational checks that have no wire-format fixture), its `polarity`, the invariant IDs it exercises, and a one-sentence `description`. `vector_suite_manifest_is_canonical_and_lists_every_fixture` parses every line and asserts the fixed count, non-empty invariant list, valid polarity, and path prefix; it intentionally does not re-derive or pin a digest over the whole manifest, since the manifest is documentation cross-referencing the digests already pinned per-fixture above, not itself an identity-bearing artifact.

## Regeneration

`regenerate_normative_v2_contract_artifacts` (`#[ignore]`) rebuilds every fixture in this directory from the same in-Rust constructors the tests use, via `encode_canonical`, so hand-edited fixture bytes can never silently drift from what the typed constructors actually produce. Run it with `NORMATIVE_V2_VECTOR_OUTPUT=contracts/dynamic-memory/v3/normative cargo +1.94 test --locked --lib memory_contracts::normative_v2::tests::regenerate_normative_v2_contract_artifacts -- --ignored --nocapture` and inspect the printed digests before updating any `EXPECTED_*` constant in `normative_v2.rs`.
