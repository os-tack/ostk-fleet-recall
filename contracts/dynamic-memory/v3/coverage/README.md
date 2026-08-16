# Coverage receipt v1 contract vectors

These fixtures freeze `CoverageReceiptV1`, the receipt shared by connectors and observers so a later stage can tell when absence is meaningful (COVER-01, COVER-02, COVER-03), and `EvaluatedConditionV1`, the separate `present`/`absent`/`indeterminate` finding a receipt is asked to support. Every `.jsonl` file contains one canonical JSON record plus exactly one repository-framing LF; the LF is excluded from every digest. No fixture in this directory carries runtime authority: a `RegistryReferenceV1` here is a structurally valid, non-zero assertion only, never proof that the referenced entry is active in the current registry head. That closure — like exhaustive-observer admission itself (the architecture doc's "Exhaustive-observer admission" section) — belongs to a later, runtime-facing workstream.

## What `CoverageReceiptV1` closes

A receipt binds, as independently typed witnesses:

- `producer`: a typed `kind` (`connector` or `observer`) plus an exact `producer_id`/`version`. Coverage is granted per exact executable, never to a kind or name globally.
- `scope`: an exact `scope` resource URI, an immutable `revision` coordinate (never a mutable label), and a half-open `[window_start, window_end)` interval in canonical UTC timestamps.
- `watermark`: a typed union — a `cursor` (opaque provider-specific bytes) or a `provider_sequence` (an ordered integer) — never both, never neither.
- `completeness`: `complete`, `partial`, or `unknown`.
- `freshness`: `current` or `stale`, always paired with the exact `freshness_rule` it was evaluated under.
- `continuity`: `contiguous`, or `gap_detected` with an optional bounded `gap` description (`gap_after`/`gap_before`, same watermark kind, strictly ordered so the gap has a provable, non-empty extent).
- `observed_through`: the exact time the producer's reading extends to. It is a required field: a receipt that omits it fails to decode at all rather than defaulting to "now" or "unbounded".
- `proof_basis`: a closed `method` (`enumerated_snapshot`, `closed_cursor_interval`, `exhaustive_ast_walk`, `closed_provider_query`) plus the exact `proof_method_registration` it was admitted under.
- `source_digest`/`source_count`/`evidence_id`: the exact source material and accepted-event identity the receipt is attesting to.

Completeness, freshness, and sequence continuity are recorded as three separate bits on purpose (COVER-03): nothing in the type itself collapses them into one another, and none of them has a default. A receipt can structurally claim `complete` completeness *and* `gap_detected` continuity at the same time — the type does not forbid that combination, because completeness and continuity are independent witnesses about different questions. Only `negative_support_admissible` decides what that combination is allowed to support, and it is stricter than either field alone: `gap_detected` continuity always fails admission for negative support, regardless of what `completeness` separately claims.

`EvaluatedConditionV1` (`present`/`absent`/`indeterminate`) is a second, deliberately separate type. A coverage receipt describes how thoroughly a domain was read; the evaluated condition describes what was found there. Conflating them would let a search that returned no hits quietly become "proof of absence" without ever checking whether the search was exhaustive.

## `negative_support_admissible`

`negative_support_admissible(receipt, condition) -> bool` is the one place this module lets a caller move from "here is a coverage receipt and a finding" to "that finding may back a negative proposition or a verified provenance gap." It returns `true` only when *every* one of the following holds, with no default and no fallback (PRED-03):

- `condition` is exactly `EvaluatedConditionV1::Absent` — `present` and `indeterminate` are never negatively supported, regardless of receipt quality;
- `receipt.validate()` succeeds (well-formed shape, ordered window, registered non-zero freshness rule and proof method, and a structurally valid bounded gap when one is present);
- `completeness` is exactly `Complete` — `Partial` and `Unknown` never qualify;
- `freshness.state` is exactly `Current` — `Stale` never qualifies;
- `continuity` is exactly `Contiguous` — `GapDetected` never qualifies, with or without a bounded `gap` description, and even when `completeness` independently claims `Complete`.

`vector-suite.jsonl` and the Rust test suite exercise the full 3 (completeness) × 2 (freshness) × 2 (continuity) = 12-cell matrix, each cell against all three `EvaluatedConditionV1` values (36 combinations total). Exactly one of those 36 combinations is admissible: `complete` + `current` + `contiguous` + `absent`.

## Fixture inventory

Standalone component fixtures (one canonical value each, used for round-trip and shape tests):

- `producer-identity.jsonl`, `coverage-scope.jsonl`, `coverage-watermark-cursor.jsonl`, `coverage-watermark-provider-sequence.jsonl`, `coverage-freshness.jsonl`, `sequence-gap.jsonl`, `coverage-proof-basis.jsonl`
- `evaluated-condition-present.jsonl`, `evaluated-condition-absent.jsonl`, `evaluated-condition-indeterminate.jsonl`

Full matrix fixtures (`matrix-<completeness>-<freshness>-<continuity>.jsonl`, 12 files, every cell of the 3×2×2 matrix; `gap_detected` cells alternate between a populated bounded `gap` and `gap: null` and between `cursor`- and `provider_sequence`-kind gap endpoints to exercise every shape once):

- `matrix-complete-current-contiguous.jsonl` — the sole admissible cell (paired with `condition: absent`); this is also the canonical positive full-receipt record, and its `receipt_id()` is the `canonical_receipt_id` pinned in `vector-suite.jsonl`.
- `matrix-complete-current-gap_detected.jsonl`, `matrix-complete-stale-contiguous.jsonl`, `matrix-complete-stale-gap_detected.jsonl`
- `matrix-partial-current-contiguous.jsonl`, `matrix-partial-current-gap_detected.jsonl`, `matrix-partial-stale-contiguous.jsonl`, `matrix-partial-stale-gap_detected.jsonl`
- `matrix-unknown-current-contiguous.jsonl`, `matrix-unknown-current-gap_detected.jsonl`, `matrix-unknown-stale-contiguous.jsonl`, `matrix-unknown-stale-gap_detected.jsonl`

Negative vectors (each decodes to the same canonical positive shape with exactly one defect, and either fails `decode_strict` or fails `CoverageReceiptV1::validate`; invariant proved in parentheses):

- `negative-missing-observed-through.jsonl` — the `observed_through` key is entirely absent (required-field decode failure; a receipt can never default this to "now").
- `negative-window-end-before-start.jsonl` — `scope.window.window_end` is before `window_start` (half-open interval must be strictly ordered).
- `negative-unregistered-proof-method.jsonl` — `proof_basis.proof_method_registration.entry_digest` is the all-zero digest (COVER-03: only a *registered* proof method counts).
- `negative-unregistered-freshness-rule.jsonl` — `freshness.freshness_rule.entry_digest` is the all-zero digest (freshness must be stated under a named, registered rule, never a bare boolean).
- `negative-floating-value.jsonl` — `source_count` is `1.5` (the strict canonical JSON profile forbids floats outright; decode fails before any typed validation runs).
- `negative-unknown-field.jsonl` — an extra top-level `unexpected` key (`#[serde(deny_unknown_fields)]` on every type in this module).
- `negative-zero-schema-version.jsonl` — `schema_version: 0` (schema version pinning).
- `negative-gap-mismatched-watermark-kinds.jsonl` — `continuity.gap.gap_after` is a `cursor` watermark while `gap_before` is a `provider_sequence` watermark (a gap's endpoints must share one watermark kind).
- `negative-gap-unordered-sequence.jsonl` — `continuity.gap.gap_after.sequence` (9) is not strictly less than `gap_before.sequence` (5) (a gap must have a provable, non-empty, ordered extent).
- `negative-arbitrary-json-value.jsonl` — the entire record is a bare JSON array (`[1,2,3]`) instead of an object; proves the type rejects arbitrary JSON shapes, not just malformed objects.

`matrix-complete-current-gap_detected.jsonl` additionally stands in for "receipt claims `complete` completeness while `continuity` is `gap_detected`, evaluated against a negative (`absent`) condition": the fixture decodes and validates cleanly (COVER-03 makes that combination structurally legal), and the Rust suite asserts `negative_support_admissible` returns `false` for it regardless of `condition`, because `gap_detected` continuity always fails admission for negative support independent of the completeness field (COVER-03).

## Digests

`CoverageReceiptV1::receipt_id()` is:

`SHA-256("ostk-coverage-receipt-v1" || 0x00 || canonical_receipt_bytes)`

using the shared `ostk-canonical-json-v1` profile and the project's `domain_separated_digest` framing (the fixed domain prefix, one `0x00` separator byte, then the canonical JSON bytes with no other framing). The preimage is the *entire* canonical receipt: every field in this module, including ones `negative_support_admissible` never inspects (such as `source_count` or `producer`), changes the bound identity. W0-OBS and connector call sites are expected to cite a coverage receipt by this exact digest, so any field change is a contract-version change for anything that already cited the old digest.

`vector-suite.jsonl` aggregates: `schema_version`, a `fixture_authority` disclaimer (structural fixtures only, no active-registry or runtime witness), the `canonical_receipt_id` of the sole admissible matrix cell, `matrix_case_count` (12), `negative_case_count` (10), and the strictly sorted, unique `negative_cases` label set. Its own pin is `domain_separated_digest(DigestDomain::TestVectorManifest, <raw file bytes minus the framing LF>)`, following the existing `TestVectorManifest` domain rather than introducing a new one — the suite manifest is not itself an identity-bearing wire artifact.

Every fixture's raw file bytes (including the framing LF) are additionally pinned by a plain, non-domain-separated SHA-256 in the Rust test suite, so an accidental byte change to any fixture — even one that still parses and validates — is caught.

## Producer identifiers used in these fixtures

`observer.ast_walker_rust`, `coverage.freshness.default_rule`, and `coverage.proof.exhaustive_ast_walk` are fixture-only labels chosen to read naturally; they are not reserved names, do not correspond to any activated registry entry, and grant no admission by appearing here.
