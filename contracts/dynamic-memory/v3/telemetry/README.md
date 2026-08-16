# Canonical telemetry v1 contract vectors

These fixtures freeze the contract-only boundary for `MeasurementReceiptV1`,
`SloEvaluationV1`, `ExemplarPolicyV1`, `ExemplarV1`, and
`ExemplarSelectionReceiptV1`. Every `.jsonl` file contains one canonical JSON
record plus exactly one trailing LF; the LF is excluded from every contract
digest (it exists only so the checked-in file ends in a newline). None of the
fixture scope, registry references, resource URIs, or digests carry runtime
authority — they are structural preimages, not proof that any named registry
entry, policy, or provider snapshot is active.

## What each fixture proves

**`measurement-receipt-v1-private-with-exemplars.jsonl`** — a bounded
measurement receipt (RUN-01, RUN-02, RUN-03) binding provider/query identity,
a durable provider link, a half-open window, aggregation/unit/result/sample
count, dimensions, coverage, missingness, deployment/workload/artifact/config
identities, a private raw-artifact reference, a provider response digest, and
an `ExemplarSelectionReceiptV1` produced by `deterministic_stratified_hash_v1`
against a two-stratum, five-candidate population (one candidate withheld).
Proves the receipt's own shape and that a real selection round-trips inside
it byte-for-byte.

**`measurement-receipt-v1-population-unavailable.jsonl`** — the same receipt
shape with an `Unbound` exemplar population (`snapshot_unavailable`). Proves
"unavailable snapshot/identities selects none, keeps the aggregate": every
selection count is zero, `exemplars` is empty, and the receipt itself is
otherwise fully populated and valid.

**`slo-evaluation-v1-compliant.jsonl`** / **`slo-evaluation-v1-nonconformant.jsonl`**
— an `SloEvaluationV1` binding the normative rule, one cited measurement
receipt ID, comparator and applicability-evaluator versions, concrete
context, coverage result, and outcome. The nonconformant fixture pins
`coverage_result: complete`, because `SloEvaluationV1::validate_shape` refuses
a `nonconformant` outcome under any coverage weaker than `complete`
(RUN-01: a verified nonconformance requires required coverage to verify).
`SloEvaluationV1` and `AlertLifecycleEventV1` are deliberately different
resources; no alert-lifecycle type is defined in this module.

**`exemplar-policy-v1-private.jsonl`** / **`exemplar-policy-v1-public-activated.jsonl`**
— the two policy shapes whose `effective_caps()` differ: private always
resolves to 8 exemplars / 1,024 B each / 8 KiB total; public only reaches its
activated cap (3 / 512 B / 1.5 KiB) once `public_activation` names an
approval and an `activated_at` no earlier than
`public_visibility_established_at`. An absent `public_activation` under
public visibility resolves to the zero-cap default. Caps are never fields on
the policy itself — `effective_caps()` derives them from fixed v1 constants,
so no payload can grant itself a larger cap by naming one.

**`exemplar-v1.jsonl`** — the closed exemplar field set: bounded time,
service/environment/region, workload/cohort, route template, status/error
class, duration, sanitized code frames, and opaque trace coordinates. There is
no header, cookie, credential, body, query-string, environment-value, user-
identifier, IP-address, database-value, or stack-local field on the type, so
the architecture doc's deny list is enforced structurally by
`#[serde(deny_unknown_fields)]` rather than by a runtime content scan.

**`exemplar-selection-receipt-v1-erased.jsonl`** — the private-with-exemplars
selection after `erase_exemplar_at(0, ...)`: `selected_count` is unchanged,
`exemplars.len()` drops by one, and one `ErasedExemplarTombstoneV1` appears
in canonical (`selection_index`-ascending) order. Proves exemplar erasure
removes the payload while the receipt's counts and identity-bearing history
remain (EVID-08, EVID-09). `selection_index` -- the tombstone's stable 0-based
position in the original round-robin selection order, not derived from
`erased_exemplar_digest` -- is what canonical order and cap/consistency
checks key off; see `erasure-is-total-for-duplicates` below for why content
digest alone cannot be the key.

**`exemplar-selection-receipt-v1-cap-truncated.jsonl`** — a real
`deterministic_stratified_hash_v1` run against a three-stratum, 9-eligible-
candidate population under the private policy's cap of 8 (`route.checkout`,
`route.orders`, `route.refund`, three candidates each): `omitted_count == 1`
and `truncated == true`. Unlike `measurement-receipt-v1-private-with-
exemplars.jsonl` (4 eligible candidates, never reaches the cap of 8), the
cap here forces a real choice between eligible records within the last
round-robin round. `authoritative_fixture_corpus_is_frozen` re-runs the
selector over this exact population and asserts canonical-byte equality with
the frozen record, so a changed ordering-key preimage, within-stratum
comparator, canonical stratum order, or round-robin walk fails a gate
instead of passing silently (the class of defect the count-only and
permutation-equality checks below cannot catch).

## Negative vectors

**`negative-float-result.jsonl`** — `measurement-receipt-v1-population-unavailable.jsonl`
with `"result":"482.5"` rewritten to the bare JSON number `482.5`. The
canonical-JSON layer forbids floating-point literals outright
(`ContractError::FloatingPointForbidden`), so this fails before
`MeasurementReceiptV1`-specific validation ever runs; the fixture pins that
end-to-end rejection at the receipt boundary.

**`negative-cap-exceeded-exemplar.jsonl`** — a fresh single-candidate,
single-stratum selection against `exemplar-policy-v1-public-activated`
(512 B per-exemplar cap; `candidate_count`/`eligible_count`/`selected_count`
all 1), with that one exemplar's canonical wire length inflated past the cap
after selection. Decodes structurally; `ExemplarSelectionReceiptV1::validate_shape`
rejects it because the exemplar's canonical wire length exceeds
`effective_caps().max_bytes_each`.

**`negative-secret-shaped-field.jsonl`** — `exemplar-v1.jsonl` with an
injected `"headers":{"authorization":"Bearer secret"}` field. `ExemplarV1`
has no `headers` field, so `#[serde(deny_unknown_fields)]` rejects the whole
record during strict decode: a secret-shaped field cannot ride into an
exemplar even if a caller tried.

**`negative-raw-log-line-field.jsonl`** — `exemplar-v1.jsonl` with an
injected `"raw_log_line":"2026-08-15 500 error at checkout.rs:42"` field.
Same structural rejection: `ExemplarV1` has no field that can hold an
arbitrary raw log line, sanitized or not.

**`negative-compliant-partial-coverage.jsonl`** — `slo-evaluation-v1-compliant.jsonl`
with `coverage_result` rewritten from `complete` to `partial`. Decodes
structurally (nothing about the JSON shape is malformed); `SloEvaluationV1::validate_shape`
rejects it. RUN-01 requires full coverage before ANY verified outcome --
`compliant` and `nonconformant` are both rank-2 "verified" outcomes
(`SloOutcomeV1::verification_rank`) -- so this pins the same requirement for
`compliant` that `slo-evaluation-v1-nonconformant.jsonl`'s pinned
`coverage_result: complete` already pins for `nonconformant`. Checking only
the `nonconformant` arm would fail open: a `compliant` outcome could then be
asserted at full verification rank under partial or unknown coverage.

**`negative-selected-count-exceeds-cap.jsonl`** — a hand-fabricated selection
receipt naming `selected_count = 9` under the private policy's cap of 8: one
present exemplar plus eight tombstones, with every other count
(`candidate_count`/`eligible_count`/strata totals/`present_and_tombstoned`)
arithmetically self-consistent so `validate_counts_and_strata` alone would
accept it. Only `validate_caps_and_tombstones`'s explicit `selected_count >
caps.max_count` check rejects it. A genuine selection can never produce this
shape: selection stops at the cap, and erasure never raises `selected_count`
(it only moves an already-selected exemplar to a tombstone). Prior to this
fixture, the count cap was checked only against `exemplars.len()`, which a
payload could keep under the cap indefinitely by naming enough fabricated
tombstones instead.

**`negative-tombstone-invalid-schema-version.jsonl`** — the erased fixture
with its one tombstone's `schema_version` rewritten from `1` to `9999`.
Decodes structurally (schema_version is just a `u32` field); `validate_shape`
must reject a tombstone this module could never have produced rather than
trust it as evidence.

**`negative-tombstone-invalid-erasure-policy.jsonl`** — the erased fixture
with its tombstone's `erasure_policy.version` rewritten from `1` to `0`.
`RegistryReferenceV1::validate` rejects a zero version; this pins that
`validate_caps_and_tombstones` actually calls it for every tombstone's
`erasure_policy`, matching the validation every other nested registry
reference in this module already receives, rather than trusting the nested
record's shape unchecked.

## Digests

`vector-suite.jsonl` pins one manifest record with the raw SHA-256 of every
fixture file's exact bytes (`shasum -a 256`) plus the semantic identities the
positive fixtures decode to: `MeasurementReceiptV1::receipt_id()` under
`DigestDomain::MeasurementReceiptV1` (`ostk-measurement-receipt-v1`),
`SloEvaluationV1::evaluation_id()` under `DigestDomain::SloEvaluationV1`
(`ostk-slo-evaluation-v1`), and `exemplar_policy_digest`/`ExemplarV1::exemplar_digest`
under `DigestDomain::ExemplarSelectionV1` (`ostk-exemplar-selection-v1`), the
same domain the `deterministic_stratified_hash_v1` per-record ordering key
uses for `SHA-256(policy_digest || measurement_source_fact_id ||
provider_record_id)`. Rust tests in `src/memory_contracts/telemetry.rs`
`include_bytes!` every fixture and assert both the raw file digest and, for
positive fixtures, the exact semantic digest. Changing any canonical record,
domain prefix, cap constant, or ordering rule is a contract-version change.

## Algorithmic invariants covered by Rust unit tests, not fixtures

Determinism ("same inputs, same selection, input order irrelevant"),
round-robin-across-strata-until-the-cap, canonical strata order plus
restart-replay identity, the withheld-vs-eligible split, public
reclassification (a private-only selection is never visible through
`public_exemplars()`), the exemplar-only causal-rejection predicate
(`exemplars_do_not_upgrade_outcome`), and the biased-extrema refusal (both at
selector-run time and, since the review that found a decoded receipt could
still claim the combination, at `ExemplarPolicyV1::validate` time) are all
properties of the pure selection function and predicates, not of one static
JSON shape — they are proven by constructing several populations in Rust and
asserting the algorithm's behavior directly, matching how this crate already
tests its other pure algorithms.

**Ordering-rule replay pinning.** `authoritative_fixture_corpus_is_frozen`
does not only decode the frozen fixtures -- for
`measurement-receipt-v1-private-with-exemplars.jsonl` and
`exemplar-selection-receipt-v1-cap-truncated.jsonl` it also re-runs
`select_exemplars_deterministic_stratified_hash_v1` over the exact population
each fixture was generated from and asserts canonical-byte equality with the
frozen record. Raw fixture SHA-256s, per-stratum counts, and
permutation-equality checks all survive an inverted ordering-key comparator;
this replay does not.

**`erasure-is-total-for-duplicates`.** `erasure_is_total_for_content_identical_selected_exemplars`
constructs two selected exemplars with byte-identical content and erases both
in sequence. `ErasedExemplarTombstoneV1::selection_index` -- the erased
record's stable 0-based position in the original round-robin selection
order, computed by `ExemplarSelectionReceiptV1::selection_index_for_present_exemplar`
-- is what makes this possible: cap/consistency validation keys off that
index rather than off content-digest set membership, so tombstoning one
content-duplicate exemplar never blocks tombstoning the other.
