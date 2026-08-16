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
in canonical (digest-ascending) order. Proves exemplar erasure removes the
payload while the receipt's counts and identity-bearing history remain
(EVID-08, EVID-09).

## Negative vectors

**`negative-float-result.jsonl`** — `measurement-receipt-v1-population-unavailable.jsonl`
with `"result":"482.5"` rewritten to the bare JSON number `482.5`. The
canonical-JSON layer forbids floating-point literals outright
(`ContractError::FloatingPointForbidden`), so this fails before
`MeasurementReceiptV1`-specific validation ever runs; the fixture pins that
end-to-end rejection at the receipt boundary.

**`negative-cap-exceeded-exemplar.jsonl`** — the private-with-exemplars
selection with its policy swapped to `exemplar-policy-v1-public-activated`
(512 B per-exemplar cap) and one exemplar's sanitized code frame inflated
past that cap. Decodes structurally; `ExemplarSelectionReceiptV1::validate_shape`
rejects it because one exemplar's canonical wire length exceeds
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
(`exemplars_do_not_upgrade_outcome`), and the biased-extrema refusal are all
properties of the pure selection function and predicates, not of one static
JSON shape — they are proven by constructing several populations in Rust and
asserting the algorithm's behavior directly, matching how this crate already
tests its other pure algorithms.
