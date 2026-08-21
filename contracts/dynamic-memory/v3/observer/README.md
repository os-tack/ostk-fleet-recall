# Canonical observer admission v2 / run receipt / result contract vectors

These fixtures freeze the contract-only boundary for exhaustive-observer
admission (COVER-01), its run receipts, its typed `observer.result.accepted`
event, and the pure `observer_derivation_disagreement` detector. Every
`.jsonl` file contains one record plus exactly one trailing LF; the LF is
excluded from every pinned digest. None of the fixture identifiers, digests,
or timestamps carries runtime authority: deserializing or structurally
validating any of these types grants no governance or append authority by
itself (AUTH-03, EVENT-03).

## What each vector proves

- `observer-admission-closed-world-v1.jsonl` — a full `ObserverAdmissionV2`
  registry body admitted `closed_world_verified` for an `ast_schema` observer
  kind: exact executable/dependency identity, predicate reference, closed
  input domain, toolchain versions, enumeration algorithm and its
  unsupported-feature diagnostics, the declared outcome-kind set in its fixed
  `success, partial, stale, parse_failure, timeout` order, a coverage-receipt
  recipe reference, and non-zero positive/negative/mutation/adversarial vector
  digests. Proves COVER-01: a non-`llm`/`semantic_search` observer_kind may
  hold the strongest mode.
- `observer-admission-positive-verified-v1.jsonl` — the same shape admitted
  only `positive_verified`. Proves the mode ladder is independently
  admissible below `closed_world_verified`.
- `observer-admission-candidate-only-v1.jsonl` — `observer_kind: "llm"`
  admitted `candidate_only`. Proves the always-`candidate_only` rule is
  satisfiable, not merely enforced as a rejection.
- `observer-run-receipt-success-v1.jsonl` — an `ObserverRunReceiptV1` with
  zero skipped/failed/unsupported/unknown inputs, `complete`/`current`/
  `contiguous` coverage, and a `success` outcome, referencing the
  closed-world admission above by `RegistryReferenceV1`. Proves PRED-05: a
  run receipt carries exact applicability/configuration, input/output
  digests, and a coverage witness that binds W0-COVER's `CoverageReceiptV1`
  by digest only — this module never imports that contract or redefines its
  shape, only its completeness/freshness/continuity triple plus digest.
- `observer-result-verified-negative-v1.jsonl` — an `ObserverResultV1`
  accepted-event preimage whose `admission_digest`/`run_receipt_digest` are
  the *real* `ObserverAdmissionV2::digest()`/`ObserverRunReceiptV1::digest()`
  of the closed-world admission and run-receipt fixtures above (asserted
  against the frozen bytes by
  `result_verified_negative_fixture_chains_to_the_frozen_admission_and_run_receipt`
  in `observer.rs`, not merely decoded independently), with `claim_shape:
  presence`, `evaluated_condition: absent`, `verification_outcome:
  verified_negative`. Proves the closed shape a `verified_negative` finding
  must take, and that PRED-05's supporting-evidence chain is real rather than
  decorative.
- `vector-suite.jsonl` — the manifest of every case file in this directory,
  proving the suite is closed and enumerable.
- `negative-llm-closed-world-v1.jsonl` — `observer_kind: "llm"` admitted
  `closed_world_verified`. Decodes as valid JSON but `validate_shape` must
  reject it: COVER-01/PRED-05 forbid an LLM or semantic-search observer from
  ever proving absence.
- `negative-unknown-field-v1.jsonl` — the closed-world admission plus one
  unrecognized top-level field. `#[serde(deny_unknown_fields)]` must reject
  decoding outright, before `validate_shape` ever runs.
- `negative-unsorted-dependency-digests-v1.jsonl` — a structurally valid
  admission whose `dependency_digests` are given in descending rather than
  strictly ascending order. Decodes, but `validate_shape` must reject the
  non-canonical set exactly as `RegistryPackageV1`'s entry ordering does.

## Invariant IDs enforced

- **COVER-01** — `ObserverAdmissionV2::validate_shape` hard-rejects any
  `observer_kind` in `{llm, semantic_search}` admitted at any mode other than
  `candidate_only`; `derive_verification_outcome` additionally refuses to
  reach `verified_negative`/`verified_exact_set` unless the admission is
  `closed_world_verified`, the run reports zero skipped, failed,
  unsupported, and unknown inputs, the run's `included` input tally is
  non-empty (a closed domain that included nothing proves nothing, however
  "complete" the coverage witness reports it), and coverage is complete,
  current, contiguous-when-applicable.
- **PRED-05** — every `ObserverRunReceiptV1` carries its own witnessed
  executable/dependency digests, the exact immutable `source_version` it
  read, exact applicability/configuration digests, input/output digests, and
  a coverage witness; `derive_verification_outcome` also rejects a run whose
  `outcome` was never declared in its own admission's `declared_outcome_kinds`
  (that set is a closed enumeration, not decoration) as `indeterminate`, the
  same way it treats dependency drift or a `timeout`;
  `derive_verification_outcome` is a pure function of an
  `AdmittedObserverV1` and one `ObserverRunReceiptV1` with no hidden state, so
  identical inputs reproduce an identical outcome and an identical
  `ObserverRunReceiptV1::digest()`.
- **AUTH-03** — `ObserverAdmissionV2`, `ObserverRunReceiptV1`, and
  `ObserverResultV1` are all public, freely constructible candidate shapes;
  only [`AdmittedObserverV1`] and [`AdmittedObserverResultV1`], each with a
  `#[cfg(test)]`-only constructor, represent the governance-activated and
  append-eligible capabilities. `derive_verification_outcome` and
  `detect_disagreement` both require an `AdmittedObserverV1`, never a bare
  `ObserverAdmissionV2`, so no payload can grant itself verification
  authority merely by asserting a matching admission ID. `detect_disagreement`
  additionally requires each side's exact `ObserverRunReceiptV1` and rejects
  unless the accompanying `ObserverResultV1` reproduces from the supplied
  admission and run receipt on *every* binding: `admission_digest` and
  `run_receipt_digest` equal the real digests of the admission/run receipt
  supplied alongside it; `predicate` equals the admission's own `predicate`
  (entry ID, version, AND entry digest — PRED-05's "predicate versions"), so
  an observer admitted for predicate Q can never emit a verified finding
  about an unrelated predicate P merely by relabelling the payload field;
  `applicability` equals the run receipt's own `applicability`, so a result
  can never claim a concrete applicability its own cited run never actually
  read (COVER-01); and its self-reported `verification_outcome` equals what
  `derive_verification_outcome` independently recomputes from that admission
  and run receipt. `detect_disagreement`'s domain-overlap test is likewise
  keyed on the two *admissions*' predicates and the two *runs*' applicability,
  never on the results' self-reported fields, so a payload-to-payload
  comparison can never reopen a seam these bindings just closed. Together
  these close the seam where a self-reported `verification_outcome` could
  otherwise be relabelled (e.g. away from a timed-out run's honest
  `indeterminate`), or a genuine proof about one predicate/applicability
  could be relabelled to oppose a genuine, unrelated verified proof, using
  only public bytes.

## How digests are pinned

Every `.jsonl` file is `include_bytes!`-frozen into
`src/memory_contracts/observer.rs`. Each fixture's raw SHA-256 (over the file
bytes minus the framing LF) is pinned as a `_RAW_SHA256` constant, and the
closed-world admission's semantic identity is additionally pinned as
`ADMISSION_DIGEST`, computed by `ObserverAdmissionV2::digest()` under the
`ostk-observer-admission-v2` domain from `src/memory_contracts/digest.rs`.
Changing any canonical record, digest domain prefix, fixed event kind
(`observer.result.accepted`), declared-outcome-kind ordering, or pinned
digest is a contract-version change, exactly as for the v2 remember and
relation fixture suites.

`scripts/gen_observer_fixtures.py` at the repository root regenerates these
files deterministically from human-readable labels (`hashlib.sha256(label)`)
so every digest's provenance is auditable by inspection; it is a one-off
authoring aid, not part of the build. The one exception is the result
fixture's `admission_digest`/`run_receipt_digest`: those are computed by
`domain_digest()`, a Python replica of
`domain_separated_digest(domain, encode_canonical(obj))` (sorted-key compact
JSON under a SHA-256 domain prefix), applied to the exact admission/run-receipt
objects the script also writes to their own fixture files — so a regeneration
can never again produce a result vector that cites digests unrelated to its
siblings.
