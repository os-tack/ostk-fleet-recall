# Canonical causal hypothesis, intervention, and ratification vectors (v3)

These fixtures freeze the contract-only boundary for `src/memory_contracts/causal.rs`:
causal hypotheses (CAUS-01), the pure v1 intervention-support derivation
(RUN-01, RUN-03), and the pure v1 ratification admissibility policy (AUTH-03,
ACT-04). Every `.jsonl` file contains one canonical JSON record plus exactly
one trailing LF; the LF is excluded from every pinned digest. None of these
records carries runtime authority: deserializing or shape-validating any of
them proves nothing about whether a cited `AcceptedEventId`, registry
reference, or principal is real. A later runtime seam must resolve those
against durable trusted witnesses before any append.

## What each vector proves

### Positive vectors

- `causal-hypothesis-v1.jsonl` — a well-formed `CausalHypothesisV1`: exact
  cause/outcome/workload/artifact/environment identities, a pre-recorded
  mechanism (narrative + predicted direction + `recorded_at`), and a
  non-empty, strictly-sorted registered material-input delta inventory.
  Proves `CausalHypothesisV1::validate_shape` and `::fingerprint` accept and
  pin the intended shape. (CAUS-01, RUN-03)
- `intervention-support-v1.jsonl` — an `InterventionSupportV1` bound to the
  hypothesis above that satisfies every requirement in lines 1418-1476 of
  `docs/DYNAMIC_MEMORY_ARCHITECTURE.md`: exposure begins before and overlaps
  outcome onset, a single material input changed, the mechanism's
  `recorded_at` precedes the outcome's `observed_at`, execution was
  unambiguous and matched the predicted direction, cohorts are a coherent
  before/after pair, and coverage is complete and current. Proves
  `derive_intervention_support_level` returns
  `Ok(Ok(SupportLevel::InterventionSupported))` for this exact pair, and that
  `ProvenInterventionSupportV1` (test-only constructor) accepts it. (CAUS-01,
  RUN-01, RUN-03)
- `causal-ratification-contributing-cause-v1.jsonl` — a `CausalRatificationV1`
  that ratifies `contributing_cause` after the one qualifying intervention
  above, with an empty `unresolved_required_gaps` set and a separation-of-duty
  result where the ratifier is distinct from the proposer, executor, and every
  implicated author. Proves `evaluate_ratification` returns `Ok(Ok(()))` and
  that `AdmittedCausalRatificationV1` (test-only constructor) accepts it.
  (AUTH-03, ACT-04)
- `causal-ratification-primary-trigger-v1.jsonl` — the same shape ratifying
  `primary_trigger`, with two confirmation lines that have distinct
  `source_fact_id`s and distinct `failure_mode` labels. Proves the
  independent-second-confirmation requirement can be satisfied, not only that
  it can fail. (AUTH-03)

### Negative vectors

Each file below is a minimal single-concern mutation of one positive fixture,
proving one specific failure mode fails closed:

- `negative-cause-equals-outcome.jsonl` — `cause == outcome` on a hypothesis;
  `validate_shape` rejects a hypothesis that explains itself.
- `negative-empty-material-input-inventory.jsonl` — an empty
  `material_input_deltas`; RUN-03 requires at least the registered causal
  candidate.
- `negative-exposure-after-onset.jsonl` — cause exposure starting after
  outcome onset; `derive_intervention_support_level` returns
  `ExposureDoesNotPrecedeAndOverlapOnset` and never `intervention_supported`.
- `negative-coverage-partial.jsonl` — confirmation coverage marked `partial`;
  `derive_intervention_support_level` returns `IncompleteOrStaleCoverage`.
  (COVER-03)
- `negative-cohorts-mixed.jsonl` — `cohort_comparison` is the `Mixed` shape;
  `derive_intervention_support_level` returns `MixedCohorts`.
- `negative-execution-ambiguous.jsonl` — `execution_outcome` is `ambiguous`;
  `derive_intervention_support_level` returns `AmbiguousExecutionOutcome`.
- `negative-material-inputs-inseparable.jsonl` — two material inputs changed
  with `material_input_separation` declared `multiple_inputs_inseparable`;
  `derive_intervention_support_level` returns
  `MaterialInputsChangedInseparably`.
- `negative-prediction-after-observation.jsonl` — the mechanism's
  `recorded_at` is after the outcome's `observed_at`;
  `derive_intervention_support_level` returns
  `PredictionRecordedAfterObservation`. This is the commit-before-observe
  check: a prediction narrated after the fact can never support
  `intervention_supported`.
- `negative-ratification-unresolved-gaps.jsonl` — a non-empty
  `unresolved_required_gaps`; `evaluate_ratification` returns
  `UnresolvedGapsPresent` regardless of everything else in the record.
- `negative-ratification-below-intervention-support.jsonl` — a `ratified`
  conclusion with `achieved_support: mechanistically_corroborated`;
  `evaluate_ratification` returns `PositiveCauseBelowInterventionSupport`.
  The v1 policy never ratifies a positive `caused_by` conclusion below
  `intervention_supported`.
- `negative-primary-trigger-same-receipt-twice.jsonl` — `primary_trigger`
  with two confirmation lines citing the *same* `source_fact_id` under two
  different `failure_mode` labels; `evaluate_ratification` returns
  `PrimaryTriggerRequiresIndependentSecondConfirmation`. Citing one receipt
  twice, however labeled, remains one evidentiary line.
- `negative-ratification-author-as-ratifier.jsonl` — the ratifier's
  `principal_id` appears in `implicated_change_author_principal_ids`, with no
  exception cited; `evaluate_separation_of_duty` returns `false` and
  `evaluate_ratification` returns `SeparationOfDutyFailed`. An author of the
  implicated change can never ratify their own change's causal claim.
- `negative-ratification-agent-exception-rejected.jsonl` — the same
  non-distinct ratifier, but as `RatifierIdentityV1::Agent` citing a signed
  separation-of-duty exception; the exception is rejected regardless, because
  an agent ratifier can never invoke it — only a human ratifier can.
- `negative-ratification-superseded-without-digest.jsonl` — `conclusion:
  superseded` with `supersedes: null`; `validate_shape` rejects a supersession
  that does not cite the exact prior digest it supersedes.
- `negative-causal-role-unknown.jsonl` — the bare JSON string `"root_cause"`
  where a `CausalRoleV1` is expected. `necessary_cause`, `sufficient_cause`,
  and unqualified `root_cause` are not variants of this closed enum at all —
  they remain unsupported until a predicate-specific methodology is
  registered — so this fails at decode, not at policy evaluation.
- `negative-adjudication-state-unknown.jsonl` — the bare JSON string
  `"pending"` where an `AdjudicationState` is expected; the closed set is
  exactly `open`, `ratified`, `refuted`, `superseded`.

## How digests are pinned

Every fixture is `include_bytes!`'d verbatim into
`src/memory_contracts/causal.rs`'s test module. Rust tests strip the final LF,
decode each record with `canonical::decode_strict`, and assert:

1. the decoded value round-trips through `canonical::encode_canonical` back to
   the exact stripped bytes (the file is already in canonical form, not merely
   valid JSON that happens to parse);
2. the exact SHA-256 of the raw fixture bytes (the file exactly as checked in,
   trailing LF included) matches a pinned constant, so an accidental
   reformatting of the file is caught even before canonical decoding runs;
3. for identity-bearing records, the derived digest —
   `CausalHypothesisV1::fingerprint`, `InterventionSupportV1::digest`, or
   `CausalRatificationV1::digest`, each computed under its own
   `DigestDomain` prefix (`ostk-causal-hypothesis-v1`,
   `ostk-intervention-support-v1`, `ostk-causal-ratification-v1`) — matches a
   second pinned constant;
4. for every negative fixture, decoding or shape/policy validation fails with
   the named error, so a future change that silently starts accepting an
   invalid shape or a blocked policy outcome breaks a test, not just a
   fixture.

`vector-suite.jsonl` is a single aggregate record: the raw SHA-256 of every
fixture file above plus the derived digests of the four positive artifacts.
It is itself `include_bytes!`'d and pinned the same way, so the manifest and
the fixtures it names cannot silently drift apart.

## Invariant IDs

- **CAUS-01** — proximity is not causality. Every positive path here requires
  either a bound `InterventionSupportV1` or, below that tier, an explicitly
  named `CorroboratingEvidenceBasisV1`; nothing reaches
  `intervention_supported` from timing alone.
- **RUN-01** — telemetry is evidence, not causation. The pre-recorded
  mechanism plus `recorded_before` check is exactly this: an outcome is
  compared against a *pre-registered* expectation, not narrated afterward.
- **AUTH-03** — agents cannot self-promote. `evaluate_separation_of_duty`
  rejects any ratifier that is the proposer, the executor, or an author of
  the implicated change, and the human-only signed-exception carve-out can
  never be invoked by `RatifierIdentityV1::Agent`.
- **ACT-04** — recovery is not root-cause resolution. `AdjudicationState` and
  `SupportLevel` are independent axes; `evaluate_ratification` never lets a
  `refuted` conclusion carry a positive causal role, and `project_adjudication_state`
  never lets a later record erase what an earlier one established — only
  append a legal transition on top of it.

## Reproducing or breaking these vectors

- To break `derive_intervention_support_level` silently, you would have to
  change what "complete and current" coverage means, or what "overlaps
  onset" means, without changing the corresponding negative fixture's
  expected error — the fixture and the test assertion must move together.
- To break `evaluate_ratification`'s separation-of-duty guarantee, you would
  need either to make `RatifierIdentityV1::Agent` accept an exception (the
  `negative-ratification-agent-exception-rejected.jsonl` vector exists
  exactly to catch that), or to stop checking implicated-author membership
  (the `negative-ratification-author-as-ratifier.jsonl` vector exists to
  catch that).
- To break the second-confirmation independence rule, you would need to start
  treating two `ConfirmationLineV1` records with the same `source_fact_id` as
  independent merely because their `failure_mode` labels differ — the
  `negative-primary-trigger-same-receipt-twice.jsonl` vector exists exactly to
  catch that.

Changing any canonical record, any expected digest, or any DigestDomain
prefix in this directory is a contract-version change.
