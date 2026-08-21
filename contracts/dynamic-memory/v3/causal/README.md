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
- `negative-ratification-disqualified-intervention.jsonl` — the exact
  positive `causal-ratification-contributing-cause-v1.jsonl` record, except
  its `intervention_support_digest` cites `negative-coverage-partial.jsonl`'s
  intervention (the cheapest disqualifying mutation: `coverage.completeness:
  partial`) instead of the qualifying one. `achieved_support` still
  self-reports `intervention_supported`, and `binds_intervention` still
  passes (the digest citation is correct). `evaluate_ratification` returns
  `BoundInterventionDoesNotReachInterventionSupported`. Fixed post-review:
  `achieved_support` is self-asserted and was previously never checked
  against what the cited intervention actually derives to; see the note in
  the "How digests are pinned" section's `hypothesis_fingerprint` entry
  above.
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
- `negative-ratification-superseded-causal-role.jsonl` — `conclusion:
  superseded` that still carries `causal_role: contributing_cause`;
  `evaluate_ratification` returns `CausalRoleForbiddenForNonRatifiedConclusion`.
  Fixed post-review: the `Superseded` arm used to be empty, so a `superseded`
  record could restate a positive causal role at any support level with no
  intervention evidence and no second confirmation, and
  `project_adjudication_state` would accept it as the very first record for a
  hypothesis (`open -> superseded`). `Refuted` and `Superseded` now share one
  match arm.
- `negative-intervention-scope-mismatch.jsonl` — an `InterventionSupportV1`
  authenticated under `tenant.attacker`/`project.attacker` instead of the
  hypothesis's `tenant.fixture`/`project.fixture`, otherwise identical to the
  positive fixture; `derive_intervention_support_level` returns
  `ScopeMismatch`. Fixed post-review: `binds_hypothesis` compared every causal
  identity except `scope`, so a cross-tenant/cross-project intervention could
  reach `intervention_supported`. `CausalRatificationV1::binds_hypothesis` and
  `::binds_intervention` check scope the same way (see
  `ratification_cross_scope_intervention_binding_fails` in
  `src/memory_contracts/causal.rs`).
- `negative-intervention-unobserved-material-input.jsonl` — a second,
  unregistered material input reported `Unobserved` alongside the one
  registered `Changed` input; `derive_intervention_support_level` returns
  `UnobservedMaterialInput`. Fixed post-review: an `Unobserved` entry used to
  be silently ignored by every check, so an intervention that never actually
  looked at a material input could still reach `intervention_supported`
  (RUN-03 requires every unknown or unobserved dimension to be explicitly
  reported and to block the strongest support level, not to be read as
  "unchanged").
- `negative-intervention-single-input-changed-zero.jsonl` — a shape-only
  negative: `material_input_separation: single_input_changed` with an
  inventory that shows *zero* changed inputs (the one registered component is
  `Unchanged`); `InterventionSupportV1::validate_shape` rejects it. Fixed
  post-review: the consistency check used to be `changed <= 1`, so a record
  could declare `single_input_changed` while its own inventory showed no
  changed input at all.
- `negative-ratification-unreconciled-opposing-evidence.jsonl` — a `ratified`
  conclusion citing one item of `opposing_evidence` with `reconciliation:
  null`; `evaluate_ratification` returns `UnreconciledOpposingEvidencePresent`.
  Fixed post-review: `opposing_evidence` used to be a bare list of
  `AcceptedEventId`s that `evaluate_ratification` never read at all, so
  arbitrary unreconciled opposing evidence could sit on an otherwise-passing
  positive record (doc line 1467: "All verified opposing evidence must be
  reconciled or the causal claim remains open"). Each entry is now an
  `OpposingEvidenceEntryV1` with an optional `OpposingEvidenceReconciliationV1`.
- `negative-ratification-empty-supporting-evidence.jsonl` — a `ratified`
  conclusion with a positive `causal_role` and an empty `supporting_evidence`
  list; `evaluate_ratification` returns
  `SupportingEvidenceRequiredForPositiveCausalRole`. Fixed post-review: an
  empty `supporting_evidence` list used to pass silently.

The following two attacks from the same review are covered by inline Rust
tests in `src/memory_contracts/causal.rs` rather than a byte-frozen fixture,
consistent with how `HypothesisMechanismMismatch` itself has no dedicated
fixture (`unbound_intervention_fails_the_hypothesis_binding_check`):

- `contradictory_material_input_observation_fails_binding_check` — an
  intervention that reports `Changed` for a component the hypothesis already
  pinned as `Unchanged` fails `binds_hypothesis`
  (`InterventionUnreachableReasonV1::HypothesisMechanismMismatch`).
  `registered_components_are_covered` now requires a registered component's
  observation to match exactly unless the hypothesis itself left it
  `Unobserved`.
- `ratification_cannot_be_replayed_against_a_different_hypothesis` — two
  hypotheses that differ in every identity but share one mechanism narrative,
  predicted direction, and `recorded_at` collide on
  `PreRecordedMechanismV1::commitment_digest` but never on
  `CausalHypothesisV1::fingerprint`. Fixed post-review:
  `CausalRatificationV1` used to carry `hypothesis_commitment_digest` — the
  mechanism's own commitment digest, whose preimage is only
  `{schema_version, mechanism_narrative, predicted_outcome_direction,
  recorded_at}` — so one ratification record could be replayed against any
  hypothesis that happened to share those four fields. The field is now
  `hypothesis_fingerprint`, checked against
  `CausalHypothesisV1::fingerprint` (which covers every causal identity plus
  scope) by the new `CausalRatificationV1::binds_hypothesis`. A parallel
  `intervention_support_digest` + `binds_intervention` binds the record to
  the exact `InterventionSupportV1` its `achieved_support` claims to rest
  on — but `binds_intervention` only proves the citation is correct (right
  scope, right digest); it proves nothing about whether the cited record
  itself qualifies. See `negative-ratification-disqualified-intervention.jsonl`
  below for the check that closes that gap.
- `disqualified_bound_intervention_blocks_ratification_despite_self_asserted_support`
  (Rust-only vector, see `negative-ratification-disqualified-intervention.jsonl`
  below) — a `ratified`/`contributing_cause` record whose `achieved_support`
  self-reports `intervention_supported` and whose `intervention_support_digest`
  correctly cites a real `InterventionSupportV1` (so `binds_intervention`
  passes), but that cited intervention itself has `coverage.completeness:
  partial` and so does not re-derive to `intervention_supported`. Fixed
  post-review: `evaluate_ratification` used to trust `achieved_support` at
  face value once the digest citation checked out; it now calls
  `derive_intervention_support_level` on the bound intervention itself and
  requires `Ok(SupportLevel::InterventionSupported)`, rejecting with
  `BoundInterventionDoesNotReachInterventionSupported` otherwise. This call
  also subsumes `intervention.binds_hypothesis(hypothesis)` and the CAUS-01
  scope check, so a disqualified or wrongly-bound intervention can never be
  cited to reach `intervention_supported` no matter what the record itself
  claims.
- `project_adjudication_state_rejects_a_fold_mixing_two_hypotheses` — two
  ratification records for two different hypotheses (different `cause`
  identity, so different `hypothesis_fingerprint`s), folded together. Fixed
  post-review: `project_adjudication_state` used to fold any slice of
  `CausalRatificationV1` without ever checking they named the same
  hypothesis, so a record authored for hypothesis B could flip hypothesis
  A's projected adjudication state. The fold now fails closed the first time
  a folded record's `hypothesis_fingerprint` differs from the one already
  seen.
- `project_adjudication_state_rejects_supersedes_citing_a_foreign_digest` and
  `project_adjudication_state_rejects_a_superseded_record_with_no_predecessor`
  — a `superseded` record whose `supersedes` digest names something other
  than the immediately preceding folded record (a real but unrelated digest,
  or — for the no-predecessor case — any digest at all when there is no
  predecessor to name). Fixed post-review: `validate_shape` requires
  `supersedes` to be *present* for a `superseded` conclusion, but no code
  path compared its *value* to anything — a superseded record could claim to
  supersede an arbitrary or nonexistent prior digest. `project_adjudication_state`
  now requires `event.supersedes == <digest of the immediately preceding
  folded record>` (computed via `CausalRatificationV1::digest`) whenever a
  folded record's conclusion is `superseded`.
- `supersedes_zero_digest_is_rejected_at_shape` — `supersedes:
  "0000...0000"` (`Sha256Digest::ZERO`). `validate_shape` already rejected a
  `ZERO` `hypothesis_fingerprint`, a `ZERO` `intervention_support_digest`,
  and any `ZERO` entry in `evidence_bundle_digests`; `supersedes` gets the
  same treatment now, for consistency (a real digest can never be `ZERO`, so
  this is also implied by the fold-level check above, but the shape check
  fails closed one layer earlier).

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

`CausalRatificationV1` carries `hypothesis_fingerprint` (not
`hypothesis_commitment_digest`) and an `intervention_support_digest`; every
ratification fixture above was regenerated against the corrected preimage, so
their derived digests differ from any value pinned before this fix.

## Invariant IDs

- **CAUS-01** — proximity is not causality. Every positive path here requires
  either a bound `InterventionSupportV1` or, below that tier, an explicitly
  named `CorroboratingEvidenceBasisV1`; nothing reaches
  `intervention_supported` from timing alone. The binding itself is
  identity-checked, not merely digest-checked: `evaluate_ratification`
  re-derives the bound intervention's support level with
  `derive_intervention_support_level` rather than trusting the record's own
  `achieved_support`, so an intervention with a correct citation but the
  wrong scope, an unbound hypothesis, or disqualifying evidence (partial
  coverage, an ambiguous execution outcome, ...) can never be cited to reach
  `intervention_supported`.
- **RUN-01** — telemetry is evidence, not causation. The pre-recorded
  mechanism plus `recorded_before` check is exactly this: an outcome is
  compared against a *pre-registered* expectation, not narrated afterward.
- **AUTH-03** — agents cannot self-promote. `evaluate_separation_of_duty`
  rejects any ratifier that is the proposer, the executor, or an author of
  the implicated change, and the human-only signed-exception carve-out can
  never be invoked by `RatifierIdentityV1::Agent`.
- **ACT-04** — recovery is not root-cause resolution. `AdjudicationState` and
  `SupportLevel` are independent axes; `evaluate_ratification` never lets a
  `refuted` *or* `superseded` conclusion carry a positive causal role, and
  `project_adjudication_state` never lets a later record erase what an
  earlier one established — only append a legal transition on top of it.
  This append-only guarantee is also identity-checked: every folded record
  must share the same `hypothesis_fingerprint` (a record for a different
  hypothesis can never flip this one's projected state), and a `superseded`
  record must cite the exact digest of the record it immediately follows
  (an arbitrary or absent prior digest fails closed).

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
- To break `evaluate_ratification`'s re-derivation of the bound
  intervention's support level, you would need to go back to trusting
  `achieved_support` at face value once `binds_intervention` passes — the
  `negative-ratification-disqualified-intervention.jsonl` vector exists
  exactly to catch that (a correct citation to a disqualified record).
- To break `project_adjudication_state`'s identity binding, you would need to
  stop comparing every folded record's `hypothesis_fingerprint` to the first
  one seen — `project_adjudication_state_rejects_a_fold_mixing_two_hypotheses`
  exists exactly to catch that — or to stop comparing a `superseded`
  record's `supersedes` digest to the immediately preceding folded record's
  own digest —
  `project_adjudication_state_rejects_supersedes_citing_a_foreign_digest`
  exists exactly to catch that.

Changing any canonical record, any expected digest, or any DigestDomain
prefix in this directory is a contract-version change.
