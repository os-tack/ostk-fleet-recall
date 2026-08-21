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
  identity, so different `hypothesis_fingerprint`s), folded together with an
  otherwise legal transition (`open -> refuted -> superseded`) and a
  `supersedes` digest that correctly cites the immediate predecessor, so the
  fingerprint mismatch is the *only* possible reason the fold can reject
  them. (The first version of this test folded two `Ratified` records, which
  `is_allowed_adjudication_transition` already rejects on its own —
  `Ratified -> Ratified` is not a legal transition — so the fingerprint
  check was never actually exercised; a mutation run against the fixed
  version confirmed the corrected test kills the mutant the first version
  missed.) Fixed post-review: `project_adjudication_state` used to fold any
  slice of `CausalRatificationV1` without ever checking they named the same
  hypothesis, so a record authored for hypothesis B could flip hypothesis
  A's projected adjudication state. The fold now fails closed the first time
  a folded record's `hypothesis_fingerprint` differs from the one already
  seen.
- `project_adjudication_state_rejects_a_fold_mixing_two_scopes` — two
  ratification records sharing one `hypothesis_fingerprint` but
  authenticated under different `scope`s, otherwise identical to the test
  above (legal transition, correct `supersedes` citation). Fixed post-review:
  the fold checked `hypothesis_fingerprint` equality but never `scope`
  equality, so a record authored under a foreign tenant/project — which can
  never truthfully `binds_hypothesis` against any real hypothesis in that
  scope — could still be folded and flip another scope's projected
  adjudication state, purely because it happened to collide on the
  fingerprint field. The fold now fails closed the first time a folded
  record's `scope` differs from the one already seen.
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
- `evaluate_ratification_rejects_ratified_positive_role_with_no_bound_intervention`
  and `evaluate_ratification_rejects_intervention_that_does_not_match_the_cited_digest`
  — a `ratified`/positive-role record checked with `intervention: None`, and
  the same record checked against an intervention whose digest does not
  match `intervention_support_digest`. Both `MissingInterventionBinding` and
  `InterventionBindingMismatch` were declared reasons with zero test
  coverage: nothing in the crate ever called `evaluate_ratification` with
  `None`, and nothing supplied a non-matching `Some(intervention)`. Both
  conjuncts of the `None` arm's guard (`conclusion == Ratified &&
  causal_role.is_some()`) survived mutation before these tests existed.
- `separation_of_duty_exception_activated_after_closure_watermark_is_rejected`,
  `separation_of_duty_exception_activated_exactly_at_closure_watermark_is_rejected`,
  and `evaluate_ratification_rejects_retroactively_activated_separation_of_duty_exception`
  — a human-role exception whose `activated_at` is dated after (or exactly
  at) the ratification's own `closure_watermark`. Fixed post-review:
  `evaluate_separation_of_duty` checked only that an exception was *present*
  and validly referenced, never that it was *previously* activated relative
  to the ratification it excuses — so an author of the implicated change
  could cite an exception "activated" a century after the fact and still
  pass. `evaluate_separation_of_duty` now takes `closure_watermark` and
  requires `exception.activated_at < closure_watermark` (strictly before,
  matching `PreRecordedMechanismV1::recorded_before`'s treatment of equal
  instants).
- `unobserved_material_input_observation_rejects_unknown_field`,
  `exemplars_only_basis_rejects_unknown_field`,
  `material_input_separation_unit_variants_reject_unknown_field`, and
  `smuggled_field_inside_material_input_separation_is_rejected_at_full_record_decode`
  — a JSON key smuggled alongside the tag of a *unit* variant
  (`Unobserved`, `ExemplarsOnly`, `SingleInputChanged`,
  `MultipleInputsInseparable`). Fixed post-review:
  `#[serde(deny_unknown_fields)]` on an internally-tagged enum has no effect
  on a unit variant — serde routes it through a tag-only visitor that never
  checks residual keys — so two different byte strings (a clean record and
  one with a smuggled key inside a unit-variant field) decoded to the
  identical value and digested to the identical `InterventionSupportV1`
  digest. Each affected variant is now declared as the empty struct-variant
  form (`Unobserved {}`, ...), which serializes to identical wire bytes but
  is field-checked at decode. `raw_fixture_bytes_are_pinned` and
  `vector_suite_manifest_matches_every_pinned_fixture_digest` (below) pass
  unchanged — no golden fixture byte moved.
- `strictly_sorted_rejects_duplicate_adjacent_elements`,
  `duplicate_material_input_component_is_rejected`,
  `duplicate_entries_in_causal_ratification_canonical_sets_are_rejected`,
  `duplicate_entries_in_intervention_support_canonical_sets_are_rejected`, and
  `duplicate_implicated_change_author_is_rejected` — an exact duplicate
  (not merely misordered) adjacent entry in a canonical set. Fixed
  post-review: `strictly_sorted` and `strictly_sorted_by_component` both use
  `<`, which rejects misordering AND duplication, but no assertion in the
  crate exercised the duplicate case specifically, so a `<` -> `<=`
  mutation — which still catches misordering — silently admitted an exact
  duplicate on every canonical set in the module
  (`material_input_deltas`, `evidence_bundle_digests`,
  `supporting_evidence`, `opposing_evidence`, `unresolved_required_gaps`,
  `residual_unknowns`, `implicated_change_author_principal_ids`, and
  `provenance_to_exposed_cohort` / `cohort_comparison.receipts`).

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
  never be invoked by `RatifierIdentityV1::Agent`. The exception itself is
  also provably prior: `evaluate_separation_of_duty` requires
  `exception.activated_at < ratification.closure_watermark`, so an exception
  "activated" at or after the ratification it excuses — retroactive
  self-authorization — is rejected exactly like a missing exception. This
  proves only relative ordering between two self-asserted timestamps, the
  same as `PreRecordedMechanismV1::recorded_before`; it does not prove
  either timestamp is honest — an external anchor or trusted clock witness
  remains a runtime concern outside this contract-only stage.
- **ACT-04** — recovery is not root-cause resolution. `AdjudicationState` and
  `SupportLevel` are independent axes; `evaluate_ratification` never lets a
  `refuted` *or* `superseded` conclusion carry a positive causal role, and
  `project_adjudication_state` never lets a later record erase what an
  earlier one established — only append a legal transition on top of it.
  This append-only guarantee is also identity-checked: every folded record
  must share both the same `hypothesis_fingerprint` and the same
  authenticated `scope` as the first (a record for a different hypothesis,
  or one authenticated under a different tenant/project, can never flip
  this one's projected state), and a `superseded` record must cite the
  exact digest of the record it immediately follows (an arbitrary or absent
  prior digest fails closed).

- `mechanism_narrative_rejects_empty_control_and_non_nfc_text` and
  `mechanism_narrative_length_boundary_is_inclusive_of_the_maximum` —
  `MechanismNarrativeTextV1::parse`. A full-file mutation sweep (this
  round) found three additional pre-existing survivors here despite this
  test's name claiming non-NFC coverage: `||` -> `&&` on the non-NFC clause
  (nothing ever passed genuinely non-NFC-normalized text — only control
  characters and emptiness were exercised), and `>` -> `==` / `>` -> `>=`
  on the length check (nothing exercised the length boundary at all). Also
  added an assertion on `MechanismNarrativeTextV1::as_str`'s actual return
  value, which no test anywhere in the crate had called.
- `missing_intervention_binding_guard_requires_ratified_conclusion_not_merely_a_causal_role`
  — a targeted mutation run (restricted to `evaluate_ratification`, 15
  mutants, all caught) found this round's own
  `evaluate_ratification_rejects_ratified_positive_role_with_no_bound_intervention`
  test does not discriminate `&&` from `||` in the `None`-arm guard: with
  `causal_role: None`, both operators evaluate `false` since the second
  conjunct is already false. This test instead sets a non-`Ratified`
  conclusion with `causal_role: Some(..)`, so the first conjunct is false
  and the second true — the only shape that tells `&&` and `||` apart.

## Known non-blocking gaps

- `MaterialInputSeparationV1::MultipleInputsIsolated { isolation_receipt }`
  lets an intervention introduce a second *changed* material input that the
  hypothesis's own RUN-03 registered inventory never named, and still reach
  `intervention_supported`: `registered_components_are_covered` only checks
  hypothesis -> intervention coverage (every component the hypothesis
  registered must be observed consistently), never the reverse (that the
  intervention introduces no new changed component the hypothesis never
  registered). `isolation_receipt` is the intended defense for exactly this
  case, but resolving whether it actually proves isolation is a later
  runtime seam's job, not something this contract-only layer can check.
- `CausalRatificationV1::bounded_scope` is declared and digested but read by
  no predicate in this module; it is a consumer-side concern (what the
  ratification's conclusion actually covers), not a v1 admissibility input.
  `closure_watermark` and `SignedSeparationOfDutyExceptionV1::activated_at`
  were in the same position before this round — both are now read by
  `evaluate_separation_of_duty`'s activation-ordering check above.

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
  exists exactly to catch that, with a legal transition and a correct
  `supersedes` citation so the fingerprint conjunct is the sole possible
  rejection — or to stop comparing every folded record's `scope` to the
  first one seen — `project_adjudication_state_rejects_a_fold_mixing_two_scopes`
  exists exactly to catch that, the same way — or to stop comparing a
  `superseded` record's `supersedes` digest to the immediately preceding
  folded record's own digest —
  `project_adjudication_state_rejects_supersedes_citing_a_foreign_digest`
  exists exactly to catch that.
- To break `evaluate_ratification`'s bound-intervention requirement, you
  would need to stop requiring *some* intervention when a `ratified`
  conclusion carries a positive causal role —
  `evaluate_ratification_rejects_ratified_positive_role_with_no_bound_intervention`
  exists exactly to catch that — or to stop checking that a supplied
  intervention actually matches the cited digest —
  `evaluate_ratification_rejects_intervention_that_does_not_match_the_cited_digest`
  exists exactly to catch that.
- To break the separation-of-duty exception's activation-ordering
  requirement, you would need to stop comparing `exception.activated_at`
  against `closure_watermark` (or weaken `<` to `<=`) —
  `separation_of_duty_exception_activated_after_closure_watermark_is_rejected`
  and `separation_of_duty_exception_activated_exactly_at_closure_watermark_is_rejected`
  exist exactly to catch that.
- To break a unit variant's unknown-field rejection, you would need to
  revert it from the empty struct-variant form back to the bare unit form —
  `unobserved_material_input_observation_rejects_unknown_field`,
  `exemplars_only_basis_rejects_unknown_field`, and
  `material_input_separation_unit_variants_reject_unknown_field` each exist
  exactly to catch that for their variant.
- To break any canonical set's rejection of an exact duplicate entry, you
  would need to weaken `strictly_sorted` or `strictly_sorted_by_component`
  from `<` to `<=` — `strictly_sorted_rejects_duplicate_adjacent_elements`
  and its per-field companions exist exactly to catch that.
- To break `MechanismNarrativeTextV1::parse`'s non-NFC or length-boundary
  checks, you would need to weaken the non-NFC `||` to `&&` or the length
  `>` to `==`/`>=` — `mechanism_narrative_rejects_empty_control_and_non_nfc_text`
  and `mechanism_narrative_length_boundary_is_inclusive_of_the_maximum` exist
  exactly to catch that.
- To break `evaluate_ratification`'s requirement that `MissingInterventionBinding`
  fires only for an actually-`Ratified` conclusion (not merely a stray
  positive `causal_role`), you would need to weaken its guard's `&&` to
  `||` —
  `missing_intervention_binding_guard_requires_ratified_conclusion_not_merely_a_causal_role`
  exists exactly to catch that.

## Mechanical verification (this round)

`mutants.sh`'s own shard/`-j 1` invocation fails in this environment: the
harness's `/bin/bash` is 3.2.57 (Apple's frozen build), which has a known
`set -u` bug on an empty array (`"${SHARD[@]}"`), and separately `cargo
mutants --in-place` rejects `--jobs`/`-j` outright in the installed version
(the same conflict the previous adversarial review's own preflight
documented working around). This round ran `cargo +1.94 mutants` directly
through the slot wrapper instead, in two passes: a whole-file pass (`-f
src/memory_contracts/causal.rs`, no `--re` filter, all ~330 mutants —
closing the coverage gap the previous review's function-name regex left,
since a bare `-f` with no filter also reaches every `Type::method` mutant)
established that `project_adjudication_state`'s fingerprint AND scope
identity checks are both caught before this pass was stopped partway
through for time; a second, narrower pass restricted to exactly the
functions this round touched (`project_adjudication_state`,
`evaluate_ratification`, `evaluate_separation_of_duty`, `strictly_sorted`,
`strictly_sorted_by_component`, `MechanismNarrativeTextV1::parse`,
`MaterialInputObservationV1`, `CorroboratingEvidenceBasisV1`,
`MaterialInputSeparationV1`) ran to completion: 47 mutants, 45 caught, 1
unviable, 1 missed (`evaluate_ratification`'s `None`-arm `&&`, fixed by
`missing_intervention_binding_guard_requires_ratified_conclusion_not_merely_a_causal_role`
above and reverified caught by a follow-up 15-mutant pass restricted to
`evaluate_ratification` alone: 15/15 caught).

Changing any canonical record, any expected digest, or any DigestDomain
prefix in this directory is a contract-version change.
