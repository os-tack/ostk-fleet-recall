# Discrepancy family/episode contracts (W0-EPIS)

Byte-frozen canonical JSON vectors for `src/memory_contracts/discrepancy.rs`. Every
file is exactly one canonical `ostk-canonical-json-v1` record plus one trailing LF
(`require_canonical` in `discrepancy.rs`'s tests enforces this on every fixture in
this directory). Digests are pinned as literal hex constants in
`discrepancy.rs::tests` and asserted equal to values recomputed from these bytes, so
any accidental edit to a fixture fails `cargo test` rather than silently drifting.

Regenerate all files here (maintainer-only, requires re-pinning the digest constants
printed to stdout afterward) with:

```
DISCREPANCY_VECTOR_OUTPUT=contracts/dynamic-memory/v3/discrepancy \
  cargo +1.94 test --locked -p ostk-fleet-recall \
  memory_contracts::discrepancy::tests::regenerate_discrepancy_contract_artifacts \
  -- --ignored --nocapture
```

## Files and what each proves

- `discrepancy-envelope.jsonl` — one immutable `DiscrepancyEnvelopeV1`: a
  `claim_conflict` finding between two implicated claim authors, over a
  `runtime_environment` applicability dimension. Proves the envelope's
  `family_fingerprint` and `episode_fingerprint` are self-consistent with its own
  fields (DISC-01, DISC-02) and that lifecycle/verification state are absent from
  its identity-bearing content ("lifecycle state and verification state therefore
  never define episode identity").
- `comparator-lineage.jsonl` — one `ComparatorLineageV1` binding cardinality,
  polarity rule, modality compatibility, concrete-applicability requirement,
  effective-interval rule, coverage-proof requirement, and comparator version
  together (PRED-02, PRED-04). Deliberately distinct in shape and vocabulary from
  the legacy `same_key_functional_value_v2` detector in `src/ledger/conflict.rs`,
  which has no comparator-lineage concept at all.
- `episode-policy.jsonl` — one `EpisodePolicyV2`: a non-windowed state-discrepancy
  policy with continuity key `runtime_environment`, a one-hour allowed observation
  gap, and the registered rule-change/late-evidence algorithms.
- `lifecycle-event-acknowledge.jsonl`, `lifecycle-event-waive.jsonl`,
  `lifecycle-event-resolve.jsonl`, `lifecycle-event-dismiss.jsonl` — one
  `DiscrepancyLifecycleEventV1` each, all targeting the envelope's episode
  fingerprint. `resolve` proves DISC-03 (resolution cites non-empty evidence);
  `dismiss` carries a structured, non-empty rationale; `waive` carries a signed
  waiver record shaped per DISC-05 (actor, structured reason kind, rationale,
  applicability scope, mandatory `expiry_at`, optional `review_by`).
- `episode-relation-superseded-split.jsonl` — one `DiscrepancyEpisodeRelationV1` of
  kind `superseded`, linking an episode whose opening transition was corrected by
  earlier evidence to its canonical replacement (one source, per the doc's split
  vector). Carries `scope`/`profile`/`family_fingerprint` bound to the same
  envelope the split replays against.
- `episode-relation-combined-from.jsonl` — one `DiscrepancyEpisodeRelationV1` of
  kind `combined_from` with two strictly sorted, unique source episodes merged into
  one, proving the `>= 2` sources arity rule, and (via
  `late_evidence_that_combines_two_episodes_records_combined_from`) that BOTH
  sources project `LifecycleState::Superseded` once the relation is supplied to
  `project_discrepancy_episode` — a combine is a supersession of its sources, not
  merely a record of the arity rule. Carries `scope`/`profile`/`family_fingerprint`
  like the split relation.
- `vector-suite.jsonl` — one manifest binding every fixture's path and every
  fingerprint/identity pinned in `discrepancy.rs::tests`, plus the sorted list of
  negative-case names exercised only in Rust (no separate JSON fixture per negative
  case, matching `relation.rs`'s pattern). It does not itself carry a raw-SHA-256
  field per fixture (unlike `contracts/dynamic-memory/v2/relation/vector-suite.jsonl`,
  which does); byte integrity here is instead enforced directly by
  `hard_coded_fixtures_match_canonical_vectors`'s `assert_eq!` against
  `encode_canonical` of the same Rust-constructed value for every fixture, which is
  an equivalent guarantee, not a weaker one. The module's `raw_sha256` test helper
  exists only to print values into `regenerate_discrepancy_contract_artifacts`'s
  (maintainer-only, `#[ignore]`) stdout for cross-checking during a manual refreeze;
  it is not consumed by any committed assertion.

## Invariant IDs covered here, and how a reviewer could try to break each one

- **DISC-01** (evidence becomes a typed observation first) — the family-fingerprint
  preimage takes a `predicate: RegistryReferenceV1` and a
  `comparator_lineage_fingerprint`, never a raw evidence chunk. Break attempt: try
  to fingerprint a family directly from free-text evidence — there is no
  constructor path that accepts one.
- **DISC-02** (provenance and compatibility are independent) — nothing in
  `DiscrepancyFamilyPreimageV1` or `DiscrepancyEpisodePreimageV1` references a
  provenance/causal-link field at all; only predicate/comparator/applicability
  identity. Break attempt: try to make a missing causal link change a family or
  episode fingerprint — no field exists for it to change.
- **DISC-03** (findings are non-destructive) — `DiscrepancyEnvelopeV1` is
  `Deserialize`, immutable, and carries no mutable lifecycle field at all; all
  state lives in append-only `DiscrepancyLifecycleEventV1` records replayed by
  `project_discrepancy_episode`, which is `Serialize`-only. Break attempt: try to
  mutate lifecycle/verification state without appending an event — there is no
  setter, only replay over history you supply.
- **DISC-04** (surfacing is query-local and explainable) — out of scope for this
  pure contract layer (no retrieval/query surface lives here); `canonical_subject`
  is a concrete `ResourceUri`, never a wildcard, so nothing here can silently stand
  in for "any subject."
- **DISC-05** (waivers are durable policy) — `WaiverRecordV1.actor` and
  `.expiry_at` are mandatory (non-`Option`) fields, so "waiver without actor" and
  "waiver without expiry" cannot be deserialized at all
  (`waiver_without_actor_or_expiry_fails_to_deserialize`). A waiver never
  clears `effective_from`/`effective_until` on the envelope
  (`waiver_does_not_split_or_erase_the_interval_and_expiry_reopens_the_same_episode`),
  and expiry is a pure function of `evaluation_time`, never a rewrite.
  `applicability_scope` is checked, not decorative: **chosen semantics** — every
  entry in `applicability_scope` must exactly match (same `dimension_id`, same
  `value`) an entry actually present in the target envelope's `applicability`.
  `authorize_lifecycle_transition` rejects the `Waive` transition outright (full
  suppression is refused, not partially applied) whenever a scope entry names a
  dimension the envelope does not carry, or a concrete value that disagrees with
  the envelope's value for that dimension; an empty scope always covers (applies
  to the full episode). There is no third, silently-accepted "narrower than the
  envelope but still applied" projection outcome
  (`disc_05_waiver_scope_must_cover_the_envelope_applicability`, covering both
  the out-of-scope-value and alien-dimension negative cases, plus the covered
  positive case reaching `LifecycleState::Waived`).
- **PRED-01** (typed comparison only) — `nominate_repeated_waiver_drift`'s return
  type is `Option<VerificationState>` restricted at the call site to `Candidate`
  only; there is no code path in this module that can return `Verified` from a
  pattern/similarity signal (`repeated_waiver_drift_is_always_candidate_only`).
- **PRED-02** (predicate-specific comparison) — `ComparatorLineageV1` binds
  cardinality + polarity + modality compatibility + applicability requirement +
  interval rule + coverage requirement + version as one unit; changing any one
  field is proven to change the fingerprint
  (`comparator_lineage_version_bump_is_a_new_lineage`).
- **PRED-03** (unknown remains unknown) — a required applicability dimension
  absent from the applicability vector fails `validate_shape` outright; the only
  way to satisfy a required dimension without a concrete resource is an explicit
  `Any` entry actually present in the vector
  (`required_applicability_dimension_omitted_is_rejected_not_treated_as_any`).
- **PRED-04** (modality is explicit) — `ModalityCompatibilityRuleV1` reuses the
  existing closed `PropositionModalityV1` (Normative/Observed/Intended/Attested)
  and requires `left <= right`, rejecting a reversed duplicate registration.
- **PRED-05** (derivation is reproducible) — `DiscrepancyEnvelopeV1` carries
  `detector`, `extractor`, and `registry` as exact `RegistryReferenceV1`/
  `RegistryHeadBindingV1` identities, plus `member_evidence_ids` and
  `supporting_evidence_ids` (non-empty, strictly sorted, deduplicated).
- **AUTH-03** (agents cannot self-promote; "cannot ... silently resolve its own
  discrepancy") — `authorize_lifecycle_transition` rejects `Dismiss`
  (`auth_03_rejects_self_implicated_dismiss`), `Resolve`
  (`auth_03_rejects_self_implicated_resolve`), and `Waive`
  (`auth_03_rejects_self_implicated_waiver_regardless_of_finding_type`) whenever
  the transition's actor is in `implicated_actor_ids`. The check is uniform across
  every `FindingType`, not narrowed to `claim_conflict`: the doc's wording is not
  scoped to claim authorship, and `implicated_actor_ids` is a generic field any
  finding type may populate. `Acknowledge` is exempt (acknowledging a discrepancy
  one is implicated in does not resolve or suppress it). The same function also
  rejects a lifecycle event whose `scope`/`profile` diverges from its envelope's —
  an episode fingerprint is a public identifier, not a secret, so knowledge of it
  alone must never authorize a cross-tenant transition
  (`lifecycle_event_scope_must_match_the_envelope_scope`), matching the
  `self.scope != other.scope` convention every sibling contract in this crate
  already enforces. AUTH-03 also covers a bare verification-state change, not
  only a `lifecycle_transition`: `verification_update` is
  `Option<VerificationUpdateV1>`, and `VerificationUpdateV1.actor` is a
  mandatory (non-`Option`) field, so an unattributed verification flip cannot
  even be constructed by a well-typed caller or deserialized under
  `deny_unknown_fields`
  (`unattributed_verification_update_fails_to_deserialize`).
  `authorize_lifecycle_transition` additionally rejects a `Refuted`
  verification update whose actor is self-implicated — the strongest possible
  suppression a verification update can achieve, gated by the same
  `is_self_implicated` check as `Dismiss`/`Resolve`/`Waive`
  (`auth_03_rejects_self_implicated_verification_refutation`). Promotion to
  `Verified` requires non-empty `evidence_event_ids` at
  `VerificationUpdateV1::validate_shape` (PRED-01/PRED-05: "a verified
  discrepancy cites evidence"), not left to a caller to remember
  (`promotion_to_verified_with_empty_evidence_is_rejected`).
- **DISC-03** (resolution accumulation) — `project_discrepancy_episode` accumulates
  `resolution_evidence_ids` across every `Resolve` transition in the replay
  (sorted, deduplicated, order-independent) instead of overwriting them, so a later
  resolution (e.g. after a reopen) can never drop evidence an earlier one cited
  (`a_later_resolution_never_drops_an_earlier_resolutions_cited_evidence`).
- **Episode-identity determinism** (doc:1329-1331, "every discrepancy type
  registers its continuity-key dimensions") —
  `DiscrepancyEnvelopeV1::validate_against_episode_policy` binds the envelope's
  `episode_policy` reference and `continuity_key_dimension_ids` to the exact
  structurally resolved `EpisodePolicyV2` (`StructurallyResolvedEpisodePolicyV2`,
  mirroring `evidence_v2.rs`'s `StructurallyResolvedConnectorSchemaV2` pattern and
  reusing the existing `DigestDomain::RegistryEntry`-keyed `RegistryEntryV1::digest`
  as the policy fingerprint). `validate_shape` alone only proves the declared
  continuity key is a sorted subset of `applicability`; it cannot prove that subset
  matches what the named policy registers, so a producer could otherwise select any
  continuity-key subset — including the empty set — while citing the same policy
  reference. `validate_against_episode_policy` closes that gap
  (`envelope_continuity_key_divergent_from_registered_policy_is_rejected`,
  `envelope_episode_policy_reference_divergent_from_registry_entry_digest_is_rejected`).
  A runtime admitting an envelope as an accepted event must call this in addition
  to `validate_shape`; it is a separate seam (like
  `validate_against_structural_connector` in `evidence_v2.rs`) because
  `validate_shape` has no access to the resolved policy body.
- **APPL-01/APPL-02/PRED-03/COVER-01 binding to a registered comparator lineage**
  (doc "Predicate schema" 341-379; the same payload-selected-authority class as
  the episode-policy gap above, on the comparator/predicate axis) —
  `DiscrepancyEnvelopeV1::validate_against_comparator_lineage` binds the
  envelope's `comparator_lineage_fingerprint` and
  `required_applicability_dimension_ids` to an exact
  `StructurallyResolvedComparatorLineageV1` (mirroring
  `StructurallyResolvedEpisodePolicyV2`, bound to the real
  `RegistryEntryKind::ComparatorLineage` reserved slot W0-REG-2 landed
  (`dd21a2e`) under its own `entry_schema_id` `registry.comparator_lineage` —
  **not** a squat on `RegistryEntryKind::PredicateSchema` as an earlier
  revision of this type did). `validate_shape` alone only proves the
  envelope's own applicability is internally self-consistent against
  whatever the *producer* declared as required; it cannot prove
  `comparator_lineage_fingerprint` names a real registered lineage, nor that
  the envelope actually satisfies that lineage's own
  `concrete_applicability_required`/`coverage_proof_required` flags. The bound
  check proves, in order:
  (a) the fingerprint matches the resolved lineage's own fingerprint
  (`envelope_comparator_lineage_fingerprint_divergent_from_registry_is_rejected`);
  (d) `required_applicability_dimension_ids` equals the registry's set for
  this lineage, not the payload's own declaration
  (`envelope_required_applicability_dimension_ids_divergent_from_registry_is_rejected`);
  (b) if `concrete_applicability_required`, every required dimension resolves
  to `Concrete`, never `Any`
  (`envelope_any_applicability_under_concrete_requirement_is_rejected`); (c) if
  `coverage_proof_required`, `coverage_receipt_ids` is non-empty
  (`envelope_missing_coverage_receipt_under_coverage_requirement_is_rejected`).
  Positive case:
  `envelope_validates_against_its_exact_registered_comparator_lineage`. A
  runtime admitting an envelope must call this in addition to `validate_shape`
  and `validate_against_episode_policy`, for the same reason: none of them has
  access to the others' resolved registry body.

  **Registry-path admissibility** (closing the adversarial-review blocker that
  the `PredicateSchema` squat left `validate_against_comparator_lineage`
  structurally unreachable at runtime): `ComparatorLineage` is
  `is_generation2_only()`, so no `SemanticallyClosedGenesisPackage` (v1),
  `SemanticallyClosedSuccessorPackage`, or `SemanticallyClosedStage4Package`
  can ever admit this entry — `decode_entry` (`genesis.rs`) and
  `decode_successor_entry` (`successor_package.rs`) both refuse it before
  reaching any comparator-specific logic
  (`comparator_lineage_entry_is_rejected_by_every_v1_and_successor_closure`,
  which appends the entry to the frozen genesis and Stage-4/successor
  fixtures and asserts each closure's rejection). What genuinely proves
  registry-package *membership* today — as opposed to a hand-built loose
  `RegistryEntryV1` — is `generation2::ReservedSlotCarriageV1::from_package_entry`
  on a manifest-verified, canonically ordered, digest-checked
  `RegistryPackageV1`: it reports the identical canonical body bytes
  `StructurallyResolvedComparatorLineageV1` resolves directly from the same
  raw entry (`comparator_lineage_registration_is_carriable_through_the_real_registry_package_path`).
  Carriage is not admission (`generation2.rs`'s own `ReservedSlotCarriageV1`
  doc comment): full generation-2 typed-body dispatch for this kind is a
  separate piece of work this workstream cannot do itself (`registry.rs`/
  `generation2.rs`/`successor_package.rs` are outside its owned files) —
  flagged under the handoff's `requests` to W0-REG.

## `LifecycleState::Superseded` reachability (doc lines 1353-1356, 1329-1331)

`project_discrepancy_episode` takes a `relations: &[DiscrepancyEpisodeRelationV1]`
parameter. Whenever a `superseded` **or** `combined_from` relation's
`from_episodes` contains the target envelope's `episode_fingerprint`, the
projection is `LifecycleState::Superseded`, overriding every event-driven
lifecycle transition and the waiver-expiry reopen
(`superseded_dominates_a_waiver_expiry_reopen`) — a replaced episode is
frozen, not reopened. This is the *only* producer of `Superseded`: passing
`&[]` (no relation set applies) never yields it. The split vector
(`late_evidence_that_changes_the_opening_transition_creates_a_replacement_episode`)
asserts both halves of the doc's "old marked superseded, retained": the OLD
episode's projection is `Superseded`, the NEW episode's is not, and neither
episode's own fingerprint changes because of the relation (retention without
erasure — the relation is an append-only sibling record, never a rewrite of
either envelope). The combine vector
(`late_evidence_that_combines_two_episodes_records_combined_from`) proves the
same "old marked superseded, retained" rule for the many-to-one case: BOTH
source envelopes project `Superseded` once the `combined_from` relation is
supplied, and neither source's own fingerprint changes — the same continuous
incompatible interval must not surface three times (once per source, once
for the combined episode).

**Scope/profile/family binding on relations** (closing the adversarial-review
blocker that a relation could force `Superseded` — the strongest suppression
in the model — from only the public episode fingerprints, with no
authenticated binding at all): `DiscrepancyEpisodeRelationV1` now carries
`scope`, `profile`, and `family_fingerprint`, and `project_discrepancy_episode`
rejects (returns `Err`, does not merely ignore) any relation that names the
target envelope's episode — as a source or as the `to_episode` — whose
`scope`/`profile`/`family_fingerprint` diverges from the envelope's own
(`episode_relation_with_foreign_scope_is_rejected`,
`episode_relation_naming_a_different_family_is_rejected`), mirroring
`authorize_lifecycle_transition`'s identical check on lifecycle events. A
relation naming *other* episodes entirely is unaffected by this check — only
relations that actually name the envelope being projected are bound
(`unrelated_episode_relation_in_the_pool_is_ignored_without_scope_or_family_checks`).

## Observation gap (doc lines 1338-1348)

`EpisodePolicyV2::allowed_observation_gap_seconds` is read by
`classify_observation_gap(policy, prior_effective_until, next_effective_from)`,
which returns `ObservationGapOutcomeV1::Bridged` (same episode; the interval
is recorded incomplete but not ended) when the gap is within the registered
bound, and `EpisodeEnded` otherwise — including when the policy registers no
bound at all (`None`, doc: "no observation gap may be bridged"). Three
committed vectors: a 30-minute gap under a one-hour bound is `Bridged`
(`observation_gap_within_the_allowed_bound_is_bridged`); a multi-day gap is
`EpisodeEnded`, paired with the prior occurrence becoming
`VerificationState::Indeterminate` (already representable via
`VerificationUpdateV1`, replayed through the ordinary lifecycle-event seam)
and a `PossiblyContinues` relation linking it to the newly opened episode
(`long_gap_ends_the_prior_occurrence_and_links_a_new_episode_by_possibly_continues`);
and a `PossiblyContinues` relation asserted for a gap that is still bridged
is rejected by `validate_possibly_continues_gap`
(`possibly_continues_is_rejected_within_the_allowed_observation_gap`) — the
policy already says those two occurrences are the same episode, so linking
them as merely "possibly" the same one contradicts it.
`classify_observation_gap`/`validate_possibly_continues_gap` are pure
decision functions, matching `select_opening_transition` and
`nominate_repeated_waiver_drift`: recording the indeterminate verification
update and the relation once the gap is classified remains the caller's
responsibility.

## Other hardening closed from the adversarial review's non-blocking observations

- **Zero-width rationale**: `str::trim` alone does not strip U+200B/U+200C/
  U+200D/U+FEFF/U+2060, so a rationale of only those characters passed the
  non-empty check in form while carrying no visible content. `is_blank_rationale`
  strips them before checking emptiness, used by both `WaiverRecordV1` and
  `DismissalReasonV1` (`dismiss_rationale_of_only_zero_width_spaces_is_rejected`,
  `waiver_rationale_of_only_zero_width_spaces_is_rejected`), while ordinary
  rationale that merely contains a stray zero-width character still passes
  (`rationale_mixing_zero_width_and_visible_content_still_passes`).
- **Backdated waiver expiry**: `authorize_lifecycle_transition` now rejects a
  `Waive` transition whose `waiver.expiry_at` is at or before the event's own
  `effective_at` — such a waiver would project `Open` the instant it is
  applied, recording an audit-trail entry for a suppression that never had
  effect (`waiver_expiry_at_or_before_the_events_effective_at_is_rejected`).
- **Duplicate event idempotency**: `project_discrepancy_episode` now dedups
  byte-identical lifecycle events (by canonical bytes, after sorting) before
  replaying them, so an at-least-once delivery retry that appends the same
  event twice is applied once, not once per occurrence
  (`duplicate_byte_identical_lifecycle_events_are_applied_once`).
- **`nominate_repeated_waiver_drift` doc accuracy**: the function's doc
  comment previously claimed the return type "structurally cannot express
  `Verified`" — false; `Option<VerificationState>` can express
  `Some(Verified)`, only the function *body* restricts it to `Candidate`.
  The comment now states this precisely.

Declined (non-blocker, unchanged from the prior review):
- **Episode-policy version-only binding**: family/episode fingerprints bind
  the bare `episode_policy_version` integer, never the policy's
  `entry_id`/`entry_digest`, so two distinct registered policies sharing a
  version number collapse into one family/episode. Both the brief and doc
  lines 1315-1319 specify "episode-policy version" as the bound field; this
  is the specified preimage shape, not a defect this workstream can unilaterally
  widen without a doc/brief change.
- **Waiver-expiry-reopen always returns `Open`, never a prior `Resolved`
  state**: changing this would require tracking and restoring an arbitrary
  prior lifecycle state (potentially itself the product of several
  transitions), a materially different projection design, not a small fix;
  `resolved_at`/`resolution_evidence_ids` are retained regardless (no
  information is lost, only the *current-state* label), and the existing
  `waiver_does_not_split_or_erase_the_interval_and_expiry_reopens_the_same_episode`
  vector pins the chosen behaviour explicitly.
- **Frozen envelope fixture's `episode_policy.entry_digest` is a placeholder**:
  informational only (the fixture proves `validate_shape`, not the
  registry-bound path; `envelope_bound_to_resolved_policy()` exists
  specifically for the latter) — no fixture bytes need to change.

## Fingerprint domain separation from `memory_conflicts`

`src/ledger/conflict.rs`'s `same_key_functional_value_v2` identity is a database
row keyed by `(tenant_id, project, claim_key, detector)` — an integer primary key
plus string columns, enforced by the CockroachDB unique indexes in migrations
0015/0017. `DiscrepancyFamilyFingerprintV1` and `DiscrepancyEpisodeFingerprintV1`
are domain-separated SHA-256 digests (`ostk-discrepancy-family-v1` /
`ostk-discrepancy-episode-v1`, distinct from every other `DigestDomain` prefix in
`digest.rs`, including every domain used by `remember_v2`/`relation`/`evidence`).
Neither identity space can produce a value that collides with, or could be mistaken
for, a row in the other: one is a bigint-keyed table row, the other is a 32-byte
digest under a fixed, versioned preimage that a legacy `memory_conflicts` row could
never have been hashed into (the detector column holds the literal string
`same_key_functional_value_v2`, which is not a valid preimage for either domain).
`memory_conflicts` and `same_key_functional_value_v2` are untouched by this
workstream (contract-only work).
