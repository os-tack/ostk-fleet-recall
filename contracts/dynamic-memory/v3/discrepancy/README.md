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
  vector).
- `episode-relation-combined-from.jsonl` — one `DiscrepancyEpisodeRelationV1` of
  kind `combined_from` with two strictly sorted, unique source episodes merged into
  one, proving the `>= 2` sources arity rule.
- `vector-suite.jsonl` — one manifest binding every fixture's path, raw SHA-256, and
  every fingerprint/identity pinned in `discrepancy.rs::tests`, plus the sorted list
  of negative-case names exercised only in Rust (no separate JSON fixture per
  negative case, matching `relation.rs`'s pattern).

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
- **AUTH-03** (agents cannot self-promote) — `authorize_lifecycle_transition`
  rejects a `Dismiss` whose actor is in `implicated_actor_ids`
  (`auth_03_rejects_self_implicated_dismiss`) and rejects a `claim_conflict`
  waiver whose actor is implicated
  (`separation_of_duty_rejects_a_claim_conflict_waiver_from_a_conflicted_author`).

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
