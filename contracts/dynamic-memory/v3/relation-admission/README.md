# Provider-attested relation admission v2 contract vectors

These fixtures freeze the structural W0-ACT admission seam for
`provider_attested` relation attestations: `ProviderAttestedRelationCandidateV2`
and the pure decision function `evaluate_provider_attested_admission` in
`relation_admission_v2.rs`. They carry no runtime authority — the named
scope, registry head, resource URIs, and provider identities are
deterministic test material. In particular, no fixture here proves an active
registry head, an authenticated connector, or an executed verifier proof; a
later repository seam must supply those facts before treating an
`admitted_provider_attested` outcome as durable.

## What each vector proves

- `candidate.jsonl` — a `ProviderAttestedRelationCandidateV2` asserting a
  `deployment_selects_artifact` edge with a `DeploymentBindsArtifactAndConfiguration`
  fact binding whose `artifact` and `configuration` are both `version`-form
  (content-addressed) resource URIs, and a `Supports` verdict. The fact
  binding's `artifact` names the edge's own `target`, and its `configuration`
  names the resource under the edge's `configuration` applicability
  dimension — the fixture binds the edge it is admitted for, not merely a
  same-shaped fact about a different one (PROV-01). The candidate carries no
  provider-identity field: `evaluate_provider_attested_admission` always
  takes the trusted provider identity and the observed evidence kind as
  separate arguments (never read from this payload), matching the module
  doc's "never payload" rule.
- `vector-suite.jsonl` — raw-pins the candidate fixture, records its
  content-addressed `candidate_id` (`SHA-256("ostk-relation-admission-v2" ||
  0x00 || canonical_bytes)`), and names every positive and negative case the
  Rust contract tests in `relation_admission_v2.rs` exercise.

## How digests are pinned

The fixture is canonical JSON (profile `ostk-canonical-json-v1`) with exactly
one trailing LF. `relation_admission_v2.rs`'s
`hard_coded_candidate_matches_canonical_vector` test re-encodes the Rust
value and asserts byte-for-byte equality with the fixture, then re-derives
`candidate_id()` and the vector-suite's `TestVectorManifest` digest, each
compared against a literal hex constant in the test module.
`RelationAdmissionOutcomeV2` itself has no wire form and is never fixture
material: it is a private-field, non-`Deserialize` capability constructible
only by calling `evaluate_provider_attested_admission` in-process, so the
test suite exercises its six closed reason variants directly rather than by
decoding a payload. Regenerating `candidate.jsonl`/`vector-suite.jsonl`
(`cargo +1.94 test regenerate_relation_admission_v2_artifacts -- --ignored
--nocapture` with `RELATION_ADMISSION_VECTOR_OUTPUT` set) is a
maintainer-only path; it must be followed by updating the literal constants
in the test module.

## Invariants exercised

- **PROV-01** — `each_prov01_binding_maps_to_its_exact_evidence_kind` checks
  all five closed `ProviderFactBindingV1` variants (ref, review, build,
  artifact, deployment) each require content-addressed (`version`-form)
  identifiers; `mutable_labels_are_structurally_insufficient` proves an
  `entity`-form (mutable-label) artifact or configuration URI is downgraded,
  never silently admitted at `provider_attested` strength. Beyond kind and
  form, `ProviderFactBindingV1::binds_edge` requires every bound identifier
  to name the *exact same resource* as the edge it is claimed to admit
  (edge `target` for the four single-identifier bindings; edge `target` plus
  the `configuration` applicability dimension for the deployment binding).
  Each binding has both a real `evaluate_provider_attested_admission` pass
  (`ref_observes_revision_binding_admitted`,
  `review_head_sha_binding_admitted`, `build_source_revision_binding_admitted`,
  `artifact_digest_binding_admitted`, `deployment_immutable_identifiers_admitted`)
  and a real edge-mismatch fail
  (`*_binding_edge_mismatch_rejected`, one per binding, plus
  `deployment_configuration_binding_edge_mismatch_rejected` for the
  deployment binding's second identifier) — a fact about a different
  artifact/revision/configuration than the edge asserts is rejected outright
  (`FactBindingDoesNotBindTheEdge`), not admitted and not merely downgraded.
- **AUTH-02** — `ProviderFactBindingV1::admits_relation_kind` binds each
  variant to the closed relation type it is bounded to prove (the edge's
  `relation_proof` registry entry id and the resource kind of its `source`
  endpoint), checked *before* `binds_edge` and independent of it: a fact
  binding that names the same digest as an edge's target is still rejected
  (`FactBindingCannotProveThisRelation`, never merely downgraded) when the
  edge itself is not the kind of edge that evidence kind is bounded to
  prove. `ref_observes_revision_cannot_admit_deployment_edge`,
  `build_consumes_revision_cannot_admit_deployment_edge`,
  `review_approves_revision_cannot_admit_artifact_edge`, and
  `artifact_binds_digest_cannot_admit_build_edge` each hold the bound
  identifier's digest exactly equal to the wrong edge's target and vary only
  the edge's relation type, proving the same-digest coincidence alone can
  never admit a cross-relation fact.
  `deployment_binding_relation_entry_id_mismatch_rejected` and
  `deployment_binding_source_kind_mismatch_rejected` isolate the two
  `admits_relation_kind` conjuncts independently for the deployment binding.
  The evidence-kind binding named by the invariant itself (Git ref event ->
  observed ref state only; review -> code-review evidence; build/artifact ->
  CI attempt; deployment -> deployment control-plane) is asserted by
  `each_prov01_binding_maps_to_its_exact_evidence_kind`, and
  `evidence_kind_scope_mismatch_is_rejected_not_downgraded` proves a
  `GitRefEvent` cannot admit a deployment fact — scope mismatches fail
  closed as `Rejected`, not merely downgraded.
- **REL-01** — `RelationAdmissionOutcomeV2` has private fields, no
  `Deserialize` impl, and is constructed only inside
  `evaluate_provider_attested_admission`; no payload byte can select
  `admitted_provider_attested` (or `verified`/`refuted`/`superseded`, which
  this module never produces at all — those remain
  `super::relation::project_relation`'s rebuildable projector outcomes).
  `refuting_verdict_is_rejected` additionally proves a `Refutes` verdict
  cannot reach `AdmittedProviderAttested`.
  `verifier_result_requires_a_registered_nonzero_proof_recipe` proves
  `require_verifier_result_proof_recipe` rejects a missing recipe and a
  zero-digest recipe, and accepts only a validated, non-zero
  `RegistryReferenceV1` (the `relation_policy_v2` proof-recipe seam).

## How a reviewer could try to break this

Attempt to add a `provider_identity` field to
`ProviderAttestedRelationCandidateV2` so a payload could self-assert who the
provider was — rejected by `deny_unknown_fields` on the closed struct; the
type has no such field to add without editing the frozen contract module.
Attempt to construct a `RelationAdmissionOutcomeV2` directly (e.g. to forge
`AdmittedProviderAttested` for a candidate that fails PROV-01) — the fields
are private and there is no public constructor other than
`evaluate_provider_attested_admission`, and the type has no `Deserialize`
impl to decode one from bytes either. Attempt to claim a Git ref event proves
a deployment's artifact/configuration identity — rejected by the exhaustive
`required_evidence_kind()` match, which the `evidence_kind_scope_mismatch_is_rejected_not_downgraded`
test exercises directly. Attempt to admit a provider fact whose evidence kind
and binding *shape* are correct but whose bound identifier names a different
artifact, revision, or configuration than the edge asserts — e.g. a real
`DeploymentControlPlane` fact about artifact `sha256:4444…` admitted for an
edge whose `target` is artifact `sha256:2222…` — rejected by
`ProviderFactBindingV1::binds_edge` as `FactBindingDoesNotBindTheEdge`, which
every `*_binding_edge_mismatch_rejected` test exercises directly. Attempt the
sharper AUTH-02 attack: keep a bound identifier's digest *exactly equal* to
an edge's target so `binds_edge` alone would admit it, but point the fact at
an edge of a different relation type entirely — e.g. a real `GitRefEvent`
fact naming the same content-addressed digest as a
`deployment_selects_artifact` edge's `target` artifact, or a real
`ReviewApprovesRevision` fact naming the same digest as an
`artifact_binds_digest` edge's `target` — rejected by
`ProviderFactBindingV1::admits_relation_kind` as
`FactBindingCannotProveThisRelation` before `binds_edge` is even consulted,
which `ref_observes_revision_cannot_admit_deployment_edge`,
`build_consumes_revision_cannot_admit_deployment_edge`,
`review_approves_revision_cannot_admit_artifact_edge`, and
`artifact_binds_digest_cannot_admit_build_edge` each exercise directly for a
different pair of relation types. A Git ref event proves the provider's
observed ref state only, CI proves only the named attempt, and a deployment
control-plane event proves only its registered predicates — never each
other's edges, no matter what digest happens to coincide.
