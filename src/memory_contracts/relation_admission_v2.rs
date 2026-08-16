//! Provider-attested relation admission v2 (PROV-01, REL-01, AUTH-02).
//!
//! This module decides only whether one candidate provider fact is strong
//! enough to enter a relation attestation at `provider_attested` basis. It
//! never decides `verified`/`refuted`/`superseded` (REL-01: those remain
//! rebuildable projector outcomes over admitted attestations, computed in
//! [`super::relation::project_relation`]). [`RelationAdmissionOutcomeV2`] has
//! private fields and no `Deserialize` impl; it is constructible only by
//! [`evaluate_provider_attested_admission`], never by decoding a payload.
//!
//! [`TrustedProviderIdentityV1`] has no `Deserialize` impl at all: a provider
//! identity can only come from the authenticated connector principal and
//! provider-instance namespace that trusted ingress already established, and
//! [`evaluate_provider_attested_admission`] takes it as a parameter separate
//! from the untrusted candidate — the candidate itself carries no provider
//! identity field a payload could set.

use serde::{Deserialize, Serialize};

use super::{
    ContractError, ContractResult,
    canonical::encode_canonical,
    common::{ContractId, RegistryReferenceV1},
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    identity::{IdentityForm, ResourceUri},
    relation::{RelationAttestationVerdictV1, RelationEdgeV1},
};

const RELATION_ADMISSION_V2_SCHEMA_VERSION: u32 = 2;

/// Authenticated connector principal plus provider-instance namespace.
///
/// No `Serialize`/`Deserialize` impl exists: this type can be built only
/// through [`Self::from_trusted_context`], from server-held authenticated
/// ingress state, never from decoded candidate bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TrustedProviderIdentityV1 {
    connector_principal_id: ContractId,
    provider_instance_namespace: ContractId,
}

impl TrustedProviderIdentityV1 {
    pub const fn from_trusted_context(
        connector_principal_id: ContractId,
        provider_instance_namespace: ContractId,
    ) -> Self {
        Self {
            connector_principal_id,
            provider_instance_namespace,
        }
    }

    pub const fn connector_principal_id(&self) -> &ContractId {
        &self.connector_principal_id
    }

    pub const fn provider_instance_namespace(&self) -> &ContractId {
        &self.provider_instance_namespace
    }
}

/// AUTH-02: the exact bounded fact one evidence kind can prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEvidenceKindV1 {
    /// Proves the provider's observed ref state only.
    GitRefEvent,
    /// A provider's PR/review/merge facts.
    CodeReview,
    /// CI proves a named attempt result.
    CiAttempt,
    /// Proves only its registered predicates (desired state, cohort
    /// membership, rollout status) — never request-serving identity.
    DeploymentControlPlane,
}

/// PROV-01: exact immutable identifiers bound by one provider fact.
///
/// Every variant carries a [`ResourceUri`];
/// [`ProviderFactBindingV1::identifiers_are_immutable`] requires
/// content-addressed (`version`-form) identity, never a mutable label such
/// as a branch name or a moving tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderFactBindingV1 {
    /// A Git ref event: the ref's observed revision, and nothing further.
    RefObservesRevision {
        ref_name: ContractId,
        observed_revision: ResourceUri,
    },
    /// A review binds the exact reviewed head SHA.
    ReviewApprovesRevision { reviewed_revision: ResourceUri },
    /// A build binds the exact source revision it consumed.
    BuildConsumesRevision { source_revision: ResourceUri },
    /// An artifact binds its exact content digest.
    ArtifactBindsDigest { artifact: ResourceUri },
    /// A deployment binds the exact artifact and configuration identities.
    DeploymentBindsArtifactAndConfiguration {
        artifact: ResourceUri,
        configuration: ResourceUri,
    },
}

impl ProviderFactBindingV1 {
    /// AUTH-02: the one evidence kind whose authority can prove this fact.
    pub const fn required_evidence_kind(&self) -> ProviderEvidenceKindV1 {
        match self {
            Self::RefObservesRevision { .. } => ProviderEvidenceKindV1::GitRefEvent,
            Self::ReviewApprovesRevision { .. } => ProviderEvidenceKindV1::CodeReview,
            Self::BuildConsumesRevision { .. } | Self::ArtifactBindsDigest { .. } => {
                ProviderEvidenceKindV1::CiAttempt
            }
            Self::DeploymentBindsArtifactAndConfiguration { .. } => {
                ProviderEvidenceKindV1::DeploymentControlPlane
            }
        }
    }

    /// PROV-01: every bound identifier is content-addressed (`version`-form),
    /// never a mutable label.
    pub fn identifiers_are_immutable(&self) -> bool {
        let is_version = |uri: &ResourceUri| uri.identity_form() == IdentityForm::Version;
        match self {
            Self::RefObservesRevision {
                observed_revision, ..
            }
            | Self::ReviewApprovesRevision {
                reviewed_revision: observed_revision,
            }
            | Self::BuildConsumesRevision {
                source_revision: observed_revision,
            }
            | Self::ArtifactBindsDigest {
                artifact: observed_revision,
            } => is_version(observed_revision),
            Self::DeploymentBindsArtifactAndConfiguration {
                artifact,
                configuration,
            } => is_version(artifact) && is_version(configuration),
        }
    }
}

/// Untrusted candidate for provider-attested relation admission.
///
/// Deliberately carries no provider-identity field: [`evaluate_provider_attested_admission`]
/// always takes the trusted provider identity as a separate parameter, so no
/// payload byte can select who the provider was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAttestedRelationCandidateV2 {
    pub schema_version: u32,
    pub edge: RelationEdgeV1,
    pub verdict: RelationAttestationVerdictV1,
    pub fact_binding: ProviderFactBindingV1,
}

impl ProviderAttestedRelationCandidateV2 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.edge.validate_shape()?;
        if self.schema_version != RELATION_ADMISSION_V2_SCHEMA_VERSION {
            return Err(ContractError::Schema(
                "invalid provider-attested relation candidate v2".into(),
            ));
        }
        Ok(())
    }

    pub fn candidate_id(&self) -> ContractResult<RelationAdmissionCandidateIdV2> {
        self.validate_shape()?;
        Ok(RelationAdmissionCandidateIdV2::from_digest(
            domain_separated_digest(DigestDomain::RelationAdmissionV2, &encode_canonical(self)?),
        ))
    }
}

/// Stable identity of one exact admission candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelationAdmissionCandidateIdV2(Sha256Digest);

impl RelationAdmissionCandidateIdV2 {
    pub const fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Sha256Digest {
        self.0
    }
}

/// Closed admission outcome (REL-01: not `verified`/`refuted`/`superseded` —
/// this only gates whether an attestation may be appended at
/// `provider_attested` basis, downgraded to `declared`, or rejected).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationAdmissionOutcomeKindV2 {
    AdmittedProviderAttested,
    DowngradedToDeclared,
    Rejected,
}

/// Closed, exhaustive reason taxonomy. No free-form prose: every reason this
/// module can produce is one of these variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationAdmissionReasonV2 {
    ProviderFactBindingVerified,
    EvidenceKindAuthorityScopeMismatch,
    MutableLabelInsufficientForProviderAttested,
    ProviderAttestedRequiresSupportsVerdict,
}

/// Opaque admission result. Private fields; constructible only by
/// [`evaluate_provider_attested_admission`]. No `Deserialize` impl exists —
/// a payload can never assert its own admission outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationAdmissionOutcomeV2 {
    candidate_id: RelationAdmissionCandidateIdV2,
    outcome: RelationAdmissionOutcomeKindV2,
    reason: RelationAdmissionReasonV2,
    connector_principal_id: ContractId,
    provider_instance_namespace: ContractId,
}

impl RelationAdmissionOutcomeV2 {
    pub const fn candidate_id(&self) -> RelationAdmissionCandidateIdV2 {
        self.candidate_id
    }

    pub const fn outcome(&self) -> RelationAdmissionOutcomeKindV2 {
        self.outcome
    }

    pub const fn reason(&self) -> RelationAdmissionReasonV2 {
        self.reason
    }

    /// The trusted provider identity this outcome was decided under. Always
    /// copied from the caller's [`TrustedProviderIdentityV1`] argument, never
    /// from the candidate payload.
    pub const fn connector_principal_id(&self) -> &ContractId {
        &self.connector_principal_id
    }

    pub const fn provider_instance_namespace(&self) -> &ContractId {
        &self.provider_instance_namespace
    }
}

/// Decide whether `candidate` is admitted at `provider_attested` basis.
///
/// `provider_identity` and `observed_evidence_kind` must come from trusted,
/// authenticated ingress — never from `candidate`. AUTH-02 bounds which
/// evidence kind may prove which fact; PROV-01 requires every bound
/// identifier to be content-addressed rather than a mutable label.
pub fn evaluate_provider_attested_admission(
    provider_identity: &TrustedProviderIdentityV1,
    observed_evidence_kind: ProviderEvidenceKindV1,
    candidate: &ProviderAttestedRelationCandidateV2,
) -> ContractResult<RelationAdmissionOutcomeV2> {
    let candidate_id = candidate.candidate_id()?;
    let connector_principal_id = provider_identity.connector_principal_id().clone();
    let provider_instance_namespace = provider_identity.provider_instance_namespace().clone();

    if observed_evidence_kind != candidate.fact_binding.required_evidence_kind() {
        return Ok(RelationAdmissionOutcomeV2 {
            candidate_id,
            outcome: RelationAdmissionOutcomeKindV2::Rejected,
            reason: RelationAdmissionReasonV2::EvidenceKindAuthorityScopeMismatch,
            connector_principal_id,
            provider_instance_namespace,
        });
    }

    if !candidate.fact_binding.identifiers_are_immutable() {
        return Ok(RelationAdmissionOutcomeV2 {
            candidate_id,
            outcome: RelationAdmissionOutcomeKindV2::DowngradedToDeclared,
            reason: RelationAdmissionReasonV2::MutableLabelInsufficientForProviderAttested,
            connector_principal_id,
            provider_instance_namespace,
        });
    }

    if candidate.verdict != RelationAttestationVerdictV1::Supports {
        return Ok(RelationAdmissionOutcomeV2 {
            candidate_id,
            outcome: RelationAdmissionOutcomeKindV2::Rejected,
            reason: RelationAdmissionReasonV2::ProviderAttestedRequiresSupportsVerdict,
            connector_principal_id,
            provider_instance_namespace,
        });
    }

    Ok(RelationAdmissionOutcomeV2 {
        candidate_id,
        outcome: RelationAdmissionOutcomeKindV2::AdmittedProviderAttested,
        reason: RelationAdmissionReasonV2::ProviderFactBindingVerified,
        connector_principal_id,
        provider_instance_namespace,
    })
}

/// A `verifier_result` attestation requires a registered proof-recipe
/// reference (`relation_policy_v2`); a payload cannot self-attest its own
/// proof was run.
pub fn require_verifier_result_proof_recipe(
    proof_recipe: Option<&RegistryReferenceV1>,
) -> ContractResult<()> {
    let Some(recipe) = proof_recipe else {
        return Err(ContractError::Schema(
            "verifier_result requires a registered proof recipe reference".into(),
        ));
    };
    recipe.validate()?;
    if recipe.entry_digest == Sha256Digest::ZERO {
        return Err(ContractError::Schema(
            "verifier_result proof recipe cannot use the zero digest".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path, str::FromStr};

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::memory_contracts::{
        canonical::{decode_strict, require_canonical},
        common::{AuthenticatedProjectScopeV1, CanonicalTimestamp, frozen_profile_reference_v1},
        evidence_v2::RegistryHeadBindingV1,
        registry::RegistryHeadV1,
        relation::ConcreteApplicabilityDimensionV1,
    };

    const CANDIDATE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/relation-admission/candidate.jsonl");
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/relation-admission/vector-suite.jsonl");

    const CANDIDATE_ID: &str = "d15de2694b7451a72441b5c81c87524206f45d66b2d163413ab4d34de909b05e";
    const VECTOR_SUITE_DIGEST: &str =
        "9d2d5dec9dc788c5ad4a6458a2189d9deaa4392e914f335622243dd2ae35af5c";

    fn record(bytes: &[u8]) -> &[u8] {
        let body = bytes
            .strip_suffix(b"\n")
            .expect("contract artifact must have one framing LF");
        assert!(!body.ends_with(b"\n"));
        assert!(!body.contains(&b'\r'));
        body
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_str(value).unwrap()
    }

    fn raw_sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn framed_raw_sha256(bytes: &[u8]) -> String {
        let mut framed = bytes.to_vec();
        framed.push(b'\n');
        raw_sha256(&framed)
    }

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.fixture").unwrap(),
            ContractId::new("project.fixture").unwrap(),
        )
    }

    fn registry_binding() -> RegistryHeadBindingV1 {
        RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id: digest(
                    "5a7263f5c98e75b94e82341d2a7729e9578d4691691b5a8401e1c37a83931261",
                ),
                package_digest: digest(
                    "5a931fd5551bec47f83adb019f3e794d1b6a759f4501e7ea26a83076d9518177",
                ),
                activation_policy_digest: digest(
                    "6f92f99ff35969845f08f9b64cee7d86fa42dc6165ebc617d950be8960b86968",
                ),
            },
            effective_from: CanonicalTimestamp::parse("2026-08-15T04:00:00.000000000Z").unwrap(),
            effective_until: None,
        }
    }

    fn reference(id: &str, digest_value: &str) -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new(id).unwrap(),
            version: 1,
            entry_digest: digest(digest_value),
        }
    }

    fn resource(identity_form: IdentityForm, kind: &str, digit: char) -> ResourceUri {
        format!(
            "urn:ostk:{}:v1:{kind}:sha256:{}",
            identity_form.as_str(),
            digit.to_string().repeat(64)
        )
        .parse()
        .unwrap()
    }

    fn edge() -> RelationEdgeV1 {
        RelationEdgeV1 {
            schema_version: 1,
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            registry: registry_binding(),
            relation_proof: reference(
                "relation.deployment_selects_artifact",
                "d0b7d4e7b630ce599389e50948541e21b4aa24d4d030860f6cfcaf7508d49df4",
            ),
            source: resource(IdentityForm::Entity, "deployment", '1'),
            target: resource(IdentityForm::Version, "artifact", '2'),
            applicability: vec![ConcreteApplicabilityDimensionV1 {
                dimension_id: ContractId::new("runtime_environment").unwrap(),
                resource: resource(IdentityForm::Entity, "environment", '3'),
            }],
        }
    }

    fn deployment_fact_binding(
        artifact_form: IdentityForm,
        configuration_form: IdentityForm,
    ) -> ProviderFactBindingV1 {
        ProviderFactBindingV1::DeploymentBindsArtifactAndConfiguration {
            artifact: resource(artifact_form, "artifact", '4'),
            configuration: resource(configuration_form, "configuration", '5'),
        }
    }

    fn candidate() -> ProviderAttestedRelationCandidateV2 {
        ProviderAttestedRelationCandidateV2 {
            schema_version: 2,
            edge: edge(),
            verdict: RelationAttestationVerdictV1::Supports,
            fact_binding: deployment_fact_binding(IdentityForm::Version, IdentityForm::Version),
        }
    }

    fn provider_identity() -> TrustedProviderIdentityV1 {
        TrustedProviderIdentityV1::from_trusted_context(
            ContractId::new("principal.deployment_connector").unwrap(),
            ContractId::new("provider.aws_ecs.prod_cluster").unwrap(),
        )
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RelationAdmissionVectorSuiteV2 {
        schema_version: u32,
        fixture_authority: String,
        candidate_path: String,
        candidate_raw_sha256: String,
        candidate_id: RelationAdmissionCandidateIdV2Wire,
        positive_cases: Vec<String>,
        negative_cases: Vec<String>,
    }

    // A thin serializable mirror of `RelationAdmissionCandidateIdV2` for the
    // vector-suite manifest: the production type intentionally has no wire
    // form, so the pinned digest here is test-only documentation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    struct RelationAdmissionCandidateIdV2Wire(Sha256Digest);

    fn positive_cases() -> Vec<String> {
        [
            "artifact_digest_binding_admitted",
            "build_source_revision_binding_admitted",
            "deployment_immutable_identifiers_admitted",
            "ref_observes_revision_binding_admitted",
            "review_head_sha_binding_admitted",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn negative_cases() -> Vec<String> {
        [
            "evidence_kind_scope_mismatch_rejected",
            "mutable_artifact_label_downgraded",
            "mutable_configuration_label_downgraded",
            "refuting_verdict_rejected",
            "unknown_field",
            "verifier_result_missing_proof_recipe",
            "verifier_result_zero_digest_recipe",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
        values.windows(2).all(|pair| pair[0] < pair[1])
    }

    fn vector_suite(candidate_bytes: &[u8]) -> RelationAdmissionVectorSuiteV2 {
        RelationAdmissionVectorSuiteV2 {
            schema_version: 2,
            fixture_authority: "none; structural canonical fixture bytes never prove an authenticated connector, active registry head, or executed verifier proof".into(),
            candidate_path: "candidate.jsonl".into(),
            candidate_raw_sha256: framed_raw_sha256(candidate_bytes),
            candidate_id: RelationAdmissionCandidateIdV2Wire(
                candidate().candidate_id().unwrap().digest(),
            ),
            positive_cases: positive_cases(),
            negative_cases: negative_cases(),
        }
    }

    #[test]
    fn hard_coded_candidate_matches_canonical_vector() {
        require_canonical(record(CANDIDATE_FIXTURE)).unwrap();
        require_canonical(record(VECTOR_SUITE_FIXTURE)).unwrap();

        let expected_candidate = candidate();
        assert_eq!(
            encode_canonical(&expected_candidate).unwrap(),
            record(CANDIDATE_FIXTURE)
        );
        let decoded: ProviderAttestedRelationCandidateV2 =
            decode_strict(record(CANDIDATE_FIXTURE)).unwrap();
        decoded.validate_shape().unwrap();
        assert_eq!(decoded, expected_candidate);

        let expected_suite = vector_suite(&encode_canonical(&expected_candidate).unwrap());
        assert_eq!(
            encode_canonical(&expected_suite).unwrap(),
            record(VECTOR_SUITE_FIXTURE)
        );
        let suite: RelationAdmissionVectorSuiteV2 =
            decode_strict(record(VECTOR_SUITE_FIXTURE)).unwrap();
        assert_eq!(suite, expected_suite);
        assert!(strictly_sorted(&suite.positive_cases));
        assert!(strictly_sorted(&suite.negative_cases));

        assert_eq!(
            expected_candidate.candidate_id().unwrap().digest(),
            digest(CANDIDATE_ID)
        );
        assert_eq!(
            domain_separated_digest(
                DigestDomain::TestVectorManifest,
                record(VECTOR_SUITE_FIXTURE)
            ),
            digest(VECTOR_SUITE_DIGEST)
        );
        assert_eq!(raw_sha256(CANDIDATE_FIXTURE), suite.candidate_raw_sha256);
    }

    #[test]
    fn each_prov01_binding_maps_to_its_exact_evidence_kind() {
        let bindings = [
            (
                ProviderFactBindingV1::RefObservesRevision {
                    ref_name: ContractId::new("ref.main").unwrap(),
                    observed_revision: resource(IdentityForm::Version, "commit", '6'),
                },
                ProviderEvidenceKindV1::GitRefEvent,
            ),
            (
                ProviderFactBindingV1::ReviewApprovesRevision {
                    reviewed_revision: resource(IdentityForm::Version, "commit", '7'),
                },
                ProviderEvidenceKindV1::CodeReview,
            ),
            (
                ProviderFactBindingV1::BuildConsumesRevision {
                    source_revision: resource(IdentityForm::Version, "commit", '8'),
                },
                ProviderEvidenceKindV1::CiAttempt,
            ),
            (
                ProviderFactBindingV1::ArtifactBindsDigest {
                    artifact: resource(IdentityForm::Version, "artifact", '9'),
                },
                ProviderEvidenceKindV1::CiAttempt,
            ),
            (
                deployment_fact_binding(IdentityForm::Version, IdentityForm::Version),
                ProviderEvidenceKindV1::DeploymentControlPlane,
            ),
        ];
        for (binding, expected_kind) in bindings {
            assert_eq!(binding.required_evidence_kind(), expected_kind);
            assert!(binding.identifiers_are_immutable());
        }
    }

    #[test]
    fn mutable_labels_are_structurally_insufficient() {
        let mutable_artifact = deployment_fact_binding(IdentityForm::Entity, IdentityForm::Version);
        assert!(!mutable_artifact.identifiers_are_immutable());

        let mutable_configuration =
            deployment_fact_binding(IdentityForm::Version, IdentityForm::Entity);
        assert!(!mutable_configuration.identifiers_are_immutable());

        let outcome = evaluate_provider_attested_admission(
            &provider_identity(),
            ProviderEvidenceKindV1::DeploymentControlPlane,
            &ProviderAttestedRelationCandidateV2 {
                fact_binding: mutable_artifact,
                ..candidate()
            },
        )
        .unwrap();
        assert_eq!(
            outcome.outcome(),
            RelationAdmissionOutcomeKindV2::DowngradedToDeclared
        );
        assert_eq!(
            outcome.reason(),
            RelationAdmissionReasonV2::MutableLabelInsufficientForProviderAttested
        );
    }

    #[test]
    fn evidence_kind_scope_mismatch_is_rejected_not_downgraded() {
        let outcome = evaluate_provider_attested_admission(
            &provider_identity(),
            ProviderEvidenceKindV1::GitRefEvent,
            &candidate(),
        )
        .unwrap();
        assert_eq!(outcome.outcome(), RelationAdmissionOutcomeKindV2::Rejected);
        assert_eq!(
            outcome.reason(),
            RelationAdmissionReasonV2::EvidenceKindAuthorityScopeMismatch
        );
    }

    #[test]
    fn refuting_verdict_is_rejected() {
        let refuting = ProviderAttestedRelationCandidateV2 {
            verdict: RelationAttestationVerdictV1::Refutes,
            ..candidate()
        };
        let outcome = evaluate_provider_attested_admission(
            &provider_identity(),
            ProviderEvidenceKindV1::DeploymentControlPlane,
            &refuting,
        )
        .unwrap();
        assert_eq!(outcome.outcome(), RelationAdmissionOutcomeKindV2::Rejected);
        assert_eq!(
            outcome.reason(),
            RelationAdmissionReasonV2::ProviderAttestedRequiresSupportsVerdict
        );
    }

    #[test]
    fn matching_binding_and_evidence_kind_is_admitted() {
        let outcome = evaluate_provider_attested_admission(
            &provider_identity(),
            ProviderEvidenceKindV1::DeploymentControlPlane,
            &candidate(),
        )
        .unwrap();
        assert_eq!(
            outcome.outcome(),
            RelationAdmissionOutcomeKindV2::AdmittedProviderAttested
        );
        assert_eq!(
            outcome.reason(),
            RelationAdmissionReasonV2::ProviderFactBindingVerified
        );
        assert_eq!(outcome.candidate_id(), candidate().candidate_id().unwrap());
    }

    #[test]
    fn verifier_result_requires_a_registered_nonzero_proof_recipe() {
        assert!(require_verifier_result_proof_recipe(None).is_err());

        let zero_digest = RegistryReferenceV1 {
            entry_id: ContractId::new("observer.rust_enum").unwrap(),
            version: 1,
            entry_digest: Sha256Digest::ZERO,
        };
        assert!(require_verifier_result_proof_recipe(Some(&zero_digest)).is_err());

        let valid = reference(
            "observer.rust_enum",
            "36660875b3d71595ccb4b5dfbc17c4c0fe546eec0fa4b8da6a63b17fec074586",
        );
        require_verifier_result_proof_recipe(Some(&valid)).unwrap();
    }

    #[test]
    fn unknown_fields_fail_closed() {
        let canonical = record(CANDIDATE_FIXTURE);
        let mut value: serde_json::Value = serde_json::from_slice(canonical).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("verified".into(), serde_json::Value::Bool(true));
        assert!(
            decode_strict::<ProviderAttestedRelationCandidateV2>(
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "maintainer-only canonical relation-admission fixture regeneration"]
    fn regenerate_relation_admission_v2_artifacts() {
        fn write(output: &Path, name: &str, bytes: &[u8]) {
            let mut framed = bytes.to_vec();
            framed.push(b'\n');
            fs::write(output.join(name), framed).unwrap();
        }

        let output = std::env::var_os("RELATION_ADMISSION_VECTOR_OUTPUT")
            .map(std::path::PathBuf::from)
            .expect("RELATION_ADMISSION_VECTOR_OUTPUT is required");
        fs::create_dir_all(&output).unwrap();

        let candidate_bytes = encode_canonical(&candidate()).unwrap();
        let suite = vector_suite(&candidate_bytes);
        let suite_bytes = encode_canonical(&suite).unwrap();

        write(&output, "candidate.jsonl", &candidate_bytes);
        write(&output, "vector-suite.jsonl", &suite_bytes);

        println!(
            "CANDIDATE_ID {}",
            candidate().candidate_id().unwrap().digest()
        );
        println!(
            "VECTOR_SUITE_DIGEST {}",
            domain_separated_digest(DigestDomain::TestVectorManifest, &suite_bytes)
        );
    }
}
