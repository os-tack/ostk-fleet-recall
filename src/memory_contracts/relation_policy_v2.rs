//! Registry body for an actively routable relation-proof contract.
//!
//! This module is deliberately authority-free. A
//! [`StructurallyResolvedRelationProofV2`] proves that one full
//! [`RegistryEntryV1`] selects the closed relation-proof-v2 body schema and
//! that its envelope agrees with its body. It does not prove package
//! membership, an active registry head, authenticated scope or actor,
//! referenced evidence, or resource identity. The later successor-package and
//! repository seams must resolve every exact dependency from one active
//! package, rederive every URI, route by the trusted relation ID, compare the
//! asserted proof reference, and re-audit support before append.

use serde::{Deserialize, Serialize};

use super::{
    ContractError, ContractResult,
    canonical::{decode_strict, encode_canonical},
    common::{ContractId, RegistryReferenceV1},
    digest::Sha256Digest,
    genesis::RelationMultiplicityV1,
    registry::{RegistryEntryKind, RegistryEntryV1},
    relation::RelationAttestationVerdictV1,
    remember_v2::{ApplicabilityDimensionRuleV2, ResourceIdentityConstraintV2},
};

/// Exact schema selector for [`RelationProofEntryV2`].
pub const RELATION_PROOF_V2_ENTRY_SCHEMA_ID: &str = "registry.relation_proof";
/// Body schema version selected by [`RELATION_PROOF_V2_ENTRY_SCHEMA_ID`].
pub const RELATION_PROOF_V2_SCHEMA_VERSION: u32 = 2;

const MAX_APPLICABILITY_DIMENSIONS: usize = 64;
const MAX_SUPPORT_EVENT_IDS: u16 = 256;

/// Closed admission rules for relation-attestation bases in schema v2.
///
/// The first active contract admits only authenticated actor declarations.
/// Adding inferred, provider-attested, or verifier-result authority requires a
/// new body schema with its own typed result/run and coverage closure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RelationAdmissionBasisRuleV2 {
    Declared {
        allowed_verdicts: Vec<RelationAttestationVerdictV1>,
        minimum_support_events: u16,
        maximum_support_events: u16,
        authenticated_actor_required: bool,
    },
}

impl RelationAdmissionBasisRuleV2 {
    /// Validate the declared-only, support-bounded first-target rule.
    pub fn validate_shape(&self) -> ContractResult<()> {
        match self {
            Self::Declared {
                allowed_verdicts,
                minimum_support_events,
                maximum_support_events,
                authenticated_actor_required,
            } => {
                if allowed_verdicts.as_slice() != [RelationAttestationVerdictV1::Supports]
                    || *minimum_support_events == 0
                    || minimum_support_events > maximum_support_events
                    || *maximum_support_events > MAX_SUPPORT_EVENT_IDS
                    || !*authenticated_actor_required
                {
                    return Err(ContractError::Schema(
                        "invalid declared relation admission rule v2".into(),
                    ));
                }
            }
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// Whether the rule admits the supplied declared support count and verdict.
    ///
    /// This checks body semantics only. It does not authenticate an actor or
    /// prove that any support event exists.
    pub fn admits_declared_shape(
        &self,
        verdict: RelationAttestationVerdictV1,
        support_count: usize,
    ) -> bool {
        match self {
            Self::Declared {
                allowed_verdicts,
                minimum_support_events,
                maximum_support_events,
                authenticated_actor_required,
            } => {
                *authenticated_actor_required
                    && allowed_verdicts.contains(&verdict)
                    && support_count >= usize::from(*minimum_support_events)
                    && support_count <= usize::from(*maximum_support_events)
            }
        }
    }
}

/// Active-package relation recipe for the first declared-only Stage-4 target.
///
/// Exact kind and recipe references close the source, target, and every
/// applicability coordinate. They are still assertions until a package
/// verifier resolves their full entry preimages and `ValidatedIdentityRecipe`
/// witnesses from the same package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RelationProofEntryV2 {
    pub schema_version: u32,
    pub relation_id: ContractId,
    pub version: u32,
    pub source_identity: ResourceIdentityConstraintV2,
    pub target_identity: ResourceIdentityConstraintV2,
    pub applicability_evaluator: RegistryReferenceV1,
    pub applicability_dimensions: Vec<ApplicabilityDimensionRuleV2>,
    pub multiplicity: RelationMultiplicityV1,
    pub temporal_overlap_required: bool,
    pub basis_rules: Vec<RelationAdmissionBasisRuleV2>,
    pub authenticated_scope_required: bool,
    pub resource_rederivation_required: bool,
    pub support_event_reaudit_required: bool,
    pub payload_may_select_attestor: bool,
    pub payload_may_select_registry_head: bool,
    pub payload_may_select_proof: bool,
    pub payload_may_select_verified_state: bool,
}

impl RelationProofEntryV2 {
    /// Validate closed body shape without granting package or runtime authority.
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.source_identity.validate_shape()?;
        self.target_identity.validate_shape()?;
        validate_registry_reference(&self.applicability_evaluator)?;
        for dimension in &self.applicability_dimensions {
            dimension.resource_identity.validate_shape()?;
        }
        for basis_rule in &self.basis_rules {
            basis_rule.validate_shape()?;
        }

        let identity_and_dimensions_are_closed = !self.applicability_dimensions.is_empty()
            && self.applicability_dimensions.len() <= MAX_APPLICABILITY_DIMENSIONS
            && dimensions_are_strictly_sorted(&self.applicability_dimensions)
            && self
                .applicability_dimensions
                .iter()
                .all(|dimension| dimension.required);
        let declared_rule_is_unique = self.basis_rules.len() == 1;
        let server_controls_authority = self.authenticated_scope_required
            && self.resource_rederivation_required
            && self.support_event_reaudit_required
            && !self.payload_may_select_attestor
            && !self.payload_may_select_registry_head
            && !self.payload_may_select_proof
            && !self.payload_may_select_verified_state;

        if self.schema_version != RELATION_PROOF_V2_SCHEMA_VERSION
            || self.version == 0
            || self.multiplicity != RelationMultiplicityV1::ManyToMany
            || self.temporal_overlap_required
            || !identity_and_dimensions_are_closed
            || !declared_rule_is_unique
            || !server_controls_authority
        {
            return Err(ContractError::Schema(
                "invalid relation proof entry v2".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// Return the single declared rule without assuming prior validation.
    pub fn declared_rule(&self) -> ContractResult<&RelationAdmissionBasisRuleV2> {
        self.validate_shape()?;
        self.basis_rules.first().ok_or_else(|| {
            ContractError::Schema("relation proof v2 is missing its declared rule".into())
        })
    }
}

/// One exact full registry entry whose relation-proof-v2 body and envelope agree.
///
/// This typestate remains structural. Any caller can construct registry-entry
/// bytes; active package membership and trusted server routing remain separate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructurallyResolvedRelationProofV2 {
    registry_reference: RegistryReferenceV1,
    proof: RelationProofEntryV2,
}

impl StructurallyResolvedRelationProofV2 {
    pub fn from_registry_entry(entry: &RegistryEntryV1) -> ContractResult<Self> {
        entry.validate()?;
        if entry.kind != RegistryEntryKind::RelationProof
            || entry.entry_schema_id.as_str() != RELATION_PROOF_V2_ENTRY_SCHEMA_ID
            || entry.entry_schema_version != RELATION_PROOF_V2_SCHEMA_VERSION
        {
            return Err(ContractError::Schema(
                "registry entry is not a relation proof v2 body".into(),
            ));
        }

        let original_body_bytes = encode_canonical(&entry.body)?;
        let proof: RelationProofEntryV2 = decode_strict(&original_body_bytes)?;
        proof.validate_shape()?;
        let canonical_typed_body_bytes = encode_canonical(&proof)?;
        let relation_id_matches = proof.relation_id == entry.entry_id;
        let version_matches = proof.version == entry.version;
        if original_body_bytes != canonical_typed_body_bytes
            || !relation_id_matches
            || !version_matches
        {
            return Err(ContractError::ManifestMismatch);
        }

        Ok(Self {
            registry_reference: RegistryReferenceV1 {
                entry_id: entry.entry_id.clone(),
                version: entry.version,
                entry_digest: entry.digest()?,
            },
            proof,
        })
    }

    pub const fn registry_reference(&self) -> &RegistryReferenceV1 {
        &self.registry_reference
    }

    pub const fn proof(&self) -> &RelationProofEntryV2 {
        &self.proof
    }
}

fn validate_registry_reference(reference: &RegistryReferenceV1) -> ContractResult<()> {
    reference.validate()?;
    if reference.entry_digest == Sha256Digest::ZERO {
        return Err(ContractError::Schema(
            "relation policy dependency cannot use the zero digest".into(),
        ));
    }
    Ok(())
}

fn dimensions_are_strictly_sorted(values: &[ApplicabilityDimensionRuleV2]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].dimension_id < pair[1].dimension_id)
}

#[cfg(test)]
mod tests {
    use std::{path::Path, str::FromStr};

    use serde::{Deserialize, Serialize};
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::memory_contracts::{
        canonical::{CanonicalValue, decode_strict, encode_canonical, require_canonical},
        digest::{DigestDomain, domain_separated_digest},
    };

    const ENTRY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/relation-policy/relation-proof-v2-entry.jsonl"
    );
    const POSITIVE_CASES_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/relation-policy/positive-cases-v2.jsonl");
    const NEGATIVE_CASES_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/relation-policy/negative-cases-v2.jsonl");
    const NEGATIVE_ALTERNATE_BASIS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/relation-policy/negative-alternate-basis-entry.jsonl"
    );
    const NEGATIVE_OPTIONAL_DIMENSION_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/relation-policy/negative-optional-dimension-entry.jsonl"
    );
    const NEGATIVE_MULTIPLICITY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/relation-policy/negative-multiplicity-entry.jsonl"
    );
    const NEGATIVE_PAYLOAD_AUTHORITY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/relation-policy/negative-payload-authority-entry.jsonl"
    );
    const NEGATIVE_REFUTING_DECLARATION_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/relation-policy/negative-refuting-declaration-entry.jsonl"
    );
    const NEGATIVE_SUPPORT_BOUNDS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/relation-policy/negative-support-bounds-entry.jsonl"
    );
    const NEGATIVE_TEMPORAL_OVERLAP_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/relation-policy/negative-temporal-overlap-entry.jsonl"
    );
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/relation-policy/vector-suite.jsonl");

    const EXPECTED_ENTRY_DIGEST: &str =
        "2ab8d1d6eb77291f9e0dd90c1234a06f0a1d66d87967184e11b9c18df5921e2b";
    const EXPECTED_POSITIVE_CASES_DIGEST: &str =
        "3af883800cbe7c4a74ee2d9de570bfdd82a435cef22d11b052271c78aaa72d94";
    const EXPECTED_NEGATIVE_CASES_DIGEST: &str =
        "56170368d04b14a732e4512ce27b4737a801a1911b0a7b39cd17f01204466557";
    const EXPECTED_VECTOR_SUITE_DIGEST: &str =
        "62e9883cc6f7ee4d5aa46cd36ff5dfaa4ba8d42548289007b66bc0c0fc28aef0";
    const EXPECTED_ENTRY_RAW_SHA256: &str =
        "391d946d3af439b6d9d64989da5d9d722b4d18b3e1bf6d85db742ecfde677d73";
    const EXPECTED_POSITIVE_CASES_RAW_SHA256: &str =
        "ee28a81354a07857ef834e23ce5d8c2b844f16019ad3179fe96872bebd622ed9";
    const EXPECTED_NEGATIVE_CASES_RAW_SHA256: &str =
        "43e3260cf9fd4b53f9eb6ebbc24d80dc159abc68dd4b8422ea01519f3e2e2964";
    const EXPECTED_NEGATIVE_ALTERNATE_BASIS_RAW_SHA256: &str =
        "d0c80dec658e342b08e27fcaddddafbc891d314c7ddbdd7cb6074a4960e16500";
    const EXPECTED_NEGATIVE_OPTIONAL_DIMENSION_RAW_SHA256: &str =
        "7b2bc2888d1f796aa28a0c67652eac8be8a5a5a1576dece820237780bcaf9349";
    const EXPECTED_NEGATIVE_MULTIPLICITY_RAW_SHA256: &str =
        "601e1f70394033e4df5c774bb11274523024b7c035bfc3986dd7f9ccaf4cd7d7";
    const EXPECTED_NEGATIVE_PAYLOAD_AUTHORITY_RAW_SHA256: &str =
        "4f395e505c0fd08c1d6f6e74ca623e15fff4a146cc474f551b0749d3bb27d3c3";
    const EXPECTED_NEGATIVE_REFUTING_DECLARATION_RAW_SHA256: &str =
        "a6a79b3193f288366698b155d6c534d43488218a908524605833db4859decbc4";
    const EXPECTED_NEGATIVE_SUPPORT_BOUNDS_RAW_SHA256: &str =
        "3ce18744f12a8aedb614b69465dc46a998644f7f6dbd697c3f332164cae44713";
    const EXPECTED_NEGATIVE_TEMPORAL_OVERLAP_RAW_SHA256: &str =
        "55ad65897523f416c9a1b7fa900971dc4e380208130bb7414a26095ebf432ef3";
    const EXPECTED_VECTOR_SUITE_RAW_SHA256: &str =
        "a59e5e5823ec65a58a1ee0956543f6a330e9236ed431197c6595c136df0a5b30";

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RelationPolicyCaseManifestV2 {
        schema_version: u32,
        suite_id: ContractId,
        entry_schema_id: ContractId,
        expected_outcome: ContractId,
        fixture_authority: String,
        cases: Vec<ContractId>,
    }

    impl RelationPolicyCaseManifestV2 {
        fn validate(&self) -> ContractResult<()> {
            if self.schema_version != RELATION_PROOF_V2_SCHEMA_VERSION
                || self.entry_schema_id.as_str() != RELATION_PROOF_V2_ENTRY_SCHEMA_ID
                || !matches!(self.expected_outcome.as_str(), "accept" | "reject")
                || self.fixture_authority != "test_only_no_runtime_authority"
                || self.cases.is_empty()
                || !strictly_sorted(&self.cases)
            {
                return Err(ContractError::Schema(
                    "invalid relation-policy case manifest".into(),
                ));
            }
            encode_canonical(self)?;
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NegativeArtifactPinV2 {
        case_id: ContractId,
        path: String,
        raw_sha256: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RelationPolicyVectorSuiteV2 {
        schema_version: u32,
        suite_id: ContractId,
        fixture_authority: String,
        relation_proof_entry_path: String,
        relation_proof_entry_digest: Sha256Digest,
        positive_cases_path: String,
        positive_cases_digest: Sha256Digest,
        negative_cases_path: String,
        negative_cases_digest: Sha256Digest,
        relation_proof_entry_raw_sha256: String,
        positive_cases_raw_sha256: String,
        negative_cases_raw_sha256: String,
        negative_artifacts: Vec<NegativeArtifactPinV2>,
    }

    fn record(bytes: &[u8]) -> &[u8] {
        let body = bytes
            .strip_suffix(b"\n")
            .expect("contract artifact must have exactly one framing LF");
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

    fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
        values.windows(2).all(|pair| pair[0] < pair[1])
    }

    fn labelled_reference(id: &str, version: u32) -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new(id).unwrap(),
            version,
            entry_digest: domain_separated_digest(
                DigestDomain::RegistryEntry,
                format!("relation-policy-v2-fixture:{id}@{version}").as_bytes(),
            ),
        }
    }

    fn resource_identity(kind: &str, recipe: &str) -> ResourceIdentityConstraintV2 {
        ResourceIdentityConstraintV2 {
            resource_kind_schema: labelled_reference(kind, 3),
            identity_recipe: labelled_reference(recipe, 3),
        }
    }

    fn proof() -> RelationProofEntryV2 {
        RelationProofEntryV2 {
            schema_version: 2,
            relation_id: ContractId::new("relation.repository_parent").unwrap(),
            version: 2,
            source_identity: resource_identity("repository", "identity.github.repository"),
            target_identity: resource_identity("repository", "identity.github.repository"),
            applicability_evaluator: labelled_reference("applicability.default", 3),
            applicability_dimensions: vec![
                ApplicabilityDimensionRuleV2 {
                    dimension_id: ContractId::new("repository_commit").unwrap(),
                    resource_identity: resource_identity("commit", "identity.github.commit"),
                    required: true,
                },
                ApplicabilityDimensionRuleV2 {
                    dimension_id: ContractId::new("runtime_environment").unwrap(),
                    resource_identity: resource_identity(
                        "environment",
                        "identity.runtime.environment",
                    ),
                    required: true,
                },
            ],
            multiplicity: RelationMultiplicityV1::ManyToMany,
            temporal_overlap_required: false,
            basis_rules: vec![RelationAdmissionBasisRuleV2::Declared {
                allowed_verdicts: vec![RelationAttestationVerdictV1::Supports],
                minimum_support_events: 1,
                maximum_support_events: 256,
                authenticated_actor_required: true,
            }],
            authenticated_scope_required: true,
            resource_rederivation_required: true,
            support_event_reaudit_required: true,
            payload_may_select_attestor: false,
            payload_may_select_registry_head: false,
            payload_may_select_proof: false,
            payload_may_select_verified_state: false,
        }
    }

    fn case_ids(values: &[&str]) -> Vec<ContractId> {
        values
            .iter()
            .map(|value| ContractId::new(*value).unwrap())
            .collect()
    }

    fn positive_cases() -> RelationPolicyCaseManifestV2 {
        RelationPolicyCaseManifestV2 {
            schema_version: 2,
            suite_id: ContractId::new("relation.proof.v2.positive").unwrap(),
            entry_schema_id: ContractId::new(RELATION_PROOF_V2_ENTRY_SCHEMA_ID).unwrap(),
            expected_outcome: ContractId::new("accept").unwrap(),
            fixture_authority: "test_only_no_runtime_authority".into(),
            cases: case_ids(&[
                "authenticated_actor_required",
                "declared_supports_only",
                "exact_resource_identity_constraints",
                "required_applicability_dimensions",
                "server_routed_proof",
                "support_event_bounds",
            ]),
        }
    }

    fn negative_cases() -> RelationPolicyCaseManifestV2 {
        RelationPolicyCaseManifestV2 {
            schema_version: 2,
            suite_id: ContractId::new("relation.proof.v2.negative").unwrap(),
            entry_schema_id: ContractId::new(RELATION_PROOF_V2_ENTRY_SCHEMA_ID).unwrap(),
            expected_outcome: ContractId::new("reject").unwrap(),
            fixture_authority: "test_only_no_runtime_authority".into(),
            cases: case_ids(&[
                "alternate_basis",
                "alternate_multiplicity",
                "optional_applicability_dimension",
                "payload_authority",
                "refuting_declared_verdict",
                "support_bounds",
                "temporal_overlap_required",
                "zero_dependency_digest",
            ]),
        }
    }

    fn manifest_digest(manifest: &RelationPolicyCaseManifestV2) -> Sha256Digest {
        manifest.validate().unwrap();
        domain_separated_digest(
            DigestDomain::TestVectorManifest,
            &encode_canonical(manifest).unwrap(),
        )
    }

    fn canonical_value<T: Serialize>(value: &T) -> CanonicalValue {
        decode_strict(&encode_canonical(value).unwrap()).unwrap()
    }

    fn entry() -> RegistryEntryV1 {
        RegistryEntryV1 {
            schema_version: 1,
            kind: RegistryEntryKind::RelationProof,
            entry_id: ContractId::new("relation.repository_parent").unwrap(),
            version: 2,
            entry_schema_id: ContractId::new(RELATION_PROOF_V2_ENTRY_SCHEMA_ID).unwrap(),
            entry_schema_version: 2,
            body: canonical_value(&proof()),
            positive_vector_digest: manifest_digest(&positive_cases()),
            negative_vector_digest: manifest_digest(&negative_cases()),
        }
    }

    fn entry_with(proof: &RelationProofEntryV2) -> RegistryEntryV1 {
        let mut value = entry();
        value.body = canonical_value(proof);
        value
    }

    fn negative_optional_dimension_entry() -> RegistryEntryV1 {
        let mut value = proof();
        value.applicability_dimensions[0].required = false;
        entry_with(&value)
    }

    fn negative_multiplicity_entry() -> RegistryEntryV1 {
        let mut value = proof();
        value.multiplicity = RelationMultiplicityV1::ManyToOne;
        entry_with(&value)
    }

    fn negative_payload_authority_entry() -> RegistryEntryV1 {
        let mut value = proof();
        value.payload_may_select_verified_state = true;
        entry_with(&value)
    }

    fn negative_refuting_declaration_entry() -> RegistryEntryV1 {
        let mut value = proof();
        let RelationAdmissionBasisRuleV2::Declared {
            allowed_verdicts, ..
        } = &mut value.basis_rules[0];
        *allowed_verdicts = vec![RelationAttestationVerdictV1::Refutes];
        entry_with(&value)
    }

    fn negative_support_bounds_entry() -> RegistryEntryV1 {
        let mut value = proof();
        let RelationAdmissionBasisRuleV2::Declared {
            maximum_support_events,
            ..
        } = &mut value.basis_rules[0];
        *maximum_support_events = 257;
        entry_with(&value)
    }

    fn negative_temporal_overlap_entry() -> RegistryEntryV1 {
        let mut value = proof();
        value.temporal_overlap_required = true;
        entry_with(&value)
    }

    fn negative_alternate_basis_bytes() -> Vec<u8> {
        let mut value = serde_json::to_value(entry()).unwrap();
        let rule = value
            .get_mut("body")
            .and_then(|body| body.get_mut("basis_rules"))
            .and_then(serde_json::Value::as_array_mut)
            .and_then(|rules| rules.first_mut())
            .and_then(serde_json::Value::as_object_mut)
            .unwrap();
        rule.insert(
            "kind".into(),
            serde_json::Value::String("verifier_result".into()),
        );
        encode_canonical(&value).unwrap()
    }

    fn negative_artifact_bytes() -> Vec<(&'static str, &'static str, Vec<u8>)> {
        vec![
            (
                "alternate_basis",
                "negative-alternate-basis-entry.jsonl",
                negative_alternate_basis_bytes(),
            ),
            (
                "alternate_multiplicity",
                "negative-multiplicity-entry.jsonl",
                encode_canonical(&negative_multiplicity_entry()).unwrap(),
            ),
            (
                "optional_applicability_dimension",
                "negative-optional-dimension-entry.jsonl",
                encode_canonical(&negative_optional_dimension_entry()).unwrap(),
            ),
            (
                "payload_authority",
                "negative-payload-authority-entry.jsonl",
                encode_canonical(&negative_payload_authority_entry()).unwrap(),
            ),
            (
                "refuting_declared_verdict",
                "negative-refuting-declaration-entry.jsonl",
                encode_canonical(&negative_refuting_declaration_entry()).unwrap(),
            ),
            (
                "support_bounds",
                "negative-support-bounds-entry.jsonl",
                encode_canonical(&negative_support_bounds_entry()).unwrap(),
            ),
            (
                "temporal_overlap_required",
                "negative-temporal-overlap-entry.jsonl",
                encode_canonical(&negative_temporal_overlap_entry()).unwrap(),
            ),
        ]
    }

    fn vector_suite() -> RelationPolicyVectorSuiteV2 {
        let entry_bytes = encode_canonical(&entry()).unwrap();
        let positive_bytes = encode_canonical(&positive_cases()).unwrap();
        let negative_bytes = encode_canonical(&negative_cases()).unwrap();
        RelationPolicyVectorSuiteV2 {
            schema_version: 2,
            suite_id: ContractId::new("relation.proof.v2").unwrap(),
            fixture_authority: "test_only_no_runtime_authority".into(),
            relation_proof_entry_path: "relation-proof-v2-entry.jsonl".into(),
            relation_proof_entry_digest: entry().digest().unwrap(),
            positive_cases_path: "positive-cases-v2.jsonl".into(),
            positive_cases_digest: manifest_digest(&positive_cases()),
            negative_cases_path: "negative-cases-v2.jsonl".into(),
            negative_cases_digest: manifest_digest(&negative_cases()),
            relation_proof_entry_raw_sha256: framed_raw_sha256(&entry_bytes),
            positive_cases_raw_sha256: framed_raw_sha256(&positive_bytes),
            negative_cases_raw_sha256: framed_raw_sha256(&negative_bytes),
            negative_artifacts: negative_artifact_bytes()
                .into_iter()
                .map(|(case_id, path, bytes)| NegativeArtifactPinV2 {
                    case_id: ContractId::new(case_id).unwrap(),
                    path: path.into(),
                    raw_sha256: framed_raw_sha256(&bytes),
                })
                .collect(),
        }
    }

    fn strict_decode_entry(bytes: &[u8]) -> RegistryEntryV1 {
        require_canonical(bytes).unwrap();
        decode_strict(bytes).unwrap()
    }

    #[test]
    fn full_entry_resolves_without_granting_package_authority() {
        let decoded = strict_decode_entry(record(ENTRY_FIXTURE));
        let resolved = StructurallyResolvedRelationProofV2::from_registry_entry(&decoded).unwrap();
        assert_eq!(
            resolved.registry_reference().entry_digest,
            decoded.digest().unwrap()
        );
        assert_eq!(resolved.proof(), &proof());
        assert_eq!(
            resolved.registry_reference().entry_digest,
            digest(EXPECTED_ENTRY_DIGEST)
        );
        let rule = resolved.proof().declared_rule().unwrap();
        assert!(!rule.admits_declared_shape(RelationAttestationVerdictV1::Supports, 0));
        assert!(rule.admits_declared_shape(RelationAttestationVerdictV1::Supports, 1));
        assert!(rule.admits_declared_shape(RelationAttestationVerdictV1::Supports, 256));
        assert!(!rule.admits_declared_shape(RelationAttestationVerdictV1::Supports, 257));
        assert!(!rule.admits_declared_shape(RelationAttestationVerdictV1::Refutes, 1));
    }

    #[test]
    fn selector_and_body_identity_are_exact() {
        let valid = entry();

        let mut wrong_kind = valid.clone();
        wrong_kind.kind = RegistryEntryKind::AuthorityRule;
        assert!(StructurallyResolvedRelationProofV2::from_registry_entry(&wrong_kind).is_err());

        let mut wrong_schema_id = valid.clone();
        wrong_schema_id.entry_schema_id = ContractId::new("registry.authority_rule").unwrap();
        assert!(
            StructurallyResolvedRelationProofV2::from_registry_entry(&wrong_schema_id).is_err()
        );

        let mut wrong_schema_version = valid.clone();
        wrong_schema_version.entry_schema_version = 1;
        assert!(
            StructurallyResolvedRelationProofV2::from_registry_entry(&wrong_schema_version)
                .is_err()
        );

        let mut wrong_body_identity = valid;
        let mut value = proof();
        value.relation_id = ContractId::new("relation.other").unwrap();
        wrong_body_identity.body = canonical_value(&value);
        assert!(
            StructurallyResolvedRelationProofV2::from_registry_entry(&wrong_body_identity).is_err()
        );

        let mut wrong_body_version = entry();
        let mut value = proof();
        value.version = 3;
        wrong_body_version.body = canonical_value(&value);
        assert!(
            StructurallyResolvedRelationProofV2::from_registry_entry(&wrong_body_version).is_err()
        );

        let mut aliased_body = entry();
        let CanonicalValue::Object(body) = &mut aliased_body.body else {
            unreachable!();
        };
        body.insert("future_optional_alias".into(), CanonicalValue::Bool(false));
        assert!(StructurallyResolvedRelationProofV2::from_registry_entry(&aliased_body).is_err());
    }

    #[test]
    fn declared_rule_and_payload_authority_fail_closed() {
        let mut zero_minimum = proof();
        let RelationAdmissionBasisRuleV2::Declared {
            minimum_support_events,
            ..
        } = &mut zero_minimum.basis_rules[0];
        *minimum_support_events = 0;
        assert!(zero_minimum.validate_shape().is_err());

        let mut unauthenticated = proof();
        let RelationAdmissionBasisRuleV2::Declared {
            authenticated_actor_required,
            ..
        } = &mut unauthenticated.basis_rules[0];
        *authenticated_actor_required = false;
        assert!(unauthenticated.validate_shape().is_err());

        let mut duplicate_rule = proof();
        duplicate_rule
            .basis_rules
            .push(duplicate_rule.basis_rules[0].clone());
        assert!(duplicate_rule.validate_shape().is_err());

        let mut alternate_multiplicity = proof();
        alternate_multiplicity.multiplicity = RelationMultiplicityV1::OneToMany;
        assert!(alternate_multiplicity.validate_shape().is_err());

        let mut temporal_overlap = proof();
        temporal_overlap.temporal_overlap_required = true;
        assert!(temporal_overlap.validate_shape().is_err());

        for field in [
            "payload_may_select_attestor",
            "payload_may_select_registry_head",
            "payload_may_select_proof",
            "payload_may_select_verified_state",
        ] {
            let mut value = proof();
            match field {
                "payload_may_select_attestor" => value.payload_may_select_attestor = true,
                "payload_may_select_registry_head" => {
                    value.payload_may_select_registry_head = true;
                }
                "payload_may_select_proof" => value.payload_may_select_proof = true,
                "payload_may_select_verified_state" => {
                    value.payload_may_select_verified_state = true;
                }
                _ => unreachable!(),
            }
            assert!(value.validate_shape().is_err(), "accepted {field}");
        }
    }

    #[test]
    fn every_non_declared_basis_tag_is_rejected() {
        for alternate in ["inferred", "provider_attested", "verifier_result"] {
            let mut value = serde_json::to_value(proof()).unwrap();
            value
                .get_mut("basis_rules")
                .and_then(serde_json::Value::as_array_mut)
                .and_then(|rules| rules.first_mut())
                .and_then(serde_json::Value::as_object_mut)
                .unwrap()
                .insert("kind".into(), serde_json::Value::String(alternate.into()));
            let bytes = encode_canonical(&value).unwrap();
            assert!(decode_strict::<RelationProofEntryV2>(&bytes).is_err());
        }
    }

    #[test]
    fn identity_and_dimension_closure_is_structurally_strict() {
        let mut zero_recipe = proof();
        zero_recipe.source_identity.identity_recipe.entry_digest = Sha256Digest::ZERO;
        assert!(zero_recipe.validate_shape().is_err());

        let mut optional_dimension = proof();
        optional_dimension.applicability_dimensions[0].required = false;
        assert!(optional_dimension.validate_shape().is_err());

        let mut duplicate_dimension = proof();
        duplicate_dimension.applicability_dimensions[1].dimension_id = duplicate_dimension
            .applicability_dimensions[0]
            .dimension_id
            .clone();
        assert!(duplicate_dimension.validate_shape().is_err());

        let mut reordered_dimensions = proof();
        reordered_dimensions.applicability_dimensions.swap(0, 1);
        assert!(reordered_dimensions.validate_shape().is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn canonical_artifacts_and_all_literal_pins_are_frozen() {
        let decoded_entry = strict_decode_entry(record(ENTRY_FIXTURE));
        assert_eq!(decoded_entry, entry());
        assert_eq!(
            decoded_entry.positive_vector_digest,
            digest(EXPECTED_POSITIVE_CASES_DIGEST)
        );
        assert_eq!(
            decoded_entry.negative_vector_digest,
            digest(EXPECTED_NEGATIVE_CASES_DIGEST)
        );

        let positive: RelationPolicyCaseManifestV2 =
            decode_strict(record(POSITIVE_CASES_FIXTURE)).unwrap();
        let negative: RelationPolicyCaseManifestV2 =
            decode_strict(record(NEGATIVE_CASES_FIXTURE)).unwrap();
        positive.validate().unwrap();
        negative.validate().unwrap();
        assert_eq!(positive, positive_cases());
        assert_eq!(negative, negative_cases());
        assert_eq!(
            manifest_digest(&positive),
            digest(EXPECTED_POSITIVE_CASES_DIGEST)
        );
        assert_eq!(
            manifest_digest(&negative),
            digest(EXPECTED_NEGATIVE_CASES_DIGEST)
        );

        for fixture in [
            NEGATIVE_ALTERNATE_BASIS_FIXTURE,
            NEGATIVE_MULTIPLICITY_FIXTURE,
            NEGATIVE_OPTIONAL_DIMENSION_FIXTURE,
            NEGATIVE_PAYLOAD_AUTHORITY_FIXTURE,
            NEGATIVE_REFUTING_DECLARATION_FIXTURE,
            NEGATIVE_SUPPORT_BOUNDS_FIXTURE,
            NEGATIVE_TEMPORAL_OVERLAP_FIXTURE,
        ] {
            let bytes = record(fixture);
            let entry = strict_decode_entry(bytes);
            assert!(StructurallyResolvedRelationProofV2::from_registry_entry(&entry).is_err());
        }

        let suite: RelationPolicyVectorSuiteV2 =
            decode_strict(record(VECTOR_SUITE_FIXTURE)).unwrap();
        assert_eq!(suite, vector_suite());
        assert_eq!(
            domain_separated_digest(
                DigestDomain::TestVectorManifest,
                record(VECTOR_SUITE_FIXTURE)
            ),
            digest(EXPECTED_VECTOR_SUITE_DIGEST)
        );

        for (fixture, expected) in [
            (ENTRY_FIXTURE, EXPECTED_ENTRY_RAW_SHA256),
            (POSITIVE_CASES_FIXTURE, EXPECTED_POSITIVE_CASES_RAW_SHA256),
            (NEGATIVE_CASES_FIXTURE, EXPECTED_NEGATIVE_CASES_RAW_SHA256),
            (
                NEGATIVE_ALTERNATE_BASIS_FIXTURE,
                EXPECTED_NEGATIVE_ALTERNATE_BASIS_RAW_SHA256,
            ),
            (
                NEGATIVE_MULTIPLICITY_FIXTURE,
                EXPECTED_NEGATIVE_MULTIPLICITY_RAW_SHA256,
            ),
            (
                NEGATIVE_OPTIONAL_DIMENSION_FIXTURE,
                EXPECTED_NEGATIVE_OPTIONAL_DIMENSION_RAW_SHA256,
            ),
            (
                NEGATIVE_PAYLOAD_AUTHORITY_FIXTURE,
                EXPECTED_NEGATIVE_PAYLOAD_AUTHORITY_RAW_SHA256,
            ),
            (
                NEGATIVE_REFUTING_DECLARATION_FIXTURE,
                EXPECTED_NEGATIVE_REFUTING_DECLARATION_RAW_SHA256,
            ),
            (
                NEGATIVE_SUPPORT_BOUNDS_FIXTURE,
                EXPECTED_NEGATIVE_SUPPORT_BOUNDS_RAW_SHA256,
            ),
            (
                NEGATIVE_TEMPORAL_OVERLAP_FIXTURE,
                EXPECTED_NEGATIVE_TEMPORAL_OVERLAP_RAW_SHA256,
            ),
            (VECTOR_SUITE_FIXTURE, EXPECTED_VECTOR_SUITE_RAW_SHA256),
        ] {
            assert_eq!(raw_sha256(fixture), expected);
        }
    }

    #[test]
    #[ignore = "maintainer-only canonical fixture regeneration"]
    #[allow(clippy::too_many_lines)]
    fn regenerate_relation_policy_v2_artifacts() {
        use std::fs;

        fn write(output: &Path, name: &str, bytes: &[u8]) {
            let mut framed = bytes.to_vec();
            framed.push(b'\n');
            fs::write(output.join(name), framed).unwrap();
        }

        let output = std::env::var_os("RELATION_POLICY_VECTOR_OUTPUT")
            .map(std::path::PathBuf::from)
            .expect("RELATION_POLICY_VECTOR_OUTPUT is required");
        fs::create_dir_all(&output).unwrap();

        write(
            &output,
            "relation-proof-v2-entry.jsonl",
            &encode_canonical(&entry()).unwrap(),
        );
        write(
            &output,
            "positive-cases-v2.jsonl",
            &encode_canonical(&positive_cases()).unwrap(),
        );
        write(
            &output,
            "negative-cases-v2.jsonl",
            &encode_canonical(&negative_cases()).unwrap(),
        );
        for (_, path, bytes) in negative_artifact_bytes() {
            write(&output, path, &bytes);
        }
        let suite_bytes = encode_canonical(&vector_suite()).unwrap();
        write(&output, "vector-suite.jsonl", &suite_bytes);

        println!("entry_digest={}", entry().digest().unwrap());
        println!(
            "positive_cases_digest={}",
            manifest_digest(&positive_cases())
        );
        println!(
            "negative_cases_digest={}",
            manifest_digest(&negative_cases())
        );
        println!(
            "vector_suite_digest={}",
            domain_separated_digest(DigestDomain::TestVectorManifest, &suite_bytes)
        );
    }
}
