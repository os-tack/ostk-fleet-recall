//! Exact, independently approved normative proposition bindings.

use serde::{Deserialize, Serialize};

use super::{
    ContractError, ContractResult,
    canonical::{CanonicalValue, encode_canonical},
    common::{
        AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, HexBytes, ProfileReferenceV1,
        RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    identity::ResourceUri,
};

const BINDING_SCHEMA_VERSION: u32 = 1;
const MAX_PROPOSITIONS: usize = 256;
const MAX_SPANS: usize = 256;
const MAX_APPROVALS: usize = 64;

/// Exact source bytes supporting one proposition. Line numbers are absent from
/// identity and remain presentation metadata only.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceByteSpanV1 {
    pub start: u64,
    pub end: u64,
    pub selected_bytes_digest: Sha256Digest,
}

impl SourceByteSpanV1 {
    fn validate(&self) -> ContractResult<()> {
        if self.start >= self.end {
            return Err(ContractError::Schema(
                "source byte span is empty or reversed".into(),
            ));
        }
        Ok(())
    }
}

/// Typed proposition selected from the exact source object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormativePropositionV1 {
    pub predicate_schema: RegistryReferenceV1,
    pub proposition_fingerprint: Sha256Digest,
}

/// Unsigned statement proposed for independent approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormativeBindingProposalV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub binding_family_id: ContractId,
    pub expected_active_binding_set_digest: Option<Sha256Digest>,
    pub repository_entity_id: ResourceUri,
    pub repository_version_id: ResourceUri,
    pub blob_id: ResourceUri,
    pub exact_path_bytes: HexBytes,
    pub source_spans: Vec<SourceByteSpanV1>,
    pub parser_artifact_id: ResourceUri,
    pub parser_configuration_digest: Sha256Digest,
    pub propositions: Vec<NormativePropositionV1>,
    pub applicability_evaluator: RegistryReferenceV1,
    pub applicability_selector: CanonicalValue,
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
    pub registry_package_digest: Sha256Digest,
    pub activation_policy_digest: Sha256Digest,
    pub explicitly_supersedes_statement_id: Option<Sha256Digest>,
    pub proposer_principal_id: ContractId,
    pub source_author_principal_id: ContractId,
}

impl NormativeBindingProposalV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.profile.validate()?;
        self.applicability_evaluator.validate()?;
        if self.schema_version != BINDING_SCHEMA_VERSION
            || self.source_spans.is_empty()
            || self.source_spans.len() > MAX_SPANS
            || self.propositions.is_empty()
            || self.propositions.len() > MAX_PROPOSITIONS
            || self.applicability_selector.as_object().is_none()
            || !strictly_sorted(&self.source_spans)
            || !strictly_sorted(&self.propositions)
            || self
                .effective_until
                .as_ref()
                .is_some_and(|until| until <= &self.effective_from)
        {
            return Err(ContractError::Schema(
                "invalid normative binding proposal".into(),
            ));
        }
        for span in &self.source_spans {
            span.validate()?;
        }
        for proposition in &self.propositions {
            proposition.predicate_schema.validate()?;
        }
        Ok(())
    }

    pub fn statement_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::NormativeBindingStatement,
            &encode_canonical(self)?,
        ))
    }
}

/// Signature framing is frozen now; cryptographic verification is added with
/// the bootstrap signer implementation rather than accepting arbitrary algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalAttestationV1 {
    pub schema_version: u32,
    pub statement_id: Sha256Digest,
    pub principal_id: ContractId,
    pub signer_key_id: ContractId,
    pub signed_at: CanonicalTimestamp,
    pub signature_algorithm: ContractId,
    pub signature_hex: HexBytes,
}

impl ApprovalAttestationV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != BINDING_SCHEMA_VERSION
            || self.signature_algorithm.as_str() != "ed25519"
            || self.signature_hex.as_bytes().len() != 64
        {
            return Err(ContractError::Schema("invalid approval attestation".into()));
        }
        Ok(())
    }
}

/// Server-derived activation projection. Unique eligible principals—not keys or
/// rows—satisfy threshold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormativeBindingActivationReceiptV1 {
    pub schema_version: u32,
    pub statement_id: Sha256Digest,
    pub approval_attestation_ids: Vec<Sha256Digest>,
    pub eligible_principal_ids: Vec<ContractId>,
    pub required_threshold: u16,
    pub separation_of_duty_satisfied: bool,
    pub accepted_at: CanonicalTimestamp,
}

impl NormativeBindingActivationReceiptV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != BINDING_SCHEMA_VERSION
            || self.required_threshold == 0
            || usize::from(self.required_threshold) > self.eligible_principal_ids.len()
            || self.approval_attestation_ids.len() > MAX_APPROVALS
            || self.eligible_principal_ids.len() > MAX_APPROVALS
            || !strictly_sorted(&self.approval_attestation_ids)
            || !strictly_sorted(&self.eligible_principal_ids)
        {
            return Err(ContractError::Schema(
                "invalid normative binding activation receipt".into(),
            ));
        }
        Ok(())
    }

    pub fn receipt_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::NormativeBindingReceipt,
            &encode_canonical(self)?,
        ))
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::memory_contracts::{
        common::ContractId,
        digest::{DigestDomain, domain_separated_digest},
    };

    fn digest(label: &str) -> Sha256Digest {
        domain_separated_digest(DigestDomain::RegistryEntry, label.as_bytes())
    }

    fn resource(form: &str, kind: &str, label: &str) -> ResourceUri {
        format!("urn:ostk:{form}:v1:{kind}:sha256:{}", digest(label))
            .parse()
            .unwrap()
    }

    fn reference(id: &str) -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new(id).unwrap(),
            version: 1,
            entry_digest: digest(id),
        }
    }

    fn proposal() -> NormativeBindingProposalV1 {
        NormativeBindingProposalV1 {
            schema_version: 1,
            profile: ProfileReferenceV1 {
                profile_id: ContractId::new("ostk-canonical-json-v1").unwrap(),
                profile_digest: domain_separated_digest(DigestDomain::CanonicalProfile, b"profile"),
                vector_manifest_digest: domain_separated_digest(
                    DigestDomain::TestVectorManifest,
                    b"vectors",
                ),
            },
            scope: AuthenticatedProjectScopeV1::from_trusted_context(
                ContractId::new("tenant.fixture").unwrap(),
                ContractId::new("project.fixture").unwrap(),
            ),
            binding_family_id: ContractId::new("slo.home.errors").unwrap(),
            expected_active_binding_set_digest: None,
            repository_entity_id: resource("entity", "repository", "repo"),
            repository_version_id: resource("version", "repository_version", "commit"),
            blob_id: resource("occurrence", "git_blob", "blob"),
            exact_path_bytes: HexBytes::new(b"docs/SLO.md".to_vec()).unwrap(),
            source_spans: vec![SourceByteSpanV1 {
                start: 10,
                end: 80,
                selected_bytes_digest: digest("span"),
            }],
            parser_artifact_id: resource("occurrence", "artifact", "parser"),
            parser_configuration_digest: digest("parser-config"),
            propositions: vec![NormativePropositionV1 {
                predicate_schema: reference("slo.error_rate"),
                proposition_fingerprint: digest("proposition"),
            }],
            applicability_evaluator: reference("environment.selector"),
            applicability_selector: CanonicalValue::Object(BTreeMap::from([(
                "environment".into(),
                CanonicalValue::String("production".into()),
            )])),
            effective_from: CanonicalTimestamp::parse("2026-08-14T12:00:00.000000000Z").unwrap(),
            effective_until: None,
            registry_package_digest: digest("registry"),
            activation_policy_digest: digest("policy"),
            explicitly_supersedes_statement_id: None,
            proposer_principal_id: ContractId::new("principal.agent").unwrap(),
            source_author_principal_id: ContractId::new("principal.author").unwrap(),
        }
    }

    #[test]
    fn statement_identity_changes_with_exact_source_span() {
        let first = proposal();
        let first_id = first.statement_id().unwrap();
        let mut shifted = first;
        shifted.source_spans[0].start += 1;
        assert_ne!(first_id, shifted.statement_id().unwrap());
    }

    #[test]
    fn set_fields_are_rejected_instead_of_silently_sorted() {
        let mut invalid = proposal();
        invalid.propositions = vec![
            NormativePropositionV1 {
                predicate_schema: reference("z"),
                proposition_fingerprint: digest("z"),
            },
            NormativePropositionV1 {
                predicate_schema: reference("a"),
                proposition_fingerprint: digest("a"),
            },
        ];
        assert!(invalid.validate().is_err());
    }
}
