//! Shared fixtures for the spec conformance unit tests.

use crate::connectors::git::GitObjectId;
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, HexBytes, RegistryReferenceV1,
    frozen_profile_reference_v1,
};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, domain_separated_digest};
use crate::memory_contracts::discrepancy::{
    DiscrepancyEpisodeFingerprintV1, DiscrepancyFamilyFingerprintV1, DiscrepancySeverityV1,
};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::identity::ResourceUri;
use crate::memory_contracts::normative::{NormativePropositionV1, SourceByteSpanV1};
use crate::memory_contracts::normative_v2::NormativeBindingProposalV2;
use crate::memory_contracts::observer::{EvaluatedConditionV1, VerificationOutcomeV1};
use crate::memory_contracts::registry::RegistryHeadV1;

use super::expectation::{ExpectedMembershipV1, RememberActionExpectationV1, repository_selector};
use super::record::{SpecCheckRecordV1, SpecVerdictV1};

pub fn label(value: &str) -> Sha256Digest {
    domain_separated_digest(DigestDomain::RegistryEntry, value.as_bytes())
}

pub fn timestamp(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).expect("fixture timestamp must be canonical")
}

pub fn resource(form: &str, kind: &str, value: &str) -> ResourceUri {
    format!("urn:ostk:{form}:v1:{kind}:sha256:{}", label(value))
        .parse()
        .expect("fixture resource URI must be valid")
}

pub fn reference(id: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version: 1,
        entry_digest: label(id),
    }
}

pub fn scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.acme").unwrap(),
        ContractId::new("project.recall").unwrap(),
    )
}

/// "`Action` in `src/service.rs` must not declare `Forget`."
pub fn expectation() -> RememberActionExpectationV1 {
    RememberActionExpectationV1 {
        schema_version: 1,
        predicate: reference("mcp.remember.allowed_actions"),
        source_path: "src/service.rs".into(),
        enum_name: "Action".into(),
        member: "Forget".into(),
        expected: ExpectedMembershipV1::Absent,
        severity: DiscrepancySeverityV1::High,
    }
}

/// A proposal that carries exactly `expectation`.
pub fn proposal_for(expectation: &RememberActionExpectationV1) -> NormativeBindingProposalV2 {
    let fingerprint = expectation.fingerprint().unwrap();
    let mut proposal = NormativeBindingProposalV2 {
        schema_version: 2,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        binding_family_id: ContractId::new("spec.remember.no_forget").unwrap(),
        expected_active_binding_set_digest: None,
        repository_entity_id: resource("entity", "repository", "repo"),
        repository_version_id: resource("version", "git_blob", "spec"),
        blob_id: resource("occurrence", "git_blob", "spec"),
        exact_path_bytes: HexBytes::new(b"docs/spec.md".to_vec()).unwrap(),
        source_spans: vec![SourceByteSpanV1 {
            start: 0,
            end: 40,
            selected_bytes_digest: label("span"),
        }],
        parser_artifact_id: resource("occurrence", "artifact", "parser"),
        parser_configuration_digest: fingerprint,
        propositions: vec![NormativePropositionV1 {
            predicate_schema: expectation.predicate.clone(),
            proposition_fingerprint: fingerprint,
        }],
        applicability_evaluator: reference("applicability.repository"),
        applicability_selector: crate::memory_contracts::canonical::CanonicalValue::Null,
        effective_from: timestamp("2026-09-01T00:00:00.000000000Z"),
        effective_until: None,
        registry_head: RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id: label("activation"),
                package_digest: label("package"),
                activation_policy_digest: label("policy"),
            },
            effective_from: timestamp("2026-01-01T00:00:00.000000000Z"),
            effective_until: None,
        },
        explicitly_supersedes_statement_id: None,
        proposer_principal_id: ContractId::new("principal.dave").unwrap(),
        source_author_principal_id: ContractId::new("principal.carol").unwrap(),
    };
    proposal.applicability_selector = repository_selector(&proposal);
    proposal
}

pub fn commit() -> GitObjectId {
    GitObjectId::parse_hex(&"c0".repeat(20)).unwrap()
}

/// A nonconforming check of `statement_id`: the observer verified `Forget`
/// present where the expectation forbids it.
pub fn nonconforming_check(statement_id: Sha256Digest) -> SpecCheckRecordV1 {
    SpecCheckRecordV1 {
        schema_version: 1,
        statement_id,
        binding_family_id: ContractId::new("spec.remember.no_forget").unwrap(),
        family_fingerprint: DiscrepancyFamilyFingerprintV1::from_digest(label("family")),
        commit_oid: commit(),
        observed_revision_uri: resource("version", "git_blob", "service"),
        observer_event_id: AcceptedEventId::from_digest(label("observer-event")),
        blob_event_id: AcceptedEventId::from_digest(label("blob-event")),
        member: "Forget".into(),
        expected: ExpectedMembershipV1::Absent,
        observed_condition: EvaluatedConditionV1::Present,
        verification_outcome: VerificationOutcomeV1::VerifiedPositive,
        verdict: SpecVerdictV1::Nonconforming,
        reasons: Vec::new(),
        episode: Some(DiscrepancyEpisodeFingerprintV1::from_digest(label(
            "episode",
        ))),
        compared_at: timestamp("2026-09-01T00:00:00.000000000Z"),
    }
}
