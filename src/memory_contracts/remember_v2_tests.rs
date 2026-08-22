use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::memory_contracts::{
    canonical::{CanonicalValue, decode_strict, encode_canonical, require_canonical},
    common::frozen_profile_reference_v1,
    digest::{DigestDomain, domain_separated_digest},
    identity::IdentityForm,
    registry::RegistryHeadV1,
};

const INGRESS_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/remember-ingress-candidate-v2.jsonl"
);
const CLAIM_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/remember/semantic-claim-v2.jsonl");
const STATEMENT_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/remember-accepted-statement-v2.jsonl"
);
const PREDICATE_ENTRY_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/remember-predicate-schema-v2-entry.jsonl"
);
const ADMISSION_ENTRY_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/remember-admission-rule-v2-entry.jsonl"
);
const PREDICATE_POSITIVE_CASES_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/remember/predicate-positive-cases-v2.jsonl");
const PREDICATE_NEGATIVE_CASES_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/remember/predicate-negative-cases-v2.jsonl");
const ADMISSION_POSITIVE_CASES_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/remember/admission-positive-cases-v2.jsonl");
const ADMISSION_NEGATIVE_CASES_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/remember/admission-negative-cases-v2.jsonl");
const NEGATIVE_FLOAT_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/remember/negative-floating-value.jsonl");
const NEGATIVE_JSON_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/negative-arbitrary-json-value.jsonl"
);
const NEGATIVE_AUTHORITY_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/negative-ingress-authority-fields.jsonl"
);
const NEGATIVE_NUMERIC_SUPPORT_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/remember/negative-numeric-support-id.jsonl");
const NEGATIVE_PHYSICAL_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/negative-statement-physical-fields.jsonl"
);
const NEGATIVE_SUBJECT_IDENTITY_FORM_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/negative-subject-identity-form.jsonl"
);
const NEGATIVE_ENVIRONMENT_IDENTITY_FORM_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/negative-environment-identity-form.jsonl"
);
const NEGATIVE_PREDICATE_DIMENSION_IDENTITY_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/negative-predicate-dimension-identity-entry.jsonl"
);
const NEGATIVE_PREDICATE_RESOURCE_VALUE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/negative-predicate-resource-value-entry.jsonl"
);
const NEGATIVE_PREDICATE_PUBLIC_DEFAULT_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/negative-predicate-public-default-entry.jsonl"
);
const NEGATIVE_ADMISSION_OBSERVER_OPEN_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/negative-admission-observer-open-entry.jsonl"
);
const NEGATIVE_ADMISSION_PAYLOAD_AUTHORITY_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/negative-admission-payload-authority-entry.jsonl"
);
const NEGATIVE_ADMISSION_DUPLICATE_BASIS_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/negative-admission-duplicate-basis-entry.jsonl"
);
const NEGATIVE_ADMISSION_BASIS_MODALITY_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/remember/negative-admission-basis-modality-entry.jsonl"
);
const VECTOR_SUITE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/remember/vector-suite.jsonl");

const CLAIM_COORDINATE_ID: &str =
    "c964975c9d734cbf6e8d0c300f97b1b2374d0107565b3be8835bbda9b8b5cded";
const CLAIM_FINGERPRINT: &str = "6911f6090f66d4601651df777ad6e4bd765f595c97e795cd07b72095f9ebe0ee";
const ACCEPTED_EVENT_ID: &str = "884c9becc53a6f2dc444df3728972c196cc52fd10184c600e8fbcb639a22e491";
const VECTOR_SUITE_DIGEST: &str =
    "21bd8d133554af1e144e4e13798b5a521545aed407fe6980db6d0132629aa6a6";
const INGRESS_RAW_SHA256: &str = "98f70e8075f82fdd9243215e63a4d49fc7fd2bcf3ac9defe3edc13d39ae09a1b";
const CLAIM_RAW_SHA256: &str = "46046d108489b9736e8caa757bf2d4d1be24897d0e8917c4b8376579f865966c";
const STATEMENT_RAW_SHA256: &str =
    "203e72429a2a0f0d60af96b62af79415adcdff6a381e32c81568ea93267f38a6";
const VECTOR_SUITE_RAW_SHA256: &str =
    "4b31addb79455c408e413803469f57b75c4769780373469c3ad54ae4b3db05dd";
const NEGATIVE_ARBITRARY_JSON_RAW_SHA256: &str =
    "2d1046da15c7a8b9860a5d1170506ab93b77683ea792550b280ee54ca09f79c8";
const NEGATIVE_FLOAT_RAW_SHA256: &str =
    "77b2d05d1a647dc037fdbe8d98e372df23f65ccdaf8483c0834f4c755cccafbd";
const NEGATIVE_AUTHORITY_RAW_SHA256: &str =
    "65c35b284ba9674eca366b740922ae583b9935c0841f99f5f503618c6a43d8f4";
const NEGATIVE_NUMERIC_SUPPORT_RAW_SHA256: &str =
    "b7a1ba95b54d27a5189eb5a1a8f6e5012bd38d18ce4e1cc5d0790208deb53a41";
const NEGATIVE_PHYSICAL_RAW_SHA256: &str =
    "c5cc7337dde9e022f3981197d38f312d56d62127f3eb96f89f33262a431c9e74";
const NEGATIVE_SUBJECT_IDENTITY_FORM_RAW_SHA256: &str =
    "e0870231e6241de9aba60bef799b652294ea79d4475d2b22e8438b120d8bd595";
const NEGATIVE_ENVIRONMENT_IDENTITY_FORM_RAW_SHA256: &str =
    "cdd41ca80a7a0b061a2330adbba39b10588573a171dc92e22fd7f6d30e963992";
const PREDICATE_ENTRY_RAW_SHA256: &str =
    "a74f9da62be272a6b99f539f691a413560f712daebd5c7cf1716dfe3d1a1ff0f";
const ADMISSION_ENTRY_RAW_SHA256: &str =
    "ca10f7c3591f739fb0535275b4abbf9d0e8206db411dcf2d4b1bb71d3ea25ab4";
const PREDICATE_POSITIVE_CASES_RAW_SHA256: &str =
    "0dc6dac2dc81f4fe2d52ccd713ec632843b546328894e5f6c3d5ffc761306230";
const PREDICATE_NEGATIVE_CASES_RAW_SHA256: &str =
    "53e2cd51d19bb5506a08c3b90d3618a13703a46f2faba3033c27223d72020007";
const ADMISSION_POSITIVE_CASES_RAW_SHA256: &str =
    "9acfbea8471b1d7179e87ec6cb97deadbce2ce522bf1cf7ff0189b2fdfebe9cc";
const ADMISSION_NEGATIVE_CASES_RAW_SHA256: &str =
    "07473341caf159cc325c5f2a31b0744fd0024162311791c629d1da7f64f10d55";
const NEGATIVE_PREDICATE_DIMENSION_IDENTITY_RAW_SHA256: &str =
    "028bafe8f27804fd0e1774141e34473c04a7e7d32411759bc9e794f951437cb4";
const NEGATIVE_PREDICATE_RESOURCE_VALUE_RAW_SHA256: &str =
    "510785d789c55bf86d18ba9d04e7ac2af3a85a77f3177d6eee76530d78035beb";
const NEGATIVE_PREDICATE_PUBLIC_DEFAULT_RAW_SHA256: &str =
    "e0ca4059e80671d322e26e8d327bd85851c6c1464487c875b96a171af395f4e1";
const NEGATIVE_ADMISSION_OBSERVER_OPEN_RAW_SHA256: &str =
    "7343de2ef67b7330950acdaed5b03dbb3dced6c9dda77d8081d04ee725051991";
const NEGATIVE_ADMISSION_PAYLOAD_AUTHORITY_RAW_SHA256: &str =
    "b0e5fbd804a5570e24c574ecf1e053e755f9a59a5c599eba2335c5f522c96214";
const NEGATIVE_ADMISSION_DUPLICATE_BASIS_RAW_SHA256: &str =
    "dc0abb9aa178145cc45bb6f3ec9d935fa380b71e410b7aac92a47740173486c4";
const NEGATIVE_ADMISSION_BASIS_MODALITY_RAW_SHA256: &str =
    "5ede144d4bba7e0ed08a46ee717655a6dec8c1a3d511f708980aa694d98d4e79";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RememberVectorSuiteV2 {
    schema_version: u32,
    fixture_authority: String,
    claim_coordinate_id: ClaimCoordinateIdV2,
    semantic_claim_fingerprint: SemanticClaimFingerprintV2,
    accepted_event_id: AcceptedEventId,
    predicate_registry_entry_digest: Sha256Digest,
    admission_registry_entry_digest: Sha256Digest,
    predicate_positive_cases_digest: Sha256Digest,
    predicate_negative_cases_digest: Sha256Digest,
    admission_positive_cases_digest: Sha256Digest,
    admission_negative_cases_digest: Sha256Digest,
    consistency_key_family: ContractId,
    consistency_key_digest: Sha256Digest,
    negative_cases: Vec<ContractId>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RememberRegistryCaseManifestV2 {
    schema_version: u32,
    case_set_id: ContractId,
    entry_schema_id: ContractId,
    expected_outcome: ContractId,
    cases: Vec<ContractId>,
}

impl RememberRegistryCaseManifestV2 {
    fn validate(&self) -> ContractResult<()> {
        if self.schema_version != 2
            || !matches!(self.expected_outcome.as_str(), "accept" | "reject")
            || self.cases.is_empty()
            || !strictly_sorted(&self.cases)
        {
            return Err(ContractError::Schema(
                "invalid remember registry case manifest".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }
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

fn labelled_digest(label: &str) -> Sha256Digest {
    domain_separated_digest(DigestDomain::RegistryEntry, label.as_bytes())
}

fn raw_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn reference(id: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version: 2,
        entry_digest: labelled_digest(id),
    }
}

fn canonical_value<T: Serialize>(value: &T) -> CanonicalValue {
    decode_strict(&encode_canonical(value).unwrap()).unwrap()
}

fn resource_identity(kind: &str, recipe: &str) -> ResourceIdentityConstraintV2 {
    ResourceIdentityConstraintV2 {
        resource_kind_schema: reference(kind),
        identity_recipe: reference(recipe),
    }
}

fn predicate_schema() -> RememberPredicateSchemaV2 {
    RememberPredicateSchemaV2 {
        schema_version: 2,
        predicate_id: ContractId::new("mcp.remember.allowed_actions").unwrap(),
        version: 2,
        subject_identity: resource_identity("repository", "identity.github.repository"),
        value_constraint: RememberValueConstraintV2::Boolean {
            unit_id: ContractId::new("unit.none").unwrap(),
        },
        comparator: PredicateComparatorV1::ExactEquality,
        allowed_modalities: vec![
            PropositionModalityV1::Attested,
            PropositionModalityV1::Intended,
        ],
        applicability_evaluator: reference("applicability.default"),
        applicability_dimensions: vec![
            ApplicabilityDimensionRuleV2 {
                dimension_id: ContractId::new("repository_commit").unwrap(),
                resource_identity: resource_identity("commit", "identity.github.commit"),
                required: true,
            },
            ApplicabilityDimensionRuleV2 {
                dimension_id: ContractId::new("runtime_environment").unwrap(),
                resource_identity: resource_identity("environment", "identity.runtime.environment"),
                required: true,
            },
        ],
        absence_semantics: AbsenceSemanticsV1::OpenWorld,
        coverage_proof: None,
        publication_default: PublicationDefaultV1::Denied,
        sensitivity_default: SensitivityDefaultV1::Project,
    }
}

fn case_ids(values: &[&str]) -> Vec<ContractId> {
    values
        .iter()
        .map(|value| ContractId::new(*value).unwrap())
        .collect()
}

fn predicate_positive_cases() -> RememberRegistryCaseManifestV2 {
    RememberRegistryCaseManifestV2 {
        schema_version: 2,
        case_set_id: ContractId::new("remember.predicate.v2.positive").unwrap(),
        entry_schema_id: ContractId::new(PREDICATE_ENTRY_SCHEMA_ID).unwrap(),
        expected_outcome: ContractId::new("accept").unwrap(),
        cases: case_ids(&[
            "closed_value_constraint",
            "exact_resource_identity_closure",
            "publication_sensitivity_defaults",
            "required_applicability_dimensions",
        ]),
    }
}

fn predicate_negative_cases() -> RememberRegistryCaseManifestV2 {
    RememberRegistryCaseManifestV2 {
        schema_version: 2,
        case_set_id: ContractId::new("remember.predicate.v2.negative").unwrap(),
        entry_schema_id: ContractId::new(PREDICATE_ENTRY_SCHEMA_ID).unwrap(),
        expected_outcome: ContractId::new("reject").unwrap(),
        cases: case_ids(&[
            "dimension_identity_recipe_zero",
            "public_default_unknown",
            "resource_value_recipe_zero",
        ]),
    }
}

fn admission_positive_cases() -> RememberRegistryCaseManifestV2 {
    RememberRegistryCaseManifestV2 {
        schema_version: 2,
        case_set_id: ContractId::new("remember.admission.v2.positive").unwrap(),
        entry_schema_id: ContractId::new(ADMISSION_ENTRY_SCHEMA_ID).unwrap(),
        expected_outcome: ContractId::new("accept").unwrap(),
        cases: case_ids(&[
            "actor_attested_or_intended",
            "governance_server_derived",
            "payload_authority_denied",
            "text_limit_bounded",
        ]),
    }
}

fn admission_negative_cases() -> RememberRegistryCaseManifestV2 {
    RememberRegistryCaseManifestV2 {
        schema_version: 2,
        case_set_id: ContractId::new("remember.admission.v2.negative").unwrap(),
        entry_schema_id: ContractId::new(ADMISSION_ENTRY_SCHEMA_ID).unwrap(),
        expected_outcome: ContractId::new("reject").unwrap(),
        cases: case_ids(&[
            "actor_observed_modality",
            "duplicate_actor_basis",
            "observer_coverage_open",
            "payload_selects_admission_rule",
        ]),
    }
}

fn case_manifest_digest(manifest: &RememberRegistryCaseManifestV2) -> Sha256Digest {
    manifest.validate().unwrap();
    domain_separated_digest(
        DigestDomain::TestVectorManifest,
        &encode_canonical(manifest).unwrap(),
    )
}

fn predicate_entry() -> RegistryEntryV1 {
    RegistryEntryV1 {
        schema_version: 1,
        kind: RegistryEntryKind::PredicateSchema,
        entry_id: ContractId::new("mcp.remember.allowed_actions").unwrap(),
        version: 2,
        entry_schema_id: ContractId::new(PREDICATE_ENTRY_SCHEMA_ID).unwrap(),
        entry_schema_version: 2,
        body: canonical_value(&predicate_schema()),
        positive_vector_digest: case_manifest_digest(&predicate_positive_cases()),
        negative_vector_digest: case_manifest_digest(&predicate_negative_cases()),
    }
}

fn predicate_reference() -> RegistryReferenceV1 {
    registry_reference_for_entry(&predicate_entry()).unwrap()
}

fn admission_rule() -> RememberAdmissionRuleV2 {
    RememberAdmissionRuleV2 {
        schema_version: 2,
        rule_id: ContractId::new("remember.actor_assertion").unwrap(),
        version: 2,
        predicate_schema: predicate_reference(),
        applicability_evaluator: reference("applicability.default"),
        allowed_assertion_kinds: vec![
            RememberAssertionKindV2::Decision,
            RememberAssertionKindV2::Fact,
            RememberAssertionKindV2::Constraint,
            RememberAssertionKindV2::Preference,
            RememberAssertionKindV2::Procedure,
        ],
        basis_rules: vec![RememberAdmissionBasisRuleV2::AuthenticatedActor {
            allowed_modalities: vec![
                PropositionModalityV1::Attested,
                PropositionModalityV1::Intended,
            ],
            maximum_support_events: 256,
        }],
        effective_interval_rule: RememberEffectiveIntervalRuleV2 {
            payload_may_select_effective_from: true,
            past_effective_from_allowed: true,
            future_effective_from_allowed: false,
            open_ended_interval_allowed: true,
            bounded_interval_allowed: true,
            microsecond_alignment_required: true,
        },
        classifier_policy: reference("classifier.default"),
        redaction_policy: reference("redaction.default"),
        retention_policy: reference("retention.default"),
        publication_rule: reference("publication.default"),
        maximum_assertion_text_utf8_bytes: 100_000,
        authenticated_scope_required: true,
        resource_rederivation_required: true,
        support_event_reaudit_required: true,
        server_derived_governance_required: true,
        registered_observer_append_enabled: false,
        normative_binding_append_enabled: false,
        payload_may_select_actor: false,
        payload_may_select_scope: false,
        payload_may_select_registry_head: false,
        payload_may_select_admission_rule: false,
        payload_may_select_admission_outcome: false,
    }
}

fn admission_entry() -> RegistryEntryV1 {
    RegistryEntryV1 {
        schema_version: 1,
        kind: RegistryEntryKind::AuthorityRule,
        entry_id: ContractId::new("remember.actor_assertion").unwrap(),
        version: 2,
        entry_schema_id: ContractId::new(ADMISSION_ENTRY_SCHEMA_ID).unwrap(),
        entry_schema_version: 2,
        body: canonical_value(&admission_rule()),
        positive_vector_digest: case_manifest_digest(&admission_positive_cases()),
        negative_vector_digest: case_manifest_digest(&admission_negative_cases()),
    }
}

fn admission_reference() -> RegistryReferenceV1 {
    registry_reference_for_entry(&admission_entry()).unwrap()
}

fn predicate_entry_with(schema: &RememberPredicateSchemaV2) -> RegistryEntryV1 {
    let mut entry = predicate_entry();
    entry.body = canonical_value(schema);
    entry
}

fn admission_entry_with(rule: &RememberAdmissionRuleV2) -> RegistryEntryV1 {
    let mut entry = admission_entry();
    entry.body = canonical_value(rule);
    entry
}

fn negative_predicate_dimension_identity_entry() -> RegistryEntryV1 {
    let mut schema = predicate_schema();
    schema.applicability_dimensions[0]
        .resource_identity
        .identity_recipe
        .entry_digest = Sha256Digest::ZERO;
    predicate_entry_with(&schema)
}

fn negative_predicate_resource_value_entry() -> RegistryEntryV1 {
    let mut schema = predicate_schema();
    let mut resource_identity = resource_identity("repository", "identity.github.repository");
    resource_identity.identity_recipe.entry_digest = Sha256Digest::ZERO;
    schema.value_constraint = RememberValueConstraintV2::ResourceUri { resource_identity };
    predicate_entry_with(&schema)
}

fn registered_observer_basis(coverage_reaudit_required: bool) -> RememberAdmissionBasisRuleV2 {
    RememberAdmissionBasisRuleV2::RegisteredObserver {
        observer_admission: reference("observer.rust_enum"),
        observer_result_event_schema: reference("observer_result.remember.v2"),
        allowed_modalities: vec![PropositionModalityV1::Observed],
        minimum_support_events: 1,
        maximum_support_events: 256,
        same_scope_required: true,
        same_registry_head_required: true,
        exact_observer_reference_required: true,
        exact_claim_output_required: true,
        coverage_reaudit_required,
    }
}

fn negative_admission_observer_open_entry() -> RegistryEntryV1 {
    let mut rule = admission_rule();
    rule.basis_rules = vec![registered_observer_basis(false)];
    admission_entry_with(&rule)
}

fn negative_admission_payload_authority_entry() -> RegistryEntryV1 {
    let mut rule = admission_rule();
    rule.payload_may_select_admission_rule = true;
    admission_entry_with(&rule)
}

fn negative_admission_duplicate_basis_entry() -> RegistryEntryV1 {
    let mut rule = admission_rule();
    rule.basis_rules = vec![
        RememberAdmissionBasisRuleV2::AuthenticatedActor {
            allowed_modalities: vec![PropositionModalityV1::Attested],
            maximum_support_events: 1,
        },
        RememberAdmissionBasisRuleV2::AuthenticatedActor {
            allowed_modalities: vec![
                PropositionModalityV1::Attested,
                PropositionModalityV1::Intended,
            ],
            maximum_support_events: 256,
        },
    ];
    admission_entry_with(&rule)
}

fn negative_admission_basis_modality_entry() -> RegistryEntryV1 {
    let mut rule = admission_rule();
    rule.basis_rules = vec![RememberAdmissionBasisRuleV2::AuthenticatedActor {
        allowed_modalities: vec![PropositionModalityV1::Observed],
        maximum_support_events: 256,
    }];
    admission_entry_with(&rule)
}

fn scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.fixture").unwrap(),
        ContractId::new("project.fixture").unwrap(),
    )
}

fn registry() -> RegistryHeadBindingV1 {
    RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: labelled_digest("activation.remember.v2"),
            package_digest: labelled_digest("package.remember.v2"),
            activation_policy_digest: labelled_digest("activation.policy.v2"),
        },
        effective_from: CanonicalTimestamp::parse("2026-08-15T12:00:00.000000000Z").unwrap(),
        effective_until: None,
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

fn first_stage4_resource_forms_match(candidate: &RememberIngressCandidateV2) -> bool {
    let dimension_matches = |dimension_id: &str, kind: &str, form: IdentityForm| {
        candidate.applicability.iter().any(|dimension| {
            dimension.dimension_id.as_str() == dimension_id
                && dimension.resource.resource_kind().as_str() == kind
                && dimension.resource.identity_form() == form
        })
    };
    candidate.asserted_subject.resource_kind().as_str() == "repository"
        && candidate.asserted_subject.identity_form() == IdentityForm::Entity
        && dimension_matches("repository_commit", "commit", IdentityForm::Version)
        && dimension_matches("runtime_environment", "environment", IdentityForm::Entity)
}

fn applicability() -> Vec<ConcreteApplicabilityDimensionV1> {
    vec![
        ConcreteApplicabilityDimensionV1 {
            dimension_id: ContractId::new("repository_commit").unwrap(),
            resource: resource(IdentityForm::Version, "commit", '3'),
        },
        ConcreteApplicabilityDimensionV1 {
            dimension_id: ContractId::new("runtime_environment").unwrap(),
            resource: resource(IdentityForm::Entity, "environment", '4'),
        },
    ]
}

fn interval() -> ClaimEffectiveIntervalV2 {
    ClaimEffectiveIntervalV2 {
        effective_from: CanonicalTimestamp::parse("2026-08-15T12:30:00.000000000Z").unwrap(),
        effective_until: None,
    }
}

fn support(digit: char) -> AcceptedEventId {
    AcceptedEventId::from_digest(digest(&digit.to_string().repeat(64)))
}

fn candidate() -> RememberIngressCandidateV2 {
    RememberIngressCandidateV2 {
        schema_version: 2,
        asserted_subject: resource(IdentityForm::Entity, "repository", '1'),
        subject_identity_recipe: reference("identity.github.repository"),
        predicate_schema: predicate_reference(),
        applicability_evaluator: reference("applicability.default"),
        admission_rule: admission_reference(),
        assertion_kind: RememberAssertionKindV2::Fact,
        assertion_text_utf8_hex_chunks: CanonicalAssertionTextV2::parse(
            "MCP remember allows deliberate record assertions.\nIt preserves authored narrative.",
        )
        .unwrap(),
        modality: PropositionModalityV1::Attested,
        polarity: ClaimPolarityV2::Affirms,
        value: CanonicalClaimValueV2::Boolean { value: true },
        applicability: applicability(),
        effective_interval: interval(),
        requested_basis: RememberAdmissionBasisV2::AuthenticatedActor,
        support_evidence_event_ids: vec![support('5'), support('6')],
    }
}

fn claim() -> SemanticClaimV2 {
    let candidate = candidate();
    SemanticClaimV2 {
        schema_version: 2,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        registry: registry(),
        subject: candidate.asserted_subject,
        subject_identity_recipe: candidate.subject_identity_recipe,
        predicate_schema: candidate.predicate_schema,
        applicability_evaluator: candidate.applicability_evaluator,
        assertion_kind: candidate.assertion_kind,
        modality: candidate.modality,
        polarity: candidate.polarity,
        value: candidate.value,
        applicability: candidate.applicability,
        effective_interval: candidate.effective_interval,
    }
}

fn statement() -> RememberAcceptedStatementV2 {
    let claim = claim();
    RememberAcceptedStatementV2 {
        schema_version: 2,
        event_kind: ContractId::new(REMEMBER_ACCEPTED_EVENT_KIND).unwrap(),
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        registry: registry(),
        claim_fingerprint: claim.fingerprint().unwrap(),
        claim,
        assertion_text_utf8_hex_chunks: CanonicalAssertionTextV2::parse(
            "MCP remember allows deliberate record assertions.\nIt preserves authored narrative.",
        )
        .unwrap(),
        actor: RememberActorV2 {
            principal_id: ContractId::new("principal.operator").unwrap(),
        },
        admission_rule: admission_reference(),
        admission_basis: RememberAdmissionBasisV2::AuthenticatedActor,
        support_evidence_event_ids: vec![support('5'), support('6')],
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn hard_coded_contract_vectors_match_independent_ids() {
    for (bytes, expected_raw_sha256) in [
        (INGRESS_FIXTURE, INGRESS_RAW_SHA256),
        (CLAIM_FIXTURE, CLAIM_RAW_SHA256),
        (STATEMENT_FIXTURE, STATEMENT_RAW_SHA256),
        (PREDICATE_ENTRY_FIXTURE, PREDICATE_ENTRY_RAW_SHA256),
        (ADMISSION_ENTRY_FIXTURE, ADMISSION_ENTRY_RAW_SHA256),
        (
            PREDICATE_POSITIVE_CASES_FIXTURE,
            PREDICATE_POSITIVE_CASES_RAW_SHA256,
        ),
        (
            PREDICATE_NEGATIVE_CASES_FIXTURE,
            PREDICATE_NEGATIVE_CASES_RAW_SHA256,
        ),
        (
            ADMISSION_POSITIVE_CASES_FIXTURE,
            ADMISSION_POSITIVE_CASES_RAW_SHA256,
        ),
        (
            ADMISSION_NEGATIVE_CASES_FIXTURE,
            ADMISSION_NEGATIVE_CASES_RAW_SHA256,
        ),
        (VECTOR_SUITE_FIXTURE, VECTOR_SUITE_RAW_SHA256),
        (NEGATIVE_JSON_FIXTURE, NEGATIVE_ARBITRARY_JSON_RAW_SHA256),
        (NEGATIVE_FLOAT_FIXTURE, NEGATIVE_FLOAT_RAW_SHA256),
        (NEGATIVE_AUTHORITY_FIXTURE, NEGATIVE_AUTHORITY_RAW_SHA256),
        (
            NEGATIVE_NUMERIC_SUPPORT_FIXTURE,
            NEGATIVE_NUMERIC_SUPPORT_RAW_SHA256,
        ),
        (NEGATIVE_PHYSICAL_FIXTURE, NEGATIVE_PHYSICAL_RAW_SHA256),
        (
            NEGATIVE_SUBJECT_IDENTITY_FORM_FIXTURE,
            NEGATIVE_SUBJECT_IDENTITY_FORM_RAW_SHA256,
        ),
        (
            NEGATIVE_ENVIRONMENT_IDENTITY_FORM_FIXTURE,
            NEGATIVE_ENVIRONMENT_IDENTITY_FORM_RAW_SHA256,
        ),
        (
            NEGATIVE_PREDICATE_DIMENSION_IDENTITY_FIXTURE,
            NEGATIVE_PREDICATE_DIMENSION_IDENTITY_RAW_SHA256,
        ),
        (
            NEGATIVE_PREDICATE_RESOURCE_VALUE_FIXTURE,
            NEGATIVE_PREDICATE_RESOURCE_VALUE_RAW_SHA256,
        ),
        (
            NEGATIVE_PREDICATE_PUBLIC_DEFAULT_FIXTURE,
            NEGATIVE_PREDICATE_PUBLIC_DEFAULT_RAW_SHA256,
        ),
        (
            NEGATIVE_ADMISSION_OBSERVER_OPEN_FIXTURE,
            NEGATIVE_ADMISSION_OBSERVER_OPEN_RAW_SHA256,
        ),
        (
            NEGATIVE_ADMISSION_PAYLOAD_AUTHORITY_FIXTURE,
            NEGATIVE_ADMISSION_PAYLOAD_AUTHORITY_RAW_SHA256,
        ),
        (
            NEGATIVE_ADMISSION_DUPLICATE_BASIS_FIXTURE,
            NEGATIVE_ADMISSION_DUPLICATE_BASIS_RAW_SHA256,
        ),
        (
            NEGATIVE_ADMISSION_BASIS_MODALITY_FIXTURE,
            NEGATIVE_ADMISSION_BASIS_MODALITY_RAW_SHA256,
        ),
    ] {
        assert_eq!(raw_sha256(bytes), expected_raw_sha256);
    }
    for bytes in [
        INGRESS_FIXTURE,
        CLAIM_FIXTURE,
        STATEMENT_FIXTURE,
        PREDICATE_ENTRY_FIXTURE,
        ADMISSION_ENTRY_FIXTURE,
        PREDICATE_POSITIVE_CASES_FIXTURE,
        PREDICATE_NEGATIVE_CASES_FIXTURE,
        ADMISSION_POSITIVE_CASES_FIXTURE,
        ADMISSION_NEGATIVE_CASES_FIXTURE,
        VECTOR_SUITE_FIXTURE,
    ] {
        require_canonical(record(bytes)).unwrap();
    }
    assert_eq!(
        encode_canonical(&candidate()).unwrap(),
        record(INGRESS_FIXTURE)
    );
    assert_eq!(encode_canonical(&claim()).unwrap(), record(CLAIM_FIXTURE));
    assert_eq!(
        encode_canonical(&statement()).unwrap(),
        record(STATEMENT_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&predicate_entry()).unwrap(),
        record(PREDICATE_ENTRY_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&admission_entry()).unwrap(),
        record(ADMISSION_ENTRY_FIXTURE)
    );
    for (bytes, expected) in [
        (PREDICATE_POSITIVE_CASES_FIXTURE, predicate_positive_cases()),
        (PREDICATE_NEGATIVE_CASES_FIXTURE, predicate_negative_cases()),
        (ADMISSION_POSITIVE_CASES_FIXTURE, admission_positive_cases()),
        (ADMISSION_NEGATIVE_CASES_FIXTURE, admission_negative_cases()),
    ] {
        let decoded: RememberRegistryCaseManifestV2 = decode_strict(record(bytes)).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded, expected);
    }

    let coordinate_id = claim().coordinate().coordinate_id().unwrap();
    let fingerprint = claim().fingerprint().unwrap();
    let event_id = statement().accepted_event_id().unwrap();
    assert_eq!(coordinate_id.digest(), digest(CLAIM_COORDINATE_ID));
    assert_eq!(fingerprint.digest(), digest(CLAIM_FINGERPRINT));
    assert_eq!(event_id.digest(), digest(ACCEPTED_EVENT_ID));

    let suite: RememberVectorSuiteV2 = decode_strict(record(VECTOR_SUITE_FIXTURE)).unwrap();
    assert_eq!(suite.schema_version, 2);
    assert!(suite.fixture_authority.starts_with("none;"));
    assert_eq!(suite.claim_coordinate_id, coordinate_id);
    assert_eq!(suite.semantic_claim_fingerprint, fingerprint);
    assert_eq!(suite.accepted_event_id, event_id);
    assert_eq!(
        suite.predicate_registry_entry_digest,
        predicate_entry().digest().unwrap()
    );
    assert_eq!(
        suite.admission_registry_entry_digest,
        admission_entry().digest().unwrap()
    );
    assert_eq!(
        suite.predicate_positive_cases_digest,
        predicate_entry().positive_vector_digest
    );
    assert_eq!(
        suite.predicate_negative_cases_digest,
        predicate_entry().negative_vector_digest
    );
    assert_eq!(
        suite.admission_positive_cases_digest,
        admission_entry().positive_vector_digest
    );
    assert_eq!(
        suite.admission_negative_cases_digest,
        admission_entry().negative_vector_digest
    );
    assert_eq!(
        suite.consistency_key_family.as_str(),
        CLAIM_CONSISTENCY_FAMILY
    );
    assert_eq!(suite.consistency_key_digest, coordinate_id.digest());
    assert!(strictly_sorted(&suite.negative_cases));
    assert_eq!(
        domain_separated_digest(
            DigestDomain::TestVectorManifest,
            record(VECTOR_SUITE_FIXTURE)
        ),
        digest(VECTOR_SUITE_DIGEST)
    );
}

#[test]
fn full_registry_entry_preimages_close_structural_policy_without_authority() {
    let decoded_predicate: RegistryEntryV1 =
        decode_strict(record(PREDICATE_ENTRY_FIXTURE)).unwrap();
    let decoded_admission: RegistryEntryV1 =
        decode_strict(record(ADMISSION_ENTRY_FIXTURE)).unwrap();
    assert_eq!(decoded_predicate, predicate_entry());
    assert_eq!(decoded_admission, admission_entry());

    let resolved = StructurallyResolvedRememberContractsV2::from_registry_entries(
        &decoded_predicate,
        &decoded_admission,
    )
    .unwrap();
    assert_eq!(resolved.predicate_reference(), &predicate_reference());
    assert_eq!(resolved.admission_reference(), &admission_reference());
    resolved.validate_candidate_shape(&candidate()).unwrap();

    let mut changed_predicate = predicate_entry();
    let mut changed_body = predicate_schema();
    changed_body.sensitivity_default = SensitivityDefaultV1::Private;
    changed_predicate.body = canonical_value(&changed_body);
    assert!(
        StructurallyResolvedRememberContractsV2::from_registry_entries(
            &changed_predicate,
            &admission_entry(),
        )
        .is_err()
    );

    let mut wrong_kind = admission_entry();
    wrong_kind.kind = RegistryEntryKind::PredicateSchema;
    assert!(
        StructurallyResolvedRememberContractsV2::from_registry_entries(
            &predicate_entry(),
            &wrong_kind,
        )
        .is_err()
    );
}

#[test]
fn typed_policy_negatives_are_canonical_raw_pinned_and_fail_closed() {
    for bytes in [
        NEGATIVE_PREDICATE_DIMENSION_IDENTITY_FIXTURE,
        NEGATIVE_PREDICATE_RESOURCE_VALUE_FIXTURE,
        NEGATIVE_PREDICATE_PUBLIC_DEFAULT_FIXTURE,
        NEGATIVE_ADMISSION_OBSERVER_OPEN_FIXTURE,
        NEGATIVE_ADMISSION_PAYLOAD_AUTHORITY_FIXTURE,
        NEGATIVE_ADMISSION_DUPLICATE_BASIS_FIXTURE,
        NEGATIVE_ADMISSION_BASIS_MODALITY_FIXTURE,
    ] {
        require_canonical(record(bytes)).unwrap();
    }

    for bytes in [
        NEGATIVE_PREDICATE_DIMENSION_IDENTITY_FIXTURE,
        NEGATIVE_PREDICATE_RESOURCE_VALUE_FIXTURE,
        NEGATIVE_PREDICATE_PUBLIC_DEFAULT_FIXTURE,
    ] {
        let entry: RegistryEntryV1 = decode_strict(record(bytes)).unwrap();
        assert!(
            StructurallyResolvedRememberContractsV2::from_registry_entries(
                &entry,
                &admission_entry(),
            )
            .is_err()
        );
    }
    for bytes in [
        NEGATIVE_ADMISSION_OBSERVER_OPEN_FIXTURE,
        NEGATIVE_ADMISSION_PAYLOAD_AUTHORITY_FIXTURE,
        NEGATIVE_ADMISSION_DUPLICATE_BASIS_FIXTURE,
        NEGATIVE_ADMISSION_BASIS_MODALITY_FIXTURE,
    ] {
        let entry: RegistryEntryV1 = decode_strict(record(bytes)).unwrap();
        assert!(
            StructurallyResolvedRememberContractsV2::from_registry_entries(
                &predicate_entry(),
                &entry,
            )
            .is_err()
        );
    }
}

#[test]
fn basis_routes_and_resource_identity_checks_remain_fail_closed() {
    let mut observer_predicate = predicate_schema();
    observer_predicate.allowed_modalities = vec![PropositionModalityV1::Observed];
    let observer_predicate_entry = predicate_entry_with(&observer_predicate);
    let observer_predicate_reference =
        registry_reference_for_entry(&observer_predicate_entry).unwrap();
    let mut observer_rule = admission_rule();
    observer_rule.basis_rules = vec![registered_observer_basis(true)];
    observer_rule.predicate_schema = observer_predicate_reference.clone();
    let observer_entry = admission_entry_with(&observer_rule);
    let observer_resolved = StructurallyResolvedRememberContractsV2::from_registry_entries(
        &observer_predicate_entry,
        &observer_entry,
    )
    .unwrap();
    let mut observer = candidate();
    observer.modality = PropositionModalityV1::Observed;
    observer.predicate_schema = observer_predicate_reference;
    observer.requested_basis = RememberAdmissionBasisV2::RegisteredObserver {
        observer_admission: reference("observer.rust_enum"),
    };
    observer.admission_rule = registry_reference_for_entry(&observer_entry).unwrap();
    observer.validate_shape().unwrap();
    assert!(
        observer_resolved
            .validate_candidate_shape(&observer)
            .is_err()
    );

    let mut duplicate = admission_rule();
    duplicate.basis_rules = vec![
        RememberAdmissionBasisRuleV2::AuthenticatedActor {
            allowed_modalities: vec![PropositionModalityV1::Attested],
            maximum_support_events: 1,
        },
        RememberAdmissionBasisRuleV2::AuthenticatedActor {
            allowed_modalities: vec![PropositionModalityV1::Intended],
            maximum_support_events: 2,
        },
    ];
    assert!(duplicate.validate_shape().is_err());

    let mut observer_enabled = admission_rule();
    observer_enabled.registered_observer_append_enabled = true;
    assert!(observer_enabled.validate_shape().is_err());
    let mut normative_enabled = admission_rule();
    normative_enabled.normative_binding_append_enabled = true;
    assert!(normative_enabled.validate_shape().is_err());

    let constraint = resource_identity("repository", "identity.github.repository");
    assert!(constraint.accepts_uri_shape(&resource(IdentityForm::Entity, "repository", 'a')));
    assert!(!constraint.accepts_uri_shape(&resource(IdentityForm::Version, "commit", 'a')));

    let mut strict_rule = admission_rule();
    strict_rule.maximum_assertion_text_utf8_bytes = 1;
    let strict_entry = admission_entry_with(&strict_rule);
    let strict_resolved = StructurallyResolvedRememberContractsV2::from_registry_entries(
        &predicate_entry(),
        &strict_entry,
    )
    .unwrap();
    let mut too_long = candidate();
    too_long.admission_rule = registry_reference_for_entry(&strict_entry).unwrap();
    assert!(strict_resolved.validate_candidate_shape(&too_long).is_err());
}

#[test]
fn first_stage4_resource_forms_are_explicit_and_mismatches_fail_closed() {
    let positive = candidate();
    assert!(first_stage4_resource_forms_match(&positive));
    assert_eq!(
        positive.asserted_subject.identity_form(),
        IdentityForm::Entity
    );
    assert_eq!(
        positive.applicability[0].resource.identity_form(),
        IdentityForm::Version
    );
    assert_eq!(
        positive.applicability[1].resource.identity_form(),
        IdentityForm::Entity
    );
    assert!(matches!(
        &positive.value,
        CanonicalClaimValueV2::Boolean { value: true }
    ));
    assert!(matches!(
        predicate_schema().value_constraint,
        RememberValueConstraintV2::Boolean { unit_id }
            if unit_id.as_str() == "unit.none"
    ));

    for bytes in [
        NEGATIVE_SUBJECT_IDENTITY_FORM_FIXTURE,
        NEGATIVE_ENVIRONMENT_IDENTITY_FORM_FIXTURE,
    ] {
        require_canonical(record(bytes)).unwrap();
        let negative: RememberIngressCandidateV2 = decode_strict(record(bytes)).unwrap();
        // Public shape remains authority-free; exact active recipe
        // rederivation is what rejects the incompatible URI form.
        negative.validate_shape().unwrap();
        assert!(!first_stage4_resource_forms_match(&negative));
    }
}

#[test]
fn ingress_cannot_select_server_authority_or_physical_state() {
    candidate().validate_shape().unwrap();
    let encoded = encode_canonical(&candidate()).unwrap();
    let text = std::str::from_utf8(&encoded).unwrap();
    for forbidden in [
        "\"profile\"",
        "\"scope\"",
        "\"registry\"",
        "\"actor\"",
        "\"event_kind\"",
        "\"claim_fingerprint\"",
        "\"accepted_event_id\"",
        "\"accepted_at\"",
        "\"epoch_id\"",
        "\"shard\"",
        "\"committed_offset\"",
    ] {
        assert!(
            !text.contains(forbidden),
            "forbidden ingress field {forbidden}"
        );
    }

    for bytes in [
        NEGATIVE_AUTHORITY_FIXTURE,
        NEGATIVE_NUMERIC_SUPPORT_FIXTURE,
        NEGATIVE_PHYSICAL_FIXTURE,
    ] {
        require_canonical(record(bytes)).unwrap();
    }
    assert!(
        decode_strict::<RememberIngressCandidateV2>(record(NEGATIVE_AUTHORITY_FIXTURE)).is_err()
    );
    assert!(
        decode_strict::<RememberAcceptedStatementV2>(record(NEGATIVE_PHYSICAL_FIXTURE)).is_err()
    );
    assert!(
        decode_strict::<RememberIngressCandidateV2>(record(NEGATIVE_NUMERIC_SUPPORT_FIXTURE))
            .is_err()
    );
}

#[test]
fn values_are_closed_typed_and_never_floating_or_arbitrary_json() {
    require_canonical(record(NEGATIVE_JSON_FIXTURE)).unwrap();
    assert!(decode_strict::<RememberIngressCandidateV2>(record(NEGATIVE_FLOAT_FIXTURE)).is_err());
    assert!(decode_strict::<RememberIngressCandidateV2>(record(NEGATIVE_JSON_FIXTURE)).is_err());

    assert!(CanonicalClaimTextV2::parse(" canonical ").is_err());
    assert!(CanonicalClaimTextV2::parse("line\nbreak").is_err());
    assert!(CanonicalClaimTextV2::parse("e\u{301}").is_err());
    let mut duplicate = candidate();
    duplicate.value = CanonicalClaimValueV2::StringSet {
        values: vec![
            CanonicalClaimTextV2::parse("alpha").unwrap(),
            CanonicalClaimTextV2::parse("alpha").unwrap(),
        ],
    };
    assert!(duplicate.validate_shape().is_err());
    let mut reversed = candidate();
    reversed.value = CanonicalClaimValueV2::StringSet {
        values: vec![
            CanonicalClaimTextV2::parse("zeta").unwrap(),
            CanonicalClaimTextV2::parse("alpha").unwrap(),
        ],
    };
    assert!(reversed.validate_shape().is_err());
}

#[test]
fn authored_text_preserves_lf_and_tab_as_exact_utf8_bytes() {
    for exact in [
        "first line\n\tindented second line",
        "  leading authored spaces",
        "authored trailing spaces  ",
        "authored trailing LF\n",
        "authored trailing TAB\t",
    ] {
        let text = CanonicalAssertionTextV2::parse(exact).unwrap();
        assert_eq!(text.as_str(), exact);
        assert_eq!(text.as_bytes(), exact.as_bytes());
        let encoded = encode_canonical(&text).unwrap();
        assert_eq!(
            encoded,
            format!("[\"{}\"]", hex::encode(exact.as_bytes())).as_bytes()
        );
        let decoded: CanonicalAssertionTextV2 = decode_strict(&encoded).unwrap();
        assert_eq!(decoded, text);
    }

    let exact = "first line\n\tindented second line";

    let noncanonical_split = format!(
        "[\"{}\",\"{}\"]",
        hex::encode(&exact.as_bytes()[..2]),
        hex::encode(&exact.as_bytes()[2..])
    );
    assert!(decode_strict::<CanonicalAssertionTextV2>(noncanonical_split.as_bytes()).is_err());

    for invalid in [
        "   \n\t",
        "carriage\rreturn",
        "nul\0byte",
        "form\u{000c}feed",
        "private\u{e000}use",
        "noncharacter\u{fdd0}",
        "byte\u{feff}order",
    ] {
        assert!(CanonicalAssertionTextV2::parse(invalid).is_err());
    }
    let largest = CanonicalAssertionTextV2::parse("a".repeat(MAX_ASSERTION_TEXT_BYTES))
        .expect("maximum assertion text must remain encodable");
    encode_canonical(&largest).unwrap();
    let mut maximum_candidate = candidate();
    maximum_candidate.assertion_text_utf8_hex_chunks = largest;
    maximum_candidate.validate_shape().unwrap();
    assert!(CanonicalAssertionTextV2::parse("a".repeat(MAX_ASSERTION_TEXT_BYTES + 1)).is_err());
}

#[test]
fn claim_meaning_and_attestation_identity_are_separate() {
    let base_claim = claim();
    let fingerprint = base_claim.fingerprint().unwrap();
    let key = base_claim.consistency_partition_key().unwrap();
    assert_eq!(key.family.as_str(), CLAIM_CONSISTENCY_FAMILY);

    let first = statement();
    let mut second = first.clone();
    second.actor.principal_id = ContractId::new("principal.second_operator").unwrap();
    second.support_evidence_event_ids = vec![support('7')];
    assert_eq!(first.claim_fingerprint, second.claim_fingerprint);
    assert_eq!(
        first.consistency_partition_key().unwrap(),
        second.consistency_partition_key().unwrap()
    );
    assert_ne!(
        first.accepted_event_id().unwrap(),
        second.accepted_event_id().unwrap()
    );

    let mut reworded = first.clone();
    reworded.assertion_text_utf8_hex_chunks =
        CanonicalAssertionTextV2::parse("Same proposition, independently authored wording.")
            .unwrap();
    assert_eq!(first.claim_fingerprint, reworded.claim_fingerprint);
    assert_ne!(
        first.accepted_event_id().unwrap(),
        reworded.accepted_event_id().unwrap()
    );

    let mut changed_value = base_claim.clone();
    changed_value.value = CanonicalClaimValueV2::Boolean { value: false };
    assert_ne!(fingerprint, changed_value.fingerprint().unwrap());
    assert_eq!(key, changed_value.consistency_partition_key().unwrap());

    let mut changed_head = base_claim.clone();
    changed_head.registry.head.activation_id = labelled_digest("activation.aba");
    assert_ne!(fingerprint, changed_head.fingerprint().unwrap());
    assert_eq!(key, changed_head.consistency_partition_key().unwrap());

    let mut changed_interval = base_claim;
    changed_interval.effective_interval.effective_from =
        CanonicalTimestamp::parse("2026-08-15T13:00:00.000000000Z").unwrap();
    assert_ne!(fingerprint, changed_interval.fingerprint().unwrap());
    assert_eq!(key, changed_interval.consistency_partition_key().unwrap());
}

#[test]
fn semantic_coordinate_changes_only_for_comparison_dimensions() {
    let base = claim();
    let key = base.consistency_partition_key().unwrap();

    let mut subject = base.clone();
    subject.subject = resource(IdentityForm::Entity, "repository", '2');
    assert_ne!(key, subject.consistency_partition_key().unwrap());

    let mut predicate = base.clone();
    predicate.predicate_schema = reference("repository.default_branch");
    assert_ne!(key, predicate.consistency_partition_key().unwrap());

    let mut context = base;
    context.applicability[1].resource = resource(IdentityForm::Entity, "environment", '9');
    assert_ne!(key, context.consistency_partition_key().unwrap());
}

#[test]
fn basis_modality_and_sets_fail_closed() {
    let mut invalid_basis = candidate();
    invalid_basis.requested_basis = RememberAdmissionBasisV2::RegisteredObserver {
        observer_admission: reference("observer.rust_enum"),
    };
    assert!(invalid_basis.validate_shape().is_err());

    let mut actor_without_citations = candidate();
    actor_without_citations.support_evidence_event_ids.clear();
    actor_without_citations.validate_shape().unwrap();

    let mut accepted_actor_without_citations = statement();
    accepted_actor_without_citations
        .support_evidence_event_ids
        .clear();
    accepted_actor_without_citations.validate_shape().unwrap();

    let mut observer_without_support = actor_without_citations;
    observer_without_support.modality = PropositionModalityV1::Observed;
    observer_without_support.requested_basis = RememberAdmissionBasisV2::RegisteredObserver {
        observer_admission: reference("observer.rust_enum"),
    };
    assert!(observer_without_support.validate_shape().is_err());

    let mut accepted_observer = statement();
    accepted_observer.claim.modality = PropositionModalityV1::Observed;
    accepted_observer.claim_fingerprint = accepted_observer.claim.fingerprint().unwrap();
    accepted_observer.admission_basis = RememberAdmissionBasisV2::RegisteredObserver {
        observer_admission: reference("observer.rust_enum"),
    };
    accepted_observer.validate_shape().unwrap();
    accepted_observer.support_evidence_event_ids.clear();
    assert!(accepted_observer.validate_shape().is_err());

    let mut accepted_normative = statement();
    accepted_normative.claim.modality = PropositionModalityV1::Normative;
    accepted_normative.claim_fingerprint = accepted_normative.claim.fingerprint().unwrap();
    accepted_normative.admission_basis = RememberAdmissionBasisV2::ActivatedNormativeBinding {
        binding_schema: reference("normative.binding.default"),
        binding_statement_id: labelled_digest("normative.statement"),
    };
    accepted_normative.support_evidence_event_ids.clear();
    accepted_normative.validate_shape().unwrap();

    let mut duplicate_support = candidate();
    duplicate_support.support_evidence_event_ids = vec![support('5'), support('5')];
    assert!(duplicate_support.validate_shape().is_err());

    let mut duplicate_dimension = candidate();
    duplicate_dimension.applicability[1].dimension_id =
        duplicate_dimension.applicability[0].dimension_id.clone();
    assert!(duplicate_dimension.validate_shape().is_err());

    let mut zero_support = candidate();
    zero_support.support_evidence_event_ids =
        vec![AcceptedEventId::from_digest(Sha256Digest::ZERO)];
    assert!(zero_support.validate_shape().is_err());

    let mut zero_reference = candidate();
    zero_reference.predicate_schema.entry_digest = Sha256Digest::ZERO;
    assert!(zero_reference.validate_shape().is_err());
}

#[test]
fn fixed_profile_head_event_kind_and_fingerprint_bindings_fail_closed() {
    let mut wrong_kind = statement();
    wrong_kind.event_kind = ContractId::new("memory.claim.proposed").unwrap();
    assert!(wrong_kind.validate_shape().is_err());

    let mut wrong_profile = statement();
    wrong_profile.profile.profile_digest = labelled_digest("attacker.profile");
    wrong_profile.claim.profile = wrong_profile.profile.clone();
    assert!(wrong_profile.validate_shape().is_err());

    let mut mismatched_head = statement();
    mismatched_head.registry.head.activation_id = labelled_digest("other.activation");
    assert!(mismatched_head.validate_shape().is_err());

    let mut wrong_fingerprint = statement();
    wrong_fingerprint.claim_fingerprint =
        SemanticClaimFingerprintV2::from_digest(Sha256Digest::ZERO);
    assert!(wrong_fingerprint.validate_shape().is_err());

    let mut sub_microsecond = statement();
    sub_microsecond.claim.effective_interval.effective_from =
        CanonicalTimestamp::parse("2026-08-15T12:30:00.000000001Z").unwrap();
    assert!(sub_microsecond.validate_shape().is_err());
}

#[test]
fn accepted_statement_excludes_all_receipt_and_append_coordinates() {
    let accepted = statement();
    accepted.validate_shape().unwrap();
    let encoded = encode_canonical(&accepted).unwrap();
    let text = std::str::from_utf8(&encoded).unwrap();
    for forbidden in [
        "\"id\"",
        "\"claim_id\"",
        "\"support_id\"",
        "\"idempotency_key\"",
        "\"accepted_at\"",
        "\"received_at\"",
        "\"created_at\"",
        "\"consistency_partition_key\"",
        "\"epoch_id\"",
        "\"shard\"",
        "\"committed_offset\"",
        "\"previous_chain_digest\"",
        "\"append_chain_digest\"",
    ] {
        assert!(
            !text.contains(forbidden),
            "forbidden event field {forbidden}"
        );
    }
}

#[test]
fn structural_bytes_cannot_enter_the_append_typestate() {
    let decoded: RememberAcceptedStatementV2 = decode_strict(record(STATEMENT_FIXTURE)).unwrap();
    decoded.validate_shape().unwrap();
    let admitted = AdmittedRememberStatementV2::from_test_witness(decoded).unwrap();
    assert_eq!(
        admitted.statement().accepted_event_id().unwrap(),
        statement().accepted_event_id().unwrap()
    );
}

#[test]
#[ignore = "maintainer-only canonical fixture regeneration"]
#[allow(clippy::too_many_lines)]
fn regenerate_remember_v2_contract_artifacts() {
    use std::{fs, path::Path};

    fn mutate_json<T: Serialize>(
        value: &T,
        mutate: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
    ) -> Vec<u8> {
        let mut value = serde_json::to_value(value).unwrap();
        let object = value.as_object_mut().unwrap();
        mutate(object);
        serde_json::to_vec(&value).unwrap()
    }

    fn framed(bytes: &[u8]) -> Vec<u8> {
        let mut framed = bytes.to_vec();
        framed.push(b'\n');
        framed
    }

    fn write(output: &Path, name: &str, bytes: &[u8]) {
        fs::write(output.join(name), framed(bytes)).unwrap();
    }

    let output = std::env::var_os("REMEMBER_VECTOR_OUTPUT")
        .map(std::path::PathBuf::from)
        .expect("REMEMBER_VECTOR_OUTPUT is required");
    fs::create_dir_all(&output).unwrap();

    let candidate = candidate();
    let claim = claim();
    let statement = statement();
    let predicate_entry = predicate_entry();
    let admission_entry = admission_entry();
    write(
        &output,
        "remember-ingress-candidate-v2.jsonl",
        &encode_canonical(&candidate).unwrap(),
    );
    write(
        &output,
        "semantic-claim-v2.jsonl",
        &encode_canonical(&claim).unwrap(),
    );
    write(
        &output,
        "remember-accepted-statement-v2.jsonl",
        &encode_canonical(&statement).unwrap(),
    );
    write(
        &output,
        "remember-predicate-schema-v2-entry.jsonl",
        &encode_canonical(&predicate_entry).unwrap(),
    );
    write(
        &output,
        "remember-admission-rule-v2-entry.jsonl",
        &encode_canonical(&admission_entry).unwrap(),
    );
    for (name, manifest) in [
        (
            "predicate-positive-cases-v2.jsonl",
            predicate_positive_cases(),
        ),
        (
            "predicate-negative-cases-v2.jsonl",
            predicate_negative_cases(),
        ),
        (
            "admission-positive-cases-v2.jsonl",
            admission_positive_cases(),
        ),
        (
            "admission-negative-cases-v2.jsonl",
            admission_negative_cases(),
        ),
    ] {
        write(&output, name, &encode_canonical(&manifest).unwrap());
    }

    let floating = mutate_json(&candidate, |object| {
        object.insert(
            "value".into(),
            serde_json::from_str(r#"{"kind":"canonical_decimal","value":0.5}"#).unwrap(),
        );
    });
    let arbitrary_json = mutate_json(&candidate, |object| {
        object.insert(
            "value".into(),
            serde_json::from_str(r#"{"kind":"json","value":{"nested":true}}"#).unwrap(),
        );
    });
    let ingress_authority = mutate_json(&candidate, |object| {
        object.insert("actor".into(), serde_json::Value::from(42));
    });
    let numeric_support = mutate_json(&candidate, |object| {
        object.insert(
            "support_evidence_event_ids".into(),
            serde_json::Value::Array(vec![serde_json::Value::from(7)]),
        );
    });
    let physical_statement = mutate_json(&statement, |object| {
        object.insert(
            "accepted_at".into(),
            serde_json::Value::String("2026-08-15T12:31:00.000000000Z".into()),
        );
        object.insert("claim_id".into(), serde_json::Value::from(99));
        object.insert("shard".into(), serde_json::Value::from(3));
    });
    let mut wrong_subject_form = candidate.clone();
    wrong_subject_form.asserted_subject = resource(IdentityForm::Version, "repository", '1');
    let mut wrong_environment_form = candidate;
    wrong_environment_form.applicability[1].resource =
        resource(IdentityForm::Version, "environment", '4');
    for bytes in [
        arbitrary_json.as_slice(),
        ingress_authority.as_slice(),
        numeric_support.as_slice(),
        physical_statement.as_slice(),
    ] {
        require_canonical(bytes).unwrap();
    }
    write(&output, "negative-floating-value.jsonl", &floating);
    write(
        &output,
        "negative-arbitrary-json-value.jsonl",
        &arbitrary_json,
    );
    write(
        &output,
        "negative-ingress-authority-fields.jsonl",
        &ingress_authority,
    );
    write(
        &output,
        "negative-numeric-support-id.jsonl",
        &numeric_support,
    );
    write(
        &output,
        "negative-statement-physical-fields.jsonl",
        &physical_statement,
    );
    write(
        &output,
        "negative-subject-identity-form.jsonl",
        &encode_canonical(&wrong_subject_form).unwrap(),
    );
    write(
        &output,
        "negative-environment-identity-form.jsonl",
        &encode_canonical(&wrong_environment_form).unwrap(),
    );

    write(
        &output,
        "negative-predicate-dimension-identity-entry.jsonl",
        &encode_canonical(&negative_predicate_dimension_identity_entry()).unwrap(),
    );
    write(
        &output,
        "negative-predicate-resource-value-entry.jsonl",
        &encode_canonical(&negative_predicate_resource_value_entry()).unwrap(),
    );
    let predicate_public = mutate_json(&predicate_entry, |object| {
        object
            .get_mut("body")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .insert(
                "publication_default".into(),
                serde_json::Value::String("public".into()),
            );
    });
    require_canonical(&predicate_public).unwrap();
    write(
        &output,
        "negative-predicate-public-default-entry.jsonl",
        &predicate_public,
    );
    write(
        &output,
        "negative-admission-observer-open-entry.jsonl",
        &encode_canonical(&negative_admission_observer_open_entry()).unwrap(),
    );
    write(
        &output,
        "negative-admission-payload-authority-entry.jsonl",
        &encode_canonical(&negative_admission_payload_authority_entry()).unwrap(),
    );
    write(
        &output,
        "negative-admission-duplicate-basis-entry.jsonl",
        &encode_canonical(&negative_admission_duplicate_basis_entry()).unwrap(),
    );
    write(
        &output,
        "negative-admission-basis-modality-entry.jsonl",
        &encode_canonical(&negative_admission_basis_modality_entry()).unwrap(),
    );

    let coordinate_id = claim.coordinate().coordinate_id().unwrap();
    let claim_fingerprint = claim.fingerprint().unwrap();
    let accepted_event_id = statement.accepted_event_id().unwrap();
    let suite = RememberVectorSuiteV2 {
        schema_version: 2,
        fixture_authority:
            "none; structural fixtures are assertions, not active-package or admission witnesses"
                .into(),
        claim_coordinate_id: coordinate_id,
        semantic_claim_fingerprint: claim_fingerprint,
        accepted_event_id,
        predicate_registry_entry_digest: predicate_entry.digest().unwrap(),
        admission_registry_entry_digest: admission_entry.digest().unwrap(),
        predicate_positive_cases_digest: predicate_entry.positive_vector_digest,
        predicate_negative_cases_digest: predicate_entry.negative_vector_digest,
        admission_positive_cases_digest: admission_entry.positive_vector_digest,
        admission_negative_cases_digest: admission_entry.negative_vector_digest,
        consistency_key_family: ContractId::new(CLAIM_CONSISTENCY_FAMILY).unwrap(),
        consistency_key_digest: coordinate_id.digest(),
        negative_cases: [
            "admission_basis_modality",
            "admission_duplicate_basis_key",
            "admission_observer_open",
            "admission_payload_authority",
            "arbitrary_json_value",
            "floating_value",
            "ingress_authority_fields",
            "numeric_support_id",
            "predicate_dimension_identity",
            "predicate_public_default",
            "predicate_resource_value",
            "runtime_environment_identity_form",
            "statement_physical_fields",
            "subject_identity_form",
        ]
        .into_iter()
        .map(|value| ContractId::new(value).unwrap())
        .collect(),
    };
    let suite_bytes = encode_canonical(&suite).unwrap();
    write(&output, "vector-suite.jsonl", &suite_bytes);

    println!("claim_coordinate_id={coordinate_id}");
    println!("semantic_claim_fingerprint={claim_fingerprint}");
    println!("accepted_event_id={accepted_event_id}");
    println!(
        "vector_suite_digest={}",
        domain_separated_digest(DigestDomain::TestVectorManifest, &suite_bytes)
    );
}
