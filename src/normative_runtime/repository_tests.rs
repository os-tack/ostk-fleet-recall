//! Unit tests for the pure admission boundary.
//!
//! Everything here runs without a database, because every fail-closed check in
//! [`admit_activation`] runs before a transaction opens. Each rejection is an
//! ordinary negative test naming the exact attack it blocks.

use std::collections::BTreeMap;

use super::*;
use crate::memory_contracts::canonical::CanonicalValue;
use crate::memory_contracts::common::{HexBytes, ProfileReferenceV1, RegistryReferenceV1};
use crate::memory_contracts::digest::{DigestDomain, domain_separated_digest};
use crate::memory_contracts::identity::ResourceUri;
use crate::memory_contracts::normative::{NormativePropositionV1, SourceByteSpanV1};
use crate::memory_contracts::normative_v2::{
    NormativeActivationSeparationOfDutyV2, NormativeContestReasonV1,
};
use crate::memory_contracts::registry::{EligibleApprovalV1, RegistryHeadV1};

const ACCEPTED_AT: &str = "2026-08-15T09:00:00.000000000Z";
const EFFECTIVE_FROM: &str = "2026-08-20T00:00:00.000000000Z";

fn label(value: &str) -> Sha256Digest {
    domain_separated_digest(DigestDomain::RegistryEntry, value.as_bytes())
}

fn timestamp(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).unwrap()
}

fn resource(form: &str, kind: &str, value: &str) -> ResourceUri {
    format!("urn:ostk:{form}:v1:{kind}:sha256:{}", label(value))
        .parse()
        .unwrap()
}

fn reference(id: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version: 1,
        entry_digest: label(id),
    }
}

fn profile() -> ProfileReferenceV1 {
    crate::memory_contracts::common::frozen_profile_reference_v1()
}

fn bound_scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.fixture").unwrap(),
        ContractId::new("project.fixture").unwrap(),
    )
}

fn binding() -> NormativeRegistryBindingV1 {
    NormativeRegistryBindingV1 {
        registry_package_digest: label("registry-package"),
        activation_policy_digest: label("activation-policy"),
    }
}

fn registry_head() -> RegistryHeadBindingV1 {
    RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: label("activation"),
            package_digest: binding().registry_package_digest,
            activation_policy_digest: binding().activation_policy_digest,
        },
        effective_from: timestamp("2026-01-01T00:00:00.000000000Z"),
        effective_until: None,
    }
}

fn proposal() -> NormativeBindingProposalV2 {
    NormativeBindingProposalV2 {
        schema_version: 2,
        profile: profile(),
        scope: bound_scope(),
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        expected_active_binding_set_digest: None,
        repository_entity_id: resource("entity", "repository", "repo"),
        repository_version_id: resource("version", "repository_version", "commit"),
        blob_id: resource("occurrence", "git_blob", "blob"),
        exact_path_bytes: HexBytes::new(b"docs/SLO.md".to_vec()).unwrap(),
        source_spans: vec![SourceByteSpanV1 {
            start: 10,
            end: 80,
            selected_bytes_digest: label("span"),
        }],
        parser_artifact_id: resource("occurrence", "artifact", "parser"),
        parser_configuration_digest: label("parser-config"),
        propositions: vec![NormativePropositionV1 {
            predicate_schema: reference("slo.error_rate"),
            proposition_fingerprint: label("proposition"),
        }],
        applicability_evaluator: reference("environment.selector"),
        applicability_selector: CanonicalValue::Object(BTreeMap::from([(
            "environment".into(),
            CanonicalValue::String("production".into()),
        )])),
        effective_from: timestamp(EFFECTIVE_FROM),
        effective_until: None,
        registry_head: registry_head(),
        explicitly_supersedes_statement_id: None,
        proposer_principal_id: ContractId::new("principal.agent").unwrap(),
        source_author_principal_id: ContractId::new("principal.author").unwrap(),
    }
}

fn receipt_for(
    proposal: &NormativeBindingProposalV2,
    approving_principals: &[&str],
) -> NormativeActivationReceiptV2 {
    let statement_id = proposal.statement_id().unwrap();
    let mut approvals: Vec<EligibleApprovalV1> = approving_principals
        .iter()
        .map(|principal| EligibleApprovalV1 {
            attestation_id: label(&format!("attestation.{principal}")),
            principal_id: ContractId::new(*principal).unwrap(),
            signer_key_id: ContractId::new(format!("key.{principal}")).unwrap(),
        })
        .collect();
    approvals.sort();
    let approving: Vec<ContractId> = approvals
        .iter()
        .map(|approval| approval.principal_id.clone())
        .collect();
    let satisfied = approving
        .iter()
        .any(|principal| principal != &proposal.source_author_principal_id);
    NormativeActivationReceiptV2 {
        schema_version: 2,
        statement_id,
        source_author_principal_id: proposal.source_author_principal_id.clone(),
        eligible_approvals: approvals,
        required_threshold: 1,
        separation_of_duty:
            NormativeActivationSeparationOfDutyV2::IndependentApprovalFromSourceAuthor,
        separation_of_duty_satisfied: satisfied,
        accepted_at: timestamp(ACCEPTED_AT),
    }
}

fn candidate() -> NormativeActivationCandidateV1 {
    let proposal = proposal();
    let receipt = receipt_for(&proposal, &["principal.author", "principal.reviewer"]);
    NormativeActivationCandidateV1 {
        proposal,
        receipt,
        retroactive_correction: None,
    }
}

fn admit(
    candidate: &NormativeActivationCandidateV1,
) -> ContractResult<AdmittedNormativeActivationV1> {
    admit_activation(candidate, &binding(), &bound_scope())
}

// --- the lawful path ---

#[test]
fn a_lawful_activation_is_admitted_and_derives_an_activation_event() {
    let candidate = candidate();
    let admitted = admit(&candidate).unwrap();
    assert_eq!(
        admitted.statement_id,
        candidate.proposal.statement_id().unwrap()
    );
    let NormativeLogRecordV1::Lifecycle { event, interval } = &admitted.record else {
        panic!("an activation must derive a lifecycle record");
    };
    assert_eq!(event.kind, NormativeLifecycleKindV1::Activation);
    assert_eq!(event.supersedes_statement_id, None);
    assert_eq!(interval.effective_from, timestamp(EFFECTIVE_FROM));
    assert_eq!(admitted.event_id, event.event_id().unwrap());
}

#[test]
fn a_proposal_naming_a_supersession_target_derives_a_supersession_event() {
    let mut candidate = candidate();
    candidate.proposal.explicitly_supersedes_statement_id = Some(label("prior"));
    candidate.receipt = receipt_for(
        &candidate.proposal,
        &["principal.author", "principal.reviewer"],
    );
    let admitted = admit(&candidate).unwrap();
    let NormativeLogRecordV1::Lifecycle { event, .. } = &admitted.record else {
        panic!("expected a lifecycle record");
    };
    assert_eq!(event.kind, NormativeLifecycleKindV1::Supersession);
    assert_eq!(event.supersedes_statement_id, Some(label("prior")));
}

// --- separation of duty (AUTH-03), fail-closed ---

#[test]
fn the_source_author_alone_cannot_ratify_their_own_binding() {
    let mut candidate = candidate();
    candidate.receipt = receipt_for(&candidate.proposal, &["principal.author"]);
    let error = admit(&candidate).unwrap_err();
    assert!(matches!(error, ContractError::Schema(_)), "got {error:?}");
}

#[test]
fn an_approval_set_of_only_implicated_actors_is_refused_closed() {
    // The author plus the proposer satisfies the contract's rule (the author is
    // not the SOLE ratifier) but every ratifier is implicated in the change, so
    // the runtime refuses it.
    let mut candidate = candidate();
    candidate.receipt = receipt_for(
        &candidate.proposal,
        &["principal.author", "principal.agent"],
    );
    // The contract layer alone would accept this receipt.
    candidate.receipt.validate().unwrap();
    let error = admit(&candidate).unwrap_err();
    assert!(matches!(error, ContractError::Schema(_)), "got {error:?}");
}

#[test]
fn a_receipt_asserting_a_separation_of_duty_verdict_it_cannot_derive_is_refused() {
    let mut candidate = candidate();
    candidate.receipt = receipt_for(&candidate.proposal, &["principal.author"]);
    // Lie about the verdict rather than about the approvals.
    candidate.receipt.separation_of_duty_satisfied = true;
    assert!(admit(&candidate).is_err());
}

#[test]
fn a_receipt_ratifying_a_different_statement_is_refused() {
    let mut candidate = candidate();
    candidate.receipt.statement_id = label("some-other-statement");
    assert!(admit(&candidate).is_err());
}

#[test]
fn a_receipt_naming_a_different_source_author_is_refused() {
    let mut candidate = candidate();
    let mut other = candidate.proposal.clone();
    other.source_author_principal_id = ContractId::new("principal.someone-else").unwrap();
    candidate.receipt = receipt_for(&other, &["principal.reviewer"]);
    candidate.receipt.statement_id = candidate.proposal.statement_id().unwrap();
    assert!(admit(&candidate).is_err());
}

#[test]
fn a_receipt_below_its_declared_threshold_is_refused() {
    let mut candidate = candidate();
    candidate.receipt.required_threshold = 3;
    assert!(admit(&candidate).is_err());
}

// --- scope and registry binding ---

#[test]
fn a_proposal_minted_for_another_project_cannot_activate_here() {
    let mut candidate = candidate();
    candidate.proposal.scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.fixture").unwrap(),
        ContractId::new("project.other").unwrap(),
    );
    candidate.receipt = receipt_for(
        &candidate.proposal,
        &["principal.author", "principal.reviewer"],
    );
    let error = admit(&candidate).unwrap_err();
    assert!(matches!(error, ContractError::Schema(_)), "got {error:?}");
}

#[test]
fn a_proposal_minted_for_another_tenant_cannot_activate_here() {
    let mut candidate = candidate();
    candidate.proposal.scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.other").unwrap(),
        ContractId::new("project.fixture").unwrap(),
    );
    candidate.receipt = receipt_for(
        &candidate.proposal,
        &["principal.author", "principal.reviewer"],
    );
    assert!(admit(&candidate).is_err());
}

#[test]
fn a_proposal_judged_against_a_different_registry_package_is_stale() {
    let mut candidate = candidate();
    candidate.proposal.registry_head.head.package_digest = label("some-other-package");
    candidate.receipt = receipt_for(
        &candidate.proposal,
        &["principal.author", "principal.reviewer"],
    );
    assert_eq!(admit(&candidate), Err(ContractError::StaleRegistryHead));
}

#[test]
fn a_proposal_judged_against_a_different_activation_policy_is_stale() {
    let mut candidate = candidate();
    candidate
        .proposal
        .registry_head
        .head
        .activation_policy_digest = label("rotated-policy");
    candidate.receipt = receipt_for(
        &candidate.proposal,
        &["principal.author", "principal.reviewer"],
    );
    assert_eq!(admit(&candidate), Err(ContractError::StaleRegistryHead));
}

#[test]
fn a_runtime_bound_to_a_zero_registry_digest_cannot_admit_anything() {
    let unbound = NormativeRegistryBindingV1 {
        registry_package_digest: Sha256Digest::ZERO,
        activation_policy_digest: label("activation-policy"),
    };
    assert!(unbound.validate().is_err());
    assert!(admit_activation(&candidate(), &unbound, &bound_scope()).is_err());
}

// --- bitemporal rules and the retroactive-correction path ---

#[test]
fn an_ordinary_activation_effective_before_it_was_accepted_is_refused() {
    let mut candidate = candidate();
    candidate.proposal.effective_from = timestamp("2026-08-01T00:00:00.000000000Z");
    candidate.receipt = receipt_for(
        &candidate.proposal,
        &["principal.author", "principal.reviewer"],
    );
    assert!(admit(&candidate).is_err());
}

fn retroactive(statement_id: Sha256Digest, effective_from: &str) -> RetroactiveCorrectionV1 {
    RetroactiveCorrectionV1 {
        schema_version: 1,
        statement_id,
        superseded_as_known_statement_id: label("prior-as-known"),
        effective_from: timestamp(effective_from),
        accepted_at: timestamp(ACCEPTED_AT),
        authorizing_policy: reference("policy.retroactive"),
        authorizing_policy_required_threshold: 3,
        normal_activation_policy: reference("policy.normal"),
        normal_activation_policy_required_threshold: 1,
    }
}

#[test]
fn a_separately_authorized_retroactive_correction_may_be_effective_before_acceptance() {
    let mut candidate = candidate();
    candidate.proposal.effective_from = timestamp("2026-08-01T00:00:00.000000000Z");
    candidate.receipt = receipt_for(
        &candidate.proposal,
        &["principal.author", "principal.reviewer"],
    );
    let statement_id = candidate.proposal.statement_id().unwrap();
    candidate.retroactive_correction =
        Some(retroactive(statement_id, "2026-08-01T00:00:00.000000000Z"));
    let admitted = admit(&candidate).unwrap();
    assert_eq!(admitted.statement_id, statement_id);
}

#[test]
fn a_retroactive_correction_for_a_different_statement_is_refused() {
    let mut candidate = candidate();
    candidate.proposal.effective_from = timestamp("2026-08-01T00:00:00.000000000Z");
    candidate.receipt = receipt_for(
        &candidate.proposal,
        &["principal.author", "principal.reviewer"],
    );
    candidate.retroactive_correction = Some(retroactive(
        label("a-different-statement"),
        "2026-08-01T00:00:00.000000000Z",
    ));
    assert!(admit(&candidate).is_err());
}

#[test]
fn a_retroactive_correction_naming_a_different_effective_time_is_refused() {
    let mut candidate = candidate();
    candidate.proposal.effective_from = timestamp("2026-08-01T00:00:00.000000000Z");
    candidate.receipt = receipt_for(
        &candidate.proposal,
        &["principal.author", "principal.reviewer"],
    );
    let statement_id = candidate.proposal.statement_id().unwrap();
    candidate.retroactive_correction =
        Some(retroactive(statement_id, "2026-08-02T00:00:00.000000000Z"));
    assert!(admit(&candidate).is_err());
}

#[test]
fn a_retroactive_correction_cannot_supersede_its_own_statement() {
    let mut candidate = candidate();
    candidate.proposal.effective_from = timestamp("2026-08-01T00:00:00.000000000Z");
    candidate.receipt = receipt_for(
        &candidate.proposal,
        &["principal.author", "principal.reviewer"],
    );
    let statement_id = candidate.proposal.statement_id().unwrap();
    let mut correction = retroactive(statement_id, "2026-08-01T00:00:00.000000000Z");
    correction.superseded_as_known_statement_id = statement_id;
    candidate.retroactive_correction = Some(correction);
    assert!(admit(&candidate).is_err());
}

#[test]
fn a_retroactive_correction_under_the_ordinary_threshold_is_refused() {
    let mut candidate = candidate();
    candidate.proposal.effective_from = timestamp("2026-08-01T00:00:00.000000000Z");
    candidate.receipt = receipt_for(
        &candidate.proposal,
        &["principal.author", "principal.reviewer"],
    );
    let statement_id = candidate.proposal.statement_id().unwrap();
    let mut correction = retroactive(statement_id, "2026-08-01T00:00:00.000000000Z");
    correction.authorizing_policy_required_threshold = 1;
    candidate.retroactive_correction = Some(correction);
    assert!(admit(&candidate).is_err());
}

// --- overlap against the durable live set ---

fn projection_with(live: &[(Sha256Digest, &str, Option<&str>)]) -> NormativeFamilyProjectionV1 {
    let mut projection = NormativeFamilyProjectionV1::empty(proposal().binding_family_id);
    projection.live = live
        .iter()
        .map(|(statement_id, from, until)| NormativeStatementIntervalV1 {
            statement_id: *statement_id,
            effective_from: timestamp(from),
            effective_until: until.map(timestamp),
        })
        .collect();
    projection
        .live
        .sort_by_key(|interval| interval.statement_id);
    projection
}

#[test]
fn an_overlapping_activation_without_explicit_supersession_is_refused() {
    let projection = projection_with(&[(label("prior"), "2026-08-01T00:00:00.000000000Z", None)]);
    assert!(require_non_conflicting_against_live(&proposal(), &projection).is_err());
}

#[test]
fn an_overlapping_activation_that_names_its_supersession_target_is_allowed() {
    let projection = projection_with(&[(label("prior"), "2026-08-01T00:00:00.000000000Z", None)]);
    let mut proposal = proposal();
    proposal.explicitly_supersedes_statement_id = Some(label("prior"));
    require_non_conflicting_against_live(&proposal, &projection).unwrap();
}

#[test]
fn a_supersession_that_still_overlaps_a_third_live_statement_is_refused() {
    let projection = projection_with(&[
        (label("prior"), "2026-08-01T00:00:00.000000000Z", None),
        (label("other"), "2026-08-05T00:00:00.000000000Z", None),
    ]);
    let mut proposal = proposal();
    proposal.explicitly_supersedes_statement_id = Some(label("prior"));
    assert!(require_non_conflicting_against_live(&proposal, &projection).is_err());
}

#[test]
fn a_non_overlapping_activation_needs_no_supersession() {
    let projection = projection_with(&[(
        label("prior"),
        "2026-08-01T00:00:00.000000000Z",
        Some("2026-08-10T00:00:00.000000000Z"),
    )]);
    require_non_conflicting_against_live(&proposal(), &projection).unwrap();
}

// --- lifecycle and contest admission ---

fn lifecycle_request(
    kind: NormativeLifecycleKindV1,
    statement_id: Sha256Digest,
) -> NormativeLifecycleRequestV1 {
    NormativeLifecycleRequestV1 {
        binding_family_id: proposal().binding_family_id,
        kind,
        statement_id,
        registry_head: registry_head(),
        effective_at: timestamp("2026-08-25T00:00:00.000000000Z"),
        expected_active_binding_set_digest: None,
        waiver_reference_digest: None,
    }
}

#[test]
fn retiring_a_live_statement_derives_a_retirement_event_with_the_stored_interval() {
    let projection = projection_with(&[(label("live"), "2026-08-01T00:00:00.000000000Z", None)]);
    let request = lifecycle_request(NormativeLifecycleKindV1::Retirement, label("live"));
    let (event_id, record) = admit_lifecycle(&request, &binding(), &projection).unwrap();
    let NormativeLogRecordV1::Lifecycle { event, interval } = &record else {
        panic!("expected a lifecycle record");
    };
    assert_eq!(event.kind, NormativeLifecycleKindV1::Retirement);
    assert_eq!(event_id, event.event_id().unwrap());
    // The interval came from the durable projection, not from the request.
    assert_eq!(
        interval.effective_from,
        timestamp("2026-08-01T00:00:00.000000000Z")
    );
}

#[test]
fn retiring_a_statement_that_is_not_live_is_refused() {
    let projection = projection_with(&[]);
    let request = lifecycle_request(NormativeLifecycleKindV1::Retirement, label("absent"));
    assert!(admit_lifecycle(&request, &binding(), &projection).is_err());
}

#[test]
fn an_activation_cannot_be_smuggled_through_the_retirement_path() {
    let projection = projection_with(&[(label("live"), "2026-08-01T00:00:00.000000000Z", None)]);
    for kind in [
        NormativeLifecycleKindV1::Activation,
        NormativeLifecycleKindV1::Supersession,
    ] {
        let request = lifecycle_request(kind, label("live"));
        assert!(admit_lifecycle(&request, &binding(), &projection).is_err());
    }
}

#[test]
fn a_retirement_judged_against_a_different_registry_head_is_stale() {
    let projection = projection_with(&[(label("live"), "2026-08-01T00:00:00.000000000Z", None)]);
    let mut request = lifecycle_request(NormativeLifecycleKindV1::Retirement, label("live"));
    request.registry_head.head.package_digest = label("some-other-package");
    assert_eq!(
        admit_lifecycle(&request, &binding(), &projection),
        Err(ContractError::StaleRegistryHead)
    );
}

fn contest_over(statements: &[Sha256Digest]) -> ContestedBindingV1 {
    let mut ids = statements.to_vec();
    ids.sort_unstable();
    ContestedBindingV1 {
        schema_version: 1,
        binding_family_id: proposal().binding_family_id,
        contested_statement_ids: ids,
        reason: NormativeContestReasonV1::LateOrCorrectiveEvidence,
        detected_at: timestamp("2026-08-25T00:00:00.000000000Z"),
        waiver_reference_digest: None,
    }
}

#[test]
fn a_contest_over_two_live_statements_is_admitted() {
    let projection = projection_with(&[
        (
            label("a"),
            "2026-08-01T00:00:00.000000000Z",
            Some("2026-08-10T00:00:00.000000000Z"),
        ),
        (label("b"), "2026-08-10T00:00:00.000000000Z", None),
    ]);
    let contest = contest_over(&[label("a"), label("b")]);
    let (contested_id, _) = admit_contest(&contest, &projection).unwrap();
    assert_eq!(contested_id, contest.contested_id().unwrap());
}

#[test]
fn a_contest_naming_fewer_than_two_live_statements_is_refused() {
    let projection = projection_with(&[(label("a"), "2026-08-01T00:00:00.000000000Z", None)]);
    let contest = contest_over(&[label("a"), label("not-live")]);
    assert!(admit_contest(&contest, &projection).is_err());
}

#[test]
fn a_contest_for_another_binding_family_is_refused() {
    let projection = projection_with(&[
        (
            label("a"),
            "2026-08-01T00:00:00.000000000Z",
            Some("2026-08-10T00:00:00.000000000Z"),
        ),
        (label("b"), "2026-08-10T00:00:00.000000000Z", None),
    ]);
    let mut contest = contest_over(&[label("a"), label("b")]);
    contest.binding_family_id = ContractId::new("slo.other.errors").unwrap();
    assert!(admit_contest(&contest, &projection).is_err());
}

// --- binding-set digest ---

#[test]
fn an_empty_live_set_has_no_binding_set_digest() {
    assert_eq!(
        active_binding_set_digest(&proposal().binding_family_id, &[]),
        None
    );
}

#[test]
fn the_binding_set_digest_is_a_function_of_the_set_not_its_order() {
    let family = proposal().binding_family_id;
    let forward = active_binding_set_digest(&family, &[label("a"), label("b")]);
    let reversed = active_binding_set_digest(&family, &[label("b"), label("a")]);
    assert_eq!(forward, reversed);
    assert!(forward.is_some());
}

#[test]
fn the_binding_set_digest_separates_families() {
    let one = active_binding_set_digest(&ContractId::new("slo.one").unwrap(), &[label("a")]);
    let two = active_binding_set_digest(&ContractId::new("slo.two").unwrap(), &[label("a")]);
    assert_ne!(one, two);
}

#[test]
fn the_binding_set_digest_changes_when_the_live_set_changes() {
    let family = proposal().binding_family_id;
    let one = active_binding_set_digest(&family, &[label("a")]);
    let two = active_binding_set_digest(&family, &[label("a"), label("b")]);
    assert_ne!(one, two);
}

#[test]
fn a_length_extension_between_family_and_statement_cannot_collide() {
    // Length framing is what stops "slo.a" + [b] from hashing like "slo." + [ab].
    let one = active_binding_set_digest(&ContractId::new("slo.ab").unwrap(), &[label("x")]);
    let two = active_binding_set_digest(&ContractId::new("slo.a").unwrap(), &[label("x")]);
    assert_ne!(one, two);
}

// --- exact witnessed head ---

#[test]
fn the_exact_witnessed_head_is_accepted() {
    require_witnessed_head(&proposal(), &registry_head()).unwrap();
}

#[test]
fn a_head_differing_only_in_activation_id_is_stale() {
    // An A -> B -> A rollback restores the package and policy digests, so the
    // digest comparison admit_activation makes still passes; only the exact
    // head comparison sees that this is a different activation.
    let mut witnessed = registry_head();
    witnessed.head.activation_id = label("a later activation of the same package");
    admit(&candidate()).unwrap();
    assert_eq!(
        require_witnessed_head(&proposal(), &witnessed),
        Err(ContractError::StaleRegistryHead)
    );
}

#[test]
fn a_head_differing_only_in_effective_from_is_stale() {
    let mut witnessed = registry_head();
    witnessed.effective_from = timestamp("2026-02-01T00:00:00.000000000Z");
    admit(&candidate()).unwrap();
    assert_eq!(
        require_witnessed_head(&proposal(), &witnessed),
        Err(ContractError::StaleRegistryHead)
    );
}
