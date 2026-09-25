//! Unit tests for normative approval verification.
//!
//! The policy is the compiled Stage-4 package's `activation.default` v2 entry,
//! whose eligible signers are `principal.alice` and `principal.bob` under the
//! public fixture seeds `0x01` and `0x02` (D4: nominal keys; the database role
//! is the real gate). Every refusal below is an ordinary negative test naming
//! the attack it blocks.

use std::collections::BTreeMap;

use ring::signature::{Ed25519KeyPair, KeyPair as _};

use super::*;
use crate::memory_contracts::canonical::CanonicalValue;
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, HexBytes, ProfileReferenceV1, RegistryReferenceV1,
    frozen_profile_reference_v1,
};
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::identity::ResourceUri;
use crate::memory_contracts::normative::{NormativePropositionV1, SourceByteSpanV1};
use crate::memory_contracts::registry::RegistryHeadV1;
use crate::normative_runtime::{
    NormativeActivationCandidateV1, NormativeRegistryBindingV1, admit_activation,
};
use crate::registry_witness::compiled_stage4_package;

const ALICE: &str = "principal.alice";
const BOB: &str = "principal.bob";
const ALICE_SEED: u8 = 0x01;
const BOB_SEED: u8 = 0x02;
const AUTHOR: &str = "principal.author";
const PROPOSER: &str = "principal.proposer";

const SIGNED_AT: &str = "2026-08-15T08:00:00.000000000Z";
const ACCEPTED_AT: &str = "2026-08-15T09:00:00.000000000Z";
const EFFECTIVE_FROM: &str = "2026-08-20T00:00:00.000000000Z";

/// The generic registry-successor approval domain. A signature made under it
/// over the same statement id must never verify as a normative approval.
const GENERIC_SUCCESSOR_PREFIX: &[u8] =
    b"ostk-registry-successor-activation-approval-signature-v2\0";

fn label(value: &str) -> Sha256Digest {
    domain_separated_digest(DigestDomain::RegistryEntry, value.as_bytes())
}

fn timestamp(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).unwrap()
}

fn id(value: &str) -> ContractId {
    ContractId::new(value).unwrap()
}

fn resource(form: &str, kind: &str, value: &str) -> ResourceUri {
    format!("urn:ostk:{form}:v1:{kind}:sha256:{}", label(value))
        .parse()
        .unwrap()
}

fn reference(entry: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: id(entry),
        version: 1,
        entry_digest: label(entry),
    }
}

fn profile() -> ProfileReferenceV1 {
    frozen_profile_reference_v1()
}

fn scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(id("tenant.fixture"), id("project.fixture"))
}

fn policy() -> StructurallyResolvedActivationPolicyV2 {
    compiled_stage4_package()
        .expect("compiled Stage-4 package")
        .activation_policy()
        .clone()
}

fn binding() -> NormativeRegistryBindingV1 {
    NormativeRegistryBindingV1 {
        registry_package_digest: compiled_stage4_package()
            .expect("compiled Stage-4 package")
            .package_digest(),
        activation_policy_digest: policy().registry_reference().entry_digest,
    }
}

fn registry_head() -> RegistryHeadBindingV1 {
    let binding = binding();
    RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: label("activation"),
            package_digest: binding.registry_package_digest,
            activation_policy_digest: binding.activation_policy_digest,
        },
        effective_from: timestamp("2026-08-01T00:00:00.000000000Z"),
        effective_until: None,
    }
}

fn proposal_by(author: &str, proposer: &str) -> NormativeBindingProposalV2 {
    NormativeBindingProposalV2 {
        schema_version: 2,
        profile: profile(),
        scope: scope(),
        binding_family_id: id("spec.remember.actions"),
        expected_active_binding_set_digest: None,
        repository_entity_id: resource("entity", "repository", "repo"),
        repository_version_id: resource("version", "repository_version", "commit"),
        blob_id: resource("occurrence", "git_blob", "blob"),
        exact_path_bytes: HexBytes::new(b"docs/SPEC.md".to_vec()).unwrap(),
        source_spans: vec![SourceByteSpanV1 {
            start: 10,
            end: 80,
            selected_bytes_digest: label("span"),
        }],
        parser_artifact_id: resource("occurrence", "artifact", "parser"),
        parser_configuration_digest: label("expectation"),
        propositions: vec![NormativePropositionV1 {
            predicate_schema: reference("mcp.remember.allowed_actions"),
            proposition_fingerprint: label("expectation"),
        }],
        applicability_evaluator: reference("applicability.default"),
        applicability_selector: CanonicalValue::Object(BTreeMap::from([(
            "repository".into(),
            CanonicalValue::String(resource("entity", "repository", "repo").to_string()),
        )])),
        effective_from: timestamp(EFFECTIVE_FROM),
        effective_until: None,
        registry_head: registry_head(),
        explicitly_supersedes_statement_id: None,
        proposer_principal_id: id(proposer),
        source_author_principal_id: id(author),
    }
}

fn proposal() -> NormativeBindingProposalV2 {
    proposal_by(AUTHOR, PROPOSER)
}

fn key_pair(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn key_id(seed: u8) -> ContractId {
    id(&format!(
        "ed25519.{}",
        hex::encode(key_pair(seed).public_key().as_ref())
    ))
}

fn signature(message: &[u8], seed: u8) -> HexBytes {
    HexBytes::new(key_pair(seed).sign(message).as_ref().to_vec()).unwrap()
}

/// An honest approval of `proposal` by `principal`, signed with `seed`.
fn approval(
    proposal: &NormativeBindingProposalV2,
    principal: &str,
    seed: u8,
) -> ApprovalAttestationV1 {
    let statement_id = proposal.statement_id().unwrap();
    ApprovalAttestationV1 {
        schema_version: 1,
        statement_id,
        principal_id: id(principal),
        signer_key_id: key_id(seed),
        signed_at: timestamp(SIGNED_AT),
        signature_algorithm: id("ed25519"),
        signature_hex: signature(&normative_approval_message(statement_id), seed),
    }
}

fn both_approvals(proposal: &NormativeBindingProposalV2) -> Vec<ApprovalAttestationV1> {
    vec![
        approval(proposal, ALICE, ALICE_SEED),
        approval(proposal, BOB, BOB_SEED),
    ]
}

fn verify(
    proposal: &NormativeBindingProposalV2,
    approvals: &[ApprovalAttestationV1],
) -> ContractResult<NormativeActivationReceiptV2> {
    verify_normative_approvals(proposal, approvals, &policy(), &timestamp(ACCEPTED_AT))
}

fn expect_signature_refusal(
    proposal: &NormativeBindingProposalV2,
    approvals: &[ApprovalAttestationV1],
    attack: &str,
) {
    match verify(proposal, approvals) {
        Err(ContractError::SignatureVerification) => {}
        Err(other) => panic!("{attack}: expected a signature refusal, got {other}"),
        Ok(_) => panic!("{attack}: minted a receipt"),
    }
}

fn expect_schema_refusal(
    proposal: &NormativeBindingProposalV2,
    approvals: &[ApprovalAttestationV1],
    attack: &str,
) {
    match verify(proposal, approvals) {
        Err(ContractError::Schema(_)) => {}
        Err(other) => panic!("{attack}: expected a schema refusal, got {other}"),
        Ok(_) => panic!("{attack}: minted a receipt"),
    }
}

// --- the lawful path ---

#[test]
fn a_valid_two_of_two_approval_mints_a_receipt_the_runtime_admits() {
    let proposal = proposal();
    let receipt = verify(&proposal, &both_approvals(&proposal)).unwrap();

    receipt.validate().unwrap();
    assert_eq!(receipt.statement_id, proposal.statement_id().unwrap());
    assert_eq!(receipt.accepted_at, timestamp(ACCEPTED_AT));
    assert_eq!(
        receipt.required_threshold,
        policy().policy().approval_threshold
    );
    let principals: Vec<&str> = receipt
        .eligible_approvals
        .iter()
        .map(|approval| approval.principal_id.as_str())
        .collect();
    let mut sorted = principals.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, [ALICE, BOB]);
    for eligible in &receipt.eligible_approvals {
        let seed = if eligible.principal_id.as_str() == ALICE {
            ALICE_SEED
        } else {
            BOB_SEED
        };
        assert_eq!(eligible.signer_key_id, key_id(seed));
    }

    let candidate = NormativeActivationCandidateV1 {
        proposal,
        receipt,
        retroactive_correction: None,
    };
    admit_activation(&candidate, &binding(), &scope()).unwrap();
}

#[test]
fn the_offline_signer_produces_approvals_the_live_policy_verifies() {
    let proposal = proposal();
    let signed: Vec<ApprovalAttestationV1> = [(ALICE, ALICE_SEED), (BOB, BOB_SEED)]
        .into_iter()
        .map(|(principal, seed)| {
            sign_normative_approval(&proposal, id(principal), &[seed; 32], timestamp(SIGNED_AT))
                .unwrap()
        })
        .collect();
    // Ed25519 is deterministic, so the offline signer and a hand-built
    // attestation are the same bytes.
    assert_eq!(signed, both_approvals(&proposal));
    verify(&proposal, &signed).unwrap();

    // A seed the policy does not list for the principal signs, but never
    // verifies.
    let wrong_key = vec![
        sign_normative_approval(&proposal, id(ALICE), &[0x03; 32], timestamp(SIGNED_AT)).unwrap(),
        signed[1].clone(),
    ];
    expect_signature_refusal(&proposal, &wrong_key, "a key the policy does not list");
}

#[test]
fn the_receipt_does_not_depend_on_the_order_approvals_arrive_in() {
    let proposal = proposal();
    let mut reversed = both_approvals(&proposal);
    reversed.reverse();
    assert_eq!(
        verify(&proposal, &both_approvals(&proposal)).unwrap(),
        verify(&proposal, &reversed).unwrap()
    );
}

#[test]
fn distinct_signatures_are_distinct_attestations() {
    let proposal = proposal();
    let [alice, bob] = <[ApprovalAttestationV1; 2]>::try_from(both_approvals(&proposal)).unwrap();
    assert_ne!(
        approval_attestation_id(&alice).unwrap(),
        approval_attestation_id(&bob).unwrap()
    );
}

// --- signatures, keys, and domains ---

#[test]
fn a_tampered_signature_is_refused() {
    let proposal = proposal();
    let mut approvals = both_approvals(&proposal);
    let mut bytes = approvals[0].signature_hex.as_bytes().to_vec();
    bytes[0] ^= 0x01;
    approvals[0].signature_hex = HexBytes::new(bytes).unwrap();
    expect_signature_refusal(&proposal, &approvals, "tampered signature");
}

#[test]
fn a_signature_over_another_statement_is_refused() {
    let proposal = proposal();
    let mut other = proposal.clone();
    other.effective_from = timestamp("2026-08-21T00:00:00.000000000Z");
    let other_statement_id = other.statement_id().unwrap();
    assert_ne!(other_statement_id, proposal.statement_id().unwrap());

    // The attestation names this statement but the signature covers another.
    let mut approvals = both_approvals(&proposal);
    approvals[0].signature_hex =
        signature(&normative_approval_message(other_statement_id), ALICE_SEED);
    expect_signature_refusal(&proposal, &approvals, "signature over another statement");

    // An honest approval of another statement does not approve this one.
    let approvals = vec![
        approval(&other, ALICE, ALICE_SEED),
        approval(&proposal, BOB, BOB_SEED),
    ];
    expect_signature_refusal(&proposal, &approvals, "approval of another statement");
}

#[test]
fn a_registry_successor_signature_over_the_same_statement_id_is_refused() {
    let proposal = proposal();
    let statement_id = proposal.statement_id().unwrap();
    let mut generic_message = GENERIC_SUCCESSOR_PREFIX.to_vec();
    generic_message.extend_from_slice(statement_id.as_bytes());
    assert_ne!(generic_message, normative_approval_message(statement_id));

    let mut approvals = both_approvals(&proposal);
    approvals[0].signature_hex = signature(&generic_message, ALICE_SEED);
    expect_signature_refusal(&proposal, &approvals, "cross-domain replay");
}

#[test]
fn a_principal_the_policy_does_not_list_is_refused() {
    let proposal = proposal();
    let approvals = vec![
        approval(&proposal, ALICE, ALICE_SEED),
        approval(&proposal, "principal.mallory", 0x03),
    ];
    expect_signature_refusal(&proposal, &approvals, "unknown principal");
}

#[test]
fn a_signer_key_id_other_than_the_policy_key_is_refused() {
    let proposal = proposal();
    let mut approvals = both_approvals(&proposal);
    approvals[0].signer_key_id = key_id(BOB_SEED);
    expect_signature_refusal(&proposal, &approvals, "key-id mismatch");
}

#[test]
fn an_eligible_principal_signing_with_another_key_is_refused() {
    let proposal = proposal();
    let statement_id = proposal.statement_id().unwrap();
    let mut approvals = both_approvals(&proposal);
    approvals[0].signature_hex = signature(&normative_approval_message(statement_id), 0x03);
    expect_signature_refusal(&proposal, &approvals, "wrong key for the principal");
}

// --- separation of duty and threshold ---

#[test]
fn the_source_author_among_the_approvers_is_refused() {
    let proposal = proposal_by(ALICE, PROPOSER);
    expect_schema_refusal(&proposal, &both_approvals(&proposal), "author approves");
}

#[test]
fn the_proposer_among_the_approvers_is_refused() {
    let proposal = proposal_by(AUTHOR, BOB);
    expect_schema_refusal(&proposal, &both_approvals(&proposal), "proposer approves");
}

#[test]
fn an_author_who_is_also_the_proposer_is_refused() {
    let proposal = proposal_by(AUTHOR, AUTHOR);
    expect_schema_refusal(&proposal, &both_approvals(&proposal), "author == proposer");
}

#[test]
fn a_single_approval_does_not_meet_the_threshold() {
    let proposal = proposal();
    let approvals = vec![approval(&proposal, ALICE, ALICE_SEED)];
    assert_eq!(
        verify(&proposal, &approvals).unwrap_err(),
        ContractError::ApprovalThresholdNotMet
    );
    assert!(verify(&proposal, &[]).is_err(), "no approval at all");
}

#[test]
fn one_principal_approving_twice_is_refused() {
    let proposal = proposal();
    let mut second = approval(&proposal, ALICE, ALICE_SEED);
    second.signed_at = timestamp("2026-08-15T08:30:00.000000000Z");
    let approvals = vec![approval(&proposal, ALICE, ALICE_SEED), second];
    expect_schema_refusal(&proposal, &approvals, "duplicate principal");
}

#[test]
fn an_approval_signed_after_acceptance_is_refused() {
    let proposal = proposal();
    let mut approvals = both_approvals(&proposal);
    approvals[1].signed_at = timestamp("2026-08-15T09:00:00.000001000Z");
    expect_schema_refusal(&proposal, &approvals, "signed after accepted_at");

    // Signing at the accepted instant itself is not late.
    approvals[1].signed_at = timestamp(ACCEPTED_AT);
    verify(&proposal, &approvals).unwrap();
}

// --- the policy the proposal is judged against ---

#[test]
fn a_proposal_naming_another_activation_policy_is_stale() {
    let mut proposal = proposal();
    proposal.registry_head.head.activation_policy_digest = label("another-policy");
    assert_eq!(
        verify(&proposal, &both_approvals(&proposal)).unwrap_err(),
        ContractError::StaleRegistryHead
    );
}
