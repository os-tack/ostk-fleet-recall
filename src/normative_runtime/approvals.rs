//! Cryptographic verification of normative activation approvals (Stage 6).
//!
//! [`crate::memory_contracts::normative_v2::NormativeActivationReceiptV2`] is
//! structural data: its own `validate()` proves only that its declared
//! approvals are unique and meet their declared threshold. This module is the
//! runtime seam its documentation asks for. [`verify_normative_approvals`]
//! mints a receipt only from approvals whose Ed25519 signatures verify
//! against the keys the ACTIVE activation policy lists, so the principals it
//! names are ones the live policy actually admits, and the threshold it
//! records is the policy's, not the caller's.
//!
//! The pattern mirrors `verify_generic_successor_activation` in
//! `memory_contracts::successor_generic`, with its own signature domain
//! ([`NORMATIVE_APPROVAL_SIGNATURE_PREFIX`]): an approval of a normative
//! statement can never be replayed as a registry successor approval, nor the
//! reverse, even when the two statement ids were equal.
//!
//! Separation of duty is the policy's strong v2 rule
//! (`ActivationPolicyEntryV2::validate_approval_principal_set`): the source
//! author and the proposer must be distinct principals, and neither may be
//! counted among the approvers. That is stronger than both the receipt's own
//! existential rule and `admit_activation`'s runtime rule, which it therefore
//! implies.
//!
//! Everything here is pure: no I/O and no clock. `accepted_at` is supplied by
//! the caller, which must read it from the server (the database's statement
//! time), never from the approver or the proposal.

use std::collections::BTreeSet;

use ring::signature;

use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId, HexBytes};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, domain_separated_digest};
use crate::memory_contracts::normative_v2::{
    ApprovalAttestationV1, NormativeActivationReceiptV2, NormativeActivationSeparationOfDutyV2,
    NormativeBindingProposalV2,
};
use crate::memory_contracts::registry::EligibleApprovalV1;
use crate::memory_contracts::successor_policy::{
    ActivationSignatureAlgorithmV2, StructurallyResolvedActivationPolicyV2,
};
use crate::memory_contracts::{ContractError, ContractResult};

/// Signature domain for a normative activation approval. The detached message
/// is this prefix followed by the 32 raw bytes of the proposal's
/// `statement_id` ([`normative_approval_message`]).
pub const NORMATIVE_APPROVAL_SIGNATURE_PREFIX: &[u8] =
    b"ostk-normative-activation-approval-signature-v2\0";

/// Schema version the normative activation receipt v2 contract requires.
const NORMATIVE_RECEIPT_SCHEMA_VERSION: u32 = 2;

/// The exact bytes an approver signs for one normative statement.
#[must_use]
pub fn normative_approval_message(statement_id: Sha256Digest) -> Vec<u8> {
    let mut message = Vec::with_capacity(NORMATIVE_APPROVAL_SIGNATURE_PREFIX.len() + 32);
    message.extend_from_slice(NORMATIVE_APPROVAL_SIGNATURE_PREFIX);
    message.extend_from_slice(statement_id.as_bytes());
    message
}

/// `schema_version` of the approval attestation wire shape (unchanged from
/// normative binding v1).
const APPROVAL_ATTESTATION_SCHEMA_VERSION: u32 = 1;

/// The only signature algorithm an approval attestation names.
const ED25519_ALGORITHM: &str = "ed25519";

/// Sign one normative statement as `principal_id` with the Ed25519 key whose
/// 32-byte seed is `seed`, at `signed_at`.
///
/// This is the offline half of [`verify_normative_approvals`]: the message is
/// [`normative_approval_message`] and the `signer_key_id` is derived from the
/// public key exactly as an activation policy derives it
/// (`ed25519.<public key hex>`). Signing proves nothing on its own; the
/// approval counts only if the ACTIVE policy lists `principal_id` with this
/// key when the statement is activated.
///
/// # Errors
///
/// A schema error when the proposal is invalid or the seed is not an Ed25519
/// key.
pub fn sign_normative_approval(
    proposal: &NormativeBindingProposalV2,
    principal_id: ContractId,
    seed: &[u8; 32],
    signed_at: CanonicalTimestamp,
) -> ContractResult<ApprovalAttestationV1> {
    let statement_id = proposal.statement_id()?;
    let key_pair = signature::Ed25519KeyPair::from_seed_unchecked(seed)
        .map_err(|_| ContractError::Schema("the approval seed is not an Ed25519 key".into()))?;
    let signer_key_id = ContractId::new(format!(
        "ed25519.{}",
        hex::encode(signature::KeyPair::public_key(&key_pair).as_ref())
    ))?;
    let attestation = ApprovalAttestationV1 {
        schema_version: APPROVAL_ATTESTATION_SCHEMA_VERSION,
        statement_id,
        principal_id,
        signer_key_id,
        signed_at,
        signature_algorithm: ContractId::new(ED25519_ALGORITHM)?,
        signature_hex: HexBytes::new(
            key_pair
                .sign(&normative_approval_message(statement_id))
                .as_ref()
                .to_vec(),
        )?,
    };
    attestation.validate_shape()?;
    Ok(attestation)
}

/// Content identity of one approval attestation, signature included. It is
/// the `attestation_id` a verified receipt records for the approval.
///
/// # Errors
///
/// A schema error when the attestation's shape is invalid.
pub fn approval_attestation_id(
    attestation: &ApprovalAttestationV1,
) -> ContractResult<Sha256Digest> {
    attestation.validate_shape()?;
    Ok(domain_separated_digest(
        DigestDomain::NormativeApprovalAttestationV1,
        &encode_canonical(attestation)?,
    ))
}

/// Verify a set of normative approvals under the active activation policy and
/// mint the activation receipt the normative runtime admits.
///
/// Checks, all fail-closed:
/// - the proposal names `policy` as its registry head's activation policy
///   (otherwise the proposal is stale against the live policy);
/// - every attestation is well formed and approves exactly this statement;
/// - its principal is an eligible signer of `policy`, its `signer_key_id` is
///   the key id `policy` derives for that principal, and its Ed25519 signature
///   over [`normative_approval_message`] verifies under that key;
/// - it was signed no later than `accepted_at`, and no principal approves twice;
/// - the approving set meets the policy's threshold, every approver is
///   eligible, and the policy's strong separation of duty holds (author and
///   proposer distinct, neither approves).
///
/// # Errors
///
/// [`ContractError::StaleRegistryHead`] when the proposal names another
/// policy; [`ContractError::SignatureVerification`] for an approval that is
/// not a valid signature by an eligible key over this statement; a schema,
/// set, eligibility, or threshold error for every other refusal.
pub fn verify_normative_approvals(
    proposal: &NormativeBindingProposalV2,
    approvals: &[ApprovalAttestationV1],
    policy: &StructurallyResolvedActivationPolicyV2,
    accepted_at: &CanonicalTimestamp,
) -> ContractResult<NormativeActivationReceiptV2> {
    let active_policy = policy.policy();
    active_policy.validate()?;
    if policy.registry_reference().entry_digest
        != proposal.registry_head.head.activation_policy_digest
    {
        return Err(ContractError::StaleRegistryHead);
    }
    let statement_id = proposal.statement_id()?;
    if approvals.len() > active_policy.eligible_signers.len() {
        return Err(ContractError::SignatureVerification);
    }

    let message = normative_approval_message(statement_id);
    let mut seen_principals = BTreeSet::new();
    let mut approving_principal_ids: Vec<ContractId> = Vec::with_capacity(approvals.len());
    let mut eligible_approvals: Vec<EligibleApprovalV1> = Vec::with_capacity(approvals.len());
    for approval in approvals {
        approval.validate_shape()?;
        if approval.statement_id != statement_id {
            return Err(ContractError::SignatureVerification);
        }
        // Only keys the ACTIVE policy lists can verify. A revoked or unknown
        // principal has no binding here and fails closed.
        let signer = active_policy
            .eligible_signers
            .iter()
            .find(|binding| binding.principal_id == approval.principal_id)
            .ok_or(ContractError::SignatureVerification)?;
        let signer_key_id = signer.signer_key_id()?;
        if approval.signer_key_id != signer_key_id {
            return Err(ContractError::SignatureVerification);
        }
        match signer.algorithm {
            ActivationSignatureAlgorithmV2::Ed25519 => {
                signature::UnparsedPublicKey::new(
                    &signature::ED25519,
                    signer.public_key.as_bytes(),
                )
                .verify(&message, approval.signature_hex.as_bytes())
                .map_err(|_| ContractError::SignatureVerification)?;
            }
        }
        if &approval.signed_at > accepted_at {
            return Err(ContractError::Schema(
                "normative approval is signed after its activation was accepted".into(),
            ));
        }
        if !seen_principals.insert(&signer.principal_id) {
            return Err(ContractError::Schema(
                "normative approvals name one principal more than once".into(),
            ));
        }
        approving_principal_ids.push(signer.principal_id.clone());
        eligible_approvals.push(EligibleApprovalV1 {
            attestation_id: approval_attestation_id(approval)?,
            principal_id: signer.principal_id.clone(),
            signer_key_id,
        });
    }

    // Threshold, eligibility, and the strong separation-of-duty rule, over the
    // canonical (sorted) approving set.
    approving_principal_ids.sort_unstable();
    active_policy.validate_approval_principal_set(
        &proposal.source_author_principal_id,
        &proposal.proposer_principal_id,
        &approving_principal_ids,
    )?;

    eligible_approvals.sort_unstable();
    let receipt = NormativeActivationReceiptV2 {
        schema_version: NORMATIVE_RECEIPT_SCHEMA_VERSION,
        statement_id,
        source_author_principal_id: proposal.source_author_principal_id.clone(),
        eligible_approvals,
        required_threshold: active_policy.approval_threshold,
        separation_of_duty:
            NormativeActivationSeparationOfDutyV2::IndependentApprovalFromSourceAuthor,
        separation_of_duty_satisfied: true,
        accepted_at: accepted_at.clone(),
    };
    receipt.validate()?;
    Ok(receipt)
}

#[cfg(test)]
#[path = "approvals_tests.rs"]
mod tests;
