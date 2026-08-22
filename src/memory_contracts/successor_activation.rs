//! Pure contracts for the one-time registry generation `0 -> 1` activation.
//!
//! This module verifies canonical proposal bytes, a package-bound conformance
//! result, fresh detached approvals under the pinned active-v1 key bridge, and
//! the exact offline-closed Stage-4 target. The resulting
//! [`VerifiedSuccessorRegistryActivationRequest`] is deliberately non-durable:
//! it proves neither that the predecessor head is still current nor that the
//! one-shot bridge is still unconsumed. A private repository must re-audit both
//! facts and perform the compare-and-swap in one transaction before using the
//! crate-private receipt, event, or head constructors.

use std::{collections::BTreeSet, fmt};

use ring::signature;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    ContractError, ContractResult,
    bootstrap::ConsistencyPartitionKeyV1,
    canonical::{decode_strict, encode_canonical, require_canonical},
    common::{
        AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, FixedHex64,
        ProfileReferenceV1, RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    evidence::AcceptedEventId,
    evidence_v2::RegistryHeadBindingV1,
    genesis_activation::{
        RegistryTestOutcomeV1, RegistryTestResultDigest, RegistryTestResultV1,
        registry_activation_consistency_partition_key,
    },
    registry::{EligibleApprovalV1, RegistryHeadV1},
    stage4_target_package::SemanticallyClosedStage4Package,
    successor_policy::{
        ActivationSignatureAlgorithmV2, GenesisSuccessorKeyBridgeDigest,
        GenesisTransitionSeparationOfDutyV1, PinnedGenesisSuccessorKeyBridge,
    },
};

const SUCCESSOR_ACTIVATION_SCHEMA_VERSION: u32 = 1;
const GENESIS_GENERATION: u32 = 0;
const FIRST_SUCCESSOR_GENERATION: u32 = 1;
const TARGET_ACTIVATION_POLICY_VERSION: u32 = 2;
const MAX_SUCCESSOR_APPROVALS: usize = 64;
const SUCCESSOR_ACTIVATION_EVENT_KIND: &str = "registry.successor.activated";

const SUCCESSOR_APPROVAL_SIGNATURE_PREFIX: &[u8] =
    b"ostk-registry-successor-activation-approval-signature-v1\0";

macro_rules! digest_newtype {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Sha256Digest);

        impl $name {
            pub const fn from_digest(digest: Sha256Digest) -> Self {
                Self(digest)
            }

            pub const fn digest(self) -> Sha256Digest {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Sha256Digest::deserialize(deserializer).map(Self)
            }
        }
    };
}

digest_newtype!(SuccessorRegistryActivationStatementId);
digest_newtype!(SuccessorRegistryActivationApprovalId);
digest_newtype!(SuccessorRegistryActivationId);

/// Deployment-trusted identity of the successor-package conformance runner.
///
/// The pin is deliberately not serializable and cannot be supplied by request
/// bytes. Its expected result digest authenticates the entire canonical test
/// result, including target package and vector roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuccessorRegistryTestRunnerPin {
    runner_artifact: Sha256Digest,
    runner_configuration: Sha256Digest,
    expected_result: RegistryTestResultDigest,
}

impl SuccessorRegistryTestRunnerPin {
    pub const fn from_trusted_config(
        runner_artifact: Sha256Digest,
        runner_configuration: Sha256Digest,
        expected_result: RegistryTestResultDigest,
    ) -> Self {
        Self {
            runner_artifact,
            runner_configuration,
            expected_result,
        }
    }
}

/// Canonical passing test result bound to the exact Stage-4 target and runner.
///
/// This remains offline proof only. It does not make the target package active
/// or authorize a durable registry transition.
#[derive(Debug, Clone)]
pub struct VerifiedSuccessorRegistryTestResult {
    result: RegistryTestResultV1,
    canonical_bytes: Vec<u8>,
    result_digest: RegistryTestResultDigest,
}

impl VerifiedSuccessorRegistryTestResult {
    pub const fn result(&self) -> &RegistryTestResultV1 {
        &self.result
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn result_digest(&self) -> RegistryTestResultDigest {
        self.result_digest
    }
}

/// Verify one canonical runner result against the exact Stage-4 package and an
/// out-of-band runner pin.
pub fn verify_successor_registry_test_result(
    input: &[u8],
    runner_pin: SuccessorRegistryTestRunnerPin,
    target: &SemanticallyClosedStage4Package,
) -> ContractResult<VerifiedSuccessorRegistryTestResult> {
    require_canonical(input)?;
    let result: RegistryTestResultV1 = decode_strict(input)?;
    validate_successor_test_result_shape(&result)?;
    let canonical_bytes = encode_canonical(&result)?;
    if canonical_bytes != input {
        return Err(ContractError::NotCanonical);
    }

    let target_registry = target
        .successor_package()
        .manifest_verified_package()
        .package();
    let result_digest = registry_test_result_digest(&result)?;
    if runner_pin.runner_artifact == Sha256Digest::ZERO
        || runner_pin.runner_configuration == Sha256Digest::ZERO
        || runner_pin.expected_result.digest() == Sha256Digest::ZERO
        || result.profile != target_registry.profile
        || result.package_digest != target.package_digest()
        || result.positive_vector_suite_digest != target_registry.positive_vector_suite_digest
        || result.negative_vector_suite_digest != target_registry.negative_vector_suite_digest
        || result.executed_vector_manifest_digest != result.profile.vector_manifest_digest
        || result.runner_artifact_digest != runner_pin.runner_artifact
        || result.runner_configuration_digest != runner_pin.runner_configuration
        || result_digest != runner_pin.expected_result
    {
        return Err(ContractError::ManifestMismatch);
    }

    Ok(VerifiedSuccessorRegistryTestResult {
        result,
        canonical_bytes,
        result_digest,
    })
}

/// Freshly approved semantic statement for the one-time generation `0 -> 1`
/// transition.
///
/// `expected_predecessor_head` binds the entire open predecessor head,
/// including its activation ID and effective interval. The exact current v1
/// policy and pinned bridge govern this transition. The target v2 policy is
/// committed for the resulting head and governs only future transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorRegistryActivationStatementV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub expected_predecessor_head: RegistryHeadBindingV1,
    pub current_v1_activation_policy: RegistryReferenceV1,
    pub target_package_digest: Sha256Digest,
    pub target_activation_policy: RegistryReferenceV1,
    pub test_vector_result_digest: RegistryTestResultDigest,
    pub genesis_successor_key_bridge_digest: GenesisSuccessorKeyBridgeDigest,
    pub from_generation: u32,
    pub to_generation: u32,
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
    pub proposer_principal_id: ContractId,
    pub package_author_principal_id: ContractId,
}

impl SuccessorRegistryActivationStatementV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        self.expected_predecessor_head.validate_shape()?;
        validate_registry_reference(&self.current_v1_activation_policy)?;
        validate_registry_reference(&self.target_activation_policy)?;
        if self.schema_version != SUCCESSOR_ACTIVATION_SCHEMA_VERSION
            || self.from_generation != GENESIS_GENERATION
            || self.to_generation != FIRST_SUCCESSOR_GENERATION
            || self.current_v1_activation_policy.version != 1
            || self.target_activation_policy.version != TARGET_ACTIVATION_POLICY_VERSION
            || self.expected_predecessor_head.effective_until.is_some()
            || self.current_v1_activation_policy.entry_digest
                != self.expected_predecessor_head.head.activation_policy_digest
            || self.target_package_digest == Sha256Digest::ZERO
            || self.target_package_digest == self.expected_predecessor_head.head.package_digest
            || self.test_vector_result_digest.digest() == Sha256Digest::ZERO
            || self.genesis_successor_key_bridge_digest.digest() == Sha256Digest::ZERO
            || !self.effective_from.is_microsecond_aligned()
            || self.effective_from <= self.expected_predecessor_head.effective_from
            || self.effective_until.is_some()
        {
            return Err(ContractError::Schema(
                "invalid successor registry activation statement v1".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }

    pub fn statement_id(&self) -> ContractResult<SuccessorRegistryActivationStatementId> {
        self.validate_shape()?;
        Ok(SuccessorRegistryActivationStatementId::from_digest(
            domain_separated_digest(
                DigestDomain::RegistrySuccessorActivationStatementV1,
                &encode_canonical(self)?,
            ),
        ))
    }
}

/// One fresh Ed25519 approval under the active-v1 bridge key map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorRegistryActivationApprovalV1 {
    pub schema_version: u32,
    pub statement_id: SuccessorRegistryActivationStatementId,
    pub signer_principal_id: ContractId,
    pub signature: FixedHex64,
}

impl SuccessorRegistryActivationApprovalV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != SUCCESSOR_ACTIVATION_SCHEMA_VERSION
            || self.statement_id.digest() == Sha256Digest::ZERO
            || self.signature.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(ContractError::Schema(
                "invalid successor registry activation approval v1".into(),
            ));
        }
        Ok(())
    }

    pub fn approval_id(&self) -> ContractResult<SuccessorRegistryActivationApprovalId> {
        self.validate_shape()?;
        Ok(SuccessorRegistryActivationApprovalId::from_digest(
            domain_separated_digest(
                DigestDomain::RegistrySuccessorActivationApprovalV1,
                &encode_canonical(self)?,
            ),
        ))
    }
}

/// Canonical principal-sorted approval set for one successor statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorRegistryActivationApprovalSetV1 {
    pub schema_version: u32,
    pub statement_id: SuccessorRegistryActivationStatementId,
    pub approvals: Vec<SuccessorRegistryActivationApprovalV1>,
}

impl SuccessorRegistryActivationApprovalSetV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != SUCCESSOR_ACTIVATION_SCHEMA_VERSION
            || self.statement_id.digest() == Sha256Digest::ZERO
            || self.approvals.is_empty()
            || self.approvals.len() > MAX_SUCCESSOR_APPROVALS
            || !self
                .approvals
                .windows(2)
                .all(|pair| pair[0].signer_principal_id < pair[1].signer_principal_id)
        {
            return Err(ContractError::Schema(
                "invalid successor registry activation approval set v1".into(),
            ));
        }
        for approval in &self.approvals {
            approval.validate_shape()?;
            if approval.statement_id != self.statement_id {
                return Err(ContractError::SignatureVerification);
            }
        }
        encode_canonical(self)?;
        Ok(())
    }
}

/// Trusted proposer and package-author identities for the private ceremony.
///
/// The statement repeats these values for signatures and audit, but cannot
/// choose them: the verifier requires exact equality to this non-serializable
/// trusted binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessorActivationPrincipalBinding {
    proposer_principal_id: ContractId,
    package_author_principal_id: ContractId,
}

impl SuccessorActivationPrincipalBinding {
    pub const fn from_trusted_config(
        proposer_principal_id: ContractId,
        package_author_principal_id: ContractId,
    ) -> Self {
        Self {
            proposer_principal_id,
            package_author_principal_id,
        }
    }
}

/// Canonical and cryptographically verified, but explicitly non-durable,
/// first-successor activation request.
///
/// The repository must lock and re-audit the exact predecessor head, active-v1
/// package/policy, and unconsumed bridge generation in the same transaction as
/// the head compare-and-swap. Possessing this value alone cannot mint durable
/// state.
#[derive(Debug)]
pub struct VerifiedSuccessorRegistryActivationRequest {
    statement: SuccessorRegistryActivationStatementV1,
    canonical_statement: Vec<u8>,
    approval_set: SuccessorRegistryActivationApprovalSetV1,
    canonical_approval_set: Vec<u8>,
    test_result: VerifiedSuccessorRegistryTestResult,
    eligible_approvals: Vec<EligibleApprovalV1>,
    required_v1_threshold: u16,
    applied_v1_separation_of_duty: GenesisTransitionSeparationOfDutyV1,
}

impl VerifiedSuccessorRegistryActivationRequest {
    pub const fn statement(&self) -> &SuccessorRegistryActivationStatementV1 {
        &self.statement
    }

    pub fn canonical_statement(&self) -> &[u8] {
        &self.canonical_statement
    }

    pub const fn approval_set(&self) -> &SuccessorRegistryActivationApprovalSetV1 {
        &self.approval_set
    }

    pub fn canonical_approval_set(&self) -> &[u8] {
        &self.canonical_approval_set
    }

    pub const fn test_result(&self) -> &VerifiedSuccessorRegistryTestResult {
        &self.test_result
    }

    pub fn eligible_approvals(&self) -> &[EligibleApprovalV1] {
        &self.eligible_approvals
    }

    pub const fn required_v1_threshold(&self) -> u16 {
        self.required_v1_threshold
    }

    pub const fn applied_v1_separation_of_duty(&self) -> GenesisTransitionSeparationOfDutyV1 {
        self.applied_v1_separation_of_duty
    }

    /// Mint a receipt only at repository-supplied server time after checking
    /// the persisted predecessor's trusted acceptance time.
    #[allow(dead_code)] // consumed by the successor repository in the next increment
    pub(crate) fn receipt_at(
        &self,
        predecessor_accepted_at: &CanonicalTimestamp,
        accepted_at: CanonicalTimestamp,
    ) -> ContractResult<SuccessorRegistryActivationReceiptV1> {
        let statement = &self.statement;
        if !predecessor_accepted_at.is_microsecond_aligned()
            || !accepted_at.is_microsecond_aligned()
            || predecessor_accepted_at < &statement.expected_predecessor_head.effective_from
            || statement.effective_from < *predecessor_accepted_at
            || statement.effective_from > accepted_at
            || statement.effective_until.is_some()
        {
            return Err(ContractError::Schema(
                "successor activation is outside the predecessor and server-time interval".into(),
            ));
        }

        let receipt = SuccessorRegistryActivationReceiptV1 {
            schema_version: SUCCESSOR_ACTIVATION_SCHEMA_VERSION,
            statement_id: statement.statement_id()?,
            predecessor_head: statement.expected_predecessor_head.clone(),
            current_v1_activation_policy: statement.current_v1_activation_policy.clone(),
            target_package_digest: statement.target_package_digest,
            target_activation_policy: statement.target_activation_policy.clone(),
            test_vector_result_digest: statement.test_vector_result_digest,
            genesis_successor_key_bridge_digest: statement.genesis_successor_key_bridge_digest,
            from_generation: statement.from_generation,
            to_generation: statement.to_generation,
            eligible_approvals: self.eligible_approvals.clone(),
            required_v1_threshold: self.required_v1_threshold,
            applied_v1_separation_of_duty: self.applied_v1_separation_of_duty,
            separation_of_duty_satisfied: true,
            accepted_at,
        };
        receipt.validate_against(self)?;
        Ok(receipt)
    }

    /// Derive the new open head only from a receipt revalidated against this
    /// request. Repository code must call this after the durable predecessor
    /// and bridge checks, never from public request fields.
    pub(crate) fn resulting_registry_head(
        &self,
        receipt: &SuccessorRegistryActivationReceiptV1,
    ) -> ContractResult<RegistryHeadBindingV1> {
        receipt.validate_against(self)?;
        let head = RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id: receipt.activation_id()?.digest(),
                package_digest: receipt.target_package_digest,
                activation_policy_digest: receipt.target_activation_policy.entry_digest,
            },
            effective_from: self.statement.effective_from.clone(),
            effective_until: self.statement.effective_until.clone(),
        };
        head.validate_shape()?;
        Ok(head)
    }
}

/// Verify a canonical generation `0 -> 1` request under the exact pinned v1
/// bridge. The target v2 activation policy is checked for structural closure
/// but deliberately does not authorize this transition.
pub fn verify_successor_registry_activation(
    canonical_statement: &[u8],
    canonical_approval_set: &[u8],
    target: &SemanticallyClosedStage4Package,
    test_result: &VerifiedSuccessorRegistryTestResult,
    bridge: &PinnedGenesisSuccessorKeyBridge,
    principal_binding: &SuccessorActivationPrincipalBinding,
) -> ContractResult<VerifiedSuccessorRegistryActivationRequest> {
    require_canonical(canonical_statement)?;
    let statement: SuccessorRegistryActivationStatementV1 = decode_strict(canonical_statement)?;
    statement.validate_shape()?;
    if encode_canonical(&statement)? != canonical_statement {
        return Err(ContractError::NotCanonical);
    }

    let target_registry = target
        .successor_package()
        .manifest_verified_package()
        .package();
    let target_policy = target.activation_policy();
    target_policy.policy().validate()?;
    bridge.bridge().validate_shape()?;
    let bridge_body = bridge.bridge();
    let predecessor_matches_bridge =
        statement.expected_predecessor_head == bridge_body.genesis_registry_head;
    if statement.profile != target_registry.profile
        || statement.profile != bridge_body.profile
        || statement.scope != bridge_body.scope
        || !predecessor_matches_bridge
        || statement.current_v1_activation_policy != bridge_body.current_v1_activation_policy
        || statement.target_package_digest != target.package_digest()
        || &statement.target_activation_policy != target_policy.registry_reference()
        || statement.test_vector_result_digest != test_result.result_digest()
        || statement.genesis_successor_key_bridge_digest != bridge.bridge_digest()
        || statement.from_generation != bridge_body.from_generation
        || statement.to_generation != bridge_body.to_generation
        || test_result.result().profile != statement.profile
        || test_result.result().package_digest != statement.target_package_digest
        || test_result.result().completed_at > statement.effective_from
        || statement.proposer_principal_id != principal_binding.proposer_principal_id
        || statement.package_author_principal_id != principal_binding.package_author_principal_id
    {
        return Err(ContractError::ManifestMismatch);
    }

    require_canonical(canonical_approval_set)?;
    let approval_set: SuccessorRegistryActivationApprovalSetV1 =
        decode_strict(canonical_approval_set)?;
    approval_set.validate_shape()?;
    if encode_canonical(&approval_set)? != canonical_approval_set {
        return Err(ContractError::NotCanonical);
    }
    let statement_id = statement.statement_id()?;
    if approval_set.statement_id != statement_id
        || approval_set.approvals.len() > bridge_body.key_map.len()
    {
        return Err(ContractError::SignatureVerification);
    }

    let signature_message = successor_approval_signature_message(statement_id);
    let mut approving_principal_ids = Vec::with_capacity(approval_set.approvals.len());
    let mut eligible_approvals = Vec::with_capacity(approval_set.approvals.len());
    for approval in &approval_set.approvals {
        let signer = bridge_body
            .key_map
            .iter()
            .find(|binding| binding.principal_id == approval.signer_principal_id)
            .ok_or(ContractError::SignatureVerification)?;
        match signer.algorithm {
            ActivationSignatureAlgorithmV2::Ed25519 => {
                signature::UnparsedPublicKey::new(
                    &signature::ED25519,
                    signer.public_key.as_bytes(),
                )
                .verify(&signature_message, approval.signature.as_bytes())
                .map_err(|_| ContractError::SignatureVerification)?;
            }
        }
        approving_principal_ids.push(signer.principal_id.clone());
        eligible_approvals.push(EligibleApprovalV1 {
            attestation_id: approval.approval_id()?.digest(),
            principal_id: signer.principal_id.clone(),
            signer_key_id: signer.signer_key_id()?,
        });
    }

    bridge.validate_first_successor_approval_principal_set(
        &statement.package_author_principal_id,
        &approving_principal_ids,
    )?;
    eligible_approvals.sort_unstable();
    if !approval_bindings_are_unique(&eligible_approvals) || !strictly_sorted(&eligible_approvals) {
        return Err(ContractError::SignatureVerification);
    }

    Ok(VerifiedSuccessorRegistryActivationRequest {
        statement,
        canonical_statement: canonical_statement.to_vec(),
        approval_set,
        canonical_approval_set: canonical_approval_set.to_vec(),
        test_result: test_result.clone(),
        eligible_approvals,
        required_v1_threshold: bridge.required_v1_threshold(),
        applied_v1_separation_of_duty: bridge.v1_separation_of_duty(),
    })
}

/// Server-derived audit receipt for the first successor activation.
///
/// Structural bytes alone grant no authority. Runtime code must obtain this
/// value through the crate-private constructor on the opaque verified request
/// after re-auditing durable predecessor and bridge state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorRegistryActivationReceiptV1 {
    pub schema_version: u32,
    pub statement_id: SuccessorRegistryActivationStatementId,
    pub predecessor_head: RegistryHeadBindingV1,
    pub current_v1_activation_policy: RegistryReferenceV1,
    pub target_package_digest: Sha256Digest,
    pub target_activation_policy: RegistryReferenceV1,
    pub test_vector_result_digest: RegistryTestResultDigest,
    pub genesis_successor_key_bridge_digest: GenesisSuccessorKeyBridgeDigest,
    pub from_generation: u32,
    pub to_generation: u32,
    pub eligible_approvals: Vec<EligibleApprovalV1>,
    pub required_v1_threshold: u16,
    pub applied_v1_separation_of_duty: GenesisTransitionSeparationOfDutyV1,
    pub separation_of_duty_satisfied: bool,
    pub accepted_at: CanonicalTimestamp,
}

impl SuccessorRegistryActivationReceiptV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.predecessor_head.validate_shape()?;
        validate_registry_reference(&self.current_v1_activation_policy)?;
        validate_registry_reference(&self.target_activation_policy)?;
        if self.schema_version != SUCCESSOR_ACTIVATION_SCHEMA_VERSION
            || self.statement_id.digest() == Sha256Digest::ZERO
            || self.predecessor_head.effective_until.is_some()
            || self.current_v1_activation_policy.version != 1
            || self.target_activation_policy.version != TARGET_ACTIVATION_POLICY_VERSION
            || self.current_v1_activation_policy.entry_digest
                != self.predecessor_head.head.activation_policy_digest
            || self.target_package_digest == Sha256Digest::ZERO
            || self.target_package_digest == self.predecessor_head.head.package_digest
            || self.test_vector_result_digest.digest() == Sha256Digest::ZERO
            || self.genesis_successor_key_bridge_digest.digest() == Sha256Digest::ZERO
            || self.from_generation != GENESIS_GENERATION
            || self.to_generation != FIRST_SUCCESSOR_GENERATION
            || self.required_v1_threshold == 0
            || usize::from(self.required_v1_threshold) > self.eligible_approvals.len()
            || self.eligible_approvals.len() > MAX_SUCCESSOR_APPROVALS
            || !strictly_sorted(&self.eligible_approvals)
            || !approval_bindings_are_unique(&self.eligible_approvals)
            || self.applied_v1_separation_of_duty
                != GenesisTransitionSeparationOfDutyV1::IndependentApprovalFromPackageAuthor
            || !self.separation_of_duty_satisfied
            || !self.accepted_at.is_microsecond_aligned()
            || self.accepted_at <= self.predecessor_head.effective_from
        {
            return Err(ContractError::Schema(
                "invalid successor registry activation receipt v1".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }

    pub fn activation_id(&self) -> ContractResult<SuccessorRegistryActivationId> {
        self.validate_shape()?;
        Ok(SuccessorRegistryActivationId::from_digest(
            domain_separated_digest(
                DigestDomain::RegistrySuccessorActivationReceiptV1,
                &encode_canonical(self)?,
            ),
        ))
    }

    pub fn validate_against(
        &self,
        activation: &VerifiedSuccessorRegistryActivationRequest,
    ) -> ContractResult<()> {
        self.validate_shape()?;
        let statement = activation.statement();
        if self.statement_id != statement.statement_id()?
            || self.predecessor_head != statement.expected_predecessor_head
            || self.current_v1_activation_policy != statement.current_v1_activation_policy
            || self.target_package_digest != statement.target_package_digest
            || self.target_activation_policy != statement.target_activation_policy
            || self.test_vector_result_digest != statement.test_vector_result_digest
            || self.genesis_successor_key_bridge_digest
                != statement.genesis_successor_key_bridge_digest
            || self.from_generation != statement.from_generation
            || self.to_generation != statement.to_generation
            || self.eligible_approvals != activation.eligible_approvals
            || self.required_v1_threshold != activation.required_v1_threshold
            || self.applied_v1_separation_of_duty != activation.applied_v1_separation_of_duty
            || self.accepted_at < statement.effective_from
        {
            return Err(ContractError::ManifestMismatch);
        }
        Ok(())
    }
}

/// Immutable semantic event announcing the generation `0 -> 1` registry head.
/// Append coordinates are absent, while receipt time remains transitively
/// committed through `activation_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorRegistryActivatedEventV1 {
    pub schema_version: u32,
    pub event_kind: ContractId,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub activation_id: SuccessorRegistryActivationId,
    pub statement_id: SuccessorRegistryActivationStatementId,
    pub predecessor_head: RegistryHeadBindingV1,
    pub activated_head: RegistryHeadBindingV1,
    pub current_v1_activation_policy: RegistryReferenceV1,
    pub target_activation_policy: RegistryReferenceV1,
    pub test_vector_result_digest: RegistryTestResultDigest,
    pub genesis_successor_key_bridge_digest: GenesisSuccessorKeyBridgeDigest,
    pub from_generation: u32,
    pub to_generation: u32,
}

impl SuccessorRegistryActivatedEventV1 {
    /// Repository-only event construction from the exact verified request and
    /// server-derived receipt.
    #[allow(dead_code)] // consumed by the successor repository in the next increment
    pub(crate) fn from_verified(
        activation: &VerifiedSuccessorRegistryActivationRequest,
        receipt: &SuccessorRegistryActivationReceiptV1,
    ) -> ContractResult<Self> {
        receipt.validate_against(activation)?;
        let event = Self::from_parts(activation, receipt)?;
        event.validate_against(activation, receipt)?;
        Ok(event)
    }

    pub fn accepted_event_id(&self) -> ContractResult<AcceptedEventId> {
        self.validate_shape()?;
        Ok(AcceptedEventId::from_digest(domain_separated_digest(
            DigestDomain::AcceptedEvent,
            &encode_canonical(self)?,
        )))
    }

    /// Genesis and successor transitions share the one scope-local
    /// `registry.activation` consistency stream.
    pub fn consistency_partition_key(&self) -> ContractResult<ConsistencyPartitionKeyV1> {
        self.validate_shape()?;
        registry_activation_consistency_partition_key(&self.scope)
    }

    pub fn validate_against(
        &self,
        activation: &VerifiedSuccessorRegistryActivationRequest,
        receipt: &SuccessorRegistryActivationReceiptV1,
    ) -> ContractResult<()> {
        self.validate_shape()?;
        receipt.validate_against(activation)?;
        if self != &Self::from_parts(activation, receipt)? {
            return Err(ContractError::ManifestMismatch);
        }
        Ok(())
    }

    fn from_parts(
        activation: &VerifiedSuccessorRegistryActivationRequest,
        receipt: &SuccessorRegistryActivationReceiptV1,
    ) -> ContractResult<Self> {
        let statement = activation.statement();
        Ok(Self {
            schema_version: SUCCESSOR_ACTIVATION_SCHEMA_VERSION,
            event_kind: ContractId::new(SUCCESSOR_ACTIVATION_EVENT_KIND)?,
            profile: statement.profile.clone(),
            scope: statement.scope.clone(),
            activation_id: receipt.activation_id()?,
            statement_id: statement.statement_id()?,
            predecessor_head: statement.expected_predecessor_head.clone(),
            activated_head: activation.resulting_registry_head(receipt)?,
            current_v1_activation_policy: statement.current_v1_activation_policy.clone(),
            target_activation_policy: statement.target_activation_policy.clone(),
            test_vector_result_digest: statement.test_vector_result_digest,
            genesis_successor_key_bridge_digest: statement.genesis_successor_key_bridge_digest,
            from_generation: statement.from_generation,
            to_generation: statement.to_generation,
        })
    }

    fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        self.predecessor_head.validate_shape()?;
        self.activated_head.validate_shape()?;
        validate_registry_reference(&self.current_v1_activation_policy)?;
        validate_registry_reference(&self.target_activation_policy)?;
        if self.schema_version != SUCCESSOR_ACTIVATION_SCHEMA_VERSION
            || self.event_kind.as_str() != SUCCESSOR_ACTIVATION_EVENT_KIND
            || self.statement_id.digest() == Sha256Digest::ZERO
            || self.predecessor_head.effective_until.is_some()
            || self.activated_head.effective_until.is_some()
            || self.current_v1_activation_policy.version != 1
            || self.target_activation_policy.version != TARGET_ACTIVATION_POLICY_VERSION
            || self.current_v1_activation_policy.entry_digest
                != self.predecessor_head.head.activation_policy_digest
            || self.target_activation_policy.entry_digest
                != self.activated_head.head.activation_policy_digest
            || self.predecessor_head.head.package_digest == self.activated_head.head.package_digest
            || self.activation_id.digest() != self.activated_head.head.activation_id
            || self.test_vector_result_digest.digest() == Sha256Digest::ZERO
            || self.genesis_successor_key_bridge_digest.digest() == Sha256Digest::ZERO
            || self.from_generation != GENESIS_GENERATION
            || self.to_generation != FIRST_SUCCESSOR_GENERATION
            || self.activated_head.effective_from <= self.predecessor_head.effective_from
        {
            return Err(ContractError::Schema(
                "invalid successor registry activated event v1".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }
}

fn validate_successor_test_result_shape(result: &RegistryTestResultV1) -> ContractResult<()> {
    result.profile.require_frozen_runtime_profile()?;
    if result.schema_version != SUCCESSOR_ACTIVATION_SCHEMA_VERSION
        || result.package_digest == Sha256Digest::ZERO
        || result.positive_vector_suite_digest == Sha256Digest::ZERO
        || result.negative_vector_suite_digest == Sha256Digest::ZERO
        || result.executed_vector_manifest_digest == Sha256Digest::ZERO
        || result.runner_artifact_digest == Sha256Digest::ZERO
        || result.runner_configuration_digest == Sha256Digest::ZERO
        || result.passed_case_count == 0
        || result.failed_case_count != 0
        || result.outcome != RegistryTestOutcomeV1::Passed
        || !result.completed_at.is_microsecond_aligned()
    {
        return Err(ContractError::Schema(
            "invalid successor registry test result".into(),
        ));
    }
    encode_canonical(result)?;
    Ok(())
}

fn registry_test_result_digest(
    result: &RegistryTestResultV1,
) -> ContractResult<RegistryTestResultDigest> {
    validate_successor_test_result_shape(result)?;
    Ok(RegistryTestResultDigest::from_digest(
        domain_separated_digest(DigestDomain::RegistryTestResult, &encode_canonical(result)?),
    ))
}

fn validate_registry_reference(reference: &RegistryReferenceV1) -> ContractResult<()> {
    reference.validate()?;
    if reference.entry_digest == Sha256Digest::ZERO {
        return Err(ContractError::Schema(
            "successor activation reference cannot use the zero digest".into(),
        ));
    }
    Ok(())
}

fn successor_approval_signature_message(
    statement_id: SuccessorRegistryActivationStatementId,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(SUCCESSOR_APPROVAL_SIGNATURE_PREFIX.len() + 32);
    message.extend_from_slice(SUCCESSOR_APPROVAL_SIGNATURE_PREFIX);
    message.extend_from_slice(statement_id.digest().as_bytes());
    message
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn approval_bindings_are_unique(values: &[EligibleApprovalV1]) -> bool {
    if values
        .iter()
        .any(|approval| approval.attestation_id == Sha256Digest::ZERO)
    {
        return false;
    }
    let principals = values
        .iter()
        .map(|approval| &approval.principal_id)
        .collect::<BTreeSet<_>>();
    let keys = values
        .iter()
        .map(|approval| &approval.signer_key_id)
        .collect::<BTreeSet<_>>();
    principals.len() == values.len() && keys.len() == values.len()
}

#[cfg(test)]
#[path = "successor_activation_tests.rs"]
mod tests;
