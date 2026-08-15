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
mod tests {
    use std::{env, fs, path::Path};

    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::memory_contracts::{
        common::frozen_profile_reference_v1,
        genesis::SemanticallyClosedGenesisPackage,
        registry::ManifestVerifiedRegistryPackage,
        successor_package::SemanticallyClosedSuccessorPackage,
        successor_policy::{
            ActiveGenesisSuccessorWitness, GenesisSuccessorKeyBridgePin,
            GenesisSuccessorKeyBridgeV1, verify_pinned_genesis_successor_key_bridge,
        },
    };

    const GENESIS_PACKAGE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");
    const BRIDGE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-policy/genesis-successor-key-bridge-v1.jsonl"
    );
    const TARGET_PACKAGE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");
    const TEST_RESULT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-activation/registry-test-result.jsonl"
    );
    const ACTIVATION_STATEMENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-activation/activation-statement.jsonl"
    );
    const ACTIVATION_APPROVAL_SET_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-activation/activation-approval-set.jsonl"
    );
    const ACTIVATION_RECEIPT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-activation/activation-receipt.jsonl"
    );
    const ACTIVATED_HEAD_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-activation/activated-head.jsonl"
    );
    const ACTIVATION_EVENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-activation/activation-event.jsonl"
    );
    const POSITIVE_VECTORS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-activation/positive-vectors.jsonl"
    );
    const NEGATIVE_VECTORS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-activation/negative-vectors.jsonl"
    );
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/successor-activation/vector-suite.jsonl");

    const GENESIS_APPROVAL_SIGNATURE_PREFIX: &[u8] =
        b"ostk-registry-activation-approval-signature-v1\0";

    const FIXTURE_AUTHORITY: &str =
        "none; public fixture seeds and structural bytes never authorize a registry transition";
    const SUCCESSOR_ACTIVATION_SUITE_ID: &str = "registry.successor_activation.v1";

    const TARGET_PACKAGE_DIGEST: &str =
        "16f98d5df93b74dab5b2188274cbd1da21d089ff7a64cd8fc29679946e7fe2c9";
    const TARGET_ACTIVATION_POLICY_DIGEST: &str =
        "5611a4fea75d0a8132395bf6e3040ce97638a3447e290f5cabc183c1bb9faa6c";
    const TARGET_POSITIVE_VECTOR_ROOT: &str =
        "767cc52d3a02d7f2466462f64655df3eaf185f3b9158ddcded0057298795a410";
    const TARGET_NEGATIVE_VECTOR_ROOT: &str =
        "e7d1974b23f3b475bc72132852f16e8f73600077e71e59a3683cb2c5301090ec";
    const EXECUTED_VECTOR_MANIFEST_DIGEST: &str =
        "f984f62866fc769df3a5617a2247e3ade694827c1de69e615a7bda68858b4174";
    const RUNNER_ARTIFACT_DIGEST: &str =
        "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    const RUNNER_CONFIGURATION_DIGEST: &str =
        "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
    const BRIDGE_DIGEST: &str = "e15309eba5118e21996a7cee6b3780c1a237982bdf4f22460bca4da189ef6592";
    const TEST_RESULT_DIGEST: &str =
        "e6783b2a018957a5861fe4e0670f55613d1ace35e381a6a9f5190ea9d7fbff8d";
    const STATEMENT_ID: &str = "b0f171117b3c734a2ac105d9d114c9735e57d5c0b3c6e205143826c8164e044d";
    const ALICE_APPROVAL_ID: &str =
        "895939a2df916e78831d6e01d829380b85cb42df899698eba4a66128ee620223";
    const BOB_APPROVAL_ID: &str =
        "b7677600be37413a5a20c305b418daf6ce997e1582207105cdbc8b1e8d4abde8";
    const ACTIVATION_ID: &str = "60fe4eb627dab5e7798a22188218c308063de7eca121ea7f4b267f9ab23db4bb";
    const ACCEPTED_EVENT_ID: &str =
        "d7f1609afb1e7ec83767dc39fefb6ad0fc491f8c3d6793e7410bd599dbb24470";
    const CONSISTENCY_KEY_DIGEST: &str =
        "9921b7e572be77d3e100eb3d3093fb0d8ff4b3b5965f75110c18bfd34479b5ec";
    const POSITIVE_CASES_DIGEST: &str =
        "e16bc43a92d3347cbba93eb13693ce547426368959966845bd3eee469a4d7de7";
    const NEGATIVE_CASES_DIGEST: &str =
        "6535b0b92ed1142ada9a63d64c0624b3f6be8effd5a99916e819a0fc664c5b40";
    const VECTOR_SUITE_DIGEST: &str =
        "f40254b9f2d242afc9b65f330879fb6c0094b10097636d1bf24558632fed785d";

    const TARGET_PACKAGE_RAW_SHA256: &str =
        "6e6a8eafe34913cc472ee9d970ddc23588568e9738040d464e1193d378e9f323";
    const BRIDGE_RAW_SHA256: &str =
        "e008106413023eb6e9da0e9e200d8b8f58b4cae7434a723a9e2e56f357c3b25b";
    const TEST_RESULT_RAW_SHA256: &str =
        "bc07fb8d0a79bea19f671a6f091611f14a7997ac72fbc72599472512562c962b";
    const STATEMENT_RAW_SHA256: &str =
        "8ff1523115d72b131f7ae7c65089d48fc0235e6ac53d743bfe3734a144f981a9";
    const APPROVAL_SET_RAW_SHA256: &str =
        "6f4979d161e5b43c50dfe441095b4682d2b9c523042b87789172ea62f2f59a11";
    const RECEIPT_RAW_SHA256: &str =
        "875d33d98753779dde29bfa0ea9d9da620a596a48b4b516ccf6f0b3c521170a2";
    const ACTIVATED_HEAD_RAW_SHA256: &str =
        "189814fb4dd696e8ebfab61177f29d7077eb17b486759bb6f01b96e30b965ea5";
    const EVENT_RAW_SHA256: &str =
        "57c841d4d66c1df89823a866413bd58807c1c2e2ecab0151b9cd2d433aae4c32";
    const POSITIVE_VECTORS_RAW_SHA256: &str =
        "82e132178b897b611b1e2e7b32a20ea1dfa32385902dcf875594a40d1e68c766";
    const NEGATIVE_VECTORS_RAW_SHA256: &str =
        "7f39618c63360c0dfcc8cfbed729e76645724dd921b40cb9f5e678be277c6cce";
    const VECTOR_SUITE_RAW_SHA256: &str =
        "95939cafebae1f98ca05c5efbfaea3f5dce0f52ed4ba485b5a9c2fc1b48884b8";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum SuccessorActivationCaseOutcomeV1 {
        Accept,
        Reject,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SuccessorActivationCaseManifestV1 {
        schema_version: u32,
        suite_id: ContractId,
        expected_outcome: SuccessorActivationCaseOutcomeV1,
        cases: Vec<ContractId>,
    }

    impl SuccessorActivationCaseManifestV1 {
        fn validate(&self, expected_outcome: SuccessorActivationCaseOutcomeV1) {
            assert_eq!(self.schema_version, SUCCESSOR_ACTIVATION_SCHEMA_VERSION);
            assert_eq!(self.suite_id.as_str(), SUCCESSOR_ACTIVATION_SUITE_ID);
            assert_eq!(self.expected_outcome, expected_outcome);
            assert!(!self.cases.is_empty());
            assert!(strictly_sorted(&self.cases));
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SuccessorActivationArtifactPinV1 {
        path: String,
        raw_sha256: Sha256Digest,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SuccessorActivationVectorSuiteV1 {
        schema_version: u32,
        suite_id: ContractId,
        fixture_authority: String,
        predecessor_head: RegistryHeadBindingV1,
        current_v1_activation_policy: RegistryReferenceV1,
        target_package_digest: Sha256Digest,
        target_activation_policy: RegistryReferenceV1,
        genesis_successor_key_bridge_digest: GenesisSuccessorKeyBridgeDigest,
        test_result_digest: RegistryTestResultDigest,
        statement_id: SuccessorRegistryActivationStatementId,
        approval_ids: Vec<SuccessorRegistryActivationApprovalId>,
        activation_id: SuccessorRegistryActivationId,
        accepted_event_id: AcceptedEventId,
        activated_head: RegistryHeadBindingV1,
        consistency_key_family: ContractId,
        consistency_key_digest: Sha256Digest,
        positive_cases_digest: Sha256Digest,
        negative_cases_digest: Sha256Digest,
        external_artifact_pins: Vec<SuccessorActivationArtifactPinV1>,
        artifact_pins: Vec<SuccessorActivationArtifactPinV1>,
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn expected_digest(value: &str) -> Sha256Digest {
        value.parse().unwrap()
    }

    fn timestamp(value: &str) -> CanonicalTimestamp {
        CanonicalTimestamp::parse(value).unwrap()
    }

    fn record(artifact: &'static [u8]) -> &'static [u8] {
        let record = artifact
            .strip_suffix(b"\n")
            .expect("fixture must have exactly one repository-framing LF");
        assert!(!record.ends_with(b"\n"));
        assert!(!record.contains(&b'\r'));
        record
    }

    fn case_id(value: &str) -> ContractId {
        ContractId::new(value).unwrap()
    }

    fn positive_cases() -> SuccessorActivationCaseManifestV1 {
        SuccessorActivationCaseManifestV1 {
            schema_version: SUCCESSOR_ACTIVATION_SCHEMA_VERSION,
            suite_id: case_id(SUCCESSOR_ACTIVATION_SUITE_ID),
            expected_outcome: SuccessorActivationCaseOutcomeV1::Accept,
            cases: [
                "canonical_target_transition",
                "current_v1_bridge_authority",
                "opaque_request_is_non_durable",
                "server_time_mints_receipt",
                "stable_registry_activation_stream",
                "target_v2_policy_is_future_authority",
            ]
            .into_iter()
            .map(case_id)
            .collect(),
        }
    }

    fn negative_cases() -> SuccessorActivationCaseManifestV1 {
        SuccessorActivationCaseManifestV1 {
            schema_version: SUCCESSOR_ACTIVATION_SCHEMA_VERSION,
            suite_id: case_id(SUCCESSOR_ACTIVATION_SUITE_ID),
            expected_outcome: SuccessorActivationCaseOutcomeV1::Reject,
            cases: [
                "bridge_digest_tamper",
                "current_v1_policy_tamper",
                "effective_time_before_test_completion",
                "effective_time_non_microsecond",
                "genesis_signature_replay",
                "insufficient_threshold",
                "package_author_only_approval",
                "predecessor_activation_id_tamper",
                "receipt_separation_of_duty_tamper",
                "reversed_approval_set",
                "signer_key_or_principal_tamper",
                "target_package_tamper",
                "target_policy_tamper",
                "test_result_pin_tamper",
                "wrong_generation",
            ]
            .into_iter()
            .map(case_id)
            .collect(),
        }
    }

    fn framed_record(canonical: &[u8]) -> Vec<u8> {
        let mut framed = Vec::with_capacity(canonical.len() + 1);
        framed.extend_from_slice(canonical);
        framed.push(b'\n');
        framed
    }

    fn raw_sha256(bytes: &[u8]) -> Sha256Digest {
        let mut hash = Sha256::new();
        hash.update(bytes);
        Sha256Digest::from_bytes(hash.finalize().into())
    }

    fn manifest_digest(manifest: &SuccessorActivationCaseManifestV1) -> Sha256Digest {
        domain_separated_digest(
            DigestDomain::TestVectorManifest,
            &encode_canonical(manifest).unwrap(),
        )
    }

    fn real_target() -> SemanticallyClosedStage4Package {
        let verified = ManifestVerifiedRegistryPackage::decode(
            record(TARGET_PACKAGE_FIXTURE),
            &frozen_profile_reference_v1(),
        )
        .unwrap();
        let successor =
            SemanticallyClosedSuccessorPackage::from_manifest_verified(verified).unwrap();
        SemanticallyClosedStage4Package::from_successor_package(successor).unwrap()
    }

    fn real_bridge() -> PinnedGenesisSuccessorKeyBridge {
        let genesis = ManifestVerifiedRegistryPackage::decode(
            record(GENESIS_PACKAGE_FIXTURE),
            &frozen_profile_reference_v1(),
        )
        .unwrap();
        let genesis = SemanticallyClosedGenesisPackage::from_manifest_verified(genesis).unwrap();
        let bridge: GenesisSuccessorKeyBridgeV1 = decode_strict(record(BRIDGE_FIXTURE)).unwrap();
        let witness = ActiveGenesisSuccessorWitness::from_test_fixture(
            bridge.profile.clone(),
            bridge.scope.clone(),
            bridge.genesis_registry_head.clone(),
            bridge.current_v1_activation_policy.clone(),
            &genesis,
            bridge.from_generation,
            false,
        )
        .unwrap();
        let pin = GenesisSuccessorKeyBridgePin::from_trusted_config(
            GenesisSuccessorKeyBridgeDigest::from_digest(domain_separated_digest(
                DigestDomain::GenesisSuccessorKeyBridgeV1,
                record(BRIDGE_FIXTURE),
            )),
        );
        verify_pinned_genesis_successor_key_bridge(record(BRIDGE_FIXTURE), pin, &witness).unwrap()
    }

    fn real_test_result(
        target: &SemanticallyClosedStage4Package,
    ) -> VerifiedSuccessorRegistryTestResult {
        let package = target
            .successor_package()
            .manifest_verified_package()
            .package();
        let result = RegistryTestResultV1 {
            schema_version: 1,
            profile: package.profile.clone(),
            package_digest: target.package_digest(),
            positive_vector_suite_digest: package.positive_vector_suite_digest,
            negative_vector_suite_digest: package.negative_vector_suite_digest,
            executed_vector_manifest_digest: package.profile.vector_manifest_digest,
            runner_artifact_digest: expected_digest(RUNNER_ARTIFACT_DIGEST),
            runner_configuration_digest: expected_digest(RUNNER_CONFIGURATION_DIGEST),
            passed_case_count: u32::try_from(package.entries.len()).unwrap(),
            failed_case_count: 0,
            outcome: RegistryTestOutcomeV1::Passed,
            completed_at: timestamp("2026-08-15T04:09:00.000000000Z"),
        };
        let bytes = encode_canonical(&result).unwrap();
        let pin = SuccessorRegistryTestRunnerPin::from_trusted_config(
            result.runner_artifact_digest,
            result.runner_configuration_digest,
            registry_test_result_digest(&result).unwrap(),
        );
        verify_successor_registry_test_result(&bytes, pin, target).unwrap()
    }

    fn real_statement(
        target: &SemanticallyClosedStage4Package,
        bridge: &PinnedGenesisSuccessorKeyBridge,
        test_result: &VerifiedSuccessorRegistryTestResult,
    ) -> SuccessorRegistryActivationStatementV1 {
        let bridge = bridge.bridge();
        SuccessorRegistryActivationStatementV1 {
            schema_version: 1,
            profile: bridge.profile.clone(),
            scope: bridge.scope.clone(),
            expected_predecessor_head: bridge.genesis_registry_head.clone(),
            current_v1_activation_policy: bridge.current_v1_activation_policy.clone(),
            target_package_digest: target.package_digest(),
            target_activation_policy: target.activation_policy().registry_reference().clone(),
            test_vector_result_digest: test_result.result_digest(),
            genesis_successor_key_bridge_digest: GenesisSuccessorKeyBridgeDigest::from_digest(
                domain_separated_digest(
                    DigestDomain::GenesisSuccessorKeyBridgeV1,
                    record(BRIDGE_FIXTURE),
                ),
            ),
            from_generation: 0,
            to_generation: 1,
            effective_from: timestamp("2026-08-15T04:10:00.000000000Z"),
            effective_until: None,
            proposer_principal_id: ContractId::new("principal.proposer").unwrap(),
            package_author_principal_id: ContractId::new("principal.author").unwrap(),
        }
    }

    fn signed_approval(
        statement_id: SuccessorRegistryActivationStatementId,
        principal: &str,
        seed: [u8; 32],
    ) -> SuccessorRegistryActivationApprovalV1 {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let signature = key_pair.sign(&successor_approval_signature_message(statement_id));
        SuccessorRegistryActivationApprovalV1 {
            schema_version: 1,
            statement_id,
            signer_principal_id: ContractId::new(principal).unwrap(),
            signature: FixedHex64::from_bytes(signature.as_ref().try_into().unwrap()),
        }
    }

    fn real_approval_set(
        statement: &SuccessorRegistryActivationStatementV1,
    ) -> SuccessorRegistryActivationApprovalSetV1 {
        let statement_id = statement.statement_id().unwrap();
        SuccessorRegistryActivationApprovalSetV1 {
            schema_version: SUCCESSOR_ACTIVATION_SCHEMA_VERSION,
            statement_id,
            approvals: vec![
                signed_approval(statement_id, "principal.alice", [1; 32]),
                signed_approval(statement_id, "principal.bob", [2; 32]),
            ],
        }
    }

    fn real_principal_binding(
        statement: &SuccessorRegistryActivationStatementV1,
    ) -> SuccessorActivationPrincipalBinding {
        SuccessorActivationPrincipalBinding::from_trusted_config(
            statement.proposer_principal_id.clone(),
            statement.package_author_principal_id.clone(),
        )
    }

    fn verify_real_statement(
        statement: &SuccessorRegistryActivationStatementV1,
        target: &SemanticallyClosedStage4Package,
        bridge: &PinnedGenesisSuccessorKeyBridge,
        test_result: &VerifiedSuccessorRegistryTestResult,
    ) -> ContractResult<VerifiedSuccessorRegistryActivationRequest> {
        verify_successor_registry_activation(
            &encode_canonical(statement)?,
            &encode_canonical(&real_approval_set(statement))?,
            target,
            test_result,
            bridge,
            &real_principal_binding(statement),
        )
    }

    fn real_predecessor_accepted_at() -> CanonicalTimestamp {
        timestamp("2026-08-15T04:00:00.000000000Z")
    }

    fn real_successor_accepted_at() -> CanonicalTimestamp {
        timestamp("2026-08-15T04:10:00.000000000Z")
    }

    fn real_verified_request() -> VerifiedSuccessorRegistryActivationRequest {
        let target = real_target();
        let bridge = real_bridge();
        let test_result = real_test_result(&target);
        let statement = real_statement(&target, &bridge, &test_result);
        verify_real_statement(&statement, &target, &bridge, &test_result).unwrap()
    }

    fn verify_tampered_real_statement(
        mutate: impl FnOnce(&mut SuccessorRegistryActivationStatementV1),
    ) -> ContractResult<VerifiedSuccessorRegistryActivationRequest> {
        let target = real_target();
        let bridge = real_bridge();
        let test_result = real_test_result(&target);
        let mut statement = real_statement(&target, &bridge, &test_result);
        mutate(&mut statement);
        statement.validate_shape()?;
        verify_real_statement(&statement, &target, &bridge, &test_result)
    }

    struct RealSuccessorArtifactGraph {
        request: VerifiedSuccessorRegistryActivationRequest,
        receipt: SuccessorRegistryActivationReceiptV1,
        activated_head: RegistryHeadBindingV1,
        event: SuccessorRegistryActivatedEventV1,
    }

    fn real_artifact_graph() -> RealSuccessorArtifactGraph {
        let request = real_verified_request();
        let receipt = request
            .receipt_at(
                &real_predecessor_accepted_at(),
                real_successor_accepted_at(),
            )
            .unwrap();
        let activated_head = request.resulting_registry_head(&receipt).unwrap();
        let event = SuccessorRegistryActivatedEventV1::from_verified(&request, &receipt).unwrap();
        RealSuccessorArtifactGraph {
            request,
            receipt,
            activated_head,
            event,
        }
    }

    fn canonical_artifact_records(
        graph: &RealSuccessorArtifactGraph,
        positive_bytes: &[u8],
        negative_bytes: &[u8],
    ) -> Vec<(&'static str, Vec<u8>)> {
        vec![
            (
                "activated-head.jsonl",
                encode_canonical(&graph.activated_head).unwrap(),
            ),
            (
                "activation-approval-set.jsonl",
                graph.request.canonical_approval_set().to_vec(),
            ),
            (
                "activation-event.jsonl",
                encode_canonical(&graph.event).unwrap(),
            ),
            (
                "activation-receipt.jsonl",
                encode_canonical(&graph.receipt).unwrap(),
            ),
            (
                "activation-statement.jsonl",
                graph.request.canonical_statement().to_vec(),
            ),
            ("negative-vectors.jsonl", negative_bytes.to_vec()),
            ("positive-vectors.jsonl", positive_bytes.to_vec()),
            (
                "registry-test-result.jsonl",
                graph.request.test_result().canonical_bytes().to_vec(),
            ),
        ]
    }

    fn vector_suite(
        graph: &RealSuccessorArtifactGraph,
        positive: &SuccessorActivationCaseManifestV1,
        negative: &SuccessorActivationCaseManifestV1,
        records: &[(&'static str, Vec<u8>)],
    ) -> SuccessorActivationVectorSuiteV1 {
        let statement = graph.request.statement();
        let consistency_key = graph.event.consistency_partition_key().unwrap();
        SuccessorActivationVectorSuiteV1 {
            schema_version: SUCCESSOR_ACTIVATION_SCHEMA_VERSION,
            suite_id: case_id(SUCCESSOR_ACTIVATION_SUITE_ID),
            fixture_authority: FIXTURE_AUTHORITY.into(),
            predecessor_head: statement.expected_predecessor_head.clone(),
            current_v1_activation_policy: statement.current_v1_activation_policy.clone(),
            target_package_digest: statement.target_package_digest,
            target_activation_policy: statement.target_activation_policy.clone(),
            genesis_successor_key_bridge_digest: statement.genesis_successor_key_bridge_digest,
            test_result_digest: graph.request.test_result().result_digest(),
            statement_id: statement.statement_id().unwrap(),
            approval_ids: graph
                .request
                .approval_set()
                .approvals
                .iter()
                .map(|approval| approval.approval_id().unwrap())
                .collect(),
            activation_id: graph.receipt.activation_id().unwrap(),
            accepted_event_id: graph.event.accepted_event_id().unwrap(),
            activated_head: graph.activated_head.clone(),
            consistency_key_family: consistency_key.family,
            consistency_key_digest: consistency_key.key_digest,
            positive_cases_digest: manifest_digest(positive),
            negative_cases_digest: manifest_digest(negative),
            external_artifact_pins: vec![
                SuccessorActivationArtifactPinV1 {
                    path: "../stage4-successor/registry-package.jsonl".into(),
                    raw_sha256: raw_sha256(TARGET_PACKAGE_FIXTURE),
                },
                SuccessorActivationArtifactPinV1 {
                    path: "../successor-policy/genesis-successor-key-bridge-v1.jsonl".into(),
                    raw_sha256: raw_sha256(BRIDGE_FIXTURE),
                },
            ],
            artifact_pins: records
                .iter()
                .map(|(path, bytes)| SuccessorActivationArtifactPinV1 {
                    path: (*path).into(),
                    raw_sha256: raw_sha256(&framed_record(bytes)),
                })
                .collect(),
        }
    }

    fn reference(id: &str, version: u32, byte: u8) -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new(id).unwrap(),
            version,
            entry_digest: digest(byte),
        }
    }

    fn predecessor_head() -> RegistryHeadBindingV1 {
        RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id: digest(1),
                package_digest: digest(2),
                activation_policy_digest: digest(3),
            },
            effective_from: timestamp("2026-08-15T04:00:00.000000000Z"),
            effective_until: None,
        }
    }

    fn statement() -> SuccessorRegistryActivationStatementV1 {
        SuccessorRegistryActivationStatementV1 {
            schema_version: 1,
            profile: frozen_profile_reference_v1(),
            scope: AuthenticatedProjectScopeV1::from_trusted_context(
                ContractId::new("tenant.fixture").unwrap(),
                ContractId::new("project.fixture").unwrap(),
            ),
            expected_predecessor_head: predecessor_head(),
            current_v1_activation_policy: reference("activation.default", 1, 3),
            target_package_digest: digest(4),
            target_activation_policy: reference("activation.default", 2, 5),
            test_vector_result_digest: RegistryTestResultDigest::from_digest(digest(6)),
            genesis_successor_key_bridge_digest: GenesisSuccessorKeyBridgeDigest::from_digest(
                digest(7),
            ),
            from_generation: 0,
            to_generation: 1,
            effective_from: timestamp("2026-08-15T04:10:00.000000000Z"),
            effective_until: None,
            proposer_principal_id: ContractId::new("principal.proposer").unwrap(),
            package_author_principal_id: ContractId::new("principal.author").unwrap(),
        }
    }

    fn signature(byte: u8) -> FixedHex64 {
        FixedHex64::from_bytes([byte; 64])
    }

    fn approval(
        statement_id: SuccessorRegistryActivationStatementId,
        principal: &str,
        signature_byte: u8,
    ) -> SuccessorRegistryActivationApprovalV1 {
        SuccessorRegistryActivationApprovalV1 {
            schema_version: 1,
            statement_id,
            signer_principal_id: ContractId::new(principal).unwrap(),
            signature: signature(signature_byte),
        }
    }

    fn test_result() -> VerifiedSuccessorRegistryTestResult {
        let result = RegistryTestResultV1 {
            schema_version: 1,
            profile: frozen_profile_reference_v1(),
            package_digest: digest(4),
            positive_vector_suite_digest: digest(8),
            negative_vector_suite_digest: digest(9),
            executed_vector_manifest_digest: frozen_profile_reference_v1().vector_manifest_digest,
            runner_artifact_digest: digest(10),
            runner_configuration_digest: digest(11),
            passed_case_count: 17,
            failed_case_count: 0,
            outcome: RegistryTestOutcomeV1::Passed,
            completed_at: timestamp("2026-08-15T04:09:00.000000000Z"),
        };
        VerifiedSuccessorRegistryTestResult {
            canonical_bytes: encode_canonical(&result).unwrap(),
            result_digest: registry_test_result_digest(&result).unwrap(),
            result,
        }
    }

    fn verified_request() -> VerifiedSuccessorRegistryActivationRequest {
        let test_result = test_result();
        let mut statement = statement();
        statement.test_vector_result_digest = test_result.result_digest();
        let statement_id = statement.statement_id().unwrap();
        let approval = approval(statement_id, "principal.alice", 12);
        let approval_set = SuccessorRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id,
            approvals: vec![approval.clone()],
        };
        let eligible_approvals = vec![EligibleApprovalV1 {
            attestation_id: approval.approval_id().unwrap().digest(),
            principal_id: ContractId::new("principal.alice").unwrap(),
            signer_key_id: ContractId::new(format!("ed25519.{}", "11".repeat(32))).unwrap(),
        }];
        VerifiedSuccessorRegistryActivationRequest {
            canonical_statement: encode_canonical(&statement).unwrap(),
            canonical_approval_set: encode_canonical(&approval_set).unwrap(),
            statement,
            approval_set,
            test_result,
            eligible_approvals,
            required_v1_threshold: 1,
            applied_v1_separation_of_duty:
                GenesisTransitionSeparationOfDutyV1::IndependentApprovalFromPackageAuthor,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn canonical_artifacts_and_all_literal_pins_are_frozen() {
        for (fixture, expected_raw_sha256) in [
            (TARGET_PACKAGE_FIXTURE, TARGET_PACKAGE_RAW_SHA256),
            (BRIDGE_FIXTURE, BRIDGE_RAW_SHA256),
            (TEST_RESULT_FIXTURE, TEST_RESULT_RAW_SHA256),
            (ACTIVATION_STATEMENT_FIXTURE, STATEMENT_RAW_SHA256),
            (ACTIVATION_APPROVAL_SET_FIXTURE, APPROVAL_SET_RAW_SHA256),
            (ACTIVATION_RECEIPT_FIXTURE, RECEIPT_RAW_SHA256),
            (ACTIVATED_HEAD_FIXTURE, ACTIVATED_HEAD_RAW_SHA256),
            (ACTIVATION_EVENT_FIXTURE, EVENT_RAW_SHA256),
            (POSITIVE_VECTORS_FIXTURE, POSITIVE_VECTORS_RAW_SHA256),
            (NEGATIVE_VECTORS_FIXTURE, NEGATIVE_VECTORS_RAW_SHA256),
            (VECTOR_SUITE_FIXTURE, VECTOR_SUITE_RAW_SHA256),
        ] {
            assert_eq!(raw_sha256(fixture).to_string(), expected_raw_sha256);
            require_canonical(record(fixture)).unwrap();
        }

        let positive = positive_cases();
        let negative = negative_cases();
        positive.validate(SuccessorActivationCaseOutcomeV1::Accept);
        negative.validate(SuccessorActivationCaseOutcomeV1::Reject);
        assert_eq!(
            encode_canonical(&positive).unwrap(),
            record(POSITIVE_VECTORS_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&negative).unwrap(),
            record(NEGATIVE_VECTORS_FIXTURE)
        );

        let graph = real_artifact_graph();
        assert_eq!(
            graph.request.test_result().canonical_bytes(),
            record(TEST_RESULT_FIXTURE)
        );
        assert_eq!(
            graph.request.canonical_statement(),
            record(ACTIVATION_STATEMENT_FIXTURE)
        );
        assert_eq!(
            graph.request.canonical_approval_set(),
            record(ACTIVATION_APPROVAL_SET_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&graph.receipt).unwrap(),
            record(ACTIVATION_RECEIPT_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&graph.activated_head).unwrap(),
            record(ACTIVATED_HEAD_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&graph.event).unwrap(),
            record(ACTIVATION_EVENT_FIXTURE)
        );

        let records = canonical_artifact_records(
            &graph,
            record(POSITIVE_VECTORS_FIXTURE),
            record(NEGATIVE_VECTORS_FIXTURE),
        );
        let suite = vector_suite(&graph, &positive, &negative, &records);
        assert_eq!(
            encode_canonical(&suite).unwrap(),
            record(VECTOR_SUITE_FIXTURE)
        );
        assert!(
            suite
                .artifact_pins
                .windows(2)
                .all(|pair| pair[0].path < pair[1].path)
        );
        assert!(
            suite
                .external_artifact_pins
                .windows(2)
                .all(|pair| pair[0].path < pair[1].path)
        );

        assert_eq!(
            graph.request.statement().target_package_digest.to_string(),
            TARGET_PACKAGE_DIGEST
        );
        assert_eq!(
            graph
                .request
                .statement()
                .target_activation_policy
                .entry_digest
                .to_string(),
            TARGET_ACTIVATION_POLICY_DIGEST
        );
        assert_eq!(
            graph
                .request
                .statement()
                .genesis_successor_key_bridge_digest
                .to_string(),
            BRIDGE_DIGEST
        );
        assert_eq!(
            graph.request.test_result().result_digest().to_string(),
            TEST_RESULT_DIGEST
        );
        assert_eq!(
            graph
                .request
                .statement()
                .statement_id()
                .unwrap()
                .to_string(),
            STATEMENT_ID
        );
        let approval_ids = graph
            .request
            .approval_set()
            .approvals
            .iter()
            .map(|approval| approval.approval_id().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(approval_ids, [ALICE_APPROVAL_ID, BOB_APPROVAL_ID]);
        assert_eq!(
            graph.receipt.activation_id().unwrap().to_string(),
            ACTIVATION_ID
        );
        assert_eq!(
            graph.event.accepted_event_id().unwrap().to_string(),
            ACCEPTED_EVENT_ID
        );
        assert_eq!(
            graph
                .event
                .consistency_partition_key()
                .unwrap()
                .key_digest
                .to_string(),
            CONSISTENCY_KEY_DIGEST
        );
        assert_eq!(
            manifest_digest(&positive).to_string(),
            POSITIVE_CASES_DIGEST
        );
        assert_eq!(
            manifest_digest(&negative).to_string(),
            NEGATIVE_CASES_DIGEST
        );
        assert_eq!(
            domain_separated_digest(
                DigestDomain::TestVectorManifest,
                record(VECTOR_SUITE_FIXTURE),
            )
            .to_string(),
            VECTOR_SUITE_DIGEST
        );
    }

    #[test]
    fn frozen_artifacts_reverify_without_granting_durable_authority() {
        let target = real_target();
        let bridge = real_bridge();
        let result: RegistryTestResultV1 = decode_strict(record(TEST_RESULT_FIXTURE)).unwrap();
        assert_eq!(
            result.package_digest,
            expected_digest(TARGET_PACKAGE_DIGEST)
        );
        assert_eq!(
            result.positive_vector_suite_digest,
            expected_digest(TARGET_POSITIVE_VECTOR_ROOT)
        );
        assert_eq!(
            result.negative_vector_suite_digest,
            expected_digest(TARGET_NEGATIVE_VECTOR_ROOT)
        );
        assert_eq!(
            result.executed_vector_manifest_digest,
            expected_digest(EXECUTED_VECTOR_MANIFEST_DIGEST)
        );
        assert_eq!(
            result.runner_artifact_digest,
            expected_digest(RUNNER_ARTIFACT_DIGEST)
        );
        assert_eq!(
            result.runner_configuration_digest,
            expected_digest(RUNNER_CONFIGURATION_DIGEST)
        );
        let runner_pin = SuccessorRegistryTestRunnerPin::from_trusted_config(
            expected_digest(RUNNER_ARTIFACT_DIGEST),
            expected_digest(RUNNER_CONFIGURATION_DIGEST),
            RegistryTestResultDigest::from_digest(expected_digest(TEST_RESULT_DIGEST)),
        );
        let verified_result =
            verify_successor_registry_test_result(record(TEST_RESULT_FIXTURE), runner_pin, &target)
                .unwrap();
        let statement: SuccessorRegistryActivationStatementV1 =
            decode_strict(record(ACTIVATION_STATEMENT_FIXTURE)).unwrap();
        let principal_binding = real_principal_binding(&statement);
        let request = verify_successor_registry_activation(
            record(ACTIVATION_STATEMENT_FIXTURE),
            record(ACTIVATION_APPROVAL_SET_FIXTURE),
            &target,
            &verified_result,
            &bridge,
            &principal_binding,
        )
        .unwrap();

        let receipt: SuccessorRegistryActivationReceiptV1 =
            decode_strict(record(ACTIVATION_RECEIPT_FIXTURE)).unwrap();
        receipt.validate_against(&request).unwrap();
        let activated_head: RegistryHeadBindingV1 =
            decode_strict(record(ACTIVATED_HEAD_FIXTURE)).unwrap();
        assert_eq!(
            activated_head,
            request.resulting_registry_head(&receipt).unwrap()
        );
        let event: SuccessorRegistryActivatedEventV1 =
            decode_strict(record(ACTIVATION_EVENT_FIXTURE)).unwrap();
        event.validate_against(&request, &receipt).unwrap();

        let positive: SuccessorActivationCaseManifestV1 =
            decode_strict(record(POSITIVE_VECTORS_FIXTURE)).unwrap();
        let negative: SuccessorActivationCaseManifestV1 =
            decode_strict(record(NEGATIVE_VECTORS_FIXTURE)).unwrap();
        positive.validate(SuccessorActivationCaseOutcomeV1::Accept);
        negative.validate(SuccessorActivationCaseOutcomeV1::Reject);
        let suite: SuccessorActivationVectorSuiteV1 =
            decode_strict(record(VECTOR_SUITE_FIXTURE)).unwrap();
        assert_eq!(suite.fixture_authority, FIXTURE_AUTHORITY);
        assert_eq!(suite.target_package_digest, target.package_digest());
        assert_eq!(
            suite.predecessor_head,
            bridge.bridge().genesis_registry_head
        );
        assert_eq!(suite.activated_head, activated_head);
        assert_eq!(suite.test_result_digest, verified_result.result_digest());
        assert_eq!(suite.statement_id, statement.statement_id().unwrap());
        assert_eq!(suite.activation_id, receipt.activation_id().unwrap());
        assert_eq!(suite.accepted_event_id, event.accepted_event_id().unwrap());
        assert_ne!(
            verified_result.result().positive_vector_suite_digest,
            suite.positive_cases_digest
        );
        assert_ne!(
            verified_result.result().negative_vector_suite_digest,
            suite.negative_cases_digest
        );
    }

    #[test]
    fn statement_closes_full_predecessor_target_bridge_and_generation() {
        let valid = statement();
        valid.validate_shape().unwrap();

        let mut stale_activation = valid.clone();
        stale_activation
            .expected_predecessor_head
            .head
            .activation_id = digest(22);
        assert_ne!(
            stale_activation.statement_id().unwrap(),
            valid.statement_id().unwrap()
        );

        let mut wrong_generation = valid.clone();
        wrong_generation.to_generation = 2;
        assert!(wrong_generation.validate_shape().is_err());

        let mut closed_predecessor = valid.clone();
        closed_predecessor.expected_predecessor_head.effective_until =
            Some(timestamp("2026-08-15T04:05:00.000000000Z"));
        assert!(closed_predecessor.validate_shape().is_err());

        let mut wrong_current_policy = valid.clone();
        wrong_current_policy
            .current_v1_activation_policy
            .entry_digest = digest(23);
        assert!(wrong_current_policy.validate_shape().is_err());

        let mut same_package = valid.clone();
        same_package.target_package_digest =
            same_package.expected_predecessor_head.head.package_digest;
        assert!(same_package.validate_shape().is_err());

        let mut scheduled_expiry = valid;
        scheduled_expiry.effective_until = Some(timestamp("2026-08-16T04:10:00.000000000Z"));
        assert!(scheduled_expiry.validate_shape().is_err());
    }

    #[test]
    fn successor_test_result_requires_database_round_trip_precision() {
        let mut result = test_result().result;
        result.completed_at = timestamp("2026-08-15T04:09:00.000000001Z");
        assert!(validate_successor_test_result_shape(&result).is_err());
    }

    #[test]
    fn frozen_target_bridge_and_fresh_signatures_close_end_to_end() {
        let request = real_verified_request();
        assert_eq!(
            request.statement().target_package_digest,
            real_target().package_digest()
        );
        assert_eq!(request.required_v1_threshold(), 2);
        assert_eq!(request.eligible_approvals().len(), 2);
        assert_eq!(
            request.applied_v1_separation_of_duty(),
            GenesisTransitionSeparationOfDutyV1::IndependentApprovalFromPackageAuthor
        );

        let receipt = request
            .receipt_at(
                &real_predecessor_accepted_at(),
                real_successor_accepted_at(),
            )
            .unwrap();
        let head = request.resulting_registry_head(&receipt).unwrap();
        let event = SuccessorRegistryActivatedEventV1::from_verified(&request, &receipt).unwrap();
        assert_eq!(head.head.package_digest, real_target().package_digest());
        assert_eq!(event.activated_head, head);
        assert_eq!(
            event.predecessor_head,
            request.statement().expected_predecessor_head
        );
    }

    #[test]
    fn exact_predecessor_target_policy_bridge_and_result_pins_fail_closed() {
        assert!(
            verify_tampered_real_statement(|statement| {
                statement.expected_predecessor_head.head.activation_id = digest(0xd1);
            })
            .is_err()
        );
        assert!(
            verify_tampered_real_statement(|statement| {
                let tampered = digest(0xd2);
                statement
                    .expected_predecessor_head
                    .head
                    .activation_policy_digest = tampered;
                statement.current_v1_activation_policy.entry_digest = tampered;
            })
            .is_err()
        );
        assert!(
            verify_tampered_real_statement(|statement| {
                statement.target_package_digest = digest(0xd3);
            })
            .is_err()
        );
        assert!(
            verify_tampered_real_statement(|statement| {
                statement.target_activation_policy.entry_digest = digest(0xd4);
            })
            .is_err()
        );
        assert!(
            verify_tampered_real_statement(|statement| {
                statement.genesis_successor_key_bridge_digest =
                    GenesisSuccessorKeyBridgeDigest::from_digest(digest(0xd5));
            })
            .is_err()
        );
        assert!(
            verify_tampered_real_statement(|statement| {
                statement.test_vector_result_digest =
                    RegistryTestResultDigest::from_digest(digest(0xd6));
            })
            .is_err()
        );
    }

    #[test]
    fn test_result_time_runner_and_principal_tampering_fail_closed() {
        let target = real_target();
        let verified_result = real_test_result(&target);
        let mut tampered_result = verified_result.result().clone();
        tampered_result.runner_configuration_digest = digest(0xe1);
        let original_pin = SuccessorRegistryTestRunnerPin::from_trusted_config(
            verified_result.result().runner_artifact_digest,
            verified_result.result().runner_configuration_digest,
            verified_result.result_digest(),
        );
        assert!(
            verify_successor_registry_test_result(
                &encode_canonical(&tampered_result).unwrap(),
                original_pin,
                &target,
            )
            .is_err()
        );

        assert!(
            verify_tampered_real_statement(|statement| {
                statement.effective_from = timestamp("2026-08-15T04:08:59.999999000Z");
            })
            .is_err()
        );
        assert!(
            verify_tampered_real_statement(|statement| {
                statement.effective_from = timestamp("2026-08-15T04:10:00.000000001Z");
            })
            .is_err()
        );

        let bridge = real_bridge();
        let result = real_test_result(&target);
        let statement = real_statement(&target, &bridge, &result);
        let approvals = real_approval_set(&statement);
        let wrong_binding = SuccessorActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.other_proposer").unwrap(),
            statement.package_author_principal_id.clone(),
        );
        assert!(
            verify_successor_registry_activation(
                &encode_canonical(&statement).unwrap(),
                &encode_canonical(&approvals).unwrap(),
                &target,
                &result,
                &bridge,
                &wrong_binding,
            )
            .is_err()
        );
    }

    #[test]
    fn signer_threshold_order_and_signature_tampering_fail_closed() {
        let target = real_target();
        let bridge = real_bridge();
        let result = real_test_result(&target);
        let statement = real_statement(&target, &bridge, &result);
        let statement_bytes = encode_canonical(&statement).unwrap();
        let binding = real_principal_binding(&statement);
        let statement_id = statement.statement_id().unwrap();

        let insufficient = SuccessorRegistryActivationApprovalSetV1 {
            schema_version: SUCCESSOR_ACTIVATION_SCHEMA_VERSION,
            statement_id,
            approvals: vec![signed_approval(statement_id, "principal.alice", [1; 32])],
        };
        assert!(
            verify_successor_registry_activation(
                &statement_bytes,
                &encode_canonical(&insufficient).unwrap(),
                &target,
                &result,
                &bridge,
                &binding,
            )
            .is_err()
        );
        assert!(
            bridge
                .validate_first_successor_approval_principal_set(
                    &case_id("principal.alice"),
                    &[case_id("principal.alice")],
                )
                .is_err()
        );

        let unknown = SuccessorRegistryActivationApprovalSetV1 {
            schema_version: SUCCESSOR_ACTIVATION_SCHEMA_VERSION,
            statement_id,
            approvals: vec![signed_approval(statement_id, "principal.mallory", [3; 32])],
        };
        assert!(
            verify_successor_registry_activation(
                &statement_bytes,
                &encode_canonical(&unknown).unwrap(),
                &target,
                &result,
                &bridge,
                &binding,
            )
            .is_err()
        );

        let mut bad_signature = real_approval_set(&statement);
        bad_signature.approvals[0].signature = FixedHex64::from_bytes([9; 64]);
        assert!(
            verify_successor_registry_activation(
                &statement_bytes,
                &encode_canonical(&bad_signature).unwrap(),
                &target,
                &result,
                &bridge,
                &binding,
            )
            .is_err()
        );

        let mut reversed = real_approval_set(&statement);
        reversed.approvals.reverse();
        assert!(
            verify_successor_registry_activation(
                &statement_bytes,
                &encode_canonical(&reversed).unwrap(),
                &target,
                &result,
                &bridge,
                &binding,
            )
            .is_err()
        );
    }

    #[test]
    fn successor_statement_and_approval_signature_domains_reject_genesis_replay() {
        let statement = statement();
        let statement_bytes = encode_canonical(&statement).unwrap();
        assert_ne!(
            DigestDomain::RegistrySuccessorActivationStatementV1.prefix(),
            DigestDomain::RegistryActivationStatement.prefix()
        );
        assert_ne!(
            DigestDomain::RegistrySuccessorActivationApprovalV1.prefix(),
            DigestDomain::RegistryActivationApproval.prefix()
        );
        assert_ne!(
            DigestDomain::RegistrySuccessorActivationReceiptV1.prefix(),
            DigestDomain::RegistryActivationReceipt.prefix()
        );
        assert_ne!(
            statement.statement_id().unwrap().digest(),
            domain_separated_digest(DigestDomain::RegistryActivationStatement, &statement_bytes)
        );
        assert_ne!(
            SUCCESSOR_APPROVAL_SIGNATURE_PREFIX,
            GENESIS_APPROVAL_SIGNATURE_PREFIX
        );

        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
        let statement_id = statement.statement_id().unwrap();
        let mut genesis_message = Vec::from(GENESIS_APPROVAL_SIGNATURE_PREFIX);
        genesis_message.extend_from_slice(statement_id.digest().as_bytes());
        let replayed_signature = key_pair.sign(&genesis_message);
        assert!(
            signature::UnparsedPublicKey::new(&signature::ED25519, key_pair.public_key().as_ref())
                .verify(
                    &successor_approval_signature_message(statement_id),
                    replayed_signature.as_ref(),
                )
                .is_err()
        );

        let successor_approval = approval(statement_id, "principal.alice", 42);
        let approval_bytes = encode_canonical(&successor_approval).unwrap();
        assert_ne!(
            successor_approval.approval_id().unwrap().digest(),
            domain_separated_digest(DigestDomain::RegistryActivationApproval, &approval_bytes)
        );

        let request = verified_request();
        let receipt = request
            .receipt_at(
                &timestamp("2026-08-15T04:05:00.000000000Z"),
                timestamp("2026-08-15T04:10:00.000000000Z"),
            )
            .unwrap();
        let receipt_bytes = encode_canonical(&receipt).unwrap();
        assert_ne!(
            receipt.activation_id().unwrap().digest(),
            domain_separated_digest(DigestDomain::RegistryActivationReceipt, &receipt_bytes)
        );
    }

    #[test]
    fn approval_set_is_principal_sorted_and_statement_exact() {
        let statement_id = statement().statement_id().unwrap();
        let valid = SuccessorRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id,
            approvals: vec![
                approval(statement_id, "principal.alice", 1),
                approval(statement_id, "principal.bob", 2),
            ],
        };
        valid.validate_shape().unwrap();

        let mut reversed = valid.clone();
        reversed.approvals.swap(0, 1);
        assert!(reversed.validate_shape().is_err());

        let mut duplicate = valid.clone();
        duplicate.approvals[1].signer_principal_id =
            duplicate.approvals[0].signer_principal_id.clone();
        assert!(duplicate.validate_shape().is_err());

        let mut wrong_statement = valid;
        wrong_statement.approvals[0].statement_id =
            SuccessorRegistryActivationStatementId::from_digest(digest(24));
        assert!(wrong_statement.validate_shape().is_err());
    }

    #[test]
    fn receipt_event_and_head_are_server_time_bounded_and_share_stream() {
        let request = verified_request();
        let predecessor_accepted_at = timestamp("2026-08-15T04:05:00.000000000Z");
        let accepted_at = timestamp("2026-08-15T04:10:00.000000000Z");
        let receipt = request
            .receipt_at(&predecessor_accepted_at, accepted_at)
            .unwrap();
        let head = request.resulting_registry_head(&receipt).unwrap();
        let event = SuccessorRegistryActivatedEventV1::from_verified(&request, &receipt).unwrap();

        assert_eq!(head, event.activated_head);
        assert_eq!(
            event.consistency_partition_key().unwrap(),
            registry_activation_consistency_partition_key(&request.statement.scope).unwrap()
        );
        assert_ne!(
            event.accepted_event_id().unwrap().digest(),
            Sha256Digest::ZERO
        );

        assert!(
            request
                .receipt_at(
                    &predecessor_accepted_at,
                    timestamp("2026-08-15T04:09:59.999999000Z"),
                )
                .is_err()
        );
        assert!(
            request
                .receipt_at(
                    &timestamp("2026-08-15T04:10:00.000001000Z"),
                    timestamp("2026-08-15T04:10:00.000001000Z"),
                )
                .is_err()
        );
        assert!(
            request
                .receipt_at(
                    &predecessor_accepted_at,
                    timestamp("2026-08-15T04:10:00.000000001Z"),
                )
                .is_err()
        );
    }

    #[test]
    fn structural_receipt_tampering_cannot_validate_against_opaque_request() {
        let request = verified_request();
        let mut receipt = request
            .receipt_at(
                &timestamp("2026-08-15T04:05:00.000000000Z"),
                timestamp("2026-08-15T04:10:00.000000000Z"),
            )
            .unwrap();
        receipt.target_activation_policy.entry_digest = digest(25);
        assert!(receipt.validate_against(&request).is_err());

        let mut false_separation_of_duty = request
            .receipt_at(
                &timestamp("2026-08-15T04:05:00.000000000Z"),
                timestamp("2026-08-15T04:10:00.000000000Z"),
            )
            .unwrap();
        false_separation_of_duty.separation_of_duty_satisfied = false;
        assert!(false_separation_of_duty.validate_against(&request).is_err());
    }

    #[test]
    fn target_policy_keys_are_future_authority_not_current_bridge_authority() {
        let target = real_target();
        let bridge = real_bridge();
        let target_policy = target.activation_policy().policy();
        let approving_principals = ["principal.alice", "principal.bob"]
            .into_iter()
            .map(case_id)
            .collect::<Vec<_>>();
        assert_eq!(target_policy.eligible_signers, bridge.bridge().key_map);
        assert_eq!(target_policy.approval_threshold, 2);
        bridge
            .validate_first_successor_approval_principal_set(
                &case_id("principal.author"),
                &approving_principals,
            )
            .unwrap();
        target_policy
            .validate_approval_principal_set(
                &case_id("principal.author"),
                &case_id("principal.proposer"),
                &approving_principals,
            )
            .unwrap();

        // The active-v1 bridge has no proposer exclusion. The installed v2
        // policy adds that stronger rule only for later generations.
        bridge
            .validate_first_successor_approval_principal_set(
                &case_id("principal.author"),
                &approving_principals,
            )
            .unwrap();
        assert!(
            target_policy
                .validate_approval_principal_set(
                    &case_id("principal.author"),
                    &case_id("principal.alice"),
                    &approving_principals,
                )
                .is_err()
        );
    }

    fn write_artifact(output: &Path, name: &str, canonical: &[u8]) {
        require_canonical(canonical).unwrap();
        fs::write(output.join(name), framed_record(canonical)).unwrap();
    }

    #[test]
    #[ignore = "maintainer-only canonical successor-activation fixture regeneration"]
    #[allow(clippy::too_many_lines)]
    fn regenerate_successor_activation_artifacts() {
        let output = env::var("SUCCESSOR_ACTIVATION_VECTOR_OUTPUT")
            .expect("set SUCCESSOR_ACTIVATION_VECTOR_OUTPUT to an explicit output directory");
        let output = Path::new(&output);
        fs::create_dir_all(output).unwrap();

        let positive = positive_cases();
        let negative = negative_cases();
        positive.validate(SuccessorActivationCaseOutcomeV1::Accept);
        negative.validate(SuccessorActivationCaseOutcomeV1::Reject);
        let positive_bytes = encode_canonical(&positive).unwrap();
        let negative_bytes = encode_canonical(&negative).unwrap();

        let graph = real_artifact_graph();
        let records = canonical_artifact_records(&graph, &positive_bytes, &negative_bytes);
        let suite = vector_suite(&graph, &positive, &negative, &records);
        let suite_bytes = encode_canonical(&suite).unwrap();

        // The target conformance result closes only the already-frozen target
        // package roots. It cannot ratify the later activation case manifests.
        assert_ne!(
            graph
                .request
                .test_result()
                .result()
                .positive_vector_suite_digest,
            suite.positive_cases_digest
        );
        assert_ne!(
            graph
                .request
                .test_result()
                .result()
                .negative_vector_suite_digest,
            suite.negative_cases_digest
        );

        for (name, bytes) in &records {
            write_artifact(output, name, bytes);
        }
        write_artifact(output, "vector-suite.jsonl", &suite_bytes);

        let approvals = graph
            .request
            .approval_set()
            .approvals
            .iter()
            .map(|approval| approval.approval_id().unwrap().to_string())
            .collect::<Vec<_>>();
        println!(
            "test_result_digest={}",
            graph.request.test_result().result_digest()
        );
        println!(
            "statement_id={}",
            graph.request.statement().statement_id().unwrap()
        );
        println!("approval_ids={}", approvals.join(","));
        println!("activation_id={}", graph.receipt.activation_id().unwrap());
        println!(
            "accepted_event_id={}",
            graph.event.accepted_event_id().unwrap()
        );
        println!(
            "consistency_key_digest={}",
            graph.event.consistency_partition_key().unwrap().key_digest
        );
        println!("positive_cases_digest={}", suite.positive_cases_digest);
        println!("negative_cases_digest={}", suite.negative_cases_digest);
        println!(
            "vector_suite_digest={}",
            domain_separated_digest(DigestDomain::TestVectorManifest, &suite_bytes)
        );
    }
}
