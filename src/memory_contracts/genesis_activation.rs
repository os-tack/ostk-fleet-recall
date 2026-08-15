//! Genesis-only registry activation contracts.
//!
//! Stage 2 proves that one out-of-band-pinned bootstrap artifact is durably
//! accepted. It deliberately does not activate that artifact's registry
//! package. This module defines the separate, freshly signed ceremony that may
//! create the first [`RegistryHeadV1`]. It defines no successor activation and
//! has no database, clock, transport, or request-routing dependency.

use std::{collections::BTreeSet, fmt};

use ring::signature;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    ContractError, ContractResult,
    bootstrap::{
        BootstrapReceiptDigest, BootstrapStatementId, ConsistencyPartitionKeyV1, EpochId,
        VerifiedBootstrapReceipt,
    },
    canonical::{decode_strict, encode_canonical, require_canonical},
    common::{
        AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, FixedHex64, ProfileReferenceV1,
    },
    control::GenesisBootstrapAppendV1,
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    evidence::AcceptedEventId,
    genesis::SemanticallyClosedGenesisPackage,
    registry::{EligibleApprovalV1, RegistryEntryKind, RegistryHeadV1},
};

const GENESIS_ACTIVATION_SCHEMA_VERSION: u32 = 1;
const MAX_ACTIVATION_APPROVALS: usize = 64;
const GENESIS_ACTIVATION_EVENT_KIND: &str = "registry.genesis.activated";
const REGISTRY_ACTIVATION_CONSISTENCY_FAMILY: &str = "registry.activation";
const ACTIVATION_APPROVAL_SIGNATURE_PREFIX: &[u8] =
    b"ostk-registry-activation-approval-signature-v1\0";

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

digest_newtype!(GenesisRegistryActivationStatementId);
digest_newtype!(GenesisRegistryActivationId);
digest_newtype!(GenesisRegistryActivationApprovalId);
digest_newtype!(RegistryTestResultDigest);

/// Exact immutable Stage-2 predecessor expected by the first activation.
///
/// Physical append position is deliberately absent. The accepted bootstrap
/// event ID commits to the same verified receipt, package, epoch, profile, and
/// semantic scope without making topology part of activation identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisRegistryAnchorV1 {
    pub bootstrap_statement_id: BootstrapStatementId,
    pub bootstrap_receipt_digest: BootstrapReceiptDigest,
    pub bootstrap_event_id: AcceptedEventId,
    pub genesis_epoch_id: EpochId,
    pub genesis_package_digest: Sha256Digest,
    pub bootstrap_signer_policy_digest: Sha256Digest,
}

impl GenesisRegistryAnchorV1 {
    /// Derive the anchor only from already verified bootstrap authority.
    pub fn from_verified(
        bootstrap: &VerifiedBootstrapReceipt,
        package: &SemanticallyClosedGenesisPackage,
    ) -> ContractResult<Self> {
        let append = GenesisBootstrapAppendV1::from_verified(bootstrap, package)?;
        let statement = &bootstrap.receipt().statement;
        Ok(Self {
            bootstrap_statement_id: bootstrap.statement_id(),
            bootstrap_receipt_digest: bootstrap.receipt_digest(),
            bootstrap_event_id: append.accepted_event_id,
            genesis_epoch_id: bootstrap.epoch_id(),
            genesis_package_digest: package.package_digest(),
            bootstrap_signer_policy_digest: statement.signer_policy_digest,
        })
    }
}

/// Outcome asserted by a registry conformance runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryTestOutcomeV1 {
    Passed,
}

/// Canonical result of running the package-bound positive and negative suites.
///
/// This wire value grants no authority on its own. It becomes usable only as a
/// [`VerifiedRegistryTestResult`] after exact package/profile/vector bindings
/// and a deployment-trusted runner pin have been checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryTestResultV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub package_digest: Sha256Digest,
    pub positive_vector_suite_digest: Sha256Digest,
    pub negative_vector_suite_digest: Sha256Digest,
    pub executed_vector_manifest_digest: Sha256Digest,
    pub runner_artifact_digest: Sha256Digest,
    pub runner_configuration_digest: Sha256Digest,
    pub passed_case_count: u32,
    pub failed_case_count: u32,
    pub outcome: RegistryTestOutcomeV1,
    pub completed_at: CanonicalTimestamp,
}

impl RegistryTestResultV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        if self.schema_version != GENESIS_ACTIVATION_SCHEMA_VERSION
            || self.passed_case_count == 0
            || self.failed_case_count != 0
            || self.outcome != RegistryTestOutcomeV1::Passed
        {
            return Err(ContractError::Schema("invalid registry test result".into()));
        }
        Ok(())
    }

    fn result_digest(&self) -> ContractResult<RegistryTestResultDigest> {
        self.validate_shape()?;
        Ok(RegistryTestResultDigest::from_digest(
            domain_separated_digest(DigestDomain::RegistryTestResult, &encode_canonical(self)?),
        ))
    }
}

/// Out-of-band identity of the conformance runner admitted by deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryTestRunnerPin {
    runner_artifact: Sha256Digest,
    runner_configuration: Sha256Digest,
    expected_result: RegistryTestResultDigest,
}

impl RegistryTestRunnerPin {
    pub const fn from_trusted_config(
        artifact_digest: Sha256Digest,
        configuration_digest: Sha256Digest,
        result_digest: RegistryTestResultDigest,
    ) -> Self {
        Self {
            runner_artifact: artifact_digest,
            runner_configuration: configuration_digest,
            expected_result: result_digest,
        }
    }
}

/// Typestate proving one canonical, passing result belongs to the exact package
/// and to the deployment-pinned runner.
#[derive(Debug, Clone)]
pub struct VerifiedRegistryTestResult {
    result: RegistryTestResultV1,
    canonical_bytes: Vec<u8>,
    result_digest: RegistryTestResultDigest,
}

impl VerifiedRegistryTestResult {
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

/// Verify a canonical conformance result against an exact package and a runner
/// identity supplied only by trusted configuration.
pub fn verify_registry_test_result(
    input: &[u8],
    runner_pin: RegistryTestRunnerPin,
    expected_profile: &ProfileReferenceV1,
    package: &SemanticallyClosedGenesisPackage,
) -> ContractResult<VerifiedRegistryTestResult> {
    require_canonical(input)?;
    let result: RegistryTestResultV1 = decode_strict(input)?;
    result.validate_shape()?;
    let registry = package.manifest_verified_package().package();
    let result_digest = result.result_digest()?;
    if &result.profile != expected_profile
        || &registry.profile != expected_profile
        || result.package_digest != package.package_digest()
        || result.positive_vector_suite_digest != registry.positive_vector_suite_digest
        || result.negative_vector_suite_digest != registry.negative_vector_suite_digest
        || result.executed_vector_manifest_digest != expected_profile.vector_manifest_digest
        || result.runner_artifact_digest != runner_pin.runner_artifact
        || result.runner_configuration_digest != runner_pin.runner_configuration
        || result_digest != runner_pin.expected_result
    {
        return Err(ContractError::BootstrapBindingMismatch);
    }
    let canonical_bytes = encode_canonical(&result)?;
    if canonical_bytes != input {
        return Err(ContractError::NotCanonical);
    }
    Ok(VerifiedRegistryTestResult {
        result,
        canonical_bytes,
        result_digest,
    })
}

/// Unsigned first-activation statement. It expects the exact immutable
/// bootstrap anchor rather than pretending an active registry head exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisRegistryActivationStatementV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub expected_anchor: GenesisRegistryAnchorV1,
    pub package_digest: Sha256Digest,
    pub resulting_activation_policy_digest: Sha256Digest,
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
    pub test_vector_result_digest: RegistryTestResultDigest,
    pub proposer_principal_id: ContractId,
    pub package_author_principal_id: ContractId,
}

impl GenesisRegistryActivationStatementV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        if self.schema_version != GENESIS_ACTIVATION_SCHEMA_VERSION
            || !self.effective_from.is_microsecond_aligned()
            || self
                .effective_until
                .as_ref()
                .is_some_and(|until| until <= &self.effective_from)
        {
            return Err(ContractError::Schema(
                "invalid genesis registry activation statement".into(),
            ));
        }
        Ok(())
    }

    pub fn statement_id(&self) -> ContractResult<GenesisRegistryActivationStatementId> {
        self.validate_shape()?;
        Ok(GenesisRegistryActivationStatementId::from_digest(
            domain_separated_digest(
                DigestDomain::RegistryActivationStatement,
                &encode_canonical(self)?,
            ),
        ))
    }
}

/// One fresh detached approval of the genesis-activation statement.
///
/// The signature message has a registry-activation-specific prefix. A valid
/// signature copied from the bootstrap receipt therefore fails closed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisRegistryActivationApprovalV1 {
    pub schema_version: u32,
    pub statement_id: GenesisRegistryActivationStatementId,
    pub signer_principal_id: ContractId,
    pub signature: FixedHex64,
}

impl GenesisRegistryActivationApprovalV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != GENESIS_ACTIVATION_SCHEMA_VERSION {
            return Err(ContractError::Schema(
                "invalid genesis registry activation approval".into(),
            ));
        }
        Ok(())
    }

    pub fn approval_id(&self) -> ContractResult<GenesisRegistryActivationApprovalId> {
        self.validate_shape()?;
        Ok(GenesisRegistryActivationApprovalId::from_digest(
            domain_separated_digest(
                DigestDomain::RegistryActivationApproval,
                &encode_canonical(self)?,
            ),
        ))
    }
}

/// Canonical set of detached approvals supplied to the activation ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisRegistryActivationApprovalSetV1 {
    pub schema_version: u32,
    pub statement_id: GenesisRegistryActivationStatementId,
    pub approvals: Vec<GenesisRegistryActivationApprovalV1>,
}

/// Deployment-bound principal identities for the private activation ceremony.
///
/// These values come from trusted operator configuration, never from the
/// statement being verified. Fresh approvals sign the same values, so an
/// author cannot evade separation of duty by naming a different payload
/// principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisActivationPrincipalBinding {
    proposer_principal_id: ContractId,
    package_author_principal_id: ContractId,
}

impl GenesisActivationPrincipalBinding {
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

impl GenesisRegistryActivationApprovalSetV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != GENESIS_ACTIVATION_SCHEMA_VERSION
            || self.approvals.is_empty()
            || self.approvals.len() > MAX_ACTIVATION_APPROVALS
            || !strictly_sorted(&self.approvals)
        {
            return Err(ContractError::Schema(
                "invalid genesis registry activation approval set".into(),
            ));
        }
        for approval in &self.approvals {
            approval.validate_shape()?;
            if approval.statement_id != self.statement_id {
                return Err(ContractError::SignatureVerification);
            }
        }
        Ok(())
    }
}

/// Cryptographically verified request for a first activation.
///
/// This typestate does not prove that Stage 2 was durably accepted and cannot
/// activate a registry by itself. The private repository must re-audit the
/// exact persisted bootstrap singleton and append chain in the same
/// `SERIALIZABLE` transaction that installs the first head.
#[derive(Debug, Clone)]
pub struct VerifiedGenesisRegistryActivationRequest {
    statement: GenesisRegistryActivationStatementV1,
    canonical_statement: Vec<u8>,
    approval_set: GenesisRegistryActivationApprovalSetV1,
    canonical_approval_set: Vec<u8>,
    test_result: VerifiedRegistryTestResult,
    eligible_approvals: Vec<EligibleApprovalV1>,
    required_threshold: u16,
}

impl VerifiedGenesisRegistryActivationRequest {
    pub const fn statement(&self) -> &GenesisRegistryActivationStatementV1 {
        &self.statement
    }

    pub fn canonical_statement(&self) -> &[u8] {
        &self.canonical_statement
    }

    pub const fn approval_set(&self) -> &GenesisRegistryActivationApprovalSetV1 {
        &self.approval_set
    }

    pub fn canonical_approval_set(&self) -> &[u8] {
        &self.canonical_approval_set
    }

    pub const fn test_result(&self) -> &VerifiedRegistryTestResult {
        &self.test_result
    }

    pub fn eligible_approvals(&self) -> &[EligibleApprovalV1] {
        &self.eligible_approvals
    }

    pub const fn required_threshold(&self) -> u16 {
        self.required_threshold
    }

    /// Materialize the server-derived receipt at the trusted acceptance time.
    /// The first seam rejects expiry and future-effective activation; the
    /// repository must additionally enforce that `effective_from` is not before
    /// the persisted bootstrap acceptance time.
    #[allow(dead_code)] // Stage 3 repository seam; not callable by external request code.
    pub(crate) fn receipt_at(
        &self,
        bootstrap_accepted_at: &CanonicalTimestamp,
        accepted_at: CanonicalTimestamp,
    ) -> ContractResult<GenesisRegistryActivationReceiptV1> {
        if self.statement.effective_until.is_some()
            || self.statement.effective_from < *bootstrap_accepted_at
            || self.statement.effective_from > accepted_at
        {
            return Err(ContractError::Schema(
                "genesis activation is outside the bootstrap and acceptance interval".into(),
            ));
        }
        let receipt = GenesisRegistryActivationReceiptV1 {
            schema_version: GENESIS_ACTIVATION_SCHEMA_VERSION,
            statement_id: self.statement.statement_id()?,
            expected_anchor: self.statement.expected_anchor.clone(),
            activated_package_digest: self.statement.package_digest,
            activated_policy_digest: self.statement.resulting_activation_policy_digest,
            eligible_approvals: self.eligible_approvals.clone(),
            required_threshold: self.required_threshold,
            separation_of_duty_satisfied: true,
            accepted_at,
        };
        receipt.validate_against(self)?;
        Ok(receipt)
    }

    /// Derive the first active head only after revalidating the server-derived
    /// receipt against this authority token.
    #[allow(dead_code)] // Stage 3 repository seam; not callable by external request code.
    pub(crate) fn registry_head(
        &self,
        receipt: &GenesisRegistryActivationReceiptV1,
    ) -> ContractResult<RegistryHeadV1> {
        receipt.validate_against(self)?;
        Ok(RegistryHeadV1 {
            activation_id: receipt.activation_id()?.digest(),
            package_digest: receipt.activated_package_digest,
            activation_policy_digest: receipt.activated_policy_digest,
        })
    }
}

/// Strictly verify a genesis-only registry activation request.
pub fn verify_genesis_registry_activation(
    canonical_statement: &[u8],
    canonical_approval_set: &[u8],
    bootstrap: &VerifiedBootstrapReceipt,
    package: &SemanticallyClosedGenesisPackage,
    test_result: &VerifiedRegistryTestResult,
    principal_binding: &GenesisActivationPrincipalBinding,
) -> ContractResult<VerifiedGenesisRegistryActivationRequest> {
    require_canonical(canonical_statement)?;
    let statement: GenesisRegistryActivationStatementV1 = decode_strict(canonical_statement)?;
    statement.validate_shape()?;
    if encode_canonical(&statement)? != canonical_statement {
        return Err(ContractError::NotCanonical);
    }

    let bootstrap_statement = &bootstrap.receipt().statement;
    let expected_anchor = GenesisRegistryAnchorV1::from_verified(bootstrap, package)?;
    let expected_policy_digest = genesis_activation_policy_digest(package)?;
    if statement.profile != bootstrap_statement.profile
        || statement.scope != bootstrap_statement.scope
        || statement.expected_anchor != expected_anchor
        || statement.package_digest != package.package_digest()
        || statement.resulting_activation_policy_digest != expected_policy_digest
        || statement.test_vector_result_digest != test_result.result_digest()
        || test_result.result().profile != statement.profile
        || test_result.result().package_digest != statement.package_digest
        || test_result.result().completed_at > statement.effective_from
        || statement.effective_until.is_some()
        || statement.proposer_principal_id != principal_binding.proposer_principal_id
        || statement.package_author_principal_id != principal_binding.package_author_principal_id
    {
        return Err(ContractError::BootstrapBindingMismatch);
    }

    require_canonical(canonical_approval_set)?;
    let approval_set: GenesisRegistryActivationApprovalSetV1 =
        decode_strict(canonical_approval_set)?;
    approval_set.validate_shape()?;
    if encode_canonical(&approval_set)? != canonical_approval_set {
        return Err(ContractError::NotCanonical);
    }
    let statement_id = statement.statement_id()?;
    if approval_set.statement_id != statement_id
        || approval_set.approvals.len() > bootstrap_statement.signer_policy.signers.len()
    {
        return Err(ContractError::SignatureVerification);
    }

    let signature_message = activation_approval_message(statement_id);
    let mut eligible_approvals = Vec::with_capacity(approval_set.approvals.len());
    let mut verified_principals = BTreeSet::new();
    for approval in &approval_set.approvals {
        let signer = bootstrap_statement
            .signer_policy
            .signers
            .iter()
            .find(|signer| signer.principal_id == approval.signer_principal_id)
            .ok_or(ContractError::SignatureVerification)?;
        signature::UnparsedPublicKey::new(&signature::ED25519, signer.public_key.as_bytes())
            .verify(&signature_message, approval.signature.as_bytes())
            .map_err(|_| ContractError::SignatureVerification)?;
        if !verified_principals.insert(&signer.principal_id) {
            return Err(ContractError::SignatureVerification);
        }
        eligible_approvals.push(EligibleApprovalV1 {
            attestation_id: approval.approval_id()?.digest(),
            principal_id: signer.principal_id.clone(),
            signer_key_id: signer_key_id(signer.public_key.as_bytes())?,
        });
    }
    let required_threshold = bootstrap_statement.signer_policy.threshold;
    if eligible_approvals.len() < usize::from(required_threshold) {
        return Err(ContractError::ApprovalThresholdNotMet);
    }
    if !separation_of_duty_satisfied(&eligible_approvals, &statement.package_author_principal_id) {
        return Err(ContractError::Schema(
            "genesis activation separation of duty was not satisfied".into(),
        ));
    }
    eligible_approvals.sort_unstable();

    Ok(VerifiedGenesisRegistryActivationRequest {
        statement,
        canonical_statement: canonical_statement.to_vec(),
        approval_set,
        canonical_approval_set: canonical_approval_set.to_vec(),
        test_result: test_result.clone(),
        eligible_approvals,
        required_threshold,
    })
}

/// Server-derived receipt for the first active registry head.
///
/// Structural validation alone grants no authority. Runtime code must obtain it
/// from [`VerifiedGenesisRegistryActivationRequest::receipt_at`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisRegistryActivationReceiptV1 {
    pub schema_version: u32,
    pub statement_id: GenesisRegistryActivationStatementId,
    pub expected_anchor: GenesisRegistryAnchorV1,
    pub activated_package_digest: Sha256Digest,
    pub activated_policy_digest: Sha256Digest,
    pub eligible_approvals: Vec<EligibleApprovalV1>,
    pub required_threshold: u16,
    pub separation_of_duty_satisfied: bool,
    pub accepted_at: CanonicalTimestamp,
}

impl GenesisRegistryActivationReceiptV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != GENESIS_ACTIVATION_SCHEMA_VERSION
            || self.required_threshold == 0
            || usize::from(self.required_threshold) > self.eligible_approvals.len()
            || self.eligible_approvals.len() > MAX_ACTIVATION_APPROVALS
            || !strictly_sorted(&self.eligible_approvals)
            || !approval_bindings_are_unique(&self.eligible_approvals)
            || !self.separation_of_duty_satisfied
        {
            return Err(ContractError::Schema(
                "invalid genesis registry activation receipt".into(),
            ));
        }
        Ok(())
    }

    pub fn activation_id(&self) -> ContractResult<GenesisRegistryActivationId> {
        self.validate_shape()?;
        Ok(GenesisRegistryActivationId::from_digest(
            domain_separated_digest(
                DigestDomain::RegistryActivationReceipt,
                &encode_canonical(self)?,
            ),
        ))
    }

    pub fn validate_against(
        &self,
        activation: &VerifiedGenesisRegistryActivationRequest,
    ) -> ContractResult<()> {
        self.validate_shape()?;
        let statement = activation.statement();
        if self.statement_id != statement.statement_id()?
            || self.expected_anchor != statement.expected_anchor
            || self.activated_package_digest != statement.package_digest
            || self.activated_policy_digest != statement.resulting_activation_policy_digest
            || self.eligible_approvals != activation.eligible_approvals
            || self.required_threshold != activation.required_threshold
            || self.accepted_at < statement.effective_from
        {
            return Err(ContractError::BootstrapBindingMismatch);
        }
        Ok(())
    }
}

/// Semantic control event announcing the first active registry head.
/// Append position is absent. Receipt time is not a direct field, but remains
/// transitively committed through `activation_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisRegistryActivatedEventV1 {
    pub schema_version: u32,
    pub event_kind: ContractId,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub activation_id: GenesisRegistryActivationId,
    pub statement_id: GenesisRegistryActivationStatementId,
    pub expected_anchor: GenesisRegistryAnchorV1,
    pub activated_package_digest: Sha256Digest,
    pub activated_policy_digest: Sha256Digest,
    pub test_vector_result_digest: RegistryTestResultDigest,
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
}

impl GenesisRegistryActivatedEventV1 {
    #[allow(dead_code)] // Stage 3 repository seam; not callable by external request code.
    pub(crate) fn from_verified(
        activation: &VerifiedGenesisRegistryActivationRequest,
        receipt: &GenesisRegistryActivationReceiptV1,
    ) -> ContractResult<Self> {
        receipt.validate_against(activation)?;
        let statement = activation.statement();
        let event = Self {
            schema_version: GENESIS_ACTIVATION_SCHEMA_VERSION,
            event_kind: ContractId::new(GENESIS_ACTIVATION_EVENT_KIND)?,
            profile: statement.profile.clone(),
            scope: statement.scope.clone(),
            activation_id: receipt.activation_id()?,
            statement_id: statement.statement_id()?,
            expected_anchor: statement.expected_anchor.clone(),
            activated_package_digest: statement.package_digest,
            activated_policy_digest: statement.resulting_activation_policy_digest,
            test_vector_result_digest: statement.test_vector_result_digest,
            effective_from: statement.effective_from.clone(),
            effective_until: statement.effective_until.clone(),
        };
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

    /// All registry-head transitions for one authenticated scope use one stable
    /// consistency key and therefore one epoch shard.
    pub fn consistency_partition_key(&self) -> ContractResult<ConsistencyPartitionKeyV1> {
        self.validate_shape()?;
        registry_activation_consistency_partition_key(&self.scope)
    }

    pub fn validate_against(
        &self,
        activation: &VerifiedGenesisRegistryActivationRequest,
        receipt: &GenesisRegistryActivationReceiptV1,
    ) -> ContractResult<()> {
        self.validate_shape()?;
        receipt.validate_against(activation)?;
        let expected = Self::from_parts(activation, receipt)?;
        if self != &expected {
            return Err(ContractError::BootstrapBindingMismatch);
        }
        Ok(())
    }

    fn from_parts(
        activation: &VerifiedGenesisRegistryActivationRequest,
        receipt: &GenesisRegistryActivationReceiptV1,
    ) -> ContractResult<Self> {
        let statement = activation.statement();
        Ok(Self {
            schema_version: GENESIS_ACTIVATION_SCHEMA_VERSION,
            event_kind: ContractId::new(GENESIS_ACTIVATION_EVENT_KIND)?,
            profile: statement.profile.clone(),
            scope: statement.scope.clone(),
            activation_id: receipt.activation_id()?,
            statement_id: statement.statement_id()?,
            expected_anchor: statement.expected_anchor.clone(),
            activated_package_digest: statement.package_digest,
            activated_policy_digest: statement.resulting_activation_policy_digest,
            test_vector_result_digest: statement.test_vector_result_digest,
            effective_from: statement.effective_from.clone(),
            effective_until: statement.effective_until.clone(),
        })
    }

    fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        if self.schema_version != GENESIS_ACTIVATION_SCHEMA_VERSION
            || self.event_kind.as_str() != GENESIS_ACTIVATION_EVENT_KIND
            || self.effective_until.is_some()
        {
            return Err(ContractError::Schema(
                "invalid genesis registry activation event".into(),
            ));
        }
        Ok(())
    }
}

/// One stable scope-local stream key shared by genesis and every future
/// registry transition. Successor implementations must call this helper rather
/// than reproduce the formula.
pub fn registry_activation_consistency_partition_key(
    scope: &AuthenticatedProjectScopeV1,
) -> ContractResult<ConsistencyPartitionKeyV1> {
    Ok(ConsistencyPartitionKeyV1 {
        family: ContractId::new(REGISTRY_ACTIVATION_CONSISTENCY_FAMILY)?,
        key_digest: domain_separated_digest(
            DigestDomain::RegistryActivationStream,
            &encode_canonical(scope)?,
        ),
    })
}

/// Exact digest of the singleton policy that will govern transitions after
/// genesis activation. It is metadata for the resulting head, never authority
/// for the genesis ceremony itself.
pub fn genesis_activation_policy_digest(
    package: &SemanticallyClosedGenesisPackage,
) -> ContractResult<Sha256Digest> {
    let mut matches = package
        .manifest_verified_package()
        .package()
        .entries
        .iter()
        .filter(|entry| entry.kind == RegistryEntryKind::ActivationPolicy);
    let entry = matches
        .next()
        .ok_or_else(|| ContractError::Schema("genesis activation policy is missing".into()))?;
    if matches.next().is_some() {
        return Err(ContractError::Schema(
            "genesis activation policy is not a singleton".into(),
        ));
    }
    entry.digest()
}

fn activation_approval_message(statement_id: GenesisRegistryActivationStatementId) -> Vec<u8> {
    let mut message = Vec::with_capacity(ACTIVATION_APPROVAL_SIGNATURE_PREFIX.len() + 32);
    message.extend_from_slice(ACTIVATION_APPROVAL_SIGNATURE_PREFIX);
    message.extend_from_slice(statement_id.digest().as_bytes());
    message
}

fn signer_key_id(public_key: &[u8; 32]) -> ContractResult<ContractId> {
    ContractId::new(format!("ed25519.{}", hex::encode(public_key)))
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn approval_bindings_are_unique(values: &[EligibleApprovalV1]) -> bool {
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

fn separation_of_duty_satisfied(
    approvals: &[EligibleApprovalV1],
    package_author_principal_id: &ContractId,
) -> bool {
    approvals
        .iter()
        .any(|approval| &approval.principal_id != package_author_principal_id)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ring::signature::Ed25519KeyPair;

    use super::*;
    use crate::memory_contracts::{
        bootstrap::{
            BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1,
            verify_pinned_bootstrap,
        },
        canonical::{decode_strict, encode_canonical},
        registry::ManifestVerifiedRegistryPackage,
    };

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GenesisActivationVectorSuiteV1 {
        accepted_event_id: AcceptedEventId,
        activation_id: GenesisRegistryActivationId,
        activation_policy_digest: Sha256Digest,
        approval_set_path: String,
        consistency_key_digest: Sha256Digest,
        event_path: String,
        fixture_authority: String,
        negative_cases: Vec<String>,
        receipt_path: String,
        schema_version: u32,
        statement_id: GenesisRegistryActivationStatementId,
        statement_path: String,
        test_result_digest: RegistryTestResultDigest,
        test_result_path: String,
    }

    const PROFILE_DIGEST: &str = "cf22991a86bfc560556c7d04efa4ee6b7b1ee0f49c919b257ea7b4f30f8e4a29";
    const VECTOR_MANIFEST_DIGEST: &str =
        "f984f62866fc769df3a5617a2247e3ade694827c1de69e615a7bda68858b4174";
    const BOOTSTRAP_RECEIPT_DIGEST: &str =
        "084ee06ea7ebf3b1d592d6e5843584485144c0ee5720fcc2124a61a7fcde48f0";
    const GENESIS_PACKAGE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");
    const BOOTSTRAP_RECEIPT: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");
    const TEST_RESULT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v1/genesis-activation/registry-test-result.jsonl"
    );
    const ACTIVATION_STATEMENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v1/genesis-activation/activation-statement.jsonl"
    );
    const ACTIVATION_APPROVAL_SET_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v1/genesis-activation/activation-approval-set.jsonl"
    );
    const ACTIVATION_RECEIPT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v1/genesis-activation/activation-receipt.jsonl"
    );
    const ACTIVATION_EVENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v1/genesis-activation/activation-event.jsonl"
    );
    const ACTIVATION_VECTOR_SUITE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v1/genesis-activation/vector-suite.jsonl");

    fn record(artifact: &'static [u8]) -> &'static [u8] {
        artifact.strip_suffix(b"\n").unwrap()
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_str(value).unwrap()
    }

    fn label_digest(label: &str) -> Sha256Digest {
        domain_separated_digest(DigestDomain::TestVectorManifest, label.as_bytes())
    }

    fn profile() -> ProfileReferenceV1 {
        ProfileReferenceV1 {
            profile_id: ContractId::new("ostk-canonical-json-v1").unwrap(),
            profile_digest: digest(PROFILE_DIGEST),
            vector_manifest_digest: digest(VECTOR_MANIFEST_DIGEST),
        }
    }

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.fixture").unwrap(),
            ContractId::new("project.fixture").unwrap(),
        )
    }

    fn principal_binding() -> GenesisActivationPrincipalBinding {
        GenesisActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.operator").unwrap(),
            ContractId::new("principal.author").unwrap(),
        )
    }

    fn bootstrap_accepted_at() -> CanonicalTimestamp {
        CanonicalTimestamp::parse("2026-08-15T02:30:00.000000000Z").unwrap()
    }

    fn package() -> SemanticallyClosedGenesisPackage {
        let package =
            ManifestVerifiedRegistryPackage::decode(record(GENESIS_PACKAGE), &profile()).unwrap();
        SemanticallyClosedGenesisPackage::from_manifest_verified(package).unwrap()
    }

    fn bootstrap(package: &SemanticallyClosedGenesisPackage) -> VerifiedBootstrapReceipt {
        verify_pinned_bootstrap(
            record(BOOTSTRAP_RECEIPT),
            BootstrapPin::from_trusted_config(BootstrapReceiptDigest::from_digest(digest(
                BOOTSTRAP_RECEIPT_DIGEST,
            ))),
            &profile(),
            &scope(),
            package,
        )
        .unwrap()
    }

    fn threshold_one_bootstrap(
        package: &SemanticallyClosedGenesisPackage,
    ) -> VerifiedBootstrapReceipt {
        let mut receipt: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
        receipt.statement.signer_policy.threshold = 1;
        receipt.statement.signer_policy_digest = receipt.statement.signer_policy.digest().unwrap();
        let statement_id = receipt.statement.statement_id().unwrap();
        let key = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
        let mut message = b"ostk-bootstrap-approval-v1\0".to_vec();
        message.extend_from_slice(statement_id.digest().as_bytes());
        receipt.attestations = vec![BootstrapAttestationV1 {
            schema_version: 1,
            statement_id,
            signer_principal_id: ContractId::new("principal.1").unwrap(),
            signature: FixedHex64::from_bytes(key.sign(&message).as_ref().try_into().unwrap()),
        }];
        let canonical_receipt = encode_canonical(&receipt).unwrap();
        let receipt_digest = BootstrapReceiptDigest::from_digest(domain_separated_digest(
            DigestDomain::BootstrapReceipt,
            &canonical_receipt,
        ));
        verify_pinned_bootstrap(
            &canonical_receipt,
            BootstrapPin::from_trusted_config(receipt_digest),
            &profile(),
            &scope(),
            package,
        )
        .unwrap()
    }

    fn runner_pin(result: &RegistryTestResultV1) -> RegistryTestRunnerPin {
        RegistryTestRunnerPin::from_trusted_config(
            label_digest("genesis-test-runner"),
            label_digest("genesis-test-runner-config"),
            result.result_digest().unwrap(),
        )
    }

    fn test_result_value(package: &SemanticallyClosedGenesisPackage) -> RegistryTestResultV1 {
        let registry = package.manifest_verified_package().package();
        RegistryTestResultV1 {
            schema_version: 1,
            profile: profile(),
            package_digest: package.package_digest(),
            positive_vector_suite_digest: registry.positive_vector_suite_digest,
            negative_vector_suite_digest: registry.negative_vector_suite_digest,
            executed_vector_manifest_digest: profile().vector_manifest_digest,
            runner_artifact_digest: label_digest("genesis-test-runner"),
            runner_configuration_digest: label_digest("genesis-test-runner-config"),
            passed_case_count: 144,
            failed_case_count: 0,
            outcome: RegistryTestOutcomeV1::Passed,
            completed_at: CanonicalTimestamp::parse("2026-08-15T02:00:00.000000000Z").unwrap(),
        }
    }

    fn verified_test_result(
        package: &SemanticallyClosedGenesisPackage,
    ) -> VerifiedRegistryTestResult {
        let bytes = encode_canonical(&test_result_value(package)).unwrap();
        let result = test_result_value(package);
        verify_registry_test_result(&bytes, runner_pin(&result), &profile(), package).unwrap()
    }

    fn statement(
        bootstrap: &VerifiedBootstrapReceipt,
        package: &SemanticallyClosedGenesisPackage,
        test_result: &VerifiedRegistryTestResult,
    ) -> GenesisRegistryActivationStatementV1 {
        GenesisRegistryActivationStatementV1 {
            schema_version: 1,
            profile: profile(),
            scope: scope(),
            expected_anchor: GenesisRegistryAnchorV1::from_verified(bootstrap, package).unwrap(),
            package_digest: package.package_digest(),
            resulting_activation_policy_digest: genesis_activation_policy_digest(package).unwrap(),
            effective_from: CanonicalTimestamp::parse("2026-08-15T03:00:00.000000000Z").unwrap(),
            effective_until: None,
            test_vector_result_digest: test_result.result_digest(),
            proposer_principal_id: ContractId::new("principal.operator").unwrap(),
            package_author_principal_id: ContractId::new("principal.author").unwrap(),
        }
    }

    fn approval(
        statement_id: GenesisRegistryActivationStatementId,
        principal: &str,
        seed_byte: u8,
    ) -> GenesisRegistryActivationApprovalV1 {
        let key = Ed25519KeyPair::from_seed_unchecked(&[seed_byte; 32]).unwrap();
        let signature = key.sign(&activation_approval_message(statement_id));
        GenesisRegistryActivationApprovalV1 {
            schema_version: 1,
            statement_id,
            signer_principal_id: ContractId::new(principal).unwrap(),
            signature: FixedHex64::from_bytes(signature.as_ref().try_into().unwrap()),
        }
    }

    fn approval_set(
        statement: &GenesisRegistryActivationStatementV1,
    ) -> GenesisRegistryActivationApprovalSetV1 {
        let statement_id = statement.statement_id().unwrap();
        GenesisRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id,
            approvals: vec![
                approval(statement_id, "principal.1", 1),
                approval(statement_id, "principal.2", 2),
            ],
        }
    }

    fn verified_activation() -> (
        SemanticallyClosedGenesisPackage,
        VerifiedBootstrapReceipt,
        VerifiedRegistryTestResult,
        VerifiedGenesisRegistryActivationRequest,
    ) {
        let package = package();
        let bootstrap = bootstrap(&package);
        let test_result = verified_test_result(&package);
        let statement = statement(&bootstrap, &package, &test_result);
        let approvals = approval_set(&statement);
        let verified = verify_genesis_registry_activation(
            &encode_canonical(&statement).unwrap(),
            &encode_canonical(&approvals).unwrap(),
            &bootstrap,
            &package,
            &test_result,
            &principal_binding(),
        )
        .unwrap();
        (package, bootstrap, test_result, verified)
    }

    #[test]
    fn exact_bindings_produce_one_head_and_stable_stream_key() {
        let (_, bootstrap, _, activation) = verified_activation();
        let receipt = activation
            .receipt_at(
                &bootstrap_accepted_at(),
                CanonicalTimestamp::parse("2026-08-15T04:00:00.000000000Z").unwrap(),
            )
            .unwrap();
        let event = GenesisRegistryActivatedEventV1::from_verified(&activation, &receipt).unwrap();
        assert_eq!(
            activation.registry_head(&receipt).unwrap().package_digest,
            bootstrap
                .receipt()
                .statement
                .genesis_registry_package_digest
        );
        assert_eq!(
            event.consistency_partition_key().unwrap(),
            event.consistency_partition_key().unwrap()
        );
        event.validate_against(&activation, &receipt).unwrap();
    }

    #[test]
    fn bootstrap_signatures_cannot_be_replayed_as_activation_approvals() {
        let package = package();
        let bootstrap = bootstrap(&package);
        let test_result = verified_test_result(&package);
        let statement = statement(&bootstrap, &package, &test_result);
        let statement_id = statement.statement_id().unwrap();
        let replayed = GenesisRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id,
            approvals: bootstrap
                .receipt()
                .attestations
                .iter()
                .take(2)
                .map(|approval| GenesisRegistryActivationApprovalV1 {
                    schema_version: 1,
                    statement_id,
                    signer_principal_id: approval.signer_principal_id.clone(),
                    signature: approval.signature,
                })
                .collect(),
        };
        let result = verify_genesis_registry_activation(
            &encode_canonical(&statement).unwrap(),
            &encode_canonical(&replayed).unwrap(),
            &bootstrap,
            &package,
            &test_result,
            &principal_binding(),
        );
        assert_eq!(result.unwrap_err(), ContractError::SignatureVerification);
    }

    #[test]
    fn target_package_policy_and_test_runner_are_exact() {
        let package = package();
        let bootstrap = bootstrap(&package);
        let test_result = verified_test_result(&package);
        let mut statement = statement(&bootstrap, &package, &test_result);
        statement.resulting_activation_policy_digest = label_digest("proposed-policy");
        let approvals = approval_set(&statement);
        assert_eq!(
            verify_genesis_registry_activation(
                &encode_canonical(&statement).unwrap(),
                &encode_canonical(&approvals).unwrap(),
                &bootstrap,
                &package,
                &test_result,
                &principal_binding(),
            )
            .unwrap_err(),
            ContractError::BootstrapBindingMismatch
        );

        let result_bytes = encode_canonical(&test_result_value(&package)).unwrap();
        let wrong_pin = RegistryTestRunnerPin::from_trusted_config(
            label_digest("another-runner"),
            label_digest("genesis-test-runner-config"),
            test_result_value(&package).result_digest().unwrap(),
        );
        assert_eq!(
            verify_registry_test_result(&result_bytes, wrong_pin, &profile(), &package)
                .unwrap_err(),
            ContractError::BootstrapBindingMismatch
        );
    }

    #[test]
    fn trusted_principal_binding_rejects_payload_identity_claims() {
        let package = package();
        let bootstrap = bootstrap(&package);
        let test_result = verified_test_result(&package);
        let statement = statement(&bootstrap, &package, &test_result);
        let approvals = approval_set(&statement);
        let wrong_binding = GenesisActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.other-operator").unwrap(),
            ContractId::new("principal.author").unwrap(),
        );
        assert_eq!(
            verify_genesis_registry_activation(
                &encode_canonical(&statement).unwrap(),
                &encode_canonical(&approvals).unwrap(),
                &bootstrap,
                &package,
                &test_result,
                &wrong_binding,
            )
            .unwrap_err(),
            ContractError::BootstrapBindingMismatch
        );
    }

    #[test]
    fn canonical_wire_scope_and_bootstrap_anchor_are_exact() {
        let package = package();
        let bootstrap = bootstrap(&package);
        let test_result = verified_test_result(&package);
        let statement = statement(&bootstrap, &package, &test_result);
        let approvals = approval_set(&statement);
        let canonical_statement = encode_canonical(&statement).unwrap();
        let mut noncanonical_statement = Vec::with_capacity(canonical_statement.len() + 1);
        noncanonical_statement.push(b' ');
        noncanonical_statement.extend_from_slice(&canonical_statement);
        assert_eq!(
            verify_genesis_registry_activation(
                &noncanonical_statement,
                &encode_canonical(&approvals).unwrap(),
                &bootstrap,
                &package,
                &test_result,
                &principal_binding(),
            )
            .unwrap_err(),
            ContractError::NotCanonical
        );

        let mut wrong_scope = statement.clone();
        wrong_scope.scope = AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.fixture").unwrap(),
            ContractId::new("project.other").unwrap(),
        );
        let wrong_scope_approvals = approval_set(&wrong_scope);
        assert_eq!(
            verify_genesis_registry_activation(
                &encode_canonical(&wrong_scope).unwrap(),
                &encode_canonical(&wrong_scope_approvals).unwrap(),
                &bootstrap,
                &package,
                &test_result,
                &principal_binding(),
            )
            .unwrap_err(),
            ContractError::BootstrapBindingMismatch
        );

        let mut wrong_anchor = statement;
        wrong_anchor.expected_anchor.bootstrap_event_id =
            AcceptedEventId::from_digest(label_digest("another-bootstrap-event"));
        let wrong_anchor_approvals = approval_set(&wrong_anchor);
        assert_eq!(
            verify_genesis_registry_activation(
                &encode_canonical(&wrong_anchor).unwrap(),
                &encode_canonical(&wrong_anchor_approvals).unwrap(),
                &bootstrap,
                &package,
                &test_result,
                &principal_binding(),
            )
            .unwrap_err(),
            ContractError::BootstrapBindingMismatch
        );
    }

    #[test]
    fn threshold_sorting_and_separation_of_duty_fail_closed() {
        let package = package();
        let bootstrap = bootstrap(&package);
        let test_result = verified_test_result(&package);
        let statement = statement(&bootstrap, &package, &test_result);
        let mut insufficient = approval_set(&statement);
        insufficient.approvals.pop();
        assert_eq!(
            verify_genesis_registry_activation(
                &encode_canonical(&statement).unwrap(),
                &encode_canonical(&insufficient).unwrap(),
                &bootstrap,
                &package,
                &test_result,
                &principal_binding(),
            )
            .unwrap_err(),
            ContractError::ApprovalThresholdNotMet
        );

        let mut reversed = approval_set(&statement);
        reversed.approvals.reverse();
        assert!(matches!(
            verify_genesis_registry_activation(
                &encode_canonical(&statement).unwrap(),
                &encode_canonical(&reversed).unwrap(),
                &bootstrap,
                &package,
                &test_result,
                &principal_binding(),
            ),
            Err(ContractError::Schema(_))
        ));

        let mut self_authored = statement;
        self_authored.package_author_principal_id = ContractId::new("principal.1").unwrap();
        let self_approvals = GenesisRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id: self_authored.statement_id().unwrap(),
            approvals: vec![approval(
                self_authored.statement_id().unwrap(),
                "principal.1",
                1,
            )],
        };
        // The fixture bootstrap threshold rejects the single self-approval even
        // before the independent separation-of-duty gate can mint authority.
        assert_eq!(
            verify_genesis_registry_activation(
                &encode_canonical(&self_authored).unwrap(),
                &encode_canonical(&self_approvals).unwrap(),
                &bootstrap,
                &package,
                &test_result,
                &GenesisActivationPrincipalBinding::from_trusted_config(
                    ContractId::new("principal.operator").unwrap(),
                    ContractId::new("principal.1").unwrap(),
                ),
            )
            .unwrap_err(),
            ContractError::ApprovalThresholdNotMet
        );

        let author = ContractId::new("principal.1").unwrap();
        let same_author_only = vec![EligibleApprovalV1 {
            attestation_id: label_digest("self-approval"),
            principal_id: author.clone(),
            signer_key_id: ContractId::new("ed25519.self").unwrap(),
        }];
        assert!(!separation_of_duty_satisfied(&same_author_only, &author));
        let mut independently_approved = same_author_only;
        independently_approved.push(EligibleApprovalV1 {
            attestation_id: label_digest("independent-approval"),
            principal_id: ContractId::new("principal.2").unwrap(),
            signer_key_id: ContractId::new("ed25519.independent").unwrap(),
        });
        assert!(separation_of_duty_satisfied(
            &independently_approved,
            &author
        ));
    }

    #[test]
    fn valid_threshold_one_self_approval_fails_separation_of_duty() {
        let package = package();
        let bootstrap = threshold_one_bootstrap(&package);
        let test_result = verified_test_result(&package);
        let mut statement = statement(&bootstrap, &package, &test_result);
        statement.package_author_principal_id = ContractId::new("principal.1").unwrap();
        let statement_id = statement.statement_id().unwrap();
        let approvals = GenesisRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id,
            approvals: vec![approval(statement_id, "principal.1", 1)],
        };
        let binding = GenesisActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.operator").unwrap(),
            ContractId::new("principal.1").unwrap(),
        );
        assert!(matches!(
            verify_genesis_registry_activation(
                &encode_canonical(&statement).unwrap(),
                &encode_canonical(&approvals).unwrap(),
                &bootstrap,
                &package,
                &test_result,
                &binding,
            ),
            Err(ContractError::Schema(message))
                if message == "genesis activation separation of duty was not satisfied"
        ));
    }

    #[test]
    fn receipt_time_is_server_derived_and_future_effective_requests_fail() {
        let (_, _, _, activation) = verified_activation();
        assert!(matches!(
            activation.receipt_at(
                &bootstrap_accepted_at(),
                CanonicalTimestamp::parse("2026-08-15T02:59:59.999999999Z").unwrap(),
            ),
            Err(ContractError::Schema(_))
        ));
        assert!(matches!(
            activation.receipt_at(
                &CanonicalTimestamp::parse("2026-08-15T03:00:00.000000001Z").unwrap(),
                CanonicalTimestamp::parse("2026-08-15T04:00:00.000000000Z").unwrap(),
            ),
            Err(ContractError::Schema(_))
        ));
    }

    #[test]
    fn effective_time_must_round_trip_cockroach_timestamp_precision() {
        let package = package();
        let bootstrap = bootstrap(&package);
        let test_result = verified_test_result(&package);
        let mut statement = statement(&bootstrap, &package, &test_result);
        statement.effective_from =
            CanonicalTimestamp::parse("2026-08-15T03:00:00.000000001Z").unwrap();
        assert!(matches!(
            statement.statement_id(),
            Err(ContractError::Schema(_))
        ));
    }

    fn assert_vector_suite_bindings(
        package: &SemanticallyClosedGenesisPackage,
        test_result: &VerifiedRegistryTestResult,
        activation: &VerifiedGenesisRegistryActivationRequest,
        receipt: &GenesisRegistryActivationReceiptV1,
        event: &GenesisRegistryActivatedEventV1,
    ) {
        require_canonical(record(ACTIVATION_VECTOR_SUITE)).unwrap();
        let vector_suite: GenesisActivationVectorSuiteV1 =
            decode_strict(record(ACTIVATION_VECTOR_SUITE)).unwrap();
        assert_eq!(
            encode_canonical(&vector_suite).unwrap(),
            record(ACTIVATION_VECTOR_SUITE)
        );
        assert_eq!(vector_suite.schema_version, 1);
        assert_eq!(vector_suite.test_result_digest, test_result.result_digest());
        assert_eq!(
            vector_suite.statement_id,
            activation.statement().statement_id().unwrap()
        );
        assert_eq!(vector_suite.activation_id, receipt.activation_id().unwrap());
        assert_eq!(
            vector_suite.accepted_event_id,
            event.accepted_event_id().unwrap()
        );
        assert_eq!(
            vector_suite.consistency_key_digest,
            event.consistency_partition_key().unwrap().key_digest
        );
        assert_eq!(
            vector_suite.activation_policy_digest,
            genesis_activation_policy_digest(package).unwrap()
        );
        assert_eq!(vector_suite.test_result_path, "registry-test-result.jsonl");
        assert_eq!(vector_suite.statement_path, "activation-statement.jsonl");
        assert_eq!(
            vector_suite.approval_set_path,
            "activation-approval-set.jsonl"
        );
        assert_eq!(vector_suite.receipt_path, "activation-receipt.jsonl");
        assert_eq!(vector_suite.event_path, "activation-event.jsonl");
        assert_eq!(
            vector_suite.fixture_authority,
            "none; deterministic fixture seeds are public test material and must never authorize runtime"
        );
        assert_eq!(
            vector_suite.negative_cases,
            [
                "bootstrap_signature_replay",
                "future_effective_activation",
                "insufficient_threshold",
                "noncanonical_wire_bytes",
                "reversed_approval_set",
                "scope_or_anchor_mismatch",
                "self_authorization_without_independent_approval",
                "test_result_pin_mismatch",
                "wrong_package_or_policy",
            ]
        );
        assert_eq!(
            domain_separated_digest(
                DigestDomain::TestVectorManifest,
                record(ACTIVATION_VECTOR_SUITE),
            )
            .to_string(),
            "5fe9828ae4e6784f3eaf8a8ff8bed8ee975e5d46820bf29b91e740047aad1926"
        );
    }

    #[test]
    fn deterministic_material_matches_frozen_vectors() {
        let (package, _, test_result, activation) = verified_activation();
        let receipt = activation
            .receipt_at(
                &bootstrap_accepted_at(),
                CanonicalTimestamp::parse("2026-08-15T04:00:00.000000000Z").unwrap(),
            )
            .unwrap();
        let event = GenesisRegistryActivatedEventV1::from_verified(&activation, &receipt).unwrap();
        assert_eq!(test_result.canonical_bytes(), record(TEST_RESULT_FIXTURE));
        assert_eq!(
            activation.test_result().canonical_bytes(),
            test_result.canonical_bytes()
        );
        assert_eq!(
            activation.canonical_statement(),
            record(ACTIVATION_STATEMENT_FIXTURE)
        );
        assert_eq!(
            activation.canonical_approval_set(),
            record(ACTIVATION_APPROVAL_SET_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&receipt).unwrap(),
            record(ACTIVATION_RECEIPT_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&event).unwrap(),
            record(ACTIVATION_EVENT_FIXTURE)
        );
        assert_vector_suite_bindings(&package, &test_result, &activation, &receipt, &event);
        assert_eq!(
            test_result.result_digest().to_string(),
            "e91e08070250a722446195b76ee685a9697298b9fdce9809027f120c829b679d"
        );
        assert_eq!(
            activation.statement().statement_id().unwrap().to_string(),
            "e9c20de2b02cfb1776ee28cacf9a84aa81706c86b5421aa092396b98a2b83993"
        );
        assert_eq!(
            receipt.activation_id().unwrap().to_string(),
            "5a7263f5c98e75b94e82341d2a7729e9578d4691691b5a8401e1c37a83931261"
        );
        assert_eq!(
            event.accepted_event_id().unwrap().to_string(),
            "1d0b5348a0589d40a54a015ef160f20cab6e7c4ff188b1cd3b5600b50f3cadc1"
        );
        assert_eq!(
            event
                .consistency_partition_key()
                .unwrap()
                .key_digest
                .to_string(),
            "9921b7e572be77d3e100eb3d3093fb0d8ff4b3b5965f75110c18bfd34479b5ec"
        );
        assert_eq!(
            genesis_activation_policy_digest(&package)
                .unwrap()
                .to_string(),
            "6f92f99ff35969845f08f9b64cee7d86fa42dc6165ebc617d950be8960b86968"
        );
    }
}
