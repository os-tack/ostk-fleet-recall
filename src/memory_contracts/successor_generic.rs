//! Pure contracts for the repeatable registry generation `N -> N+1` activation
//! (`N >= 1`) and for resolving a contested successor set.
//!
//! The one-time generation `0 -> 1` ceremony lives in
//! [`super::successor_activation`] and is frozen. It borrows verification keys
//! from a deployment-pinned genesis key bridge because generation zero has no
//! installed activation-policy v2. Every later generation is different: the
//! **currently active** package already installs a key-complete
//! [`ActivationPolicyEntryV2`], so this module has no bridge, no bridge digest
//! field, and no bridge signature prefix. A statement that carries one is
//! rejected by `deny_unknown_fields`, and an approval produced under the v1
//! bridge signature prefix fails signature verification.
//!
//! Nothing here is durable. A verified request proves canonical bytes,
//! conformance binding, and threshold-satisfying approvals under the installed
//! predecessor policy. It does not prove that the named predecessor head is
//! still current. A private repository must re-read the head under its stream
//! lock and compare-and-swap the exact expected head — activation ID included —
//! in the same transaction before touching the crate-private receipt, event,
//! and head constructors.
//!
//! # Invariants
//!
//! - **AUTH-03 - agents cannot self-promote.** Eligibility, threshold, and
//!   separation of duty come from [`InstalledSuccessorPolicyV2`], whose
//!   constructor is crate-private and fed only by a durable head audit. The
//!   proposed package's own policy is committed to the resulting head but never
//!   authorizes its own activation, and the author and proposer must be
//!   distinct with neither counted as an approver. For a contest, no party that
//!   proposed, authored, or approved a contender may *propose* that contest's
//!   resolution, and no contender's proposer or author may be counted among its
//!   approvers. Both sides of that comparison are authenticated: the barred
//!   principal sets are read out of [`AuditedContestedSetV1`], and the subject
//!   being tested is [`ContestedResolutionPrincipalBinding`], supplied by
//!   trusted configuration rather than by the request payload. A contender's
//!   *approvers* may still approve a resolution: they are eligible signers of
//!   the fallback authority, and barring them would leave a contest between two
//!   quorum-approved contenders structurally unresolvable.
//! - **AUTH-04 - normativity is designated.** Only a verified activation
//!   produces a head. An activation event moves the head forward; a contested
//!   resolution selects among heads that activations already produced and can
//!   install no other, because every member of an [`AuditedContestedSetV1`] is
//!   an [`AuditedContenderActivationV2`] - a persisted request whose signatures,
//!   package, and conformance result were re-verified under the authorizing
//!   policy, not merely a self-consistent statement/receipt/event triple. Every
//!   statement binds the exact target package digest, the policy that governs
//!   the transition, the policy the target installs, and a conformance result
//!   pinned to an out-of-band runner identity. A contest is resolvable only
//!   under the policy of the generation it forks from: its contested generation
//!   is the audited policy's generation plus one, checked at audit time and
//!   re-checked at verification and at receipt mint.
//! - **REPLAY-01 - semantic projections are rebuildable.** Every identity is a
//!   domain-separated digest over canonical bytes, so replaying the same
//!   statement and approvals reproduces the same statement ID, approval IDs,
//!   activation ID, accepted event ID, and head.
//!   [`classify_generic_successor_replay`] resolves a re-submission into
//!   exactly one of four closed classes.

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
    registry::{
        EligibleApprovalV1, ManifestVerifiedRegistryPackage, RegistryEntryKind, RegistryHeadV1,
    },
    successor_policy::{
        ActivationPolicyEntryV2, ActivationSeparationOfDutyV2, ActivationSignatureAlgorithmV2,
        StructurallyResolvedActivationPolicyV2,
    },
};

/// Schema version of every generic `N -> N+1` artifact in this module.
const SUCCESSOR_GENERIC_SCHEMA_VERSION: u32 = 2;
/// Schema version of the reused `RegistryTestResultV1` conformance record.
const REGISTRY_TEST_RESULT_SCHEMA_VERSION: u32 = 1;
/// Schema version of the contested-set and resolution artifacts.
const CONTESTED_SCHEMA_VERSION: u32 = 1;
/// Lowest predecessor generation this module governs; `0 -> 1` stays frozen.
const MIN_PREDECESSOR_GENERATION: u32 = 1;
/// Lowest activation-policy version that can install verification keys.
const MIN_ACTIVATION_POLICY_VERSION: u32 = 2;
const MAX_GENERIC_APPROVALS: usize = 64;
const MAX_CONTESTED_SUCCESSORS: usize = 16;

const SUCCESSOR_GENERIC_EVENT_KIND: &str = "registry.successor.activated.v2";

const GENERIC_APPROVAL_SIGNATURE_PREFIX: &[u8] =
    b"ostk-registry-successor-activation-approval-signature-v2\0";
const CONTESTED_RESOLUTION_SIGNATURE_PREFIX: &[u8] =
    b"ostk-registry-contested-resolution-approval-signature-v1\0";

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

digest_newtype!(GenericSuccessorActivationStatementId);
digest_newtype!(GenericSuccessorActivationApprovalId);
digest_newtype!(GenericSuccessorActivationId);
digest_newtype!(RegistryContestedSetId);
digest_newtype!(ContestedSetResolutionStatementId);
digest_newtype!(ContestedSetResolutionApprovalId);
digest_newtype!(ContestedSetResolutionId);

/// Structurally closed successor target package.
///
/// The package embeds exactly one activation-policy v2 entry, which becomes the
/// governance policy of the resulting head. Closure is a property of public
/// bytes: any caller can build one, and it authorizes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructurallyClosedSuccessorTargetV2 {
    package_digest: Sha256Digest,
    activation_policy: StructurallyResolvedActivationPolicyV2,
    positive_vector_suite_digest: Sha256Digest,
    negative_vector_suite_digest: Sha256Digest,
    entry_count: u32,
    profile: ProfileReferenceV1,
}

impl StructurallyClosedSuccessorTargetV2 {
    /// Narrow one manifest-verified package into a successor target.
    ///
    /// Exactly one activation-policy entry is admitted: an ambiguous package
    /// could otherwise install a policy the statement did not name.
    pub fn from_manifest_verified(
        package: &ManifestVerifiedRegistryPackage,
    ) -> ContractResult<Self> {
        let body = package.package();
        body.profile.require_frozen_runtime_profile()?;
        let mut policy_entries = body
            .entries
            .iter()
            .filter(|entry| entry.kind == RegistryEntryKind::ActivationPolicy);
        let policy_entry = policy_entries
            .next()
            .ok_or(ContractError::ManifestMismatch)?;
        if policy_entries.next().is_some() {
            return Err(ContractError::ManifestMismatch);
        }
        let activation_policy =
            StructurallyResolvedActivationPolicyV2::from_registry_entry(policy_entry)?;
        if activation_policy.registry_reference().version < MIN_ACTIVATION_POLICY_VERSION
            || body.positive_vector_suite_digest == Sha256Digest::ZERO
            || body.negative_vector_suite_digest == Sha256Digest::ZERO
        {
            return Err(ContractError::ManifestMismatch);
        }
        Ok(Self {
            package_digest: package.package_digest(),
            activation_policy,
            positive_vector_suite_digest: body.positive_vector_suite_digest,
            negative_vector_suite_digest: body.negative_vector_suite_digest,
            entry_count: u32::try_from(body.entries.len())
                .map_err(|_| ContractError::ManifestMismatch)?,
            profile: body.profile.clone(),
        })
    }

    pub const fn package_digest(&self) -> Sha256Digest {
        self.package_digest
    }

    pub const fn activation_policy(&self) -> &StructurallyResolvedActivationPolicyV2 {
        &self.activation_policy
    }

    pub const fn entry_count(&self) -> u32 {
        self.entry_count
    }

    pub const fn profile(&self) -> &ProfileReferenceV1 {
        &self.profile
    }
}

/// Deployment-trusted identity of the successor-package conformance runner.
///
/// The pin is deliberately not serializable and cannot be supplied by request
/// bytes. Its expected result digest authenticates the entire canonical result,
/// including the target package digest and both vector roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericSuccessorTestRunnerPin {
    runner_artifact: Sha256Digest,
    runner_configuration: Sha256Digest,
    expected_result: RegistryTestResultDigest,
}

impl GenericSuccessorTestRunnerPin {
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

/// Canonical passing conformance result bound to one exact target and runner.
///
/// Offline proof only: it never makes the target package active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGenericSuccessorTestResult {
    result: RegistryTestResultV1,
    canonical_bytes: Vec<u8>,
    result_digest: RegistryTestResultDigest,
}

impl VerifiedGenericSuccessorTestResult {
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

/// Verify one canonical runner result against the exact target package and an
/// out-of-band runner pin.
pub fn verify_generic_successor_test_result(
    input: &[u8],
    runner_pin: GenericSuccessorTestRunnerPin,
    target: &StructurallyClosedSuccessorTargetV2,
) -> ContractResult<VerifiedGenericSuccessorTestResult> {
    require_canonical(input)?;
    let result: RegistryTestResultV1 = decode_strict(input)?;
    validate_generic_test_result_shape(&result)?;
    let canonical_bytes = encode_canonical(&result)?;
    if canonical_bytes != input {
        return Err(ContractError::NotCanonical);
    }

    let result_digest = generic_test_result_digest(&result)?;
    if runner_pin.runner_artifact == Sha256Digest::ZERO
        || runner_pin.runner_configuration == Sha256Digest::ZERO
        || runner_pin.expected_result.digest() == Sha256Digest::ZERO
        || result.profile != *target.profile()
        || result.package_digest != target.package_digest()
        || result.positive_vector_suite_digest != target.positive_vector_suite_digest
        || result.negative_vector_suite_digest != target.negative_vector_suite_digest
        || result.executed_vector_manifest_digest != result.profile.vector_manifest_digest
        || result.runner_artifact_digest != runner_pin.runner_artifact
        || result.runner_configuration_digest != runner_pin.runner_configuration
        || result_digest != runner_pin.expected_result
    {
        return Err(ContractError::ManifestMismatch);
    }

    Ok(VerifiedGenericSuccessorTestResult {
        result,
        canonical_bytes,
        result_digest,
    })
}

/// The activation policy actually installed by the currently active package at
/// generation `N`, together with that generation's open head.
///
/// This is the only authority that decides eligibility, threshold, and
/// separation of duty for the `N -> N+1` transition; the proposed package never
/// gets a vote in its own activation. The constructor is crate-private on
/// purpose: it may be minted only from a durable audit that read the head and
/// its package under one stream lock. Public bytes can never produce one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledSuccessorPolicyV2 {
    profile: ProfileReferenceV1,
    scope: AuthenticatedProjectScopeV1,
    generation: u32,
    head: RegistryHeadBindingV1,
    policy_reference: RegistryReferenceV1,
    policy: ActivationPolicyEntryV2,
}

impl InstalledSuccessorPolicyV2 {
    /// Mint the installed-policy witness from a fully audited durable head.
    ///
    /// The caller must have proved, in the same transaction, that `head` is the
    /// current open head at `generation` and that `policy` is the activation
    /// policy embedded in the package named by that head.
    #[allow(dead_code)] // consumed by the successor repository in the next increment
    pub(crate) fn from_durable_audit(
        profile: ProfileReferenceV1,
        scope: AuthenticatedProjectScopeV1,
        generation: u32,
        head: RegistryHeadBindingV1,
        installed_package: &StructurallyClosedSuccessorTargetV2,
    ) -> ContractResult<Self> {
        profile.require_frozen_runtime_profile()?;
        head.validate_shape()?;
        let policy_reference = installed_package
            .activation_policy()
            .registry_reference()
            .clone();
        let policy = installed_package.activation_policy().policy().clone();
        policy.validate()?;
        if generation < MIN_PREDECESSOR_GENERATION
            || head.effective_until.is_some()
            || head.head.package_digest != installed_package.package_digest()
            || head.head.activation_policy_digest != policy_reference.entry_digest
            || policy_reference.version < MIN_ACTIVATION_POLICY_VERSION
            || profile != *installed_package.profile()
        {
            return Err(ContractError::ManifestMismatch);
        }
        Ok(Self {
            profile,
            scope,
            generation,
            head,
            policy_reference,
            policy,
        })
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub const fn head(&self) -> &RegistryHeadBindingV1 {
        &self.head
    }

    pub const fn policy_reference(&self) -> &RegistryReferenceV1 {
        &self.policy_reference
    }

    pub const fn policy(&self) -> &ActivationPolicyEntryV2 {
        &self.policy
    }

    pub const fn scope(&self) -> &AuthenticatedProjectScopeV1 {
        &self.scope
    }

    pub const fn profile(&self) -> &ProfileReferenceV1 {
        &self.profile
    }
}

/// Trusted proposer and package-author identities for one activation ceremony.
///
/// The statement repeats these values so signatures commit to them, but cannot
/// choose them: the verifier requires exact equality to this non-serializable
/// binding supplied by authenticated configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericSuccessorPrincipalBinding {
    proposer_principal_id: ContractId,
    package_author_principal_id: ContractId,
}

impl GenericSuccessorPrincipalBinding {
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

/// Freshly approved semantic statement for one generation `N -> N+1` step.
///
/// `expected_predecessor_head` binds the whole open predecessor head, activation
/// ID included, so an `A -> B -> A` package sequence cannot revive a stale
/// proposal: the third activation mints a new activation ID even though the
/// package digest repeats.
///
/// There is deliberately no key-bridge field. Generic transitions are authorized
/// by the policy the predecessor package already installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericSuccessorActivationStatementV2 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub expected_predecessor_head: RegistryHeadBindingV1,
    pub current_activation_policy: RegistryReferenceV1,
    pub target_package_digest: Sha256Digest,
    pub target_activation_policy: RegistryReferenceV1,
    pub test_vector_result_digest: RegistryTestResultDigest,
    pub from_generation: u32,
    pub to_generation: u32,
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
    pub proposer_principal_id: ContractId,
    pub package_author_principal_id: ContractId,
}

impl GenericSuccessorActivationStatementV2 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        self.expected_predecessor_head.validate_shape()?;
        validate_registry_reference(&self.current_activation_policy)?;
        validate_registry_reference(&self.target_activation_policy)?;
        let expected_to_generation = self
            .from_generation
            .checked_add(1)
            .ok_or_else(|| ContractError::Schema("successor generation overflow".into()))?;
        if self.schema_version != SUCCESSOR_GENERIC_SCHEMA_VERSION
            || self.from_generation < MIN_PREDECESSOR_GENERATION
            || self.to_generation != expected_to_generation
            || self.current_activation_policy.version < MIN_ACTIVATION_POLICY_VERSION
            || self.target_activation_policy.version < MIN_ACTIVATION_POLICY_VERSION
            || self.expected_predecessor_head.effective_until.is_some()
            || self.current_activation_policy.entry_digest
                != self.expected_predecessor_head.head.activation_policy_digest
            || self.target_package_digest == Sha256Digest::ZERO
            // Re-activating the exact current package is a no-op, not a
            // transition. Activating an *earlier* package digest is a
            // deliberate revert and stays admissible.
            || self.target_package_digest == self.expected_predecessor_head.head.package_digest
            || self.test_vector_result_digest.digest() == Sha256Digest::ZERO
            || !self.effective_from.is_microsecond_aligned()
            || self.effective_from <= self.expected_predecessor_head.effective_from
            || self.effective_until.is_some()
            // The installed v2 rule requires distinct author and proposer; a
            // statement that collapses them fails before any signature work.
            || self.proposer_principal_id == self.package_author_principal_id
        {
            return Err(ContractError::Schema(
                "invalid generic successor activation statement v2".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }

    pub fn statement_id(&self) -> ContractResult<GenericSuccessorActivationStatementId> {
        self.validate_shape()?;
        Ok(GenericSuccessorActivationStatementId::from_digest(
            domain_separated_digest(
                DigestDomain::RegistrySuccessorActivationStatementV2,
                &encode_canonical(self)?,
            ),
        ))
    }
}

/// One fresh Ed25519 approval under the installed predecessor policy keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericSuccessorActivationApprovalV2 {
    pub schema_version: u32,
    pub statement_id: GenericSuccessorActivationStatementId,
    pub signer_principal_id: ContractId,
    pub signature: FixedHex64,
}

impl GenericSuccessorActivationApprovalV2 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != SUCCESSOR_GENERIC_SCHEMA_VERSION
            || self.statement_id.digest() == Sha256Digest::ZERO
            || self.signature.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(ContractError::Schema(
                "invalid generic successor activation approval v2".into(),
            ));
        }
        Ok(())
    }

    pub fn approval_id(&self) -> ContractResult<GenericSuccessorActivationApprovalId> {
        self.validate_shape()?;
        Ok(GenericSuccessorActivationApprovalId::from_digest(
            domain_separated_digest(
                DigestDomain::RegistrySuccessorActivationApprovalV2,
                &encode_canonical(self)?,
            ),
        ))
    }
}

/// Canonical principal-sorted approval set for one generic statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericSuccessorActivationApprovalSetV2 {
    pub schema_version: u32,
    pub statement_id: GenericSuccessorActivationStatementId,
    pub approvals: Vec<GenericSuccessorActivationApprovalV2>,
}

impl GenericSuccessorActivationApprovalSetV2 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != SUCCESSOR_GENERIC_SCHEMA_VERSION
            || self.statement_id.digest() == Sha256Digest::ZERO
            || self.approvals.is_empty()
            || self.approvals.len() > MAX_GENERIC_APPROVALS
            || !self
                .approvals
                .windows(2)
                .all(|pair| pair[0].signer_principal_id < pair[1].signer_principal_id)
        {
            return Err(ContractError::Schema(
                "invalid generic successor activation approval set v2".into(),
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

/// Canonical and cryptographically verified, but explicitly non-durable,
/// generic successor activation request.
#[derive(Debug, Clone)]
pub struct VerifiedGenericSuccessorActivation {
    statement: GenericSuccessorActivationStatementV2,
    canonical_statement: Vec<u8>,
    approval_set: GenericSuccessorActivationApprovalSetV2,
    canonical_approval_set: Vec<u8>,
    test_result: VerifiedGenericSuccessorTestResult,
    eligible_approvals: Vec<EligibleApprovalV1>,
    required_threshold: u16,
    applied_separation_of_duty: ActivationSeparationOfDutyV2,
}

impl VerifiedGenericSuccessorActivation {
    pub const fn statement(&self) -> &GenericSuccessorActivationStatementV2 {
        &self.statement
    }

    pub fn canonical_statement(&self) -> &[u8] {
        &self.canonical_statement
    }

    pub const fn approval_set(&self) -> &GenericSuccessorActivationApprovalSetV2 {
        &self.approval_set
    }

    pub fn canonical_approval_set(&self) -> &[u8] {
        &self.canonical_approval_set
    }

    pub const fn test_result(&self) -> &VerifiedGenericSuccessorTestResult {
        &self.test_result
    }

    pub fn eligible_approvals(&self) -> &[EligibleApprovalV1] {
        &self.eligible_approvals
    }

    pub const fn required_threshold(&self) -> u16 {
        self.required_threshold
    }

    pub const fn applied_separation_of_duty(&self) -> ActivationSeparationOfDutyV2 {
        self.applied_separation_of_duty
    }

    pub fn statement_id(&self) -> ContractResult<GenericSuccessorActivationStatementId> {
        self.statement.statement_id()
    }

    /// Compare-and-swap precondition: the whole expected head must still be the
    /// exact current head, activation ID included.
    ///
    /// Package-digest equality is not enough. After `A -> B -> A` the current
    /// head names package `A` again under a *new* activation ID, so a proposal
    /// written against the first `A` remains stale.
    pub fn require_expected_head(&self, current: &RegistryHeadBindingV1) -> ContractResult<()> {
        if &self.statement.expected_predecessor_head != current {
            return Err(ContractError::StaleRegistryHead);
        }
        Ok(())
    }

    /// Mint a receipt only from a head re-audited under the repository's
    /// stream lock, at repository-supplied server time, and after checking the
    /// persisted predecessor's trusted acceptance time.
    ///
    /// `reaudited_policy` is the compare-and-swap precondition: verification
    /// alone proves bytes and approvals, never freshness, so the accepted form
    /// cannot exist without presenting the head that is current *now*.
    #[allow(dead_code)] // consumed by the successor repository in the next increment
    pub(crate) fn receipt_at(
        &self,
        reaudited_policy: &InstalledSuccessorPolicyV2,
        predecessor_accepted_at: &CanonicalTimestamp,
        accepted_at: CanonicalTimestamp,
    ) -> ContractResult<GenericSuccessorActivationReceiptV2> {
        let statement = &self.statement;
        self.require_expected_head(reaudited_policy.head())?;
        if statement.profile != *reaudited_policy.profile()
            || statement.scope != *reaudited_policy.scope()
            || statement.from_generation != reaudited_policy.generation()
            || statement.current_activation_policy != *reaudited_policy.policy_reference()
        {
            return Err(ContractError::ManifestMismatch);
        }
        if !predecessor_accepted_at.is_microsecond_aligned()
            || !accepted_at.is_microsecond_aligned()
            || predecessor_accepted_at < &statement.expected_predecessor_head.effective_from
            || statement.effective_from < *predecessor_accepted_at
            || statement.effective_from > accepted_at
            || statement.effective_until.is_some()
        {
            return Err(ContractError::Schema(
                "generic successor activation is outside the predecessor and server-time interval"
                    .into(),
            ));
        }

        let receipt = GenericSuccessorActivationReceiptV2 {
            schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
            statement_id: statement.statement_id()?,
            predecessor_head: statement.expected_predecessor_head.clone(),
            current_activation_policy: statement.current_activation_policy.clone(),
            target_package_digest: statement.target_package_digest,
            target_activation_policy: statement.target_activation_policy.clone(),
            test_vector_result_digest: statement.test_vector_result_digest,
            from_generation: statement.from_generation,
            to_generation: statement.to_generation,
            eligible_approvals: self.eligible_approvals.clone(),
            required_threshold: self.required_threshold,
            applied_separation_of_duty: self.applied_separation_of_duty,
            separation_of_duty_satisfied: true,
            accepted_at,
        };
        receipt.validate_against(self)?;
        Ok(receipt)
    }

    /// Derive the new open head only from a receipt revalidated against this
    /// request. Repository code must call this after the durable head audit and
    /// compare-and-swap, never from public request fields.
    pub(crate) fn resulting_registry_head(
        &self,
        receipt: &GenericSuccessorActivationReceiptV2,
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

/// Verify a canonical generation `N -> N+1` request under the policy the
/// predecessor package installed.
///
/// The target package's own activation policy is checked for structural closure
/// and is committed to the resulting head, but it deliberately does not
/// authorize its own activation: a package cannot lower the threshold, widen the
/// signer set, or relax separation of duty to admit itself.
pub fn verify_generic_successor_activation(
    canonical_statement: &[u8],
    canonical_approval_set: &[u8],
    installed_policy: &InstalledSuccessorPolicyV2,
    target: &StructurallyClosedSuccessorTargetV2,
    test_result: &VerifiedGenericSuccessorTestResult,
    principal_binding: &GenericSuccessorPrincipalBinding,
) -> ContractResult<VerifiedGenericSuccessorActivation> {
    require_canonical(canonical_statement)?;
    let statement: GenericSuccessorActivationStatementV2 = decode_strict(canonical_statement)?;
    statement.validate_shape()?;
    if encode_canonical(&statement)? != canonical_statement {
        return Err(ContractError::NotCanonical);
    }

    let active_policy = installed_policy.policy();
    active_policy.validate()?;
    target.activation_policy().policy().validate()?;
    if statement.profile != *installed_policy.profile()
        || statement.profile != *target.profile()
        || statement.scope != *installed_policy.scope()
        || statement.from_generation != installed_policy.generation()
        || statement.current_activation_policy != *installed_policy.policy_reference()
        || statement.target_package_digest != target.package_digest()
        || &statement.target_activation_policy != target.activation_policy().registry_reference()
        || statement.test_vector_result_digest != test_result.result_digest()
        || test_result.result().profile != statement.profile
        || test_result.result().package_digest != statement.target_package_digest
        || test_result.result().completed_at > statement.effective_from
        || statement.proposer_principal_id != principal_binding.proposer_principal_id
        || statement.package_author_principal_id != principal_binding.package_author_principal_id
    {
        return Err(ContractError::ManifestMismatch);
    }
    // Head equality is checked separately and last, so a scope or package
    // mismatch never masquerades as a stale-head outcome.
    if statement.expected_predecessor_head != *installed_policy.head() {
        return Err(ContractError::StaleRegistryHead);
    }

    require_canonical(canonical_approval_set)?;
    let approval_set: GenericSuccessorActivationApprovalSetV2 =
        decode_strict(canonical_approval_set)?;
    approval_set.validate_shape()?;
    if encode_canonical(&approval_set)? != canonical_approval_set {
        return Err(ContractError::NotCanonical);
    }
    let statement_id = statement.statement_id()?;
    if approval_set.statement_id != statement_id
        || approval_set.approvals.len() > active_policy.eligible_signers.len()
    {
        return Err(ContractError::SignatureVerification);
    }

    let signature_message =
        approval_signature_message(GENERIC_APPROVAL_SIGNATURE_PREFIX, statement_id.digest());
    let mut approving_principal_ids = Vec::with_capacity(approval_set.approvals.len());
    let mut eligible_approvals = Vec::with_capacity(approval_set.approvals.len());
    for approval in &approval_set.approvals {
        // Only keys the *installed* policy still lists can verify. A revoked or
        // never-installed key has no binding here and fails closed.
        let signer = active_policy
            .eligible_signers
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

    // The v2 policy rule, encoded in
    // `ActivationPolicyEntryV2::validate_approval_principal_set`: author and
    // proposer must be distinct and neither may be counted as an approver.
    active_policy.validate_approval_principal_set(
        &statement.package_author_principal_id,
        &statement.proposer_principal_id,
        &approving_principal_ids,
    )?;
    eligible_approvals.sort_unstable();
    if !approval_bindings_are_unique(&eligible_approvals) || !strictly_sorted(&eligible_approvals) {
        return Err(ContractError::SignatureVerification);
    }

    Ok(VerifiedGenericSuccessorActivation {
        statement,
        canonical_statement: canonical_statement.to_vec(),
        approval_set,
        canonical_approval_set: canonical_approval_set.to_vec(),
        test_result: test_result.clone(),
        eligible_approvals,
        required_threshold: active_policy.approval_threshold,
        applied_separation_of_duty: active_policy.separation_of_duty,
    })
}

/// Closed classification of a re-submitted generic successor request.
///
/// These are the same four cases, tested in the same order, that the frozen
/// `0 -> 1` repository seam distinguishes in
/// `registry_activation::successor_cockroach::classify_replay_identity`
/// (stale statement, corrupt preimage, approval-set conflict, exact replay),
/// lifted into a pure function so replay is decided by bytes and identities
/// rather than by transport behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericSuccessorReplayClassV2 {
    /// Identical statement and identical approval set: exactly one effect.
    ExactReplay,
    /// A different statement already won this predecessor head.
    StaleStatement,
    /// One statement ID maps to two different canonical preimages.
    IntegrityCollision,
    /// Same statement, different approval ceremony.
    ApprovalSetConflict,
}

/// Classify a candidate against the exact stored bytes for the same head.
pub fn classify_generic_successor_replay(
    candidate: &VerifiedGenericSuccessorActivation,
    stored_statement_id: GenericSuccessorActivationStatementId,
    stored_canonical_statement: &[u8],
    stored_canonical_approval_set: &[u8],
) -> ContractResult<GenericSuccessorReplayClassV2> {
    let candidate_statement_id = candidate.statement_id()?;
    if stored_statement_id != candidate_statement_id {
        return Ok(GenericSuccessorReplayClassV2::StaleStatement);
    }
    if stored_canonical_statement != candidate.canonical_statement() {
        return Ok(GenericSuccessorReplayClassV2::IntegrityCollision);
    }
    if stored_canonical_approval_set != candidate.canonical_approval_set() {
        return Ok(GenericSuccessorReplayClassV2::ApprovalSetConflict);
    }
    Ok(GenericSuccessorReplayClassV2::ExactReplay)
}

/// Server-derived audit receipt for one generic successor activation.
///
/// Structural bytes alone grant no authority. Runtime code must obtain this
/// value through the crate-private constructor on the verified request after
/// re-auditing the durable head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericSuccessorActivationReceiptV2 {
    pub schema_version: u32,
    pub statement_id: GenericSuccessorActivationStatementId,
    pub predecessor_head: RegistryHeadBindingV1,
    pub current_activation_policy: RegistryReferenceV1,
    pub target_package_digest: Sha256Digest,
    pub target_activation_policy: RegistryReferenceV1,
    pub test_vector_result_digest: RegistryTestResultDigest,
    pub from_generation: u32,
    pub to_generation: u32,
    pub eligible_approvals: Vec<EligibleApprovalV1>,
    pub required_threshold: u16,
    pub applied_separation_of_duty: ActivationSeparationOfDutyV2,
    pub separation_of_duty_satisfied: bool,
    pub accepted_at: CanonicalTimestamp,
}

impl GenericSuccessorActivationReceiptV2 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.predecessor_head.validate_shape()?;
        validate_registry_reference(&self.current_activation_policy)?;
        validate_registry_reference(&self.target_activation_policy)?;
        let expected_to_generation = self
            .from_generation
            .checked_add(1)
            .ok_or_else(|| ContractError::Schema("successor generation overflow".into()))?;
        if self.schema_version != SUCCESSOR_GENERIC_SCHEMA_VERSION
            || self.statement_id.digest() == Sha256Digest::ZERO
            || self.predecessor_head.effective_until.is_some()
            || self.current_activation_policy.version < MIN_ACTIVATION_POLICY_VERSION
            || self.target_activation_policy.version < MIN_ACTIVATION_POLICY_VERSION
            || self.current_activation_policy.entry_digest
                != self.predecessor_head.head.activation_policy_digest
            || self.target_package_digest == Sha256Digest::ZERO
            || self.target_package_digest == self.predecessor_head.head.package_digest
            || self.test_vector_result_digest.digest() == Sha256Digest::ZERO
            || self.from_generation < MIN_PREDECESSOR_GENERATION
            || self.to_generation != expected_to_generation
            || self.required_threshold == 0
            || usize::from(self.required_threshold) > self.eligible_approvals.len()
            || self.eligible_approvals.len() > MAX_GENERIC_APPROVALS
            || !strictly_sorted(&self.eligible_approvals)
            || !approval_bindings_are_unique(&self.eligible_approvals)
            || self.applied_separation_of_duty
                != ActivationSeparationOfDutyV2::AuthorAndProposerDistinctNeitherMayApprove
            || !self.separation_of_duty_satisfied
            || !self.accepted_at.is_microsecond_aligned()
            || self.accepted_at <= self.predecessor_head.effective_from
        {
            return Err(ContractError::Schema(
                "invalid generic successor activation receipt v2".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }

    pub fn activation_id(&self) -> ContractResult<GenericSuccessorActivationId> {
        self.validate_shape()?;
        Ok(GenericSuccessorActivationId::from_digest(
            domain_separated_digest(
                DigestDomain::RegistrySuccessorActivationReceiptV2,
                &encode_canonical(self)?,
            ),
        ))
    }

    pub fn validate_against(
        &self,
        activation: &VerifiedGenericSuccessorActivation,
    ) -> ContractResult<()> {
        self.validate_shape()?;
        let statement = activation.statement();
        if self.statement_id != statement.statement_id()?
            || self.predecessor_head != statement.expected_predecessor_head
            || self.current_activation_policy != statement.current_activation_policy
            || self.target_package_digest != statement.target_package_digest
            || self.target_activation_policy != statement.target_activation_policy
            || self.test_vector_result_digest != statement.test_vector_result_digest
            || self.from_generation != statement.from_generation
            || self.to_generation != statement.to_generation
            || self.eligible_approvals != activation.eligible_approvals
            || self.required_threshold != activation.required_threshold
            || self.applied_separation_of_duty != activation.applied_separation_of_duty
            || self.accepted_at < statement.effective_from
        {
            return Err(ContractError::ManifestMismatch);
        }
        Ok(())
    }
}

/// Immutable semantic event announcing one generation `N -> N+1` registry head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericSuccessorActivatedEventV2 {
    pub schema_version: u32,
    pub event_kind: ContractId,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub activation_id: GenericSuccessorActivationId,
    pub statement_id: GenericSuccessorActivationStatementId,
    pub predecessor_head: RegistryHeadBindingV1,
    pub activated_head: RegistryHeadBindingV1,
    pub current_activation_policy: RegistryReferenceV1,
    pub target_activation_policy: RegistryReferenceV1,
    pub test_vector_result_digest: RegistryTestResultDigest,
    pub from_generation: u32,
    pub to_generation: u32,
}

impl GenericSuccessorActivatedEventV2 {
    /// Repository-only event construction from the exact verified request and
    /// server-derived receipt.
    #[allow(dead_code)] // consumed by the successor repository in the next increment
    pub(crate) fn from_verified(
        activation: &VerifiedGenericSuccessorActivation,
        receipt: &GenericSuccessorActivationReceiptV2,
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

    /// Genesis, first-successor, and generic transitions share the one
    /// scope-local `registry.activation` consistency stream.
    pub fn consistency_partition_key(&self) -> ContractResult<ConsistencyPartitionKeyV1> {
        self.validate_shape()?;
        registry_activation_consistency_partition_key(&self.scope)
    }

    pub fn validate_against(
        &self,
        activation: &VerifiedGenericSuccessorActivation,
        receipt: &GenericSuccessorActivationReceiptV2,
    ) -> ContractResult<()> {
        self.validate_shape()?;
        receipt.validate_against(activation)?;
        if self != &Self::from_parts(activation, receipt)? {
            return Err(ContractError::ManifestMismatch);
        }
        Ok(())
    }

    fn from_parts(
        activation: &VerifiedGenericSuccessorActivation,
        receipt: &GenericSuccessorActivationReceiptV2,
    ) -> ContractResult<Self> {
        let statement = activation.statement();
        Ok(Self {
            schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
            event_kind: ContractId::new(SUCCESSOR_GENERIC_EVENT_KIND)?,
            profile: statement.profile.clone(),
            scope: statement.scope.clone(),
            activation_id: receipt.activation_id()?,
            statement_id: statement.statement_id()?,
            predecessor_head: statement.expected_predecessor_head.clone(),
            activated_head: activation.resulting_registry_head(receipt)?,
            current_activation_policy: statement.current_activation_policy.clone(),
            target_activation_policy: statement.target_activation_policy.clone(),
            test_vector_result_digest: statement.test_vector_result_digest,
            from_generation: statement.from_generation,
            to_generation: statement.to_generation,
        })
    }

    fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        self.predecessor_head.validate_shape()?;
        self.activated_head.validate_shape()?;
        validate_registry_reference(&self.current_activation_policy)?;
        validate_registry_reference(&self.target_activation_policy)?;
        let expected_to_generation = self
            .from_generation
            .checked_add(1)
            .ok_or_else(|| ContractError::Schema("successor generation overflow".into()))?;
        if self.schema_version != SUCCESSOR_GENERIC_SCHEMA_VERSION
            || self.event_kind.as_str() != SUCCESSOR_GENERIC_EVENT_KIND
            || self.statement_id.digest() == Sha256Digest::ZERO
            || self.predecessor_head.effective_until.is_some()
            || self.activated_head.effective_until.is_some()
            || self.current_activation_policy.version < MIN_ACTIVATION_POLICY_VERSION
            || self.target_activation_policy.version < MIN_ACTIVATION_POLICY_VERSION
            || self.current_activation_policy.entry_digest
                != self.predecessor_head.head.activation_policy_digest
            || self.target_activation_policy.entry_digest
                != self.activated_head.head.activation_policy_digest
            || self.predecessor_head.head.package_digest == self.activated_head.head.package_digest
            || self.predecessor_head.head.activation_id == self.activated_head.head.activation_id
            || self.activation_id.digest() != self.activated_head.head.activation_id
            || self.test_vector_result_digest.digest() == Sha256Digest::ZERO
            || self.from_generation < MIN_PREDECESSOR_GENERATION
            || self.to_generation != expected_to_generation
            || self.activated_head.effective_from <= self.predecessor_head.effective_from
        {
            return Err(ContractError::Schema(
                "invalid generic successor activated event v2".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }
}

/// One member of a contested successor set.
///
/// Every contender is an activation that verified on its own merits against the
/// same predecessor head. Being verified is exactly why the set is contested:
/// receipt time never breaks the tie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContestedSuccessorV1 {
    pub activation_id: GenericSuccessorActivationId,
    pub statement_id: GenericSuccessorActivationStatementId,
    pub to_generation: u32,
    pub activated_head: RegistryHeadBindingV1,
    pub proposer_principal_id: ContractId,
    pub package_author_principal_id: ContractId,
    pub approving_principal_ids: Vec<ContractId>,
}

impl ContestedSuccessorV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        self.activated_head.validate_shape()?;
        if self.activation_id.digest() == Sha256Digest::ZERO
            || self.statement_id.digest() == Sha256Digest::ZERO
            || self.to_generation <= MIN_PREDECESSOR_GENERATION
            || self.activated_head.head.activation_id != self.activation_id.digest()
            || self.activated_head.effective_until.is_some()
            || self.proposer_principal_id == self.package_author_principal_id
            || self.approving_principal_ids.is_empty()
            || self.approving_principal_ids.len() > MAX_GENERIC_APPROVALS
            || !strictly_sorted(&self.approving_principal_ids)
        {
            return Err(ContractError::Schema("invalid contested successor".into()));
        }
        Ok(())
    }

    /// Every principal that participated in selecting this successor.
    fn self_selecting_principals(&self) -> BTreeSet<&ContractId> {
        let mut principals = self.proposing_principals();
        principals.extend(self.approving_principal_ids.iter());
        principals
    }

    /// The principals that authored and proposed this successor.
    fn proposing_principals(&self) -> BTreeSet<&ContractId> {
        let mut principals = BTreeSet::new();
        principals.insert(&self.proposer_principal_id);
        principals.insert(&self.package_author_principal_id);
        principals
    }
}

/// Immutable record of two or more incompatible successors of one head.
///
/// While such a record stands, the registry projection is `ambiguous`: affected
/// automatic verification suspends and every projector reports its last
/// unambiguous closed watermark as stale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryContestedSetV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub last_unambiguous_head: RegistryHeadBindingV1,
    pub last_unambiguous_activation_policy: RegistryReferenceV1,
    pub contested_generation: u32,
    pub contenders: Vec<ContestedSuccessorV1>,
}

impl RegistryContestedSetV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        self.last_unambiguous_head.validate_shape()?;
        validate_registry_reference(&self.last_unambiguous_activation_policy)?;
        if self.schema_version != CONTESTED_SCHEMA_VERSION
            || self.contested_generation <= MIN_PREDECESSOR_GENERATION
            || self.last_unambiguous_activation_policy.version < MIN_ACTIVATION_POLICY_VERSION
            || self.last_unambiguous_activation_policy.entry_digest
                != self.last_unambiguous_head.head.activation_policy_digest
            || self.last_unambiguous_head.effective_until.is_some()
            || self.contenders.len() < 2
            || self.contenders.len() > MAX_CONTESTED_SUCCESSORS
            || !self
                .contenders
                .windows(2)
                .all(|pair| pair[0].activation_id < pair[1].activation_id)
        {
            return Err(ContractError::Schema(
                "invalid registry contested set v1".into(),
            ));
        }
        let mut statement_ids = BTreeSet::new();
        for contender in &self.contenders {
            contender.validate_shape()?;
            if contender.to_generation != self.contested_generation
                || contender.activated_head.effective_from
                    <= self.last_unambiguous_head.effective_from
                || !statement_ids.insert(contender.statement_id)
            {
                return Err(ContractError::Schema(
                    "invalid registry contested set v1".into(),
                ));
            }
        }
        encode_canonical(self)?;
        Ok(())
    }

    pub fn contested_set_id(&self) -> ContractResult<RegistryContestedSetId> {
        self.validate_shape()?;
        Ok(RegistryContestedSetId::from_digest(
            domain_separated_digest(
                DigestDomain::RegistryContestedSetV1,
                &encode_canonical(self)?,
            ),
        ))
    }

    /// Exact contested activation-ID set, in canonical order.
    pub fn contested_activation_ids(&self) -> ContractResult<Vec<GenericSuccessorActivationId>> {
        self.validate_shape()?;
        Ok(self
            .contenders
            .iter()
            .map(|contender| contender.activation_id)
            .collect())
    }
}

/// The durable bytes and out-of-band evidence one contender audit consumes.
///
/// Every field is something a repository must genuinely possess: the two
/// canonical request records it persisted, the *real package bytes* the
/// activation targeted, and the conformance result that package passed under a
/// deployment-pinned runner. None of it can be conjured from the activation's
/// own three artifacts, which is exactly the point.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // consumed by the successor repository in the next increment
pub(crate) struct ContenderActivationAuditV2<'a> {
    /// The canonical statement bytes, as persisted.
    pub canonical_statement: &'a [u8],
    /// The canonical approval-set bytes, as persisted. Their signatures are
    /// re-verified against the authorizing policy's installed keys.
    pub canonical_approval_set: &'a [u8],
    /// The activated package, narrowed from its manifest-verified bytes.
    pub target: &'a StructurallyClosedSuccessorTargetV2,
    /// That package's passing conformance result under the runner pin.
    pub test_result: &'a VerifiedGenericSuccessorTestResult,
    /// The persisted server-derived receipt.
    pub receipt: &'a GenericSuccessorActivationReceiptV2,
    /// The persisted accepted event.
    pub event: &'a GenericSuccessorActivatedEventV2,
}

/// One contender's durable activation, re-verified under the authorizing policy.
///
/// A contested set is only as trustworthy as its members, and a bare
/// [`ContestedSuccessorV1`] is a claim: it *names* an activation ID, a statement
/// ID, an activated head, a proposer, an author, and an approver set, and
/// nothing in those wire bytes proves any of them ever happened. This typestate
/// is the proof, and its constructor is crate-private for the same reason
/// [`InstalledSuccessorPolicyV2::from_durable_audit`] is.
///
/// Mutual consistency among a statement, a receipt, and an event is *not* that
/// proof. [`GenericSuccessorActivationReceiptV2::activation_id`] is a digest
/// over the receipt itself, so reproducing the activated head from it is
/// self-anchoring: a wholly synthetic triple reproduces just as well as a real
/// one. The audit therefore re-runs the full verifier
/// ([`verify_generic_successor_activation`]) over the persisted request bytes
/// against evidence that lives outside those three artifacts:
///
/// - the **authorizing policy**, whose crate-private witness is fed by a durable
///   head audit, supplies the eligible keys, the threshold, and the
///   separation-of-duty rule, and every approval signature must verify under it;
/// - the **target package**, built from real manifest-verified bytes, must be
///   exactly the package the statement names, and it fixes the activation
///   policy the resulting head installs;
/// - the **conformance result**, pinned to an out-of-band runner identity, must
///   be exactly the result the statement names.
///
/// Only then are the receipt and the event admitted, and only by full
/// re-derivation: [`GenericSuccessorActivationReceiptV2::validate_against`]
/// requires the receipt's approval attestations, threshold, and
/// separation-of-duty verdict to be the ones the verifier just derived, and
/// [`GenericSuccessorActivatedEventV2::validate_against`] requires the event to
/// equal the event those two produce. A package that never passed conformance
/// and a policy that was never installed cannot enter a contender at all, and
/// an approver set that never signed cannot either.
#[derive(Debug, Clone)]
pub struct AuditedContenderActivationV2 {
    activation: VerifiedGenericSuccessorActivation,
    receipt: GenericSuccessorActivationReceiptV2,
    event: GenericSuccessorActivatedEventV2,
    activation_id: GenericSuccessorActivationId,
}

impl AuditedContenderActivationV2 {
    /// Mint the contender witness from durable bytes read under one stream lock.
    ///
    /// The caller must have read the request bytes, the receipt, and the event
    /// from the accepted event history of the same scope in the same
    /// transaction, and must supply the authorizing policy, the target package,
    /// and the conformance result as the out-of-band evidence they are.
    ///
    /// The proposer and package author are the one pair the audit cannot
    /// re-derive from policy: no receipt or event carries them. They are bound
    /// instead by hashing - the statement must hash to `receipt.statement_id` -
    /// so the ceremony-time [`GenericSuccessorPrincipalBinding`] is rebuilt from
    /// the audited statement rather than re-imposed here. Naming a principal in
    /// a contender therefore costs a real threshold-satisfying ceremony under
    /// the authorizing policy's own keys.
    #[allow(dead_code)] // consumed by the successor repository in the next increment
    pub(crate) fn from_durable_audit(
        authorizing_policy: &InstalledSuccessorPolicyV2,
        audit: &ContenderActivationAuditV2<'_>,
    ) -> ContractResult<Self> {
        require_canonical(audit.canonical_statement)?;
        let statement: GenericSuccessorActivationStatementV2 =
            decode_strict(audit.canonical_statement)?;
        statement.validate_shape()?;
        let principal_binding = GenericSuccessorPrincipalBinding::from_trusted_config(
            statement.proposer_principal_id,
            statement.package_author_principal_id,
        );
        // The full ceremony verifier, re-run over persisted bytes: canonical
        // form, package and conformance binding, signature verification under
        // the installed keys, eligibility, threshold, and separation of duty.
        let activation = verify_generic_successor_activation(
            audit.canonical_statement,
            audit.canonical_approval_set,
            authorizing_policy,
            audit.target,
            audit.test_result,
            &principal_binding,
        )?;
        // The persisted receipt and event are admitted only if they are exactly
        // the ones that verified request produces.
        audit.receipt.validate_against(&activation)?;
        audit.event.validate_against(&activation, audit.receipt)?;
        let activation_id = audit.receipt.activation_id()?;
        Ok(Self {
            activation,
            receipt: audit.receipt.clone(),
            event: audit.event.clone(),
            activation_id,
        })
    }

    pub const fn activation(&self) -> &VerifiedGenericSuccessorActivation {
        &self.activation
    }

    pub const fn statement(&self) -> &GenericSuccessorActivationStatementV2 {
        self.activation.statement()
    }

    pub const fn receipt(&self) -> &GenericSuccessorActivationReceiptV2 {
        &self.receipt
    }

    pub const fn event(&self) -> &GenericSuccessorActivatedEventV2 {
        &self.event
    }

    pub const fn activation_id(&self) -> GenericSuccessorActivationId {
        self.activation_id
    }

    /// Derive - never accept - this contender's contested-set record.
    fn contender(&self) -> ContractResult<ContestedSuccessorV1> {
        // `eligible_approvals` is attestation-sorted and committed by the
        // activation ID; the contested record carries the same principals in
        // principal order.
        let mut approving_principal_ids = self
            .receipt
            .eligible_approvals
            .iter()
            .map(|approval| approval.principal_id.clone())
            .collect::<Vec<_>>();
        approving_principal_ids.sort_unstable();
        let statement = self.statement();
        let contender = ContestedSuccessorV1 {
            activation_id: self.activation_id,
            statement_id: self.receipt.statement_id,
            to_generation: self.receipt.to_generation,
            activated_head: self.event.activated_head.clone(),
            proposer_principal_id: statement.proposer_principal_id.clone(),
            package_author_principal_id: statement.package_author_principal_id.clone(),
            approving_principal_ids,
        };
        contender.validate_shape()?;
        Ok(contender)
    }
}

/// A contested set whose every member was re-derived from durable activation
/// artifacts under the repository's stream lock.
///
/// [`verify_contested_set_resolution`] accepts nothing else. The wire form
/// [`RegistryContestedSetV1`] is a *projection* of this value, never an input
/// to it: the contenders, the authorizing head, the authorizing policy
/// reference, and the contested generation are all computed here from the
/// audited authority. Two consequences a plain wire struct cannot give:
///
/// - a fabricated contender cannot install an arbitrary head through the
///   resolution receipt, because every head here comes from a request whose
///   approvals verified under the authorizing policy's installed keys, against
///   real package bytes and a runner-pinned conformance result;
/// - whoever supplies the set cannot choose who is barred from driving the
///   resolution, because the barred principal sets are read out of the same
///   audited statements - and naming a principal in one costs a real
///   threshold-satisfying ceremony under those same keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditedContestedSetV1 {
    set: RegistryContestedSetV1,
}

impl AuditedContestedSetV1 {
    /// Build the contested set from the authorizing policy and the audited
    /// activations of its contenders.
    ///
    /// `authorizing_policy` is the installed policy of the last common
    /// unambiguous predecessor: the head every contender tried to succeed. The
    /// contested generation is that policy's generation plus one and is never a
    /// caller claim, so a contest can only be resolved by the policy of the
    /// generation it actually forks from.
    ///
    /// Each contender was already re-verified under *an* authorizing policy when
    /// its [`AuditedContenderActivationV2`] was minted. This constructor re-runs
    /// the governance half against *this* policy, so a witness minted elsewhere
    /// cannot be carried into a contest the policy does not govern.
    #[allow(dead_code)] // consumed by the successor repository in the next increment
    pub(crate) fn from_durable_audit(
        authorizing_policy: &InstalledSuccessorPolicyV2,
        contenders: &[AuditedContenderActivationV2],
    ) -> ContractResult<Self> {
        let policy = authorizing_policy.policy();
        policy.validate()?;
        let contested_generation = authorizing_policy
            .generation()
            .checked_add(1)
            .ok_or_else(|| ContractError::Schema("contested generation overflow".into()))?;
        let mut records = Vec::with_capacity(contenders.len());
        for audited in contenders {
            let statement = audited.statement();
            let receipt = audited.receipt();
            if statement.profile != *authorizing_policy.profile()
                || statement.scope != *authorizing_policy.scope()
                || statement.expected_predecessor_head != *authorizing_policy.head()
                || statement.current_activation_policy != *authorizing_policy.policy_reference()
                || statement.from_generation != authorizing_policy.generation()
                || statement.to_generation != contested_generation
                // The receipt's server-derived verdict must be this policy's,
                // not one the contender chose for itself.
                || receipt.required_threshold != policy.approval_threshold
                || receipt.applied_separation_of_duty != policy.separation_of_duty
            {
                return Err(ContractError::ManifestMismatch);
            }
            require_contender_approvals_under_policy(policy, statement, receipt)?;
            records.push(audited.contender()?);
        }
        records.sort_by(|left, right| left.activation_id.cmp(&right.activation_id));
        let set = RegistryContestedSetV1 {
            schema_version: CONTESTED_SCHEMA_VERSION,
            profile: authorizing_policy.profile().clone(),
            scope: authorizing_policy.scope().clone(),
            last_unambiguous_head: authorizing_policy.head().clone(),
            last_unambiguous_activation_policy: authorizing_policy.policy_reference().clone(),
            contested_generation,
            contenders: records,
        };
        set.validate_shape()?;
        Ok(Self { set })
    }

    pub const fn set(&self) -> &RegistryContestedSetV1 {
        &self.set
    }

    pub fn contested_set_id(&self) -> ContractResult<RegistryContestedSetId> {
        self.set.contested_set_id()
    }

    pub fn contested_activation_ids(&self) -> ContractResult<Vec<GenericSuccessorActivationId>> {
        self.set.contested_activation_ids()
    }

    /// A published contested-set record is only a projection of this value.
    pub fn require_wire_form(&self, wire: &RegistryContestedSetV1) -> ContractResult<()> {
        if &self.set != wire {
            return Err(ContractError::ManifestMismatch);
        }
        Ok(())
    }
}

/// Trusted identity of the principal actually driving one contested-set
/// resolution ceremony.
///
/// The resolution statement repeats the proposer so the approvals commit to it,
/// but it cannot *choose* it: [`verify_contested_set_resolution`] requires exact
/// equality to this non-serializable binding, which comes from authenticated
/// configuration exactly as [`GenericSuccessorPrincipalBinding`] does for an
/// activation.
///
/// Without it the no-self-selection bar would test a string the requester picked
/// out of the payload: a barred contestant could drive the resolution simply by
/// writing a different name. Authenticating the barred sets (they are read out
/// of [`AuditedContestedSetV1`]) is only half the comparison; this is the other
/// half - the subject being tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContestedResolutionPrincipalBinding {
    proposer_principal_id: ContractId,
}

impl ContestedResolutionPrincipalBinding {
    pub const fn from_trusted_config(proposer_principal_id: ContractId) -> Self {
        Self {
            proposer_principal_id,
        }
    }
}

/// Unsigned statement selecting exactly one member of an exact contested set.
///
/// `contested_activation_ids` is the compare-and-swap precondition: resolution
/// commits only against that exact set, so a contender appearing later cannot be
/// silently excluded by an in-flight resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContestedSetResolutionStatementV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub contested_set_id: RegistryContestedSetId,
    pub contested_activation_ids: Vec<GenericSuccessorActivationId>,
    pub selected_activation_id: GenericSuccessorActivationId,
    pub authorizing_activation_policy: RegistryReferenceV1,
    pub effective_from: CanonicalTimestamp,
    pub proposer_principal_id: ContractId,
}

impl ContestedSetResolutionStatementV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        validate_registry_reference(&self.authorizing_activation_policy)?;
        if self.schema_version != CONTESTED_SCHEMA_VERSION
            || self.contested_set_id.digest() == Sha256Digest::ZERO
            || self.contested_activation_ids.len() < 2
            || self.contested_activation_ids.len() > MAX_CONTESTED_SUCCESSORS
            || !strictly_sorted(&self.contested_activation_ids)
            || !self
                .contested_activation_ids
                .contains(&self.selected_activation_id)
            || self.authorizing_activation_policy.version < MIN_ACTIVATION_POLICY_VERSION
            || !self.effective_from.is_microsecond_aligned()
        {
            return Err(ContractError::Schema(
                "invalid contested set resolution statement v1".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }

    pub fn statement_id(&self) -> ContractResult<ContestedSetResolutionStatementId> {
        self.validate_shape()?;
        Ok(ContestedSetResolutionStatementId::from_digest(
            domain_separated_digest(
                DigestDomain::RegistryContestedResolutionStatementV1,
                &encode_canonical(self)?,
            ),
        ))
    }
}

/// One fresh Ed25519 approval of a contested-set resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContestedSetResolutionApprovalV1 {
    pub schema_version: u32,
    pub statement_id: ContestedSetResolutionStatementId,
    pub signer_principal_id: ContractId,
    pub signature: FixedHex64,
}

impl ContestedSetResolutionApprovalV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != CONTESTED_SCHEMA_VERSION
            || self.statement_id.digest() == Sha256Digest::ZERO
            || self.signature.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(ContractError::Schema(
                "invalid contested set resolution approval v1".into(),
            ));
        }
        Ok(())
    }

    pub fn approval_id(&self) -> ContractResult<ContestedSetResolutionApprovalId> {
        self.validate_shape()?;
        Ok(ContestedSetResolutionApprovalId::from_digest(
            domain_separated_digest(
                DigestDomain::RegistryContestedResolutionApprovalV1,
                &encode_canonical(self)?,
            ),
        ))
    }
}

/// Canonical principal-sorted approval set for one resolution statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContestedSetResolutionApprovalSetV1 {
    pub schema_version: u32,
    pub statement_id: ContestedSetResolutionStatementId,
    pub approvals: Vec<ContestedSetResolutionApprovalV1>,
}

impl ContestedSetResolutionApprovalSetV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != CONTESTED_SCHEMA_VERSION
            || self.statement_id.digest() == Sha256Digest::ZERO
            || self.approvals.is_empty()
            || self.approvals.len() > MAX_GENERIC_APPROVALS
            || !self
                .approvals
                .windows(2)
                .all(|pair| pair[0].signer_principal_id < pair[1].signer_principal_id)
        {
            return Err(ContractError::Schema(
                "invalid contested set resolution approval set v1".into(),
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

/// Canonical, cryptographically verified, non-durable contested resolution.
#[derive(Debug, Clone)]
pub struct VerifiedContestedSetResolution {
    statement: ContestedSetResolutionStatementV1,
    canonical_statement: Vec<u8>,
    approval_set: ContestedSetResolutionApprovalSetV1,
    canonical_approval_set: Vec<u8>,
    selected_head: RegistryHeadBindingV1,
    eligible_approvals: Vec<EligibleApprovalV1>,
    required_threshold: u16,
}

impl VerifiedContestedSetResolution {
    pub const fn statement(&self) -> &ContestedSetResolutionStatementV1 {
        &self.statement
    }

    pub fn canonical_statement(&self) -> &[u8] {
        &self.canonical_statement
    }

    pub const fn approval_set(&self) -> &ContestedSetResolutionApprovalSetV1 {
        &self.approval_set
    }

    pub fn canonical_approval_set(&self) -> &[u8] {
        &self.canonical_approval_set
    }

    pub const fn selected_head(&self) -> &RegistryHeadBindingV1 {
        &self.selected_head
    }

    pub fn eligible_approvals(&self) -> &[EligibleApprovalV1] {
        &self.eligible_approvals
    }

    pub const fn required_threshold(&self) -> u16 {
        self.required_threshold
    }

    /// Mint the resolution receipt only from a re-audited authority, at
    /// repository-supplied server time.
    ///
    /// Verification proves bytes and approvals, never freshness. Like
    /// [`VerifiedGenericSuccessorActivation::receipt_at`], the accepted form
    /// cannot exist without re-presenting the authority that is current *now*:
    /// the re-audited last common unambiguous policy and the re-audited
    /// contested set. Both the exact contested activation-ID set and the
    /// selected contender's own head are compare-and-swapped against it.
    #[allow(dead_code)] // consumed by the successor repository in the next increment
    pub(crate) fn receipt_at(
        &self,
        reaudited_policy: &InstalledSuccessorPolicyV2,
        reaudited_set: &AuditedContestedSetV1,
        accepted_at: CanonicalTimestamp,
    ) -> ContractResult<ContestedSetResolutionReceiptV1> {
        // The exact contested activation-ID set is the compare-and-swap
        // precondition; report set drift before any other binding mismatch.
        if self.statement.contested_activation_ids != reaudited_set.contested_activation_ids()? {
            return Err(ContractError::StaleRegistryHead);
        }
        require_resolution_binding(&self.statement, reaudited_set, reaudited_policy)?;
        let selected = reaudited_set
            .set()
            .contenders
            .iter()
            .find(|contender| contender.activation_id == self.statement.selected_activation_id)
            .ok_or(ContractError::ManifestMismatch)?;
        if selected.activated_head != self.selected_head {
            return Err(ContractError::ManifestMismatch);
        }
        if !accepted_at.is_microsecond_aligned() || accepted_at < self.statement.effective_from {
            return Err(ContractError::Schema(
                "contested set resolution is outside the server-time interval".into(),
            ));
        }
        let receipt = ContestedSetResolutionReceiptV1 {
            schema_version: CONTESTED_SCHEMA_VERSION,
            statement_id: self.statement.statement_id()?,
            contested_set_id: self.statement.contested_set_id,
            contested_activation_ids: self.statement.contested_activation_ids.clone(),
            selected_activation_id: self.statement.selected_activation_id,
            selected_head: self.selected_head.clone(),
            authorizing_activation_policy: self.statement.authorizing_activation_policy.clone(),
            eligible_approvals: self.eligible_approvals.clone(),
            required_threshold: self.required_threshold,
            self_selection_excluded: true,
            accepted_at,
        };
        receipt.validate_against(self)?;
        Ok(receipt)
    }
}

/// Verify one canonical contested-set resolution.
///
/// `authorizing_policy` must be the installed policy of the **last common
/// unambiguous predecessor** — the head both contenders tried to succeed — or a
/// separately deployment-pinned break-glass policy audited into the same
/// typestate. `audited_set` must be the matching [`AuditedContestedSetV1`]: no
/// contender may be a claim, so no receipt can install a head that no activation
/// produced. The contested generation must be exactly the authorizing policy's
/// generation plus one.
///
/// `principal_binding` is the authenticated identity of the party driving the
/// ceremony. The payload's `proposer_principal_id` must equal it exactly, which
/// is what makes the bar below meaningful: no contender's proposer, package
/// author, or approver may *propose* the resolution, and no contender's proposer
/// or package author may be counted among its approvers, so neither contested
/// successor can authorize its own selection by relabelling itself.
///
/// The approver half of that bar is deliberately narrower than the proposer
/// half: an eligible signer of the last common unambiguous predecessor policy
/// who merely approved a contender may still approve the resolution. Those
/// signers are the authority the contest falls back to; barring them outright
/// would make a contest between two quorum-approved contenders structurally
/// unresolvable whenever the predecessor policy's signer set is exactly its
/// threshold.
pub fn verify_contested_set_resolution(
    canonical_statement: &[u8],
    canonical_approval_set: &[u8],
    audited_set: &AuditedContestedSetV1,
    authorizing_policy: &InstalledSuccessorPolicyV2,
    principal_binding: &ContestedResolutionPrincipalBinding,
) -> ContractResult<VerifiedContestedSetResolution> {
    let contested_set = audited_set.set();
    require_canonical(canonical_statement)?;
    let statement: ContestedSetResolutionStatementV1 = decode_strict(canonical_statement)?;
    statement.validate_shape()?;
    if encode_canonical(&statement)? != canonical_statement {
        return Err(ContractError::NotCanonical);
    }
    // The proposer is authenticated before anything is decided about it. A
    // payload label the requester chose would make the no-self-selection bar a
    // test of a string the requester also chose.
    if statement.proposer_principal_id != principal_binding.proposer_principal_id {
        return Err(ContractError::ManifestMismatch);
    }

    // Compare-and-swap on the exact contested activation-ID set, first and on
    // its own, so a contender that appeared after the statement was written is
    // reported as a stale precondition rather than a generic binding mismatch.
    if statement.contested_activation_ids != contested_set.contested_activation_ids()? {
        return Err(ContractError::StaleRegistryHead);
    }

    let policy = authorizing_policy.policy();
    policy.validate()?;
    require_resolution_binding(&statement, audited_set, authorizing_policy)?;
    let selected = contested_set
        .contenders
        .iter()
        .find(|contender| contender.activation_id == statement.selected_activation_id)
        .ok_or(ContractError::ManifestMismatch)?;

    require_canonical(canonical_approval_set)?;
    let approval_set: ContestedSetResolutionApprovalSetV1 = decode_strict(canonical_approval_set)?;
    approval_set.validate_shape()?;
    if encode_canonical(&approval_set)? != canonical_approval_set {
        return Err(ContractError::NotCanonical);
    }
    let statement_id = statement.statement_id()?;
    if approval_set.statement_id != statement_id
        || approval_set.approvals.len() > policy.eligible_signers.len()
    {
        return Err(ContractError::SignatureVerification);
    }

    let signature_message =
        approval_signature_message(CONTESTED_RESOLUTION_SIGNATURE_PREFIX, statement_id.digest());
    let mut approving_principal_ids = Vec::with_capacity(approval_set.approvals.len());
    let mut eligible_approvals = Vec::with_capacity(approval_set.approvals.len());
    for approval in &approval_set.approvals {
        let signer = policy
            .eligible_signers
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

    validate_resolution_principal_set(
        policy,
        contested_set,
        &statement.proposer_principal_id,
        &approving_principal_ids,
    )?;
    eligible_approvals.sort_unstable();
    if !approval_bindings_are_unique(&eligible_approvals) || !strictly_sorted(&eligible_approvals) {
        return Err(ContractError::SignatureVerification);
    }

    Ok(VerifiedContestedSetResolution {
        statement,
        canonical_statement: canonical_statement.to_vec(),
        approval_set,
        canonical_approval_set: canonical_approval_set.to_vec(),
        selected_head: selected.activated_head.clone(),
        eligible_approvals,
        required_threshold: policy.approval_threshold,
    })
}

/// Server-derived receipt closing one contested set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContestedSetResolutionReceiptV1 {
    pub schema_version: u32,
    pub statement_id: ContestedSetResolutionStatementId,
    pub contested_set_id: RegistryContestedSetId,
    pub contested_activation_ids: Vec<GenericSuccessorActivationId>,
    pub selected_activation_id: GenericSuccessorActivationId,
    pub selected_head: RegistryHeadBindingV1,
    pub authorizing_activation_policy: RegistryReferenceV1,
    pub eligible_approvals: Vec<EligibleApprovalV1>,
    pub required_threshold: u16,
    pub self_selection_excluded: bool,
    pub accepted_at: CanonicalTimestamp,
}

impl ContestedSetResolutionReceiptV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.selected_head.validate_shape()?;
        validate_registry_reference(&self.authorizing_activation_policy)?;
        if self.schema_version != CONTESTED_SCHEMA_VERSION
            || self.statement_id.digest() == Sha256Digest::ZERO
            || self.contested_set_id.digest() == Sha256Digest::ZERO
            || self.contested_activation_ids.len() < 2
            || self.contested_activation_ids.len() > MAX_CONTESTED_SUCCESSORS
            || !strictly_sorted(&self.contested_activation_ids)
            || !self
                .contested_activation_ids
                .contains(&self.selected_activation_id)
            || self.selected_head.head.activation_id != self.selected_activation_id.digest()
            || self.authorizing_activation_policy.version < MIN_ACTIVATION_POLICY_VERSION
            || self.required_threshold == 0
            || usize::from(self.required_threshold) > self.eligible_approvals.len()
            || self.eligible_approvals.len() > MAX_GENERIC_APPROVALS
            || !strictly_sorted(&self.eligible_approvals)
            || !approval_bindings_are_unique(&self.eligible_approvals)
            || !self.self_selection_excluded
            || !self.accepted_at.is_microsecond_aligned()
        {
            return Err(ContractError::Schema(
                "invalid contested set resolution receipt v1".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }

    pub fn resolution_id(&self) -> ContractResult<ContestedSetResolutionId> {
        self.validate_shape()?;
        Ok(ContestedSetResolutionId::from_digest(
            domain_separated_digest(
                DigestDomain::RegistryContestedResolutionReceiptV1,
                &encode_canonical(self)?,
            ),
        ))
    }

    pub fn validate_against(
        &self,
        resolution: &VerifiedContestedSetResolution,
    ) -> ContractResult<()> {
        self.validate_shape()?;
        let statement = resolution.statement();
        if self.statement_id != statement.statement_id()?
            || self.contested_set_id != statement.contested_set_id
            || self.contested_activation_ids != statement.contested_activation_ids
            || self.selected_activation_id != statement.selected_activation_id
            || self.selected_head != resolution.selected_head
            || self.authorizing_activation_policy != statement.authorizing_activation_policy
            || self.eligible_approvals != resolution.eligible_approvals
            || self.required_threshold != resolution.required_threshold
            || self.accepted_at < statement.effective_from
        {
            return Err(ContractError::ManifestMismatch);
        }
        Ok(())
    }
}

/// Bind one resolution statement to the audited contest and its authorizing
/// policy.
///
/// The contested generation must be exactly the authorizing policy's generation
/// plus one: the generation an [`InstalledSuccessorPolicyV2`] claims is not
/// derivable from its head bytes, so head equality alone cannot pin it, and a
/// contest must be resolvable only by the policy of the generation it forks
/// from. The resolution must also follow every contender it chooses between.
fn require_resolution_binding(
    statement: &ContestedSetResolutionStatementV1,
    audited_set: &AuditedContestedSetV1,
    authorizing_policy: &InstalledSuccessorPolicyV2,
) -> ContractResult<()> {
    let contested_set = audited_set.set();
    let expected_contested_generation = authorizing_policy
        .generation()
        .checked_add(1)
        .ok_or_else(|| ContractError::Schema("contested generation overflow".into()))?;
    if statement.profile != *authorizing_policy.profile()
        || statement.profile != contested_set.profile
        || statement.scope != *authorizing_policy.scope()
        || statement.scope != contested_set.scope
        || statement.authorizing_activation_policy != *authorizing_policy.policy_reference()
        || statement.authorizing_activation_policy
            != contested_set.last_unambiguous_activation_policy
        || *authorizing_policy.head() != contested_set.last_unambiguous_head
        || contested_set.contested_generation != expected_contested_generation
        || statement.contested_set_id != audited_set.contested_set_id()?
    {
        return Err(ContractError::ManifestMismatch);
    }
    // A resolution cannot claim to take effect before the contest it resolves
    // existed: it must follow every contender it chooses between.
    if contested_set
        .contenders
        .iter()
        .any(|contender| statement.effective_from <= contender.activated_head.effective_from)
    {
        return Err(ContractError::Schema(
            "a contested resolution cannot take effect before its contenders".into(),
        ));
    }
    Ok(())
}

/// Re-apply one authorizing policy to a contender's persisted receipt.
///
/// The contender audit already verified these approvals cryptographically; this
/// re-states the governance verdict against the policy that is about to govern
/// the contest, so an audited witness cannot be carried across policies. Every
/// attestation must name a principal the policy still lists, under that
/// principal's currently installed key ID, and the whole set must satisfy
/// [`ActivationPolicyEntryV2::validate_approval_principal_set`] - eligibility,
/// canonical order, threshold, and strong separation of duty alike.
fn require_contender_approvals_under_policy(
    policy: &ActivationPolicyEntryV2,
    statement: &GenericSuccessorActivationStatementV2,
    receipt: &GenericSuccessorActivationReceiptV2,
) -> ContractResult<()> {
    for approval in &receipt.eligible_approvals {
        let signer = policy
            .eligible_signers
            .iter()
            .find(|binding| binding.principal_id == approval.principal_id)
            .ok_or_else(|| {
                ContractError::InvalidSignerPolicy(
                    "contested contender approval principal is not eligible".into(),
                )
            })?;
        if signer.signer_key_id()? != approval.signer_key_id {
            return Err(ContractError::InvalidSignerPolicy(
                "contested contender approval names an uninstalled signer key".into(),
            ));
        }
    }
    let mut approving_principal_ids = receipt
        .eligible_approvals
        .iter()
        .map(|approval| approval.principal_id.clone())
        .collect::<Vec<_>>();
    approving_principal_ids.sort_unstable();
    policy.validate_approval_principal_set(
        &statement.package_author_principal_id,
        &statement.proposer_principal_id,
        &approving_principal_ids,
    )
}

/// Apply eligibility, threshold, canonical ordering, and the no-self-selection
/// rule to one resolution approval set.
fn validate_resolution_principal_set(
    policy: &ActivationPolicyEntryV2,
    contested_set: &RegistryContestedSetV1,
    proposer_principal_id: &ContractId,
    approving_principal_ids: &[ContractId],
) -> ContractResult<()> {
    if approving_principal_ids.len() > policy.eligible_signers.len()
        || !strictly_sorted(approving_principal_ids)
    {
        return Err(ContractError::NonCanonicalSet {
            field: "approving_principal_ids",
        });
    }
    if approving_principal_ids
        .iter()
        .any(|principal| principal == proposer_principal_id)
    {
        return Err(ContractError::Schema(
            "the contested-resolution proposer cannot also approve it".into(),
        ));
    }
    if approving_principal_ids.iter().any(|principal| {
        !policy
            .eligible_signers
            .iter()
            .any(|binding| &binding.principal_id == principal)
    }) {
        return Err(ContractError::InvalidSignerPolicy(
            "contested-resolution approval principal is not eligible".into(),
        ));
    }
    // Neither contested successor may authorize its own selection. Nobody who
    // proposed, authored, or approved a contender may drive the resolution, and
    // no contender's proposer or package author may be counted as an approver.
    // Eligible signers of the last common unambiguous predecessor policy are
    // otherwise the legitimate deciders: they are the authority the contest
    // fell back to, not the parties that created it.
    let drivers = contested_set
        .contenders
        .iter()
        .flat_map(ContestedSuccessorV1::self_selecting_principals)
        .collect::<BTreeSet<_>>();
    let proposing = contested_set
        .contenders
        .iter()
        .flat_map(ContestedSuccessorV1::proposing_principals)
        .collect::<BTreeSet<_>>();
    if drivers.contains(proposer_principal_id)
        || approving_principal_ids
            .iter()
            .any(|principal| proposing.contains(principal))
    {
        return Err(ContractError::Schema(
            "a contested successor cannot authorize its own selection".into(),
        ));
    }
    if approving_principal_ids.len() < usize::from(policy.approval_threshold) {
        return Err(ContractError::ApprovalThresholdNotMet);
    }
    Ok(())
}

fn validate_generic_test_result_shape(result: &RegistryTestResultV1) -> ContractResult<()> {
    result.profile.require_frozen_runtime_profile()?;
    if result.schema_version != REGISTRY_TEST_RESULT_SCHEMA_VERSION
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
            "invalid generic successor registry test result".into(),
        ));
    }
    encode_canonical(result)?;
    Ok(())
}

fn generic_test_result_digest(
    result: &RegistryTestResultV1,
) -> ContractResult<RegistryTestResultDigest> {
    validate_generic_test_result_shape(result)?;
    Ok(RegistryTestResultDigest::from_digest(
        domain_separated_digest(DigestDomain::RegistryTestResult, &encode_canonical(result)?),
    ))
}

fn validate_registry_reference(reference: &RegistryReferenceV1) -> ContractResult<()> {
    reference.validate()?;
    if reference.entry_digest == Sha256Digest::ZERO {
        return Err(ContractError::Schema(
            "generic successor reference cannot use the zero digest".into(),
        ));
    }
    Ok(())
}

fn approval_signature_message(prefix: &[u8], statement_id: Sha256Digest) -> Vec<u8> {
    let mut message = Vec::with_capacity(prefix.len() + 32);
    message.extend_from_slice(prefix);
    message.extend_from_slice(statement_id.as_bytes());
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
#[path = "successor_generic_tests.rs"]
mod tests;
