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
mod tests {
    use std::{env, fs, path::Path};

    use ring::signature::Ed25519KeyPair;
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::memory_contracts::{
        common::frozen_profile_reference_v1,
        registry::{RegistryEntryV1, RegistryManifestEntryV1, RegistryPackageV1},
    };

    // Frozen inputs owned by earlier workstreams. They are read, never written.
    const GENERATION_ONE_PACKAGE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");
    const GENERATION_ONE_HEAD_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-activation/activated-head.jsonl"
    );
    const ACTIVATION_POLICY_ENTRY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-policy/activation-policy-v2.jsonl"
    );

    const GENERATION_TWO_PACKAGE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/generation-2-package.jsonl"
    );
    const ACTIVATION_TEST_RESULT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/activation-test-result.jsonl"
    );
    const ACTIVATION_STATEMENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/activation-statement.jsonl"
    );
    const ACTIVATION_APPROVAL_SET_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/activation-approval-set.jsonl"
    );
    const ACTIVATION_RECEIPT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/activation-receipt.jsonl"
    );
    const ACTIVATED_HEAD_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/successor-generic/activated-head.jsonl");
    const ACTIVATION_EVENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/activation-event.jsonl"
    );
    const ROLLBACK_TEST_RESULT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/rollback-test-result.jsonl"
    );
    const ROLLBACK_STATEMENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/rollback-statement.jsonl"
    );
    const ROLLBACK_APPROVAL_SET_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/rollback-approval-set.jsonl"
    );
    const ROLLBACK_RECEIPT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/rollback-receipt.jsonl"
    );
    const ROLLBACK_HEAD_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/rollback-activated-head.jsonl"
    );
    const ROLLBACK_EVENT_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/successor-generic/rollback-event.jsonl");
    const RIVAL_STATEMENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/contested-rival-statement.jsonl"
    );
    const RIVAL_APPROVAL_SET_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/contested-rival-approval-set.jsonl"
    );
    const RIVAL_RECEIPT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/contested-rival-receipt.jsonl"
    );
    const CONTESTED_SET_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/successor-generic/contested-set.jsonl");
    const RESOLUTION_STATEMENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/contested-resolution-statement.jsonl"
    );
    const RESOLUTION_APPROVAL_SET_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/contested-resolution-approval-set.jsonl"
    );
    const RESOLUTION_RECEIPT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/contested-resolution-receipt.jsonl"
    );
    const POSITIVE_VECTORS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/positive-vectors.jsonl"
    );
    const NEGATIVE_VECTORS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/successor-generic/negative-vectors.jsonl"
    );
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/successor-generic/vector-suite.jsonl");

    /// The one-shot generation `0 -> 1` approval prefix. Approvals produced with
    /// it must never verify here: generic transitions use no key bridge.
    const BRIDGE_APPROVAL_SIGNATURE_PREFIX: &[u8] =
        b"ostk-registry-successor-activation-approval-signature-v1\0";

    const SUITE_ID: &str = "registry.successor-generic.v2";
    const FIXTURE_AUTHORITY: &str =
        "none; public fixture seeds and structural bytes never authorize a registry transition";

    const RUNNER_ARTIFACT_DIGEST: &str =
        "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    const RUNNER_CONFIGURATION_DIGEST: &str =
        "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";

    const GENERATION_ONE_PACKAGE_DIGEST: &str =
        "16f98d5df93b74dab5b2188274cbd1da21d089ff7a64cd8fc29679946e7fe2c9";
    const GENERATION_ONE_ACTIVATION_ID: &str =
        "60fe4eb627dab5e7798a22188218c308063de7eca121ea7f4b267f9ab23db4bb";
    const ACTIVATION_POLICY_ENTRY_DIGEST: &str =
        "5611a4fea75d0a8132395bf6e3040ce97638a3447e290f5cabc183c1bb9faa6c";

    const PREDECESSOR_ACCEPTED_AT: &str = "2026-08-15T04:10:00.000000000Z";
    const GENERATION_TWO_TEST_COMPLETED_AT: &str = "2026-08-16T04:00:00.000000000Z";
    const GENERATION_TWO_EFFECTIVE_FROM: &str = "2026-08-16T04:10:00.000000000Z";
    const GENERATION_THREE_TEST_COMPLETED_AT: &str = "2026-08-17T04:00:00.000000000Z";
    const GENERATION_THREE_EFFECTIVE_FROM: &str = "2026-08-17T04:10:00.000000000Z";
    const RESOLUTION_EFFECTIVE_FROM: &str = "2026-08-18T04:10:00.000000000Z";

    const GENERATION_TWO_PACKAGE_DIGEST: &str =
        "49fb2c6db81008b5ed8acd781e297e7d0a3ed49f6b1ff639618cd7d83296190a";
    const GENERATION_TWO_STATEMENT_ID: &str =
        "64fd15dc659c800496ca3fa598b06a51d605b08788870f7acc1f35380f557bf6";
    const GENERATION_TWO_ACTIVATION_ID: &str =
        "0fc0b1e4214c2c9e11f3ee63af05ea46de93e39a02aadd115cecaf4247ac7b31";
    const GENERATION_TWO_ACCEPTED_EVENT_ID: &str =
        "2ddccbc871e8b4dd89c503d06fc8341254d6a4a6ec5957bf639ee20262b85597";
    const ROLLBACK_STATEMENT_ID: &str =
        "c900386b859932a89cb9a221f8675baa46d9b19e37754b12328a1fbc58f96b84";
    const ROLLBACK_ACTIVATION_ID: &str =
        "ac335f07967e0bb8861274984731b835caac5aebb5aca45b56bb05f769f4bcab";
    const ROLLBACK_ACCEPTED_EVENT_ID: &str =
        "cf0352dc993c96ca710e49d521fc51805df532fbdf00ae1988e763b1ac68fb4f";
    const RIVAL_STATEMENT_ID: &str =
        "4c82bb9903393f82c3c9f13e9ede86db576856e8aceac02a1f5d6492a8d949e1";
    const RIVAL_ACTIVATION_ID: &str =
        "a0468c76b84897e6783ca0e0f2c7ef1edc36a8ee00a5cf4e8ee6144ed7fc0118";
    const CONTESTED_SET_ID: &str =
        "6c5bff5cdc424d44400dfb8f50ec18cf4376605ed47a99893ebe661030c52b82";
    const RESOLUTION_STATEMENT_ID: &str =
        "97665d1abeb5c33e517d2be2cc4e5ca3d54d39f9700dcc0e80adeb7a268b1410";
    const RESOLUTION_ID: &str = "0f42d0373321e061ba3dfb286bc391fbc6fb66726a0afd7fc44fe93b80f01187";
    const CONSISTENCY_KEY_DIGEST: &str =
        "9921b7e572be77d3e100eb3d3093fb0d8ff4b3b5965f75110c18bfd34479b5ec";
    const POSITIVE_CASES_DIGEST: &str =
        "77e02c9c9565ac6b25c1dc1084a58ae1e8c8b07b62180a8d23bafa9310d8eedb";
    const NEGATIVE_CASES_DIGEST: &str =
        "04b82a8819842356925ca00ff032bb86ffecf9708207058ced8fb48fd1a45614";
    const VECTOR_SUITE_RAW_SHA256: &str =
        "52de3abd84b961c6c654bfe6d06d39b967533f747420c716a1337a45c1c886f7";
    const VECTOR_SUITE_DIGEST: &str =
        "101342044d9080270267c58b7790dc264d8f67d6d8e2d144d03e3afcbbc88519";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum CaseOutcomeV1 {
        Accept,
        Reject,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CaseManifestV1 {
        schema_version: u32,
        suite_id: ContractId,
        expected_outcome: CaseOutcomeV1,
        cases: Vec<ContractId>,
    }

    impl CaseManifestV1 {
        fn validate(&self, expected_outcome: CaseOutcomeV1) {
            assert_eq!(self.schema_version, SUCCESSOR_GENERIC_SCHEMA_VERSION);
            assert_eq!(self.suite_id.as_str(), SUITE_ID);
            assert_eq!(self.expected_outcome, expected_outcome);
            assert!(!self.cases.is_empty());
            assert!(strictly_sorted(&self.cases));
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ArtifactPinV1 {
        path: String,
        raw_sha256: Sha256Digest,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct VectorSuiteV1 {
        schema_version: u32,
        suite_id: ContractId,
        fixture_authority: String,
        predecessor_head: RegistryHeadBindingV1,
        current_activation_policy: RegistryReferenceV1,
        generation_two_package_digest: Sha256Digest,
        generation_two_statement_id: GenericSuccessorActivationStatementId,
        generation_two_approval_ids: Vec<GenericSuccessorActivationApprovalId>,
        generation_two_activation_id: GenericSuccessorActivationId,
        generation_two_accepted_event_id: AcceptedEventId,
        generation_two_head: RegistryHeadBindingV1,
        rollback_target_package_digest: Sha256Digest,
        rollback_statement_id: GenericSuccessorActivationStatementId,
        rollback_activation_id: GenericSuccessorActivationId,
        rollback_accepted_event_id: AcceptedEventId,
        rollback_head: RegistryHeadBindingV1,
        rival_statement_id: GenericSuccessorActivationStatementId,
        rival_activation_id: GenericSuccessorActivationId,
        contested_set_id: RegistryContestedSetId,
        contested_activation_ids: Vec<GenericSuccessorActivationId>,
        resolution_statement_id: ContestedSetResolutionStatementId,
        resolution_id: ContestedSetResolutionId,
        consistency_key_family: ContractId,
        consistency_key_digest: Sha256Digest,
        positive_cases_digest: Sha256Digest,
        negative_cases_digest: Sha256Digest,
        external_artifact_pins: Vec<ArtifactPinV1>,
        artifact_pins: Vec<ArtifactPinV1>,
    }

    fn expected_digest(value: &str) -> Sha256Digest {
        value.parse().unwrap()
    }

    fn timestamp(value: &str) -> CanonicalTimestamp {
        CanonicalTimestamp::parse(value).unwrap()
    }

    fn case_id(value: &str) -> ContractId {
        ContractId::new(value).unwrap()
    }

    /// Assert-friendly rejection: the verified typestates are deliberately not
    /// comparable, so a negative case compares the exact error instead.
    fn rejection<T: fmt::Debug>(result: ContractResult<T>) -> ContractError {
        result.expect_err("the contract must reject this input")
    }

    fn record(artifact: &'static [u8]) -> &'static [u8] {
        let record = artifact
            .strip_suffix(b"\n")
            .expect("fixture must have exactly one repository-framing LF");
        assert!(!record.ends_with(b"\n"));
        assert!(!record.contains(&b'\r'));
        record
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

    fn manifest_digest(manifest: &CaseManifestV1) -> Sha256Digest {
        domain_separated_digest(
            DigestDomain::TestVectorManifest,
            &encode_canonical(manifest).unwrap(),
        )
    }

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            case_id("tenant.fixture"),
            case_id("project.fixture"),
        )
    }

    fn generation_one_package() -> ManifestVerifiedRegistryPackage {
        ManifestVerifiedRegistryPackage::decode(
            record(GENERATION_ONE_PACKAGE_FIXTURE),
            &frozen_profile_reference_v1(),
        )
        .unwrap()
    }

    fn generation_one_target() -> StructurallyClosedSuccessorTargetV2 {
        StructurallyClosedSuccessorTargetV2::from_manifest_verified(&generation_one_package())
            .unwrap()
    }

    fn generation_one_head() -> RegistryHeadBindingV1 {
        let head: RegistryHeadBindingV1 =
            decode_strict(record(GENERATION_ONE_HEAD_FIXTURE)).unwrap();
        head.validate_shape().unwrap();
        head
    }

    /// A minimal but real generation-2 package: one activation-policy v2 entry
    /// whose suite roots are that entry's own frozen vector roots.
    fn generation_two_package() -> ManifestVerifiedRegistryPackage {
        let entry: RegistryEntryV1 =
            decode_strict(record(ACTIVATION_POLICY_ENTRY_FIXTURE)).unwrap();
        let package = RegistryPackageV1 {
            schema_version: 1,
            profile: frozen_profile_reference_v1(),
            manifest: vec![RegistryManifestEntryV1 {
                kind: entry.kind,
                entry_id: entry.entry_id.clone(),
                version: entry.version,
                entry_digest: entry.digest().unwrap(),
            }],
            positive_vector_suite_digest: entry.positive_vector_digest,
            negative_vector_suite_digest: entry.negative_vector_digest,
            entries: vec![entry],
        };
        ManifestVerifiedRegistryPackage::new(package, &frozen_profile_reference_v1()).unwrap()
    }

    fn generation_two_target() -> StructurallyClosedSuccessorTargetV2 {
        StructurallyClosedSuccessorTargetV2::from_manifest_verified(&generation_two_package())
            .unwrap()
    }

    fn installed_policy(
        generation: u32,
        head: &RegistryHeadBindingV1,
        installed_package: &StructurallyClosedSuccessorTargetV2,
    ) -> InstalledSuccessorPolicyV2 {
        InstalledSuccessorPolicyV2::from_durable_audit(
            frozen_profile_reference_v1(),
            scope(),
            generation,
            head.clone(),
            installed_package,
        )
        .unwrap()
    }

    fn conformance_result(
        target: &StructurallyClosedSuccessorTargetV2,
        completed_at: &str,
    ) -> VerifiedGenericSuccessorTestResult {
        let result = RegistryTestResultV1 {
            schema_version: REGISTRY_TEST_RESULT_SCHEMA_VERSION,
            profile: frozen_profile_reference_v1(),
            package_digest: target.package_digest(),
            positive_vector_suite_digest: target.positive_vector_suite_digest,
            negative_vector_suite_digest: target.negative_vector_suite_digest,
            executed_vector_manifest_digest: frozen_profile_reference_v1().vector_manifest_digest,
            runner_artifact_digest: expected_digest(RUNNER_ARTIFACT_DIGEST),
            runner_configuration_digest: expected_digest(RUNNER_CONFIGURATION_DIGEST),
            passed_case_count: target.entry_count(),
            failed_case_count: 0,
            outcome: RegistryTestOutcomeV1::Passed,
            completed_at: timestamp(completed_at),
        };
        let bytes = encode_canonical(&result).unwrap();
        let pin = GenericSuccessorTestRunnerPin::from_trusted_config(
            result.runner_artifact_digest,
            result.runner_configuration_digest,
            generic_test_result_digest(&result).unwrap(),
        );
        verify_generic_successor_test_result(&bytes, pin, target).unwrap()
    }

    struct StatementSpec<'a> {
        predecessor_head: &'a RegistryHeadBindingV1,
        current_policy: &'a RegistryReferenceV1,
        target: &'a StructurallyClosedSuccessorTargetV2,
        test_result: &'a VerifiedGenericSuccessorTestResult,
        from_generation: u32,
        effective_from: &'a str,
        proposer: &'a str,
        author: &'a str,
    }

    fn statement(spec: &StatementSpec<'_>) -> GenericSuccessorActivationStatementV2 {
        GenericSuccessorActivationStatementV2 {
            schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            expected_predecessor_head: spec.predecessor_head.clone(),
            current_activation_policy: spec.current_policy.clone(),
            target_package_digest: spec.target.package_digest(),
            target_activation_policy: spec.target.activation_policy().registry_reference().clone(),
            test_vector_result_digest: spec.test_result.result_digest(),
            from_generation: spec.from_generation,
            to_generation: spec.from_generation + 1,
            effective_from: timestamp(spec.effective_from),
            effective_until: None,
            proposer_principal_id: case_id(spec.proposer),
            package_author_principal_id: case_id(spec.author),
        }
    }

    fn detached_signature(prefix: &[u8], statement_id: Sha256Digest, seed: [u8; 32]) -> FixedHex64 {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let signature = key_pair.sign(&approval_signature_message(prefix, statement_id));
        FixedHex64::from_bytes(signature.as_ref().try_into().unwrap())
    }

    fn activation_approval(
        statement_id: GenericSuccessorActivationStatementId,
        principal: &str,
        seed: [u8; 32],
    ) -> GenericSuccessorActivationApprovalV2 {
        GenericSuccessorActivationApprovalV2 {
            schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
            statement_id,
            signer_principal_id: case_id(principal),
            signature: detached_signature(
                GENERIC_APPROVAL_SIGNATURE_PREFIX,
                statement_id.digest(),
                seed,
            ),
        }
    }

    fn approval_set_of(
        statement: &GenericSuccessorActivationStatementV2,
        approvals: Vec<GenericSuccessorActivationApprovalV2>,
    ) -> GenericSuccessorActivationApprovalSetV2 {
        GenericSuccessorActivationApprovalSetV2 {
            schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
            statement_id: statement.statement_id().unwrap(),
            approvals,
        }
    }

    fn quorum_approval_set(
        statement: &GenericSuccessorActivationStatementV2,
    ) -> GenericSuccessorActivationApprovalSetV2 {
        let statement_id = statement.statement_id().unwrap();
        approval_set_of(
            statement,
            vec![
                activation_approval(statement_id, "principal.alice", [1; 32]),
                activation_approval(statement_id, "principal.bob", [2; 32]),
            ],
        )
    }

    fn verify_activation(
        statement: &GenericSuccessorActivationStatementV2,
        approval_set: &GenericSuccessorActivationApprovalSetV2,
        installed: &InstalledSuccessorPolicyV2,
        target: &StructurallyClosedSuccessorTargetV2,
        test_result: &VerifiedGenericSuccessorTestResult,
    ) -> ContractResult<VerifiedGenericSuccessorActivation> {
        verify_generic_successor_activation(
            &encode_canonical(statement)?,
            &encode_canonical(approval_set)?,
            installed,
            target,
            test_result,
            &GenericSuccessorPrincipalBinding::from_trusted_config(
                statement.proposer_principal_id.clone(),
                statement.package_author_principal_id.clone(),
            ),
        )
    }

    struct ActivationArtifacts {
        /// The policy that authorized this activation - the same one a
        /// contender audit must present.
        installed: InstalledSuccessorPolicyV2,
        target: StructurallyClosedSuccessorTargetV2,
        test_result: VerifiedGenericSuccessorTestResult,
        activation: VerifiedGenericSuccessorActivation,
        receipt: GenericSuccessorActivationReceiptV2,
        head: RegistryHeadBindingV1,
        event: GenericSuccessorActivatedEventV2,
    }

    struct ArtifactSpec<'a> {
        activation: VerifiedGenericSuccessorActivation,
        installed: &'a InstalledSuccessorPolicyV2,
        target: &'a StructurallyClosedSuccessorTargetV2,
        test_result: &'a VerifiedGenericSuccessorTestResult,
        predecessor_accepted_at: &'a str,
        accepted_at: &'a str,
    }

    fn activation_artifacts(spec: ArtifactSpec<'_>) -> ActivationArtifacts {
        let activation = spec.activation;
        let receipt = activation
            .receipt_at(
                spec.installed,
                &timestamp(spec.predecessor_accepted_at),
                timestamp(spec.accepted_at),
            )
            .unwrap();
        let head = activation.resulting_registry_head(&receipt).unwrap();
        let event = GenericSuccessorActivatedEventV2::from_verified(&activation, &receipt).unwrap();
        ActivationArtifacts {
            installed: spec.installed.clone(),
            target: spec.target.clone(),
            test_result: spec.test_result.clone(),
            activation,
            receipt,
            head,
            event,
        }
    }

    /// The generation `1 -> 2 -> 3` chain plus its contested branch.
    struct SuccessorChain {
        generation_two: ActivationArtifacts,
        rollback: ActivationArtifacts,
        rival: ActivationArtifacts,
        contested_set: AuditedContestedSetV1,
        resolution: VerifiedContestedSetResolution,
        resolution_receipt: ContestedSetResolutionReceiptV1,
    }

    fn successor_of_generation_one(proposer: &str, author: &str) -> ActivationArtifacts {
        let head = generation_one_head();
        let predecessor = generation_one_target();
        let installed = installed_policy(1, &head, &predecessor);
        let target = generation_two_target();
        let test_result = conformance_result(&target, GENERATION_TWO_TEST_COMPLETED_AT);
        let statement = statement(&StatementSpec {
            predecessor_head: &head,
            current_policy: installed.policy_reference(),
            target: &target,
            test_result: &test_result,
            from_generation: 1,
            effective_from: GENERATION_TWO_EFFECTIVE_FROM,
            proposer,
            author,
        });
        let approval_set = quorum_approval_set(&statement);
        let activation =
            verify_activation(&statement, &approval_set, &installed, &target, &test_result)
                .unwrap();
        activation_artifacts(ArtifactSpec {
            activation,
            installed: &installed,
            target: &target,
            test_result: &test_result,
            predecessor_accepted_at: PREDECESSOR_ACCEPTED_AT,
            accepted_at: GENERATION_TWO_EFFECTIVE_FROM,
        })
    }

    fn generation_two_activation() -> ActivationArtifacts {
        successor_of_generation_one("principal.proposer", "principal.author")
    }

    /// A second, independently valid successor of the same generation-1 head.
    fn rival_activation() -> ActivationArtifacts {
        successor_of_generation_one("principal.rival-proposer", "principal.rival-author")
    }

    /// Generation `2 -> 3` reverting to the generation-1 package digest.
    fn rollback_activation(generation_two: &ActivationArtifacts) -> ActivationArtifacts {
        let installed = installed_policy(2, &generation_two.head, &generation_two_target());
        let target = generation_one_target();
        let test_result = conformance_result(&target, GENERATION_THREE_TEST_COMPLETED_AT);
        let statement = statement(&StatementSpec {
            predecessor_head: &generation_two.head,
            current_policy: installed.policy_reference(),
            target: &target,
            test_result: &test_result,
            from_generation: 2,
            effective_from: GENERATION_THREE_EFFECTIVE_FROM,
            proposer: "principal.proposer",
            author: "principal.author",
        });
        let approval_set = quorum_approval_set(&statement);
        let activation =
            verify_activation(&statement, &approval_set, &installed, &target, &test_result)
                .unwrap();
        activation_artifacts(ArtifactSpec {
            activation,
            installed: &installed,
            target: &target,
            test_result: &test_result,
            predecessor_accepted_at: GENERATION_TWO_EFFECTIVE_FROM,
            accepted_at: GENERATION_THREE_EFFECTIVE_FROM,
        })
    }

    /// The durable bytes and out-of-band evidence a repository would re-read for
    /// one contender under its stream lock.
    fn contender_audit(artifacts: &ActivationArtifacts) -> ContenderActivationAuditV2<'_> {
        ContenderActivationAuditV2 {
            canonical_statement: artifacts.activation.canonical_statement(),
            canonical_approval_set: artifacts.activation.canonical_approval_set(),
            target: &artifacts.target,
            test_result: &artifacts.test_result,
            receipt: &artifacts.receipt,
            event: &artifacts.event,
        }
    }

    fn audited_contender(artifacts: &ActivationArtifacts) -> AuditedContenderActivationV2 {
        AuditedContenderActivationV2::from_durable_audit(
            &artifacts.installed,
            &contender_audit(artifacts),
        )
        .unwrap()
    }

    fn generation_one_policy() -> InstalledSuccessorPolicyV2 {
        installed_policy(1, &generation_one_head(), &generation_one_target())
    }

    fn audited_contested_set(contenders: &[&ActivationArtifacts]) -> AuditedContestedSetV1 {
        let audited = contenders
            .iter()
            .map(|artifacts| audited_contender(artifacts))
            .collect::<Vec<_>>();
        AuditedContestedSetV1::from_durable_audit(&generation_one_policy(), &audited).unwrap()
    }

    fn contested_set(
        generation_two: &ActivationArtifacts,
        rival: &ActivationArtifacts,
    ) -> AuditedContestedSetV1 {
        audited_contested_set(&[generation_two, rival])
    }

    fn resolution_statement(
        set: &AuditedContestedSetV1,
        selected: GenericSuccessorActivationId,
        proposer: &str,
    ) -> ContestedSetResolutionStatementV1 {
        ContestedSetResolutionStatementV1 {
            schema_version: CONTESTED_SCHEMA_VERSION,
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            contested_set_id: set.contested_set_id().unwrap(),
            contested_activation_ids: set.contested_activation_ids().unwrap(),
            selected_activation_id: selected,
            authorizing_activation_policy: set.set().last_unambiguous_activation_policy.clone(),
            effective_from: timestamp(RESOLUTION_EFFECTIVE_FROM),
            proposer_principal_id: case_id(proposer),
        }
    }

    fn resolution_approval_set(
        statement: &ContestedSetResolutionStatementV1,
    ) -> ContestedSetResolutionApprovalSetV1 {
        let statement_id = statement.statement_id().unwrap();
        let approval = |principal: &str, seed: [u8; 32]| ContestedSetResolutionApprovalV1 {
            schema_version: CONTESTED_SCHEMA_VERSION,
            statement_id,
            signer_principal_id: case_id(principal),
            signature: detached_signature(
                CONTESTED_RESOLUTION_SIGNATURE_PREFIX,
                statement_id.digest(),
                seed,
            ),
        };
        ContestedSetResolutionApprovalSetV1 {
            schema_version: CONTESTED_SCHEMA_VERSION,
            statement_id,
            approvals: vec![
                approval("principal.alice", [1; 32]),
                approval("principal.bob", [2; 32]),
            ],
        }
    }

    /// The honest ceremony: the authenticated driver is exactly the principal
    /// the statement names. Attacks that disagree with the trusted binding call
    /// `verify_contested_set_resolution` directly.
    fn verify_resolution(
        statement: &ContestedSetResolutionStatementV1,
        approval_set: &ContestedSetResolutionApprovalSetV1,
        set: &AuditedContestedSetV1,
    ) -> ContractResult<VerifiedContestedSetResolution> {
        verify_contested_set_resolution(
            &encode_canonical(statement)?,
            &encode_canonical(approval_set)?,
            set,
            &generation_one_policy(),
            &ContestedResolutionPrincipalBinding::from_trusted_config(
                statement.proposer_principal_id.clone(),
            ),
        )
    }

    fn successor_chain() -> SuccessorChain {
        let generation_two = generation_two_activation();
        let rollback = rollback_activation(&generation_two);
        let rival = rival_activation();
        let set = contested_set(&generation_two, &rival);
        let statement = resolution_statement(
            &set,
            generation_two.receipt.activation_id().unwrap(),
            "principal.arbiter",
        );
        let approval_set = resolution_approval_set(&statement);
        let resolution = verify_resolution(&statement, &approval_set, &set).unwrap();
        let resolution_receipt = resolution
            .receipt_at(
                &generation_one_policy(),
                &set,
                timestamp(RESOLUTION_EFFECTIVE_FROM),
            )
            .unwrap();
        SuccessorChain {
            generation_two,
            rollback,
            rival,
            contested_set: set,
            resolution,
            resolution_receipt,
        }
    }

    fn positive_cases() -> CaseManifestV1 {
        CaseManifestV1 {
            schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
            suite_id: case_id(SUITE_ID),
            expected_outcome: CaseOutcomeV1::Accept,
            cases: [
                "contested-resolution-under-last-unambiguous-policy",
                "contested-set-records-two-valid-successors",
                "exact-replay-is-a-no-op",
                "generation-one-to-two-activation",
                "installed-policy-is-the-only-authority",
                "rollback-to-an-earlier-package-at-generation-three",
                "stable-registry-activation-stream",
            ]
            .into_iter()
            .map(case_id)
            .collect(),
        }
    }

    fn negative_cases() -> CaseManifestV1 {
        CaseManifestV1 {
            schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
            suite_id: case_id(SUITE_ID),
            expected_outcome: CaseOutcomeV1::Reject,
            cases: [
                "aba-stale-after-package-digest-returns",
                "approval-below-threshold",
                "approval-under-key-bridge-prefix",
                "approval-under-uninstalled-principal",
                "author-counted-as-approver",
                "contested-contender-approvals-not-derived-from-the-verified-request",
                "contested-contender-head-does-not-reproduce-from-its-activation",
                "contested-contender-of-another-predecessor-head",
                "contested-contender-package-never-passed-conformance",
                "contested-generation-does-not-follow-the-authorizing-policy",
                "contested-resolution-before-its-contenders",
                "contested-resolution-by-a-contestant",
                "contested-resolution-proposer-disagrees-with-trusted-binding",
                "contested-resolution-set-drift",
                "fabricated-contested-contender",
                "genesis-generation-statement",
                "key-bridge-field-in-statement",
                "proposer-counted-as-approver",
                "reactivating-the-current-package",
                "revoked-signer-key",
                "stale-contested-authority-at-receipt-mint",
                "stale-expected-head",
                "stale-head-at-receipt-mint",
                "wrong-generation-step",
                "wrong-scope",
            ]
            .into_iter()
            .map(case_id)
            .collect(),
        }
    }

    #[allow(clippy::too_many_lines)] // one exhaustive list of every checked-in artifact
    fn canonical_artifact_records(
        chain: &SuccessorChain,
        positive_bytes: &[u8],
        negative_bytes: &[u8],
    ) -> Vec<(&'static str, Vec<u8>)> {
        vec![
            (
                "activated-head.jsonl",
                encode_canonical(&chain.generation_two.head).unwrap(),
            ),
            (
                "activation-approval-set.jsonl",
                chain
                    .generation_two
                    .activation
                    .canonical_approval_set()
                    .to_vec(),
            ),
            (
                "activation-event.jsonl",
                encode_canonical(&chain.generation_two.event).unwrap(),
            ),
            (
                "activation-receipt.jsonl",
                encode_canonical(&chain.generation_two.receipt).unwrap(),
            ),
            (
                "activation-statement.jsonl",
                chain
                    .generation_two
                    .activation
                    .canonical_statement()
                    .to_vec(),
            ),
            (
                "activation-test-result.jsonl",
                chain
                    .generation_two
                    .activation
                    .test_result()
                    .canonical_bytes()
                    .to_vec(),
            ),
            (
                "contested-resolution-approval-set.jsonl",
                chain.resolution.canonical_approval_set().to_vec(),
            ),
            (
                "contested-resolution-receipt.jsonl",
                encode_canonical(&chain.resolution_receipt).unwrap(),
            ),
            (
                "contested-resolution-statement.jsonl",
                chain.resolution.canonical_statement().to_vec(),
            ),
            (
                "contested-rival-approval-set.jsonl",
                chain.rival.activation.canonical_approval_set().to_vec(),
            ),
            (
                "contested-rival-receipt.jsonl",
                encode_canonical(&chain.rival.receipt).unwrap(),
            ),
            (
                "contested-rival-statement.jsonl",
                chain.rival.activation.canonical_statement().to_vec(),
            ),
            (
                "contested-set.jsonl",
                encode_canonical(chain.contested_set.set()).unwrap(),
            ),
            (
                "generation-2-package.jsonl",
                generation_two_package().canonical_bytes().to_vec(),
            ),
            ("negative-vectors.jsonl", negative_bytes.to_vec()),
            ("positive-vectors.jsonl", positive_bytes.to_vec()),
            (
                "rollback-activated-head.jsonl",
                encode_canonical(&chain.rollback.head).unwrap(),
            ),
            (
                "rollback-approval-set.jsonl",
                chain.rollback.activation.canonical_approval_set().to_vec(),
            ),
            (
                "rollback-event.jsonl",
                encode_canonical(&chain.rollback.event).unwrap(),
            ),
            (
                "rollback-receipt.jsonl",
                encode_canonical(&chain.rollback.receipt).unwrap(),
            ),
            (
                "rollback-statement.jsonl",
                chain.rollback.activation.canonical_statement().to_vec(),
            ),
            (
                "rollback-test-result.jsonl",
                chain
                    .rollback
                    .activation
                    .test_result()
                    .canonical_bytes()
                    .to_vec(),
            ),
        ]
    }

    fn vector_suite(
        chain: &SuccessorChain,
        positive: &CaseManifestV1,
        negative: &CaseManifestV1,
        records: &[(&'static str, Vec<u8>)],
    ) -> VectorSuiteV1 {
        let statement = chain.generation_two.activation.statement();
        let consistency_key = chain
            .generation_two
            .event
            .consistency_partition_key()
            .unwrap();
        VectorSuiteV1 {
            schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
            suite_id: case_id(SUITE_ID),
            fixture_authority: FIXTURE_AUTHORITY.into(),
            predecessor_head: statement.expected_predecessor_head.clone(),
            current_activation_policy: statement.current_activation_policy.clone(),
            generation_two_package_digest: statement.target_package_digest,
            generation_two_statement_id: statement.statement_id().unwrap(),
            generation_two_approval_ids: chain
                .generation_two
                .activation
                .approval_set()
                .approvals
                .iter()
                .map(|approval| approval.approval_id().unwrap())
                .collect(),
            generation_two_activation_id: chain.generation_two.receipt.activation_id().unwrap(),
            generation_two_accepted_event_id: chain
                .generation_two
                .event
                .accepted_event_id()
                .unwrap(),
            generation_two_head: chain.generation_two.head.clone(),
            rollback_target_package_digest: chain
                .rollback
                .activation
                .statement()
                .target_package_digest,
            rollback_statement_id: chain.rollback.activation.statement_id().unwrap(),
            rollback_activation_id: chain.rollback.receipt.activation_id().unwrap(),
            rollback_accepted_event_id: chain.rollback.event.accepted_event_id().unwrap(),
            rollback_head: chain.rollback.head.clone(),
            rival_statement_id: chain.rival.activation.statement_id().unwrap(),
            rival_activation_id: chain.rival.receipt.activation_id().unwrap(),
            contested_set_id: chain.contested_set.contested_set_id().unwrap(),
            contested_activation_ids: chain.contested_set.contested_activation_ids().unwrap(),
            resolution_statement_id: chain.resolution.statement().statement_id().unwrap(),
            resolution_id: chain.resolution_receipt.resolution_id().unwrap(),
            consistency_key_family: consistency_key.family,
            consistency_key_digest: consistency_key.key_digest,
            positive_cases_digest: manifest_digest(positive),
            negative_cases_digest: manifest_digest(negative),
            external_artifact_pins: vec![
                ArtifactPinV1 {
                    path: "../../v2/stage4-successor/registry-package.jsonl".into(),
                    raw_sha256: raw_sha256(GENERATION_ONE_PACKAGE_FIXTURE),
                },
                ArtifactPinV1 {
                    path: "../../v2/successor-activation/activated-head.jsonl".into(),
                    raw_sha256: raw_sha256(GENERATION_ONE_HEAD_FIXTURE),
                },
                ArtifactPinV1 {
                    path: "../../v2/successor-policy/activation-policy-v2.jsonl".into(),
                    raw_sha256: raw_sha256(ACTIVATION_POLICY_ENTRY_FIXTURE),
                },
            ],
            artifact_pins: records
                .iter()
                .map(|(path, bytes)| ArtifactPinV1 {
                    path: (*path).into(),
                    raw_sha256: raw_sha256(&framed_record(bytes)),
                })
                .collect(),
        }
    }

    fn write_artifact(output: &Path, name: &str, canonical: &[u8]) {
        require_canonical(canonical).unwrap();
        fs::write(output.join(name), framed_record(canonical)).unwrap();
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one exhaustive freeze of every checked-in artifact
    fn canonical_artifacts_and_all_literal_pins_are_frozen() {
        let positive = positive_cases();
        let negative = negative_cases();
        positive.validate(CaseOutcomeV1::Accept);
        negative.validate(CaseOutcomeV1::Reject);
        assert_eq!(
            encode_canonical(&positive).unwrap(),
            record(POSITIVE_VECTORS_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&negative).unwrap(),
            record(NEGATIVE_VECTORS_FIXTURE)
        );

        let chain = successor_chain();
        let records = canonical_artifact_records(
            &chain,
            record(POSITIVE_VECTORS_FIXTURE),
            record(NEGATIVE_VECTORS_FIXTURE),
        );
        let suite = vector_suite(&chain, &positive, &negative, &records);
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

        // Every checked-in record equals its regenerated canonical bytes, and
        // the suite's own pin for that path equals the literal file hash.
        let frozen: Vec<(&'static str, &'static [u8])> = vec![
            ("activated-head.jsonl", ACTIVATED_HEAD_FIXTURE),
            (
                "activation-approval-set.jsonl",
                ACTIVATION_APPROVAL_SET_FIXTURE,
            ),
            ("activation-event.jsonl", ACTIVATION_EVENT_FIXTURE),
            ("activation-receipt.jsonl", ACTIVATION_RECEIPT_FIXTURE),
            ("activation-statement.jsonl", ACTIVATION_STATEMENT_FIXTURE),
            (
                "activation-test-result.jsonl",
                ACTIVATION_TEST_RESULT_FIXTURE,
            ),
            (
                "contested-resolution-approval-set.jsonl",
                RESOLUTION_APPROVAL_SET_FIXTURE,
            ),
            (
                "contested-resolution-receipt.jsonl",
                RESOLUTION_RECEIPT_FIXTURE,
            ),
            (
                "contested-resolution-statement.jsonl",
                RESOLUTION_STATEMENT_FIXTURE,
            ),
            (
                "contested-rival-approval-set.jsonl",
                RIVAL_APPROVAL_SET_FIXTURE,
            ),
            ("contested-rival-receipt.jsonl", RIVAL_RECEIPT_FIXTURE),
            ("contested-rival-statement.jsonl", RIVAL_STATEMENT_FIXTURE),
            ("contested-set.jsonl", CONTESTED_SET_FIXTURE),
            ("generation-2-package.jsonl", GENERATION_TWO_PACKAGE_FIXTURE),
            ("negative-vectors.jsonl", NEGATIVE_VECTORS_FIXTURE),
            ("positive-vectors.jsonl", POSITIVE_VECTORS_FIXTURE),
            ("rollback-activated-head.jsonl", ROLLBACK_HEAD_FIXTURE),
            ("rollback-approval-set.jsonl", ROLLBACK_APPROVAL_SET_FIXTURE),
            ("rollback-event.jsonl", ROLLBACK_EVENT_FIXTURE),
            ("rollback-receipt.jsonl", ROLLBACK_RECEIPT_FIXTURE),
            ("rollback-statement.jsonl", ROLLBACK_STATEMENT_FIXTURE),
            ("rollback-test-result.jsonl", ROLLBACK_TEST_RESULT_FIXTURE),
        ];
        assert_eq!(frozen.len(), records.len());
        for (&(expected_path, bytes), (path, canonical)) in frozen.iter().zip(&records) {
            assert_eq!(expected_path, *path);
            require_canonical(record(bytes)).unwrap();
            assert_eq!(record(bytes), canonical.as_slice(), "{path} drifted");
            let pin = suite
                .artifact_pins
                .iter()
                .find(|pin| pin.path == *path)
                .expect("every artifact is pinned by the suite");
            assert_eq!(raw_sha256(bytes), pin.raw_sha256);
        }
        for (path, fixture) in [
            (
                "../../v2/stage4-successor/registry-package.jsonl",
                GENERATION_ONE_PACKAGE_FIXTURE,
            ),
            (
                "../../v2/successor-activation/activated-head.jsonl",
                GENERATION_ONE_HEAD_FIXTURE,
            ),
            (
                "../../v2/successor-policy/activation-policy-v2.jsonl",
                ACTIVATION_POLICY_ENTRY_FIXTURE,
            ),
        ] {
            let pin = suite
                .external_artifact_pins
                .iter()
                .find(|pin| pin.path == path)
                .expect("every external input is pinned by the suite");
            assert_eq!(raw_sha256(fixture), pin.raw_sha256);
        }

        // Inputs owned by the frozen `0 -> 1` contract are unchanged.
        assert_eq!(
            generation_one_package().package_digest().to_string(),
            GENERATION_ONE_PACKAGE_DIGEST
        );
        assert_eq!(
            generation_one_head().head.activation_id.to_string(),
            GENERATION_ONE_ACTIVATION_ID
        );
        assert_eq!(
            generation_one_target()
                .activation_policy()
                .registry_reference()
                .entry_digest
                .to_string(),
            ACTIVATION_POLICY_ENTRY_DIGEST
        );

        assert_eq!(
            suite.generation_two_package_digest.to_string(),
            GENERATION_TWO_PACKAGE_DIGEST
        );
        assert_eq!(
            suite.generation_two_statement_id.to_string(),
            GENERATION_TWO_STATEMENT_ID
        );
        assert_eq!(
            suite.generation_two_activation_id.to_string(),
            GENERATION_TWO_ACTIVATION_ID
        );
        assert_eq!(
            suite.generation_two_accepted_event_id.to_string(),
            GENERATION_TWO_ACCEPTED_EVENT_ID
        );
        assert_eq!(
            suite.rollback_statement_id.to_string(),
            ROLLBACK_STATEMENT_ID
        );
        assert_eq!(
            suite.rollback_activation_id.to_string(),
            ROLLBACK_ACTIVATION_ID
        );
        assert_eq!(
            suite.rollback_accepted_event_id.to_string(),
            ROLLBACK_ACCEPTED_EVENT_ID
        );
        assert_eq!(suite.rival_statement_id.to_string(), RIVAL_STATEMENT_ID);
        assert_eq!(suite.rival_activation_id.to_string(), RIVAL_ACTIVATION_ID);
        assert_eq!(suite.contested_set_id.to_string(), CONTESTED_SET_ID);
        assert_eq!(
            suite.resolution_statement_id.to_string(),
            RESOLUTION_STATEMENT_ID
        );
        assert_eq!(suite.resolution_id.to_string(), RESOLUTION_ID);
        assert_eq!(
            suite.consistency_key_digest.to_string(),
            CONSISTENCY_KEY_DIGEST
        );
        assert_eq!(
            suite.consistency_key_family.as_str(),
            "registry.activation",
            "genesis, first-successor, and generic activations share one stream"
        );
        assert_eq!(
            suite.positive_cases_digest.to_string(),
            POSITIVE_CASES_DIGEST
        );
        assert_eq!(
            suite.negative_cases_digest.to_string(),
            NEGATIVE_CASES_DIGEST
        );
        assert_eq!(
            raw_sha256(VECTOR_SUITE_FIXTURE).to_string(),
            VECTOR_SUITE_RAW_SHA256
        );
        assert_eq!(
            domain_separated_digest(
                DigestDomain::TestVectorManifest,
                record(VECTOR_SUITE_FIXTURE)
            )
            .to_string(),
            VECTOR_SUITE_DIGEST
        );
    }

    #[test]
    fn frozen_artifacts_reverify_without_granting_durable_authority() {
        let head = generation_one_head();
        let installed = installed_policy(1, &head, &generation_one_target());
        let target = generation_two_target();
        let pin = GenericSuccessorTestRunnerPin::from_trusted_config(
            expected_digest(RUNNER_ARTIFACT_DIGEST),
            expected_digest(RUNNER_CONFIGURATION_DIGEST),
            RegistryTestResultDigest::from_digest(domain_separated_digest(
                DigestDomain::RegistryTestResult,
                record(ACTIVATION_TEST_RESULT_FIXTURE),
            )),
        );
        let test_result = verify_generic_successor_test_result(
            record(ACTIVATION_TEST_RESULT_FIXTURE),
            pin,
            &target,
        )
        .unwrap();
        let activation = verify_generic_successor_activation(
            record(ACTIVATION_STATEMENT_FIXTURE),
            record(ACTIVATION_APPROVAL_SET_FIXTURE),
            &installed,
            &target,
            &test_result,
            &GenericSuccessorPrincipalBinding::from_trusted_config(
                case_id("principal.proposer"),
                case_id("principal.author"),
            ),
        )
        .unwrap();
        // Verification proves bytes and approvals, never freshness: the head
        // check is a separate, explicit obligation.
        activation.require_expected_head(&head).unwrap();
        assert_eq!(
            activation.required_threshold(),
            2,
            "the installed predecessor policy fixes the threshold"
        );
        assert_eq!(
            activation.applied_separation_of_duty(),
            ActivationSeparationOfDutyV2::AuthorAndProposerDistinctNeitherMayApprove
        );

        // A receipt decoded from public bytes is inert until it revalidates
        // against the exact verified request it belongs to.
        let receipt: GenericSuccessorActivationReceiptV2 =
            decode_strict(record(ACTIVATION_RECEIPT_FIXTURE)).unwrap();
        receipt.validate_against(&activation).unwrap();
        let event: GenericSuccessorActivatedEventV2 =
            decode_strict(record(ACTIVATION_EVENT_FIXTURE)).unwrap();
        event.validate_against(&activation, &receipt).unwrap();
        let stored_head: RegistryHeadBindingV1 =
            decode_strict(record(ACTIVATED_HEAD_FIXTURE)).expect("the activated head is canonical");
        assert_eq!(
            activation.resulting_registry_head(&receipt).unwrap(),
            stored_head
        );

        let rollback_receipt: GenericSuccessorActivationReceiptV2 =
            decode_strict(record(ROLLBACK_RECEIPT_FIXTURE)).unwrap();
        // The checked-in contested-set record is a projection of the audited
        // value, never an input to it.
        let wire_set: RegistryContestedSetV1 =
            decode_strict(record(CONTESTED_SET_FIXTURE)).expect("the contested set is canonical");
        let chain = successor_chain();
        chain.contested_set.require_wire_form(&wire_set).unwrap();
        let mut forged = wire_set;
        forged.contenders[0].activated_head.head.package_digest =
            Sha256Digest::from_bytes([0xde; 32]);
        assert_eq!(
            chain.contested_set.require_wire_form(&forged),
            Err(ContractError::ManifestMismatch)
        );

        assert_eq!(
            rollback_receipt.validate_against(&activation),
            Err(ContractError::ManifestMismatch),
            "a receipt cannot be transplanted onto another request"
        );
        assert_eq!(
            event.validate_against(&activation, &rollback_receipt),
            Err(ContractError::ManifestMismatch)
        );
    }

    #[test]
    fn rollback_activates_an_earlier_package_under_a_new_activation_id() {
        let chain = successor_chain();
        let rollback_statement = chain.rollback.activation.statement();
        assert_eq!(rollback_statement.from_generation, 2);
        assert_eq!(rollback_statement.to_generation, 3);
        // The revert targets exactly the generation-1 package digest.
        assert_eq!(
            rollback_statement.target_package_digest,
            generation_one_package().package_digest()
        );
        assert_eq!(
            chain.rollback.head.head.package_digest,
            generation_one_head().head.package_digest
        );
        // No prior activation identity is rewritten: the revert mints a new one.
        assert_ne!(
            chain.rollback.head.head.activation_id,
            generation_one_head().head.activation_id
        );
        assert_ne!(
            chain.rollback.head.head.activation_id,
            chain.generation_two.head.head.activation_id
        );
        assert!(chain.rollback.head.effective_from > chain.generation_two.head.effective_from);
        assert_eq!(
            record(ROLLBACK_HEAD_FIXTURE),
            encode_canonical(&chain.rollback.head).unwrap()
        );
    }

    #[test]
    fn stale_and_aba_expected_heads_fail_closed() {
        let chain = successor_chain();
        let head = generation_one_head();
        let installed = installed_policy(1, &head, &generation_one_target());
        let target = generation_two_target();
        let test_result = conformance_result(&target, GENERATION_TWO_TEST_COMPLETED_AT);

        // A -> B -> A: the rollback head names package A again, so package
        // equality alone would revive the stale generation-1 proposal.
        assert_eq!(
            chain.rollback.head.head.package_digest,
            head.head.package_digest
        );
        assert_eq!(
            chain
                .generation_two
                .activation
                .require_expected_head(&chain.rollback.head),
            Err(ContractError::StaleRegistryHead)
        );
        assert_eq!(
            chain
                .generation_two
                .activation
                .require_expected_head(&chain.generation_two.head),
            Err(ContractError::StaleRegistryHead)
        );

        // Verification happened while generation 1 was current; by mint time
        // the head has moved to generation 3. The receipt seam re-presents the
        // audited head, so the accepted form cannot be minted at all.
        let moved_on = installed_policy(3, &chain.rollback.head, &generation_one_target());
        assert_eq!(
            rejection(chain.generation_two.activation.receipt_at(
                &moved_on,
                &timestamp(PREDECESSOR_ACCEPTED_AT),
                timestamp(GENERATION_TWO_EFFECTIVE_FROM),
            )),
            ContractError::StaleRegistryHead
        );

        // A statement written against a head that is not the audited current
        // head is rejected during verification, not merely at CAS time.
        let mut drifted = statement(&StatementSpec {
            predecessor_head: &head,
            current_policy: installed.policy_reference(),
            target: &target,
            test_result: &test_result,
            from_generation: 1,
            effective_from: GENERATION_TWO_EFFECTIVE_FROM,
            proposer: "principal.proposer",
            author: "principal.author",
        });
        drifted.expected_predecessor_head.head.activation_id = Sha256Digest::from_bytes([0x5a; 32]);
        let approval_set = quorum_approval_set(&drifted);
        assert_eq!(
            rejection(verify_activation(
                &drifted,
                &approval_set,
                &installed,
                &target,
                &test_result
            )),
            ContractError::StaleRegistryHead
        );
    }

    #[test]
    fn installed_policy_governs_eligibility_threshold_and_separation_of_duty() {
        let head = generation_one_head();
        let installed = installed_policy(1, &head, &generation_one_target());
        let target = generation_two_target();
        let test_result = conformance_result(&target, GENERATION_TWO_TEST_COMPLETED_AT);
        let spec = |proposer: &'static str, author: &'static str| StatementSpec {
            predecessor_head: &head,
            current_policy: installed.policy_reference(),
            target: &target,
            test_result: &test_result,
            from_generation: 1,
            effective_from: GENERATION_TWO_EFFECTIVE_FROM,
            proposer,
            author,
        };

        // Below the installed threshold of two.
        let proposal = statement(&spec("principal.proposer", "principal.author"));
        let statement_id = proposal.statement_id().unwrap();
        let single = approval_set_of(
            &proposal,
            vec![activation_approval(
                statement_id,
                "principal.alice",
                [1; 32],
            )],
        );
        assert_eq!(
            rejection(verify_activation(
                &proposal,
                &single,
                &installed,
                &target,
                &test_result
            )),
            ContractError::ApprovalThresholdNotMet
        );

        // A principal the installed policy does not list has no key here, and a
        // listed principal signing with a rotated key verifies against nothing.
        let uninstalled = approval_set_of(
            &proposal,
            vec![
                activation_approval(statement_id, "principal.alice", [1; 32]),
                activation_approval(statement_id, "principal.carol", [3; 32]),
            ],
        );
        assert_eq!(
            rejection(verify_activation(
                &proposal,
                &uninstalled,
                &installed,
                &target,
                &test_result
            )),
            ContractError::SignatureVerification
        );
        let revoked = approval_set_of(
            &proposal,
            vec![
                activation_approval(statement_id, "principal.alice", [9; 32]),
                activation_approval(statement_id, "principal.bob", [2; 32]),
            ],
        );
        assert_eq!(
            rejection(verify_activation(
                &proposal,
                &revoked,
                &installed,
                &target,
                &test_result
            )),
            ContractError::SignatureVerification
        );

        // The package author may not be counted as an approver, and the author
        // and proposer may not be the same principal. Both are the installed
        // v2 rule in `ActivationPolicyEntryV2::validate_approval_principal_set`.
        let author_approves = statement(&spec("principal.proposer", "principal.alice"));
        let author_set = quorum_approval_set(&author_approves);
        assert!(matches!(
            verify_activation(
                &author_approves,
                &author_set,
                &installed,
                &target,
                &test_result
            ),
            Err(ContractError::Schema(_))
        ));
        let proposer_approves = statement(&spec("principal.alice", "principal.author"));
        let proposer_set = quorum_approval_set(&proposer_approves);
        assert!(matches!(
            verify_activation(
                &proposer_approves,
                &proposer_set,
                &installed,
                &target,
                &test_result
            ),
            Err(ContractError::Schema(_))
        ));
        let mut collapsed = proposal;
        collapsed.package_author_principal_id = collapsed.proposer_principal_id.clone();
        assert!(collapsed.validate_shape().is_err());
    }

    #[test]
    fn no_key_bridge_participates_in_generic_transitions() {
        let head = generation_one_head();
        let installed = installed_policy(1, &head, &generation_one_target());
        let target = generation_two_target();
        let test_result = conformance_result(&target, GENERATION_TWO_TEST_COMPLETED_AT);
        let statement = statement(&StatementSpec {
            predecessor_head: &head,
            current_policy: installed.policy_reference(),
            target: &target,
            test_result: &test_result,
            from_generation: 1,
            effective_from: GENERATION_TWO_EFFECTIVE_FROM,
            proposer: "principal.proposer",
            author: "principal.author",
        });
        let statement_id = statement.statement_id().unwrap();

        // Approvals minted under the one-shot `0 -> 1` bridge prefix do not
        // verify under the generic v2 approval domain.
        let bridge_signed =
            |principal: &str, seed: [u8; 32]| GenericSuccessorActivationApprovalV2 {
                schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
                statement_id,
                signer_principal_id: case_id(principal),
                signature: detached_signature(
                    BRIDGE_APPROVAL_SIGNATURE_PREFIX,
                    statement_id.digest(),
                    seed,
                ),
            };
        let bridged = approval_set_of(
            &statement,
            vec![
                bridge_signed("principal.alice", [1; 32]),
                bridge_signed("principal.bob", [2; 32]),
            ],
        );
        assert_eq!(
            rejection(verify_activation(
                &statement,
                &bridged,
                &installed,
                &target,
                &test_result
            )),
            ContractError::SignatureVerification
        );

        // A statement carrying a bridge digest is not a generic statement.
        let canonical = encode_canonical(&statement).unwrap();
        let marker: &[u8] = br#","package_author_principal_id""#;
        let position = canonical
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("canonical key order places the author after the generation fields");
        let mut with_bridge = canonical[..position].to_vec();
        with_bridge.extend_from_slice(
            br#","genesis_successor_key_bridge_digest":"e15309eba5118e21996a7cee6b3780c1a237982bdf4f22460bca4da189ef6592""#,
        );
        with_bridge.extend_from_slice(&canonical[position..]);
        require_canonical(&with_bridge).expect("only the unknown key differs");
        assert!(decode_strict::<GenericSuccessorActivationStatementV2>(&with_bridge).is_err());
    }

    #[test]
    fn wrong_scope_and_generation_steps_fail_closed() {
        let head = generation_one_head();
        let installed = installed_policy(1, &head, &generation_one_target());
        let target = generation_two_target();
        let test_result = conformance_result(&target, GENERATION_TWO_TEST_COMPLETED_AT);
        let base = statement(&StatementSpec {
            predecessor_head: &head,
            current_policy: installed.policy_reference(),
            target: &target,
            test_result: &test_result,
            from_generation: 1,
            effective_from: GENERATION_TWO_EFFECTIVE_FROM,
            proposer: "principal.proposer",
            author: "principal.author",
        });

        let mut wrong_scope = base.clone();
        wrong_scope.scope = AuthenticatedProjectScopeV1::from_trusted_context(
            case_id("tenant.other"),
            case_id("project.fixture"),
        );
        let approvals = quorum_approval_set(&wrong_scope);
        assert_eq!(
            rejection(verify_activation(
                &wrong_scope,
                &approvals,
                &installed,
                &target,
                &test_result
            )),
            ContractError::ManifestMismatch
        );

        // Generation zero belongs to the frozen bridge contract, a two-step
        // jump is not a transition, and re-activating the current package is a
        // no-op rather than a successor.
        let mut genesis_step = base.clone();
        genesis_step.from_generation = 0;
        genesis_step.to_generation = 1;
        assert!(genesis_step.validate_shape().is_err());
        let mut double_step = base.clone();
        double_step.to_generation = 3;
        assert!(double_step.validate_shape().is_err());
        let mut same_package = base;
        same_package.target_package_digest = head.head.package_digest;
        assert!(same_package.validate_shape().is_err());
    }

    #[test]
    fn replay_classification_mirrors_the_frozen_first_successor_semantics() {
        let chain = successor_chain();
        let activation = &chain.generation_two.activation;
        let statement_id = activation.statement_id().unwrap();

        assert_eq!(
            classify_generic_successor_replay(
                activation,
                statement_id,
                activation.canonical_statement(),
                activation.canonical_approval_set(),
            )
            .unwrap(),
            GenericSuccessorReplayClassV2::ExactReplay
        );
        assert_eq!(
            classify_generic_successor_replay(
                activation,
                statement_id,
                record(ROLLBACK_STATEMENT_FIXTURE),
                activation.canonical_approval_set(),
            )
            .unwrap(),
            GenericSuccessorReplayClassV2::IntegrityCollision
        );
        assert_eq!(
            classify_generic_successor_replay(
                activation,
                statement_id,
                activation.canonical_statement(),
                chain.rival.activation.canonical_approval_set(),
            )
            .unwrap(),
            GenericSuccessorReplayClassV2::ApprovalSetConflict
        );
        assert_eq!(
            classify_generic_successor_replay(
                activation,
                chain.rival.activation.statement_id().unwrap(),
                chain.rival.activation.canonical_statement(),
                chain.rival.activation.canonical_approval_set(),
            )
            .unwrap(),
            GenericSuccessorReplayClassV2::StaleStatement
        );
    }

    #[test]
    fn contested_set_records_two_valid_successors_of_one_head() {
        let chain = successor_chain();
        // Both contenders verified on their own merits against the same head.
        assert_eq!(
            chain
                .generation_two
                .activation
                .statement()
                .expected_predecessor_head,
            chain.rival.activation.statement().expected_predecessor_head
        );
        assert_ne!(
            chain.generation_two.receipt.activation_id().unwrap(),
            chain.rival.receipt.activation_id().unwrap()
        );
        assert_eq!(
            chain.generation_two.activation.statement().effective_from,
            chain.rival.activation.statement().effective_from,
            "the contest is over the same scope and effective interval"
        );
        assert_eq!(chain.contested_set.set().contenders.len(), 2);
        assert_eq!(chain.contested_set.set().contested_generation, 2);
        let ids = chain.contested_set.contested_activation_ids().unwrap();
        assert!(strictly_sorted(&ids));
        assert!(ids.contains(&chain.generation_two.receipt.activation_id().unwrap()));
        assert!(ids.contains(&chain.rival.receipt.activation_id().unwrap()));

        // Every field of the record is derived from the audited activations,
        // and the contested generation follows the authorizing policy.
        assert_eq!(
            chain.contested_set.set().contested_generation,
            generation_one_policy().generation() + 1
        );
        assert_eq!(
            chain.contested_set.set().last_unambiguous_head,
            *generation_one_policy().head()
        );

        // A single-contender record is not a contest.
        let mut lone = chain.contested_set.set().clone();
        lone.contenders.truncate(1);
        assert!(lone.validate_shape().is_err());
        assert_eq!(
            rejection(AuditedContestedSetV1::from_durable_audit(
                &generation_one_policy(),
                &[audited_contender(&chain.generation_two)],
            )),
            ContractError::Schema("invalid registry contested set v1".into())
        );
    }

    /// A wholly synthetic contender: three artifacts that agree with each other
    /// perfectly and correspond to no activation that ever happened.
    struct GhostContender {
        statement: GenericSuccessorActivationStatementV2,
        approval_set: GenericSuccessorActivationApprovalSetV2,
        receipt: GenericSuccessorActivationReceiptV2,
        event: GenericSuccessorActivatedEventV2,
    }

    /// Build the coherent forgery the mutual-consistency audit used to accept:
    /// a package digest that never passed conformance, an activation policy that
    /// was never installed, and a receipt whose own digest anchors the head the
    /// event announces.
    fn ghost_contender(approvals: Vec<GenericSuccessorActivationApprovalV2>) -> GhostContender {
        let head = generation_one_head();
        let installed = generation_one_policy();
        let ghost_package = Sha256Digest::from_bytes([0xbe; 32]);
        let ghost_policy = RegistryReferenceV1 {
            entry_id: case_id("activation.ghost"),
            version: 7,
            entry_digest: Sha256Digest::from_bytes([0xca; 32]),
        };
        let statement = GenericSuccessorActivationStatementV2 {
            schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            expected_predecessor_head: head.clone(),
            current_activation_policy: installed.policy_reference().clone(),
            target_package_digest: ghost_package,
            target_activation_policy: ghost_policy.clone(),
            test_vector_result_digest: RegistryTestResultDigest::from_digest(
                Sha256Digest::from_bytes([0x77; 32]),
            ),
            from_generation: 1,
            to_generation: 2,
            effective_from: timestamp(GENERATION_TWO_EFFECTIVE_FROM),
            effective_until: None,
            proposer_principal_id: case_id("principal.mallory"),
            package_author_principal_id: case_id("principal.mallory-author"),
        };
        let statement_id = statement.statement_id().unwrap();
        let approval_set = GenericSuccessorActivationApprovalSetV2 {
            schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
            statement_id,
            approvals,
        };
        let receipt = GenericSuccessorActivationReceiptV2 {
            schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
            statement_id,
            predecessor_head: head.clone(),
            current_activation_policy: installed.policy_reference().clone(),
            target_package_digest: ghost_package,
            target_activation_policy: ghost_policy.clone(),
            test_vector_result_digest: statement.test_vector_result_digest,
            from_generation: 1,
            to_generation: 2,
            eligible_approvals: vec![EligibleApprovalV1 {
                attestation_id: Sha256Digest::from_bytes([0x99; 32]),
                principal_id: case_id("principal.mallory-approver"),
                signer_key_id: case_id("key.mallory"),
            }],
            required_threshold: 1,
            applied_separation_of_duty:
                ActivationSeparationOfDutyV2::AuthorAndProposerDistinctNeitherMayApprove,
            separation_of_duty_satisfied: true,
            accepted_at: timestamp(GENERATION_TWO_EFFECTIVE_FROM),
        };
        let activation_id = receipt.activation_id().unwrap();
        let event = GenericSuccessorActivatedEventV2 {
            schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
            event_kind: case_id(SUCCESSOR_GENERIC_EVENT_KIND),
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            activation_id,
            statement_id,
            predecessor_head: head,
            activated_head: RegistryHeadBindingV1 {
                head: RegistryHeadV1 {
                    activation_id: activation_id.digest(),
                    package_digest: ghost_package,
                    activation_policy_digest: ghost_policy.entry_digest,
                },
                effective_from: timestamp(GENERATION_TWO_EFFECTIVE_FROM),
                effective_until: None,
            },
            current_activation_policy: installed.policy_reference().clone(),
            target_activation_policy: ghost_policy,
            test_vector_result_digest: statement.test_vector_result_digest,
            from_generation: 1,
            to_generation: 2,
        };
        GhostContender {
            statement,
            approval_set,
            receipt,
            event,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one adversary, many coherent forgeries
    fn contested_contenders_must_reproduce_from_their_own_activations() {
        let generation_two = generation_two_activation();
        let rival = rival_activation();
        let policy = generation_one_policy();
        let target = generation_two_target();
        let test_result = conformance_result(&target, GENERATION_TWO_TEST_COMPLETED_AT);

        // ATTACK: three artifacts forged *coherently*, not one at a time. The
        // statement names a package digest that never passed conformance and an
        // activation policy that was never installed; the receipt agrees with
        // the statement field for field; the event's activated head is derived
        // from the receipt's own digest exactly as `resulting_registry_head`
        // would derive it, and it is signed for by the two really installed
        // keys. Mutual consistency is therefore complete - and worthless.
        let ghost_statement_id = ghost_contender(Vec::new())
            .statement
            .statement_id()
            .unwrap();
        let ghost = ghost_contender(vec![
            activation_approval(ghost_statement_id, "principal.alice", [1; 32]),
            activation_approval(ghost_statement_id, "principal.bob", [2; 32]),
        ]);
        assert_eq!(
            ghost.event.activated_head.head.activation_id,
            ghost.receipt.activation_id().unwrap().digest(),
            "the forgery is internally consistent: the head reproduces from the receipt"
        );
        let ghost_statement_bytes = encode_canonical(&ghost.statement).unwrap();
        let ghost_approval_bytes = encode_canonical(&ghost.approval_set).unwrap();
        assert_eq!(
            rejection(AuditedContenderActivationV2::from_durable_audit(
                &policy,
                &ContenderActivationAuditV2 {
                    canonical_statement: &ghost_statement_bytes,
                    canonical_approval_set: &ghost_approval_bytes,
                    target: &target,
                    test_result: &test_result,
                    receipt: &ghost.receipt,
                    event: &ghost.event,
                },
            )),
            ContractError::ManifestMismatch,
            "a contender must bind real package bytes and a runner-pinned conformance result"
        );

        // ATTACK: the real generation-2 statement, approved by a principal the
        // installed policy does not list. There is no key to verify against, so
        // an approver set nobody eligible signed cannot enter a contender.
        let statement_bytes = generation_two.activation.canonical_statement().to_vec();
        let approval_bytes = generation_two.activation.canonical_approval_set().to_vec();
        let real_statement_id = generation_two.activation.statement_id().unwrap();
        let mallory_approvals = encode_canonical(&GenericSuccessorActivationApprovalSetV2 {
            schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
            statement_id: real_statement_id,
            approvals: vec![activation_approval(
                real_statement_id,
                "principal.mallory-approver",
                [9; 32],
            )],
        })
        .unwrap();
        assert_eq!(
            rejection(AuditedContenderActivationV2::from_durable_audit(
                &policy,
                &ContenderActivationAuditV2 {
                    canonical_statement: &statement_bytes,
                    canonical_approval_set: &mallory_approvals,
                    target: &target,
                    test_result: &test_result,
                    receipt: &generation_two.receipt,
                    event: &generation_two.event,
                },
            )),
            ContractError::SignatureVerification
        );

        // ATTACK: a real statement and real approvals, with the receipt
        // rewritten to a threshold of one and an approver who never signed. The
        // receipt is admitted only if it is the one the verifier derives.
        let mut downgraded = generation_two.receipt.clone();
        downgraded.required_threshold = 1;
        downgraded.eligible_approvals = vec![EligibleApprovalV1 {
            attestation_id: Sha256Digest::from_bytes([0x99; 32]),
            principal_id: case_id("principal.mallory-approver"),
            signer_key_id: case_id("key.mallory"),
        }];
        assert_eq!(
            rejection(AuditedContenderActivationV2::from_durable_audit(
                &policy,
                &ContenderActivationAuditV2 {
                    canonical_statement: &statement_bytes,
                    canonical_approval_set: &approval_bytes,
                    target: &target,
                    test_result: &test_result,
                    receipt: &downgraded,
                    event: &generation_two.event,
                },
            )),
            ContractError::ManifestMismatch,
            "the receipt's threshold and approver set are server-derived, not claimed"
        );

        // A head naming a package digest that never passed conformance cannot be
        // slipped into the event either: the event must equal the one the
        // verified request and its receipt produce.
        let mut forged_head = generation_two.event.clone();
        forged_head.activated_head.head.package_digest = Sha256Digest::from_bytes([0xde; 32]);
        assert_eq!(
            rejection(AuditedContenderActivationV2::from_durable_audit(
                &policy,
                &ContenderActivationAuditV2 {
                    canonical_statement: &statement_bytes,
                    canonical_approval_set: &approval_bytes,
                    target: &target,
                    test_result: &test_result,
                    receipt: &generation_two.receipt,
                    event: &forged_head,
                },
            )),
            ContractError::ManifestMismatch
        );
        for mutate in [
            (|event: &mut GenericSuccessorActivatedEventV2| {
                event.activated_head.head.activation_policy_digest =
                    Sha256Digest::from_bytes([0xad; 32]);
            }) as fn(&mut GenericSuccessorActivatedEventV2),
            |event: &mut GenericSuccessorActivatedEventV2| {
                event.activated_head.head.activation_id = Sha256Digest::from_bytes([0x11; 32]);
            },
        ] {
            let mut forged = generation_two.event.clone();
            mutate(&mut forged);
            assert!(
                AuditedContenderActivationV2::from_durable_audit(
                    &policy,
                    &ContenderActivationAuditV2 {
                        canonical_statement: &statement_bytes,
                        canonical_approval_set: &approval_bytes,
                        target: &target,
                        test_result: &test_result,
                        receipt: &generation_two.receipt,
                        event: &forged,
                    },
                )
                .is_err()
            );
        }

        // Rewriting the receipt instead moves the activation ID, so the event
        // no longer reproduces from it either.
        let mut rewritten = generation_two.receipt.clone();
        rewritten.target_package_digest = Sha256Digest::from_bytes([0xde; 32]);
        assert_eq!(
            rejection(AuditedContenderActivationV2::from_durable_audit(
                &policy,
                &ContenderActivationAuditV2 {
                    canonical_statement: &statement_bytes,
                    canonical_approval_set: &approval_bytes,
                    target: &target,
                    test_result: &test_result,
                    receipt: &rewritten,
                    event: &generation_two.event,
                },
            )),
            ContractError::ManifestMismatch
        );

        // The proposer and author are bound by the statement digest, so another
        // genuine activation's receipt cannot be transplanted onto this request
        // to rename who proposed the contender - and therefore cannot bar a
        // legitimate arbiter from resolving the contest.
        assert_eq!(
            rejection(AuditedContenderActivationV2::from_durable_audit(
                &policy,
                &ContenderActivationAuditV2 {
                    canonical_statement: rival.activation.canonical_statement(),
                    canonical_approval_set: rival.activation.canonical_approval_set(),
                    target: &target,
                    test_result: &test_result,
                    receipt: &generation_two.receipt,
                    event: &generation_two.event,
                },
            )),
            ContractError::ManifestMismatch
        );

        // A genuine activation of a different predecessor head is not a
        // contender of this contest, and the authorizing policy says so before
        // the contested set is ever assembled.
        let rollback = rollback_activation(&generation_two);
        assert_eq!(
            rejection(AuditedContenderActivationV2::from_durable_audit(
                &policy,
                &contender_audit(&rollback),
            )),
            ContractError::ManifestMismatch,
            "generation 2 -> 3 is not a step the generation-1 policy governs"
        );
        assert_eq!(
            rejection(AuditedContestedSetV1::from_durable_audit(
                &policy,
                &[
                    audited_contender(&generation_two),
                    audited_contender(&rollback),
                ],
            )),
            ContractError::ManifestMismatch
        );
    }

    #[test]
    fn contested_generation_must_follow_the_authorizing_policy_generation() {
        let chain = successor_chain();
        let selected = chain.generation_two.receipt.activation_id().unwrap();
        let statement = resolution_statement(&chain.contested_set, selected, "principal.arbiter");
        let approvals = resolution_approval_set(&statement);

        // The generation an `InstalledSuccessorPolicyV2` claims is not derivable
        // from its head bytes, so head equality alone cannot pin it. A policy
        // audited at generation 9 governs a generation-10 contest and nothing
        // else, even when it presents the frozen generation-1 head.
        let mismatched = InstalledSuccessorPolicyV2::from_durable_audit(
            frozen_profile_reference_v1(),
            scope(),
            9,
            generation_one_head(),
            &generation_one_target(),
        )
        .unwrap();
        assert_eq!(
            rejection(verify_contested_set_resolution(
                &encode_canonical(&statement).unwrap(),
                &encode_canonical(&approvals).unwrap(),
                &chain.contested_set,
                &mismatched,
                &ContestedResolutionPrincipalBinding::from_trusted_config(case_id(
                    "principal.arbiter",
                )),
            )),
            ContractError::ManifestMismatch
        );
        assert_eq!(
            rejection(chain.resolution.receipt_at(
                &mismatched,
                &chain.contested_set,
                timestamp(RESOLUTION_EFFECTIVE_FROM),
            )),
            ContractError::ManifestMismatch
        );

        // And a contest cannot be audited into existence at a generation its
        // own contenders did not step to.
        assert_eq!(
            rejection(AuditedContestedSetV1::from_durable_audit(
                &mismatched,
                &[
                    audited_contender(&chain.generation_two),
                    audited_contender(&chain.rival),
                ],
            )),
            ContractError::ManifestMismatch
        );
    }

    #[test]
    fn contested_resolution_requires_the_last_unambiguous_policy_and_bars_self_selection() {
        let chain = successor_chain();
        let selected = chain.generation_two.receipt.activation_id().unwrap();
        assert_eq!(
            *chain.resolution.selected_head(),
            chain.generation_two.head,
            "resolution installs the selected contender's own head"
        );
        assert_eq!(
            chain.resolution_receipt.contested_activation_ids,
            chain.contested_set.contested_activation_ids().unwrap()
        );
        assert!(chain.resolution_receipt.self_selection_excluded);

        // Neither contested successor may authorize its own selection.
        for contestant in [
            "principal.proposer",
            "principal.author",
            "principal.rival-proposer",
            "principal.rival-author",
            "principal.alice",
        ] {
            let statement = resolution_statement(&chain.contested_set, selected, contestant);
            let approvals = resolution_approval_set(&statement);
            assert!(
                matches!(
                    verify_resolution(&statement, &approvals, &chain.contested_set),
                    Err(ContractError::Schema(_))
                ),
                "{contestant} must not be able to resolve the contest"
            );
        }

        // The contested activation-ID set is a compare-and-swap precondition:
        // a third successor of the same head appearing after the statement was
        // written cannot be silently excluded from the contest it belongs to.
        let late = successor_of_generation_one("principal.late-proposer", "principal.late-author");
        let drifted = audited_contested_set(&[&chain.generation_two, &chain.rival, &late]);
        let stale = resolution_statement(&chain.contested_set, selected, "principal.arbiter");
        let approvals = resolution_approval_set(&stale);
        assert_eq!(
            rejection(verify_resolution(&stale, &approvals, &drifted)),
            ContractError::StaleRegistryHead,
            "a resolution cannot silently exclude a contender that appeared later"
        );
        assert_eq!(
            rejection(chain.resolution.receipt_at(
                &generation_one_policy(),
                &drifted,
                timestamp(RESOLUTION_EFFECTIVE_FROM),
            )),
            ContractError::StaleRegistryHead,
            "the receipt seam re-audits the contested set, not only the verifier"
        );

        // The re-audited authority is a compare-and-swap precondition at mint
        // time: a head that has since moved cannot mint the accepted form.
        let moved_on = installed_policy(2, &chain.generation_two.head, &generation_two_target());
        assert!(
            chain
                .resolution
                .receipt_at(
                    &moved_on,
                    &chain.contested_set,
                    timestamp(RESOLUTION_EFFECTIVE_FROM)
                )
                .is_err()
        );

        // A resolution cannot claim to take effect before the contest existed.
        let mut early = resolution_statement(&chain.contested_set, selected, "principal.arbiter");
        early.effective_from = timestamp(GENERATION_TWO_EFFECTIVE_FROM);
        let early_approvals = resolution_approval_set(&early);
        assert!(matches!(
            verify_resolution(&early, &early_approvals, &chain.contested_set),
            Err(ContractError::Schema(_))
        ));

        // Selecting an activation outside the recorded set is impossible.
        let mut foreign = stale;
        foreign.selected_activation_id = chain.rollback.receipt.activation_id().unwrap();
        assert!(foreign.validate_shape().is_err());
    }

    #[test]
    fn the_contested_resolution_proposer_is_authenticated_not_labelled() {
        let chain = successor_chain();
        let selected = chain.generation_two.receipt.activation_id().unwrap();
        // The party actually driving the ceremony, from authenticated
        // configuration rather than from the request payload.
        let driver =
            ContestedResolutionPrincipalBinding::from_trusted_config(case_id("principal.proposer"));

        // Truthfully named, contender A's own proposer is barred.
        let honest = resolution_statement(&chain.contested_set, selected, "principal.proposer");
        let honest_approvals = resolution_approval_set(&honest);
        assert!(matches!(
            verify_contested_set_resolution(
                &encode_canonical(&honest).unwrap(),
                &encode_canonical(&honest_approvals).unwrap(),
                &chain.contested_set,
                &generation_one_policy(),
                &driver,
            ),
            Err(ContractError::Schema(_))
        ));

        // The same party writing a different name in the payload no longer
        // escapes the bar. The proposer is compared against trusted
        // configuration before the barred sets are consulted at all, so the
        // rule tests an authenticated identity rather than a chosen string.
        for alias in [
            "principal.proposer-but-spelled-differently",
            "principal.zzz",
            "principal.arbiter",
        ] {
            let aliased = resolution_statement(&chain.contested_set, selected, alias);
            let approvals = resolution_approval_set(&aliased);
            assert_eq!(
                rejection(verify_contested_set_resolution(
                    &encode_canonical(&aliased).unwrap(),
                    &encode_canonical(&approvals).unwrap(),
                    &chain.contested_set,
                    &generation_one_policy(),
                    &driver,
                )),
                ContractError::ManifestMismatch,
                "{alias} disagrees with the authenticated driver"
            );
        }
    }

    #[test]
    #[ignore = "maintainer-only canonical generic-successor fixture regeneration"]
    fn regenerate_generic_successor_artifacts() {
        let output = env::var("SUCCESSOR_GENERIC_VECTOR_OUTPUT")
            .expect("set SUCCESSOR_GENERIC_VECTOR_OUTPUT to an explicit output directory");
        let output = Path::new(&output);
        fs::create_dir_all(output).unwrap();

        let positive = positive_cases();
        let negative = negative_cases();
        positive.validate(CaseOutcomeV1::Accept);
        negative.validate(CaseOutcomeV1::Reject);
        let positive_bytes = encode_canonical(&positive).unwrap();
        let negative_bytes = encode_canonical(&negative).unwrap();

        let chain = successor_chain();
        let records = canonical_artifact_records(&chain, &positive_bytes, &negative_bytes);
        let suite = vector_suite(&chain, &positive, &negative, &records);
        let suite_bytes = encode_canonical(&suite).unwrap();

        for (name, bytes) in &records {
            write_artifact(output, name, bytes);
        }
        write_artifact(output, "vector-suite.jsonl", &suite_bytes);

        println!(
            "generation_two_package_digest={}",
            suite.generation_two_package_digest
        );
        println!(
            "generation_two_statement_id={}",
            suite.generation_two_statement_id
        );
        println!(
            "generation_two_activation_id={}",
            suite.generation_two_activation_id
        );
        println!(
            "generation_two_accepted_event_id={}",
            suite.generation_two_accepted_event_id
        );
        println!("rollback_statement_id={}", suite.rollback_statement_id);
        println!("rollback_activation_id={}", suite.rollback_activation_id);
        println!(
            "rollback_accepted_event_id={}",
            suite.rollback_accepted_event_id
        );
        println!("rival_statement_id={}", suite.rival_statement_id);
        println!("rival_activation_id={}", suite.rival_activation_id);
        println!("contested_set_id={}", suite.contested_set_id);
        println!("resolution_statement_id={}", suite.resolution_statement_id);
        println!("resolution_id={}", suite.resolution_id);
        println!("consistency_key_digest={}", suite.consistency_key_digest);
        println!("positive_cases_digest={}", suite.positive_cases_digest);
        println!("negative_cases_digest={}", suite.negative_cases_digest);
        println!(
            "vector_suite_raw_sha256={}",
            raw_sha256(&framed_record(&suite_bytes))
        );
        println!(
            "vector_suite_digest={}",
            domain_separated_digest(DigestDomain::TestVectorManifest, &suite_bytes)
        );
    }
}
