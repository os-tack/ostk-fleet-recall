//! Action proposal, authorization, attempt, receipt, and verification contracts.
//!
//! ACT-01: recommendation, authorization, execution, and verification are
//! distinct authorities; confidence never grants permission. No field in this
//! module carries a numeric confidence, trust, or risk *score* that any pure
//! function here treats as a substitute for an authenticated decision-maker.
//! [`ActionRiskLevelV1`] is descriptive metadata on a proposal only; it is
//! never read by [`authorize`], [`revalidate_authorization`], or
//! [`reconcile_receipt`].
//!
//! Every public wire struct in this module establishes shape and semantic
//! identity only. [`AuthorizedActionV1`], [`RevalidatedAuthorizationV1`], and
//! [`ReconciledExecutionV1`] are the only accepted-authority forms; each has
//! private fields and is constructible only by the matching pure function in
//! this module (`authorize`, `revalidate_authorization`,
//! `reconcile_receipt`), never by deserializing a payload. This module cannot
//! authenticate a decision-maker, observe real provider state, or execute
//! anything; it defines the exact structural rules a later runtime seam must
//! still apply.

use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    ContractError, ContractResult,
    canonical::encode_canonical,
    common::{
        AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, FixedHex32, ProfileReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    identity::ResourceUri,
};

const ACTION_PROPOSAL_SCHEMA_VERSION: u32 = 1;
const ACTION_AUTHORIZATION_SCHEMA_VERSION: u32 = 1;
const ACTION_EXECUTION_REQUEST_SCHEMA_VERSION: u32 = 1;
const ACTION_ATTEMPT_SCHEMA_VERSION: u32 = 1;
const ACTION_RECEIPT_SCHEMA_VERSION: u32 = 1;
const ACTION_VERIFICATION_SCHEMA_VERSION: u32 = 1;
const MAX_PRECONDITIONS: usize = 64;
/// ACT-03: the declared freshness window a revalidation must fall within,
/// measured backward from `started_at`. Bounds "immediately before
/// execution" structurally rather than narrative: a revalidation timestamp
/// more than five minutes older than the moment execution started is no
/// longer a revalidation of *this* dispatch.
const MAX_REVALIDATION_TO_START_GAP: Duration = Duration::seconds(300);

/// Parse an already-canonical [`CanonicalTimestamp`] into a UTC instant for
/// duration arithmetic. [`CanonicalTimestamp::parse`] already proves the
/// exact RFC-3339 nanosecond form at construction, so this can fail only if
/// that invariant were ever violated.
fn parse_canonical_timestamp(value: &CanonicalTimestamp) -> ContractResult<DateTime<Utc>> {
    value
        .as_str()
        .parse::<DateTime<Utc>>()
        .map_err(|_| ContractError::Schema("canonical timestamp is not parseable RFC-3339".into()))
}

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

digest_newtype!(ActionProposalDigestV1);
digest_newtype!(AuthorizationDigestV1);
digest_newtype!(AttemptIdV1);
digest_newtype!(ReceiptIdV1);
digest_newtype!(VerificationIdV1);

/// Opaque, content-addressed commitment to a described system state.
///
/// The bytes that produced this digest, and how they were observed, live
/// outside this pure leaf. Equality is the only operation this module needs:
/// compare-and-swap admission never inspects a state's meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ActionStateDigestV1(Sha256Digest);

impl ActionStateDigestV1 {
    pub const fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Sha256Digest {
        self.0
    }
}

/// Exact operation and target of one proposed action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionOperationV1 {
    pub operation_id: ContractId,
    pub target: ResourceUri,
}

/// Closed, descriptive risk classification. Never consulted by any admission
/// rule in this module (ACT-01: confidence never grants permission).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRiskLevelV1 {
    Low,
    Medium,
    High,
    Critical,
}

/// Immutable, content-addressed intent to perform exactly one operation.
///
/// `desired_outcome_digest` and `rollback_plan_digest` reference off-band
/// structured narrative by content hash; this leaf never carries free-form
/// prose that a comparator would need to interpret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionProposalV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub proposer_principal_id: ContractId,
    pub operation: ActionOperationV1,
    pub expected_pre_state: ActionStateDigestV1,
    pub desired_outcome_digest: Sha256Digest,
    pub expiry: CanonicalTimestamp,
    pub risk: ActionRiskLevelV1,
    pub rollback_plan_digest: Sha256Digest,
}

impl ActionProposalV1 {
    /// Validate closed wire shape only. This proves nothing about an active
    /// decision-maker, current system state, or provider reachability.
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        if self.schema_version != ACTION_PROPOSAL_SCHEMA_VERSION
            || self.desired_outcome_digest == Sha256Digest::ZERO
            || self.rollback_plan_digest == Sha256Digest::ZERO
        {
            return Err(ContractError::Schema("invalid action proposal".into()));
        }
        Ok(())
    }

    /// Immutable proposal digest (ACT-02). Every authorization binds this
    /// exact value; no physical append or receipt metadata participates.
    pub fn proposal_digest(&self) -> ContractResult<ActionProposalDigestV1> {
        self.validate_shape()?;
        Ok(ActionProposalDigestV1::from_digest(
            domain_separated_digest(DigestDomain::ActionProposalV1, &encode_canonical(self)?),
        ))
    }
}

/// Authorization binding one exact proposal digest (ACT-02).
///
/// Fields are exactly the set ACT-02 names: proposal digest, environment,
/// current and target state, preconditions, scope, expiry, and permitted
/// uses. No confidence, trust, or risk field exists here to short-circuit
/// [`revalidate_authorization`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub decision_maker_principal_id: ContractId,
    pub proposal_digest: ActionProposalDigestV1,
    pub environment: ContractId,
    pub current_state: ActionStateDigestV1,
    pub target_state: ActionStateDigestV1,
    pub preconditions: Vec<ContractId>,
    pub expiry: CanonicalTimestamp,
    pub permitted_uses: u32,
}

impl AuthorizationV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        if self.schema_version != ACTION_AUTHORIZATION_SCHEMA_VERSION
            || self.permitted_uses == 0
            || self.preconditions.len() > MAX_PRECONDITIONS
            || !strictly_sorted(&self.preconditions)
        {
            return Err(ContractError::Schema("invalid action authorization".into()));
        }
        Ok(())
    }

    pub fn authorization_digest(&self) -> ContractResult<AuthorizationDigestV1> {
        self.validate_shape()?;
        Ok(AuthorizationDigestV1::from_digest(domain_separated_digest(
            DigestDomain::ActionAuthorizationV1,
            &encode_canonical(self)?,
        )))
    }
}

/// Opaque authority produced only by [`authorize`].
///
/// It proves the exact proposal/authorization pairing was self-consistent
/// and non-self-promoted (AUTH-03); it does not prove the decision-maker was
/// a real, authenticated principal — that fact must come from trusted
/// ingress, not this leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizedActionV1 {
    proposal_digest: ActionProposalDigestV1,
    authorization_digest: AuthorizationDigestV1,
}

impl AuthorizedActionV1 {
    pub const fn proposal_digest(&self) -> ActionProposalDigestV1 {
        self.proposal_digest
    }

    pub const fn authorization_digest(&self) -> AuthorizationDigestV1 {
        self.authorization_digest
    }

    /// Open the canonical execution request this authorized pair permits.
    /// `proposal_digest`/`authorization_digest` here are copied from a
    /// successful [`authorize`] call, so an `ExecutionRequestV1` opened this
    /// way always names a proposal its authorization actually approved.
    /// A caller may still hand-assemble an [`ExecutionRequestV1`] directly
    /// (it derives `Deserialize`); [`revalidate_authorization`] is what
    /// closes that gap by independently re-checking
    /// `attempt.request.proposal_digest == authorization.proposal_digest`
    /// against the authorization actually supplied at revalidation time,
    /// so a hand-assembled request naming an unapproved proposal is
    /// rejected there rather than trusted because it was well-formed.
    pub fn open_execution_request(
        &self,
        idempotency_key: FixedHex32,
    ) -> ContractResult<ExecutionRequestV1> {
        let request = ExecutionRequestV1 {
            schema_version: ACTION_EXECUTION_REQUEST_SCHEMA_VERSION,
            proposal_digest: self.proposal_digest,
            authorization_digest: self.authorization_digest,
            idempotency_key,
        };
        request.validate_shape()?;
        Ok(request)
    }
}

/// Bind one proposal to one authorization (ACT-02) and reject self-promotion
/// (AUTH-03: an agent cannot authorize its own proposal).
pub fn authorize(
    proposal: &ActionProposalV1,
    authorization: &AuthorizationV1,
) -> ContractResult<AuthorizedActionV1> {
    let proposal_digest = proposal.proposal_digest()?;
    let authorization_digest = authorization.authorization_digest()?;
    if authorization.proposal_digest != proposal_digest {
        return Err(ContractError::Schema(
            "authorization does not bind the exact proposal digest".into(),
        ));
    }
    if authorization.scope != proposal.scope || authorization.profile != proposal.profile {
        return Err(ContractError::Schema(
            "authorization scope or profile does not match its proposal".into(),
        ));
    }
    if authorization.decision_maker_principal_id == proposal.proposer_principal_id {
        return Err(ContractError::Schema(
            "a decision-maker cannot authorize its own proposal (AUTH-03)".into(),
        ));
    }
    // ACT-02: an approval cannot outlive the intent it approves — an
    // authorization expiring after its own proposal would let execution
    // proceed against a proposal the proposer's own stated expiry had
    // already retired.
    if authorization.expiry > proposal.expiry {
        return Err(ContractError::Schema(
            "authorization expiry outlives its proposal's expiry (ACT-02)".into(),
        ));
    }
    Ok(AuthorizedActionV1 {
        proposal_digest,
        authorization_digest,
    })
}

/// Canonical execution request identity (ACT-03).
///
/// Deliberately excludes every observational field (timestamps, provider
/// request ID, revalidated state): a timeout or retry that resupplies the
/// same proposal, authorization, and idempotency key recomputes the exact
/// same [`AttemptIdV1`] and therefore never mints a new action identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequestV1 {
    pub schema_version: u32,
    pub proposal_digest: ActionProposalDigestV1,
    pub authorization_digest: AuthorizationDigestV1,
    pub idempotency_key: FixedHex32,
}

impl ExecutionRequestV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != ACTION_EXECUTION_REQUEST_SCHEMA_VERSION {
            return Err(ContractError::Schema(
                "invalid action execution request".into(),
            ));
        }
        Ok(())
    }

    pub fn attempt_id(&self) -> ContractResult<AttemptIdV1> {
        self.validate_shape()?;
        Ok(AttemptIdV1::from_digest(domain_separated_digest(
            DigestDomain::ActionAttemptV1,
            &encode_canonical(self)?,
        )))
    }
}

/// ACT-03: reuse of an idempotency key with a different canonical execution
/// request fails closed. Reuse with the exact same request is a no-op: both
/// recompute the same [`AttemptIdV1`].
pub fn check_idempotency_reuse(
    previous: &ExecutionRequestV1,
    candidate: &ExecutionRequestV1,
) -> ContractResult<()> {
    previous.validate_shape()?;
    candidate.validate_shape()?;
    if previous.idempotency_key != candidate.idempotency_key {
        return Ok(());
    }
    if previous.proposal_digest != candidate.proposal_digest
        || previous.authorization_digest != candidate.authorization_digest
    {
        return Err(ContractError::Schema(
            "idempotency key reused with a different canonical execution request".into(),
        ));
    }
    Ok(())
}

/// One attempt to execute an authorized request (ACT-03).
///
/// `revalidated_current_state` and `revalidated_preconditions` are what the
/// runtime observed immediately before dispatch; [`revalidate_authorization`]
/// is the only pure check that compares them against the authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAttemptV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub request: ExecutionRequestV1,
    pub revalidated_current_state: ActionStateDigestV1,
    pub revalidated_preconditions: Vec<ContractId>,
    pub revalidated_at: CanonicalTimestamp,
    pub provider_request_id: ContractId,
    pub started_at: CanonicalTimestamp,
}

impl ExecutionAttemptV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        self.request.validate_shape()?;
        // ACT-03: "authorization expiry, remaining uses, and preconditions
        // are revalidated immediately before execution." Revalidation must
        // precede or coincide with execution start (never follow it — a
        // revalidation recorded after dispatch already began revalidates
        // nothing), and the gap between them is structurally bounded so
        // "immediately before" cannot mean an arbitrarily stale revalidation
        // that merely happens to predate `started_at`.
        if self.schema_version != ACTION_ATTEMPT_SCHEMA_VERSION
            || self.revalidated_preconditions.len() > MAX_PRECONDITIONS
            || !strictly_sorted(&self.revalidated_preconditions)
            || self.revalidated_at > self.started_at
        {
            return Err(ContractError::Schema("invalid execution attempt".into()));
        }
        let revalidated_at = parse_canonical_timestamp(&self.revalidated_at)?;
        let started_at = parse_canonical_timestamp(&self.started_at)?;
        if started_at - revalidated_at > MAX_REVALIDATION_TO_START_GAP {
            return Err(ContractError::Schema(
                "revalidation is not immediately before execution start (ACT-03)".into(),
            ));
        }
        Ok(())
    }

    pub fn attempt_id(&self) -> ContractResult<AttemptIdV1> {
        self.validate_shape()?;
        self.request.attempt_id()
    }
}

/// Opaque proof that an authorization was rechecked immediately before execution.
///
/// Exact authorization binding, unexpired, uses remaining, unchanged current
/// state (compare-and-swap), and an unchanged precondition set (ACT-03).
/// Constructible only via [`revalidate_authorization`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevalidatedAuthorizationV1 {
    attempt_id: AttemptIdV1,
    remaining_uses_after: u32,
}

impl RevalidatedAuthorizationV1 {
    pub const fn attempt_id(&self) -> AttemptIdV1 {
        self.attempt_id
    }

    pub const fn remaining_uses_after(&self) -> u32 {
        self.remaining_uses_after
    }
}

/// ACT-03: stale actions fail closed.
///
/// Rechecks current state with compare-and-swap semantics, and revalidates
/// authorization expiry, remaining uses, and the exact precondition set
/// immediately before execution.
///
/// Runtime obligation (not enforced by this pure leaf): `remaining_uses_before_attempt`
/// is a plain caller-supplied count, not a value this module reads from
/// durable storage. The runtime must persist `remaining_uses_after` from the
/// returned [`RevalidatedAuthorizationV1`] back to the authorization's durable
/// use counter, atomically with (or otherwise safely ordered against) any
/// concurrent revalidation of the same authorization — this function has no
/// way to detect a racing decrement it never saw.
pub fn revalidate_authorization(
    authorization: &AuthorizationV1,
    attempt: &ExecutionAttemptV1,
    remaining_uses_before_attempt: u32,
) -> ContractResult<RevalidatedAuthorizationV1> {
    let authorization_digest = authorization.authorization_digest()?;
    attempt.validate_shape()?;
    if attempt.request.authorization_digest != authorization_digest {
        return Err(ContractError::Schema(
            "execution attempt does not bind the exact authorization digest".into(),
        ));
    }
    // ACT-02/ACT-03: an authorization revalidates only the exact proposal it
    // was granted for. Without this, `attempt.request.proposal_digest` is a
    // wire-decoded field a caller controls; nothing else in this function
    // (or `reconcile_receipt`/`check_idempotency_reuse`) compares it against
    // `authorization.proposal_digest`, so a single authorization could
    // otherwise revalidate attempts declaring arbitrary, unauthorized
    // proposals.
    if attempt.request.proposal_digest != authorization.proposal_digest {
        return Err(ContractError::Schema(
            "execution attempt declares a proposal digest the authorization did not approve (ACT-02)"
                .into(),
        ));
    }
    if attempt.scope != authorization.scope || attempt.profile != authorization.profile {
        return Err(ContractError::Schema(
            "execution attempt scope or profile does not match its authorization".into(),
        ));
    }
    if attempt.revalidated_at >= authorization.expiry {
        return Err(ContractError::Schema(
            "authorization expired before revalidation (ACT-03)".into(),
        ));
    }
    if remaining_uses_before_attempt == 0
        || remaining_uses_before_attempt > authorization.permitted_uses
    {
        return Err(ContractError::Schema(
            "authorization has no remaining uses (ACT-03)".into(),
        ));
    }
    if attempt.revalidated_current_state != authorization.current_state {
        return Err(ContractError::Schema(
            "current state changed since authorization; stale precondition fails closed (ACT-03)"
                .into(),
        ));
    }
    if attempt.revalidated_preconditions != authorization.preconditions {
        return Err(ContractError::Schema(
            "revalidated preconditions no longer match the authorized set (ACT-03)".into(),
        ));
    }
    Ok(RevalidatedAuthorizationV1 {
        attempt_id: attempt.attempt_id()?,
        remaining_uses_after: remaining_uses_before_attempt - 1,
    })
}

/// Closed provider outcome taxonomy. An ambiguous outcome is `indeterminate`,
/// never silently coerced to failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderResultV1 {
    Success,
    Failure,
    Ambiguous,
}

/// Closed reconciliation state (ACT-03/ACT-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationStateV1 {
    Reconciled,
    Indeterminate,
    Failed,
}

/// Exact before/after identities and provider result for one attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceiptV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub attempt_id: AttemptIdV1,
    pub before_state: ActionStateDigestV1,
    pub after_state: Option<ActionStateDigestV1>,
    pub provider_result: ProviderResultV1,
    pub completion_digest: Sha256Digest,
    pub reconciliation_state: ReconciliationStateV1,
    pub provider_request_id: ContractId,
    pub recorded_at: CanonicalTimestamp,
}

impl ExecutionReceiptV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        // ACT-03/ACT-04: "an ambiguous provider outcome is `indeterminate`,
        // not failure." A raw `Ambiguous` provider result may only ever be
        // recorded as `Indeterminate`; it must never be coerced directly to
        // `Reconciled` or `Failed` on this same receipt. Determining the
        // real outcome later (by provider request ID and read-after-write)
        // produces a distinct receipt whose `provider_result` reflects what
        // was actually established (`Success`/`Failure`), reconciled via
        // [`reconcile_receipt`] against the same unchanged attempt identity
        // — it never rewrites an ambiguous receipt's own outcome in place.
        let outcome_is_consistent = matches!(
            (
                self.provider_result,
                self.reconciliation_state,
                self.after_state.is_some(),
            ),
            (
                ProviderResultV1::Success,
                ReconciliationStateV1::Reconciled,
                true
            ) | (
                ProviderResultV1::Failure,
                ReconciliationStateV1::Failed,
                false
            ) | (
                ProviderResultV1::Ambiguous,
                ReconciliationStateV1::Indeterminate,
                false
            )
        );
        if self.schema_version != ACTION_RECEIPT_SCHEMA_VERSION
            || self.completion_digest == Sha256Digest::ZERO
            || !outcome_is_consistent
        {
            return Err(ContractError::Schema("invalid execution receipt".into()));
        }
        Ok(())
    }

    pub fn receipt_id(&self) -> ContractResult<ReceiptIdV1> {
        self.validate_shape()?;
        Ok(ReceiptIdV1::from_digest(domain_separated_digest(
            DigestDomain::ActionReceiptV1,
            &encode_canonical(self)?,
        )))
    }
}

/// Opaque proof that a receipt was reconciled to its exact attempt by
/// provider request ID (ACT-03). Constructible only via [`reconcile_receipt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconciledExecutionV1 {
    attempt_id: AttemptIdV1,
    receipt_id: ReceiptIdV1,
    reconciliation_state: ReconciliationStateV1,
}

impl ReconciledExecutionV1 {
    pub const fn attempt_id(&self) -> AttemptIdV1 {
        self.attempt_id
    }

    pub const fn receipt_id(&self) -> ReceiptIdV1 {
        self.receipt_id
    }

    pub const fn reconciliation_state(&self) -> ReconciliationStateV1 {
        self.reconciliation_state
    }
}

/// ACT-03: the same attempt is reconciled by provider request ID and
/// read-after-write state, never by wall-clock proximity or a fresh attempt.
pub fn reconcile_receipt(
    attempt: &ExecutionAttemptV1,
    receipt: &ExecutionReceiptV1,
) -> ContractResult<ReconciledExecutionV1> {
    let attempt_id = attempt.attempt_id()?;
    let receipt_id = receipt.receipt_id()?;
    if receipt.attempt_id != attempt_id {
        return Err(ContractError::Schema(
            "receipt does not bind the exact attempt identity".into(),
        ));
    }
    if receipt.provider_request_id != attempt.provider_request_id {
        return Err(ContractError::Schema(
            "receipt is not reconciled by the exact provider request ID (ACT-03)".into(),
        ));
    }
    // ACT-03/APPL-01: the receipt that closes an attempt must assert the
    // exact pre-state the CAS was performed against, and the exact tenant
    // scope the attempt was authorized under — never an arbitrary pre-state
    // or a cross-tenant scope smuggled in on the closing receipt.
    if receipt.before_state != attempt.revalidated_current_state {
        return Err(ContractError::Schema(
            "receipt before-state does not match the attempt's revalidated current state (ACT-03)"
                .into(),
        ));
    }
    if receipt.scope != attempt.scope || receipt.profile != attempt.profile {
        return Err(ContractError::Schema(
            "receipt scope or profile does not match its attempt".into(),
        ));
    }
    if receipt.recorded_at < attempt.started_at {
        return Err(ContractError::Schema(
            "receipt predates the attempt it reconciles".into(),
        ));
    }
    Ok(ReconciledExecutionV1 {
        attempt_id,
        receipt_id,
        reconciliation_state: receipt.reconciliation_state,
    })
}

/// Closed verification outcome for one metric/query/rule observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationResultV1 {
    Candidate,
    Verified,
    Refuted,
    Indeterminate,
}

/// Closed mitigation conclusion (ACT-04). Deliberately independent of
/// [`VerificationResultV1`]: recovery is not root-cause resolution, so no
/// pure function in this module derives one from the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MitigationConclusionV1 {
    Mitigated,
    NotMitigated,
    Indeterminate,
}

/// A metric/query/rule observation over one receipt (ACT-04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub receipt_id: ReceiptIdV1,
    pub metric_or_rule: ContractId,
    pub observation_window_start: CanonicalTimestamp,
    pub observation_window_end: CanonicalTimestamp,
    pub result: VerificationResultV1,
    pub mitigation_conclusion: MitigationConclusionV1,
    pub recorded_at: CanonicalTimestamp,
}

impl VerificationV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        if self.schema_version != ACTION_VERIFICATION_SCHEMA_VERSION
            || self.observation_window_end <= self.observation_window_start
        {
            return Err(ContractError::Schema("invalid action verification".into()));
        }
        Ok(())
    }

    pub fn verification_id(&self) -> ContractResult<VerificationIdV1> {
        self.validate_shape()?;
        Ok(VerificationIdV1::from_digest(domain_separated_digest(
            DigestDomain::ActionVerificationV1,
            &encode_canonical(self)?,
        )))
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path, str::FromStr};

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::memory_contracts::{
        canonical::{decode_strict, require_canonical},
        common::frozen_profile_reference_v1,
        identity::IdentityForm,
    };

    const PROPOSAL_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/action/proposal.jsonl");
    const AUTHORIZATION_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/action/authorization.jsonl");
    const ATTEMPT_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/action/execution-attempt.jsonl");
    const RECEIPT_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/action/execution-receipt.jsonl");
    const VERIFICATION_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/action/verification.jsonl");
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/action/vector-suite.jsonl");

    const PROPOSAL_DIGEST: &str =
        "d30cb678c2488ab7972968bf1c626962f83b4f6c37e3689c05dcdd606798f5fa";
    const AUTHORIZATION_DIGEST: &str =
        "b0a7b9a89d41a20a7b56ad572241b45027f1c20abdb743914aff8a6015cba482";
    const ATTEMPT_ID: &str = "760703adb756672d4688e40bffee05e658ee5df630561f09d1219f28b05b0d8b";
    const RECEIPT_ID: &str = "b397f45899a71822327b8d62f7f69fd9606fff5154de6eada2fbfbdca3043cee";
    const VERIFICATION_ID: &str =
        "52acc011337f5ca3dde28b3c298fc6f3008ad9b0dda25bc732d1396a2b3d29d6";
    const VECTOR_SUITE_DIGEST: &str =
        "21b2f0ef7e7e450622e55266b9cc04d40e9f82f91dafec69676e209dc998929a";

    fn record(bytes: &[u8]) -> &[u8] {
        let body = bytes
            .strip_suffix(b"\n")
            .expect("contract artifact must have one framing LF");
        assert!(!body.ends_with(b"\n"));
        assert!(!body.contains(&b'\r'));
        body
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_str(value).unwrap()
    }

    fn raw_sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn framed_raw_sha256(bytes: &[u8]) -> String {
        let mut framed = bytes.to_vec();
        framed.push(b'\n');
        raw_sha256(&framed)
    }

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.fixture").unwrap(),
            ContractId::new("project.fixture").unwrap(),
        )
    }

    fn state(digit: char) -> ActionStateDigestV1 {
        ActionStateDigestV1::from_digest(digest(&digit.to_string().repeat(64)))
    }

    fn target() -> ResourceUri {
        format!(
            "urn:ostk:{}:v1:{}:sha256:{}",
            IdentityForm::Entity.as_str(),
            "deployment_cohort",
            "9".repeat(64)
        )
        .parse()
        .unwrap()
    }

    fn proposal() -> ActionProposalV1 {
        ActionProposalV1 {
            schema_version: 1,
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            proposer_principal_id: ContractId::new("principal.incident_agent").unwrap(),
            operation: ActionOperationV1 {
                operation_id: ContractId::new("deployment.rollback").unwrap(),
                target: target(),
            },
            expected_pre_state: state('1'),
            desired_outcome_digest: digest(&"2".repeat(64)),
            expiry: CanonicalTimestamp::parse("2026-08-16T01:00:00.000000000Z").unwrap(),
            risk: ActionRiskLevelV1::High,
            rollback_plan_digest: digest(&"3".repeat(64)),
        }
    }

    fn authorization() -> AuthorizationV1 {
        AuthorizationV1 {
            schema_version: 1,
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            decision_maker_principal_id: ContractId::new("principal.on_call_engineer").unwrap(),
            proposal_digest: proposal().proposal_digest().unwrap(),
            environment: ContractId::new("environment.production").unwrap(),
            current_state: state('1'),
            target_state: state('4'),
            preconditions: vec![
                ContractId::new("precondition.change_ticket_open").unwrap(),
                ContractId::new("precondition.on_call_paged").unwrap(),
            ],
            expiry: CanonicalTimestamp::parse("2026-08-16T00:30:00.000000000Z").unwrap(),
            permitted_uses: 1,
        }
    }

    fn execution_request() -> ExecutionRequestV1 {
        let authorized = authorize(&proposal(), &authorization()).unwrap();
        authorized
            .open_execution_request(FixedHex32::from_bytes([0x5a; 32]))
            .unwrap()
    }

    fn attempt() -> ExecutionAttemptV1 {
        ExecutionAttemptV1 {
            schema_version: 1,
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            request: execution_request(),
            revalidated_current_state: state('1'),
            revalidated_preconditions: authorization().preconditions,
            revalidated_at: CanonicalTimestamp::parse("2026-08-16T00:05:00.000000000Z").unwrap(),
            provider_request_id: ContractId::new("provider.request.abc123").unwrap(),
            started_at: CanonicalTimestamp::parse("2026-08-16T00:05:00.000000000Z").unwrap(),
        }
    }

    fn receipt() -> ExecutionReceiptV1 {
        ExecutionReceiptV1 {
            schema_version: 1,
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            attempt_id: attempt().attempt_id().unwrap(),
            before_state: state('1'),
            after_state: Some(state('4')),
            provider_result: ProviderResultV1::Success,
            completion_digest: digest(&"6".repeat(64)),
            reconciliation_state: ReconciliationStateV1::Reconciled,
            provider_request_id: ContractId::new("provider.request.abc123").unwrap(),
            recorded_at: CanonicalTimestamp::parse("2026-08-16T00:06:00.000000000Z").unwrap(),
        }
    }

    fn verification() -> VerificationV1 {
        VerificationV1 {
            schema_version: 1,
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            receipt_id: receipt().receipt_id().unwrap(),
            metric_or_rule: ContractId::new("slo.http_error_rate").unwrap(),
            observation_window_start: CanonicalTimestamp::parse("2026-08-16T00:06:00.000000000Z")
                .unwrap(),
            observation_window_end: CanonicalTimestamp::parse("2026-08-16T00:16:00.000000000Z")
                .unwrap(),
            result: VerificationResultV1::Verified,
            mitigation_conclusion: MitigationConclusionV1::Mitigated,
            recorded_at: CanonicalTimestamp::parse("2026-08-16T00:16:00.000000000Z").unwrap(),
        }
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ActionVectorSuiteV1 {
        schema_version: u32,
        fixture_authority: String,
        proposal_path: String,
        proposal_raw_sha256: String,
        proposal_digest: ActionProposalDigestV1,
        authorization_path: String,
        authorization_raw_sha256: String,
        authorization_digest: AuthorizationDigestV1,
        attempt_path: String,
        attempt_raw_sha256: String,
        attempt_id: AttemptIdV1,
        receipt_path: String,
        receipt_raw_sha256: String,
        receipt_id: ReceiptIdV1,
        verification_path: String,
        verification_raw_sha256: String,
        verification_id: VerificationIdV1,
        negative_cases: Vec<String>,
    }

    fn negative_cases() -> Vec<String> {
        [
            "ambiguous_provider_result_requires_indeterminate",
            "attempt_declares_unauthorized_proposal_digest",
            "attempt_scope_or_profile_mismatch_rejected",
            "authorization_expiry_outlives_proposal_rejected",
            "authorization_expiry_reached",
            "idempotency_reuse_different_authorization",
            "idempotency_reuse_different_proposal",
            "mitigation_independent_of_verification_result",
            "receipt_before_state_mismatch",
            "receipt_predates_attempt",
            "receipt_provider_request_id_mismatch",
            "receipt_scope_mismatch",
            "receipt_wrong_attempt_binding",
            "reconciliation_state_result_mismatch",
            "revalidated_at_after_started_at_rejected",
            "revalidation_gap_exceeds_freshness_window_rejected",
            "self_authorized_proposal_rejected",
            "stale_current_state_fails_closed",
            "stale_preconditions_fail_closed",
            "unknown_field",
            "uses_exhausted",
            "wrong_authorization_proposal_digest",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn vector_suite(
        proposal_bytes: &[u8],
        authorization_bytes: &[u8],
        attempt_bytes: &[u8],
        receipt_bytes: &[u8],
        verification_bytes: &[u8],
    ) -> ActionVectorSuiteV1 {
        ActionVectorSuiteV1 {
            schema_version: 1,
            fixture_authority: "none; structural canonical fixture bytes never prove an authenticated decision-maker, observed system state, or provider execution".into(),
            proposal_path: "proposal.jsonl".into(),
            proposal_raw_sha256: framed_raw_sha256(proposal_bytes),
            proposal_digest: proposal().proposal_digest().unwrap(),
            authorization_path: "authorization.jsonl".into(),
            authorization_raw_sha256: framed_raw_sha256(authorization_bytes),
            authorization_digest: authorization().authorization_digest().unwrap(),
            attempt_path: "execution-attempt.jsonl".into(),
            attempt_raw_sha256: framed_raw_sha256(attempt_bytes),
            attempt_id: attempt().attempt_id().unwrap(),
            receipt_path: "execution-receipt.jsonl".into(),
            receipt_raw_sha256: framed_raw_sha256(receipt_bytes),
            receipt_id: receipt().receipt_id().unwrap(),
            verification_path: "verification.jsonl".into(),
            verification_raw_sha256: framed_raw_sha256(verification_bytes),
            verification_id: verification().verification_id().unwrap(),
            negative_cases: negative_cases(),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn hard_coded_fixtures_match_canonical_vectors() {
        for bytes in [
            PROPOSAL_FIXTURE,
            AUTHORIZATION_FIXTURE,
            ATTEMPT_FIXTURE,
            RECEIPT_FIXTURE,
            VERIFICATION_FIXTURE,
            VECTOR_SUITE_FIXTURE,
        ] {
            require_canonical(record(bytes)).unwrap();
        }

        let expected_proposal = proposal();
        assert_eq!(
            encode_canonical(&expected_proposal).unwrap(),
            record(PROPOSAL_FIXTURE)
        );
        let decoded_proposal: ActionProposalV1 = decode_strict(record(PROPOSAL_FIXTURE)).unwrap();
        decoded_proposal.validate_shape().unwrap();
        assert_eq!(decoded_proposal, expected_proposal);

        let expected_authorization = authorization();
        assert_eq!(
            encode_canonical(&expected_authorization).unwrap(),
            record(AUTHORIZATION_FIXTURE)
        );
        let decoded_authorization: AuthorizationV1 =
            decode_strict(record(AUTHORIZATION_FIXTURE)).unwrap();
        decoded_authorization.validate_shape().unwrap();
        assert_eq!(decoded_authorization, expected_authorization);

        let expected_attempt = attempt();
        assert_eq!(
            encode_canonical(&expected_attempt).unwrap(),
            record(ATTEMPT_FIXTURE)
        );
        let decoded_attempt: ExecutionAttemptV1 = decode_strict(record(ATTEMPT_FIXTURE)).unwrap();
        decoded_attempt.validate_shape().unwrap();
        assert_eq!(decoded_attempt, expected_attempt);

        let expected_receipt = receipt();
        assert_eq!(
            encode_canonical(&expected_receipt).unwrap(),
            record(RECEIPT_FIXTURE)
        );
        let decoded_receipt: ExecutionReceiptV1 = decode_strict(record(RECEIPT_FIXTURE)).unwrap();
        decoded_receipt.validate_shape().unwrap();
        assert_eq!(decoded_receipt, expected_receipt);

        let expected_verification = verification();
        assert_eq!(
            encode_canonical(&expected_verification).unwrap(),
            record(VERIFICATION_FIXTURE)
        );
        let decoded_verification: VerificationV1 =
            decode_strict(record(VERIFICATION_FIXTURE)).unwrap();
        decoded_verification.validate_shape().unwrap();
        assert_eq!(decoded_verification, expected_verification);

        let expected_suite = vector_suite(
            &encode_canonical(&expected_proposal).unwrap(),
            &encode_canonical(&expected_authorization).unwrap(),
            &encode_canonical(&expected_attempt).unwrap(),
            &encode_canonical(&expected_receipt).unwrap(),
            &encode_canonical(&expected_verification).unwrap(),
        );
        assert_eq!(
            encode_canonical(&expected_suite).unwrap(),
            record(VECTOR_SUITE_FIXTURE)
        );
        let suite: ActionVectorSuiteV1 = decode_strict(record(VECTOR_SUITE_FIXTURE)).unwrap();
        assert_eq!(suite, expected_suite);
        assert!(strictly_sorted(&suite.negative_cases));

        assert_eq!(
            expected_proposal.proposal_digest().unwrap().digest(),
            digest(PROPOSAL_DIGEST)
        );
        assert_eq!(
            expected_authorization
                .authorization_digest()
                .unwrap()
                .digest(),
            digest(AUTHORIZATION_DIGEST)
        );
        assert_eq!(
            expected_attempt.attempt_id().unwrap().digest(),
            digest(ATTEMPT_ID)
        );
        assert_eq!(
            expected_receipt.receipt_id().unwrap().digest(),
            digest(RECEIPT_ID)
        );
        assert_eq!(
            expected_verification.verification_id().unwrap().digest(),
            digest(VERIFICATION_ID)
        );
        assert_eq!(
            domain_separated_digest(
                DigestDomain::TestVectorManifest,
                record(VECTOR_SUITE_FIXTURE)
            ),
            digest(VECTOR_SUITE_DIGEST)
        );

        assert_eq!(raw_sha256(PROPOSAL_FIXTURE), suite.proposal_raw_sha256);
        assert_eq!(
            raw_sha256(AUTHORIZATION_FIXTURE),
            suite.authorization_raw_sha256
        );
        assert_eq!(raw_sha256(ATTEMPT_FIXTURE), suite.attempt_raw_sha256);
        assert_eq!(raw_sha256(RECEIPT_FIXTURE), suite.receipt_raw_sha256);
        assert_eq!(
            raw_sha256(VERIFICATION_FIXTURE),
            suite.verification_raw_sha256
        );
    }

    #[test]
    fn authorization_binds_exact_proposal_digest_and_rejects_self_promotion() {
        let authorized = authorize(&proposal(), &authorization()).unwrap();
        assert_eq!(
            authorized.proposal_digest(),
            proposal().proposal_digest().unwrap()
        );

        let mut wrong_digest = authorization();
        wrong_digest.proposal_digest = ActionProposalDigestV1::from_digest(digest(&"e".repeat(64)));
        assert!(authorize(&proposal(), &wrong_digest).is_err());

        let mut self_authorized = authorization();
        self_authorized.decision_maker_principal_id = proposal().proposer_principal_id;
        assert!(authorize(&proposal(), &self_authorized).is_err());
    }

    #[test]
    fn authorization_expiry_outlives_proposal_rejected() {
        let mut later_expiry = authorization();
        later_expiry.expiry = CanonicalTimestamp::parse("2026-08-16T02:00:00.000000000Z").unwrap();
        assert!(authorize(&proposal(), &later_expiry).is_err());

        // Exactly equal to the proposal's own expiry is still acceptable:
        // the approval does not outlive the intent it approves.
        let mut equal_expiry = authorization();
        equal_expiry.expiry = proposal().expiry;
        authorize(&proposal(), &equal_expiry).unwrap();
    }

    #[test]
    fn idempotency_reuse_is_exact_or_rejected() {
        let request = execution_request();
        assert!(check_idempotency_reuse(&request, &request).is_ok());

        let mut different_proposal = request;
        different_proposal.proposal_digest =
            ActionProposalDigestV1::from_digest(digest(&"f".repeat(64)));
        assert!(check_idempotency_reuse(&request, &different_proposal).is_err());

        let mut different_authorization = request;
        different_authorization.authorization_digest =
            AuthorizationDigestV1::from_digest(digest(&"f".repeat(64)));
        assert!(check_idempotency_reuse(&request, &different_authorization).is_err());

        let mut different_key = request;
        different_key.idempotency_key = FixedHex32::from_bytes([0x11; 32]);
        assert!(check_idempotency_reuse(&request, &different_key).is_ok());
    }

    #[test]
    fn timeout_retry_never_mints_a_new_attempt_identity() {
        let first = attempt();
        let mut retried = attempt();
        retried.revalidated_at =
            CanonicalTimestamp::parse("2026-08-16T00:10:00.000000000Z").unwrap();
        retried.started_at = retried.revalidated_at.clone();
        retried.provider_request_id = ContractId::new("provider.request.def456").unwrap();
        assert_eq!(first.attempt_id().unwrap(), retried.attempt_id().unwrap());
    }

    #[test]
    fn revalidation_fails_closed_on_stale_state_expiry_and_uses() {
        let authorized_authorization = authorization();
        revalidate_authorization(&authorized_authorization, &attempt(), 1).unwrap();

        let mut stale_state = attempt();
        stale_state.revalidated_current_state = state('9');
        assert!(revalidate_authorization(&authorized_authorization, &stale_state, 1).is_err());

        let mut stale_preconditions = attempt();
        stale_preconditions.revalidated_preconditions =
            vec![ContractId::new("precondition.on_call_paged").unwrap()];
        assert!(
            revalidate_authorization(&authorized_authorization, &stale_preconditions, 1).is_err()
        );

        let mut expired = attempt();
        expired.revalidated_at =
            CanonicalTimestamp::parse("2026-08-16T01:00:00.000000000Z").unwrap();
        expired.started_at = expired.revalidated_at.clone();
        assert!(revalidate_authorization(&authorized_authorization, &expired, 1).is_err());

        assert!(revalidate_authorization(&authorized_authorization, &attempt(), 0).is_err());
        assert!(revalidate_authorization(&authorized_authorization, &attempt(), 2).is_err());
    }

    #[test]
    fn revalidated_at_after_started_at_rejected() {
        // Positive: revalidated strictly before execution start, within the
        // declared freshness window.
        let mut on_time = attempt();
        on_time.started_at = CanonicalTimestamp::parse("2026-08-16T00:05:00.000000000Z").unwrap();
        on_time.revalidated_at =
            CanonicalTimestamp::parse("2026-08-16T00:04:30.000000000Z").unwrap();
        on_time.validate_shape().unwrap();
        revalidate_authorization(&authorization(), &on_time, 1).unwrap();

        // Negative: a revalidation recorded *after* dispatch already began
        // revalidates nothing and must be rejected, not accepted as if a
        // later timestamp were merely "fresher."
        let mut revalidated_after_start = attempt();
        revalidated_after_start.started_at =
            CanonicalTimestamp::parse("2026-08-16T00:05:00.000000000Z").unwrap();
        revalidated_after_start.revalidated_at =
            CanonicalTimestamp::parse("2026-08-16T00:20:00.000000000Z").unwrap();
        assert!(revalidated_after_start.validate_shape().is_err());
    }

    #[test]
    fn revalidation_gap_exceeds_freshness_window_rejected() {
        // Revalidated strictly before start, but far enough before it that
        // it no longer counts as "immediately before execution."
        let mut stale_gap = attempt();
        stale_gap.started_at = CanonicalTimestamp::parse("2026-08-16T00:20:00.000000000Z").unwrap();
        stale_gap.revalidated_at =
            CanonicalTimestamp::parse("2026-08-16T00:05:00.000000000Z").unwrap();
        assert!(stale_gap.validate_shape().is_err());
    }

    #[test]
    fn attempt_declares_unauthorized_proposal_digest() {
        // ACT-02/ACT-03 PROV finding: an attempt whose request names a
        // proposal digest the authorization never approved must not
        // revalidate, even though the attempt still binds the correct
        // authorization digest.
        let mut unauthorized_proposal = attempt();
        unauthorized_proposal.request.proposal_digest =
            ActionProposalDigestV1::from_digest(digest(&"c".repeat(64)));
        assert_ne!(
            unauthorized_proposal.request.proposal_digest,
            authorization().proposal_digest
        );
        assert!(revalidate_authorization(&authorization(), &unauthorized_proposal, 1).is_err());
    }

    #[test]
    fn attempt_scope_or_profile_mismatch_rejected() {
        let mut mismatched_scope = attempt();
        mismatched_scope.scope = AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.attacker").unwrap(),
            ContractId::new("project.attacker").unwrap(),
        );
        assert!(revalidate_authorization(&authorization(), &mismatched_scope, 1).is_err());
    }

    #[test]
    fn ambiguous_provider_outcome_is_indeterminate_not_failure() {
        let mut ambiguous = receipt();
        ambiguous.provider_result = ProviderResultV1::Ambiguous;
        ambiguous.reconciliation_state = ReconciliationStateV1::Indeterminate;
        ambiguous.after_state = None;
        ambiguous.validate_shape().unwrap();

        let mut coerced_to_failure = ambiguous;
        coerced_to_failure.reconciliation_state = ReconciliationStateV1::Failed;
        assert!(coerced_to_failure.validate_shape().is_err());
    }

    #[test]
    fn reconciliation_state_result_mismatch() {
        // Every (provider_result, reconciliation_state, after_state) triple
        // outside the three closed combinations fails closed, not only the
        // Ambiguous-coerced-to-Failed case above.
        let mut success_marked_failed = receipt();
        success_marked_failed.reconciliation_state = ReconciliationStateV1::Failed;
        assert!(success_marked_failed.validate_shape().is_err());

        let mut failure_marked_reconciled = receipt();
        failure_marked_reconciled.provider_result = ProviderResultV1::Failure;
        failure_marked_reconciled.after_state = None;
        assert!(failure_marked_reconciled.validate_shape().is_err());

        let mut success_missing_after_state = receipt();
        success_missing_after_state.after_state = None;
        assert!(success_missing_after_state.validate_shape().is_err());
    }

    #[test]
    fn reconciliation_binds_exact_attempt_and_provider_request_id() {
        let reconciled = reconcile_receipt(&attempt(), &receipt()).unwrap();
        assert_eq!(reconciled.attempt_id(), attempt().attempt_id().unwrap());
        assert_eq!(
            reconciled.reconciliation_state(),
            ReconciliationStateV1::Reconciled
        );

        let mut wrong_attempt = receipt();
        wrong_attempt.attempt_id = AttemptIdV1::from_digest(digest(&"7".repeat(64)));
        assert!(reconcile_receipt(&attempt(), &wrong_attempt).is_err());

        let mut wrong_provider_request = receipt();
        wrong_provider_request.provider_request_id =
            ContractId::new("provider.request.other").unwrap();
        assert!(reconcile_receipt(&attempt(), &wrong_provider_request).is_err());

        let mut before_attempt = receipt();
        before_attempt.recorded_at =
            CanonicalTimestamp::parse("2026-08-15T00:00:00.000000000Z").unwrap();
        assert!(reconcile_receipt(&attempt(), &before_attempt).is_err());
    }

    #[test]
    fn receipt_before_state_mismatch() {
        // ACT-03: the receipt closing an attempt must assert the exact
        // pre-state the compare-and-swap was performed against, never an
        // arbitrary before-state.
        let mut wrong_before_state = receipt();
        wrong_before_state.before_state = state('9');
        assert_ne!(
            wrong_before_state.before_state,
            attempt().revalidated_current_state
        );
        assert!(reconcile_receipt(&attempt(), &wrong_before_state).is_err());
    }

    #[test]
    fn receipt_scope_mismatch() {
        // APPL-01/ACT-03: a receipt from a different tenant/project scope
        // must never close another tenant's attempt.
        let mut wrong_scope = receipt();
        wrong_scope.scope = AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.attacker").unwrap(),
            ContractId::new("project.attacker").unwrap(),
        );
        assert!(reconcile_receipt(&attempt(), &wrong_scope).is_err());
    }

    #[test]
    fn mitigation_conclusion_is_independent_of_verification_result() {
        let mut mitigated_but_refuted = verification();
        mitigated_but_refuted.result = VerificationResultV1::Refuted;
        mitigated_but_refuted.mitigation_conclusion = MitigationConclusionV1::Mitigated;
        mitigated_but_refuted.validate_shape().unwrap();

        let mut not_mitigated_but_verified = verification();
        not_mitigated_but_verified.result = VerificationResultV1::Verified;
        not_mitigated_but_verified.mitigation_conclusion = MitigationConclusionV1::NotMitigated;
        not_mitigated_but_verified.validate_shape().unwrap();
    }

    #[test]
    fn no_confidence_or_risk_field_can_grant_permission() {
        let authorization_bytes = encode_canonical(&authorization()).unwrap();
        let text = std::str::from_utf8(&authorization_bytes).unwrap();
        for forbidden in ["confidence", "trust_score", "\"risk\""] {
            assert!(!text.contains(forbidden), "forbidden field {forbidden}");
        }
        let attempt_bytes = encode_canonical(&attempt()).unwrap();
        let attempt_text = std::str::from_utf8(&attempt_bytes).unwrap();
        for forbidden in ["confidence", "trust_score", "\"risk\""] {
            assert!(
                !attempt_text.contains(forbidden),
                "forbidden field {forbidden}"
            );
        }
    }

    #[test]
    fn unknown_fields_and_malformed_bindings_fail_closed() {
        let canonical = record(PROPOSAL_FIXTURE);
        let mut value: serde_json::Value = serde_json::from_slice(canonical).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("confidence".into(), serde_json::Value::Bool(true));
        assert!(decode_strict::<ActionProposalV1>(&serde_json::to_vec(&value).unwrap()).is_err());

        let mut zero_digest = proposal();
        zero_digest.desired_outcome_digest = Sha256Digest::ZERO;
        assert!(zero_digest.validate_shape().is_err());

        let mut unsorted_preconditions = authorization();
        unsorted_preconditions.preconditions = vec![
            ContractId::new("precondition.on_call_paged").unwrap(),
            ContractId::new("precondition.change_ticket_open").unwrap(),
        ];
        assert!(unsorted_preconditions.validate_shape().is_err());

        let mut zero_uses = authorization();
        zero_uses.permitted_uses = 0;
        assert!(zero_uses.validate_shape().is_err());

        let mut inverted_window = verification();
        inverted_window.observation_window_end = inverted_window.observation_window_start.clone();
        assert!(inverted_window.validate_shape().is_err());
    }

    #[test]
    #[ignore = "maintainer-only canonical action fixture regeneration"]
    fn regenerate_action_contract_artifacts() {
        fn write(output: &Path, name: &str, bytes: &[u8]) {
            let mut framed = bytes.to_vec();
            framed.push(b'\n');
            fs::write(output.join(name), framed).unwrap();
        }

        let output = std::env::var_os("ACTION_VECTOR_OUTPUT")
            .map(std::path::PathBuf::from)
            .expect("ACTION_VECTOR_OUTPUT is required");
        fs::create_dir_all(&output).unwrap();

        let proposal_bytes = encode_canonical(&proposal()).unwrap();
        let authorization_bytes = encode_canonical(&authorization()).unwrap();
        let attempt_bytes = encode_canonical(&attempt()).unwrap();
        let receipt_bytes = encode_canonical(&receipt()).unwrap();
        let verification_bytes = encode_canonical(&verification()).unwrap();
        let suite = vector_suite(
            &proposal_bytes,
            &authorization_bytes,
            &attempt_bytes,
            &receipt_bytes,
            &verification_bytes,
        );
        let suite_bytes = encode_canonical(&suite).unwrap();

        for (name, bytes) in [
            ("proposal.jsonl", proposal_bytes.as_slice()),
            ("authorization.jsonl", authorization_bytes.as_slice()),
            ("execution-attempt.jsonl", attempt_bytes.as_slice()),
            ("execution-receipt.jsonl", receipt_bytes.as_slice()),
            ("verification.jsonl", verification_bytes.as_slice()),
            ("vector-suite.jsonl", suite_bytes.as_slice()),
        ] {
            write(&output, name, bytes);
        }

        println!("PROPOSAL_DIGEST {}", proposal().proposal_digest().unwrap());
        println!(
            "AUTHORIZATION_DIGEST {}",
            authorization().authorization_digest().unwrap()
        );
        println!("ATTEMPT_ID {}", attempt().attempt_id().unwrap());
        println!("RECEIPT_ID {}", receipt().receipt_id().unwrap());
        println!(
            "VERIFICATION_ID {}",
            verification().verification_id().unwrap()
        );
        println!(
            "VECTOR_SUITE_DIGEST {}",
            domain_separated_digest(DigestDomain::TestVectorManifest, &suite_bytes)
        );
    }
}
