//! Admission rules, record shapes, and the repository trait for the
//! discrepancy ledger runtime (W3-DISC, Stage 6).
//!
//! [`admit_envelope`], [`admit_lifecycle_event`], and [`admit_relation`] are
//! the whole fail-closed boundary, and they are pure: they run before any
//! transaction opens, so a rejected record never touches the database. Every
//! check below is an ordinary negative test in `repository_tests.rs`.
//!
//! # Scope binds from the runtime, never from the payload
//!
//! The authenticated `(tenant, project)` scope a record claims must equal the
//! scope the repository was constructed for — the same
//! [`crate::control_log::TrustedControlScope`] discipline the normative and
//! observer runtimes use. A payload declaring its own scope is refused with a
//! typed error before anything is written; knowledge of a public episode
//! fingerprint alone never authorizes a cross-tenant append.
//!
//! # The envelope cannot self-select its authority
//!
//! An envelope names an episode policy and a comparator lineage by registry
//! reference. Admission requires the caller to present the exact
//! structurally-resolved bodies those references must match
//! ([`DiscrepancyEnvelopeCandidateV1`]); the contract's own
//! `validate_against_episode_policy` / `validate_against_comparator_lineage`
//! then prove the references (including entry digests) agree with the
//! presented bodies, so a producer cannot cite a policy while declaring its
//! own continuity key, nor cite a lineage while declaring its own required
//! applicability dimensions.

use async_trait::async_trait;

use crate::Result;
use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::common::{AuthenticatedProjectScopeV1, CanonicalTimestamp};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, domain_separated_digest};
use crate::memory_contracts::discrepancy::{
    DiscrepancyEnvelopeId, DiscrepancyEnvelopeV1, DiscrepancyEpisodeFingerprintV1,
    DiscrepancyEpisodeRelationV1, DiscrepancyFamilyFingerprintV1, DiscrepancyLifecycleEventId,
    DiscrepancyLifecycleEventV1, LifecycleState, StructurallyResolvedComparatorLineageV1,
    StructurallyResolvedEpisodePolicyV2, VerificationState, authorize_lifecycle_transition,
};
use crate::memory_contracts::{ContractError, ContractResult};
use crate::registry_witness::WriterAuthorityWitness;
use serde::{Deserialize, Serialize};

/// The active registry head this runtime is bound to at construction.
///
/// The caller reads it from the registry activation head and hands it over
/// once; every envelope must name exactly this package and activation policy
/// or it is stale. Binding it at construction is what stops an envelope from
/// choosing which registry it is judged against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscrepancyRegistryBindingV1 {
    pub registry_package_digest: Sha256Digest,
    pub activation_policy_digest: Sha256Digest,
}

impl DiscrepancyRegistryBindingV1 {
    /// The binding a strict writer-authority witness certifies: the active
    /// head's package and activation-policy digests, never caller-supplied
    /// ones. The witness is a snapshot of one read (D4), so a caller re-reads
    /// it for every invocation rather than caching the binding.
    #[must_use]
    pub const fn from_witness(witness: &WriterAuthorityWitness) -> Self {
        Self {
            registry_package_digest: witness.package_digest(),
            activation_policy_digest: witness.activation_policy_digest(),
        }
    }

    /// Reject a zero digest closed: an unbound runtime must not exist.
    pub fn validate(&self) -> ContractResult<()> {
        if self.registry_package_digest == Sha256Digest::ZERO
            || self.activation_policy_digest == Sha256Digest::ZERO
        {
            return Err(ContractError::Schema(
                "discrepancy runtime registry binding must name a non-zero package and policy"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// One envelope admission attempt: the envelope plus the exact resolved
/// policy and lineage bodies its references must match.
#[derive(Debug, Clone)]
pub struct DiscrepancyEnvelopeCandidateV1 {
    pub envelope: DiscrepancyEnvelopeV1,
    pub resolved_episode_policy: StructurallyResolvedEpisodePolicyV2,
    pub resolved_comparator_lineage: StructurallyResolvedComparatorLineageV1,
}

/// An envelope that passed every pure check, with its derived identities and
/// the exact canonical bytes the ledger appends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedDiscrepancyEnvelopeV1 {
    pub envelope_id: DiscrepancyEnvelopeId,
    pub family_fingerprint: DiscrepancyFamilyFingerprintV1,
    pub episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    pub canonical_envelope: Vec<u8>,
}

/// Every pure fail-closed check an envelope must pass, in one place.
pub fn admit_envelope(
    candidate: &DiscrepancyEnvelopeCandidateV1,
    binding: &DiscrepancyRegistryBindingV1,
    bound_scope: &AuthenticatedProjectScopeV1,
) -> ContractResult<AdmittedDiscrepancyEnvelopeV1> {
    binding.validate()?;
    let envelope = &candidate.envelope;
    envelope.validate_shape()?;

    // SCOPE binding: the envelope's authenticated project scope must be the
    // scope this repository was constructed for. A payload minted for another
    // tenant/project is refused before a transaction opens.
    if &envelope.scope != bound_scope {
        return Err(ContractError::Schema(
            "discrepancy envelope scope is not the runtime's bound project scope".into(),
        ));
    }

    // Registry binding: an envelope judged against a registry package or
    // activation policy other than the live one is stale, not merely
    // different.
    if envelope.registry.head.package_digest != binding.registry_package_digest
        || envelope.registry.head.activation_policy_digest != binding.activation_policy_digest
    {
        return Err(ContractError::StaleRegistryHead);
    }

    // The envelope's episode-policy reference and continuity key must be the
    // REGISTERED ones (digest-checked), and its comparator-lineage
    // fingerprint and required-applicability set must be the registered
    // lineage's own — never the payload's declaration.
    envelope.validate_against_episode_policy(&candidate.resolved_episode_policy)?;
    envelope.validate_against_comparator_lineage(&candidate.resolved_comparator_lineage)?;

    Ok(AdmittedDiscrepancyEnvelopeV1 {
        envelope_id: envelope.envelope_id()?,
        family_fingerprint: envelope.family_fingerprint,
        episode_fingerprint: envelope.episode_fingerprint,
        canonical_envelope: encode_canonical(envelope)?,
    })
}

/// A lifecycle event that passed every pure check against its stored
/// envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedDiscrepancyLifecycleEventV1 {
    pub event_id: DiscrepancyLifecycleEventId,
    pub episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    pub canonical_event: Vec<u8>,
}

/// Authorize one lifecycle event against the DURABLE envelope it targets.
///
/// `envelope` is the stored envelope the repository loaded, never a
/// caller-supplied copy, so the AUTH-03 self-implication checks and the
/// DISC-05 waiver-scope check inside the contract's
/// [`authorize_lifecycle_transition`] run against the identity the ledger
/// actually holds.
pub fn admit_lifecycle_event(
    envelope: &DiscrepancyEnvelopeV1,
    event: &DiscrepancyLifecycleEventV1,
    bound_scope: &AuthenticatedProjectScopeV1,
) -> ContractResult<AdmittedDiscrepancyLifecycleEventV1> {
    // The event's own scope must be the runtime's bound scope. The contract
    // check below additionally proves it equals the envelope's scope; this
    // check keeps the boundary honest even if the two ever diverge.
    if &event.scope != bound_scope {
        return Err(ContractError::Schema(
            "discrepancy lifecycle event scope is not the runtime's bound project scope".into(),
        ));
    }
    authorize_lifecycle_transition(envelope, event)?;
    Ok(AdmittedDiscrepancyLifecycleEventV1 {
        event_id: event.lifecycle_event_id()?,
        episode_fingerprint: event.episode_fingerprint,
        canonical_event: encode_canonical(event)?,
    })
}

/// A relation that passed every pure check, with its ledger identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedDiscrepancyRelationV1 {
    pub relation_id: Sha256Digest,
    pub family_fingerprint: DiscrepancyFamilyFingerprintV1,
    pub canonical_relation: Vec<u8>,
}

/// Validate one episode relation for append.
///
/// The relation's authenticated scope must be the runtime's bound scope: a
/// relation can force the strongest suppression a projection can reach
/// (`Superseded`) purely from public episode fingerprints, so scope is
/// checked here exactly as for envelopes and lifecycle events. The
/// per-episode family agreement is proven inside the repository transaction
/// against the stored envelopes ([`DiscrepancyLedgerRepository::append_relation`]).
pub fn admit_relation(
    relation: &DiscrepancyEpisodeRelationV1,
    bound_scope: &AuthenticatedProjectScopeV1,
) -> ContractResult<AdmittedDiscrepancyRelationV1> {
    relation.validate_shape()?;
    if &relation.scope != bound_scope {
        return Err(ContractError::Schema(
            "discrepancy episode relation scope is not the runtime's bound project scope".into(),
        ));
    }
    let canonical_relation = encode_canonical(relation)?;
    Ok(AdmittedDiscrepancyRelationV1 {
        relation_id: domain_separated_digest(
            DigestDomain::DiscrepancyEpisodeRelationV1,
            &canonical_relation,
        ),
        family_fingerprint: relation.family_fingerprint,
        canonical_relation,
    })
}

/// One record in an episode's append-only ledger log.
///
/// Sequence 1 is always the envelope; every later sequence is a lifecycle
/// event. Relations live in their own family-keyed store because one
/// relation names several episodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)] // one envelope seeds each log; boxing it buys nothing.
pub enum DiscrepancyLogRecordV1 {
    Envelope { envelope: DiscrepancyEnvelopeV1 },
    Lifecycle { event: DiscrepancyLifecycleEventV1 },
}

impl DiscrepancyLogRecordV1 {
    #[must_use]
    pub const fn record_kind(&self) -> &'static str {
        match self {
            Self::Envelope { .. } => "envelope",
            Self::Lifecycle { .. } => "lifecycle",
        }
    }

    /// A stored record must still satisfy its contract shape when replayed.
    pub fn validate(&self) -> ContractResult<()> {
        match self {
            Self::Envelope { envelope } => envelope.validate_shape(),
            Self::Lifecycle { event } => event.validate_shape(),
        }
    }
}

/// One durable log row, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscrepancyLogEntryV1 {
    pub seq: u64,
    pub record_id: Sha256Digest,
    pub record: DiscrepancyLogRecordV1,
}

/// The durable projection row for one episode: the canonical projection
/// bytes plus the denormalised read columns and the deterministic evaluation
/// instant they were computed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDiscrepancyProjectionV1 {
    pub episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    pub cursor_seq: u64,
    pub evaluated_at: CanonicalTimestamp,
    pub lifecycle_state: LifecycleState,
    pub verification_state: VerificationState,
    pub canonical_projection: Vec<u8>,
}

/// What one accepted append did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscrepancyLedgerTransitionV1 {
    /// The appended record's own identity (envelope id, lifecycle event id,
    /// or relation id).
    pub record_id: Sha256Digest,
    /// The episode-log sequence the record landed at; `None` for a relation,
    /// which appends to the family relation store rather than one episode's
    /// log.
    pub log_seq: Option<u64>,
    /// Every episode whose stored projection was recomputed in the same
    /// transaction as the append.
    pub refreshed_episodes: Vec<DiscrepancyEpisodeFingerprintV1>,
}

/// Outcome of one append attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscrepancyAppendOutcomeV1 {
    /// The record and its projection refresh committed together.
    Appended(DiscrepancyLedgerTransitionV1),
    /// A byte-identical record is already durable. Nothing was written: an
    /// at-least-once delivery retry is idempotent, not double-applied.
    AlreadyRecorded { record_id: Sha256Digest },
}

/// The lifecycle states of an episode that still stands: open,
/// acknowledged, or waived (a waiver expires back to open). Resolved,
/// dismissed, and superseded episodes are closed.
pub const STANDING_LIFECYCLE_STATES: [LifecycleState; 3] = [
    LifecycleState::Open,
    LifecycleState::Acknowledged,
    LifecycleState::Waived,
];

/// Whether an episode in `state` still stands
/// ([`STANDING_LIFECYCLE_STATES`]).
#[must_use]
pub const fn is_standing(state: LifecycleState) -> bool {
    matches!(
        state,
        LifecycleState::Open | LifecycleState::Acknowledged | LifecycleState::Waived
    )
}

/// What an admission that opens at most one standing episode per family did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscrepancyOpeningOutcomeV1 {
    /// The envelope seeded its episode, or this exact envelope was already
    /// durable.
    Admitted(DiscrepancyAppendOutcomeV1),
    /// The envelope's family already has this standing episode, the lowest
    /// keyed one if several stand. Nothing was written.
    FamilyStands(DiscrepancyEpisodeFingerprintV1),
}

/// Append and read surface for the discrepancy ledger, bound once to
/// physical scope, semantic scope, and the active registry head.
#[async_trait]
pub trait DiscrepancyLedgerRepository: Send + Sync {
    /// Admit one detection envelope, seeding its episode's log at sequence 1
    /// and its projection, atomically. A byte-identical envelope is
    /// idempotent; a DIFFERENT envelope for an already-seeded episode is
    /// refused closed (per-detection identity is immutable).
    async fn admit_envelope(
        &self,
        candidate: &DiscrepancyEnvelopeCandidateV1,
    ) -> Result<DiscrepancyAppendOutcomeV1>;

    /// Append one lifecycle event to its episode's log and advance the
    /// projection with it, atomically. Refused closed when the episode has
    /// no admitted envelope, or when the contract's authorization (scope,
    /// AUTH-03 self-implication, DISC-05 waiver rules) rejects the event
    /// against the STORED envelope.
    async fn append_lifecycle_event(
        &self,
        event: &DiscrepancyLifecycleEventV1,
    ) -> Result<DiscrepancyAppendOutcomeV1>;

    /// Append one episode relation to its family's relation store and
    /// recompute the stored projection of every in-scope episode the
    /// relation names, atomically. Refused closed when any in-scope episode
    /// it names belongs to a different family, scope, or profile than the
    /// relation claims.
    async fn append_relation(
        &self,
        relation: &DiscrepancyEpisodeRelationV1,
    ) -> Result<DiscrepancyAppendOutcomeV1>;

    /// Read the stored envelope seeding one episode, if admitted.
    async fn read_envelope(
        &self,
        episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    ) -> Result<Option<DiscrepancyEnvelopeV1>>;

    /// Read one episode's whole ledger log, in sequence order.
    async fn read_log(
        &self,
        episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    ) -> Result<Vec<DiscrepancyLogEntryV1>>;

    /// Read every stored relation for one family.
    async fn read_relations(
        &self,
        family_fingerprint: DiscrepancyFamilyFingerprintV1,
    ) -> Result<Vec<DiscrepancyEpisodeRelationV1>>;

    /// Read the stored projection exactly as persisted.
    async fn read_projection(
        &self,
        episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    ) -> Result<Option<StoredDiscrepancyProjectionV1>>;

    /// Re-derive the projection from the durable log and relation store
    /// alone. Must equal the stored projection byte for byte.
    async fn rebuild_projection(
        &self,
        episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    ) -> Result<StoredDiscrepancyProjectionV1>;
}

/// Denormalised column value for a lifecycle state.
#[must_use]
pub const fn lifecycle_state_str(state: LifecycleState) -> &'static str {
    match state {
        LifecycleState::Open => "open",
        LifecycleState::Acknowledged => "acknowledged",
        LifecycleState::Resolved => "resolved",
        LifecycleState::Waived => "waived",
        LifecycleState::Dismissed => "dismissed",
        LifecycleState::Superseded => "superseded",
    }
}

/// Decode a stored lifecycle-state column, failing closed on drift.
pub fn lifecycle_state_from_str(value: &str) -> ContractResult<LifecycleState> {
    Ok(match value {
        "open" => LifecycleState::Open,
        "acknowledged" => LifecycleState::Acknowledged,
        "resolved" => LifecycleState::Resolved,
        "waived" => LifecycleState::Waived,
        "dismissed" => LifecycleState::Dismissed,
        "superseded" => LifecycleState::Superseded,
        _ => {
            return Err(ContractError::Schema(
                "stored lifecycle state is not a known value".into(),
            ));
        }
    })
}

/// Denormalised column value for a verification state.
#[must_use]
pub const fn verification_state_str(state: VerificationState) -> &'static str {
    match state {
        VerificationState::Candidate => "candidate",
        VerificationState::Verified => "verified",
        VerificationState::Refuted => "refuted",
        VerificationState::Indeterminate => "indeterminate",
    }
}

/// Decode a stored verification-state column, failing closed on drift.
pub fn verification_state_from_str(value: &str) -> ContractResult<VerificationState> {
    Ok(match value {
        "candidate" => VerificationState::Candidate,
        "verified" => VerificationState::Verified,
        "refuted" => VerificationState::Refuted,
        "indeterminate" => VerificationState::Indeterminate,
        _ => {
            return Err(ContractError::Schema(
                "stored verification state is not a known value".into(),
            ));
        }
    })
}

#[cfg(test)]
#[path = "repository_tests.rs"]
mod tests;
