//! Erasure event, tombstone, fence, generation, receipt, and legal-hold
//! contracts (EVID-01, EVID-05, EVID-08, EVID-09).
//!
//! This module is contract-only. [`ErasureEventV1`] is a public candidate
//! shape: it establishes byte identity and structural validity, never
//! authority to erase anything. The only way to obtain
//! [`AdmittedErasureEventV1`], the opaque capability a future append
//! repository would consume, is [`AdmittedErasureEventV1::from_test_witness`],
//! which exists only under `#[cfg(test)]`. Likewise
//! [`ErasureAcceptanceEffectV1`] — the atomic bundle of a retrieval-deny
//! tombstone plus the fence and generation transitions an acceptance forces —
//! has no production constructor. Untrusted input can propose an erasure; it
//! cannot manufacture the accepted effect of one.
//!
//! [`ErasureScope`] is exactly the typed target every evidence representation
//! already indexes under `erasure_scopes`
//! ([`super::evidence::ErasureScopeReferenceV1`]): `representation`,
//! `source_fact`, `resource`, or `privacy_subject`, plus the exact digest of
//! the erased identity. Erasure and evidence share one type on purpose, so an
//! erasure event's declared target and a representation's indexed scope
//! compare without a lossy conversion, and a parent-scope erasure (a
//! `privacy_subject` tombstone) and a child-scope erasure (a `representation`
//! tombstone) are just two entries in the same closed enum rather than a
//! separate hierarchy this module would otherwise have to invent and get
//! wrong.
//!
//! The composite fence ([`ErasureFenceV1`]) tracks one epoch per scope kind,
//! per tenant/project — not per exact target. That is a deliberate
//! coarsening: any erasure of a given kind in a tenant/project advances that
//! kind's shared counter, so a projection/embedding/cache/archive commit that
//! captured an `expected` fence and later CASes against `current`
//! ([`ErasureFenceCasV1::may_commit`]) fails closed the moment *any* erasure
//! of a relevant kind lands, without this module needing to reason about
//! which exact target the in-flight work touched.

use serde::{Deserialize, Serialize};

use super::{
    ContractError, ContractResult,
    canonical::encode_canonical,
    common::{
        AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, ProfileReferenceV1,
        RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    evidence::VisibilityClass,
};

const ERASURE_SCHEMA_VERSION: u32 = 1;
const ERASURE_ACCEPTED_EVENT_KIND: &str = "erasure.accepted";
const MAX_RESIDUAL_STORES: usize = 64;
const MAX_RECOMPUTE_TARGETS: usize = 256;

pub use super::evidence::AcceptedEventId;
/// Exactly the typed target an evidence representation already indexes under
/// `erasure_scopes`. See the module documentation for why this is a type
/// alias rather than a parallel definition.
pub use super::evidence::{ErasureScopeKind, ErasureScopeReferenceV1 as ErasureScope};

fn validate_policy_reference(reference: &RegistryReferenceV1) -> ContractResult<()> {
    reference.validate()?;
    if reference.entry_digest == Sha256Digest::ZERO {
        return Err(ContractError::Schema(
            "erasure policy reference cannot use the zero digest".into(),
        ));
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

/// Effective interval over which an erasure (or a legal hold, or a
/// representation's earlier retention) applies. `effective_until` is
/// exclusive and, when present, strictly after `effective_from`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveIntervalV1 {
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
}

impl EffectiveIntervalV1 {
    fn validate(&self) -> ContractResult<()> {
        let until_is_valid = self
            .effective_until
            .as_ref()
            .is_none_or(|until| until.is_microsecond_aligned() && *until > self.effective_from);
        if !self.effective_from.is_microsecond_aligned() || !until_is_valid {
            return Err(ContractError::Schema(
                "invalid erasure effective interval".into(),
            ));
        }
        Ok(())
    }
}

/// Separately authorized prospective re-consent semantics named by an erasure
/// event.
///
/// Re-consent is forward-looking only: it may authorize a genuinely
/// new source fact under a new consent basis, and by construction of
/// [`re_consent_permits_new_source_fact`] it can never be used to revive the
/// exact identity a tombstone covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProspectiveReConsentV1 {
    NotAuthorized,
    AuthorizedForNewSourceFact { consent_policy: RegistryReferenceV1 },
}

/// Stable accepted-erasure semantic preimage proposed to the append ledger.
///
/// Public construction and hashing establish byte shape only. A later
/// repository seam must independently resolve `policy_basis` against an
/// active registry witness, confirm `policy_basis_effective_from` from that
/// same witness (never from this payload alone), and prove authority to
/// erase `target` before this candidate may become an
/// [`AdmittedErasureEventV1`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureEventV1 {
    pub schema_version: u32,
    pub event_kind: ContractId,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub target: ErasureScope,
    pub effective: EffectiveIntervalV1,
    pub policy_basis: RegistryReferenceV1,
    pub policy_basis_effective_from: CanonicalTimestamp,
    pub re_consent: ProspectiveReConsentV1,
    pub requested_at: CanonicalTimestamp,
}

impl ErasureEventV1 {
    /// Validate structural bindings only. This does not admit the event.
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        self.effective.validate()?;
        validate_policy_reference(&self.policy_basis)?;
        if let ProspectiveReConsentV1::AuthorizedForNewSourceFact { consent_policy } =
            &self.re_consent
        {
            validate_policy_reference(consent_policy)?;
        }
        if self.schema_version != ERASURE_SCHEMA_VERSION
            || self.event_kind.as_str() != ERASURE_ACCEPTED_EVENT_KIND
            || self.target.target_digest == Sha256Digest::ZERO
            || !self.policy_basis_effective_from.is_microsecond_aligned()
            || !self.requested_at.is_microsecond_aligned()
            // An erasure cannot claim effect under a policy basis before that
            // basis itself took effect.
            || self.effective.effective_from < self.policy_basis_effective_from
        {
            return Err(ContractError::Schema(
                "invalid erasure event candidate".into(),
            ));
        }
        Ok(())
    }

    /// Semantic accepted-event identity. Receipt and append metadata cannot
    /// affect it because those values are not fields in this preimage.
    pub fn accepted_event_id(&self) -> ContractResult<AcceptedEventId> {
        self.validate_shape()?;
        Ok(AcceptedEventId::from_digest(domain_separated_digest(
            DigestDomain::ErasureEventV1,
            &encode_canonical(self)?,
        )))
    }
}

/// Opaque authority capability consumed by the future erasure-acceptance
/// repository.
///
/// No production constructor exists in this contract-only
/// stage. Deserializing or structurally validating [`ErasureEventV1`] cannot
/// create it.
#[derive(Debug)]
pub struct AdmittedErasureEventV1 {
    event: ErasureEventV1,
    accepted_event_id: AcceptedEventId,
}

impl AdmittedErasureEventV1 {
    pub const fn event(&self) -> &ErasureEventV1 {
        &self.event
    }

    pub const fn accepted_event_id(&self) -> AcceptedEventId {
        self.accepted_event_id
    }

    #[cfg(test)]
    fn from_test_witness(event: ErasureEventV1) -> ContractResult<Self> {
        let accepted_event_id = event.accepted_event_id()?;
        Ok(Self {
            event,
            accepted_event_id,
        })
    }
}

/// Monotonic tenant/project erasure generation. Every accepted erasure event
/// increments this counter; it never decreases.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureGenerationV1 {
    pub scope: AuthenticatedProjectScopeV1,
    pub value: u64,
}

impl ErasureGenerationV1 {
    /// Whether `self` is a valid monotonic advance over `previous` within the
    /// same tenant/project scope.
    pub fn advances(&self, previous: &Self) -> bool {
        self.scope == previous.scope && self.value > previous.value
    }
}

/// One scope-kind's epoch counter within a composite fence. See the module
/// documentation for why this is per scope-kind rather than per exact
/// target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureFenceEntryV1 {
    pub kind: ErasureScopeKind,
    pub epoch: u64,
}

const REQUIRED_FENCE_KINDS: [ErasureScopeKind; 4] = [
    ErasureScopeKind::PrivacySubject,
    ErasureScopeKind::Representation,
    ErasureScopeKind::Resource,
    ErasureScopeKind::SourceFact,
];

/// Composite fence covering the representation, source-fact, resource, and
/// privacy-subject scopes plus the tenant/project erasure generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureFenceV1 {
    pub schema_version: u32,
    pub scope: AuthenticatedProjectScopeV1,
    pub entries: Vec<ErasureFenceEntryV1>,
    pub generation: ErasureGenerationV1,
}

impl ErasureFenceV1 {
    pub fn validate(&self) -> ContractResult<()> {
        let covers_every_required_kind = REQUIRED_FENCE_KINDS
            .iter()
            .all(|kind| self.entries.iter().any(|entry| entry.kind == *kind));
        if self.schema_version != ERASURE_SCHEMA_VERSION
            || self.generation.scope != self.scope
            || self.entries.len() != REQUIRED_FENCE_KINDS.len()
            || !strictly_sorted(&self.entries)
            || !covers_every_required_kind
        {
            return Err(ContractError::Schema(
                "erasure fence must cover exactly the four scope kinds once each".into(),
            ));
        }
        Ok(())
    }

    /// Content-addressed identity of this exact fence state, so a CAS log or
    /// audit trail can name one fence snapshot without re-embedding it.
    pub fn fence_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::ErasureFenceV1,
            &encode_canonical(self)?,
        ))
    }
}

/// Two-sided compare-and-swap preimage a projection/embedding/cache/archive
/// commit must present: the fence it observed when work began (`expected`)
/// versus the fence at commit time (`current`).
///
/// Any entry epoch that moved,
/// or a generation that moved, fails the commit closed — the mechanical form
/// of "work begun before a parent, subject, or child tombstone cannot commit
/// afterward" (EVID-09).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureFenceCasV1 {
    pub expected: ErasureFenceV1,
    pub current: ErasureFenceV1,
}

impl ErasureFenceCasV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.expected.validate()?;
        self.current.validate()?;
        if self.expected.scope != self.current.scope {
            return Err(ContractError::Schema(
                "erasure fence CAS preimage crosses tenant/project scope".into(),
            ));
        }
        Ok(())
    }

    /// Whether the work that captured `expected` may still commit against
    /// `current`. `false` means the commit must fail closed and restart from
    /// a freshly observed fence.
    pub fn may_commit(&self) -> ContractResult<bool> {
        self.validate()?;
        let same_generation = self.expected.generation.value == self.current.generation.value;
        let no_epoch_advanced = self.current.entries.iter().all(|current_entry| {
            self.expected.entries.iter().any(|expected_entry| {
                expected_entry.kind == current_entry.kind
                    && expected_entry.epoch == current_entry.epoch
            })
        });
        Ok(same_generation && no_epoch_advanced)
    }
}

/// Closed, single-variant pin of a tombstone's retrieval semantics. The
/// variant itself — not a boolean any input could flip — is what a tombstone
/// asserts: retrieval is denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TombstoneDenyModeV1 {
    RetrievalDeny,
}

/// Lifecycle metadata retained beyond the bare digest, gated by policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TombstoneLifecycleV1 {
    DigestOnly,
    DigestAndMetadata {
        installed_at: CanonicalTimestamp,
        superseded_by: Option<AcceptedEventId>,
    },
}

/// Immutable record installed atomically with an accepted erasure event.
///
/// It
/// carries no payload byte, canonical text, or embedding — only a digest,
/// policy reference, and policy-gated lifecycle metadata.
/// `#[serde(deny_unknown_fields)]` on this type and on
/// [`TombstoneLifecycleV1`] means no later field can smuggle payload bytes
/// back in without becoming a new, separately reviewed contract version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureTombstoneV1 {
    pub schema_version: u32,
    pub deny_mode: TombstoneDenyModeV1,
    pub target: ErasureScope,
    pub erasure_event_id: AcceptedEventId,
    pub policy_basis: RegistryReferenceV1,
    pub lifecycle: TombstoneLifecycleV1,
}

impl ErasureTombstoneV1 {
    pub fn validate(&self) -> ContractResult<()> {
        validate_policy_reference(&self.policy_basis)?;
        let lifecycle_is_valid = match &self.lifecycle {
            TombstoneLifecycleV1::DigestOnly => true,
            TombstoneLifecycleV1::DigestAndMetadata {
                installed_at,
                superseded_by,
            } => {
                installed_at.is_microsecond_aligned()
                    && superseded_by
                        .as_ref()
                        .is_none_or(|id| id.digest() != Sha256Digest::ZERO)
            }
        };
        if self.schema_version != ERASURE_SCHEMA_VERSION
            || self.target.target_digest == Sha256Digest::ZERO
            || self.erasure_event_id.digest() == Sha256Digest::ZERO
            || !lifecycle_is_valid
        {
            return Err(ContractError::Schema("invalid erasure tombstone".into()));
        }
        Ok(())
    }

    /// Content-addressed identity of this exact tombstone. Two tombstones
    /// with the same `erasure_event_id` and `target` but different lifecycle
    /// metadata are different records and get different identities.
    pub fn tombstone_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::ErasureTombstoneV1,
            &encode_canonical(self)?,
        ))
    }
}

/// A prospective re-consent event may authorize a genuinely new source fact.
///
/// It can never revive the identity a tombstone covers and never permits
/// redelivery under that old identity: the candidate target must name a
/// different digest than the tombstoned one, re-consent must actually be
/// authorized, and its consent-policy reference must itself validate (a
/// zero-digest or unversioned policy reference authorizes nothing). This
/// checks one tombstone only, not the full tombstone set for the scope; a
/// caller must still confirm the candidate's scope does not conflict with
/// any other active tombstone before treating this as a complete
/// authorization decision.
///
/// This fails closed on the tombstone itself first: `tombstone.validate()`
/// must succeed before any permissive answer is possible. A tombstone this
/// module cannot validate (for example one carrying the zero sentinel as its
/// `target.target_digest`) has coverage nobody can determine, so it must
/// never be treated as "different from the candidate" and therefore
/// permissive — that would be the same fail-open shape this module closes
/// elsewhere (`RetainableMatcherPolicyV1::required_scope_action`,
/// `RestoreGateV1::outcome`) for an unvalidated input.
pub fn re_consent_permits_new_source_fact(
    tombstone: &ErasureTombstoneV1,
    re_consent: &ProspectiveReConsentV1,
    candidate_target: &ErasureScope,
) -> ContractResult<bool> {
    tombstone.validate()?;
    Ok(match re_consent {
        ProspectiveReConsentV1::AuthorizedForNewSourceFact { consent_policy } => {
            validate_policy_reference(consent_policy).is_ok()
                && candidate_target.target_digest != tombstone.target.target_digest
        }
        ProspectiveReConsentV1::NotAuthorized => false,
    })
}

/// The exact atomic effect of accepting one [`ErasureEventV1`]: the
/// retrieval-deny tombstone it installs, the fence entries it forces to
/// advance, and the tenant/project generation transition it forces.
///
/// No
/// production constructor exists in this contract-only stage; only a
/// repository seam performing the real atomic tombstone-install plus
/// epoch/generation increment in one transaction may vouch for this shape.
#[derive(Debug)]
pub struct ErasureAcceptanceEffectV1 {
    admitted_event: AdmittedErasureEventV1,
    tombstone: ErasureTombstoneV1,
    advanced_entries: Vec<ErasureFenceEntryV1>,
    generation_before: ErasureGenerationV1,
    generation_after: ErasureGenerationV1,
}

impl ErasureAcceptanceEffectV1 {
    pub const fn admitted_event(&self) -> &AdmittedErasureEventV1 {
        &self.admitted_event
    }

    pub const fn tombstone(&self) -> &ErasureTombstoneV1 {
        &self.tombstone
    }

    pub fn advanced_entries(&self) -> &[ErasureFenceEntryV1] {
        &self.advanced_entries
    }

    pub const fn generation_before(&self) -> &ErasureGenerationV1 {
        &self.generation_before
    }

    pub const fn generation_after(&self) -> &ErasureGenerationV1 {
        &self.generation_after
    }

    #[cfg(test)]
    fn from_test_witness(
        admitted_event: AdmittedErasureEventV1,
        tombstone: ErasureTombstoneV1,
        advanced_entries: Vec<ErasureFenceEntryV1>,
        generation_before: ErasureGenerationV1,
        generation_after: ErasureGenerationV1,
    ) -> ContractResult<Self> {
        tombstone.validate()?;
        let target = admitted_event.event().target.clone();
        let covers_own_kind = advanced_entries
            .iter()
            .any(|entry| entry.kind == target.kind);
        if tombstone.erasure_event_id != admitted_event.accepted_event_id()
            || tombstone.target != target
            || advanced_entries.is_empty()
            || !covers_own_kind
            || !generation_after.advances(&generation_before)
        {
            return Err(ContractError::Schema(
                "erasure acceptance effect is not internally consistent".into(),
            ));
        }
        Ok(Self {
            admitted_event,
            tombstone,
            advanced_entries,
            generation_before,
            generation_after,
        })
    }
}

/// Whether cleanup deleted Fleet Recall's own copy, or is only attesting to
/// deletion at the authoritative upstream provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureDeletionActorV1 {
    FleetRecall,
    AuthoritativeProvider,
}

/// One governed store's residual state for one erasure receipt.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureStoreResidualV1 {
    pub store_id: ContractId,
    pub deletion_actor: ErasureDeletionActorV1,
    pub residual_present: bool,
}

/// Closed receipt-state machine: a receipt starts `attempted`, may sit
/// `pending` while any store still shows a residual, and becomes `complete`
/// only once every governed store verifies removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureReceiptStateV1 {
    Attempted,
    Pending,
    Complete,
}

/// Cleanup outcome for one accepted erasure event.
///
/// `state = complete`
/// requires every residual to be absent and the key destroyed: key
/// destruction alone, with plaintext or a derived copy still resident
/// anywhere in `residual_inventory`, is not sufficient evidence of erasure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureReceiptV1 {
    pub schema_version: u32,
    pub erasure_event_id: AcceptedEventId,
    pub state: ErasureReceiptStateV1,
    pub residual_inventory: Vec<ErasureStoreResidualV1>,
    pub key_destroyed: bool,
    pub issued_at: CanonicalTimestamp,
}

impl ErasureReceiptV1 {
    pub fn validate(&self) -> ContractResult<()> {
        let any_residual_present = self
            .residual_inventory
            .iter()
            .any(|residual| residual.residual_present);
        if self.schema_version != ERASURE_SCHEMA_VERSION
            || self.erasure_event_id.digest() == Sha256Digest::ZERO
            || self.residual_inventory.is_empty()
            || self.residual_inventory.len() > MAX_RESIDUAL_STORES
            || !strictly_sorted(&self.residual_inventory)
            || !self.issued_at.is_microsecond_aligned()
            || (self.state == ErasureReceiptStateV1::Complete
                && (any_residual_present || !self.key_destroyed))
        {
            return Err(ContractError::Schema("invalid erasure receipt".into()));
        }
        Ok(())
    }

    /// Content-addressed identity of this exact receipt state. A later
    /// `pending` -> `complete` transition for the same `erasure_event_id`
    /// is a different record with a different identity, not a mutation.
    pub fn receipt_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::ErasureReceiptV1,
            &encode_canonical(self)?,
        ))
    }
}

/// A legal hold defers removal of `target` without ever widening its
/// visibility.
///
/// `visibility_ceiling` can never be `publication_approved`, so a
/// held private record cannot become public merely by being held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldV1 {
    pub schema_version: u32,
    pub target: ErasureScope,
    pub policy_basis: RegistryReferenceV1,
    pub placed_at: CanonicalTimestamp,
    pub released_at: Option<CanonicalTimestamp>,
    pub visibility_ceiling: VisibilityClass,
}

impl LegalHoldV1 {
    pub fn validate(&self) -> ContractResult<()> {
        validate_policy_reference(&self.policy_basis)?;
        let released_is_valid = self
            .released_at
            .as_ref()
            .is_none_or(|released| released.is_microsecond_aligned() && *released > self.placed_at);
        if self.schema_version != ERASURE_SCHEMA_VERSION
            || self.target.target_digest == Sha256Digest::ZERO
            || !self.placed_at.is_microsecond_aligned()
            || !released_is_valid
            || self.visibility_ceiling == VisibilityClass::PublicationApproved
        {
            return Err(ContractError::Schema("invalid legal hold".into()));
        }
        Ok(())
    }

    /// Whether removal may proceed at `at`. A hold defers removal for its
    /// entire active interval; only a recorded release lifts it.
    pub fn permits_removal(&self, at: &CanonicalTimestamp) -> bool {
        self.released_at
            .as_ref()
            .is_some_and(|released| released <= at)
    }

    /// Content-addressed identity of this exact hold state. Placing and
    /// later releasing a hold are different records with different
    /// identities, not an in-place mutation of one.
    pub fn hold_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::LegalHoldV1,
            &encode_canonical(self)?,
        ))
    }
}

/// The scope action a retainable-matcher policy forces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainableMatcherScopeActionV1 {
    Retain,
    DisableAndPurge,
}

/// Whether policy permits retaining even a pseudonymous matcher needed to
/// suppress late redelivery of an erased identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RetainableMatcherPolicyV1 {
    PseudonymousMatcherAllowed { matcher_policy: RegistryReferenceV1 },
    PseudonymousMatcherForbidden,
}

impl RetainableMatcherPolicyV1 {
    /// Validate the policy reference backing an allowed pseudonymous
    /// matcher. A matcher policy that cannot itself be verified (zero digest
    /// or unversioned) is not evidence that a matcher may be retained.
    pub fn validate(&self) -> ContractResult<()> {
        if let Self::PseudonymousMatcherAllowed { matcher_policy } = self {
            validate_policy_reference(matcher_policy)?;
        }
        Ok(())
    }

    /// The system must not promise replay-safe suppression while continuing
    /// to accept an event it can no longer recognize: once the sole
    /// retainable matcher is forbidden, the connector/resource scope must be
    /// disabled and purged rather than kept partially alive. A matcher
    /// policy that fails to validate can never report `Retain`.
    pub fn required_scope_action(&self) -> ContractResult<RetainableMatcherScopeActionV1> {
        self.validate()?;
        Ok(match self {
            Self::PseudonymousMatcherAllowed { .. } => RetainableMatcherScopeActionV1::Retain,
            Self::PseudonymousMatcherForbidden => RetainableMatcherScopeActionV1::DisableAndPurge,
        })
    }
}

/// Restore/reprojection outcome for one candidate reader or materialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreGateOutcomeV1 {
    Serve,
    Suppressed,
    Quarantined,
}

/// Gate a restore or reprojection must evaluate before exposing any reader.
///
/// The tombstone tail must be applied first: an un-applied tail cannot prove
/// absence of coverage, so `tombstone_tail_applied: false` must never be read
/// as "not covered."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreGateV1 {
    pub schema_version: u32,
    pub tombstone_tail_applied: bool,
    pub covered_by_tombstone: bool,
    pub quarantine_preferred: bool,
}

impl RestoreGateV1 {
    /// Decide the outcome for one candidate reader/materialization.
    pub fn outcome(&self) -> ContractResult<RestoreGateOutcomeV1> {
        if self.schema_version != ERASURE_SCHEMA_VERSION {
            return Err(ContractError::Schema(
                "restore gate schema_version is not recognized".into(),
            ));
        }
        if !self.tombstone_tail_applied {
            return Err(ContractError::Schema(
                "restore gate decided before its tombstone tail was applied".into(),
            ));
        }
        Ok(
            match (self.covered_by_tombstone, self.quarantine_preferred) {
                (true, true) => RestoreGateOutcomeV1::Quarantined,
                (true, false) => RestoreGateOutcomeV1::Suppressed,
                (false, _) => RestoreGateOutcomeV1::Serve,
            },
        )
    }
}

/// Closed verification-state machine for a proposition's support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportVerificationStateV1 {
    Verified,
    Unsupported,
    Unverifiable,
}

/// The re-evaluation forced when erased (or retention-expired) material was
/// the sole reproducible support for a proposition.
///
/// If retained canonical
/// redacted evidence remains sufficient under policy, support may stay
/// `verified` and there is nothing to recompute; otherwise it must downgrade
/// and name every dependent discrepancy that must be recomputed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependentSupportTransitionV1 {
    pub schema_version: u32,
    pub erasure_event_id: AcceptedEventId,
    pub next_state: SupportVerificationStateV1,
    pub sufficient_redacted_evidence_remains: bool,
    pub recompute_targets: Vec<AcceptedEventId>,
}

impl DependentSupportTransitionV1 {
    pub fn validate(&self) -> ContractResult<()> {
        let downgrades = !matches!(self.next_state, SupportVerificationStateV1::Verified);
        let any_recompute_target_zero = self
            .recompute_targets
            .iter()
            .any(|target| target.digest() == Sha256Digest::ZERO);
        if self.schema_version != ERASURE_SCHEMA_VERSION
            || self.erasure_event_id.digest() == Sha256Digest::ZERO
            || any_recompute_target_zero
            || self.recompute_targets.len() > MAX_RECOMPUTE_TARGETS
            || !strictly_sorted(&self.recompute_targets)
            // `sufficient_redacted_evidence_remains` and `downgrades` are two
            // names for the same fact; asserting both or neither is a
            // contradiction.
            || self.sufficient_redacted_evidence_remains == downgrades
            || (downgrades && self.recompute_targets.is_empty())
            || (!downgrades && !self.recompute_targets.is_empty())
        {
            return Err(ContractError::Schema(
                "invalid dependent support transition".into(),
            ));
        }
        Ok(())
    }
}

/// Erasure dominates checkpoints: a new checkpoint is minted at a strictly
/// higher erasure generation, and the old checkpoint's digest is never
/// advanced in place.
///
/// Constructing this rule with the same digest on both
/// sides, or a non-advancing generation, is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointErasureRuleV1 {
    pub schema_version: u32,
    pub previous_checkpoint_digest: Sha256Digest,
    pub previous_generation: ErasureGenerationV1,
    pub new_checkpoint_digest: Sha256Digest,
    pub new_generation: ErasureGenerationV1,
}

impl CheckpointErasureRuleV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != ERASURE_SCHEMA_VERSION
            || self.previous_checkpoint_digest == Sha256Digest::ZERO
            || self.new_checkpoint_digest == Sha256Digest::ZERO
            || self.previous_checkpoint_digest == self.new_checkpoint_digest
            || !self.new_generation.advances(&self.previous_generation)
        {
            return Err(ContractError::Schema(
                "invalid checkpoint erasure rule".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::memory_contracts::{
        canonical::{decode_strict, require_canonical},
        common::frozen_profile_reference_v1,
    };

    const ERASURE_EVENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/erasure-event-representation.jsonl"
    );
    const ERASURE_EVENT_PRIVACY_SUBJECT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/erasure-event-privacy-subject.jsonl"
    );
    const TOMBSTONE_DIGEST_ONLY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/erasure-tombstone-digest-only.jsonl"
    );
    const TOMBSTONE_WITH_METADATA_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/erasure-tombstone-with-metadata.jsonl"
    );
    const FENCE_GENESIS_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/erasure/erasure-fence-genesis.jsonl");
    const FENCE_ADVANCED_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/erasure/erasure-fence-advanced.jsonl");
    const FENCE_GENERATION_ONLY_ADVANCE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/erasure-fence-generation-only-advance.jsonl"
    );
    const FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/erasure-fence-privacy-subject-only-advance.jsonl"
    );
    const FENCE_REPRESENTATION_ONLY_ADVANCE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/erasure-fence-representation-only-advance.jsonl"
    );
    const RECEIPT_PENDING_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/erasure/erasure-receipt-pending.jsonl");
    const RECEIPT_COMPLETE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/erasure/erasure-receipt-complete.jsonl");
    const LEGAL_HOLD_ACTIVE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/erasure/legal-hold-active.jsonl");
    const RETAINABLE_MATCHER_FORBIDDEN_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/retainable-matcher-forbidden.jsonl"
    );
    const RESTORE_GATE_QUARANTINED_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/erasure/restore-gate-quarantined.jsonl");
    const DEPENDENT_TRANSITION_UNVERIFIABLE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/dependent-support-transition-unverifiable.jsonl"
    );
    const CHECKPOINT_RULE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/erasure/checkpoint-erasure-rule.jsonl");
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/erasure/vector-suite.jsonl");

    const NEGATIVE_TOMBSTONE_PAYLOAD_BYTES_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/negative-tombstone-payload-bytes.jsonl"
    );
    const NEGATIVE_RECEIPT_COMPLETE_WITH_RESIDUAL_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/negative-receipt-complete-with-residual.jsonl"
    );
    const NEGATIVE_RECEIPT_COMPLETE_RESIDUAL_DESPITE_KEY_DESTROYED_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/negative-receipt-complete-residual-despite-key-destroyed.jsonl"
    );
    const NEGATIVE_FENCE_MISSING_SCOPE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/negative-fence-missing-scope.jsonl"
    );
    const NEGATIVE_EVENT_EFFECTIVE_BEFORE_POLICY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/negative-event-effective-before-policy-basis.jsonl"
    );
    const NEGATIVE_LEGAL_HOLD_PUBLICATION_VISIBILITY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/negative-legal-hold-publication-visibility.jsonl"
    );
    const NEGATIVE_CHECKPOINT_SAME_DIGEST_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/negative-checkpoint-same-digest.jsonl"
    );
    const NEGATIVE_DEPENDENT_TRANSITION_CONTRADICTION_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/erasure/negative-dependent-transition-contradiction.jsonl"
    );

    const EVENT_RAW_SHA256: &str =
        "aaf2b43c93722e29a7597e8314b53bb9e70d62aed83498aba42f92546455e94f";
    const EVENT_PRIVACY_SUBJECT_RAW_SHA256: &str =
        "fc5450cd58e3ecd598edbbc2068e0c30cd0a777d9b52b015150028e06158cf2b";
    const TOMBSTONE_DIGEST_ONLY_RAW_SHA256: &str =
        "06d1fd3080df8b6b31ff65f0c28db932e6e5c8c05f2f6c4c0db98afdc4c25697";
    const TOMBSTONE_WITH_METADATA_RAW_SHA256: &str =
        "43cf525bfd163f7daa58713fc7a3687e164dffcf6f2338d627cf050538de022e";
    const FENCE_GENESIS_RAW_SHA256: &str =
        "c304c6dc2737fcd1e06ddc6b98575411e5bab964252584e74738de5f728de0b8";
    const FENCE_ADVANCED_RAW_SHA256: &str =
        "2a14a5116838ba3f2c36940386426b3ea76892e3eaf6a0145e4cc2dfa7c5e935";
    const FENCE_GENERATION_ONLY_ADVANCE_RAW_SHA256: &str =
        "41b1de5e55ba11e49728d8596111cd6894c1940aaff459c9804ace98cb7c3108";
    const FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_RAW_SHA256: &str =
        "c08ebbb1eaf85cbd221ba173b19f92178d94637eb5269704be0357c60771bdaf";
    const FENCE_REPRESENTATION_ONLY_ADVANCE_RAW_SHA256: &str =
        "e2408179f10ebf7b01bd3d3ed2f824e0c9d6f362a38fa56762cbe03e6132cde5";
    const RECEIPT_PENDING_RAW_SHA256: &str =
        "c555bc876c40b80d59a4097897d733cab27c93fb6e358a8ad3751e1931e08e34";
    const RECEIPT_COMPLETE_RAW_SHA256: &str =
        "aa42cb2037f281597b961efe23b0eb8f2a2e00e83b8d81f7c41940ed41e704ff";
    const LEGAL_HOLD_ACTIVE_RAW_SHA256: &str =
        "586821cd43f81e07dc83d0aee1d49d0086c3fb4d9fddcc520cbac0c49ea82aee";
    const RETAINABLE_MATCHER_FORBIDDEN_RAW_SHA256: &str =
        "ee23b0640acd9ee6f58bab284692486a96e2e4b46933bcbc803770eb15a867bd";
    const RESTORE_GATE_QUARANTINED_RAW_SHA256: &str =
        "39f95767f885d1ba9203d6c0042db3a502d8db9769f21a551c62f081e5cc3ec5";
    const DEPENDENT_TRANSITION_UNVERIFIABLE_RAW_SHA256: &str =
        "dd59e4c40c99112408ec84c2b53666fddc4ee631841d652eb336a2b27810e355";
    const CHECKPOINT_RULE_RAW_SHA256: &str =
        "209a78376cba81b37a84bf6e964bb1020689c58bf81df0b708b2fc866820b9a4";
    const VECTOR_SUITE_RAW_SHA256: &str =
        "f4655abf09783f04a4291c08805dfdb5ecbe1ca96b99ee2bcf24820e47631673";

    const NEGATIVE_TOMBSTONE_PAYLOAD_BYTES_RAW_SHA256: &str =
        "73bc971338b53b4d9a4c2a367fa360afaba779c43590dc5010a0dc48a0f23dc1";
    const NEGATIVE_RECEIPT_COMPLETE_WITH_RESIDUAL_RAW_SHA256: &str =
        "606949c8ba313c2292ab566670887c04fb9371126d2e02cb9b7d51d725262518";
    const NEGATIVE_RECEIPT_COMPLETE_RESIDUAL_DESPITE_KEY_DESTROYED_RAW_SHA256: &str =
        "63a770367f7cb6ca769e4b5d1c5e459f3a0cc4253de2f476c85dd5685bbc49f7";
    const NEGATIVE_FENCE_MISSING_SCOPE_RAW_SHA256: &str =
        "e756d74843605c550000bbc70681ca660e7ff692c6f7610af1ccaa08c2ca91ab";
    const NEGATIVE_EVENT_EFFECTIVE_BEFORE_POLICY_RAW_SHA256: &str =
        "ee34d4a521822ab59fa0373a86eaca1bd98947944f618b9bc57ff55befec2710";
    const NEGATIVE_LEGAL_HOLD_PUBLICATION_VISIBILITY_RAW_SHA256: &str =
        "233dfcd14b4d95749e38760cd347879a86399e9670d537b427e1bf64c7ffa850";
    const NEGATIVE_CHECKPOINT_SAME_DIGEST_RAW_SHA256: &str =
        "47c38e6210f278ce19e04620f5aa697965cfbc34550dfa34319c1f47db84e830";
    const NEGATIVE_DEPENDENT_TRANSITION_CONTRADICTION_RAW_SHA256: &str =
        "1bb57031518350db795ec0857e16e935c946ee811c9cbdf06a781f25c250fbea";

    const EVENT_ACCEPTED_EVENT_ID: &str =
        "3c3b6bd2d6f9ad4a1e66a74cf51ca3380e747dd7bd332aa2bb6169294c61e6af";
    const EVENT_PRIVACY_SUBJECT_ACCEPTED_EVENT_ID: &str =
        "1c27e30e7bad9e8a2d049adf89a4b1468a244b933d334cad7b1e355e9556320c";

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ErasureVectorSuiteV1 {
        schema_version: u32,
        fixture_authority: String,
        erasure_event_id: AcceptedEventId,
        erasure_event_privacy_subject_id: AcceptedEventId,
        negative_cases: Vec<ContractId>,
    }

    impl ErasureVectorSuiteV1 {
        fn validate(&self) -> ContractResult<()> {
            if self.schema_version != ERASURE_SCHEMA_VERSION
                || self.negative_cases.is_empty()
                || !strictly_sorted(&self.negative_cases)
            {
                return Err(ContractError::Schema("invalid erasure vector suite".into()));
            }
            encode_canonical(self)?;
            Ok(())
        }
    }

    fn vector_suite() -> ErasureVectorSuiteV1 {
        ErasureVectorSuiteV1 {
            schema_version: 1,
            fixture_authority: "none; structural fixtures are assertions, not active-policy \
                                 or repository-acceptance witnesses"
                .to_owned(),
            erasure_event_id: event_representation().accepted_event_id().unwrap(),
            erasure_event_privacy_subject_id: event_privacy_subject().accepted_event_id().unwrap(),
            negative_cases: vec![
                ContractId::new("checkpoint_same_digest").unwrap(),
                ContractId::new("dependent_transition_contradiction").unwrap(),
                ContractId::new("event_effective_before_policy_basis").unwrap(),
                ContractId::new("fence_missing_scope").unwrap(),
                ContractId::new("legal_hold_publication_visibility").unwrap(),
                ContractId::new("receipt_complete_residual_despite_key_destroyed").unwrap(),
                ContractId::new("receipt_complete_with_residual").unwrap(),
                ContractId::new("tombstone_payload_bytes").unwrap(),
            ],
        }
    }

    fn record(bytes: &[u8]) -> &[u8] {
        let body = bytes
            .strip_suffix(b"\n")
            .expect("contract artifact must have exactly one framing LF");
        assert!(!body.ends_with(b"\n"));
        assert!(!body.contains(&b'\r'));
        body
    }

    fn raw_sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_str(value).unwrap()
    }

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.fixture").unwrap(),
            ContractId::new("project.fixture").unwrap(),
        )
    }

    fn labelled_digest(label: &str) -> Sha256Digest {
        domain_separated_digest(DigestDomain::RegistryEntry, label.as_bytes())
    }

    fn policy_basis() -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new("policy.retention.privacy_erasure").unwrap(),
            version: 1,
            entry_digest: labelled_digest("policy.retention.privacy_erasure"),
        }
    }

    fn target_representation() -> ErasureScope {
        ErasureScope {
            kind: ErasureScopeKind::Representation,
            target_digest: labelled_digest("representation.fixture.one"),
        }
    }

    fn target_privacy_subject() -> ErasureScope {
        ErasureScope {
            kind: ErasureScopeKind::PrivacySubject,
            target_digest: labelled_digest("privacy_subject.fixture.one"),
        }
    }

    fn event_representation() -> ErasureEventV1 {
        ErasureEventV1 {
            schema_version: 1,
            event_kind: ContractId::new(ERASURE_ACCEPTED_EVENT_KIND).unwrap(),
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            target: target_representation(),
            effective: EffectiveIntervalV1 {
                effective_from: CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z")
                    .unwrap(),
                effective_until: None,
            },
            policy_basis: policy_basis(),
            policy_basis_effective_from: CanonicalTimestamp::parse(
                "2026-01-01T00:00:00.000000000Z",
            )
            .unwrap(),
            re_consent: ProspectiveReConsentV1::NotAuthorized,
            requested_at: CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap(),
        }
    }

    fn event_privacy_subject() -> ErasureEventV1 {
        ErasureEventV1 {
            target: target_privacy_subject(),
            re_consent: ProspectiveReConsentV1::AuthorizedForNewSourceFact {
                consent_policy: policy_basis(),
            },
            ..event_representation()
        }
    }

    fn tombstone_digest_only() -> ErasureTombstoneV1 {
        ErasureTombstoneV1 {
            schema_version: 1,
            deny_mode: TombstoneDenyModeV1::RetrievalDeny,
            target: target_representation(),
            erasure_event_id: event_representation().accepted_event_id().unwrap(),
            policy_basis: policy_basis(),
            lifecycle: TombstoneLifecycleV1::DigestOnly,
        }
    }

    fn tombstone_with_metadata() -> ErasureTombstoneV1 {
        ErasureTombstoneV1 {
            lifecycle: TombstoneLifecycleV1::DigestAndMetadata {
                installed_at: CanonicalTimestamp::parse("2026-08-16T00:00:01.000000000Z").unwrap(),
                superseded_by: None,
            },
            ..tombstone_digest_only()
        }
    }

    fn generation(value: u64) -> ErasureGenerationV1 {
        ErasureGenerationV1 {
            scope: scope(),
            value,
        }
    }

    fn fence(entries: Vec<ErasureFenceEntryV1>, generation_value: u64) -> ErasureFenceV1 {
        ErasureFenceV1 {
            schema_version: 1,
            scope: scope(),
            entries,
            generation: generation(generation_value),
        }
    }

    fn genesis_fence() -> ErasureFenceV1 {
        fence(
            REQUIRED_FENCE_KINDS
                .iter()
                .map(|kind| ErasureFenceEntryV1 {
                    kind: *kind,
                    epoch: 0,
                })
                .collect(),
            0,
        )
    }

    fn advanced_fence() -> ErasureFenceV1 {
        fence(
            REQUIRED_FENCE_KINDS
                .iter()
                .map(|kind| ErasureFenceEntryV1 {
                    kind: *kind,
                    epoch: u64::from(*kind == ErasureScopeKind::Representation),
                })
                .collect(),
            1,
        )
    }

    /// Generation advanced, every per-kind epoch unchanged from genesis.
    /// Isolates the `same_generation` conjunct of `may_commit`: no epoch
    /// entry differs, so a CAS that only checked epochs would wrongly permit
    /// this commit.
    fn fence_generation_only_advance() -> ErasureFenceV1 {
        fence(
            REQUIRED_FENCE_KINDS
                .iter()
                .map(|kind| ErasureFenceEntryV1 {
                    kind: *kind,
                    epoch: 0,
                })
                .collect(),
            1,
        )
    }

    /// Only the `privacy_subject` epoch advanced; generation and every other
    /// epoch unchanged from genesis. This is the parent-side half of the
    /// parent-vs-child scope race: work captured the genesis fence, then a
    /// `privacy_subject` tombstone landed. Isolates the `no_epoch_advanced`
    /// conjunct of `may_commit` (generation alone would wrongly permit it).
    fn fence_privacy_subject_only_advance() -> ErasureFenceV1 {
        fence(
            REQUIRED_FENCE_KINDS
                .iter()
                .map(|kind| ErasureFenceEntryV1 {
                    kind: *kind,
                    epoch: u64::from(*kind == ErasureScopeKind::PrivacySubject),
                })
                .collect(),
            0,
        )
    }

    /// Only the `representation` epoch advanced; generation and every other
    /// epoch unchanged from genesis. The mirrored, child-side half of the
    /// same race: a `representation` projection commit racing a
    /// `representation`-kind tombstone, with no generation movement to lean
    /// on. Also isolates the `no_epoch_advanced` conjunct of `may_commit`.
    fn fence_representation_only_advance() -> ErasureFenceV1 {
        fence(
            REQUIRED_FENCE_KINDS
                .iter()
                .map(|kind| ErasureFenceEntryV1 {
                    kind: *kind,
                    epoch: u64::from(*kind == ErasureScopeKind::Representation),
                })
                .collect(),
            0,
        )
    }

    fn receipt_pending() -> ErasureReceiptV1 {
        ErasureReceiptV1 {
            schema_version: 1,
            erasure_event_id: event_representation().accepted_event_id().unwrap(),
            state: ErasureReceiptStateV1::Pending,
            residual_inventory: vec![
                ErasureStoreResidualV1 {
                    store_id: ContractId::new("store.cache").unwrap(),
                    deletion_actor: ErasureDeletionActorV1::FleetRecall,
                    residual_present: true,
                },
                ErasureStoreResidualV1 {
                    store_id: ContractId::new("store.index").unwrap(),
                    deletion_actor: ErasureDeletionActorV1::FleetRecall,
                    residual_present: false,
                },
            ],
            key_destroyed: false,
            issued_at: CanonicalTimestamp::parse("2026-08-16T00:00:02.000000000Z").unwrap(),
        }
    }

    fn receipt_complete() -> ErasureReceiptV1 {
        ErasureReceiptV1 {
            state: ErasureReceiptStateV1::Complete,
            residual_inventory: vec![
                ErasureStoreResidualV1 {
                    store_id: ContractId::new("store.cache").unwrap(),
                    deletion_actor: ErasureDeletionActorV1::FleetRecall,
                    residual_present: false,
                },
                ErasureStoreResidualV1 {
                    store_id: ContractId::new("store.index").unwrap(),
                    deletion_actor: ErasureDeletionActorV1::AuthoritativeProvider,
                    residual_present: false,
                },
            ],
            key_destroyed: true,
            ..receipt_pending()
        }
    }

    /// `state: complete`, `key_destroyed: true`, and exactly one governed
    /// store still showing a residual. Isolates the `any_residual_present`
    /// half of the `complete` conjunction: key destruction alone, even when
    /// it genuinely happened, is not sufficient evidence of erasure while
    /// plaintext or a derived copy remains anywhere in the inventory.
    fn receipt_complete_residual_despite_key_destroyed() -> ErasureReceiptV1 {
        ErasureReceiptV1 {
            schema_version: 1,
            erasure_event_id: event_representation().accepted_event_id().unwrap(),
            state: ErasureReceiptStateV1::Complete,
            residual_inventory: vec![ErasureStoreResidualV1 {
                store_id: ContractId::new("store.archive").unwrap(),
                deletion_actor: ErasureDeletionActorV1::FleetRecall,
                residual_present: true,
            }],
            key_destroyed: true,
            issued_at: CanonicalTimestamp::parse("2026-08-16T00:00:03.000000000Z").unwrap(),
        }
    }

    fn legal_hold_active() -> LegalHoldV1 {
        LegalHoldV1 {
            schema_version: 1,
            target: target_representation(),
            policy_basis: policy_basis(),
            placed_at: CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap(),
            released_at: None,
            visibility_ceiling: VisibilityClass::Private,
        }
    }

    fn retainable_matcher_forbidden() -> RetainableMatcherPolicyV1 {
        RetainableMatcherPolicyV1::PseudonymousMatcherForbidden
    }

    fn restore_gate_quarantined() -> RestoreGateV1 {
        RestoreGateV1 {
            schema_version: 1,
            tombstone_tail_applied: true,
            covered_by_tombstone: true,
            quarantine_preferred: true,
        }
    }

    fn dependent_transition_unverifiable() -> DependentSupportTransitionV1 {
        DependentSupportTransitionV1 {
            schema_version: 1,
            erasure_event_id: event_representation().accepted_event_id().unwrap(),
            next_state: SupportVerificationStateV1::Unverifiable,
            sufficient_redacted_evidence_remains: false,
            recompute_targets: vec![AcceptedEventId::from_digest(labelled_digest(
                "discrepancy.fixture.one",
            ))],
        }
    }

    fn checkpoint_rule() -> CheckpointErasureRuleV1 {
        CheckpointErasureRuleV1 {
            schema_version: 1,
            previous_checkpoint_digest: labelled_digest("checkpoint.fixture.previous"),
            previous_generation: generation(0),
            new_checkpoint_digest: labelled_digest("checkpoint.fixture.new"),
            new_generation: generation(1),
        }
    }

    #[test]
    fn erasure_event_shape_and_identity() {
        let event = event_representation();
        event.validate_shape().unwrap();
        assert!(event.accepted_event_id().is_ok());

        let mut wrong_kind = event.clone();
        wrong_kind.event_kind = ContractId::new("erasure.proposed").unwrap();
        assert!(wrong_kind.validate_shape().is_err());

        let mut zero_target = event.clone();
        zero_target.target.target_digest = Sha256Digest::ZERO;
        assert!(zero_target.validate_shape().is_err());

        let mut effective_before_policy = event;
        effective_before_policy.effective.effective_from =
            CanonicalTimestamp::parse("2025-01-01T00:00:00.000000000Z").unwrap();
        assert_eq!(
            effective_before_policy.validate_shape(),
            Err(ContractError::Schema(
                "invalid erasure event candidate".into()
            ))
        );

        let negative_event: ErasureEventV1 =
            decode_strict(record(NEGATIVE_EVENT_EFFECTIVE_BEFORE_POLICY_FIXTURE)).unwrap();
        // Distinguishing property: this fixture decodes to an otherwise
        // shape-valid event whose effective interval starts strictly before
        // the policy basis it claims to act under.
        assert!(
            negative_event.effective.effective_from < negative_event.policy_basis_effective_from
        );
        assert_eq!(
            negative_event.validate_shape(),
            Err(ContractError::Schema(
                "invalid erasure event candidate".into()
            ))
        );
    }

    #[test]
    fn re_consent_policy_reference_must_itself_validate() {
        let unverifiable_re_consent = ProspectiveReConsentV1::AuthorizedForNewSourceFact {
            consent_policy: RegistryReferenceV1 {
                entry_id: ContractId::new("policy.bogus").unwrap(),
                version: 0,
                entry_digest: Sha256Digest::ZERO,
            },
        };
        let mut event = event_privacy_subject();
        event.re_consent = unverifiable_re_consent.clone();
        assert!(
            event.validate_shape().is_err(),
            "an event candidate must not shape-validate with an unverifiable re-consent policy \
             reference"
        );
        assert!(
            event.accepted_event_id().is_err(),
            "accepted_event_id must refuse a candidate whose re-consent policy reference does \
             not validate"
        );

        let different_target = ErasureScope {
            kind: ErasureScopeKind::Representation,
            target_digest: labelled_digest("representation.fixture.two"),
        };
        assert!(
            !re_consent_permits_new_source_fact(
                &tombstone_digest_only(),
                &unverifiable_re_consent,
                &different_target
            )
            .unwrap(),
            "an unverifiable consent-policy reference must never permit a new source fact"
        );
    }

    #[test]
    fn admitted_event_is_unconstructible_outside_test_witness() {
        let admitted = AdmittedErasureEventV1::from_test_witness(event_representation()).unwrap();
        assert_eq!(
            admitted.accepted_event_id(),
            event_representation().accepted_event_id().unwrap()
        );
        assert_eq!(admitted.event(), &event_representation());
    }

    #[test]
    fn tombstone_validates_and_carries_no_payload() {
        tombstone_digest_only().validate().unwrap();
        tombstone_with_metadata().validate().unwrap();

        let mut zero_target = tombstone_digest_only();
        zero_target.target.target_digest = Sha256Digest::ZERO;
        assert!(zero_target.validate().is_err());

        // A tombstone that binds to no erasure event at all (the zero
        // digest) must never validate: it would otherwise get a stable
        // tombstone_id while asserting retrieval-deny for an event that
        // does not exist.
        let mut zero_event_id = tombstone_digest_only();
        zero_event_id.erasure_event_id = AcceptedEventId::from_digest(Sha256Digest::ZERO);
        assert!(zero_event_id.validate().is_err());

        // The type itself has no field that could carry payload bytes; a
        // fixture attempting to add one is rejected by
        // `#[serde(deny_unknown_fields)]`, exercised below against the
        // on-disk fixture.
        assert!(
            decode_strict::<ErasureTombstoneV1>(record(NEGATIVE_TOMBSTONE_PAYLOAD_BYTES_FIXTURE))
                .is_err()
        );

        assert_ne!(
            tombstone_digest_only().tombstone_id().unwrap(),
            tombstone_with_metadata().tombstone_id().unwrap()
        );
    }

    #[test]
    fn fence_requires_all_four_scope_kinds_exactly_once() {
        genesis_fence().validate().unwrap();
        advanced_fence().validate().unwrap();

        let mut missing_scope = genesis_fence();
        missing_scope.entries.pop();
        assert!(missing_scope.validate().is_err());

        // Isolate the `covers_every_required_kind` conjunct from the
        // `entries.len() != 4` check: four entries, strictly sorted, but one
        // kind duplicated and another kind entirely absent. The length check
        // alone cannot catch this -- only the coverage check can.
        let mut duplicate_kind_missing_scope = genesis_fence();
        duplicate_kind_missing_scope.entries = vec![
            ErasureFenceEntryV1 {
                kind: ErasureScopeKind::PrivacySubject,
                epoch: 0,
            },
            ErasureFenceEntryV1 {
                kind: ErasureScopeKind::PrivacySubject,
                epoch: 1,
            },
            ErasureFenceEntryV1 {
                kind: ErasureScopeKind::Representation,
                epoch: 0,
            },
            ErasureFenceEntryV1 {
                kind: ErasureScopeKind::Resource,
                epoch: 0,
            },
        ];
        assert_eq!(
            duplicate_kind_missing_scope.entries.len(),
            REQUIRED_FENCE_KINDS.len()
        );
        assert!(strictly_sorted(&duplicate_kind_missing_scope.entries));
        assert!(duplicate_kind_missing_scope.validate().is_err());

        // Isolate `strictly_sorted(&self.entries)` from both of the above:
        // four entries, one of each required kind, but out of order.
        let mut unsorted_but_complete = genesis_fence();
        unsorted_but_complete.entries.swap(0, 1);
        assert_eq!(
            unsorted_but_complete.entries.len(),
            REQUIRED_FENCE_KINDS.len()
        );
        assert!(REQUIRED_FENCE_KINDS.iter().all(|kind| {
            unsorted_but_complete
                .entries
                .iter()
                .any(|entry| entry.kind == *kind)
        }));
        assert!(!strictly_sorted(&unsorted_but_complete.entries));
        assert!(unsorted_but_complete.validate().is_err());

        let negative_fence: ErasureFenceV1 =
            decode_strict(record(NEGATIVE_FENCE_MISSING_SCOPE_FIXTURE)).unwrap();
        // Distinguishing property, not just the shared error string: this
        // fixture decodes to a fence with only three scope-kind entries.
        assert_eq!(negative_fence.entries.len(), 3);
        assert_eq!(
            negative_fence.validate(),
            Err(ContractError::Schema(
                "erasure fence must cover exactly the four scope kinds once each".into()
            ))
        );

        assert_ne!(
            genesis_fence().fence_id().unwrap(),
            advanced_fence().fence_id().unwrap()
        );
    }

    #[test]
    fn fence_cas_rejects_a_commit_after_concurrent_erasure() {
        let concurrent_erasure = ErasureFenceCasV1 {
            expected: genesis_fence(),
            current: advanced_fence(),
        };
        assert_eq!(concurrent_erasure.may_commit(), Ok(false));

        let no_interleaving_erasure = ErasureFenceCasV1 {
            expected: genesis_fence(),
            current: genesis_fence(),
        };
        assert_eq!(no_interleaving_erasure.may_commit(), Ok(true));

        let cross_scope = ErasureFenceCasV1 {
            expected: genesis_fence(),
            current: ErasureFenceV1 {
                scope: AuthenticatedProjectScopeV1::from_trusted_context(
                    ContractId::new("tenant.other").unwrap(),
                    ContractId::new("project.other").unwrap(),
                ),
                generation: ErasureGenerationV1 {
                    scope: AuthenticatedProjectScopeV1::from_trusted_context(
                        ContractId::new("tenant.other").unwrap(),
                        ContractId::new("project.other").unwrap(),
                    ),
                    value: 0,
                },
                ..genesis_fence()
            },
        };
        assert!(cross_scope.may_commit().is_err());

        // Isolate the `same_generation` conjunct: the generation alone
        // advances while every per-kind epoch stays at genesis. A CAS that
        // dropped the epoch check entirely (kept only the generation check)
        // would still catch this one -- the point is that dropping the
        // *generation* check must not let it slip through, which the next
        // two cases confirm from the other side.
        let generation_only: ErasureFenceV1 =
            decode_strict(record(FENCE_GENERATION_ONLY_ADVANCE_FIXTURE)).unwrap();
        assert_eq!(generation_only.generation.value, 1);
        assert!(generation_only.entries.iter().all(|entry| entry.epoch == 0));
        assert_eq!(
            ErasureFenceCasV1 {
                expected: genesis_fence(),
                current: generation_only,
            }
            .may_commit(),
            Ok(false),
            "a generation-only advance with every epoch unchanged must still fail closed"
        );

        // Isolate the `no_epoch_advanced` conjunct, parent side: only the
        // `privacy_subject` epoch moves and the generation does not move at
        // all. A CAS that dropped the epoch check (kept only the generation
        // check) would wrongly permit this -- the mechanical form of "a
        // privacy_subject tombstone racing representation-scoped work".
        let privacy_subject_only: ErasureFenceV1 =
            decode_strict(record(FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_FIXTURE)).unwrap();
        assert_eq!(privacy_subject_only.generation.value, 0);
        assert_eq!(
            privacy_subject_only
                .entries
                .iter()
                .find(|entry| entry.kind == ErasureScopeKind::PrivacySubject)
                .unwrap()
                .epoch,
            1
        );
        assert_eq!(
            ErasureFenceCasV1 {
                expected: genesis_fence(),
                current: privacy_subject_only.clone(),
            }
            .may_commit(),
            Ok(false),
            "a privacy_subject-only epoch advance must fail closed even with no generation move"
        );

        // Mirrored, child side of the same race: only `representation`
        // moves, generation unchanged.
        let representation_only: ErasureFenceV1 =
            decode_strict(record(FENCE_REPRESENTATION_ONLY_ADVANCE_FIXTURE)).unwrap();
        assert_eq!(representation_only.generation.value, 0);
        assert_eq!(
            representation_only
                .entries
                .iter()
                .find(|entry| entry.kind == ErasureScopeKind::Representation)
                .unwrap()
                .epoch,
            1
        );
        assert_eq!(
            ErasureFenceCasV1 {
                expected: genesis_fence(),
                current: representation_only,
            }
            .may_commit(),
            Ok(false),
            "a representation-only epoch advance must fail closed even with no generation move"
        );

        // The two single-epoch-advance fences differ from each other only in
        // which kind moved, and from genesis in exactly one entry -- proof
        // that `may_commit` distinguishes per-kind epochs rather than
        // reasoning about the fence as an undifferentiated blob.
        assert_ne!(
            privacy_subject_only.fence_id().unwrap(),
            genesis_fence().fence_id().unwrap()
        );
    }

    #[test]
    fn re_consent_never_revives_the_erased_identity() {
        let tombstone = tombstone_digest_only();
        let authorized = ProspectiveReConsentV1::AuthorizedForNewSourceFact {
            consent_policy: policy_basis(),
        };
        let different_target = ErasureScope {
            kind: ErasureScopeKind::Representation,
            target_digest: labelled_digest("representation.fixture.two"),
        };
        assert!(
            re_consent_permits_new_source_fact(&tombstone, &authorized, &different_target).unwrap()
        );
        assert!(
            !re_consent_permits_new_source_fact(&tombstone, &authorized, &tombstone.target)
                .unwrap()
        );
        assert!(
            !re_consent_permits_new_source_fact(
                &tombstone,
                &ProspectiveReConsentV1::NotAuthorized,
                &different_target
            )
            .unwrap()
        );

        // A tombstone this module cannot validate must never yield a
        // permissive answer, no matter how "different" the candidate target
        // looks from its (unverifiable) target digest.
        let mut invalid_tombstone = tombstone;
        invalid_tombstone.target.target_digest = Sha256Digest::ZERO;
        assert!(invalid_tombstone.validate().is_err());
        assert!(
            re_consent_permits_new_source_fact(&invalid_tombstone, &authorized, &different_target)
                .is_err(),
            "an invalid tombstone must fail closed, never report permitted"
        );
    }

    #[test]
    fn acceptance_effect_ties_tombstone_fence_and_generation_atomically() {
        let admitted = AdmittedErasureEventV1::from_test_witness(event_representation()).unwrap();
        let effect = ErasureAcceptanceEffectV1::from_test_witness(
            admitted,
            tombstone_digest_only(),
            vec![ErasureFenceEntryV1 {
                kind: ErasureScopeKind::Representation,
                epoch: 1,
            }],
            generation(0),
            generation(1),
        )
        .unwrap();
        assert_eq!(effect.generation_before().value, 0);
        assert_eq!(effect.generation_after().value, 1);
        assert_eq!(effect.advanced_entries().len(), 1);

        let mismatched_target =
            AdmittedErasureEventV1::from_test_witness(event_privacy_subject()).unwrap();
        assert!(
            ErasureAcceptanceEffectV1::from_test_witness(
                mismatched_target,
                tombstone_digest_only(),
                vec![ErasureFenceEntryV1 {
                    kind: ErasureScopeKind::PrivacySubject,
                    epoch: 1,
                }],
                generation(0),
                generation(1),
            )
            .is_err()
        );

        let admitted_again =
            AdmittedErasureEventV1::from_test_witness(event_representation()).unwrap();
        assert!(
            ErasureAcceptanceEffectV1::from_test_witness(
                admitted_again,
                tombstone_digest_only(),
                vec![ErasureFenceEntryV1 {
                    kind: ErasureScopeKind::Representation,
                    epoch: 1,
                }],
                generation(1),
                generation(1),
            )
            .is_err(),
            "generation must strictly advance"
        );
    }

    #[test]
    fn receipt_complete_requires_no_residual_and_key_destroyed() {
        receipt_pending().validate().unwrap();
        receipt_complete().validate().unwrap();

        let mut key_not_destroyed = receipt_complete();
        key_not_destroyed.key_destroyed = false;
        assert!(key_not_destroyed.validate().is_err());

        // Isolate `strictly_sorted(&self.residual_inventory)`: the same two
        // rows as `receipt_pending()`, only reordered. Every other conjunct
        // still passes (non-empty, within the size cap, `pending` so the
        // `complete` conjunction never applies, `issued_at` aligned, a
        // non-zero `erasure_event_id`) -- only the ordering is wrong.
        let mut unsorted_residuals = receipt_pending();
        unsorted_residuals.residual_inventory.reverse();
        assert_eq!(unsorted_residuals.residual_inventory.len(), 2);
        assert!(!strictly_sorted(&unsorted_residuals.residual_inventory));
        assert!(unsorted_residuals.validate().is_err());

        // A receipt bound to no erasure event at all (the zero digest) must
        // never validate: it is the record that discharges EVID-08, and it
        // must name the event it discharges.
        let mut zero_event_id = receipt_complete();
        zero_event_id.erasure_event_id = AcceptedEventId::from_digest(Sha256Digest::ZERO);
        assert!(zero_event_id.validate().is_err());

        let negative_receipt: ErasureReceiptV1 =
            decode_strict(record(NEGATIVE_RECEIPT_COMPLETE_WITH_RESIDUAL_FIXTURE)).unwrap();
        // Distinguishing property, not just the shared error string: this
        // fixture claims `complete` while `key_destroyed` is still `false`
        // *and* a governed store still shows a residual -- it fails the
        // `complete` conjunction for two independent reasons at once, so it
        // alone cannot isolate the `any_residual_present` half of that
        // conjunction (see `receipt_complete_residual_despite_key_destroyed`
        // below for the fixture that does).
        assert_eq!(negative_receipt.state, ErasureReceiptStateV1::Complete);
        assert!(!negative_receipt.key_destroyed);
        assert!(
            negative_receipt
                .residual_inventory
                .iter()
                .any(|residual| residual.residual_present)
        );
        assert_eq!(
            negative_receipt.validate(),
            Err(ContractError::Schema("invalid erasure receipt".into()))
        );

        // Isolates the `any_residual_present` half specifically: the key
        // genuinely was destroyed (`key_destroyed: true`), yet exactly one
        // governed store still shows a residual. Key destruction alone, with
        // plaintext or a derived copy still resident anywhere in the
        // inventory, is not sufficient evidence of erasure -- this is the
        // one case in the suite where `key_destroyed` cannot be blamed for
        // the rejection.
        let residual_despite_key_destroyed: ErasureReceiptV1 = decode_strict(record(
            NEGATIVE_RECEIPT_COMPLETE_RESIDUAL_DESPITE_KEY_DESTROYED_FIXTURE,
        ))
        .unwrap();
        assert_eq!(
            residual_despite_key_destroyed.state,
            ErasureReceiptStateV1::Complete
        );
        assert!(residual_despite_key_destroyed.key_destroyed);
        assert!(
            residual_despite_key_destroyed
                .residual_inventory
                .iter()
                .any(|residual| residual.residual_present)
        );
        assert_eq!(
            residual_despite_key_destroyed.validate(),
            Err(ContractError::Schema("invalid erasure receipt".into()))
        );
        assert_eq!(
            residual_despite_key_destroyed,
            receipt_complete_residual_despite_key_destroyed()
        );

        assert_ne!(
            receipt_pending().receipt_id().unwrap(),
            receipt_complete().receipt_id().unwrap()
        );
    }

    #[test]
    fn legal_hold_defers_removal_and_never_widens_visibility() {
        let hold = legal_hold_active();
        hold.validate().unwrap();
        assert!(hold.hold_id().is_ok());
        let before = CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap();
        let during = CanonicalTimestamp::parse("2026-08-17T00:00:00.000000000Z").unwrap();
        assert!(!hold.permits_removal(&before));
        assert!(!hold.permits_removal(&during));

        let mut released = hold;
        released.released_at =
            Some(CanonicalTimestamp::parse("2026-08-18T00:00:00.000000000Z").unwrap());
        assert!(released.permits_removal(
            &CanonicalTimestamp::parse("2026-08-19T00:00:00.000000000Z").unwrap()
        ));
        assert!(!released.permits_removal(&during));

        let negative_hold: LegalHoldV1 =
            decode_strict(record(NEGATIVE_LEGAL_HOLD_PUBLICATION_VISIBILITY_FIXTURE)).unwrap();
        // Distinguishing property: this fixture decodes to a hold whose
        // ceiling is exactly the one class that would let a held record
        // become public.
        assert_eq!(
            negative_hold.visibility_ceiling,
            VisibilityClass::PublicationApproved
        );
        assert_eq!(
            negative_hold.validate(),
            Err(ContractError::Schema("invalid legal hold".into()))
        );
    }

    #[test]
    fn forbidden_matcher_forces_disable_and_purge() {
        assert_eq!(
            retainable_matcher_forbidden().required_scope_action(),
            Ok(RetainableMatcherScopeActionV1::DisableAndPurge)
        );
        assert_eq!(
            RetainableMatcherPolicyV1::PseudonymousMatcherAllowed {
                matcher_policy: policy_basis()
            }
            .required_scope_action(),
            Ok(RetainableMatcherScopeActionV1::Retain)
        );

        let mut zero_digest_matcher = RetainableMatcherPolicyV1::PseudonymousMatcherAllowed {
            matcher_policy: policy_basis(),
        };
        if let RetainableMatcherPolicyV1::PseudonymousMatcherAllowed { matcher_policy } =
            &mut zero_digest_matcher
        {
            matcher_policy.entry_digest = Sha256Digest::ZERO;
        }
        assert!(
            zero_digest_matcher.required_scope_action().is_err(),
            "an unverifiable matcher policy must never report Retain"
        );
    }

    #[test]
    fn restore_gate_refuses_a_decision_before_the_tail_is_applied() {
        assert_eq!(
            restore_gate_quarantined().outcome(),
            Ok(RestoreGateOutcomeV1::Quarantined)
        );
        let mut suppressed = restore_gate_quarantined();
        suppressed.quarantine_preferred = false;
        assert_eq!(suppressed.outcome(), Ok(RestoreGateOutcomeV1::Suppressed));
        let mut serve = restore_gate_quarantined();
        serve.covered_by_tombstone = false;
        assert_eq!(serve.outcome(), Ok(RestoreGateOutcomeV1::Serve));
        let mut undecided = restore_gate_quarantined();
        undecided.tombstone_tail_applied = false;
        assert!(undecided.outcome().is_err());

        // An unrecognized schema_version must never be silently decided
        // under this version's truth table -- in particular it must never
        // be read as `Serve`, even when every other field looks servable.
        let mut unrecognized_schema = restore_gate_quarantined();
        unrecognized_schema.schema_version = 99;
        unrecognized_schema.covered_by_tombstone = false;
        assert!(unrecognized_schema.outcome().is_err());
        let mut unrecognized_schema_zero = restore_gate_quarantined();
        unrecognized_schema_zero.schema_version = 0;
        assert!(unrecognized_schema_zero.outcome().is_err());
    }

    #[test]
    fn dependent_support_transition_requires_consistent_recompute_list() {
        dependent_transition_unverifiable().validate().unwrap();

        // The mandatory erasure-event binding must not be the zero digest.
        let mut zero_event_id = dependent_transition_unverifiable();
        zero_event_id.erasure_event_id = AcceptedEventId::from_digest(Sha256Digest::ZERO);
        assert!(zero_event_id.validate().is_err());

        // Nor may any individual recompute target be the zero digest.
        let mut zero_recompute_target = dependent_transition_unverifiable();
        zero_recompute_target.recompute_targets =
            vec![AcceptedEventId::from_digest(Sha256Digest::ZERO)];
        assert!(zero_recompute_target.validate().is_err());

        let negative_transition: DependentSupportTransitionV1 =
            decode_strict(record(NEGATIVE_DEPENDENT_TRANSITION_CONTRADICTION_FIXTURE)).unwrap();
        // Distinguishing property: this fixture claims `next_state:
        // verified` (support fully intact) while still naming a nonempty
        // recompute list -- a verified proposition has nothing left to
        // recompute.
        assert_eq!(
            negative_transition.next_state,
            SupportVerificationStateV1::Verified
        );
        assert!(!negative_transition.recompute_targets.is_empty());
        assert_eq!(
            negative_transition.validate(),
            Err(ContractError::Schema(
                "invalid dependent support transition".into()
            ))
        );
    }

    #[test]
    fn checkpoint_rule_requires_a_strictly_higher_generation_and_new_digest() {
        checkpoint_rule().validate().unwrap();
        let negative_rule: CheckpointErasureRuleV1 =
            decode_strict(record(NEGATIVE_CHECKPOINT_SAME_DIGEST_FIXTURE)).unwrap();
        // Distinguishing property: this fixture decodes to a rule whose old
        // and new checkpoint digests are identical -- the "old never
        // advanced in place" invariant made concrete.
        assert_eq!(
            negative_rule.previous_checkpoint_digest,
            negative_rule.new_checkpoint_digest
        );
        assert_eq!(
            negative_rule.validate(),
            Err(ContractError::Schema(
                "invalid checkpoint erasure rule".into()
            ))
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn hard_coded_contract_vectors_match_independent_ids() {
        for (bytes, expected_raw_sha256) in [
            (ERASURE_EVENT_FIXTURE, EVENT_RAW_SHA256),
            (
                ERASURE_EVENT_PRIVACY_SUBJECT_FIXTURE,
                EVENT_PRIVACY_SUBJECT_RAW_SHA256,
            ),
            (
                TOMBSTONE_DIGEST_ONLY_FIXTURE,
                TOMBSTONE_DIGEST_ONLY_RAW_SHA256,
            ),
            (
                TOMBSTONE_WITH_METADATA_FIXTURE,
                TOMBSTONE_WITH_METADATA_RAW_SHA256,
            ),
            (FENCE_GENESIS_FIXTURE, FENCE_GENESIS_RAW_SHA256),
            (FENCE_ADVANCED_FIXTURE, FENCE_ADVANCED_RAW_SHA256),
            (
                FENCE_GENERATION_ONLY_ADVANCE_FIXTURE,
                FENCE_GENERATION_ONLY_ADVANCE_RAW_SHA256,
            ),
            (
                FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_FIXTURE,
                FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_RAW_SHA256,
            ),
            (
                FENCE_REPRESENTATION_ONLY_ADVANCE_FIXTURE,
                FENCE_REPRESENTATION_ONLY_ADVANCE_RAW_SHA256,
            ),
            (RECEIPT_PENDING_FIXTURE, RECEIPT_PENDING_RAW_SHA256),
            (RECEIPT_COMPLETE_FIXTURE, RECEIPT_COMPLETE_RAW_SHA256),
            (LEGAL_HOLD_ACTIVE_FIXTURE, LEGAL_HOLD_ACTIVE_RAW_SHA256),
            (
                RETAINABLE_MATCHER_FORBIDDEN_FIXTURE,
                RETAINABLE_MATCHER_FORBIDDEN_RAW_SHA256,
            ),
            (
                RESTORE_GATE_QUARANTINED_FIXTURE,
                RESTORE_GATE_QUARANTINED_RAW_SHA256,
            ),
            (
                DEPENDENT_TRANSITION_UNVERIFIABLE_FIXTURE,
                DEPENDENT_TRANSITION_UNVERIFIABLE_RAW_SHA256,
            ),
            (CHECKPOINT_RULE_FIXTURE, CHECKPOINT_RULE_RAW_SHA256),
            (VECTOR_SUITE_FIXTURE, VECTOR_SUITE_RAW_SHA256),
            (
                NEGATIVE_TOMBSTONE_PAYLOAD_BYTES_FIXTURE,
                NEGATIVE_TOMBSTONE_PAYLOAD_BYTES_RAW_SHA256,
            ),
            (
                NEGATIVE_RECEIPT_COMPLETE_WITH_RESIDUAL_FIXTURE,
                NEGATIVE_RECEIPT_COMPLETE_WITH_RESIDUAL_RAW_SHA256,
            ),
            (
                NEGATIVE_RECEIPT_COMPLETE_RESIDUAL_DESPITE_KEY_DESTROYED_FIXTURE,
                NEGATIVE_RECEIPT_COMPLETE_RESIDUAL_DESPITE_KEY_DESTROYED_RAW_SHA256,
            ),
            (
                NEGATIVE_FENCE_MISSING_SCOPE_FIXTURE,
                NEGATIVE_FENCE_MISSING_SCOPE_RAW_SHA256,
            ),
            (
                NEGATIVE_EVENT_EFFECTIVE_BEFORE_POLICY_FIXTURE,
                NEGATIVE_EVENT_EFFECTIVE_BEFORE_POLICY_RAW_SHA256,
            ),
            (
                NEGATIVE_LEGAL_HOLD_PUBLICATION_VISIBILITY_FIXTURE,
                NEGATIVE_LEGAL_HOLD_PUBLICATION_VISIBILITY_RAW_SHA256,
            ),
            (
                NEGATIVE_CHECKPOINT_SAME_DIGEST_FIXTURE,
                NEGATIVE_CHECKPOINT_SAME_DIGEST_RAW_SHA256,
            ),
            (
                NEGATIVE_DEPENDENT_TRANSITION_CONTRADICTION_FIXTURE,
                NEGATIVE_DEPENDENT_TRANSITION_CONTRADICTION_RAW_SHA256,
            ),
        ] {
            assert_eq!(raw_sha256(bytes), expected_raw_sha256);
        }

        for bytes in [
            ERASURE_EVENT_FIXTURE,
            ERASURE_EVENT_PRIVACY_SUBJECT_FIXTURE,
            TOMBSTONE_DIGEST_ONLY_FIXTURE,
            TOMBSTONE_WITH_METADATA_FIXTURE,
            FENCE_GENESIS_FIXTURE,
            FENCE_ADVANCED_FIXTURE,
            FENCE_GENERATION_ONLY_ADVANCE_FIXTURE,
            FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_FIXTURE,
            FENCE_REPRESENTATION_ONLY_ADVANCE_FIXTURE,
            RECEIPT_PENDING_FIXTURE,
            RECEIPT_COMPLETE_FIXTURE,
            LEGAL_HOLD_ACTIVE_FIXTURE,
            RETAINABLE_MATCHER_FORBIDDEN_FIXTURE,
            RESTORE_GATE_QUARANTINED_FIXTURE,
            DEPENDENT_TRANSITION_UNVERIFIABLE_FIXTURE,
            CHECKPOINT_RULE_FIXTURE,
            VECTOR_SUITE_FIXTURE,
        ] {
            require_canonical(record(bytes)).unwrap();
        }

        assert_eq!(
            encode_canonical(&event_representation()).unwrap(),
            record(ERASURE_EVENT_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&event_privacy_subject()).unwrap(),
            record(ERASURE_EVENT_PRIVACY_SUBJECT_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&tombstone_digest_only()).unwrap(),
            record(TOMBSTONE_DIGEST_ONLY_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&tombstone_with_metadata()).unwrap(),
            record(TOMBSTONE_WITH_METADATA_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&genesis_fence()).unwrap(),
            record(FENCE_GENESIS_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&advanced_fence()).unwrap(),
            record(FENCE_ADVANCED_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&fence_generation_only_advance()).unwrap(),
            record(FENCE_GENERATION_ONLY_ADVANCE_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&fence_privacy_subject_only_advance()).unwrap(),
            record(FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&fence_representation_only_advance()).unwrap(),
            record(FENCE_REPRESENTATION_ONLY_ADVANCE_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&receipt_pending()).unwrap(),
            record(RECEIPT_PENDING_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&receipt_complete()).unwrap(),
            record(RECEIPT_COMPLETE_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&legal_hold_active()).unwrap(),
            record(LEGAL_HOLD_ACTIVE_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&retainable_matcher_forbidden()).unwrap(),
            record(RETAINABLE_MATCHER_FORBIDDEN_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&restore_gate_quarantined()).unwrap(),
            record(RESTORE_GATE_QUARANTINED_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&dependent_transition_unverifiable()).unwrap(),
            record(DEPENDENT_TRANSITION_UNVERIFIABLE_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&checkpoint_rule()).unwrap(),
            record(CHECKPOINT_RULE_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&vector_suite()).unwrap(),
            record(VECTOR_SUITE_FIXTURE)
        );

        let event_id = event_representation().accepted_event_id().unwrap();
        let event_privacy_subject_id = event_privacy_subject().accepted_event_id().unwrap();
        assert_eq!(event_id.digest(), digest(EVENT_ACCEPTED_EVENT_ID));
        assert_eq!(
            event_privacy_subject_id.digest(),
            digest(EVENT_PRIVACY_SUBJECT_ACCEPTED_EVENT_ID)
        );
        assert_ne!(event_id, event_privacy_subject_id);

        let suite: ErasureVectorSuiteV1 = decode_strict(record(VECTOR_SUITE_FIXTURE)).unwrap();
        suite.validate().unwrap();
        assert_eq!(suite, vector_suite());
    }
}
