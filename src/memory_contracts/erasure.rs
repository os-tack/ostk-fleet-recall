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
//!
//! # Decode strictness (EVID-01) and the required ingress gate
//!
//! Every record type in this module —
//! [`ErasureEventV1`], [`ErasureTombstoneV1`], [`ErasureFenceV1`],
//! [`ErasureReceiptV1`], [`LegalHoldV1`], [`RetainableMatcherPolicyV1`],
//! [`RestoreGateV1`], [`DependentSupportTransitionV1`], and
//! [`CheckpointErasureRuleV1`] — defines its identity (where it has one) or
//! its accepted shape over the **typed canonical form**, and
//! [`super::canonical::decode_typed_canonical`] is the only decode function
//! this module treats as an admissible ingress gate for wire bytes a caller
//! intends to trust, exactly as `coverage.rs` documents for
//! [`super::coverage::CoverageReceiptV1`]. [`super::canonical::decode_strict`]
//! alone proves duplicate-safe strict JSON, never that the input is the
//! *sole* accepted encoding of the value it decodes to: a derived
//! `Deserialize` on a plain struct accepts a well-typed positional JSON array
//! in a nested struct's place exactly as readily as an object, an `Option`
//! field accepts its wire key whether present-as-`null` or omitted entirely,
//! and — the sharper failure for a module whose entire purpose is denying
//! retrieval of erased content — `#[serde(deny_unknown_fields)]` on an
//! internally-tagged enum does not reject an extra key riding alongside a
//! *bare unit* variant's tag (serde issue #1358). This module closes the
//! last of those at the type level for its three fieldless variants
//! ([`ProspectiveReConsentV1::NotAuthorized`], [`TombstoneLifecycleV1::
//! DigestOnly`], [`RetainableMatcherPolicyV1::PseudonymousMatcherForbidden`]
//! are `{}` struct variants, not unit variants — see each one's doc comment)
//! and closes every other same-ID-different-bytes shape, generically and at
//! once, by requiring `decode_typed_canonical`: it decodes with
//! `decode_strict`, re-encodes the decoded value with
//! [`super::canonical::encode_canonical`], and rejects the input unless the
//! two byte strings are identical, so at most one accepted byte string
//! exists per value. See
//! `same_id_different_bytes_forms_decode_under_decode_strict_but_are_rejected_by_decode_typed_canonical`
//! in the tests module for the reproduced collisions (an unknown field on a
//! fieldless variant, an omitted optional key, a positional-array nested
//! struct) and their rejection.

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
    /// Fieldless *struct* variant (`{}`), not a bare unit variant. Serde's
    /// internally-tagged representation buffers every wire key — including
    /// ones outside the closed field set — into a `Content` tree keyed only
    /// by the `kind` tag before dispatching to the variant deserializer; for
    /// a bare unit variant that dispatch calls `deserialize_unit`, which
    /// accepts (and silently drops) any sibling keys regardless of
    /// `#[serde(deny_unknown_fields)]` on the enum. A zero-field *struct*
    /// variant instead dispatches through `deserialize_struct` with an empty
    /// field list, which does enforce `deny_unknown_fields` — so
    /// `{"kind":"not_authorized","exfiltrated":"..."}` is rejected at decode,
    /// not merely re-encoded away. See `SequenceContinuityV1::Contiguous {}`
    /// in `coverage.rs` for the identical fix. The wire shape is unchanged:
    /// `{}` still serializes as exactly `{"kind":"not_authorized"}`.
    NotAuthorized {},
    AuthorizedForNewSourceFact {
        consent_policy: RegistryReferenceV1,
    },
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

/// The epoch a fence's `entries` assign to exactly one occurrence of `kind`.
///
/// Returns `None` when `kind` is missing OR ambiguous (more than one entry
/// claims it) rather than picking either candidate — an ambiguous fence has
/// no epoch anyone can trust for that kind, so it must compare unequal to
/// everything, never equal by accident. This is what keeps
/// [`ErasureFenceCasV1::may_commit`] sound even if `entries.len() ==
/// REQUIRED_FENCE_KINDS.len()` were ever weakened or bypassed: a duplicate-kind
/// `expected` fence cannot satisfy a lookup that requires a single match.
fn single_epoch_for_kind(entries: &[ErasureFenceEntryV1], kind: ErasureScopeKind) -> Option<u64> {
    let mut matches = entries.iter().filter(|entry| entry.kind == kind);
    let only = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(only.epoch)
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
    ///
    /// `no_epoch_advanced` binds each required scope kind by exact,
    /// unambiguous per-kind lookup (`single_epoch_for_kind`) rather than
    /// asking whether *some* `expected` entry matches each `current` entry.
    /// That keeps this sound on its own — not merely because `validate()`
    /// happens to force exactly four entries, one per kind — so a forged
    /// `expected` fence carrying a duplicate kind can never be read as
    /// "no epoch advanced" even if the arity guard in `ErasureFenceV1::
    /// validate` were ever removed or bypassed upstream.
    pub fn may_commit(&self) -> ContractResult<bool> {
        self.validate()?;
        let same_generation = self.expected.generation.value == self.current.generation.value;
        let no_epoch_advanced = REQUIRED_FENCE_KINDS.iter().all(|kind| {
            match (
                single_epoch_for_kind(&self.current.entries, *kind),
                single_epoch_for_kind(&self.expected.entries, *kind),
            ) {
                (Some(current_epoch), Some(expected_epoch)) => current_epoch == expected_epoch,
                _ => false,
            }
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
    /// Fieldless *struct* variant (`{}`), not a bare unit variant — see
    /// [`ProspectiveReConsentV1::NotAuthorized`] for why: `deny_unknown_fields`
    /// on this internally-tagged enum does not, by itself, reject an extra
    /// key riding alongside a bare unit variant's `kind` tag (serde issue
    /// #1358), which is exactly the shape this type exists to forbid — a
    /// tombstone is the record that asserts an erased identity carries no
    /// payload bytes. `{}` still serializes as exactly `{"kind":
    /// "digest_only"}`.
    DigestOnly {},
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
/// `#[serde(deny_unknown_fields)]` on this type closes that for every field
/// this struct declares directly. It does **not**, by itself, close it for
/// [`TombstoneLifecycleV1::DigestOnly`]: `deny_unknown_fields` on an
/// internally-tagged enum does not reject an extra key riding alongside a
/// *bare unit* variant's tag (serde issue #1358) — an ingress path that
/// decoded with [`super::canonical::decode_strict`] alone could accept
/// `{"kind":"digest_only","canonical_text":"..."}` and silently drop the
/// smuggled field, reproducing the clean tombstone's identity. This module
/// closes that two ways: `DigestOnly {}` is a fieldless *struct* variant,
/// not a unit variant, so the smuggled key is rejected at decode time (see
/// `DigestOnly`'s doc comment); and every caller must decode through
/// [`super::canonical::decode_typed_canonical`], the required ingress gate
/// for this module (see the module-level doc comment), which independently
/// rejects any input whose re-encoding does not reproduce it byte for byte.
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
            TombstoneLifecycleV1::DigestOnly {} => true,
            TombstoneLifecycleV1::DigestAndMetadata {
                installed_at,
                superseded_by,
            } => {
                installed_at.is_microsecond_aligned()
                    && superseded_by.as_ref().is_none_or(|id| {
                        id.digest() != Sha256Digest::ZERO && *id != self.erasure_event_id
                    })
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
        ProspectiveReConsentV1::NotAuthorized {} => false,
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
    ///
    /// Fails closed on the hold itself first: `self.validate()` must succeed
    /// before any permissive answer is possible. An unvalidatable hold (for
    /// example one whose `released_at` precedes `placed_at`) has a release
    /// state nobody can trust, so it must never be treated as "released" and
    /// therefore permissive — a legal hold exists to DEFER removal, and
    /// answering `true` for a record this module cannot validate would
    /// destroy held material. This is the same fail-closed shape as
    /// `re_consent_permits_new_source_fact`, `RetainableMatcherPolicyV1::
    /// required_scope_action`, and `RestoreGateV1::outcome`.
    pub fn permits_removal(&self, at: &CanonicalTimestamp) -> ContractResult<bool> {
        self.validate()?;
        Ok(self
            .released_at
            .as_ref()
            .is_some_and(|released| released <= at))
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
    PseudonymousMatcherAllowed {
        matcher_policy: RegistryReferenceV1,
    },
    /// Fieldless *struct* variant (`{}`), not a bare unit variant — see
    /// [`ProspectiveReConsentV1::NotAuthorized`] for why. `{}` still
    /// serializes as exactly `{"kind":"pseudonymous_matcher_forbidden"}`.
    PseudonymousMatcherForbidden {},
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
            Self::PseudonymousMatcherForbidden {} => {
                RetainableMatcherScopeActionV1::DisableAndPurge
            }
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
#[path = "erasure_tests.rs"]
mod tests;
