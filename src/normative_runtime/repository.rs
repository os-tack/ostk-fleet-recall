//! Admission rules, request/outcome shapes, and the repository trait for the
//! normative activation runtime (W3-NORM, Stage 6).
//!
//! [`admit_activation`] is the whole fail-closed boundary, and it is pure: it
//! runs before any transaction opens, so a rejected activation never touches the
//! database. [`admit_rebase`] is the same boundary for a head rebase, pure too,
//! but judged under the head lock against the durable head and live set. Every
//! check below is an ordinary negative test in `repository_tests.rs`.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;

use crate::Result;
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, RegistryReferenceV1,
};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, framed_digest};
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::normative_v2::{
    ContestedBindingV1, NormativeActivationReceiptV2, NormativeBindingProposalV2,
    NormativeCompositeHeadV2, NormativeHeadRebaseV1, NormativeLifecycleEventV1,
    NormativeLifecycleKindV1, RetroactiveCorrectionV1, require_effective_not_before_accepted,
};
use crate::memory_contracts::registry::RegistryPackageV1;
use crate::memory_contracts::{ContractError, ContractResult};
use crate::registry_witness::WriterAuthorityWitness;

use super::projection::{
    NormativeFamilyProjectionV1, NormativeLogEntryV1, NormativeLogRecordV1,
    NormativeStatementIntervalV1,
};

/// The active registry head this runtime is bound to at construction.
///
/// The caller reads it from the registry activation head and hands it over once;
/// every proposal must name exactly this package and activation policy or its
/// compare-and-set is stale. Binding it at construction is what stops a proposal
/// from choosing which registry it is judged against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormativeRegistryBindingV1 {
    pub registry_package_digest: Sha256Digest,
    pub activation_policy_digest: Sha256Digest,
}

impl NormativeRegistryBindingV1 {
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
                "normative runtime registry binding must name a non-zero package and policy".into(),
            ));
        }
        Ok(())
    }

    /// The composite head that a proposal expecting `active_binding_set_digest`
    /// must match exactly.
    #[must_use]
    pub const fn composite_head(
        &self,
        active_binding_set_digest: Option<Sha256Digest>,
    ) -> NormativeCompositeHeadV2 {
        NormativeCompositeHeadV2 {
            active_binding_set_digest,
            registry_package_digest: self.registry_package_digest,
            activation_policy_digest: self.activation_policy_digest,
        }
    }
}

/// One activation attempt.
///
/// The unsigned proposal, the activation receipt that ratifies it, and — only
/// for a retroactive correction — the separately authorized record that permits
/// an effective time before the accepted time.
#[derive(Debug, Clone)]
pub struct NormativeActivationCandidateV1 {
    pub proposal: NormativeBindingProposalV2,
    pub receipt: NormativeActivationReceiptV2,
    pub retroactive_correction: Option<RetroactiveCorrectionV1>,
}

/// A retirement, retraction, or expiry of one live statement.
#[derive(Debug, Clone)]
pub struct NormativeLifecycleRequestV1 {
    pub binding_family_id: ContractId,
    /// Must be [`NormativeLifecycleKindV1::Retirement`],
    /// [`NormativeLifecycleKindV1::Retraction`], or
    /// [`NormativeLifecycleKindV1::Expiry`]: activation and supersession are
    /// reached only through [`NormativeActivationRepository::activate`], which
    /// requires a receipt.
    pub kind: NormativeLifecycleKindV1,
    pub statement_id: Sha256Digest,
    pub registry_head: RegistryHeadBindingV1,
    pub effective_at: CanonicalTimestamp,
    /// The binding-set digest this request expects to be current: the same
    /// compare-and-set discipline an activation uses.
    pub expected_active_binding_set_digest: Option<Sha256Digest>,
    pub waiver_reference_digest: Option<Sha256Digest>,
}

/// What one accepted transition did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormativeTransitionV1 {
    /// The lifecycle event's own identity, as appended.
    pub event_id: Sha256Digest,
    /// The statement the event names; `None` for a contest record, which names
    /// a set of statements rather than one.
    pub statement_id: Option<Sha256Digest>,
    /// Head revision after the transition (strictly monotone).
    pub head_revision: u64,
    /// Normative-log sequence the projection cursor now sits at.
    pub log_seq: u64,
    /// The binding-set digest now current, `None` when nothing is live.
    pub active_binding_set_digest: Option<Sha256Digest>,
}

/// Outcome of one compare-and-set activation or lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormativeActivationOutcomeV1 {
    /// The compare-and-set won: the log row, the head advance, and the
    /// projection advance all committed together.
    Installed(NormativeTransitionV1),
    /// The compare-and-set lost to a concurrent transition. Nothing was written.
    /// This is an outcome, not an error: the caller re-reads the head and
    /// re-proposes against it.
    Lost {
        /// The binding-set digest actually current when this attempt ran.
        observed_binding_set_digest: Option<Sha256Digest>,
        /// The head revision actually current when this attempt ran.
        observed_head_revision: u64,
    },
}

/// The durable compare-and-set head for one binding family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormativeHeadRowV1 {
    pub binding_family_id: ContractId,
    pub active_binding_set_digest: Option<Sha256Digest>,
    pub registry_package_digest: Sha256Digest,
    pub activation_policy_digest: Sha256Digest,
    pub head_revision: u64,
    pub log_seq: u64,
}

impl NormativeHeadRowV1 {
    /// The exact composite a proposal's `require_current_composite` is checked
    /// against.
    #[must_use]
    pub const fn composite_head(&self) -> NormativeCompositeHeadV2 {
        NormativeCompositeHeadV2 {
            active_binding_set_digest: self.active_binding_set_digest,
            registry_package_digest: self.registry_package_digest,
            activation_policy_digest: self.activation_policy_digest,
        }
    }
}

/// An activation that passed every pure check.
///
/// It carries the lifecycle event the runtime *derived* from the candidate. The
/// event is never supplied by the caller, so a caller cannot declare an
/// activation to be a supersession, or vice versa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedNormativeActivationV1 {
    pub statement_id: Sha256Digest,
    pub event_id: Sha256Digest,
    pub record: NormativeLogRecordV1,
    pub interval: NormativeStatementIntervalV1,
    pub expected_head: NormativeCompositeHeadV2,
}

/// Digest of the set of statements currently live for one binding family.
///
/// `None` for an empty set: the composite head an inaugural activation must
/// expect. Length-framed under its own domain, so no two families and no two
/// live sets can collide, and the digest is a function of the *set* — sorted,
/// order-insensitive — not of the order statements were activated in.
#[must_use]
pub fn active_binding_set_digest(
    binding_family_id: &ContractId,
    live_statement_ids: &[Sha256Digest],
) -> Option<Sha256Digest> {
    if live_statement_ids.is_empty() {
        return None;
    }
    let mut sorted = live_statement_ids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(sorted.len() + 1);
    parts.push(binding_family_id.as_str().as_bytes());
    for statement_id in &sorted {
        parts.push(statement_id.as_bytes());
    }
    Some(framed_digest(
        DigestDomain::NormativeActiveBindingSetV1,
        &parts,
    ))
}

/// Refuse a proposal that does not name exactly the witnessed registry head.
///
/// [`admit_activation`] compares only the package and activation-policy
/// digests, which an A -> B -> A rollback restores unchanged. A caller holding
/// a strict writer-authority witness compares the whole head binding instead:
/// the exact `activation_id` (ABA safety) and the head's effective interval, so
/// a proposal drafted against an earlier activation of the same package is
/// stale rather than silently re-targeted.
///
/// # Errors
///
/// [`ContractError::StaleRegistryHead`] on any difference.
pub fn require_witnessed_head(
    proposal: &NormativeBindingProposalV2,
    head: &RegistryHeadBindingV1,
) -> ContractResult<()> {
    if &proposal.registry_head != head {
        return Err(ContractError::StaleRegistryHead);
    }
    Ok(())
}

/// Every pure fail-closed check an activation must pass, in one place.
///
/// Ordered so the cheapest structural rejections run first, but every check is
/// independent: none of them is reachable only because an earlier one passed.
pub fn admit_activation(
    candidate: &NormativeActivationCandidateV1,
    binding: &NormativeRegistryBindingV1,
    bound_scope: &AuthenticatedProjectScopeV1,
) -> ContractResult<AdmittedNormativeActivationV1> {
    binding.validate()?;
    let proposal = &candidate.proposal;
    let statement_id = proposal.statement_id()?;

    // SCOPE binding: the proposal's authenticated project scope must be the
    // scope this repository was constructed for. Without this a proposal minted
    // for another tenant/project would activate here under our credentials.
    if &proposal.scope != bound_scope {
        return Err(ContractError::Schema(
            "normative proposal scope is not the runtime's bound project scope".into(),
        ));
    }

    // Registry/policy binding: a proposal judged against a registry package or
    // activation policy other than the live one is stale, not merely different.
    if proposal.registry_head.head.package_digest != binding.registry_package_digest
        || proposal.registry_head.head.activation_policy_digest != binding.activation_policy_digest
    {
        return Err(ContractError::StaleRegistryHead);
    }

    // The receipt must ratify THIS statement and name THIS source author.
    if candidate.receipt.statement_id != statement_id {
        return Err(ContractError::Schema(
            "normative activation receipt ratifies a different statement".into(),
        ));
    }
    if candidate.receipt.source_author_principal_id != proposal.source_author_principal_id {
        return Err(ContractError::Schema(
            "normative activation receipt names a different source author".into(),
        ));
    }
    // Threshold, unique principal/key bindings, and the contract's own
    // separation-of-duty re-derivation (AUTH-03).
    candidate.receipt.validate()?;

    // Runtime separation of duty, stronger than the contract's: every actor
    // implicated in the change — the source author AND the proposer — is
    // excluded from being the only ratifier. An approval set consisting solely
    // of implicated principals is refused closed.
    let independent = candidate.receipt.eligible_approvals.iter().any(|approval| {
        approval.principal_id != proposal.source_author_principal_id
            && approval.principal_id != proposal.proposer_principal_id
    });
    if !independent {
        return Err(ContractError::Schema(
            "normative activation has no ratifier independent of the actors implicated in the change"
                .into(),
        ));
    }

    // Bitemporal rule: an ordinary activation may not be effective before it was
    // accepted. Only a separately authorized retroactive correction may be, and
    // it must be about exactly this statement at exactly these two times.
    match &candidate.retroactive_correction {
        None => require_effective_not_before_accepted(
            &proposal.effective_from,
            &candidate.receipt.accepted_at,
        )?,
        Some(correction) => {
            correction.validate()?;
            if correction.statement_id != statement_id
                || correction.effective_from != proposal.effective_from
                || correction.accepted_at != candidate.receipt.accepted_at
            {
                return Err(ContractError::Schema(
                    "retroactive correction does not describe this activation".into(),
                ));
            }
            // A correction preserves the prior as-known conclusion; it may not
            // name the statement it introduces as the thing it corrects.
            if correction.superseded_as_known_statement_id == statement_id {
                return Err(ContractError::Schema(
                    "retroactive correction cannot supersede its own statement".into(),
                ));
            }
        }
    }

    // The lifecycle event is DERIVED, never supplied: a proposal that names a
    // supersession target becomes a Supersession event, everything else an
    // Activation. Its own validate() then rejects a self-supersession.
    let kind = if proposal.explicitly_supersedes_statement_id.is_some() {
        NormativeLifecycleKindV1::Supersession
    } else {
        NormativeLifecycleKindV1::Activation
    };
    let event = NormativeLifecycleEventV1 {
        schema_version: 1,
        kind,
        binding_family_id: proposal.binding_family_id.clone(),
        statement_id,
        registry_head: proposal.registry_head.clone(),
        effective_at: candidate.receipt.accepted_at.clone(),
        supersedes_statement_id: proposal.explicitly_supersedes_statement_id,
        waiver_reference_digest: None,
    };
    let event_id = event.event_id()?;
    let interval = NormativeStatementIntervalV1 {
        statement_id,
        effective_from: proposal.effective_from.clone(),
        effective_until: proposal.effective_until.clone(),
    };
    let record = NormativeLogRecordV1::Lifecycle {
        event,
        interval: interval.clone(),
    };
    record.validate()?;

    Ok(AdmittedNormativeActivationV1 {
        statement_id,
        event_id,
        record,
        interval,
        expected_head: proposal.expected_composite_head(),
    })
}

/// Refuse an activation that overlaps any live statement it does not explicitly
/// supersede (the contract's own conflict rule, applied to the durable live set).
pub fn require_non_conflicting_against_live(
    proposal: &NormativeBindingProposalV2,
    projection: &NormativeFamilyProjectionV1,
) -> ContractResult<()> {
    for live in &projection.live {
        proposal.require_non_conflicting_activation(
            &projection.binding_family_id,
            live.statement_id,
            &live.effective_from,
            live.effective_until.as_ref(),
        )?;
    }
    Ok(())
}

/// Derive the lifecycle record for a retirement, retraction, or expiry.
///
/// The statement's interval is taken from the durable projection, not from the
/// caller, so a retirement cannot restate a statement's effective span.
pub fn admit_lifecycle(
    request: &NormativeLifecycleRequestV1,
    binding: &NormativeRegistryBindingV1,
    projection: &NormativeFamilyProjectionV1,
) -> ContractResult<(Sha256Digest, NormativeLogRecordV1)> {
    binding.validate()?;
    match request.kind {
        NormativeLifecycleKindV1::Retirement
        | NormativeLifecycleKindV1::Retraction
        | NormativeLifecycleKindV1::Expiry => {}
        NormativeLifecycleKindV1::Activation | NormativeLifecycleKindV1::Supersession => {
            return Err(ContractError::Schema(
                "activation and supersession require a ratified activation candidate".into(),
            ));
        }
    }
    if request.registry_head.head.package_digest != binding.registry_package_digest
        || request.registry_head.head.activation_policy_digest != binding.activation_policy_digest
    {
        return Err(ContractError::StaleRegistryHead);
    }
    if request.binding_family_id != projection.binding_family_id {
        return Err(ContractError::Schema(
            "normative lifecycle request names a different binding family".into(),
        ));
    }
    let Some(interval) = projection
        .live
        .iter()
        .find(|interval| interval.statement_id == request.statement_id)
    else {
        return Err(ContractError::Schema(
            "normative lifecycle request names a statement that is not live".into(),
        ));
    };
    let event = NormativeLifecycleEventV1 {
        schema_version: 1,
        kind: request.kind,
        binding_family_id: request.binding_family_id.clone(),
        statement_id: request.statement_id,
        registry_head: request.registry_head.clone(),
        effective_at: request.effective_at.clone(),
        supersedes_statement_id: None,
        waiver_reference_digest: request.waiver_reference_digest,
    };
    let event_id = event.event_id()?;
    let record = NormativeLogRecordV1::Lifecycle {
        event,
        interval: interval.clone(),
    };
    record.validate()?;
    Ok((event_id, record))
}

/// Refuse a contest record that does not describe this family's live set.
///
/// A contest is only meaningful while at least two of the statements it names
/// are live; recording one against a single live statement (or none) would flip
/// the family to `unknown` on no evidence.
pub fn admit_contest(
    contest: &ContestedBindingV1,
    projection: &NormativeFamilyProjectionV1,
) -> ContractResult<(Sha256Digest, NormativeLogRecordV1)> {
    contest.validate()?;
    if contest.binding_family_id != projection.binding_family_id {
        return Err(ContractError::Schema(
            "contested binding names a different binding family".into(),
        ));
    }
    let live = projection.live_statement_ids();
    let named_and_live = contest
        .contested_statement_ids
        .iter()
        .filter(|statement_id| live.contains(statement_id))
        .count();
    if named_and_live < 2 {
        return Err(ContractError::Schema(
            "contested binding must name at least two live statements".into(),
        ));
    }
    let contested_id = contest.contested_id()?;
    let record = NormativeLogRecordV1::Contest {
        contest: contest.clone(),
    };
    record.validate()?;
    Ok((contested_id, record))
}

/// The registry head a rebase moves binding families onto, and every registry
/// entry that head's authority resolves (ADR 0008 D3).
///
/// A family's live statements name registry entries in two places: in the
/// active successor package (a spec statement's subject is derived under its
/// `identity.github.repository` recipe) and in the genesis package the
/// scope's pinned bootstrap binds (its predicate and applicability evaluator,
/// ADR 0007 D1). A successor transition never changes the genesis package, so
/// the entries a head resolves are its own package's and the genesis
/// package's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormativeRebaseTargetV1 {
    binding: NormativeRegistryBindingV1,
    registry_activation_id: Sha256Digest,
    entries: BTreeSet<RegistryReferenceV1>,
}

impl NormativeRebaseTargetV1 {
    /// A target over an explicit entry set.
    ///
    /// # Errors
    ///
    /// [`ContractError::Schema`] for a zero package, policy, or activation
    /// digest.
    pub fn new(
        binding: NormativeRegistryBindingV1,
        registry_activation_id: Sha256Digest,
        entries: impl IntoIterator<Item = RegistryReferenceV1>,
    ) -> ContractResult<Self> {
        binding.validate()?;
        if registry_activation_id == Sha256Digest::ZERO {
            return Err(ContractError::Schema(
                "a normative rebase target must name its exact registry activation".into(),
            ));
        }
        Ok(Self {
            binding,
            registry_activation_id,
            entries: entries.into_iter().collect(),
        })
    }

    /// The head a strict writer-authority witness certifies: its package and
    /// activation-policy digests, its exact activation, and every entry of its
    /// package and of the genesis package it descends from, each named by its
    /// manifest's verified digest.
    ///
    /// # Errors
    ///
    /// [`ContractError::Schema`] for a zero digest, which a verified witness
    /// never has.
    pub fn from_witness(witness: &WriterAuthorityWitness) -> ContractResult<Self> {
        let successor = witness.package().manifest_verified_package().package();
        let genesis = witness
            .genesis_package()
            .manifest_verified_package()
            .package();
        Self::new(
            NormativeRegistryBindingV1::from_witness(witness),
            witness.activation_id(),
            package_references(successor).chain(package_references(genesis)),
        )
    }

    /// The package and activation-policy digests a rebased head carries.
    #[must_use]
    pub const fn binding(&self) -> NormativeRegistryBindingV1 {
        self.binding
    }

    /// The exact activation of the target head.
    #[must_use]
    pub const fn registry_activation_id(&self) -> Sha256Digest {
        self.registry_activation_id
    }

    /// Whether the target resolves `reference` to the very same entry: same
    /// id, same version, byte-identical digest.
    #[must_use]
    pub fn carries(&self, reference: &RegistryReferenceV1) -> bool {
        self.entries.contains(reference)
    }
}

/// Every entry of `package`, as the reference its verified manifest names.
fn package_references(
    package: &RegistryPackageV1,
) -> impl Iterator<Item = RegistryReferenceV1> + '_ {
    package.manifest.iter().map(|manifest| RegistryReferenceV1 {
        entry_id: manifest.entry_id.clone(),
        version: manifest.version,
        entry_digest: manifest.entry_digest,
    })
}

/// One family's rebase, with the dependencies its caller resolved.
///
/// The normative log holds each statement's interval but not its proposal, so
/// the caller resolves what every live statement depends on (for a spec
/// statement, `crate::spec_conformance::spec_statement_dependencies`) and the
/// runtime checks, under the head lock, that it described exactly the durable
/// live set at exactly the head revision it read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormativeRebaseRequestV1 {
    pub binding_family_id: ContractId,
    /// The head revision the dependencies were resolved at. A head that moved
    /// since is [`NormativeRebaseOutcomeV1::Stale`], never rebased over.
    pub expected_head_revision: u64,
    /// Every live statement of the family, each with the registry entries it
    /// depends on.
    pub live_statement_dependencies: BTreeMap<Sha256Digest, BTreeSet<RegistryReferenceV1>>,
}

/// What one rebase attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormativeRebaseOutcomeV1 {
    /// The rebase row, the head's move, and the projection's cursor advance
    /// committed together.
    Rebased {
        transition: NormativeTransitionV1,
        rebase: Box<NormativeHeadRebaseV1>,
    },
    /// The head already names the target package and policy. Nothing was
    /// written.
    AlreadyCurrent { head_revision: u64 },
    /// The head moved since the request was resolved. Nothing was written; the
    /// caller re-reads the family and resolves again.
    Stale { observed_head_revision: u64 },
}

/// What [`admit_rebase`] decided under the head lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormativeRebaseAdmissionV1 {
    /// The head already names the target.
    AlreadyCurrent,
    /// The head is not at the revision the request was resolved at.
    Stale,
    /// Append this record and move the head to the target.
    Rebase {
        record_id: Sha256Digest,
        record: Box<NormativeLogRecordV1>,
    },
}

/// Every pure check a head rebase must pass, judged against the durable head
/// and projection read under the head lock.
///
/// A head already at the target is [`NormativeRebaseAdmissionV1::AlreadyCurrent`]
/// (a rebase is idempotent), and one at another revision than the request was
/// resolved at is [`NormativeRebaseAdmissionV1::Stale`]. Otherwise the request
/// must describe exactly the family's live statements, and the target must
/// carry every registry entry any of them depends on, byte for byte; only then
/// is the rebase record derived, with `rebased_at` the caller's server time.
///
/// # Errors
///
/// [`ContractError::Schema`] for a request about another family, a head that
/// names the target package under another activation policy, a projection
/// whose cursor disagrees with its head, a request that does not describe the
/// live set, and a dependency the target does not carry.
pub fn admit_rebase(
    head: &NormativeHeadRowV1,
    projection: &NormativeFamilyProjectionV1,
    target: &NormativeRebaseTargetV1,
    request: &NormativeRebaseRequestV1,
    rebased_at: CanonicalTimestamp,
) -> ContractResult<NormativeRebaseAdmissionV1> {
    let binding = target.binding();
    binding.validate()?;
    if head.binding_family_id != request.binding_family_id
        || projection.binding_family_id != request.binding_family_id
    {
        return Err(ContractError::Schema(
            "normative rebase request names a different binding family".into(),
        ));
    }
    if head.registry_package_digest == binding.registry_package_digest {
        if head.activation_policy_digest == binding.activation_policy_digest {
            return Ok(NormativeRebaseAdmissionV1::AlreadyCurrent);
        }
        return Err(ContractError::Schema(
            "normative head names the target package under another activation policy".into(),
        ));
    }
    if head.head_revision != request.expected_head_revision {
        return Ok(NormativeRebaseAdmissionV1::Stale);
    }
    if projection.cursor_seq != head.log_seq {
        return Err(ContractError::Schema(
            "normative projection cursor disagrees with its head log sequence".into(),
        ));
    }
    let live: BTreeSet<Sha256Digest> = projection.live_statement_ids().into_iter().collect();
    if request
        .live_statement_dependencies
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        != live
    {
        return Err(ContractError::Schema(
            "normative rebase request does not describe the family's live statements".into(),
        ));
    }
    let mut carried = BTreeSet::new();
    for (statement_id, dependencies) in &request.live_statement_dependencies {
        for dependency in dependencies {
            if !target.carries(dependency) {
                return Err(ContractError::Schema(format!(
                    "live statement {statement_id} depends on registry entry {} v{} ({}), which \
                     the target head does not carry byte for byte",
                    dependency.entry_id, dependency.version, dependency.entry_digest
                )));
            }
            carried.insert(dependency.entry_digest);
        }
    }
    let rebase = NormativeHeadRebaseV1 {
        schema_version: 1,
        binding_family_id: request.binding_family_id.clone(),
        from_registry_package_digest: head.registry_package_digest,
        from_activation_policy_digest: head.activation_policy_digest,
        to_registry_package_digest: binding.registry_package_digest,
        to_activation_policy_digest: binding.activation_policy_digest,
        registry_activation_id: target.registry_activation_id(),
        carried_entry_digests: carried.into_iter().collect(),
        rebased_at,
    };
    let record_id = rebase.record_id()?;
    let record = NormativeLogRecordV1::Rebase { rebase };
    record.validate()?;
    Ok(NormativeRebaseAdmissionV1::Rebase {
        record_id,
        record: Box::new(record),
    })
}

/// Append and read surface for the normative activation runtime, bound once to
/// physical scope, semantic scope, and the active registry head.
#[async_trait]
pub trait NormativeActivationRepository: Send + Sync {
    /// Compare-and-set one activation (or supersession) into place. The log
    /// append, the head advance, and the projection advance commit together or
    /// not at all; a concurrent winner makes this return
    /// [`NormativeActivationOutcomeV1::Lost`] with nothing written.
    async fn activate(
        &self,
        candidate: &NormativeActivationCandidateV1,
    ) -> Result<NormativeActivationOutcomeV1>;

    /// Append a retirement, retraction, or expiry under the same
    /// compare-and-set. History is never erased: the prior activation row stays.
    async fn retire(
        &self,
        request: &NormativeLifecycleRequestV1,
    ) -> Result<NormativeActivationOutcomeV1>;

    /// Record that two or more live statements cannot be ordered, flipping the
    /// family's projection to `unknown`.
    async fn record_contest(&self, contest: &ContestedBindingV1) -> Result<NormativeTransitionV1>;

    /// Read the durable compare-and-set head, if the family has one.
    async fn read_head(&self, binding_family_id: &ContractId)
    -> Result<Option<NormativeHeadRowV1>>;

    /// Read the stored projection exactly as persisted, with its cursor.
    async fn read_projection(
        &self,
        binding_family_id: &ContractId,
    ) -> Result<Option<NormativeFamilyProjectionV1>>;

    /// Read the whole normative log for one family, in sequence order.
    async fn read_log(&self, binding_family_id: &ContractId) -> Result<Vec<NormativeLogEntryV1>>;

    /// Re-derive the projection from the durable log alone. Must equal the
    /// stored projection byte for byte.
    async fn rebuild_projection(
        &self,
        binding_family_id: &ContractId,
    ) -> Result<NormativeFamilyProjectionV1>;
}

#[cfg(test)]
#[path = "repository_tests.rs"]
mod tests;
