//! Writing one observer run atomically (W3-OBSRT).
//!
//! # What "atomically" means here, mechanically
//!
//! The run receipt and the observer result travel as ONE canonical
//! [`ObserverRunRecordV1`], sealed into ONE governed content object, and that
//! object's write is the [`AppendProjection`] the append transaction runs.
//! [`AcceptedEventRepository::append`] executes the head witness fence, the
//! event insert, the projection, and the head compare-and-swap inside one
//! serializable transaction, so the receipt and the accepted event commit
//! together or neither does. There is no window in which a result event names
//! a receipt that is not durable, and none in which a receipt exists without
//! the event that admitted it (EVENT-03).
//!
//! # Replay
//!
//! Every byte of the record is a function of the admission, the pinned
//! commit and blob, and the algorithm's output. The observation instant is the
//! observed commit's own. So a second run over the same pins produces the same
//! source-fact identity, the same representation key, and the same
//! accepted-event id, and the ledger classifies it as
//! [`AppendOutcome::Replayed`] — one durable event, reported twice
//! (REPLAY-01).
//!
//! # The ledger classifies; this module counts
//!
//! `Appended`, `Replayed`, and `Quarantined` are the ledger's verdicts. A
//! quarantine writes a bounded dead-letter receipt and NO event row, so
//! [`ObserverRunOutcomeV1::accepted_event`] is `None` for one: citing the id
//! this module computed would name a ledger position that is not in
//! `memory_evidence_events`.

use std::sync::Arc;

use crate::control_log::TrustedControlScope;
use crate::evidence_ledger::{
    AcceptedEventRepository, ActiveStage4Package, AppendOutcome, ContentKeyEncryptionKey,
    EvidenceAdmissionRequestV1, GovernedContentProjection, WriterAuthorityWitness, admit_evidence,
};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::evidence_v2::RepresentationLineageV2;
use crate::memory_contracts::observer::VerificationOutcomeV1;

use super::admission::require_remember_basis_is_package_governed;
use super::error::ObserverRuntimeResult;
use super::ingress::{ObserverConnectorBindingV1, ObserverIngressClocksV1};
use super::receipt::ObserverRunRecordV1;

/// Everything one write needs, bundled so adding an input is a visible change
/// to a named contract rather than another positional argument.
pub struct ObserverDrainContextV1<'drain> {
    /// The active package's connector, already resolved.
    pub binding: &'drain ObserverConnectorBindingV1,
    /// The active Stage-4 package admission resolves everything from.
    pub active: &'drain ActiveStage4Package,
    /// The head witness the append transaction re-reads.
    pub witness: &'drain WriterAuthorityWitness,
    /// The accepted-event ledger.
    pub ledger: &'drain dyn AcceptedEventRepository,
    /// Physical and semantic scope of the governed content store.
    pub control_scope: &'drain TrustedControlScope,
    /// Key-encryption key the governed run record is sealed under.
    pub kek: &'drain ContentKeyEncryptionKey,
    /// The runtime's own ingress clock.
    pub clocks: &'drain ObserverIngressClocksV1,
}

impl std::fmt::Debug for ObserverDrainContextV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObserverDrainContextV1")
            .finish_non_exhaustive()
    }
}

/// What one write did, in the ledger's own vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserverRunOutcomeV1 {
    /// Whether the ledger appended a new event, recognised a replay, or
    /// refused the record into quarantine.
    pub disposition: ObserverAppendDispositionV1,
    /// The accepted-event identity, present only when a durable event row
    /// backs it. A quarantine contributes `None`.
    pub accepted_event: Option<AcceptedEventId>,
    /// The verification outcome the result carries. Reported, never decided
    /// here: it is whatever the contract derived from the admission and the
    /// run receipt.
    pub verification_outcome: VerificationOutcomeV1,
}

/// The ledger's verdict on one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserverAppendDispositionV1 {
    /// A new durable event.
    Appended,
    /// An exact replay of an event that already existed.
    Replayed,
    /// Refused into quarantine; no event row exists.
    Quarantined,
}

/// Admit and append one observer run record through the W1-EVID seam.
///
/// [`require_remember_basis_is_package_governed`] runs FIRST and before any
/// derivation or database work: if the active package would let a
/// `registered_observer` remember append happen, this runtime declines to run
/// rather than performing one. Moving the remember basis stays a package
/// change with its own approvals, never a side effect of an observation.
pub async fn drain_observer_run(
    context: &ObserverDrainContextV1<'_>,
    record: &ObserverRunRecordV1,
) -> ObserverRuntimeResult<ObserverRunOutcomeV1> {
    require_remember_basis_is_package_governed(context.active)?;

    let ingress = context.binding.build_ingress(record, context.clocks, 1)?;
    let admitted = admit_evidence(
        context.active,
        EvidenceAdmissionRequestV1 {
            candidate: &ingress.candidate,
            locators: &ingress.locators,
            canonical_payload: &ingress.canonical_payload,
            delivery: ingress.delivery.clone(),
            // A run record is rendered once. A different rendering of the same
            // run would have to name its predecessor explicitly (EVENT-01);
            // this runtime never mints one silently.
            lineage: RepresentationLineageV2::Origin,
        },
    )?;
    let accepted_event_id = admitted.statement().accepted_event_id()?;
    // The governed content object carries the run receipt AND the result, and
    // this projection is what runs inside the append transaction — which is
    // the whole of "written atomically".
    let projection =
        GovernedContentProjection::new(context.control_scope, admitted.content(), context.kek)?;
    let appendable = admitted.appendable(context.witness)?;
    let disposition = match context
        .ledger
        .append(context.witness, &appendable, Arc::new(projection))
        .await?
    {
        AppendOutcome::Appended { .. } => ObserverAppendDispositionV1::Appended,
        AppendOutcome::Replayed { .. } => ObserverAppendDispositionV1::Replayed,
        AppendOutcome::Quarantined { .. } => ObserverAppendDispositionV1::Quarantined,
    };
    Ok(ObserverRunOutcomeV1 {
        accepted_event: match disposition {
            ObserverAppendDispositionV1::Appended | ObserverAppendDispositionV1::Replayed => {
                Some(accepted_event_id)
            }
            ObserverAppendDispositionV1::Quarantined => None,
        },
        disposition,
        verification_outcome: record.verification_outcome(),
    })
}
