//! Draining CI facts into the accepted-event ledger, and the bounded coverage
//! that makes an absence meaningful (W3-CIEV, COVER-01..03).
//!
//! The drain owns no authority of its own. For each fact it builds an ingress,
//! hands it to [`admit_evidence`], seals the admitted governed content, and
//! calls [`AcceptedEventRepository::append`] — the same seam every other
//! producer uses. It classifies nothing: `Appended`, `Replayed`, and
//! `Quarantined` are the ledger's verdicts, counted and reported, never
//! reinterpreted. A re-drain of the SAME recorded scan reports `replayed` and
//! writes no second event, because both identities and both clocks are
//! functions of the scan rather than of the moment the drain ran.
//!
//! # A quarantine is not a ledger position
//!
//! [`AppendOutcome::Quarantined`] writes a bounded dead-letter receipt and NO
//! event row; the shard head does not advance. The accepted-event id this
//! module computed for such a fact therefore names nothing in
//! `memory_evidence_events`, and one rule follows everywhere below: **a
//! quarantined fact contributes nothing a receipt may cite.**
//!
//! A refused WINDOW observation is stronger still. The window is the whole
//! statement of what was measured, so if the ledger declined it there is no
//! durable bound on the scan at all, and [`ci_coverage_observation`] refuses
//! the scope closed with [`CiDrainError::WindowObservationQuarantined`] rather
//! than anchoring on an older window that happened to survive. A receipt
//! claiming a range is covered while the ledger refused that range's defining
//! evidence is exactly the "trust me, I looked" claim COVER-03 forbids.
//!
//! # Order matters: runs first, window last
//!
//! [`ci_scan_facts`] emits the settled runs and then the window observation, so
//! the observation the receipt binds is appended only after every run it counts
//! has already been offered to the ledger. A window that claims `n` admitted
//! runs is therefore never durable before those runs were.

use std::sync::Arc;

use crate::control_log::TrustedControlScope;
use crate::coverage_runtime::{CoverageCursorRowV1, SequenceIntervalV1};
use crate::evidence_ledger::{
    AcceptedEventRepository, ActiveStage4Package, AppendOutcome, ContentKeyEncryptionKey,
    EvidenceAdmissionRequestV1, GovernedContentProjection, WriterAuthorityWitness, admit_evidence,
};
use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId, HexBytes};
use crate::memory_contracts::coverage::{
    CoverageFreshnessV1, CoverageProofBasisV1, CoverageScopeV1, CoverageWindowV1,
    ProducerIdentityV1,
};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, framed_digest};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::evidence_v2::RepresentationLineageV2;
use crate::memory_contracts::identity::ResourceUri;

use super::error::{CiDrainError, CiDrainResult};
use super::fact::{CiCoverageWindowV1, CiFactV1, CiWindowObservationLogV1};
use super::ingress::{CiConnectorBindingV1, CiIngressClocksV1};
use super::scan::CiScanV1;

/// What one drain did, in the ledger's own vocabulary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CiDrainReportV1 {
    /// Facts that became new accepted events.
    pub appended: u64,
    /// Facts the ledger recognised as exact replays of existing events.
    pub replayed: u64,
    /// Facts the ledger refused into quarantine.
    pub quarantined: u64,
    /// Accepted-event identity of every fact the ledger made DURABLE, in scan
    /// order. A replay contributes the identity of the event that already
    /// existed; a quarantine contributes nothing.
    pub events: Vec<AcceptedEventId>,
    /// Logical event key of each durably admitted fact, in the same order as
    /// [`Self::events`]. This is the exact set a coverage receipt's
    /// `source_digest` and `source_count` report.
    pub admitted_keys: Vec<HexBytes>,
    /// Accepted-event identity of the newest DURABLE window observation, which
    /// is what a coverage receipt binds.
    pub window_observation_event: Option<AcceptedEventId>,
    /// Window observations the ledger refused into quarantine. Any non-zero
    /// count voids this scan's coverage claim.
    pub quarantined_window_observations: u64,
}

impl CiDrainReportV1 {
    /// Total facts drained.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.appended + self.replayed + self.quarantined
    }

    /// Record a fact the ledger made durable (appended or replayed).
    ///
    /// Deliberately private and deliberately the ONLY writer of [`Self::events`],
    /// [`Self::admitted_keys`], and [`Self::window_observation_event`]: the
    /// three fields a receipt reads can therefore only be reached from an
    /// append outcome that left an event row behind.
    fn record_durable(
        &mut self,
        fact: &CiFactV1,
        accepted_event_id: AcceptedEventId,
    ) -> CiDrainResult<()> {
        self.events.push(accepted_event_id);
        self.admitted_keys.push(fact.logical_event_key()?);
        if matches!(fact, CiFactV1::WindowObservation(_)) {
            self.window_observation_event = Some(accepted_event_id);
        }
        Ok(())
    }
}

/// Everything one drain needs, bundled so adding an input is a visible change
/// to a named contract rather than another positional argument.
pub struct CiDrainContextV1<'drain> {
    /// The active package's CI connector, already resolved.
    pub binding: &'drain CiConnectorBindingV1,
    /// The active package admission resolves everything from.
    pub active: &'drain ActiveStage4Package,
    /// The head witness the append transaction re-reads.
    pub witness: &'drain WriterAuthorityWitness,
    /// The accepted-event ledger.
    pub ledger: &'drain dyn AcceptedEventRepository,
    /// Physical and semantic scope of the governed content store.
    pub control_scope: &'drain TrustedControlScope,
    /// Key-encryption key the governed content is sealed under.
    pub kek: &'drain ContentKeyEncryptionKey,
    /// The connector's own observation and receipt clocks.
    pub clocks: &'drain CiIngressClocksV1,
}

impl std::fmt::Debug for CiDrainContextV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CiDrainContextV1")
            .finish_non_exhaustive()
    }
}

/// Turn one scan into the ordered fact batch a drain consumes.
///
/// The window observation is minted through the append-only log, so its
/// sequence number and its predecessor range are the log's and never the
/// caller's, and it is emitted LAST so no receipt can bind a window before the
/// runs it counts reached the ledger.
pub fn ci_scan_facts(
    scan: &CiScanV1,
    log: &mut CiWindowObservationLogV1,
    max_observations: usize,
) -> CiDrainResult<Vec<CiFactV1>> {
    let mut facts: Vec<CiFactV1> = scan
        .runs
        .iter()
        .cloned()
        .map(CiFactV1::WorkflowRun)
        .collect();
    let observation = log.observe(
        scan.window.clone(),
        scan.admitted_run_count(),
        scan.failed_run_count(),
        max_observations,
    )?;
    facts.push(CiFactV1::WindowObservation(observation.clone()));
    Ok(facts)
}

/// Drain an ordered batch of CI facts through the W1-EVID admission seam.
pub async fn drain_ci_facts(
    context: &CiDrainContextV1<'_>,
    facts: &[CiFactV1],
) -> CiDrainResult<CiDrainReportV1> {
    let mut report = CiDrainReportV1::default();
    for fact in facts {
        let ingress = context.binding.build_ingress(fact, context.clocks, 1)?;
        let admitted = admit_evidence(
            context.active,
            EvidenceAdmissionRequestV1 {
                candidate: &ingress.candidate,
                locators: &ingress.locators,
                canonical_payload: &ingress.canonical_payload,
                delivery: ingress.delivery.clone(),
                // A CI fact is rendered once. A different rendering of the same
                // fact would have to name its predecessor explicitly
                // (EVENT-01); this connector never mints one silently.
                lineage: RepresentationLineageV2::Origin,
            },
        )?;
        let accepted_event_id = admitted.statement().accepted_event_id()?;
        let projection =
            GovernedContentProjection::new(context.control_scope, admitted.content(), context.kek)?;
        let appendable = admitted.appendable(context.witness)?;
        match context
            .ledger
            .append(context.witness, &appendable, Arc::new(projection))
            .await?
        {
            AppendOutcome::Appended { .. } => {
                report.appended += 1;
                report.record_durable(fact, accepted_event_id)?;
            }
            AppendOutcome::Replayed { .. } => {
                report.replayed += 1;
                report.record_durable(fact, accepted_event_id)?;
            }
            // No event row exists at `accepted_event_id`, so this fact is
            // recorded ONLY as a refusal count.
            AppendOutcome::Quarantined { .. } => {
                report.quarantined += 1;
                if matches!(fact, CiFactV1::WindowObservation(_)) {
                    report.quarantined_window_observations += 1;
                }
            }
        }
    }
    Ok(report)
}

/// Deployment-supplied coverage registration for one CI connector instance.
///
/// Every registry reference here is deployment configuration read from the
/// active registry, exactly like the coverage runtime's own callers supply it:
/// this connector does not mint freshness rules or proof methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiCoverageBindingV1 {
    /// Connector instance the cursor and receipts are keyed to.
    pub connector_instance: ContractId,
    /// Producer identity stamped into every receipt.
    pub producer: ProducerIdentityV1,
    /// Freshness state under its registered rule.
    pub freshness: CoverageFreshnessV1,
    /// Proof basis under its registered method.
    pub proof_basis: CoverageProofBasisV1,
    /// The half-open time window this coverage domain reports on.
    pub time_window: CoverageWindowV1,
}

/// Build the coverage observation for one CI window scan.
///
/// The observed sequence interval is the window's own run-number range, so the
/// coverage cursor and the epistemic window this connector answers questions
/// against are literally the same numbers. The receipt's source manifest is
/// [`CiDrainReportV1::admitted_keys`] rather than the scan's input batch, so a
/// fact the ledger refused cannot reach a receipt by either route.
///
/// Two refusals, in order:
///
/// 1. **A quarantined window observation voids the scope.** The ledger refused
///    the statement of what was measured, so there is no durable bound to
///    report and this fails closed.
/// 2. **No window observation at all is refused too.** A coverage claim that
///    binds no evidence is the receipt COVER-03 rejects.
pub fn ci_coverage_observation(
    coverage: &CiCoverageBindingV1,
    window_resource: ResourceUri,
    window: &CiCoverageWindowV1,
    target: SequenceIntervalV1,
    report: &CiDrainReportV1,
    observed_through: CanonicalTimestamp,
) -> CiDrainResult<crate::coverage_runtime::CoverageObservationV1> {
    if report.quarantined_window_observations > 0 {
        return Err(CiDrainError::WindowObservationQuarantined);
    }
    let evidence_id = report
        .window_observation_event
        .ok_or(CiDrainError::NoWindowObservation)?;
    let window_id = window.window_id()?;
    // Half-open, because the coverage runtime's intervals are: the window's
    // inclusive `last_run_number` is `end - 1`.
    let observed = SequenceIntervalV1::new(window.first_run_number, window.last_run_number + 1)
        .map_err(|_| {
            CiDrainError::Fact(super::error::CiFactError::Schema(
                "ci window range is not a valid coverage interval",
            ))
        })?;
    Ok(crate::coverage_runtime::CoverageObservationV1 {
        connector_instance: coverage.connector_instance.clone(),
        producer: coverage.producer.clone(),
        scope: CoverageScopeV1 {
            scope: window_resource,
            revision: HexBytes::new(window_id.as_bytes().to_vec())?,
            window: coverage.time_window.clone(),
        },
        target,
        observed,
        freshness: coverage.freshness.clone(),
        proof_basis: coverage.proof_basis.clone(),
        source_digest: ci_scan_manifest_digest(&report.admitted_keys),
        source_count: u32::try_from(report.admitted_keys.len()).unwrap_or(u32::MAX),
        evidence_id,
        observed_through,
    })
}

/// Content-addressed digest of exactly which facts a manifest names, in order.
///
/// Framed over each fact's logical event key rather than its payload bytes, so
/// the manifest identifies the observed *set* without restating the governed
/// content the ledger already stores. It takes keys rather than facts on
/// purpose: the only manifest a receipt is allowed to report is
/// [`CiDrainReportV1::admitted_keys`], and a function that accepted a raw fact
/// batch would make "digest what I scanned" as easy to write as "digest what
/// the ledger kept".
#[must_use]
pub fn ci_scan_manifest_digest(keys: &[HexBytes]) -> Sha256Digest {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(keys.len() + 1);
    parts.push(b"ci-scan-manifest");
    parts.extend(keys.iter().map(HexBytes::as_bytes));
    framed_digest(DigestDomain::CiScanManifestV1, &parts)
}

/// Logical event keys of an ordered fact batch.
pub fn ci_fact_manifest_keys(facts: &[CiFactV1]) -> CiDrainResult<Vec<HexBytes>> {
    facts
        .iter()
        .map(|fact| fact.logical_event_key().map_err(CiDrainError::Fact))
        .collect()
}

/// The next run number a scan should read.
///
/// The cursor's high watermark is the EXCLUSIVE end of the merged observed
/// range, so it is already the next unread run number. An absent cursor resumes
/// at one, because a domain with no observation has covered nothing — and,
/// crucially, "has covered nothing" is what makes every question about it
/// UNKNOWN rather than negative.
///
/// Resuming here is not an optimisation, it is what keeps `observed_at` honest:
/// a settled run re-read in a LATER window would be observed at a different
/// instant, mint a different accepted-event id for one representation, and be
/// quarantined by the ledger as a preimage disagreement. The cursor is what
/// makes each settled run observed exactly once.
#[must_use]
pub fn ci_resume_run_number(cursor: Option<&CoverageCursorRowV1>) -> u64 {
    cursor
        .and_then(|row| row.observed.high_watermark())
        .unwrap_or(1)
}

/// Canonical bytes of one CI fact, for callers that need the exact governed
/// rendering without building a whole ingress.
pub fn ci_fact_canonical_bytes(fact: &CiFactV1) -> CiDrainResult<Vec<u8>> {
    fact.validate()?;
    Ok(encode_canonical(fact)?)
}

#[cfg(test)]
#[path = "drain_tests.rs"]
mod tests;
