//! Draining git facts into the accepted-event ledger, and the coverage
//! receipts that make an absence meaningful (W2-GIT, COVER-01..03).
//!
//! The drain owns no authority of its own. For each fact it builds an ingress,
//! hands it to [`admit_evidence`], seals the admitted governed content, and
//! calls [`AcceptedEventRepository::append`] — the same seam every other
//! producer uses. It classifies nothing: `Appended`, `Replayed`, and
//! `Quarantined` are the ledger's verdicts, counted and reported, never
//! reinterpreted. A re-scan of an unchanged repository therefore reports
//! `replayed` and writes no second event, because the source-fact and
//! representation identities are functions of the objects, not of the scan.
//!
//! # A quarantine is not a ledger position
//!
//! [`AppendOutcome::Quarantined`] writes a bounded dead-letter receipt and NO
//! event row; the shard head does not advance. The accepted-event id this
//! module computed for such a fact therefore names nothing in
//! `memory_evidence_events`, and one rule follows from that everywhere below:
//! **a quarantined fact contributes nothing a receipt may cite.** It is absent
//! from [`GitDrainReportV1::events`], absent from
//! [`GitDrainReportV1::admitted_keys`] -- and so from the `source_digest` and
//! `source_count` a receipt reports -- and it can never become a receipt's
//! anchor.
//!
//! A refused ref observation is stronger still: the scan then has no durable
//! newest view of that ref at all, so [`git_coverage_observation`] refuses the
//! whole scan closed with [`GitDrainError::RefObservationQuarantined`] instead
//! of quietly anchoring the receipt on an older observation that survived. A
//! receipt asserting a repo+ref range is covered while the ledger refused that
//! range's newest evidence is exactly the "trust me, I looked" claim COVER-03
//! forbids.
//!
//! That outcome is reachable, not hypothetical. A ref observation's source-fact
//! identity closes over `(repository, ref_name, target, observation_seq,
//! observed_at)` while its canonical payload also carries `previous_target` and
//! `observer` (see [`GitFactV1::immutable_revision`]), so two observations
//! agreeing on the former and disagreeing on the latter share one
//! representation key, mint different accepted-event ids, and the second is
//! quarantined as a preimage disagreement. A connector that resumes from the
//! repo+ref cursor and rebuilds its observation log without the prior target,
//! or that is reconfigured with a different observer identity, produces exactly
//! that pair.

use std::sync::Arc;

use crate::control_log::TrustedControlScope;
use crate::coverage_runtime::{CoverageCursorRowV1, SequenceIntervalV1};
use crate::evidence_ledger::{
    AcceptedEventRepository, ActiveStage4Package, AppendOutcome, ContentKeyEncryptionKey,
    EvidenceAdmissionRequestV1, GovernedContentProjection, WriterAuthorityWitness, admit_evidence,
};
use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::common::CanonicalTimestamp;
use crate::memory_contracts::common::{ContractId, HexBytes};
use crate::memory_contracts::coverage::{
    CoverageFreshnessV1, CoverageProofBasisV1, CoverageScopeV1, CoverageWindowV1,
    ProducerIdentityV1,
};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, framed_digest};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::evidence_v2::RepresentationLineageV2;
use crate::memory_contracts::identity::ResourceUri;

use super::error::{GitDrainError, GitDrainResult};
use super::fact::{GitFactV1, GitObjectId};
use super::ingress::{GitConnectorBindingV1, GitIngressClocksV1};

/// What one drain did, in the ledger's own vocabulary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitDrainReportV1 {
    /// Facts that became new accepted events.
    pub appended: u64,
    /// Facts the ledger recognised as exact replays of existing events.
    pub replayed: u64,
    /// Facts the ledger refused into quarantine.
    pub quarantined: u64,
    /// Accepted-event identity of every fact the ledger made DURABLE, in scan
    /// order. A replay contributes the identity of the event that already
    /// existed; a quarantine contributes nothing, because a quarantine writes
    /// no event row and citing its id would name a ledger position that is not
    /// in `memory_evidence_events`.
    pub events: Vec<AcceptedEventId>,
    /// Logical event key of each durably admitted fact, in the same order as
    /// [`Self::events`]. This is the exact set a coverage receipt's
    /// `source_digest` and `source_count` report, so a refused fact is never
    /// counted as observed source material.
    pub admitted_keys: Vec<HexBytes>,
    /// Accepted-event identity of the newest DURABLE ref observation drained,
    /// which is what a coverage receipt binds.
    pub ref_observation_event: Option<AcceptedEventId>,
    /// Ref observations the ledger refused into quarantine. Any non-zero count
    /// voids this scan's coverage claim: the newest view of the ref is not in
    /// the ledger, so no receipt for the scope may be minted.
    pub quarantined_ref_observations: u64,
}

impl GitDrainReportV1 {
    /// Total facts drained.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.appended + self.replayed + self.quarantined
    }

    /// Record a fact the ledger made durable (appended or replayed).
    ///
    /// Deliberately private and deliberately the ONLY writer of [`Self::events`],
    /// [`Self::admitted_keys`], and [`Self::ref_observation_event`]: the three
    /// fields a receipt reads can therefore only ever be reached from an append
    /// outcome that left an event row behind.
    fn record_durable(
        &mut self,
        fact: &GitFactV1,
        accepted_event_id: AcceptedEventId,
    ) -> GitDrainResult<()> {
        self.events.push(accepted_event_id);
        self.admitted_keys.push(fact.logical_event_key()?);
        if matches!(fact, GitFactV1::RefObservation(_)) {
            self.ref_observation_event = Some(accepted_event_id);
        }
        Ok(())
    }
}

/// Everything one drain needs, bundled so adding an input is a visible change
/// to a named contract rather than another positional argument.
pub struct GitDrainContextV1<'drain> {
    /// The active package's git connector, already resolved.
    pub binding: &'drain GitConnectorBindingV1,
    /// The active Stage-4 package admission resolves everything from.
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
    pub clocks: &'drain GitIngressClocksV1,
}

impl std::fmt::Debug for GitDrainContextV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GitDrainContextV1")
            .finish_non_exhaustive()
    }
}

/// Drain an ordered batch of git facts through the W1-EVID admission seam.
pub async fn drain_git_facts(
    context: &GitDrainContextV1<'_>,
    facts: &[GitFactV1],
) -> GitDrainResult<GitDrainReportV1> {
    let mut report = GitDrainReportV1::default();
    for fact in facts {
        let ingress = context.binding.build_ingress(fact, context.clocks, 1)?;
        let admitted = admit_evidence(
            context.active,
            EvidenceAdmissionRequestV1 {
                candidate: &ingress.candidate,
                locators: &ingress.locators,
                canonical_payload: &ingress.canonical_payload,
                delivery: ingress.delivery.clone(),
                // A git fact is rendered once. A different rendering of the
                // same fact would have to name its predecessor explicitly
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
            // recorded ONLY as a refusal count. Nothing a receipt reads is
            // touched.
            AppendOutcome::Quarantined { .. } => {
                report.quarantined += 1;
                if matches!(fact, GitFactV1::RefObservation(_)) {
                    report.quarantined_ref_observations += 1;
                }
            }
        }
    }
    Ok(report)
}

/// Deployment-supplied coverage registration for one git connector instance.
///
/// Every registry reference here is deployment configuration read from the
/// active registry, exactly like the coverage runtime's own callers supply it:
/// this connector does not mint freshness rules or proof methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCoverageBindingV1 {
    /// Connector instance the cursor and receipts are keyed to.
    pub connector_instance: ContractId,
    /// Producer identity stamped into every receipt.
    pub producer: ProducerIdentityV1,
    /// Freshness state under its registered rule.
    pub freshness: CoverageFreshnessV1,
    /// Proof basis under its registered method.
    pub proof_basis: CoverageProofBasisV1,
    /// The half-open time window this coverage domain reports on.
    pub window: CoverageWindowV1,
}

/// Build the coverage observation for one repository+ref scan.
///
/// The scan's own DURABLE ref-observation event anchors the receipt, and the
/// receipt's source manifest is [`GitDrainReportV1::admitted_keys`] rather than
/// the scan's input batch. Both come from the report and never from the caller,
/// so a fact the ledger refused cannot reach a receipt by either route.
///
/// Two refusals, in order:
///
/// 1. **A quarantined ref observation voids the scope.** The ledger refused the
///    newest view of this ref, so the range this receipt would cover has no
///    accepted evidence at its head. Falling back to an older observation that
///    did survive would mint a receipt claiming coverage the ledger declined,
///    so this fails closed with [`GitDrainError::RefObservationQuarantined`]
///    instead.
/// 2. **No ref observation at all is refused too.** A coverage claim that binds
///    no evidence is exactly the "trust me, I looked" receipt COVER-03 rejects.
pub fn git_coverage_observation(
    coverage: &GitCoverageBindingV1,
    ref_resource: ResourceUri,
    ref_target: &GitObjectId,
    target: SequenceIntervalV1,
    observed: SequenceIntervalV1,
    report: &GitDrainReportV1,
    observed_through: CanonicalTimestamp,
) -> GitDrainResult<crate::coverage_runtime::CoverageObservationV1> {
    if report.quarantined_ref_observations > 0 {
        return Err(GitDrainError::RefObservationQuarantined);
    }
    let evidence_id = report
        .ref_observation_event
        .ok_or(GitDrainError::NoRefObservation)?;
    Ok(crate::coverage_runtime::CoverageObservationV1 {
        connector_instance: coverage.connector_instance.clone(),
        producer: coverage.producer.clone(),
        scope: CoverageScopeV1 {
            scope: ref_resource,
            revision: HexBytes::new(ref_target.as_bytes().to_vec())?,
            window: coverage.window.clone(),
        },
        target,
        observed,
        freshness: coverage.freshness.clone(),
        proof_basis: coverage.proof_basis.clone(),
        source_digest: git_scan_manifest_digest(&report.admitted_keys),
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
/// [`GitDrainReportV1::admitted_keys`], and a function that accepted a raw fact
/// batch would make "digest what I scanned" as easy to write as "digest what
/// the ledger kept".
#[must_use]
pub fn git_scan_manifest_digest(keys: &[HexBytes]) -> Sha256Digest {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(keys.len() + 1);
    parts.push(b"git-scan-manifest");
    parts.extend(keys.iter().map(HexBytes::as_bytes));
    framed_digest(DigestDomain::GitScanManifestV1, &parts)
}

/// Logical event keys of an ordered fact batch.
///
/// For callers that want the manifest of an *intended* scan before anything is
/// drained. The keys a receipt reports are the report's, not these.
pub fn git_fact_manifest_keys(facts: &[GitFactV1]) -> GitDrainResult<Vec<HexBytes>> {
    facts
        .iter()
        .map(|fact| fact.logical_event_key().map_err(GitDrainError::Fact))
        .collect()
}

/// The next provider sequence a repository+ref scan should read.
///
/// The cursor's high watermark is the EXCLUSIVE end of the merged observed
/// range, so it is already the next unread sequence — adding one to it would
/// skip a sequence on every resume. An absent cursor resumes at one, because a
/// domain with no observation has covered nothing.
#[must_use]
pub fn git_resume_sequence(cursor: Option<&CoverageCursorRowV1>) -> u64 {
    cursor
        .and_then(|row| row.observed.high_watermark())
        .unwrap_or(1)
}

/// Canonical bytes of one git fact, for callers that need the exact governed
/// rendering without building a whole ingress.
pub fn git_fact_canonical_bytes(fact: &GitFactV1) -> GitDrainResult<Vec<u8>> {
    fact.validate()?;
    Ok(encode_canonical(fact)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::git::fact::{
        GIT_FACT_SCHEMA_VERSION, GitBlobSourceFactV1, GitFileModeV1, GitRefName,
        GitRefObservationFactV1, GitRepositoryIdV1,
    };
    use crate::coverage_runtime::ObservedRangeV1;
    use crate::memory_contracts::common::{CanonicalDecimal, ContractId};
    use crate::memory_contracts::coverage::CoverageCompletenessV1;
    use crate::memory_contracts::digest::Sha256Digest;
    use chrono::Utc;

    fn repository() -> GitRepositoryIdV1 {
        GitRepositoryIdV1::from_trusted_config(ContractId::new("git.repo.fixture").unwrap(), 7)
            .unwrap()
    }

    fn blob(blob_seed: u8) -> GitFactV1 {
        GitFactV1::BlobSource(GitBlobSourceFactV1 {
            schema_version: GIT_FACT_SCHEMA_VERSION,
            repository: repository(),
            commit_id: GitObjectId::parse_hex(&hex::encode([0x11; 20])).unwrap(),
            tree_id: GitObjectId::parse_hex(&hex::encode([0x22; 20])).unwrap(),
            path: HexBytes::new(b"a.txt".to_vec()).unwrap(),
            mode: GitFileModeV1::Regular,
            blob_id: GitObjectId::parse_hex(&hex::encode([blob_seed; 20])).unwrap(),
            byte_length: CanonicalDecimal::parse("3").unwrap(),
            committed_at: CanonicalTimestamp::parse("2026-08-15T12:00:00.000000000Z").unwrap(),
        })
    }

    fn test_resource_uri() -> ResourceUri {
        use std::str::FromStr as _;
        ResourceUri::from_str(&format!(
            "urn:ostk:entity:v1:provider_instance:sha256:{}",
            hex::encode([0xab_u8; 32])
        ))
        .unwrap()
    }

    fn ref_observation(target_seed: u8, previous: Option<u8>, observer: &str) -> GitFactV1 {
        GitFactV1::RefObservation(GitRefObservationFactV1 {
            schema_version: GIT_FACT_SCHEMA_VERSION,
            repository: repository(),
            ref_name: GitRefName::parse("refs/heads/main").unwrap(),
            target: GitObjectId::parse_hex(&hex::encode([target_seed; 20])).unwrap(),
            observation_seq: 1,
            observed_at: CanonicalTimestamp::parse("2026-08-15T12:30:00.000000000Z").unwrap(),
            previous_target: previous
                .map(|seed| GitObjectId::parse_hex(&hex::encode([seed; 20])).unwrap()),
            observer: ContractId::new(observer).unwrap(),
        })
    }

    fn manifest(facts: &[GitFactV1]) -> Sha256Digest {
        git_scan_manifest_digest(&git_fact_manifest_keys(facts).unwrap())
    }

    fn event(seed: u8) -> AcceptedEventId {
        AcceptedEventId::from_digest(Sha256Digest::from_bytes([seed; 32]))
    }

    fn coverage_binding() -> GitCoverageBindingV1 {
        GitCoverageBindingV1 {
            connector_instance: ContractId::new("connector.git.instance-1").unwrap(),
            producer: ProducerIdentityV1 {
                schema_version: 1,
                kind: crate::memory_contracts::coverage::ProducerKindV1::Connector,
                producer_id: ContractId::new("connector.git").unwrap(),
                version: 1,
            },
            freshness: CoverageFreshnessV1 {
                state: crate::memory_contracts::coverage::FreshnessStateV1::Current,
                freshness_rule: crate::memory_contracts::common::RegistryReferenceV1 {
                    entry_id: ContractId::new("coverage.freshness.default-rule").unwrap(),
                    version: 1,
                    entry_digest: Sha256Digest::from_bytes([0x0c; 32]),
                },
            },
            proof_basis: CoverageProofBasisV1 {
                method:
                    crate::memory_contracts::coverage::CoverageProofMethodV1::EnumeratedSnapshot,
                proof_method_registration: crate::memory_contracts::common::RegistryReferenceV1 {
                    entry_id: ContractId::new("coverage.proof.enumerated-snapshot").unwrap(),
                    version: 1,
                    entry_digest: Sha256Digest::from_bytes([0x0d; 32]),
                },
            },
            window: CoverageWindowV1 {
                window_start: CanonicalTimestamp::parse("2026-08-15T12:00:00.000000000Z").unwrap(),
                window_end: CanonicalTimestamp::parse("2026-08-15T13:00:00.000000000Z").unwrap(),
            },
        }
    }

    fn observe(
        report: &GitDrainReportV1,
    ) -> GitDrainResult<crate::coverage_runtime::CoverageObservationV1> {
        git_coverage_observation(
            &coverage_binding(),
            test_resource_uri(),
            &GitObjectId::parse_hex(&hex::encode([0xaa; 20])).unwrap(),
            SequenceIntervalV1::new(1, 3).unwrap(),
            SequenceIntervalV1::new(1, 3).unwrap(),
            report,
            CanonicalTimestamp::parse("2026-08-15T13:00:00.000000000Z").unwrap(),
        )
    }

    fn cursor(intervals: &[(u64, u64)]) -> CoverageCursorRowV1 {
        let mut observed = ObservedRangeV1::default();
        for (start, end) in intervals {
            observed
                .insert(SequenceIntervalV1::new(*start, *end).unwrap())
                .unwrap();
        }
        CoverageCursorRowV1 {
            observed,
            target: SequenceIntervalV1::new(1, 100).unwrap(),
            observation_seq: 1,
            last_completeness: CoverageCompletenessV1::Partial,
            last_receipt_id: None,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn a_manifest_digest_depends_on_the_observed_set_and_its_order() {
        let left = manifest(&[blob(0x01), blob(0x02)]);
        let right = manifest(&[blob(0x02), blob(0x01)]);
        let shorter = manifest(&[blob(0x01)]);
        assert_ne!(left, right, "order is part of the manifest");
        assert_ne!(left, shorter);
        assert_eq!(left, manifest(&[blob(0x01), blob(0x02)]));
    }

    #[test]
    fn an_empty_scan_still_has_a_stable_non_zero_manifest_digest() {
        let digest = git_scan_manifest_digest(&[]);
        assert_ne!(digest, Sha256Digest::ZERO);
        assert_eq!(digest, git_scan_manifest_digest(&[]));
    }

    #[test]
    fn an_absent_cursor_resumes_at_one() {
        assert_eq!(git_resume_sequence(None), 1);
    }

    #[test]
    fn a_cursor_resumes_after_its_high_watermark() {
        // Intervals are half-open, so [1, 10) covers 1..=9 and 10 is next.
        assert_eq!(git_resume_sequence(Some(&cursor(&[(1, 10)]))), 10);
        assert_eq!(git_resume_sequence(Some(&cursor(&[(1, 5), (20, 30)]))), 30);
        assert_eq!(git_resume_sequence(Some(&cursor(&[(1, 2)]))), 2);
    }

    #[test]
    fn a_coverage_observation_without_a_ref_event_is_refused() {
        let refused = observe(&GitDrainReportV1::default());
        assert!(matches!(refused, Err(GitDrainError::NoRefObservation)));
    }

    /// The regression guard for the receipt that could be anchored on nothing.
    ///
    /// A quarantine writes a dead-letter row and NO event row, so the accepted
    /// event id the drain computed for a refused ref observation names nothing
    /// in `memory_evidence_events`. Here the drain even has an OLDER ref
    /// observation that survived — the tempting fallback — and the receipt is
    /// still refused, because the range it would claim has no accepted evidence
    /// at its head.
    #[test]
    fn a_coverage_observation_whose_ref_observation_was_quarantined_is_refused() {
        let mut report = GitDrainReportV1 {
            appended: 1,
            quarantined: 1,
            quarantined_ref_observations: 1,
            ..GitDrainReportV1::default()
        };
        report
            .record_durable(
                &ref_observation(0xaa, None, "connector.git.instance-1"),
                event(0x31),
            )
            .unwrap();

        let refused = observe(&report);
        assert!(
            matches!(refused, Err(GitDrainError::RefObservationQuarantined)),
            "a refused ref observation voids the scope rather than falling back \
             to the older observation that survived: {refused:?}"
        );

        // And the same report without the refusal does mint a receipt, so the
        // rejection above is the guard talking and not missing scaffolding.
        report.quarantined_ref_observations = 0;
        assert_eq!(observe(&report).unwrap().evidence_id, event(0x31));
    }

    /// Two ref observations agreeing on every field the source-fact identity
    /// closes over, and disagreeing on a field only the canonical payload
    /// carries. This is the shape the ledger quarantines as a preimage
    /// disagreement, and the reason the guard above is reachable in the resume
    /// path rather than only under a fault injector.
    #[test]
    fn two_ref_observations_can_share_an_identity_while_disagreeing_on_their_bytes() {
        let rebuilt = ref_observation(0xaa, None, "connector.git.instance-1");
        let resumed = ref_observation(0xaa, Some(0x55), "connector.git.instance-1");
        let reobserved = ref_observation(0xaa, None, "connector.git.instance-2");

        for other in [&resumed, &reobserved] {
            assert_eq!(
                rebuilt.immutable_revision().unwrap(),
                other.immutable_revision().unwrap(),
                "the source-fact revision does not close over previous_target or observer"
            );
            assert_eq!(
                rebuilt.provider_object_id().unwrap(),
                other.provider_object_id().unwrap()
            );
            assert_ne!(
                rebuilt.canonical_payload().unwrap(),
                other.canonical_payload().unwrap(),
                "the governed bytes DO differ, which is what the ledger refuses"
            );
        }
    }

    /// COVER-03's source manifest reports what the ledger kept, not what the
    /// scan read: a fact the ledger refused is neither digested nor counted.
    #[test]
    fn a_receipt_manifest_counts_only_the_facts_the_ledger_kept() {
        let kept = [
            blob(0x01),
            ref_observation(0xaa, None, "connector.git.instance-1"),
        ];
        let refused = blob(0x02);

        let mut report = GitDrainReportV1 {
            appended: 2,
            quarantined: 1,
            ..GitDrainReportV1::default()
        };
        report.record_durable(&kept[0], event(0x41)).unwrap();
        report.record_durable(&kept[1], event(0x42)).unwrap();

        let observation = observe(&report).unwrap();
        assert_eq!(observation.source_count, 2);
        assert_eq!(observation.source_digest, manifest(&kept));
        assert_ne!(
            observation.source_digest,
            manifest(&[kept[0].clone(), kept[1].clone(), refused]),
            "the refused fact must not appear in the manifest"
        );
    }

    /// `record_durable` is the only writer of the three fields a receipt reads,
    /// and it is reached only from an append outcome that left an event row.
    #[test]
    fn only_a_durable_fact_reaches_the_fields_a_receipt_reads() {
        let mut report = GitDrainReportV1::default();
        report.record_durable(&blob(0x01), event(0x51)).unwrap();
        assert_eq!(
            report.ref_observation_event, None,
            "a blob is not a ref view"
        );

        report
            .record_durable(
                &ref_observation(0xaa, None, "connector.git.instance-1"),
                event(0x52),
            )
            .unwrap();
        assert_eq!(report.ref_observation_event, Some(event(0x52)));
        assert_eq!(report.events, vec![event(0x51), event(0x52)]);
        assert_eq!(report.admitted_keys.len(), 2);
    }

    #[test]
    fn a_report_totals_every_ledger_verdict() {
        let report = GitDrainReportV1 {
            appended: 3,
            replayed: 2,
            quarantined: 1,
            quarantined_ref_observations: 1,
            ..GitDrainReportV1::default()
        };
        assert_eq!(report.total(), 6);
    }
}
