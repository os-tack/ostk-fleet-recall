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
    /// Accepted-event identity of every fact drained, in scan order. A replay
    /// contributes the identity of the event that already existed.
    pub events: Vec<AcceptedEventId>,
    /// Accepted-event identity of the newest ref observation drained, which is
    /// what a coverage receipt binds.
    pub ref_observation_event: Option<AcceptedEventId>,
}

impl GitDrainReportV1 {
    /// Total facts drained.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.appended + self.replayed + self.quarantined
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
            AppendOutcome::Appended { .. } => report.appended += 1,
            AppendOutcome::Replayed { .. } => report.replayed += 1,
            AppendOutcome::Quarantined { .. } => report.quarantined += 1,
        }
        report.events.push(accepted_event_id);
        if matches!(fact, GitFactV1::RefObservation(_)) {
            report.ref_observation_event = Some(accepted_event_id);
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
/// The scan's own accepted ref-observation event anchors the receipt: a
/// coverage claim that binds no evidence is exactly the "trust me, I looked"
/// receipt COVER-03 rejects, so a drain that produced no ref observation cannot
/// produce a receipt either.
#[allow(clippy::too_many_arguments)] // Every argument is a distinct proven input; bundling them would hide which are caller-supplied.
pub fn git_coverage_observation(
    coverage: &GitCoverageBindingV1,
    ref_resource: ResourceUri,
    ref_target: &GitObjectId,
    target: SequenceIntervalV1,
    observed: SequenceIntervalV1,
    facts: &[GitFactV1],
    report: &GitDrainReportV1,
    observed_through: CanonicalTimestamp,
) -> GitDrainResult<crate::coverage_runtime::CoverageObservationV1> {
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
        source_digest: git_scan_manifest_digest(facts)?,
        source_count: u32::try_from(facts.len()).unwrap_or(u32::MAX),
        evidence_id,
        observed_through,
    })
}

/// Content-addressed digest of exactly which facts a scan observed, in order.
///
/// Framed over each fact's logical event key rather than its payload bytes, so
/// the manifest identifies the observed *set* without restating the governed
/// content the ledger already stores.
pub fn git_scan_manifest_digest(facts: &[GitFactV1]) -> GitDrainResult<Sha256Digest> {
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(facts.len() + 1);
    keys.push(b"git-scan-manifest".to_vec());
    for fact in facts {
        keys.push(fact.logical_event_key()?.as_bytes().to_vec());
    }
    let parts: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    Ok(framed_digest(DigestDomain::GitScanManifestV1, &parts))
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
        GIT_FACT_SCHEMA_VERSION, GitBlobSourceFactV1, GitFileModeV1, GitRepositoryIdV1,
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
        let left = git_scan_manifest_digest(&[blob(0x01), blob(0x02)]).unwrap();
        let right = git_scan_manifest_digest(&[blob(0x02), blob(0x01)]).unwrap();
        let shorter = git_scan_manifest_digest(&[blob(0x01)]).unwrap();
        assert_ne!(left, right, "order is part of the manifest");
        assert_ne!(left, shorter);
        assert_eq!(
            left,
            git_scan_manifest_digest(&[blob(0x01), blob(0x02)]).unwrap()
        );
    }

    #[test]
    fn an_empty_scan_still_has_a_stable_non_zero_manifest_digest() {
        let digest = git_scan_manifest_digest(&[]).unwrap();
        assert_ne!(digest, Sha256Digest::ZERO);
        assert_eq!(digest, git_scan_manifest_digest(&[]).unwrap());
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
        let coverage = GitCoverageBindingV1 {
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
        };
        let refused = git_coverage_observation(
            &coverage,
            test_resource_uri(),
            &GitObjectId::parse_hex(&hex::encode([0xaa; 20])).unwrap(),
            SequenceIntervalV1::new(1, 3).unwrap(),
            SequenceIntervalV1::new(1, 3).unwrap(),
            &[blob(0x01)],
            &GitDrainReportV1::default(),
            CanonicalTimestamp::parse("2026-08-15T13:00:00.000000000Z").unwrap(),
        );
        assert!(matches!(refused, Err(GitDrainError::NoRefObservation)));
    }

    #[test]
    fn a_report_totals_every_ledger_verdict() {
        let report = GitDrainReportV1 {
            appended: 3,
            replayed: 2,
            quarantined: 1,
            events: Vec::new(),
            ref_observation_event: None,
        };
        assert_eq!(report.total(), 6);
    }
}
