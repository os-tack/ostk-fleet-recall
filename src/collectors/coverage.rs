//! Coverage from pull passes (ADR 0008 D8).
//!
//! Only a reconciliation pass writes coverage, and only through its own
//! `collector_observation` item: an item admitted through the same sink whose
//! external id is the collector instance, whose version marker is
//! `m:<manifest digest>`, and whose text is a rendered summary of the pass
//! (how many items it holds current, which containers it read completely). The
//! summary is a function of the manifest and the container outcomes only, so
//! an unchanged pass re-stages the same version (a primary-key no-op) and its
//! receipt cites the same event.
//!
//! One pass is one coverage domain of the instance's coverage runtime:
//!
//! * scope: the provider-scope entity URI; revision: the manifest digest;
//!   window: `[coverage_since, observed_through)`;
//! * target: `[0, N + 1)`, where ordinals `0..N` are the pass's containers in
//!   sorted order and ordinal `N` is the pass itself;
//! * observed: the pass's ordinal, which its admitted observation item
//!   witnesses, and every container read to exhaustion whose items were all
//!   admitted.
//!
//! The pass's own ordinal is what lets a pass that completed no container
//! still record a receipt: an observation cannot be empty, and without a new
//! receipt the newest cursor would still be an earlier pass's complete one.
//! With it, the newest cursor of the instance is always the latest
//! reconciliation's, and it is complete exactly when every container was.

use std::fmt::Write as _;

use sha2::{Digest as _, Sha256};

use crate::coverage_runtime::{CoverageObservationV1, ObservedRangeError, SequenceIntervalV1};
use crate::error::{FleetError, Result};
use crate::memory_contracts::collected_item::{ItemLifecycleV1, ObjectKindV1, TextFormatV1};
use crate::memory_contracts::common::{
    CanonicalTimestamp, ContractId, HexBytes, RegistryReferenceV1,
};
use crate::memory_contracts::coverage::{
    CoverageFreshnessV1, CoverageProofBasisV1, CoverageProofMethodV1, CoverageScopeV1,
    CoverageWindowV1, FreshnessStateV1, ProducerIdentityV1, ProducerKindV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::identity::ResourceUri;

use super::binding::CollectorInstanceV1;
use super::draft::{CollectedItemDraftV1, DraftSectionV1};
use super::pull::PassSettlementV1;
use super::sink::CursorAdvanceV1;

/// The object kind of a pass's own observation item. Item recall never
/// returns it.
pub const OBSERVATION_OBJECT_KIND: &str = "collector_observation";

/// The cursor domain a pull collector's passes are counted under.
pub const PASS_CURSOR_DOMAIN: &str = "collector.pass";

/// The freshness rule every collector receipt names: the worker's.
pub const COLLECTOR_FRESHNESS_LABEL: &str = "coverage.freshness.worker_tick";

/// The proof method of a complete enumeration (a documents root, an import).
pub const ENUMERATED_SNAPSHOT_LABEL: &str = "coverage.proof.enumerated_snapshot";

/// The proof method of a provider query read to its end (an API listing).
pub const CLOSED_PROVIDER_QUERY_LABEL: &str = "coverage.proof.closed_provider_query";

/// A registry reference naming a compile-time label; its digest is the
/// SHA-256 of the label, because no registered entry exists to digest (ADR
/// 0006 D2). The same rule as the worker's own receipts.
#[must_use]
pub fn label_reference(label: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(label)
            .unwrap_or_else(|_| unreachable!("coverage labels are contract ids")),
        version: 1,
        entry_digest: Sha256Digest::from_bytes(Sha256::digest(label.as_bytes()).into()),
    }
}

/// The label of a proof method.
#[must_use]
pub const fn proof_label(method: CoverageProofMethodV1) -> &'static str {
    match method {
        CoverageProofMethodV1::EnumeratedSnapshot => ENUMERATED_SNAPSHOT_LABEL,
        CoverageProofMethodV1::ClosedProviderQuery => CLOSED_PROVIDER_QUERY_LABEL,
        CoverageProofMethodV1::ClosedCursorInterval => "coverage.proof.closed_cursor_interval",
        CoverageProofMethodV1::ExhaustiveAstWalk => "coverage.proof.exhaustive_ast_walk",
    }
}

/// The observation item's version marker: `m:<manifest digest>`.
#[must_use]
pub fn observation_marker(settlement: &PassSettlementV1) -> String {
    format!("m:{}", settlement.manifest_digest)
}

/// The rendered summary a pass's observation item carries.
///
/// It says which instance read which provider scope, how many items the pass
/// holds current, and which containers were partial and why. It names no
/// item and quotes no provider text.
#[must_use]
pub fn observation_text(instance: &CollectorInstanceV1, settlement: &PassSettlementV1) -> String {
    let complete = settlement
        .containers
        .iter()
        .filter(|container| container.complete())
        .count();
    let mut text = format!(
        "collector pass of {} over {} scope {}: {} current items; {} of {} containers read \
         completely",
        instance.connector_instance_id,
        instance.provider,
        instance.provider_scope_id,
        settlement.manifest.len(),
        complete,
        settlement.containers.len()
    );
    for container in &settlement.containers {
        if container.complete() {
            continue;
        }
        let reasons: Vec<&str> = container
            .reasons
            .iter()
            .map(|reason| reason.as_str())
            .collect();
        // Writing to a String cannot fail.
        let _ = write!(
            text,
            "\ncontainer {} partial: {}",
            container.ordinal,
            reasons.join(", ")
        );
    }
    text.push('\n');
    text
}

/// The pass's observation item, ordered at the pass.
///
/// # Errors
///
/// None in practice: the object kind is a valid token.
pub fn observation_draft(
    instance: &CollectorInstanceV1,
    settlement: &PassSettlementV1,
    pass_order_micros: u64,
) -> Result<CollectedItemDraftV1> {
    Ok(CollectedItemDraftV1 {
        provider: instance.provider.clone(),
        provider_scope_id: instance.provider_scope_id.as_str().to_owned(),
        object_kind: ObjectKindV1::new(OBSERVATION_OBJECT_KIND)?,
        external_id: instance.connector_instance_id.as_str().to_owned(),
        marker: Some(observation_marker(settlement)),
        order_micros: pass_order_micros,
        lifecycle: ItemLifecycleV1::Live,
        container: None,
        thread: None,
        author: None,
        created_at: None,
        updated_at: None,
        title: None,
        sections: vec![DraftSectionV1::whole(observation_text(
            instance, settlement,
        ))],
        text_format: TextFormatV1::Plain,
        links: Vec::new(),
        provider_url: None,
        visibility: None,
    })
}

/// The pass cursor's advance: the pass number, its order, and its manifest
/// digest followed by one byte, 1 when every container was complete.
#[must_use]
pub fn pass_cursor(
    settlement: &PassSettlementV1,
    pass_seq: u64,
    pass_order_micros: u64,
) -> CursorAdvanceV1 {
    let mut cursor_state = settlement.manifest_digest.as_bytes().to_vec();
    cursor_state.push(u8::from(settlement.complete()));
    CursorAdvanceV1 {
        domain_key: PASS_CURSOR_DOMAIN.to_owned(),
        cursor_state,
        high_water_order: Some(pass_order_micros),
        pass_seq,
    }
}

/// The pass's coverage target and the maximal observed runs inside it. See
/// the module documentation.
///
/// # Errors
///
/// Never for a settled pass; the interval constructors refuse an empty range.
pub fn coverage_ranges(
    settlement: &PassSettlementV1,
) -> std::result::Result<(SequenceIntervalV1, Vec<SequenceIntervalV1>), ObservedRangeError> {
    let containers = u64::try_from(settlement.containers.len()).unwrap_or(u64::MAX - 1);
    let target = SequenceIntervalV1::new(0, containers + 1)?;
    // Ordinal N, the pass itself, is always observed.
    let observed: Vec<bool> = settlement
        .containers
        .iter()
        .map(super::pull::SettledContainerV1::complete)
        .chain(std::iter::once(true))
        .collect();
    let mut runs = Vec::new();
    let mut start: Option<u64> = None;
    for (ordinal, seen) in (0_u64..).zip(observed.iter().copied().chain(std::iter::once(false))) {
        match (seen, start) {
            (true, None) => start = Some(ordinal),
            (false, Some(first)) => {
                runs.push(SequenceIntervalV1::new(first, ordinal)?);
                start = None;
            }
            _ => {}
        }
    }
    Ok((target, runs))
}

/// Everything a pass's receipt is bound to besides the settlement.
#[derive(Debug, Clone)]
pub struct PassCoverageV1<'a> {
    /// The collector instance: the receipt's key.
    pub instance: &'a ContractId,
    /// The connector principal that produced the pass.
    pub principal: &'a ContractId,
    /// The provider-scope entity URI.
    pub scope: ResourceUri,
    /// Start of the covered window: the sources file's `coverage_since`.
    pub window_start: CanonicalTimestamp,
    /// When the pass's reading ended: the window's end.
    pub observed_through: CanonicalTimestamp,
    /// The collector's proof method.
    pub proof_method: CoverageProofMethodV1,
    /// The pass's admitted observation item.
    pub evidence_id: AcceptedEventId,
}

/// One coverage observation per observed run of the pass's domain.
///
/// # Errors
///
/// [`FleetError::Configuration`] for a manifest digest that is not a hex
/// coordinate or ranges the runtime refuses.
pub fn coverage_observations(
    coverage: &PassCoverageV1<'_>,
    settlement: &PassSettlementV1,
) -> Result<Vec<CoverageObservationV1>> {
    let (target, runs) = coverage_ranges(settlement)
        .map_err(|error| FleetError::Configuration(format!("the pass's coverage: {error}")))?;
    let scope = CoverageScopeV1 {
        scope: coverage.scope.clone(),
        revision: HexBytes::new(settlement.manifest_digest.as_bytes().to_vec())?,
        window: CoverageWindowV1 {
            window_start: coverage.window_start.clone(),
            window_end: coverage.observed_through.clone(),
        },
    };
    let producer = ProducerIdentityV1 {
        schema_version: 1,
        kind: ProducerKindV1::Connector,
        producer_id: coverage.principal.clone(),
        version: 1,
    };
    let source_count = u32::try_from(settlement.manifest.len()).unwrap_or(u32::MAX);
    Ok(runs
        .into_iter()
        .map(|observed| CoverageObservationV1 {
            connector_instance: coverage.instance.clone(),
            producer: producer.clone(),
            scope: scope.clone(),
            target,
            observed,
            freshness: CoverageFreshnessV1 {
                state: FreshnessStateV1::Current,
                freshness_rule: label_reference(COLLECTOR_FRESHNESS_LABEL),
            },
            proof_basis: CoverageProofBasisV1 {
                method: coverage.proof_method,
                proof_method_registration: label_reference(proof_label(coverage.proof_method)),
            },
            source_digest: settlement.manifest_digest,
            source_count,
            evidence_id: coverage.evidence_id,
            observed_through: coverage.observed_through.clone(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::collectors::pull::{PartialReasonV1, SettledContainerV1};
    use crate::memory_contracts::collected_item::{
        BoundedTextV1, ProviderKindV1, derive_observation_manifest,
    };

    fn settlement(complete: &[bool]) -> PassSettlementV1 {
        let manifest = vec![Sha256Digest::from_bytes([3; 32])];
        PassSettlementV1 {
            containers: (0_u32..)
                .zip(complete)
                .map(|(ordinal, complete)| SettledContainerV1 {
                    ordinal,
                    container_key: None,
                    reasons: if *complete {
                        BTreeSet::new()
                    } else {
                        BTreeSet::from([PartialReasonV1::ListingBound])
                    },
                })
                .collect(),
            manifest_digest: derive_observation_manifest(&manifest),
            manifest,
        }
    }

    fn ranges(complete: &[bool]) -> (Vec<u64>, Vec<[u64; 2]>) {
        let (target, runs) = coverage_ranges(&settlement(complete)).unwrap();
        (
            vec![target.start, target.end],
            runs.iter().map(|run| [run.start, run.end]).collect(),
        )
    }

    #[test]
    fn a_complete_pass_observes_its_whole_target_in_one_run() {
        assert_eq!(ranges(&[true]), (vec![0, 2], vec![[0, 2]]));
        assert_eq!(ranges(&[true, true, true]), (vec![0, 4], vec![[0, 4]]));
        // A pass over no container still observes itself.
        assert_eq!(ranges(&[]), (vec![0, 1], vec![[0, 1]]));
    }

    #[test]
    fn a_partial_pass_still_observes_itself_and_its_complete_containers() {
        assert_eq!(ranges(&[false]), (vec![0, 2], vec![[1, 2]]));
        assert_eq!(
            ranges(&[true, false, true, true]),
            (vec![0, 5], vec![[0, 1], [2, 5]])
        );
        assert_eq!(ranges(&[false, false]), (vec![0, 3], vec![[2, 3]]));
    }

    #[test]
    fn the_observation_is_a_function_of_the_manifest_and_the_outcomes() {
        let instance = CollectorInstanceV1 {
            connector_instance_id: ContractId::new("docs.specs").unwrap(),
            provider: ProviderKindV1::new("docs").unwrap(),
            provider_scope_id: BoundedTextV1::new("specs").unwrap(),
        };
        let complete = settlement(&[true]);
        let first = observation_draft(&instance, &complete, 1_000).unwrap();
        let later = observation_draft(&instance, &complete, 2_000).unwrap();
        assert_eq!(first.marker, later.marker);
        assert!(first.sections == later.sections);
        assert_eq!(
            first.marker.as_deref(),
            Some(format!("m:{}", complete.manifest_digest).as_str())
        );
        assert_eq!(first.external_id, "docs.specs");
        assert_eq!(first.object_kind.as_str(), OBSERVATION_OBJECT_KIND);

        let partial = observation_draft(&instance, &settlement(&[false]), 1_000).unwrap();
        assert!(partial.sections != first.sections);
        assert!(
            partial.sections[0]
                .text
                .contains("container 0 partial: listing_bound")
        );

        let cursor = pass_cursor(&complete, 4, 1_000);
        assert_eq!(cursor.domain_key, PASS_CURSOR_DOMAIN);
        assert_eq!(cursor.cursor_state.len(), 33);
        assert_eq!(cursor.cursor_state[32], 1);
        assert_eq!(
            pass_cursor(&settlement(&[false]), 4, 1_000).cursor_state[32],
            0
        );
    }

    #[test]
    fn every_proof_label_is_a_registered_reference_shape() {
        for method in [
            CoverageProofMethodV1::EnumeratedSnapshot,
            CoverageProofMethodV1::ClosedProviderQuery,
            CoverageProofMethodV1::ClosedCursorInterval,
            CoverageProofMethodV1::ExhaustiveAstWalk,
        ] {
            let reference = label_reference(proof_label(method));
            assert!(reference.validate().is_ok());
        }
        assert_eq!(
            label_reference(COLLECTOR_FRESHNESS_LABEL),
            label_reference(crate::worker::COVERAGE_FRESHNESS_LABEL)
        );
        assert_eq!(
            ENUMERATED_SNAPSHOT_LABEL,
            crate::worker::COVERAGE_PROOF_LABEL
        );
    }
}
