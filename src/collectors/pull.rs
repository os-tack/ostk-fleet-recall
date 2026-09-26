//! The pull framework: one reconciliation pass of one worker collector, staged
//! page by page through the sink (ADR 0008 D8).
//!
//! A [`PullCollectorV1`] reads its provider and hands every page to the
//! [`PageStager`], which stages the page, its cursor advances, and its
//! container observations in one sink transaction (REPLAY-02), and remembers,
//! for every container, which item versions the pass holds current and
//! whether any item it read was refused. The pass returns one
//! [`ContainerOutcomeV1`] per container it listed, each with a
//! [`ListingBoundV1`] that has no default: every adapter states whether it read
//! each container to exhaustion, exactly as a CI provider states its listing
//! bound.
//!
//! After the worker drains what the pass staged, [`PageStager::settle`] decides
//! each container's completeness: complete only when its listing was read to
//! exhaustion and every item the pass holds current in it was admitted.
//! A dead-lettered, withheld, or refused item, or one the drain did not
//! admit, leaves its container partial; an audience refusal does not, since an
//! item the project may not read is outside the domain by definition. The
//! settled pass names the admitted versions it holds current, whose digest is
//! the pass manifest that the pass's `collector_observation` item and its
//! coverage receipt carry ([`super::coverage`]).

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;

use crate::error::{FleetError, Result};
use crate::memory_contracts::collected_item::{
    AudienceBasisV1, CollectionModeV1, ContainerKindV1, ItemCollectionV1, ItemLifecycleV1,
    ObjectKindV1, ProviderKindV1, TextFormatV1, VisibilityHintV1, derive_container_key,
    derive_observation_manifest,
};
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId};
use crate::memory_contracts::coverage::CoverageProofMethodV1;
use crate::memory_contracts::digest::Sha256Digest;
use crate::worker::CollectorSourceV1;

use super::audience::{AudiencePolicyV1, ProviderAudienceV1};
use super::binding::CollectorInstanceV1;
use super::cockroach::framed_sha256;
use super::draft::{
    CollectedItemDraftV1, DraftContainerV1, SealContextV1, collection_record, seal,
};
use super::redaction::CollectorRedactorV1;
use super::sink::{
    CollectedItemSink, CollectorCursorV1, CollectorDeadLetterV1, ContainerObservationV1,
    CursorAdvanceV1, DeadLetterReasonV1, KnownVersionV1, OutboxRowStateV1, StageContextV1,
    StageDraftV1, StageOutcomeV1, StagedItemV1, draft_digest,
};

/// Why a container's coverage in one pass is partial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PartialReasonV1 {
    /// The listing stopped at a bound the operator set: a file count, a page
    /// budget.
    ListingBound,
    /// The provider rate-limited the listing.
    RateLimited,
    /// Part of the listing could not be read: a directory, a page.
    Unreadable,
    /// The provider refused to list the container (not a member, a missing
    /// scope).
    ProviderRefused,
    /// An item the listing named was dead-lettered or withheld.
    ItemRefused,
    /// An item the pass staged or relied on was not admitted by the drain.
    NotAdmitted,
}

impl PartialReasonV1 {
    /// A stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListingBound => "listing_bound",
            Self::RateLimited => "rate_limited",
            Self::Unreadable => "unreadable",
            Self::ProviderRefused => "provider_refused",
            Self::ItemRefused => "item_refused",
            Self::NotAdmitted => "not_admitted",
        }
    }
}

/// How far one container's listing reached. There is deliberately no
/// default: a defaulted "complete" is exactly the assumption that claims
/// coverage of items nobody read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingBoundV1 {
    /// Read to exhaustion: the provider said there was nothing more.
    Complete,
    /// Cut short, for this reason.
    Truncated(PartialReasonV1),
}

/// What one pass read of one container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerOutcomeV1 {
    /// Its position in the pass's sorted container list, from 0.
    pub ordinal: u32,
    /// Its key; `None` for a domain of items that have no container.
    pub container_key: Option<Sha256Digest>,
    /// How far its listing reached.
    pub listing: ListingBoundV1,
}

/// What one pass is given.
#[derive(Debug, Clone, Copy)]
pub struct PullPassInputV1<'a> {
    /// The configured source.
    pub source: &'a CollectorSourceV1,
    /// The instance, pinned to its provider and scope.
    pub instance: &'a CollectorInstanceV1,
    /// The pass's sequence number for this instance, from 1.
    pub pass_seq: u64,
    /// When the pass started, by the database's clock: fixed for the pass.
    pub pass_instant: &'a CanonicalTimestamp,
    /// [`Self::pass_instant`] in microseconds: the order a collector whose
    /// provider has no order of its own gives what it reads (a document).
    pub pass_order_micros: u64,
}

/// What one pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullPassOutcomeV1 {
    /// One outcome per container the pass listed, ordinals `0..N`.
    pub containers: Vec<ContainerOutcomeV1>,
    /// Whether the pass reconciled the whole source (listed every container
    /// it covers): only a reconciliation writes coverage and the status
    /// row's `last_checked_at`.
    pub reconcile: bool,
    /// The collector's own counters, keyed by [`PullCollectorV1::counter_keys`].
    pub counters: BTreeMap<&'static str, u64>,
    /// The earliest provider time a reconciliation read from, when the
    /// collector reads a time window that may start after the sources file's
    /// `coverage_since` (a Slack `backfill_since`): the receipt's window then
    /// starts there. `None` for a pass that reads everything.
    pub window_start: Option<CanonicalTimestamp>,
}

/// One provider read by one pass.
#[async_trait]
pub trait PullCollectorV1: Send + Sync {
    /// Every counter the collector reports, each present in every report.
    fn counter_keys(&self) -> &'static [&'static str];

    /// The coverage proof method a reconciliation pass establishes.
    fn proof_method(&self) -> CoverageProofMethodV1;

    /// The provider audience of the pass's own observation item: a summary
    /// of the pass, which holds no provider text.
    fn observation_audience(&self) -> ProviderAudienceV1;

    /// Run one pass, staging every page through `stager`.
    ///
    /// # Errors
    ///
    /// Anything that stops the pass. Pages already staged stay staged; the
    /// source reports the failure and writes no coverage.
    async fn pass(
        &self,
        input: &PullPassInputV1<'_>,
        stager: &mut PageStager<'_>,
    ) -> Result<PullPassOutcomeV1>;
}

/// One item a pull read, with the provider audience of its container when the
/// collector read it.
#[derive(Debug, Clone)]
pub struct PulledItemV1 {
    /// The draft.
    pub draft: CollectedItemDraftV1,
    /// The provider audience of its container.
    pub provider_audience: Option<ProviderAudienceV1>,
}

/// One item the memory holds, to withdraw.
#[derive(Debug, Clone, Copy)]
pub struct WithdrawnItemV1<'a> {
    /// The provider kind.
    pub provider: &'a ProviderKindV1,
    /// The provider scope.
    pub provider_scope_id: &'a str,
    /// The item's object kind.
    pub object_kind: &'a ObjectKindV1,
    /// The item's external id.
    pub external_id: &'a str,
    /// The order of the observation that narrowed it: at least the order the
    /// memory holds it at, or the refusal is stale and changes nothing.
    pub order_micros: u64,
}

/// A content-free observation that withdraws an item the memory holds.
///
/// For a collector that finds an item's audience narrowed without a read
/// that could carry its content: a note that left the listed folders, an
/// issue moved into a team the collector does not admit or can no longer
/// see, the comments on an issue in the trash. The draft says the item is
/// private, so the sink refuses it on its audience whatever its container,
/// before sealing anything: it carries no text, and the refusal of an item
/// the memory holds withdraws the item for the pull's tier, so every body of
/// it is withheld at read time. An admissible read of the item at an order
/// at least as great lifts the withdrawal.
#[must_use]
pub fn withdrawal(item: &WithdrawnItemV1<'_>, container: Option<DraftContainerV1>) -> PulledItemV1 {
    PulledItemV1 {
        draft: CollectedItemDraftV1 {
            provider: item.provider.clone(),
            provider_scope_id: item.provider_scope_id.to_owned(),
            object_kind: item.object_kind.clone(),
            external_id: item.external_id.to_owned(),
            marker: None,
            order_micros: item.order_micros,
            lifecycle: ItemLifecycleV1::Live,
            container,
            thread: None,
            author: None,
            created_at: None,
            updated_at: None,
            title: None,
            sections: Vec::new(),
            text_format: TextFormatV1::Plain,
            links: Vec::new(),
            provider_url: None,
            visibility: Some(VisibilityHintV1::Private),
        },
        provider_audience: Some(ProviderAudienceV1::Restricted),
    }
}

/// What a [`PageStager`] stages under.
#[derive(Debug, Clone, Copy)]
pub struct PageStagerContextV1<'a> {
    /// The instance.
    pub instance: &'a CollectorInstanceV1,
    /// The authenticated connector principal.
    pub principal: &'a ContractId,
    /// The redactor, under the active package's guarantee.
    pub redactor: &'a CollectorRedactorV1,
    /// The instance's audience policy.
    pub policy: &'a AudiencePolicyV1,
    /// The pass's sequence number.
    pub pass_seq: u64,
    /// The pass's order in microseconds.
    pub pass_order_micros: u64,
}

/// What a pass staged, kept, and refused, in counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StagerStatsV1 {
    /// Pages staged.
    pub pages: u64,
    /// Outbox rows newly written.
    pub rows_staged: u64,
    /// Parts already staged: a primary-key no-op.
    pub rows_already_staged: u64,
    /// Items staged, newly or not.
    pub items_staged: u64,
    /// Items found unchanged and kept at their known version.
    pub items_kept: u64,
    /// Items refused at staging for a reason that leaves coverage partial.
    pub items_refused: u64,
    /// Items refused for their audience: outside the domain.
    pub items_audience_refused: u64,
    /// Dead letters for material that never became a draft.
    pub dead_letters: u64,
}

/// One version the pass holds current in one container.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TrackedVersionV1 {
    container: Option<Sha256Digest>,
    version_key: Sha256Digest,
    /// Parts that must be admitted for the version to count; empty for a
    /// version that already heads its tier.
    stage_ids: Vec<Sha256Digest>,
}

/// One container, settled after the drain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledContainerV1 {
    /// Its ordinal.
    pub ordinal: u32,
    /// Its key.
    pub container_key: Option<Sha256Digest>,
    /// Why it is partial; empty when it is complete.
    pub reasons: BTreeSet<PartialReasonV1>,
}

impl SettledContainerV1 {
    /// Whether the pass read it completely and every item it holds current
    /// there was admitted.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.reasons.is_empty()
    }
}

/// One pass, settled after the drain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassSettlementV1 {
    /// Every container, by ordinal.
    pub containers: Vec<SettledContainerV1>,
    /// The admitted versions the pass holds current, sorted.
    pub manifest: Vec<Sha256Digest>,
    /// [`derive_observation_manifest`] over [`Self::manifest`].
    pub manifest_digest: Sha256Digest,
}

impl PassSettlementV1 {
    /// Whether every container is complete.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.containers.iter().all(SettledContainerV1::complete)
    }
}

/// Stages one pass's pages and remembers what they hold. See the module
/// documentation.
#[derive(Debug)]
pub struct PageStager<'s> {
    sink: &'s CollectedItemSink,
    instance: CollectorInstanceV1,
    principal: ContractId,
    redactor: CollectorRedactorV1,
    policy: AudiencePolicyV1,
    collection: ItemCollectionV1,
    pass_seq: u64,
    pass_order_micros: u64,
    tracked: Vec<TrackedVersionV1>,
    partial: BTreeMap<Option<Sha256Digest>, BTreeSet<PartialReasonV1>>,
    stats: StagerStatsV1,
}

impl<'s> PageStager<'s> {
    /// A stager for one pass of one instance.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] when the instance cannot record a pull.
    pub fn new(sink: &'s CollectedItemSink, context: &PageStagerContextV1<'_>) -> Result<Self> {
        let collection = collection_record(
            CollectionModeV1::Pull,
            context.instance.connector_instance_id.clone(),
            None,
            None,
        )
        .map_err(|refusal| FleetError::Configuration(refusal.to_string()))?;
        Ok(Self {
            sink,
            instance: context.instance.clone(),
            principal: context.principal.clone(),
            redactor: context.redactor.clone(),
            policy: context.policy.clone(),
            collection,
            pass_seq: context.pass_seq,
            pass_order_micros: context.pass_order_micros,
            tracked: Vec::new(),
            partial: BTreeMap::new(),
            stats: StagerStatsV1::default(),
        })
    }

    /// The instance the pass stages for.
    #[must_use]
    pub const fn instance(&self) -> &CollectorInstanceV1 {
        &self.instance
    }

    /// What the pass has staged, kept, and refused so far.
    #[must_use]
    pub const fn stats(&self) -> StagerStatsV1 {
        self.stats
    }

    /// The key of one of this instance's containers.
    #[must_use]
    pub fn container_key(&self, kind: &ContainerKindV1, id: &str) -> Sha256Digest {
        derive_container_key(
            &self.instance.provider,
            self.instance.provider_scope_id.as_str(),
            kind,
            id,
        )
    }

    /// The newest version the memory knows of every item of `object_kind` in
    /// this instance's provider scope, through verified channels, by external
    /// id.
    ///
    /// # Errors
    ///
    /// As [`CollectedItemSink::known_versions`].
    pub async fn known_versions(
        &self,
        object_kind: &ObjectKindV1,
    ) -> Result<BTreeMap<String, KnownVersionV1>> {
        self.sink
            .known_versions(
                &self.instance.provider,
                self.instance.provider_scope_id.as_str(),
                object_kind,
                CollectionModeV1::Pull.trust_tier(),
            )
            .await
    }

    /// One of this instance's cursors.
    ///
    /// # Errors
    ///
    /// As [`CollectedItemSink::read_cursor`].
    pub async fn read_cursor(&self, domain_key: &str) -> Result<Option<CollectorCursorV1>> {
        self.sink
            .read_cursor(&self.instance.connector_instance_id, domain_key)
            .await
    }

    /// The content digest the sink would seal `draft` with, or `None` when
    /// sealing would refuse it (staging then dead-letters it). Sealing is
    /// pure, so this is what a collector with no version marker of its own
    /// compares with the newest known version.
    #[must_use]
    pub fn content_digest(&self, draft: &CollectedItemDraftV1) -> Option<Sha256Digest> {
        seal(
            draft,
            &SealContextV1 {
                redactor: &self.redactor,
                // The basis is sealed into the envelope, never into the
                // content digest.
                audience: AudienceBasisV1::OperatorDeclared,
                collection: &self.collection,
            },
        )
        .ok()
        .map(|sealed| sealed.content_digest)
    }

    /// Stage one page, its cursor advances, and its container observations in
    /// one sink transaction, and remember what it holds.
    ///
    /// # Errors
    ///
    /// As [`CollectedItemSink::stage`]. A refused item is not an error: it
    /// is dead-lettered, and its container is partial unless the refusal was
    /// its audience.
    pub async fn stage_page(
        &mut self,
        items: Vec<PulledItemV1>,
        cursor_advances: &[CursorAdvanceV1],
        container_observations: &[ContainerObservationV1],
    ) -> Result<StageOutcomeV1> {
        let delivery_id = self.page_delivery_id(&items);
        let containers: Vec<Option<Sha256Digest>> = items
            .iter()
            .map(|item| {
                item.draft
                    .container
                    .as_ref()
                    .map(|container| self.container_key(&container.kind, &container.id))
            })
            .collect();
        let drafts: Vec<StageDraftV1> = items
            .into_iter()
            .map(|item| StageDraftV1 {
                draft: item.draft,
                provider_audience: item.provider_audience,
                delivery_id: delivery_id.clone(),
            })
            .collect();
        let outcome = self
            .sink
            .stage(
                &drafts,
                &StageContextV1 {
                    instance: &self.instance,
                    principal: &self.principal,
                    mode: CollectionModeV1::Pull,
                    attester: None,
                    via: None,
                    redactor: &self.redactor,
                    policy: &self.policy,
                    capture_scopes: &[],
                    pass_seq: Some(self.pass_seq),
                    container_observations,
                    cursor_advances,
                    source_status: None,
                },
            )
            .await?;
        self.stats.pages += 1;
        self.stats.rows_staged += outcome.rows_staged;
        self.stats.rows_already_staged += outcome.rows_already_staged;
        for (item, container) in outcome.items.iter().zip(containers) {
            match item {
                StagedItemV1::Staged {
                    version_key,
                    stage_ids,
                    ..
                } => {
                    self.stats.items_staged += 1;
                    self.tracked.push(TrackedVersionV1 {
                        container,
                        version_key: *version_key,
                        stage_ids: stage_ids.clone(),
                    });
                }
                StagedItemV1::Refused {
                    reason: DeadLetterReasonV1::AudienceRefused,
                    ..
                } => self.stats.items_audience_refused += 1,
                StagedItemV1::Refused { .. } => {
                    self.stats.items_refused += 1;
                    self.mark_partial(container, PartialReasonV1::ItemRefused);
                }
            }
        }
        Ok(outcome)
    }

    /// Hold an unchanged item current at the version the memory already
    /// knows, in `container`. Its pending parts, if any, are drained with the
    /// pass.
    pub fn keep(&mut self, container: Option<Sha256Digest>, known: &KnownVersionV1) {
        self.stats.items_kept += 1;
        self.tracked.push(TrackedVersionV1 {
            container,
            version_key: known.version_key,
            stage_ids: known.pending.clone(),
        });
    }

    /// Record a dead letter for material in `container` that never became a
    /// draft, and leave the container partial.
    ///
    /// # Errors
    ///
    /// As [`CollectedItemSink::record_dead_letter`].
    pub async fn dead_letter(
        &mut self,
        container: Option<Sha256Digest>,
        reason: DeadLetterReasonV1,
        payload_digest: Sha256Digest,
        diagnostic: &str,
    ) -> Result<()> {
        self.sink
            .record_dead_letter(
                &self.instance.connector_instance_id,
                &self.instance.provider,
                &CollectorDeadLetterV1 {
                    mode: CollectionModeV1::Pull,
                    reason,
                    payload_digest,
                    delivery_id: None,
                    diagnostic: diagnostic.to_owned(),
                },
            )
            .await?;
        self.stats.dead_letters += 1;
        self.mark_partial(container, PartialReasonV1::ItemRefused);
        Ok(())
    }

    /// Leave `container` partial for `reason`.
    pub fn mark_partial(&mut self, container: Option<Sha256Digest>, reason: PartialReasonV1) {
        self.partial.entry(container).or_default().insert(reason);
    }

    /// Every stage id the pass staged or relies on: what the worker drains
    /// with the pass.
    #[must_use]
    pub fn stage_ids(&self) -> Vec<Sha256Digest> {
        self.tracked
            .iter()
            .flat_map(|version| version.stage_ids.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Settle the pass against the rows' states after the drain.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] when the container ordinals are not
    /// exactly `0..N`.
    pub fn settle(
        &self,
        containers: &[ContainerOutcomeV1],
        states: &BTreeMap<Sha256Digest, OutboxRowStateV1>,
    ) -> Result<PassSettlementV1> {
        settle(&self.tracked, &self.partial, containers, states)
    }

    /// The transport delivery id of one page: a digest of the instance, the
    /// pass, the page's position, and its drafts.
    fn page_delivery_id(&self, items: &[PulledItemV1]) -> Vec<u8> {
        let pass = self.pass_order_micros.to_be_bytes();
        let page = self.stats.pages.to_be_bytes();
        let digests: Vec<Sha256Digest> =
            items.iter().map(|item| draft_digest(&item.draft)).collect();
        let mut parts: Vec<&[u8]> = vec![
            self.instance.connector_instance_id.as_str().as_bytes(),
            &pass,
            &page,
        ];
        parts.extend(digests.iter().map(|digest| digest.as_bytes().as_slice()));
        framed_sha256("ostk-collector-pull-page-v1", &parts)
            .as_bytes()
            .to_vec()
    }
}

/// Settle one pass: a version counts when every part it relies on was
/// admitted; a container is complete when its listing was and nothing in it
/// was refused or left unadmitted.
fn settle(
    tracked: &[TrackedVersionV1],
    partial: &BTreeMap<Option<Sha256Digest>, BTreeSet<PartialReasonV1>>,
    containers: &[ContainerOutcomeV1],
    states: &BTreeMap<Sha256Digest, OutboxRowStateV1>,
) -> Result<PassSettlementV1> {
    let mut ordered: Vec<&ContainerOutcomeV1> = containers.iter().collect();
    ordered.sort_by_key(|container| container.ordinal);
    if ordered
        .iter()
        .zip(0_u32..)
        .any(|(container, expected)| container.ordinal != expected)
    {
        return Err(FleetError::Configuration(
            "a pull pass numbers its containers 0 to N-1, each once".to_owned(),
        ));
    }
    let mut reasons = partial.clone();
    let mut manifest = BTreeSet::new();
    for version in tracked {
        let admitted = version
            .stage_ids
            .iter()
            .all(|id| matches!(states.get(id), Some(OutboxRowStateV1::Admitted(_))));
        if admitted {
            manifest.insert(version.version_key);
        } else {
            reasons
                .entry(version.container)
                .or_default()
                .insert(PartialReasonV1::NotAdmitted);
        }
    }
    let containers = ordered
        .into_iter()
        .map(|container| {
            let mut container_reasons = reasons
                .get(&container.container_key)
                .cloned()
                .unwrap_or_default();
            if let ListingBoundV1::Truncated(reason) = container.listing {
                container_reasons.insert(reason);
            }
            SettledContainerV1 {
                ordinal: container.ordinal,
                container_key: container.container_key,
                reasons: container_reasons,
            }
        })
        .collect();
    let manifest: Vec<Sha256Digest> = manifest.into_iter().collect();
    Ok(PassSettlementV1 {
        containers,
        manifest_digest: derive_observation_manifest(&manifest),
        manifest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn tracked(container: u8, version: u8, stage_ids: &[u8]) -> TrackedVersionV1 {
        TrackedVersionV1 {
            container: Some(digest(container)),
            version_key: digest(version),
            stage_ids: stage_ids.iter().map(|id| digest(*id)).collect(),
        }
    }

    fn outcome(ordinal: u32, container: u8, listing: ListingBoundV1) -> ContainerOutcomeV1 {
        ContainerOutcomeV1 {
            ordinal,
            container_key: Some(digest(container)),
            listing,
        }
    }

    fn admitted(ids: &[u8]) -> BTreeMap<Sha256Digest, OutboxRowStateV1> {
        ids.iter()
            .map(|id| (digest(*id), OutboxRowStateV1::Admitted(digest(0xee))))
            .collect()
    }

    #[test]
    fn a_container_is_complete_when_listed_to_exhaustion_and_everything_is_admitted() {
        let settled = settle(
            &[tracked(1, 10, &[100, 101]), tracked(1, 11, &[])],
            &BTreeMap::new(),
            &[outcome(0, 1, ListingBoundV1::Complete)],
            &admitted(&[100, 101]),
        )
        .unwrap();
        assert!(settled.complete());
        assert_eq!(settled.manifest, [digest(10), digest(11)]);
        assert_eq!(
            settled.manifest_digest,
            derive_observation_manifest(&[digest(10), digest(11)])
        );
    }

    #[test]
    fn a_truncated_listing_a_refusal_or_an_unadmitted_part_leaves_its_container_partial() {
        let containers = [
            outcome(
                0,
                1,
                ListingBoundV1::Truncated(PartialReasonV1::ListingBound),
            ),
            outcome(1, 2, ListingBoundV1::Complete),
            outcome(2, 3, ListingBoundV1::Complete),
            outcome(3, 4, ListingBoundV1::Complete),
        ];
        let partial = BTreeMap::from([(
            Some(digest(3)),
            BTreeSet::from([PartialReasonV1::ItemRefused]),
        )]);
        let mut states = admitted(&[100]);
        states.insert(digest(101), OutboxRowStateV1::DeadLettered);
        let settled = settle(
            &[tracked(2, 10, &[100, 101]), tracked(4, 11, &[102])],
            &partial,
            &containers,
            &states,
        )
        .unwrap();
        let reasons: Vec<Vec<PartialReasonV1>> = settled
            .containers
            .iter()
            .map(|container| container.reasons.iter().copied().collect())
            .collect();
        assert_eq!(
            reasons,
            [
                vec![PartialReasonV1::ListingBound],
                vec![PartialReasonV1::NotAdmitted],
                vec![PartialReasonV1::ItemRefused],
                vec![PartialReasonV1::NotAdmitted],
            ]
        );
        assert!(!settled.complete());
        assert!(
            settled.manifest.is_empty(),
            "no version was wholly admitted"
        );
    }

    #[test]
    fn container_ordinals_must_be_zero_to_n() {
        for ordinals in [&[1_u32][..], &[0, 0], &[0, 2]] {
            let containers: Vec<ContainerOutcomeV1> = ordinals
                .iter()
                .map(|ordinal| outcome(*ordinal, 1, ListingBoundV1::Complete))
                .collect();
            assert!(settle(&[], &BTreeMap::new(), &containers, &BTreeMap::new()).is_err());
        }
        let shuffled = [
            outcome(1, 2, ListingBoundV1::Complete),
            outcome(0, 1, ListingBoundV1::Complete),
        ];
        let settled = settle(&[], &BTreeMap::new(), &shuffled, &BTreeMap::new()).unwrap();
        assert_eq!(settled.containers[0].container_key, Some(digest(1)));
    }

    #[test]
    fn the_manifest_is_the_same_whatever_order_the_versions_were_held() {
        let containers = [outcome(0, 1, ListingBoundV1::Complete)];
        let forward = settle(
            &[tracked(1, 10, &[]), tracked(1, 11, &[])],
            &BTreeMap::new(),
            &containers,
            &BTreeMap::new(),
        )
        .unwrap();
        let backward = settle(
            &[tracked(1, 11, &[]), tracked(1, 10, &[])],
            &BTreeMap::new(),
            &containers,
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(forward.manifest_digest, backward.manifest_digest);
    }
}
