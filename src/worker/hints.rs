//! The collect step's ingress hints (ADR 0008 D12).
//!
//! Before each collector's pass, the step reads that instance's due hints
//! (at most [`MAX_HINTS_PER_TICK`], oldest first) and settles each one in the
//! transaction that stages what it caused, which is the queue's
//! acknowledgement:
//!
//! * **Upsert.** The adapter's fetcher re-reads the object through the
//!   collector's own credential and audience rules
//!   ([`crate::collectors::pull::ObjectFetcherV1`]), and what it read is
//!   staged in pull mode, exactly as a pass would stage it. An object that is
//!   gone, or outside what the instance admits, settles the hint with
//!   nothing staged.
//! * **Delete.** An item the memory already holds gets a push-mode tombstone
//!   at the provider's signed event time, in the container and thread its
//!   head records; one the memory never held, or holds as a tombstone,
//!   settles the hint with nothing staged. A deletion never mints an item.
//! * **Failure.** A provider failure (a rate limit, a failed request, a
//!   refused credential) backs the hint off, `60 s * 2^n`; the eighth makes
//!   it `dead` with a `retry_exhausted` dead letter, which
//!   `collect retry --delivery` reopens. A staged item refused as
//!   `clock_ahead` settles nothing and counts as a failure, so it is read
//!   again.
//!
//! What a hint staged is drained at once, so the pass that follows sees it
//! as the memory's version. A hint never establishes coverage: its rows are
//! no pass's, and the pass's settlement never counts them.

use crate::collectors::draft::{CollectedItemDraftV1, DraftContainerV1, DraftThreadV1};
use crate::collectors::http::scrub_diagnostic;
use crate::collectors::ingress::HintKindV1;
use crate::collectors::pull::{
    FetchedObjectV1, HintedObjectV1, ObjectFetcherV1, PageStager, PageStagerContextV1,
    PullPassInputV1,
};
use crate::collectors::sink::{
    CollectedDrainContextV1, CollectedDrainReportV1, CollectedItemSink, DeadLetterReasonV1,
    HintFailureV1, HintSettlementV1, PendingHintV1, StageContextV1, StageDraftV1, StageOutcomeV1,
    StagedItemV1,
};
use crate::memory_contracts::collected_item::{
    CollectionModeV1, ContainerKindV1, ItemLifecycleV1, ObjectKindV1, TextFormatV1,
};
use crate::memory_contracts::digest::Sha256Digest;

use super::WorkerCountersV1;
use super::ingest::describe;
use super::sources::CollectorSourceV1;

/// Hints one collector reads at most per tick.
pub const MAX_HINTS_PER_TICK: u32 = 256;

/// What a collector that takes webhooks reports about its hints, beside its
/// pass's counters, once the schema has the hint queue.
pub(super) const HINT_COUNTERS: [&str; 6] = [
    "hints_read",
    "hints_settled",
    "hints_staged",
    "hints_tombstones",
    "hints_retried",
    "hints_dead",
];

/// Everything one collector's hints are read under: the pass's own binding.
pub(super) struct HintRunV1<'a> {
    pub sink: &'a CollectedItemSink,
    pub drain: &'a CollectedDrainContextV1<'a>,
    pub source: &'a CollectorSourceV1,
    pub stager: PageStagerContextV1<'a>,
    pub input: &'a PullPassInputV1<'a>,
    pub fetcher: Option<&'a dyn ObjectFetcherV1>,
}

/// What one hint came to.
enum HintEndV1 {
    /// Settled; these rows were staged (possibly none).
    Settled {
        stage_ids: Vec<Sha256Digest>,
        tombstone: bool,
    },
    /// Not settled: counted as a failed fetch.
    Failed(String),
}

fn bump(counters: &mut WorkerCountersV1, key: &'static str, by: u64) {
    *counters.entry(key).or_insert(0) += by;
}

/// The stage ids a staging call staged, and whether it settled without an
/// item refused as `clock_ahead`.
fn staged(outcome: &StageOutcomeV1, tombstone: bool) -> HintEndV1 {
    if outcome
        .refused
        .contains_key(&DeadLetterReasonV1::ClockAhead)
    {
        return HintEndV1::Failed(
            "the provider's clock is ahead of the observation; the hint is read again".to_owned(),
        );
    }
    HintEndV1::Settled {
        stage_ids: outcome
            .items
            .iter()
            .flat_map(|item| match item {
                StagedItemV1::Staged { stage_ids, .. } => stage_ids.clone(),
                StagedItemV1::Refused { .. } => Vec::new(),
            })
            .collect(),
        tombstone,
    }
}

impl HintRunV1<'_> {
    fn settlement(&self, hint: &PendingHintV1) -> HintSettlementV1 {
        HintSettlementV1 {
            instance: self.stager.instance.connector_instance_id.clone(),
            delivery_key: hint.delivery_key,
        }
    }

    /// Settle a hint that caused nothing.
    async fn nothing(&self, hint: &PendingHintV1) -> std::result::Result<HintEndV1, String> {
        self.sink
            .settle_hint(&self.settlement(hint))
            .await
            .map_err(describe)?;
        Ok(HintEndV1::Settled {
            stage_ids: Vec::new(),
            tombstone: false,
        })
    }

    /// A deletion: a push-mode tombstone for an item the memory holds.
    async fn delete(&self, hint: &PendingHintV1) -> std::result::Result<HintEndV1, String> {
        let instance = self.stager.instance;
        let Ok(object_kind) = ObjectKindV1::new(hint.object_kind.clone()) else {
            return self.nothing(hint).await;
        };
        let target = self
            .sink
            .hint_target(
                &instance.provider,
                instance.provider_scope_id.as_str(),
                &object_kind,
                &hint.external_id,
            )
            .await
            .map_err(describe)?;
        let Some(target) = target.filter(|target| !target.lifecycle.is_tombstone()) else {
            return self.nothing(hint).await;
        };
        let Some(order_micros) = hint
            .provider_event_at
            .and_then(|at| u64::try_from(at.timestamp_micros()).ok())
        else {
            return Ok(HintEndV1::Failed(
                "a deletion hint names no provider event time".to_owned(),
            ));
        };
        let container = match target.container {
            Some((kind, id)) => Some(DraftContainerV1 {
                kind: ContainerKindV1::new(kind).map_err(describe)?,
                id,
                label: None,
            }),
            None => None,
        };
        let draft = CollectedItemDraftV1 {
            provider: instance.provider.clone(),
            provider_scope_id: instance.provider_scope_id.as_str().to_owned(),
            object_kind,
            external_id: hint.external_id.clone(),
            marker: None,
            order_micros,
            lifecycle: ItemLifecycleV1::Deleted,
            container,
            thread: target
                .thread_root
                .filter(|root| *root != hint.external_id)
                .map(|root| DraftThreadV1 {
                    parent_external_id: Some(root.clone()),
                    root_external_id: root,
                }),
            author: None,
            created_at: None,
            updated_at: None,
            title: None,
            sections: Vec::new(),
            text_format: TextFormatV1::Plain,
            links: Vec::new(),
            provider_url: None,
            visibility: None,
        };
        let outcome = self
            .sink
            .stage_settling(
                &[StageDraftV1 {
                    draft,
                    provider_audience: None,
                    delivery_id: hint.delivery_key.as_bytes().to_vec(),
                }],
                &StageContextV1 {
                    instance,
                    principal: self.stager.principal,
                    mode: CollectionModeV1::Push,
                    attester: None,
                    via: None,
                    redactor: self.stager.redactor,
                    policy: self.stager.policy,
                    capture_scopes: &[],
                    pass_seq: None,
                    container_observations: &[],
                    cursor_advances: &[],
                    source_status: None,
                },
                &[self.settlement(hint)],
            )
            .await
            .map_err(describe)?;
        Ok(staged(&outcome, true))
    }

    /// An upsert: re-read the object and stage what the read found.
    async fn upsert(
        &self,
        hint: &PendingHintV1,
        stager: &mut PageStager<'_>,
    ) -> std::result::Result<HintEndV1, String> {
        let Some(fetcher) = self.fetcher else {
            return Ok(HintEndV1::Failed(format!(
                "provider {} re-reads no hinted object",
                self.source.provider
            )));
        };
        let read = fetcher
            .fetch(
                self.input,
                &HintedObjectV1 {
                    object_kind: &hint.object_kind,
                    external_id: &hint.external_id,
                    container_id: hint.container_id.as_deref(),
                },
                stager,
            )
            .await
            .map_err(describe)?;
        match read {
            FetchedObjectV1::Nothing(_) => self.nothing(hint).await,
            FetchedObjectV1::Failed(message) => Ok(HintEndV1::Failed(scrub_diagnostic(&message))),
            FetchedObjectV1::Stage {
                items,
                observations,
            } => {
                let outcome = stager
                    .stage_hint(items, &observations, &self.settlement(hint))
                    .await
                    .map_err(describe)?;
                Ok(staged(&outcome, false))
            }
        }
    }

    /// Read and settle the instance's due hints; whether any staged a row.
    pub(super) async fn run(
        &self,
        counters: &mut WorkerCountersV1,
        total: &mut CollectedDrainReportV1,
    ) -> std::result::Result<bool, String> {
        let instance = &self.stager.instance.connector_instance_id;
        let pending = self
            .sink
            .pending_hints(instance, MAX_HINTS_PER_TICK)
            .await
            .map_err(describe)?;
        let mut stager = PageStager::new(self.sink, &self.stager).map_err(describe)?;
        let mut changed = false;
        for hint in pending {
            bump(counters, "hints_read", 1);
            let end = match hint.kind {
                HintKindV1::Delete => self.delete(&hint).await?,
                HintKindV1::Upsert => self.upsert(&hint, &mut stager).await?,
            };
            match end {
                HintEndV1::Settled {
                    stage_ids,
                    tombstone,
                } => {
                    bump(counters, "hints_settled", 1);
                    if stage_ids.is_empty() {
                        continue;
                    }
                    changed = true;
                    bump(
                        counters,
                        if tombstone {
                            "hints_tombstones"
                        } else {
                            "hints_staged"
                        },
                        1,
                    );
                    let drained = self
                        .sink
                        .drain_stage_ids(self.drain, &stage_ids)
                        .await
                        .map_err(describe)?;
                    bump(counters, "appended", drained.appended);
                    bump(counters, "replayed", drained.replayed);
                    super::collect::merge(total, &drained);
                }
                HintEndV1::Failed(error) => {
                    match self
                        .sink
                        .hint_failed(instance, &hint, &error)
                        .await
                        .map_err(describe)?
                    {
                        HintFailureV1::Retried { .. } => bump(counters, "hints_retried", 1),
                        HintFailureV1::Dead => bump(counters, "hints_dead", 1),
                        HintFailureV1::Gone => {}
                    }
                }
            }
        }
        Ok(changed)
    }
}
