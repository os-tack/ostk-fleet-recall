//! Re-reading the Granola note an ingress hint names (ADR 0008 D12).
//!
//! A hint names a note. The fetch reads it exactly as a pass's sweep reads
//! one note ([`super::GranolaPassV1`]): `notes/{id}` (with its transcript
//! when the instance reads transcripts, paged when it is too long for one
//! answer), placed in the listed folder with the least id or the key's
//! workspace, its summary and transcript drafted, an unchanged item kept as
//! it is, and a note outside the listed folders withdrawing what the memory
//! holds of it. A `404` stages nothing and tombstones nothing: only two
//! complete listings without the note do. A rate limit, a failed request, or
//! a refused key backs the hint off.

use std::collections::BTreeMap;

use async_trait::async_trait;

use crate::error::{FleetError, Result};
use crate::memory_contracts::collected_item::{ObjectKindV1, ProviderKindV1};

use super::render::{GRANOLA_PROVIDER, SUMMARY_OBJECT_KIND, TRANSCRIPT_OBJECT_KIND, is_note_id};
use super::{GranolaPassV1, GranolaPullV1, NoteEndV1, NotesCursorV1};
use crate::collectors::audience::ProviderAudienceV1;
use crate::collectors::pull::{
    FetchedObjectV1, HintedObjectV1, ObjectFetcherV1, PageStager, PullPassInputV1,
};
use crate::collectors::sink::ContainerObservationV1;

/// Requests one hinted note may take: the note, a retry without its
/// transcript, and two transcript pages.
const HINT_REQUEST_BUDGET: u32 = 4;

/// Re-reads hinted notes of one configured key.
#[derive(Debug)]
pub struct GranolaFetchV1 {
    collector: GranolaPullV1,
}

impl GranolaFetchV1 {
    /// A fetcher reading as `collector` reads.
    #[must_use]
    pub const fn new(collector: GranolaPullV1) -> Self {
        Self { collector }
    }
}

#[async_trait]
impl ObjectFetcherV1 for GranolaFetchV1 {
    async fn fetch(
        &self,
        input: &PullPassInputV1<'_>,
        hint: &HintedObjectV1<'_>,
        stager: &mut PageStager<'_>,
    ) -> Result<FetchedObjectV1> {
        if hint.object_kind != SUMMARY_OBJECT_KIND {
            return Ok(FetchedObjectV1::Nothing("unknown_object_kind"));
        }
        if !is_note_id(hint.external_id) {
            return Ok(FetchedObjectV1::Nothing("malformed_id"));
        }
        let workspace = self.collector.settings.all_notes_visible_to_key;
        let (folder_kind, slots) = self.collector.slots(input, stager)?;
        let observations = slots
            .iter()
            .filter(|_| workspace)
            .map(|slot| ContainerObservationV1 {
                kind: slot.container.kind.clone(),
                id: slot.container.id.clone(),
                label: None,
                provider_audience: ProviderAudienceV1::OperatorScoped,
            })
            .collect::<Vec<_>>();
        let mut pass = GranolaPassV1 {
            collector: &self.collector,
            input,
            provider: ProviderKindV1::new(GRANOLA_PROVIDER)?,
            folder_kind,
            observed: slots
                .iter()
                .filter(|_| workspace)
                .map(|slot| slot.key)
                .collect(),
            slots,
            workspace,
            summaries: stager
                .known_versions(&ObjectKindV1::new(SUMMARY_OBJECT_KIND)?)
                .await?,
            transcripts: stager
                .known_versions(&ObjectKindV1::new(TRANSCRIPT_OBJECT_KIND)?)
                .await?,
            cursor: NotesCursorV1::fresh(),
            reconcile: false,
            observations,
            unsaved: 0,
            budget: HINT_REQUEST_BUDGET,
            counters: BTreeMap::new(),
        };
        match pass.note(hint.external_id, stager).await {
            Ok(NoteEndV1::Settled(items)) => Ok(FetchedObjectV1::Stage {
                items,
                observations: pass.observations,
            }),
            Ok(NoteEndV1::Stop(reason)) => Ok(FetchedObjectV1::Failed(format!(
                "Granola could not be read now ({})",
                reason.as_str()
            ))),
            Err(FleetError::Configuration(message)) => Ok(FetchedObjectV1::Failed(message)),
            Err(error) => Err(error),
        }
    }
}
