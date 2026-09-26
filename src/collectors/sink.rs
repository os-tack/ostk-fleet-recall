//! The collected-item sink: one staging path and one drain for every
//! collector (ADR 0008 D4).
//!
//! ```text
//! collector (pull | hint-driven fetch | capture | import)
//!   -> StageDraftV1 (memory only)
//!   -> CollectedItemSink::stage       one SERIALIZABLE transaction:
//!        container observations       recorded, withdrawn, or kept
//!        per draft: scope check -> audience (server-derived) -> seal
//!          (sanitize, redact, split, envelope, stage id) -> clock check
//!          -> INSERT memory_collector_outbox_v1 ON CONFLICT DO NOTHING
//!          -> lift the item's withdrawals this channel may lift
//!        refusals                     digest-only dead letters; a narrowing
//!                                     refusal of a known item withdraws it
//!        cursor advances, status      in the same transaction (REPLAY-02)
//!   -> CollectedItemSink::drain       per pending row:
//!        connector.collected.<mode> -> candidate -> admit_evidence
//!        -> AcceptedEventRepository::append with CollectedDrainProjection:
//!             governed content + outbox row admitted (envelope NULLed)
//!             + item history + links + head move   (one transaction, EVENT-03)
//!   -> the existing body, lexical, and dense projectors
//! ```
//!
//! # Clocks
//!
//! `observed_at` and `received_at` are the staging transaction's
//! `statement_timestamp()`, and `occurred_at` is the envelope's provider clock
//! (else the observation). All three are stored on the row, so re-draining a
//! row rebuilds a byte-identical candidate and replays rather than minting a
//! second event. An item whose provider clock is ahead of the observation is
//! not staged (`clock_ahead`), and the page's cursor advances are not applied,
//! so the next read sees it again. A capture's or an import's order is the
//! caller's word, not the provider's, so one ahead of the observation is
//! refused the same way: a head only moves to a greater order, and a
//! far-future one would otherwise stay presented for good.
//!
//! # Drain outcomes
//!
//! | Outcome | Row |
//! |---|---|
//! | appended, or replayed by a concurrent drain | `admitted` |
//! | the ledger quarantined the event | `quarantined`, with its quarantine id |
//! | admission refused the candidate | `dead_lettered`, `admission_refused` dead letter; the drain goes on |
//! | the head moved, the authority was unavailable, storage failed | `attempts + 1`; the eighth failure is `retry_exhausted` |
//! | the active package does not carry `connector.collected.<mode>` | stays `pending`; the caller reports it |
//!
//! Every settled row loses its envelope: the redacted text stays in the
//! governed content store and the body plane, and the outbox keeps only its
//! digest.
//!
//! # Withdrawals
//!
//! What a container observation or an audience refusal does to what the
//! memory already admitted is [`super::withdrawal`]'s: a withdrawal is lifted
//! only by a channel at least as trusted as the one that made it, a container
//! refused before anything was admitted through it is still recorded
//! withdrawn, and an item whose own audience narrowed is withdrawn until an
//! admissible observation at least as new lifts it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::context::FleetScope;
use crate::control_log::TrustedControlScope;
use crate::error::{FleetError, Result};
use crate::evidence_ledger::{
    AcceptedEventRepository, ActiveStage4Package, AppendOutcome, AppendProjection,
    ContentKeyEncryptionKey, EvidenceAdmissionError, EvidenceAdmissionRequestV1,
    EvidenceAppendError, EvidenceAppendResult, GovernedContentProjection, ProjectionContext,
    admit_evidence,
};
use crate::memory_contracts::collected_item::{
    AudienceBasisV1, BoundedTextV1, CollectedItemEnvelopeV1, CollectionModeV1, ContainerKindV1,
    ItemCollectionV1, ItemLifecycleV1, ItemRedactionV1, MAX_LABEL_BYTES, ProviderKindV1,
    TrustTierV1, derive_container_key, derive_item_key, timestamp_micros,
};
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId};
use crate::memory_contracts::digest::{Sha256Digest, body_digest};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::evidence_v2::RepresentationLineageV2;
use crate::registry_witness::VerifiedWriterAuthority;
use crate::store::cockroach::{RetryPolicy, with_serializable_retry};

use super::audience::{
    AudienceDecisionV1, AudienceInputV1, AudiencePolicyV1, AudienceRefusalV1, CaptureScopeV1,
    KnownContainerV1, ProviderAudienceV1, classify, is_direct_container_kind,
};
use super::binding::{
    CollectedConnectorBindingV1, CollectedIngressV1, CollectedRowClocksV1, CollectorInstanceV1,
    MAX_DELIVERY_ID_BYTES,
};
use super::cockroach::{
    BUMP_ATTEMPTS_SQL, COUNT_PENDING_SQL, INSERT_DEAD_LETTER_SQL, INSERT_ITEM_SQL, INSERT_LINK_SQL,
    INSERT_OUTBOX_SQL, ITEM_SEEN_SQL, LIFT_ITEM_SQL, LOCK_HEADS_SQL, LOCK_PENDING_ROW_SQL,
    MARK_ADMITTED_SQL, MARK_DEAD_LETTERED_SQL, MARK_QUARANTINED_SQL,
    MAX_DEAD_LETTER_DIAGNOSTIC_BYTES, MAX_DRAIN_ATTEMPTS, MAX_OUTBOX_ERROR_BYTES, PART_STATE_SQL,
    RECORD_CONTAINER_SQL, RECORD_WITHDRAWN_CONTAINER_SQL, SELECT_CURSOR_SQL, SELECT_ROW_STATE_SQL,
    UPDATE_HEAD_PRESENTATION_SQL, UPSERT_CURSOR_SQL, UPSERT_HEAD_SQL, WITHDRAW_CONTAINER_SQL,
    WITHDRAW_ITEM_SQL, bounded, digest_column, framed_sha256, known_container, lock_container,
    lock_item_withdrawals, optional_digest_column, select_pending_by_id_sql, select_pending_sql,
    statement_time,
};
use super::draft::{
    CollectedItemDraftV1, ItemRefusalV1, SealContextV1, collection_record, has_hidden_scalar, seal,
};
use super::heads::{
    CompletedVersionV1, TierHeadV1, advance_tier_head, part_completes_version, present,
};
use super::redaction::{CollectorDispositionV1, CollectorRedactorV1, scan_collected_secrets};
use super::status::{CollectorSourceStatusV1, upsert_collector_source};
use super::text::{sanitize_line, truncate_on_char_boundary};
use super::withdrawal::{
    ContainerWriteV1, ItemWithdrawalStateV1, after_admission, after_refusal, container_write,
    may_lift, narrows_item, observes_item_audience,
};

/// Item-withdrawal rows one staging call holds, by item and tier.
type ItemWithdrawals = BTreeMap<(Sha256Digest, TrustTierV1), ItemWithdrawalStateV1>;

/// Pending rows one [`CollectedItemSink::drain`] call reads at most, when the
/// caller asks for more.
pub const MAX_DRAIN_ROWS: u32 = 4_096;

/// Most distinct row errors a drain report carries.
const MAX_REPORTED_ERRORS: usize = 8;

/// Longest cursor domain key migration 0033 stores.
const MAX_CURSOR_DOMAIN_BYTES: usize = 256;

/// Longest cursor state migration 0033 stores.
const MAX_CURSOR_STATE_BYTES: usize = 16_384;

/// Why an item or a row was dead-lettered: the closed reasons migration 0033
/// admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadLetterReasonV1 {
    /// A provider payload could not be parsed.
    ParseFailed,
    /// The item breaks the envelope contract, or names another scope.
    ValidationFailed,
    /// A secret shape survived redaction, or sits in an id.
    RedactionWithheld,
    /// The server-derived audience refused the item.
    AudienceRefused,
    /// The item needs more parts than one version may have.
    Oversize,
    /// The provider clock is ahead of the observation.
    ClockAhead,
    /// Evidence admission refused the staged candidate.
    AdmissionRefused,
    /// A delivery's signature did not verify.
    InvalidSignature,
    /// A delivery's signed timestamp is outside the window.
    StaleSignature,
    /// A delivery names another provider scope than the instance's.
    UnauthorizedScope,
    /// A staged row failed to append eight times.
    RetryExhausted,
    /// A hinted object could not be fetched.
    FetchFailed,
}

impl DeadLetterReasonV1 {
    /// The stored reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ParseFailed => "parse_failed",
            Self::ValidationFailed => "validation_failed",
            Self::RedactionWithheld => "redaction_withheld",
            Self::AudienceRefused => "audience_refused",
            Self::Oversize => "oversize",
            Self::ClockAhead => "clock_ahead",
            Self::AdmissionRefused => "admission_refused",
            Self::InvalidSignature => "invalid_signature",
            Self::StaleSignature => "stale_signature",
            Self::UnauthorizedScope => "unauthorized_scope",
            Self::RetryExhausted => "retry_exhausted",
            Self::FetchFailed => "fetch_failed",
        }
    }

    /// The reason a sealing refusal is recorded under.
    #[must_use]
    pub const fn of_refusal(refusal: ItemRefusalV1) -> Self {
        match refusal {
            ItemRefusalV1::Validation(_) => Self::ValidationFailed,
            ItemRefusalV1::Oversize { .. } => Self::Oversize,
            ItemRefusalV1::RedactionWithheld { .. } => Self::RedactionWithheld,
        }
    }
}

/// A dead letter's key: a digest of the instance, the reason, the payload
/// digest, and the stage id, so recording one refusal twice is a no-op.
#[must_use]
pub fn dead_letter_id(
    instance: &str,
    reason: DeadLetterReasonV1,
    payload_digest: &Sha256Digest,
    stage_id: Option<&Sha256Digest>,
) -> Sha256Digest {
    framed_sha256(
        "ostk-collector-dead-letter-v1",
        &[
            instance.as_bytes(),
            reason.as_str().as_bytes(),
            payload_digest.as_bytes(),
            stage_id.map_or(&[][..], |stage_id| stage_id.as_bytes()),
        ],
    )
}

/// A digest of everything one draft says, for the dead letter of a draft
/// refused before it had an envelope. The digest is all that is kept.
#[must_use]
pub fn draft_digest(draft: &CollectedItemDraftV1) -> Sha256Digest {
    let order = draft.order_micros.to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![
        draft.provider.as_str().as_bytes(),
        draft.provider_scope_id.as_bytes(),
        draft.object_kind.as_str().as_bytes(),
        draft.external_id.as_bytes(),
        draft.marker.as_deref().unwrap_or_default().as_bytes(),
        &order,
        draft.lifecycle.as_str().as_bytes(),
        draft.title.as_deref().unwrap_or_default().as_bytes(),
    ];
    parts.extend(draft.sections.iter().map(|section| section.text.as_bytes()));
    framed_sha256("ostk-collector-draft-v1", &parts)
}

/// One draft handed to the sink, with what the collector learned about its
/// audience and the transport delivery it arrived in.
#[derive(Debug, Clone)]
pub struct StageDraftV1 {
    /// The draft.
    pub draft: CollectedItemDraftV1,
    /// The provider's audience for the item's container, when the collector
    /// read it. A container observation in the same call supplies it too.
    pub provider_audience: Option<ProviderAudienceV1>,
    /// The transport delivery id (a page digest, a hint key, a request
    /// digest, a file digest plus a line number): 1 to 64 bytes.
    pub delivery_id: Vec<u8>,
}

/// What a verified collector or an operator import learned about one
/// container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerObservationV1 {
    /// What kind of container.
    pub kind: ContainerKindV1,
    /// The provider-stable container id.
    pub id: String,
    /// Its current display label.
    pub label: Option<String>,
    /// Who the provider says can read it.
    pub provider_audience: ProviderAudienceV1,
}

/// One cursor advance, applied in the staging transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct CursorAdvanceV1 {
    /// The cursor's domain inside the instance (a channel, a team, a root).
    pub domain_key: String,
    /// The collector's own opaque cursor bytes.
    pub cursor_state: Vec<u8>,
    /// The highest provider order the cursor passed.
    pub high_water_order: Option<u64>,
    /// The pass the advance belongs to.
    pub pass_seq: u64,
}

/// Lengths only: a cursor may hold provider paging tokens.
impl std::fmt::Debug for CursorAdvanceV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CursorAdvanceV1")
            .field("domain_key", &self.domain_key)
            .field("cursor_state_bytes", &self.cursor_state.len())
            .field("high_water_order", &self.high_water_order)
            .field("pass_seq", &self.pass_seq)
            .finish()
    }
}

/// One stored cursor.
#[derive(Clone, PartialEq, Eq)]
pub struct CollectorCursorV1 {
    /// The collector's opaque cursor bytes.
    pub cursor_state: Vec<u8>,
    /// The highest provider order the cursor passed.
    pub high_water_order: Option<u64>,
    /// The pass it was advanced in.
    pub pass_seq: u64,
    /// When it was advanced.
    pub updated_at: DateTime<Utc>,
}

impl std::fmt::Debug for CollectorCursorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CollectorCursorV1")
            .field("cursor_state_bytes", &self.cursor_state.len())
            .field("high_water_order", &self.high_water_order)
            .field("pass_seq", &self.pass_seq)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Everything one staging call shares across its drafts.
#[derive(Debug, Clone, Copy)]
pub struct StageContextV1<'a> {
    /// The collector instance, pinned to its provider and scope.
    pub instance: &'a CollectorInstanceV1,
    /// The authenticated connector principal.
    pub principal: &'a ContractId,
    /// The trust channel.
    pub mode: CollectionModeV1,
    /// The attesting principal: required for a capture, refused otherwise.
    pub attester: Option<&'a ContractId>,
    /// The tool an agent says it read the items through; capture only.
    pub via: Option<&'a str>,
    /// The redactor, under the active package's guarantee.
    pub redactor: &'a CollectorRedactorV1,
    /// The instance's audience policy.
    pub policy: &'a AudiencePolicyV1,
    /// The operator's capture scopes.
    pub capture_scopes: &'a [CaptureScopeV1],
    /// The pull pass the drafts belong to.
    pub pass_seq: Option<u64>,
    /// Containers the collector observed; recorded, or withdrawn when their
    /// audience is no longer admissible. Not for a capture.
    pub container_observations: &'a [ContainerObservationV1],
    /// Cursor advances; not applied when an item was `clock_ahead`.
    pub cursor_advances: &'a [CursorAdvanceV1],
    /// The instance's status row.
    pub source_status: Option<&'a CollectorSourceStatusV1>,
}

/// What staging did with one draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StagedItemV1 {
    /// Every part is in the outbox (newly, or already).
    Staged {
        /// The item key.
        item_key: Sha256Digest,
        /// The version key.
        version_key: Sha256Digest,
        /// Every part's stage id, in order.
        stage_ids: Vec<Sha256Digest>,
        /// Parts this call newly staged.
        new_rows: u32,
        /// What sanitizing and redacting did.
        redaction: ItemRedactionV1,
    },
    /// The draft was refused and dead-lettered.
    Refused {
        /// The dead letter's reason.
        reason: DeadLetterReasonV1,
        /// A static diagnostic; never provider content.
        diagnostic: String,
    },
}

/// What one staging call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageOutcomeV1 {
    /// The staging transaction's clock: every new row's `observed_at`.
    pub observed_at: CanonicalTimestamp,
    /// One entry per draft, in order.
    pub items: Vec<StagedItemV1>,
    /// Outbox rows newly written.
    pub rows_staged: u64,
    /// Parts already staged (a primary-key no-op).
    pub rows_already_staged: u64,
    /// Refused drafts, by reason.
    pub refused: BTreeMap<DeadLetterReasonV1, u64>,
    /// Containers recorded as readable: new, re-opened, or relabelled.
    pub containers_recorded: u64,
    /// Containers withdrawn, whether recorded before or not.
    pub containers_withdrawn: u64,
    /// Items withdrawn because a refusal narrowed an item already admitted
    /// or staged.
    pub items_withdrawn: u64,
    /// Item withdrawals an admissible observation lifted.
    pub item_withdrawals_lifted: u64,
    /// Whether the cursor advances were applied.
    pub cursors_advanced: bool,
}

/// What a drain needs from the tick that runs it.
pub struct CollectedDrainContextV1<'a> {
    /// This tick's verified head; every connector binds from it.
    pub verified: &'a VerifiedWriterAuthority,
    /// The accepted-event ledger.
    pub ledger: &'a dyn AcceptedEventRepository,
    /// Physical and semantic scope of the governed content store.
    pub control_scope: &'a TrustedControlScope,
    /// The key governed content is sealed under.
    pub kek: &'a ContentKeyEncryptionKey,
}

impl std::fmt::Debug for CollectedDrainContextV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CollectedDrainContextV1")
            .field("control_scope", &self.control_scope)
            .finish_non_exhaustive()
    }
}

/// One row the drain made durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DrainedPartV1 {
    /// The row's stage id.
    pub stage_id: Sha256Digest,
    /// The accepted event that admitted it.
    pub accepted_event_id: Sha256Digest,
    /// Whether the event already existed.
    pub replayed: bool,
}

/// What one drain did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CollectedDrainReportV1 {
    /// Pending rows read.
    pub rows_read: u64,
    /// Rows whose event was newly appended.
    pub appended: u64,
    /// Rows whose event already existed.
    pub replayed: u64,
    /// Rows the ledger quarantined.
    pub quarantined: u64,
    /// Rows admission refused, dead-lettered.
    pub dead_lettered: u64,
    /// Rows that failed and will be retried.
    pub retried: u64,
    /// Rows that failed an eighth time, dead-lettered.
    pub retry_exhausted: u64,
    /// Rows left pending because the active package cannot admit them.
    pub held: u64,
    /// The connector schemas the active package does not carry.
    pub held_connectors: BTreeSet<String>,
    /// The first distinct errors behind held and retried rows.
    pub errors: Vec<String>,
    /// Every row made durable, in drain order.
    pub admitted: Vec<DrainedPartV1>,
}

impl CollectedDrainReportV1 {
    fn note(&mut self, error: String) {
        if self.errors.len() < MAX_REPORTED_ERRORS && !self.errors.contains(&error) {
            self.errors.push(error);
        }
    }
}

/// The sink, bound once to one physical `(tenant_id, project)`.
#[derive(Clone)]
pub struct CollectedItemSink {
    pool: PgPool,
    tenant_id: Uuid,
    project: String,
    retry: RetryPolicy,
}

impl std::fmt::Debug for CollectedItemSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CollectedItemSink")
            .field("tenant_id", &self.tenant_id)
            .field("project", &self.project)
            .finish_non_exhaustive()
    }
}

impl CollectedItemSink {
    /// Bind the sink to `scope`.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] for an invalid scope.
    pub fn new(pool: PgPool, scope: &FleetScope, retry: RetryPolicy) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            pool,
            tenant_id: scope.tenant_id,
            project: scope.project.clone(),
            retry,
        })
    }

    /// Stage `drafts` in one serializable transaction. See the module
    /// documentation for what one call does.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] for a context the sink cannot stage
    /// under (an attester outside a capture, a container observation in a
    /// capture, a malformed cursor or container id, a status the table cannot
    /// hold); any database failure. A refused draft is not an error: it is
    /// dead-lettered and reported in the outcome.
    pub async fn stage(
        &self,
        drafts: &[StageDraftV1],
        context: &StageContextV1<'_>,
    ) -> Result<StageOutcomeV1> {
        let prepared = Arc::new(self.prepare_stage(drafts, context)?);
        with_serializable_retry(&self.pool, self.retry, move |transaction| {
            let prepared = Arc::clone(&prepared);
            Box::pin(async move { prepared.run(transaction).await })
        })
        .await
    }

    /// Prepare `drafts` for staging inside a caller's own serializable
    /// transaction, beside writes the caller must commit with them: an agent
    /// capture reserves its idempotency receipt in the transaction that
    /// stages its items (ADR 0008 D10). [`Self::stage`] is exactly this, run
    /// in a transaction of its own.
    ///
    /// # Errors
    ///
    /// As [`Self::stage`], for a context the sink cannot stage under.
    pub fn prepare_stage(
        &self,
        drafts: &[StageDraftV1],
        context: &StageContextV1<'_>,
    ) -> Result<PreparedStageV1> {
        Ok(PreparedStageV1 {
            job: StageJob::prepare(self, drafts, context)?,
        })
    }

    /// Drain at most `limit` pending rows, oldest first.
    ///
    /// # Errors
    ///
    /// A limit of zero or above [`MAX_DRAIN_ROWS`], a context bound to
    /// another scope, a ledger integrity failure, or a database failure that
    /// also stopped the row's retry from being recorded. A refused,
    /// quarantined, retried, or held row is not an error: it is in the
    /// report.
    pub async fn drain(
        &self,
        context: &CollectedDrainContextV1<'_>,
        limit: u32,
    ) -> Result<CollectedDrainReportV1> {
        if limit == 0 || limit > MAX_DRAIN_ROWS {
            return Err(FleetError::Configuration(format!(
                "a collected-item drain reads 1 to {MAX_DRAIN_ROWS} rows"
            )));
        }
        self.require_scope(context)?;
        let rows: Vec<PgRow> = sqlx::query(&select_pending_sql())
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?;
        self.drain_rows(context, &rows).await
    }

    /// Drain exactly the named rows that are still pending.
    ///
    /// # Errors
    ///
    /// As [`Self::drain`].
    pub async fn drain_stage_ids(
        &self,
        context: &CollectedDrainContextV1<'_>,
        stage_ids: &[Sha256Digest],
    ) -> Result<CollectedDrainReportV1> {
        self.require_scope(context)?;
        if stage_ids.is_empty() {
            return Ok(CollectedDrainReportV1::default());
        }
        let ids: Vec<Vec<u8>> = stage_ids.iter().map(|id| id.as_bytes().to_vec()).collect();
        let rows: Vec<PgRow> = sqlx::query(&select_pending_by_id_sql())
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(&ids)
            .fetch_all(&self.pool)
            .await?;
        self.drain_rows(context, &rows).await
    }

    /// Staged parts still waiting to be admitted in this scope.
    ///
    /// # Errors
    ///
    /// A database failure.
    pub async fn pending_rows(&self) -> Result<u64> {
        let count: i64 = sqlx::query_scalar(COUNT_PENDING_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .fetch_one(&self.pool)
            .await?;
        u64::try_from(count)
            .map_err(|_| FleetError::Memory("the pending count is negative".to_owned()))
    }

    /// One instance's cursor for one domain.
    ///
    /// # Errors
    ///
    /// A database failure, or a stored cursor outside its bounds.
    pub async fn read_cursor(
        &self,
        instance: &ContractId,
        domain_key: &str,
    ) -> Result<Option<CollectorCursorV1>> {
        let row: Option<PgRow> = sqlx::query(SELECT_CURSOR_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(instance.as_str())
            .bind(domain_key)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            let high_water: Option<i64> = row.try_get("high_water_order")?;
            let pass_seq: i64 = row.try_get("pass_seq")?;
            Ok(CollectorCursorV1 {
                cursor_state: row.try_get("cursor_state")?,
                high_water_order: high_water.map(u64::try_from).transpose().map_err(|_| {
                    FleetError::Memory("a stored high-water order is negative".into())
                })?,
                pass_seq: u64::try_from(pass_seq)
                    .map_err(|_| FleetError::Memory("a stored pass sequence is negative".into()))?,
                updated_at: row.try_get("updated_at")?,
            })
        })
        .transpose()
    }

    fn require_scope(&self, context: &CollectedDrainContextV1<'_>) -> Result<()> {
        if context.control_scope.tenant_id() != self.tenant_id
            || context.control_scope.project() != self.project
        {
            return Err(FleetError::Configuration(
                "the drain's ledger scope is not the sink's (tenant, project)".to_owned(),
            ));
        }
        Ok(())
    }

    async fn drain_rows(
        &self,
        context: &CollectedDrainContextV1<'_>,
        rows: &[PgRow],
    ) -> Result<CollectedDrainReportV1> {
        let mut report = CollectedDrainReportV1 {
            rows_read: u64::try_from(rows.len()).unwrap_or(u64::MAX),
            ..CollectedDrainReportV1::default()
        };
        let mut bindings = DrainBindings::default();
        for row in rows {
            let row = PendingRowV1::decode(row)?;
            match self.drain_row(context, &mut bindings, &row).await? {
                RowOutcome::Appended(event) => {
                    report.appended += 1;
                    report.admitted.push(DrainedPartV1 {
                        stage_id: row.stage_id,
                        accepted_event_id: event,
                        replayed: false,
                    });
                }
                RowOutcome::Replayed(event) => {
                    report.replayed += 1;
                    report.admitted.push(DrainedPartV1 {
                        stage_id: row.stage_id,
                        accepted_event_id: event,
                        replayed: true,
                    });
                }
                RowOutcome::Quarantined => report.quarantined += 1,
                RowOutcome::Refused => report.dead_lettered += 1,
                RowOutcome::Retried(error) => {
                    report.retried += 1;
                    report.note(error);
                }
                RowOutcome::RetryExhausted(error) => {
                    report.retry_exhausted += 1;
                    report.note(error);
                }
                RowOutcome::Held { connector, reason } => {
                    report.held += 1;
                    report.held_connectors.insert(connector.to_owned());
                    report.note(reason);
                }
                RowOutcome::Gone => {}
            }
        }
        Ok(report)
    }

    /// Admit one pending row, or record why not.
    #[allow(clippy::too_many_lines)] // one linear bind -> build -> admit -> append pipeline
    async fn drain_row(
        &self,
        context: &CollectedDrainContextV1<'_>,
        bindings: &mut DrainBindings,
        row: &PendingRowV1,
    ) -> Result<RowOutcome> {
        let Ok(mode) = CollectionModeV1::parse(&row.mode) else {
            return self
                .refuse(row, "the stored collection mode is not known")
                .await;
        };
        let DrainBindings {
            active: actives,
            bindings: resolved,
        } = bindings;
        let active = match DrainBindings::active(actives, context.verified, mode) {
            Ok(active) => active,
            Err(reason) => {
                return Ok(RowOutcome::Held {
                    connector: mode.connector_schema_id(),
                    reason,
                });
            }
        };
        let Some((principal, instance)) = row.identity() else {
            return self
                .refuse(
                    row,
                    "the stored instance, principal, or provider scope is invalid",
                )
                .await;
        };
        let binding = match DrainBindings::binding(resolved, active, mode, principal, instance) {
            Ok(binding) => binding,
            Err(reason) => {
                return Ok(RowOutcome::Held {
                    connector: mode.connector_schema_id(),
                    reason,
                });
            }
        };
        let Some(clocks) = row.clocks() else {
            return self
                .refuse(row, "the stored clocks are not canonical")
                .await;
        };
        let ingress = match binding.build(&row.envelope, &clocks, &row.delivery_id, 1) {
            Ok(ingress) => ingress,
            Err(error) => return self.refuse(row, &error.to_string()).await,
        };
        let admitted = match admit_evidence(
            active,
            EvidenceAdmissionRequestV1 {
                candidate: &ingress.candidate,
                locators: &ingress.locators,
                canonical_payload: &ingress.canonical_payload,
                delivery: ingress.delivery.clone(),
                // A staged envelope is rendered once; a different rendering of
                // the same item is a new stage id, never a silent successor.
                lineage: RepresentationLineageV2::Origin,
            },
        ) {
            Ok(admitted) => admitted,
            Err(EvidenceAdmissionError::Append(error)) => {
                return self.append_failed(row, error).await;
            }
            Err(error) => return self.refuse(row, &error.to_string()).await,
        };
        let accepted_event_id = match admitted.statement().accepted_event_id() {
            Ok(id) => id,
            Err(error) => return self.refuse(row, &error.to_string()).await,
        };
        let Some(part) = AdmittedPartV1::of(&ingress, mode) else {
            return self
                .refuse(row, "the admitted envelope has an unrepresentable field")
                .await;
        };
        let projection = CollectedDrainProjection {
            content: GovernedContentProjection::new(
                context.control_scope,
                admitted.content(),
                context.kek,
            )
            .map_err(FleetError::from)?,
            tenant_id: self.tenant_id,
            project: self.project.clone(),
            part,
        };
        let witness = context.verified.append_witness();
        let appendable = match admitted.appendable(witness) {
            Ok(appendable) => appendable,
            Err(error) => return self.append_failed(row, error).await,
        };
        match context
            .ledger
            .append(witness, &appendable, Arc::new(projection))
            .await
        {
            Ok(AppendOutcome::Appended { .. }) => {
                Ok(RowOutcome::Appended(accepted_event_id.digest()))
            }
            Ok(AppendOutcome::Replayed { .. }) => self.replayed(row, accepted_event_id).await,
            Ok(AppendOutcome::Quarantined {
                quarantine_id,
                reason,
            }) => {
                let reason = serde_json::to_value(reason)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_else(|| "quarantined".to_owned());
                sqlx::query(MARK_QUARANTINED_SQL)
                    .bind(self.tenant_id)
                    .bind(&self.project)
                    .bind(row.stage_id.as_bytes().as_slice())
                    .bind(quarantine_id.digest().as_bytes().as_slice())
                    .bind(bounded(
                        &format!("the ledger quarantined the event: {reason}"),
                        MAX_OUTBOX_ERROR_BYTES,
                    ))
                    .execute(&self.pool)
                    .await?;
                Ok(RowOutcome::Quarantined)
            }
            Err(error) => self.append_failed(row, error).await,
        }
    }

    /// The ledger already held the event: a concurrent drain admitted the
    /// row, whose projection settled it. Anything else is retried.
    async fn replayed(
        &self,
        row: &PendingRowV1,
        accepted_event_id: AcceptedEventId,
    ) -> Result<RowOutcome> {
        let state: Option<PgRow> = sqlx::query(SELECT_ROW_STATE_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(row.stage_id.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await?;
        let admitted = match &state {
            Some(state) => {
                state.try_get::<String, _>("state")? == "admitted"
                    && optional_digest_column(state, "accepted_event_id")?
                        == Some(accepted_event_id.digest())
            }
            None => false,
        };
        if admitted {
            return Ok(RowOutcome::Replayed(accepted_event_id.digest()));
        }
        self.retry(
            row,
            "the ledger replayed the event, but the staged row is still pending",
        )
        .await
    }

    /// Classify an append failure: a moved or unavailable head and a storage
    /// failure are retried, a contract refusal is dead-lettered, and a ledger
    /// integrity failure stops the drain.
    async fn append_failed(
        &self,
        row: &PendingRowV1,
        error: EvidenceAppendError,
    ) -> Result<RowOutcome> {
        match error {
            EvidenceAppendError::WitnessMismatch(_)
            | EvidenceAppendError::StatementAuthority(_)
            | EvidenceAppendError::AuthorityUnavailable(_)
            | EvidenceAppendError::Storage(_) => self.retry(row, &error.to_string()).await,
            EvidenceAppendError::Contract(_) => self.refuse(row, &error.to_string()).await,
            EvidenceAppendError::LedgerIntegrity(_) => Err(FleetError::from(error)),
        }
    }

    /// Dead-letter a row admission refused, and settle it.
    async fn refuse(&self, row: &PendingRowV1, diagnostic: &str) -> Result<RowOutcome> {
        let letter = RowLetter {
            reason: DeadLetterReasonV1::AdmissionRefused,
            diagnostic: bounded(diagnostic, MAX_DEAD_LETTER_DIAGNOSTIC_BYTES),
            attempts: row.attempts,
        };
        let (tenant_id, project, row, letter) = (
            self.tenant_id,
            self.project.clone(),
            Arc::new(row.clone()),
            Arc::new(letter),
        );
        with_serializable_retry(&self.pool, self.retry, move |transaction| {
            let (project, row, letter) = (project.clone(), Arc::clone(&row), Arc::clone(&letter));
            Box::pin(async move {
                settle_dead_letter(transaction, tenant_id, &project, &row, &letter).await
            })
        })
        .await?;
        Ok(RowOutcome::Refused)
    }

    /// Count one failed attempt; the eighth dead-letters the row.
    async fn retry(&self, row: &PendingRowV1, error: &str) -> Result<RowOutcome> {
        let error = bounded(error, MAX_OUTBOX_ERROR_BYTES);
        let (tenant_id, project, shared_row, shared_error) = (
            self.tenant_id,
            self.project.clone(),
            Arc::new(row.clone()),
            Arc::new(error.clone()),
        );
        let exhausted = with_serializable_retry(&self.pool, self.retry, move |transaction| {
            let (project, row, error) = (
                project.clone(),
                Arc::clone(&shared_row),
                Arc::clone(&shared_error),
            );
            Box::pin(async move {
                let attempts: Option<i64> = sqlx::query_scalar(LOCK_PENDING_ROW_SQL)
                    .bind(tenant_id)
                    .bind(&project)
                    .bind(row.stage_id.as_bytes().as_slice())
                    .fetch_optional(&mut **transaction)
                    .await?;
                let Some(attempts) = attempts else {
                    return Ok(None);
                };
                let next = attempts.saturating_add(1);
                if next >= MAX_DRAIN_ATTEMPTS {
                    let letter = RowLetter {
                        reason: DeadLetterReasonV1::RetryExhausted,
                        diagnostic: bounded(&error, MAX_DEAD_LETTER_DIAGNOSTIC_BYTES),
                        attempts: MAX_DRAIN_ATTEMPTS,
                    };
                    settle_dead_letter(transaction, tenant_id, &project, &row, &letter).await?;
                    return Ok(Some(true));
                }
                sqlx::query(BUMP_ATTEMPTS_SQL)
                    .bind(tenant_id)
                    .bind(&project)
                    .bind(row.stage_id.as_bytes().as_slice())
                    .bind(next)
                    .bind(error.as_str())
                    .execute(&mut **transaction)
                    .await?;
                Ok(Some(false))
            })
        })
        .await?;
        Ok(match exhausted {
            None => RowOutcome::Gone,
            Some(true) => RowOutcome::RetryExhausted(error),
            Some(false) => RowOutcome::Retried(error),
        })
    }
}

/// One staging call, prepared outside any transaction
/// ([`CollectedItemSink::prepare_stage`]) and run inside a caller's.
///
/// It owns every input, so a serialization retry runs it again, from the same
/// inputs, in a fresh transaction; every write it makes is idempotent.
pub struct PreparedStageV1 {
    job: StageJob,
}

/// Identity and counts only: the drafts are provider content.
impl std::fmt::Debug for PreparedStageV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedStageV1")
            .field("instance", &self.job.instance.connector_instance_id)
            .field("mode", &self.job.mode.as_str())
            .field("drafts", &self.job.drafts.len())
            .finish_non_exhaustive()
    }
}

impl PreparedStageV1 {
    /// Stage the prepared drafts in `transaction`, which must be a
    /// serializable transaction on the sink's database. Everything
    /// [`CollectedItemSink::stage`] does in its own transaction happens here,
    /// and commits or rolls back with the caller's other writes.
    ///
    /// # Errors
    ///
    /// Any database failure, and a status row another owner holds. A refused
    /// draft is not an error: it is dead-lettered and reported in the outcome.
    pub async fn run(&self, transaction: &mut Transaction<'_, Postgres>) -> Result<StageOutcomeV1> {
        self.job.run(transaction).await
    }
}

/// What the drain did with one row.
enum RowOutcome {
    Appended(Sha256Digest),
    Replayed(Sha256Digest),
    Quarantined,
    Refused,
    Retried(String),
    RetryExhausted(String),
    Held {
        connector: &'static str,
        reason: String,
    },
    /// Another drain settled the row first.
    Gone,
}

type ActivePackages = HashMap<CollectionModeV1, std::result::Result<ActiveStage4Package, String>>;
type ResolvedBindings = HashMap<
    (CollectionModeV1, String, String),
    std::result::Result<CollectedConnectorBindingV1, String>,
>;

/// The connectors and bindings one drain resolved, so each is resolved once.
#[derive(Default)]
struct DrainBindings {
    active: ActivePackages,
    bindings: ResolvedBindings,
}

impl DrainBindings {
    fn active<'m>(
        actives: &'m mut ActivePackages,
        verified: &VerifiedWriterAuthority,
        mode: CollectionModeV1,
    ) -> std::result::Result<&'m ActiveStage4Package, String> {
        actives
            .entry(mode)
            .or_insert_with(|| {
                let connector = mode.connector_schema_id();
                ContractId::new(connector)
                    .map_err(|error| error.to_string())
                    .and_then(|schema| {
                        verified.bind_connector(&schema).map_err(|error| {
                            format!(
                                "the active package does not admit {connector} ({error}); run \
                                 `ostk-authority-install apply --target generation-3`"
                            )
                        })
                    })
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    fn binding<'m>(
        resolved: &'m mut ResolvedBindings,
        active: &ActiveStage4Package,
        mode: CollectionModeV1,
        principal: ContractId,
        instance: CollectorInstanceV1,
    ) -> std::result::Result<&'m CollectedConnectorBindingV1, String> {
        let key = (
            mode,
            principal.as_str().to_owned(),
            format!(
                "{}\u{0}{}\u{0}{}",
                instance.connector_instance_id,
                instance.provider,
                instance.provider_scope_id.as_str()
            ),
        );
        resolved
            .entry(key)
            .or_insert_with(|| {
                CollectedConnectorBindingV1::resolve(active, mode, principal, instance)
                    .map_err(|error| format!("the collected connector does not bind: {error}"))
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}

/// One pending outbox row.
#[derive(Clone)]
struct PendingRowV1 {
    stage_id: Sha256Digest,
    instance: String,
    principal: String,
    mode: String,
    provider: String,
    provider_scope_id: String,
    envelope: Vec<u8>,
    envelope_sha256: Sha256Digest,
    delivery_id: Vec<u8>,
    occurred_at: DateTime<Utc>,
    observed_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    attempts: i64,
}

impl PendingRowV1 {
    fn decode(row: &PgRow) -> Result<Self> {
        let envelope: Option<Vec<u8>> = row.try_get("canonical_envelope")?;
        Ok(Self {
            stage_id: digest_column(row, "stage_id")?,
            instance: row.try_get("collector_instance_id")?,
            principal: row.try_get("principal_id")?,
            mode: row.try_get("collection_mode")?,
            provider: row.try_get("provider")?,
            provider_scope_id: row.try_get("provider_scope_id")?,
            envelope: envelope.ok_or_else(|| {
                FleetError::Memory("a pending collector row has no envelope".to_owned())
            })?,
            envelope_sha256: digest_column(row, "envelope_sha256")?,
            delivery_id: row.try_get("delivery_id")?,
            occurred_at: row.try_get("occurred_at")?,
            observed_at: row.try_get("observed_at")?,
            received_at: row.try_get("received_at")?,
            attempts: row.try_get("attempts")?,
        })
    }

    fn identity(&self) -> Option<(ContractId, CollectorInstanceV1)> {
        Some((
            ContractId::new(&self.principal).ok()?,
            CollectorInstanceV1 {
                connector_instance_id: ContractId::new(&self.instance).ok()?,
                provider: ProviderKindV1::new(self.provider.clone()).ok()?,
                provider_scope_id: BoundedTextV1::new(self.provider_scope_id.clone()).ok()?,
            },
        ))
    }

    fn clocks(&self) -> Option<CollectedRowClocksV1> {
        Some(CollectedRowClocksV1 {
            occurred_at: CanonicalTimestamp::from_datetime(&self.occurred_at).ok()?,
            observed_at: CanonicalTimestamp::from_datetime(&self.observed_at).ok()?,
            received_at: CanonicalTimestamp::from_datetime(&self.received_at).ok()?,
        })
    }
}

/// A dead letter for one staged row.
struct RowLetter {
    reason: DeadLetterReasonV1,
    diagnostic: String,
    attempts: i64,
}

/// Record a row's dead letter and settle the row, in `transaction`.
async fn settle_dead_letter(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    project: &str,
    row: &PendingRowV1,
    letter: &RowLetter,
) -> Result<()> {
    let now = statement_time(transaction).await?;
    let id = dead_letter_id(
        &row.instance,
        letter.reason,
        &row.envelope_sha256,
        Some(&row.stage_id),
    );
    sqlx::query(INSERT_DEAD_LETTER_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(id.as_bytes().as_slice())
        .bind(&row.instance)
        .bind(&row.mode)
        .bind(&row.provider)
        .bind(letter.reason.as_str())
        .bind(row.stage_id.as_bytes().as_slice())
        .bind(row.delivery_id.as_slice())
        .bind(row.envelope_sha256.as_bytes().as_slice())
        .bind(letter.diagnostic.as_str())
        .bind(now)
        .execute(&mut **transaction)
        .await?;
    sqlx::query(MARK_DEAD_LETTERED_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(row.stage_id.as_bytes().as_slice())
        .bind(now)
        .bind(bounded(&letter.diagnostic, MAX_OUTBOX_ERROR_BYTES))
        .bind(letter.attempts)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Staging
// ---------------------------------------------------------------------------

/// A container observation, prepared outside the transaction.
struct PreparedContainerV1 {
    key: Sha256Digest,
    kind: ContainerKindV1,
    id: String,
    label: Option<String>,
    provider_audience: ProviderAudienceV1,
    decision: AudienceDecisionV1,
}

/// Everything one staging transaction needs, owned, so a serialization retry
/// re-runs it from the same inputs.
struct StageJob {
    tenant_id: Uuid,
    project: String,
    instance: CollectorInstanceV1,
    principal: ContractId,
    mode: CollectionModeV1,
    attester: Option<ContractId>,
    collection: ItemCollectionV1,
    redactor: CollectorRedactorV1,
    policy: AudiencePolicyV1,
    capture_scopes: Vec<CaptureScopeV1>,
    pass_seq: Option<i64>,
    drafts: Vec<StageDraftV1>,
    containers: Vec<PreparedContainerV1>,
    cursors: Vec<CursorAdvanceV1>,
    status: Option<CollectorSourceStatusV1>,
}

impl StageJob {
    fn prepare(
        sink: &CollectedItemSink,
        drafts: &[StageDraftV1],
        context: &StageContextV1<'_>,
    ) -> Result<Self> {
        let refuse = |message: &str| FleetError::Configuration(message.to_owned());
        let collection = collection_record(
            context.mode,
            context.instance.connector_instance_id.clone(),
            context.attester.cloned(),
            context.via,
        )
        .map_err(|refusal| FleetError::Configuration(refusal.to_string()))?;
        if context.mode == CollectionModeV1::Capture && !context.container_observations.is_empty() {
            return Err(refuse(
                "a capture cannot record a container: only a verified collector or an operator \
                 import does",
            ));
        }
        let pass_seq = context
            .pass_seq
            .map(i64::try_from)
            .transpose()
            .map_err(|_| refuse("a pass sequence exceeds INT8"))?;
        for cursor in context.cursor_advances {
            if cursor.domain_key.is_empty()
                || cursor.domain_key.len() > MAX_CURSOR_DOMAIN_BYTES
                || cursor.cursor_state.is_empty()
                || cursor.cursor_state.len() > MAX_CURSOR_STATE_BYTES
                || i64::try_from(cursor.pass_seq).is_err()
                || cursor
                    .high_water_order
                    .is_some_and(|order| i64::try_from(order).is_err())
            {
                return Err(refuse(
                    "a cursor advance is outside migration 0033's bounds",
                ));
            }
        }
        if let Some(status) = context.source_status {
            status.validate()?;
            if status.instance != context.instance.connector_instance_id {
                return Err(refuse(
                    "a staging call reports the status of its own instance only",
                ));
            }
        }
        let containers = context
            .container_observations
            .iter()
            .map(|observation| prepare_container(context, observation))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            tenant_id: sink.tenant_id,
            project: sink.project.clone(),
            instance: context.instance.clone(),
            principal: context.principal.clone(),
            mode: context.mode,
            attester: context.attester.cloned(),
            collection,
            redactor: context.redactor.clone(),
            policy: context.policy.clone(),
            capture_scopes: context.capture_scopes.to_vec(),
            pass_seq,
            drafts: drafts.to_vec(),
            containers,
            cursors: context.cursor_advances.to_vec(),
            status: context.source_status.cloned(),
        })
    }

    async fn run(&self, transaction: &mut Transaction<'_, Postgres>) -> Result<StageOutcomeV1> {
        let now = statement_time(transaction).await?;
        let observed_at = CanonicalTimestamp::from_datetime(&now)
            .map_err(|error| FleetError::Memory(format!("the staging clock: {error}")))?;
        let mut outcome = StageOutcomeV1 {
            observed_at: observed_at.clone(),
            items: Vec::with_capacity(self.drafts.len()),
            rows_staged: 0,
            rows_already_staged: 0,
            refused: BTreeMap::new(),
            containers_recorded: 0,
            containers_withdrawn: 0,
            items_withdrawn: 0,
            item_withdrawals_lifted: 0,
            cursors_advanced: false,
        };
        for container in &self.containers {
            self.observe_container(transaction, container, now, &mut outcome)
                .await?;
        }
        // One locking read for every item this call may withdraw or lift.
        let mut withdrawals = if observes_item_audience(self.mode) {
            let keys: Vec<Sha256Digest> = self
                .drafts
                .iter()
                .map(|staged| draft_item_key(&staged.draft))
                .collect();
            lock_item_withdrawals(transaction, self.tenant_id, &self.project, &keys).await?
        } else {
            ItemWithdrawals::new()
        };
        let mut clock_ahead = false;
        for staged in &self.drafts {
            let item = self
                .stage_one(
                    transaction,
                    staged,
                    (&observed_at, now),
                    &mut withdrawals,
                    &mut outcome,
                )
                .await?;
            if let StagedItemV1::Refused { reason, .. } = &item {
                *outcome.refused.entry(*reason).or_insert(0) += 1;
                clock_ahead |= *reason == DeadLetterReasonV1::ClockAhead;
            }
            outcome.items.push(item);
        }
        // A cursor never passes an item that was not staged because its clock
        // was ahead: the page is read again, and what did stage replays.
        if !clock_ahead {
            for cursor in &self.cursors {
                sqlx::query(UPSERT_CURSOR_SQL)
                    .bind(self.tenant_id)
                    .bind(&self.project)
                    .bind(self.instance.connector_instance_id.as_str())
                    .bind(&cursor.domain_key)
                    .bind(cursor.cursor_state.as_slice())
                    .bind(cursor.high_water_order.map(order_i64))
                    .bind(order_i64(cursor.pass_seq))
                    .bind(now)
                    .execute(&mut **transaction)
                    .await?;
            }
            outcome.cursors_advanced = !self.cursors.is_empty();
        }
        if let Some(status) = &self.status {
            upsert_collector_source(transaction, self.tenant_id, &self.project, status).await?;
        }
        Ok(outcome)
    }

    /// Apply one container observation under the withdrawal rules.
    async fn observe_container(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        container: &PreparedContainerV1,
        now: DateTime<Utc>,
        outcome: &mut StageOutcomeV1,
    ) -> Result<()> {
        let tier = self.mode.trust_tier();
        let stored =
            lock_container(transaction, self.tenant_id, &self.project, &container.key).await?;
        match container_write(stored, container.decision, tier) {
            ContainerWriteV1::Record(basis) => {
                sqlx::query(RECORD_CONTAINER_SQL)
                    .bind(self.tenant_id)
                    .bind(&self.project)
                    .bind(container.key.as_bytes().as_slice())
                    .bind(self.instance.provider.as_str())
                    .bind(self.instance.provider_scope_id.as_str())
                    .bind(container.kind.as_str())
                    .bind(&container.id)
                    .bind(container.label.as_deref())
                    .bind(basis.as_str())
                    .bind(self.instance.connector_instance_id.as_str())
                    .bind(now)
                    .bind(tier.as_str())
                    .execute(&mut **transaction)
                    .await?;
                outcome.containers_recorded += 1;
            }
            ContainerWriteV1::RecordWithdrawn => {
                // A container never admitted keeps no label: a private
                // channel's name is not the project's to read.
                outcome.containers_withdrawn += sqlx::query(RECORD_WITHDRAWN_CONTAINER_SQL)
                    .bind(self.tenant_id)
                    .bind(&self.project)
                    .bind(container.key.as_bytes().as_slice())
                    .bind(self.instance.provider.as_str())
                    .bind(self.instance.provider_scope_id.as_str())
                    .bind(container.kind.as_str())
                    .bind(&container.id)
                    .bind(self.instance.connector_instance_id.as_str())
                    .bind(now)
                    .bind(tier.as_str())
                    .execute(&mut **transaction)
                    .await?
                    .rows_affected();
            }
            write @ (ContainerWriteV1::Withdraw | ContainerWriteV1::Confirm) => {
                sqlx::query(WITHDRAW_CONTAINER_SQL)
                    .bind(self.tenant_id)
                    .bind(&self.project)
                    .bind(container.key.as_bytes().as_slice())
                    .bind(tier.as_str())
                    .bind(self.instance.connector_instance_id.as_str())
                    .bind(now)
                    .execute(&mut **transaction)
                    .await?;
                if write == ContainerWriteV1::Withdraw {
                    outcome.containers_withdrawn += 1;
                }
            }
            ContainerWriteV1::Keep => {}
        }
        Ok(())
    }

    /// A narrowing refusal of `draft`: withdraw its item for this channel's
    /// tier, unless it is a first sighting or a stale report.
    async fn withdraw_item(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        draft: &CollectedItemDraftV1,
        refusal: AudienceRefusalV1,
        now: DateTime<Utc>,
        withdrawals: &mut ItemWithdrawals,
        outcome: &mut StageOutcomeV1,
    ) -> Result<()> {
        // A draft whose order no envelope could carry is no observation.
        let Ok(order) = i64::try_from(draft.order_micros) else {
            return Ok(());
        };
        if order > crate::memory_contracts::canonical::MAX_SAFE_INTEGER {
            return Ok(());
        }
        let key = draft_item_key(draft);
        let tier = self.mode.trust_tier();
        let stored = withdrawals.get(&(key, tier)).copied();
        let (seen, newest_admissible) = if stored.is_some() {
            (true, None)
        } else {
            // What a channel that may lift this tier's row already staged.
            let lifting: &[&str] = match tier {
                TrustTierV1::Verified => &["pull", "push"],
                TrustTierV1::Reported => &["pull", "push", "import"],
            };
            let row: PgRow = sqlx::query(ITEM_SEEN_SQL)
                .bind(self.tenant_id)
                .bind(&self.project)
                .bind(key.as_bytes().as_slice())
                .bind(lifting)
                .fetch_one(&mut **transaction)
                .await?;
            let newest: Option<i64> = row.try_get("newest_admissible")?;
            (
                row.try_get::<bool, _>("seen")?,
                newest.and_then(|newest| u64::try_from(newest).ok()),
            )
        };
        let Some(next) = after_refusal(stored, draft.order_micros, seen, newest_admissible) else {
            return Ok(());
        };
        sqlx::query(WITHDRAW_ITEM_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(key.as_bytes().as_slice())
            .bind(tier.as_str())
            .bind(order_i64(next.order))
            .bind(refusal.as_str())
            .bind(self.mode.as_str())
            .bind(self.instance.connector_instance_id.as_str())
            .bind(now)
            .execute(&mut **transaction)
            .await?;
        withdrawals.insert((key, tier), next);
        outcome.items_withdrawn += 1;
        Ok(())
    }

    /// An admissible observation of an item at `order`: lift every withdrawal
    /// of it this channel may lift.
    async fn lift_item(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        key: Sha256Digest,
        order: u64,
        now: DateTime<Utc>,
        withdrawals: &mut ItemWithdrawals,
        outcome: &mut StageOutcomeV1,
    ) -> Result<()> {
        let observer = self.mode.trust_tier();
        for tier in [TrustTierV1::Verified, TrustTierV1::Reported] {
            if !may_lift(observer, tier) {
                continue;
            }
            let Some(stored) = withdrawals.get(&(key, tier)).copied() else {
                continue;
            };
            let Some(next) = after_admission(stored, order) else {
                continue;
            };
            sqlx::query(LIFT_ITEM_SQL)
                .bind(self.tenant_id)
                .bind(&self.project)
                .bind(key.as_bytes().as_slice())
                .bind(tier.as_str())
                .bind(order_i64(next.order))
                .bind(self.mode.as_str())
                .bind(self.instance.connector_instance_id.as_str())
                .bind(now)
                .execute(&mut **transaction)
                .await?;
            withdrawals.insert((key, tier), next);
            if stored.withdrawn {
                outcome.item_withdrawals_lifted += 1;
            }
        }
        Ok(())
    }

    /// Stage one draft, or dead-letter it.
    #[allow(clippy::too_many_lines)] // one linear scope -> audience -> seal -> clock -> insert pipeline
    async fn stage_one(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        staged: &StageDraftV1,
        (observed_at, now): (&CanonicalTimestamp, DateTime<Utc>),
        withdrawals: &mut ItemWithdrawals,
        outcome: &mut StageOutcomeV1,
    ) -> Result<StagedItemV1> {
        let draft = &staged.draft;
        let letter =
            |reason: DeadLetterReasonV1, diagnostic: &str, stage_id: Option<Sha256Digest>| {
                DraftLetter {
                    reason,
                    diagnostic: bounded(diagnostic, MAX_DEAD_LETTER_DIAGNOSTIC_BYTES),
                    stage_id,
                }
            };
        if draft.provider != self.instance.provider
            || draft.provider_scope_id != self.instance.provider_scope_id.as_str()
        {
            return self
                .dead_letter(
                    transaction,
                    staged,
                    letter(
                        DeadLetterReasonV1::ValidationFailed,
                        "provider_scope_mismatch: the item's provider scope is not the \
                         collector instance's",
                        None,
                    ),
                    now,
                )
                .await;
        }
        if staged.delivery_id.is_empty() || staged.delivery_id.len() > MAX_DELIVERY_ID_BYTES {
            return self
                .dead_letter(
                    transaction,
                    staged,
                    letter(
                        DeadLetterReasonV1::ValidationFailed,
                        "a delivery id is 1 to 64 bytes",
                        None,
                    ),
                    now,
                )
                .await;
        }
        let container_key = draft.container.as_ref().map(|container| {
            derive_container_key(
                &draft.provider,
                &draft.provider_scope_id,
                &container.kind,
                &container.id,
            )
        });
        let known = match &container_key {
            Some(key) => known_container(transaction, self.tenant_id, &self.project, key).await?,
            None => KnownContainerV1::Unknown,
        };
        // A direct conversation is one by its kind, whatever the channel or
        // the caller said: no scope, declaration, or record admits it.
        let direct = draft
            .container
            .as_ref()
            .is_some_and(|container| is_direct_container_kind(&container.kind));
        let provider_audience = if direct {
            Some(ProviderAudienceV1::DirectMessage)
        } else {
            staged.provider_audience.or_else(|| {
                draft.container.as_ref().and_then(|container| {
                    self.containers
                        .iter()
                        .find(|observed| {
                            observed.kind == container.kind && observed.id == container.id
                        })
                        .map(|observed| observed.provider_audience)
                })
            })
        };
        let decision = classify(&AudienceInputV1 {
            mode: self.mode,
            provider: draft.provider.as_str(),
            provider_scope_id: &draft.provider_scope_id,
            container_id: draft.container_id(),
            provider_audience,
            hint: draft.visibility,
            policy: &self.policy,
            capture_scopes: &self.capture_scopes,
            known_container: known,
        });
        let basis = match decision {
            AudienceDecisionV1::Admit(basis) => basis,
            AudienceDecisionV1::Refuse(refusal) => {
                if observes_item_audience(self.mode) && narrows_item(refusal) {
                    self.withdraw_item(transaction, draft, refusal, now, withdrawals, outcome)
                        .await?;
                }
                return self
                    .dead_letter(
                        transaction,
                        staged,
                        letter(DeadLetterReasonV1::AudienceRefused, refusal.as_str(), None),
                        now,
                    )
                    .await;
            }
        };
        let sealed = match seal(
            draft,
            &SealContextV1 {
                redactor: &self.redactor,
                audience: basis,
                collection: &self.collection,
            },
        ) {
            Ok(sealed) => sealed,
            Err(refusal) => {
                return self
                    .dead_letter(
                        transaction,
                        staged,
                        letter(
                            DeadLetterReasonV1::of_refusal(refusal),
                            &refusal.to_string(),
                            None,
                        ),
                        now,
                    )
                    .await;
            }
        };
        // A reported order is the agent's or the importer's word, and the head
        // only ever moves to a greater one: an order ahead of the observation
        // would present that version for good. It is refused as the provider
        // clock is, never clamped.
        if self.mode.trust_tier() == TrustTierV1::Reported
            && sealed.provider_order > observed_micros(observed_at)?
        {
            return self
                .dead_letter(
                    transaction,
                    staged,
                    letter(
                        DeadLetterReasonV1::ClockAhead,
                        "the reported order is ahead of the observation",
                        sealed.parts.first().map(|part| part.stage_id),
                    ),
                    now,
                )
                .await;
        }
        for part in &sealed.parts {
            let refusal = if part.envelope.occurred_at(observed_at) > *observed_at {
                Some((
                    DeadLetterReasonV1::ClockAhead,
                    "the provider clock is ahead of the observation",
                ))
            } else if part.envelope.validate_observed(observed_at).is_err() {
                Some((
                    DeadLetterReasonV1::ValidationFailed,
                    "a sealed part failed the collected-item contract",
                ))
            } else {
                None
            };
            if let Some((reason, diagnostic)) = refusal {
                return self
                    .dead_letter(
                        transaction,
                        staged,
                        letter(reason, diagnostic, Some(part.stage_id)),
                        now,
                    )
                    .await;
            }
        }
        let mut new_rows = 0_u32;
        for part in &sealed.parts {
            let occurred = part.envelope.occurred_at(observed_at);
            let occurred = parse_timestamp(&occurred).ok_or_else(|| {
                FleetError::Memory("a provider clock is not canonical".to_owned())
            })?;
            let written = sqlx::query(INSERT_OUTBOX_SQL)
                .bind(self.tenant_id)
                .bind(&self.project)
                .bind(part.stage_id.as_bytes().as_slice())
                .bind(self.instance.connector_instance_id.as_str())
                .bind(self.principal.as_str())
                .bind(self.mode.as_str())
                .bind(self.attester.as_ref().map(ContractId::as_str))
                .bind(self.instance.provider.as_str())
                .bind(self.instance.provider_scope_id.as_str())
                .bind(sealed.item_key.as_bytes().as_slice())
                .bind(sealed.version_key.as_bytes().as_slice())
                .bind(sealed.container_key.map(|key| key.as_bytes().to_vec()))
                .bind(i64::from(part.envelope.part.ordinal))
                .bind(i64::from(part.envelope.part.count))
                .bind(order_i64(sealed.provider_order))
                .bind(self.pass_seq)
                .bind(part.canonical_envelope.as_slice())
                .bind(Sha256::digest(&part.canonical_envelope).as_slice())
                .bind(staged.delivery_id.as_slice())
                .bind(occurred)
                .bind(now)
                .execute(&mut **transaction)
                .await?
                .rows_affected();
            if written == 1 {
                new_rows += 1;
                outcome.rows_staged += 1;
            } else {
                outcome.rows_already_staged += 1;
            }
        }
        if observes_item_audience(self.mode) {
            self.lift_item(
                transaction,
                sealed.item_key,
                sealed.provider_order,
                now,
                withdrawals,
                outcome,
            )
            .await?;
        }
        Ok(StagedItemV1::Staged {
            item_key: sealed.item_key,
            version_key: sealed.version_key,
            stage_ids: sealed.stage_ids(),
            new_rows,
            redaction: sealed.redaction,
        })
    }

    /// Record a refused draft as a digest-only dead letter.
    async fn dead_letter(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        staged: &StageDraftV1,
        letter: DraftLetter,
        now: DateTime<Utc>,
    ) -> Result<StagedItemV1> {
        let payload = draft_digest(&staged.draft);
        let id = dead_letter_id(
            self.instance.connector_instance_id.as_str(),
            letter.reason,
            &payload,
            letter.stage_id.as_ref(),
        );
        let delivery = (!staged.delivery_id.is_empty()
            && staged.delivery_id.len() <= MAX_DELIVERY_ID_BYTES)
            .then_some(staged.delivery_id.as_slice());
        sqlx::query(INSERT_DEAD_LETTER_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(id.as_bytes().as_slice())
            .bind(self.instance.connector_instance_id.as_str())
            .bind(self.mode.as_str())
            .bind(self.instance.provider.as_str())
            .bind(letter.reason.as_str())
            .bind(letter.stage_id.map(|stage_id| stage_id.as_bytes().to_vec()))
            .bind(delivery)
            .bind(payload.as_bytes().as_slice())
            .bind(letter.diagnostic.as_str())
            .bind(now)
            .execute(&mut **transaction)
            .await?;
        Ok(StagedItemV1::Refused {
            reason: letter.reason,
            diagnostic: letter.diagnostic,
        })
    }
}

/// A dead letter for one refused draft.
struct DraftLetter {
    reason: DeadLetterReasonV1,
    diagnostic: String,
    stage_id: Option<Sha256Digest>,
}

/// Validate one container observation and decide its audience.
fn prepare_container(
    context: &StageContextV1<'_>,
    observation: &ContainerObservationV1,
) -> Result<PreparedContainerV1> {
    if has_hidden_scalar(&observation.id) {
        return Err(FleetError::Configuration(
            "a container id holds a hidden scalar".to_owned(),
        ));
    }
    let id = BoundedTextV1::<MAX_LABEL_BYTES>::new(observation.id.clone())
        .map_err(|_| {
            FleetError::Configuration("a container id is not a bounded NFC line".to_owned())
        })?
        .as_str()
        .to_owned();
    if !scan_collected_secrets(&id).is_empty() {
        return Err(FleetError::Configuration(
            "a container id holds a secret shape".to_owned(),
        ));
    }
    let label = observation.label.as_deref().and_then(|label| {
        match context
            .redactor
            .redact(&sanitize_line(label).text)
            .disposition
        {
            CollectorDispositionV1::Stage { text } => {
                let text = truncate_on_char_boundary(text, MAX_LABEL_BYTES);
                let text = text.trim_end();
                // Shortening can complete a shape, as the sealer knows.
                (!text.is_empty() && scan_collected_secrets(text).is_empty())
                    .then(|| text.to_owned())
            }
            CollectorDispositionV1::Withhold { .. } => None,
        }
    });
    let decision = classify(&AudienceInputV1 {
        mode: context.mode,
        provider: context.instance.provider.as_str(),
        provider_scope_id: context.instance.provider_scope_id.as_str(),
        container_id: Some(&id),
        provider_audience: Some(observation.provider_audience),
        hint: None,
        policy: context.policy,
        capture_scopes: &[],
        known_container: KnownContainerV1::Unknown,
    });
    Ok(PreparedContainerV1 {
        key: derive_container_key(
            &context.instance.provider,
            context.instance.provider_scope_id.as_str(),
            &observation.kind,
            &id,
        ),
        kind: observation.kind.clone(),
        id,
        label,
        provider_audience: observation.provider_audience,
        decision,
    })
}

/// The item key a draft names, derived exactly as sealing derives it.
fn draft_item_key(draft: &CollectedItemDraftV1) -> Sha256Digest {
    derive_item_key(
        &draft.provider,
        &draft.provider_scope_id,
        &draft.object_kind,
        &draft.external_id,
    )
}

/// A provider order or pass sequence as `INT8`; every bound the contracts
/// put on them is inside it.
fn order_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn parse_timestamp(value: &CanonicalTimestamp) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value.as_str())
        .ok()
        .map(|parsed| parsed.with_timezone(&Utc))
}

/// The staging clock in microseconds, on the provider order's axis.
fn observed_micros(observed_at: &CanonicalTimestamp) -> Result<u64> {
    timestamp_micros(observed_at)
        .map_err(|error| FleetError::Memory(format!("the staging clock has no order: {error}")))
}

// ---------------------------------------------------------------------------
// The drain's projection
// ---------------------------------------------------------------------------

/// Everything the projection writes about one admitted part.
struct AdmittedPartV1 {
    stage_id: Sha256Digest,
    item_key: Sha256Digest,
    version_key: Sha256Digest,
    part_ordinal: u32,
    part_count: u32,
    provider: String,
    provider_scope_id: String,
    object_kind: String,
    external_id: String,
    mode: CollectionModeV1,
    tier: TrustTierV1,
    instance: String,
    attester: Option<String>,
    lifecycle: ItemLifecycleV1,
    marker: String,
    provider_order: u64,
    redaction_profile: u32,
    container_key: Option<Sha256Digest>,
    thread_root: Option<String>,
    author_id: Option<String>,
    author_kind: Option<String>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
    provider_url: Option<String>,
    canonical_resource_id: String,
    body_content_id: Sha256Digest,
    content_digest: Sha256Digest,
    audience_basis: AudienceBasisV1,
    links: Vec<(String, String)>,
}

impl AdmittedPartV1 {
    fn of(ingress: &CollectedIngressV1, mode: CollectionModeV1) -> Option<Self> {
        let envelope: &CollectedItemEnvelopeV1 = &ingress.envelope;
        let clock = |value: &Option<CanonicalTimestamp>| {
            value
                .as_ref()
                .map_or(Some(None), |value| parse_timestamp(value).map(Some))
        };
        Some(Self {
            stage_id: ingress.stage_id,
            item_key: envelope.item_key(),
            version_key: envelope.version_key(),
            part_ordinal: envelope.part.ordinal,
            part_count: envelope.part.count,
            provider: envelope.provider.as_str().to_owned(),
            provider_scope_id: envelope.provider_scope_id.as_str().to_owned(),
            object_kind: envelope.object_kind.as_str().to_owned(),
            external_id: envelope.external_id.as_str().to_owned(),
            mode,
            tier: mode.trust_tier(),
            instance: envelope.collection.collector_instance.as_str().to_owned(),
            attester: envelope
                .collection
                .attester
                .as_ref()
                .map(|attester| attester.as_str().to_owned()),
            lifecycle: envelope.lifecycle,
            marker: envelope.version.marker.as_str().to_owned(),
            provider_order: envelope.version.order_micros,
            redaction_profile: envelope.redaction.profile_version,
            container_key: envelope.container_key(),
            thread_root: envelope
                .thread
                .as_ref()
                .map(|thread| thread.root_external_id.as_str().to_owned()),
            author_id: envelope
                .author
                .as_ref()
                .map(|author| author.id.as_str().to_owned()),
            author_kind: envelope
                .author
                .as_ref()
                .map(|author| author.kind.as_str().to_owned()),
            created_at: clock(&envelope.created_at)?,
            updated_at: clock(&envelope.updated_at)?,
            provider_url: envelope
                .provider_url
                .as_ref()
                .map(|url| url.as_str().to_owned()),
            canonical_resource_id: ingress
                .candidate
                .source_fact
                .canonical_resource_id
                .to_string(),
            body_content_id: body_digest(&ingress.canonical_payload),
            content_digest: envelope.content_digest,
            audience_basis: envelope.audience.basis,
            links: envelope
                .links
                .iter()
                .map(|link| {
                    (
                        link.rel.as_str().to_owned(),
                        link.target.as_str().to_owned(),
                    )
                })
                .collect(),
        })
    }

    const fn completed(&self) -> CompletedVersionV1 {
        CompletedVersionV1 {
            version_key: self.version_key,
            content_digest: self.content_digest,
            provider_order: self.provider_order,
            redaction_profile: self.redaction_profile,
            lifecycle: self.lifecycle,
            part_count: self.part_count,
            container_key: self.container_key,
        }
    }
}

/// The projection one collected append commits with its event: the governed
/// content object, the outbox row settled as admitted with its envelope
/// dropped, the item history row and its links, and, when the part completes
/// its version, the head move. One transaction (EVENT-03).
struct CollectedDrainProjection {
    content: GovernedContentProjection,
    tenant_id: Uuid,
    project: String,
    part: AdmittedPartV1,
}

fn integrity(message: &str) -> EvidenceAppendError {
    EvidenceAppendError::LedgerIntegrity(message.to_owned())
}

/// One stored tier row, as the move rule reads it.
struct StoredHeadV1 {
    head: TierHeadV1,
    presented: bool,
    disagreement: bool,
}

fn decode_head(row: &PgRow) -> EvidenceAppendResult<(TrustTierV1, StoredHeadV1)> {
    let tier = TrustTierV1::parse(&row.try_get::<String, _>("trust_tier")?)?;
    let lifecycle = ItemLifecycleV1::parse(&row.try_get::<String, _>("lifecycle")?)?;
    let count = |column: &str| -> EvidenceAppendResult<u64> {
        u64::try_from(row.try_get::<i64, _>(column)?)
            .map_err(|_| integrity("a stored head count is negative"))
    };
    let version = CompletedVersionV1 {
        version_key: digest_column(row, "version_key_digest")?,
        content_digest: digest_column(row, "content_digest")?,
        provider_order: count("provider_order")?,
        redaction_profile: u32::try_from(count("redaction_profile")?)
            .map_err(|_| integrity("a stored redaction profile is out of range"))?,
        lifecycle,
        part_count: u32::try_from(count("part_count")?)
            .map_err(|_| integrity("a stored part count is out of range"))?,
        container_key: optional_digest_column(row, "container_key")?,
    };
    Ok((
        tier,
        StoredHeadV1 {
            head: TierHeadV1 {
                version,
                version_count: count("version_count")?,
                order_ties: count("order_ties")?,
                revision: count("revision")?,
            },
            presented: row.try_get("presented")?,
            disagreement: row.try_get("disagreement")?,
        },
    ))
}

/// One tier row after the move, and what to write for it.
struct HeadPlanV1 {
    tier: TrustTierV1,
    head: TierHeadV1,
    content_changed: bool,
    stored_flags: Option<(bool, bool)>,
    presented: bool,
    disagreement: bool,
}

impl CollectedDrainProjection {
    async fn write_history(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        event: &Sha256Digest,
        now: DateTime<Utc>,
    ) -> EvidenceAppendResult<()> {
        let part = &self.part;
        sqlx::query(INSERT_ITEM_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(event.as_bytes().as_slice())
            .bind(part.stage_id.as_bytes().as_slice())
            .bind(part.item_key.as_bytes().as_slice())
            .bind(part.version_key.as_bytes().as_slice())
            .bind(i64::from(part.part_ordinal))
            .bind(i64::from(part.part_count))
            .bind(&part.provider)
            .bind(&part.provider_scope_id)
            .bind(&part.object_kind)
            .bind(&part.external_id)
            .bind(part.mode.as_str())
            .bind(part.tier.as_str())
            .bind(&part.instance)
            .bind(part.attester.as_deref())
            .bind(part.lifecycle.as_str())
            .bind(&part.marker)
            .bind(order_i64(part.provider_order))
            .bind(i64::from(part.redaction_profile))
            .bind(part.container_key.map(|key| key.as_bytes().to_vec()))
            .bind(part.thread_root.as_deref())
            .bind(part.author_id.as_deref())
            .bind(part.author_kind.as_deref())
            .bind(part.created_at)
            .bind(part.updated_at)
            .bind(part.provider_url.as_deref())
            .bind(&part.canonical_resource_id)
            .bind(part.body_content_id.as_bytes().as_slice())
            .bind(part.content_digest.as_bytes().as_slice())
            .bind(part.audience_basis.as_str())
            .bind(now)
            .execute(&mut **transaction)
            .await?;
        for (ordinal, (rel, target)) in (0_i64..).zip(&part.links) {
            sqlx::query(INSERT_LINK_SQL)
                .bind(self.tenant_id)
                .bind(&self.project)
                .bind(event.as_bytes().as_slice())
                .bind(ordinal)
                .bind(rel)
                .bind(target)
                .execute(&mut **transaction)
                .await?;
        }
        Ok(())
    }

    /// Apply the move rule to the item's tier rows, then present the result.
    async fn advance_heads(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        event: &Sha256Digest,
        now: DateTime<Utc>,
    ) -> EvidenceAppendResult<()> {
        let part = &self.part;
        let rows: Vec<PgRow> = sqlx::query(LOCK_HEADS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(part.item_key.as_bytes().as_slice())
            .fetch_all(&mut **transaction)
            .await?;
        let mut stored = BTreeMap::new();
        for row in &rows {
            let (tier, head) = decode_head(row)?;
            stored.insert(tier, head);
        }
        let (moved, _) = advance_tier_head(
            stored.get(&part.tier).map(|stored| &stored.head),
            &part.completed(),
        );
        let mut plans = Vec::with_capacity(2);
        for tier in [TrustTierV1::Verified, TrustTierV1::Reported] {
            let before = stored.remove(&tier);
            let stored_flags = before
                .as_ref()
                .map(|before| (before.presented, before.disagreement));
            let (head, content_changed) = match (&moved, tier == part.tier) {
                (Some(moved), true) => (Some(moved.clone()), true),
                _ => (before.map(|before| before.head), false),
            };
            if let Some(head) = head {
                plans.push(HeadPlanV1 {
                    tier,
                    head,
                    content_changed,
                    stored_flags,
                    presented: false,
                    disagreement: false,
                });
            }
        }
        let version_of = |tier: TrustTierV1| {
            plans
                .iter()
                .find(|plan| plan.tier == tier)
                .map(|plan| plan.head.version.clone())
        };
        let (verified, reported) = (
            version_of(TrustTierV1::Verified),
            version_of(TrustTierV1::Reported),
        );
        let Some(presentation) = present(verified.as_ref(), reported.as_ref()) else {
            return Ok(());
        };
        for plan in &mut plans {
            plan.presented = plan.tier == presentation.presented;
            plan.disagreement = plan.presented && presentation.disagreement;
        }
        // One presented row per item is a unique index: demote before
        // promoting.
        plans.sort_by_key(|plan| plan.presented);
        for plan in &plans {
            if plan.content_changed {
                self.write_head(transaction, plan, event, now).await?;
            } else if plan.stored_flags != Some((plan.presented, plan.disagreement)) {
                sqlx::query(UPDATE_HEAD_PRESENTATION_SQL)
                    .bind(self.tenant_id)
                    .bind(&self.project)
                    .bind(part.item_key.as_bytes().as_slice())
                    .bind(plan.tier.as_str())
                    .bind(plan.presented)
                    .bind(plan.disagreement)
                    .bind(now)
                    .execute(&mut **transaction)
                    .await?;
            }
        }
        Ok(())
    }

    async fn write_head(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        plan: &HeadPlanV1,
        event: &Sha256Digest,
        now: DateTime<Utc>,
    ) -> EvidenceAppendResult<()> {
        let part = &self.part;
        let head = &plan.head;
        let count =
            |value: u64| i64::try_from(value).map_err(|_| integrity("a head count exceeds INT8"));
        sqlx::query(UPSERT_HEAD_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(part.item_key.as_bytes().as_slice())
            .bind(plan.tier.as_str())
            .bind(plan.presented)
            .bind(&part.provider)
            .bind(&part.provider_scope_id)
            .bind(&part.object_kind)
            .bind(&part.external_id)
            .bind(
                head.version
                    .container_key
                    .map(|key| key.as_bytes().to_vec()),
            )
            .bind(head.version.version_key.as_bytes().as_slice())
            .bind(head.version.content_digest.as_bytes().as_slice())
            .bind(count(head.version.provider_order)?)
            .bind(i64::from(head.version.redaction_profile))
            .bind(head.version.lifecycle.as_str())
            .bind(i64::from(head.version.part_count))
            .bind(count(head.version_count)?)
            .bind(count(head.order_ties)?)
            .bind(plan.disagreement)
            .bind(event.as_bytes().as_slice())
            .bind(count(head.revision)?)
            .bind(now)
            .execute(&mut **transaction)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl AppendProjection for CollectedDrainProjection {
    async fn project(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: ProjectionContext,
    ) -> EvidenceAppendResult<()> {
        self.content.project(transaction, context).await?;
        let now = statement_time(transaction).await?;
        let event = context.accepted_event_id.digest();
        let part = &self.part;
        let settled = sqlx::query(MARK_ADMITTED_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(part.stage_id.as_bytes().as_slice())
            .bind(event.as_bytes().as_slice())
            .bind(now)
            .execute(&mut **transaction)
            .await?
            .rows_affected();
        if settled != 1 {
            return Err(integrity(
                "the staged collector row was not pending when its event was appended",
            ));
        }
        let state: PgRow = sqlx::query(PART_STATE_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(part.item_key.as_bytes().as_slice())
            .bind(part.version_key.as_bytes().as_slice())
            .bind(part.tier.as_str())
            .bind(i64::from(part.part_ordinal))
            .fetch_one(&mut **transaction)
            .await?;
        let distinct_before = u32::try_from(state.try_get::<i64, _>("distinct_parts")?)
            .map_err(|_| integrity("a version's admitted part count is out of range"))?;
        let already_admitted: bool = state.try_get("has_part")?;
        self.write_history(transaction, &event, now).await?;
        if part_completes_version(already_admitted, distinct_before, part.part_count) {
            self.advance_heads(transaction, &event, now).await?;
        }
        Ok(())
    }
}

#[path = "sink_reads.rs"]
mod reads;

pub use reads::{CollectorDeadLetterV1, KnownVersionV1, OutboxRowStateV1};

#[path = "sink_operator.rs"]
mod operator;

pub use operator::{
    AdoptedRowV1, CollectorCursorRowV1, CollectorInstanceStatusV1, CollectorSourceRowV1,
    CollectorStatusReportV1, DeadLetterListingV1, DeadLetterRowV1, ImportCompletionV1,
    MAX_LISTED_DEAD_LETTERS, MAX_STATUS_CURSORS, PassUnsettledV1, RetireImportV1,
};

#[cfg(test)]
#[path = "sink_tests.rs"]
mod tests;
