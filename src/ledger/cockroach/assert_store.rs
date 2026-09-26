//! Event-first `remember(action="assert")` for the `CockroachDB` claim ledger
//! (ADR 0002 D3, EVENT-03).
//!
//! # Order
//!
//! Outside any transaction, an assert:
//!
//! 1. replays a receipt already committed under its idempotency key;
//! 2. re-verifies the pinned writer authority
//!    ([`WriterAuthorityRuntime::verify`](crate::registry_witness::WriterAuthorityRuntime::verify));
//! 3. resolves the collected items the assertion cites (`support_items`,
//!    ADR 0008 D11) in this scope and merges their parts' events into its
//!    support event IDs;
//! 4. routes and admits the assertion against the package that head
//!    activates ([`admit_remember_assertion`]), with the server clock;
//! 5. embeds the claim passages, so no model call holds a SQL lock.
//!
//! Then ONE serializable transaction, the accepted-event append, re-reads the
//! head, inserts the `memory.claim.accepted` event, and runs
//! [`ClaimAssertProjection`], which in that same transaction:
//!
//! 1. re-audits every support event ID against this scope's ledger, and,
//!    where claim item links are served, refuses any support event that is a
//!    collected item hidden from recall now (cited through `support_items`
//!    or listed directly);
//! 2. reserves the idempotency receipt, naming the event;
//! 3. checks the active embedding model;
//! 4. writes the claim projection `record` writes, plus the event's ID, and
//!    one private link per cited item part, a directly listed collected-item
//!    event included;
//! 5. runs the unchanged functional-value conflict detector;
//! 6. writes the `claim_recorded` audit event, naming the event;
//! 7. completes the receipt with the committed response.
//!
//! Any failure rolls back the event with its projection. A refusal writes
//! nothing and leaves the key free. Only SQLSTATE 40001 is retried; a head
//! that moved between admission and append is refused as
//! `registry_head_changed`, never re-admitted behind the caller's back.
//!
//! # Replay
//!
//! The same key and request replay the stored response. An identical
//! accepted statement under a NEW key (only possible when the caller pins
//! `effective_from`, since the default is the server clock) is not written
//! twice: the ledger reports it as a replay without running the projection,
//! and the assert is refused as `already_asserted`, naming the claim that
//! statement already projects. That key stays unconsumed.
//!
//! # What the claim row is
//!
//! The legacy projection of the admitted statement: the assertion kind's
//! claim kind, `claim-v2:<coordinate id>:<modality>` as its key, the
//! rederived subject URI, the predicate entry ID, the canonical tagged value,
//! polarity `1`/`-1`, the effective interval as `valid_from`/`valid_to`,
//! origin `operator_asserted`, the agent as actor, confidence `1.0`, and
//! conflict eligibility. The lifecycle (`retract`, `resolve`, `acknowledge`,
//! `dismiss`, `waive`) then acts on that projection exactly as on a recorded
//! claim; the accepted event stays in the ledger. The non-null
//! `accepted_event_id` is what the publication reader withholds the claim,
//! its synthetic chunk, and its conflicts by
//! ([`CockroachMemoryService::publication`](crate::CockroachMemoryService::publication)),
//! since the predicate's publication default is denied.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};

use super::item_links::{
    CitationV1, ResolvedItemV1, audit_cited_events, insert_assert_links, item_support_unavailable,
    resolve_citations,
};
use super::lifecycle_store::{Replayable, bounded_ids};
use super::{
    ClaimPassage, CockroachClaimLedger, MAX_IDEMPOTENCY_KEY_BYTES, claim_recorded_event_payload,
    detect_and_observe, insert_claim_projection, insert_claim_recorded_event, protocol_error,
    replayed_mutation, require_active_model,
};
use crate::evidence_ledger::{
    AcceptedEventKindV1, AcceptedEventRepository as _, AppendOutcome, AppendProjection,
    AppendableAcceptedEvent, EvidenceAppendError, EvidenceAppendResult, ProjectionContext,
};
use crate::ledger::lifecycle::OPERATOR_ASSERTED_ORIGIN;
use crate::ledger::types::PreparedClaim;
use crate::ledger::{
    AcceptedEventRefV1, AssertedClaimMutation, ClaimInput, ClaimMutation, LifecycleRefusal,
    MAX_SUPPORT_ITEMS, RefusalCode, assert_unavailable, canonical_json,
};
use crate::memory_contracts::common::CanonicalTimestamp;
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::registry_witness::WriterAuthorityError;
use crate::remember_runtime::{
    AdmittedRememberAssertionV1, RememberAdmissionRefusal, RememberAdmissionRefusalReason,
    RememberAssertInputV1, admit_remember_assertion, claim_kind_for, claim_polarity_for,
};
use crate::{FleetError, FleetScope, Result};

const ASSERT_OPERATION: &str = "assert";

/// Which of the requested support events this scope's ledger holds. The
/// `(tenant_id, project, event_id)` unique index answers it.
const KNOWN_SUPPORT_EVENTS_SQL: &str = "SELECT event_id FROM memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND event_id = ANY($3)";
/// The tenant-wide key is reserved with the event it will name, as record
/// reserves its key.
const RESERVE_ASSERT_RECEIPT_SQL: &str = "INSERT INTO memory_mutation_receipts (\
         tenant_id, idempotency_key, project, request, operation, accepted_event_id\
     ) VALUES ($1, $2, $3, $4, 'assert', $5) \
     ON CONFLICT (tenant_id, idempotency_key) DO NOTHING \
     RETURNING idempotency_key";
const FINISH_ASSERT_RECEIPT_SQL: &str = "UPDATE memory_mutation_receipts \
     SET claim_id = $5, response = $6 \
     WHERE tenant_id = $1 AND idempotency_key = $2 \
       AND project = $3 AND request = $4 AND operation = 'assert'";
/// The claim an already-accepted statement projects, found by its key and
/// then its event.
const CLAIM_BY_ACCEPTED_EVENT_SQL: &str = "SELECT id \
     FROM memory_claims@memory_claims_scope_key_idx \
     WHERE tenant_id = $1 AND project = $2 AND claim_key = $3 AND accepted_event_id = $4 \
     ORDER BY id LIMIT 1";
const CLAIM_ACCEPTED_EVENT_SQL: &str = "SELECT accepted_event_id FROM memory_claims \
     WHERE tenant_id = $1 AND project = $2 AND id = $3";
/// Which of the given claims an assert projected, by primary key.
const ASSERTED_CLAIM_IDS_SQL: &str = "SELECT id FROM memory_claims@primary \
     WHERE tenant_id = $1 AND project = $2 AND id = ANY($3) \
       AND accepted_event_id IS NOT NULL \
     ORDER BY id";

/// Serve one assert. See the module documentation for the order.
pub(super) async fn assert_claim(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    input: &RememberAssertInputV1,
    idempotency_key: &str,
) -> Result<AssertedClaimMutation> {
    let Some(assert) = ledger.event_first_assert.as_ref() else {
        return Err(assert_unavailable());
    };
    ledger.ensure_scope(scope)?;
    let key = idempotency_key.trim();
    if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(FleetError::Memory(format!(
            "idempotency_key must be between 1 and {MAX_IDEMPOTENCY_KEY_BYTES} bytes"
        )));
    }
    let request = assert_request(scope, input);
    // A non-transactional fast path avoids verifying, admitting, and
    // embedding a known replay. The append transaction reserves the key
    // again, so a concurrent first assert stays at-most-once.
    if let Some(replayed) =
        replayed_mutation(&ledger.pool, scope, key, &request, ASSERT_OPERATION).await?
    {
        return Ok(replayed);
    }
    if !input.support_items.is_empty() && ledger.claim_item_links.is_none() {
        return Err(item_support_unavailable());
    }

    let verified = assert
        .authority()
        .verify()
        .await
        .map_err(writer_authority_unavailable)?;
    let package = verified.witness().package();
    let route = assert.route(package).map_err(|error| {
        refusal(
            RefusalCode::AssertUnavailable,
            format!("the active registry package serves no assert route: {error}"),
            json!({}),
        )
    })?;
    // Cited items resolve to their events before admission, so the admitted
    // statement cites events only; the append transaction audits them again.
    let (cited_items, resolved_input) = resolve_support_items(ledger, scope, input).await?;
    let admitted = admit_remember_assertion(
        &route,
        package,
        verified.head_binding(),
        assert.authority().semantic_scope(),
        assert.actor(),
        resolved_input.as_ref().unwrap_or(input),
        Utc::now(),
    )
    .map_err(admission_refused)?;
    let (claim_input, prepared) = claim_projection(scope, input, &admitted)?;
    let passages = ledger.embed_claim_passages(scope, &claim_input, &prepared)?;

    let appendable = AppendableAcceptedEvent::admitted_memory_claim(
        admitted.admitted(),
        verified.append_witness(),
    )
    .map_err(append_failure)?;
    let projection = Arc::new(ClaimAssertProjection {
        scope: scope.clone(),
        key: key.to_owned(),
        request: request.clone(),
        input: claim_input,
        prepared,
        passages,
        model: ledger.claim_model.clone(),
        accepted_event_id: admitted.accepted_event_id(),
        support_event_ids: admitted
            .admitted()
            .statement()
            .support_evidence_event_ids
            .clone(),
        cited_items,
        links_served: ledger.claim_item_links.is_some(),
        outcome: Mutex::new(None),
    });
    let appended = assert
        .authority()
        .ledger()
        .append(
            verified.append_witness(),
            &appendable,
            Arc::clone(&projection) as Arc<dyn AppendProjection>,
        )
        .await;
    match resolve_append(appended, projection.take_outcome()) {
        AppendResolution::Committed(asserted) => Ok(*asserted),
        AppendResolution::ReadReceipt => {
            replayed_mutation(&ledger.pool, scope, key, &request, ASSERT_OPERATION)
                .await?
                .ok_or_else(|| protocol_error("a concurrently reserved assert receipt disappeared"))
        }
        AppendResolution::AlreadyAppended => {
            replay_or_refuse_duplicate(ledger, scope, key, &request, &admitted).await
        }
        AppendResolution::Fail(error) => Err(error),
    }
}

/// Resolve the assertion's `support_items` in this ledger's scope (ADR 0008
/// D11): the cited items, and the assertion with their events merged into
/// `support_evidence_event_ids` (sorted, without duplicates) and the items
/// removed, which is what admission takes. `None` when it cites no item.
async fn resolve_support_items(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    input: &RememberAssertInputV1,
) -> Result<(Vec<ResolvedItemV1>, Option<RememberAssertInputV1>)> {
    if input.support_items.is_empty() {
        return Ok((Vec::new(), None));
    }
    let support_invalid = |message: String| {
        refusal(
            RefusalCode::AssertionNotAdmitted,
            message,
            json!({ "reason": RememberAdmissionRefusalReason::SupportInvalid.as_str() }),
        )
    };
    if input.support_items.len() > MAX_SUPPORT_ITEMS {
        return Err(support_invalid(format!(
            "at most {MAX_SUPPORT_ITEMS} support_items are admitted"
        )));
    }
    for (index, reference) in input.support_items.iter().enumerate() {
        reference.validate().map_err(|error| {
            support_invalid(match error {
                FleetError::Memory(message) => format!("support_items[{index}]: {message}"),
                other => format!("support_items[{index}]: {other}"),
            })
        })?;
    }
    let fields: Vec<String> = (0..input.support_items.len())
        .map(|index| format!("support_items[{index}]"))
        .collect();
    let citations: Vec<CitationV1<'_>> = fields
        .iter()
        .zip(&input.support_items)
        .map(|(field, reference)| CitationV1 { field, reference })
        .collect();
    let mut connection = ledger.pool.acquire().await?;
    let cited = resolve_citations(&mut connection, scope, &citations).await?;
    drop(connection);
    let mut resolved = input.clone();
    resolved.support_evidence_event_ids = input
        .support_evidence_event_ids
        .iter()
        .copied()
        .chain(cited.iter().flat_map(ResolvedItemV1::event_ids))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    resolved.support_items.clear();
    Ok((cited, Some(resolved)))
}

/// The canonical request a receipt binds: the trusted scope attribution and
/// the assertion as the caller sent it.
fn assert_request(scope: &FleetScope, input: &RememberAssertInputV1) -> Value {
    json!({
        "scope": {
            "project": scope.project,
            "agent": scope.agent,
            "session_id": scope.session_id,
            "privacy_tier": scope.privacy_tier,
        },
        "assertion": input,
    })
}

/// The admitted statement is already accepted, so the append ran no
/// projection. The same statement committed under this very key is a replay
/// of this request (a concurrent retry that won); under any other key it is
/// refused as `already_asserted`, and this key stays free.
async fn replay_or_refuse_duplicate(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    key: &str,
    request: &Value,
    admitted: &AdmittedRememberAssertionV1,
) -> Result<AssertedClaimMutation> {
    if let Some(replayed) =
        replayed_mutation(&ledger.pool, scope, key, request, ASSERT_OPERATION).await?
    {
        return Ok(replayed);
    }
    let event_id = admitted.accepted_event_id();
    let claim_id: Option<i64> = sqlx::query_scalar(CLAIM_BY_ACCEPTED_EVENT_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(admitted.claim_key())
        .bind(digest_bytes(event_id.digest()))
        .fetch_optional(&ledger.pool)
        .await?;
    Err(already_asserted(claim_id, event_id))
}

/// The accepted event a claim projects, by primary key.
pub(super) async fn claim_accepted_event_id(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    claim_id: i64,
) -> Result<Option<AcceptedEventId>> {
    ledger.ensure_scope(scope)?;
    if claim_id <= 0 {
        return Ok(None);
    }
    let stored: Option<Option<Vec<u8>>> = sqlx::query_scalar(CLAIM_ACCEPTED_EVENT_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_id)
        .fetch_optional(&ledger.pool)
        .await?;
    stored
        .flatten()
        .map(|bytes| {
            <[u8; 32]>::try_from(bytes)
                .map(|bytes| AcceptedEventId::from_digest(Sha256Digest::from_bytes(bytes)))
                .map_err(|_| protocol_error("stored claim accepted_event_id is not 32 bytes"))
        })
        .transpose()
}

/// Which of up to 100 claims an assert projected, by primary key.
pub(super) async fn asserted_claim_ids(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    claim_ids: &[i64],
) -> Result<Vec<i64>> {
    ledger.ensure_scope(scope)?;
    let ids = bounded_ids(claim_ids, "claim")?;
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    Ok(sqlx::query_scalar(ASSERTED_CLAIM_IDS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&ids)
        .fetch_all(&ledger.pool)
        .await?)
}

/// The legacy claim row an admitted assertion projects to, as a
/// [`ClaimInput`] for the shared projection helpers and the
/// [`PreparedClaim`] that carries its server-derived key, subject,
/// predicate, and value.
fn claim_projection(
    scope: &FleetScope,
    input: &RememberAssertInputV1,
    admitted: &AdmittedRememberAssertionV1,
) -> Result<(ClaimInput, PreparedClaim)> {
    let claim = &admitted.admitted().statement().claim;
    let value = canonical_json(
        &serde_json::to_value(&claim.value)
            .map_err(|error| protocol_error(format!("serialize admitted claim value: {error}")))?,
    );
    let subject = admitted.subject().to_string();
    let predicate = admitted.predicate().entry_id.to_string();
    let claim_input = ClaimInput {
        kind: claim_kind_for(claim.assertion_kind),
        text: input.text.clone(),
        subject: Some(subject.clone()),
        predicate: Some(predicate.clone()),
        value: Some(value.clone()),
        polarity: claim_polarity_for(claim.polarity),
        origin: OPERATOR_ASSERTED_ORIGIN.to_owned(),
        actor: Some(scope.agent.clone()),
        confidence: 1.0,
        valid_from: Some(utc(&claim.effective_interval.effective_from)?),
        valid_to: claim
            .effective_interval
            .effective_until
            .as_ref()
            .map(utc)
            .transpose()?,
        support: Vec::new(),
    };
    // Admission already enforced every rule this checks; a failure here is a
    // contradiction between the two, not a caller error.
    claim_input.validate().map_err(|error| {
        protocol_error(format!(
            "admitted assertion has no valid claim projection: {error}"
        ))
    })?;
    let prepared = PreparedClaim {
        subject: Some(subject),
        predicate: Some(predicate),
        claim_key: Some(admitted.claim_key().to_owned()),
        value: Some(value),
        conflict_eligible: claim_input.kind.is_conflict_eligible(),
    };
    Ok((claim_input, prepared))
}

fn utc(timestamp: &CanonicalTimestamp) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(timestamp.as_str())
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|error| protocol_error(format!("admitted timestamp does not parse: {error}")))
}

fn digest_bytes(digest: Sha256Digest) -> Vec<u8> {
    digest.as_bytes().to_vec()
}

/// What the projection left behind for the caller of the append.
#[derive(Debug)]
enum ProjectionOutcome {
    /// Everything committed with the event; this is the stored response.
    Committed(Box<AssertedClaimMutation>),
    /// Another transaction holds the key. The projection returned an error
    /// so the event rolled back; the caller re-reads the receipt.
    ReceiptRaced,
}

/// The claim projection of one admitted assertion, run inside the append
/// transaction after the event insert.
///
/// A serializable retry re-runs it in a fresh transaction, so it keeps no
/// state across runs except the outcome of the latest one.
struct ClaimAssertProjection {
    scope: FleetScope,
    key: String,
    request: Value,
    input: ClaimInput,
    prepared: PreparedClaim,
    passages: Vec<ClaimPassage>,
    model: String,
    accepted_event_id: AcceptedEventId,
    support_event_ids: Vec<AcceptedEventId>,
    /// The collected items the assertion cites, resolved before admission;
    /// their events are among `support_event_ids`.
    cited_items: Vec<ResolvedItemV1>,
    /// This ledger serves claim item links: the collected-item tables are
    /// readable, so every support event is audited against them and linked.
    links_served: bool,
    outcome: Mutex<Option<ProjectionOutcome>>,
}

impl ClaimAssertProjection {
    fn set_outcome(&self, outcome: Option<ProjectionOutcome>) {
        *self.outcome.lock().unwrap_or_else(PoisonError::into_inner) = outcome;
    }

    fn take_outcome(&self) -> Option<ProjectionOutcome> {
        self.outcome
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    #[allow(clippy::too_many_lines)] // the event-first projection is kept visibly in one unit
    async fn write(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: ProjectionContext,
    ) -> Result<ProjectionOutcome> {
        if context.kind != AcceptedEventKindV1::MemoryClaim
            || context.accepted_event_id != self.accepted_event_id
        {
            return Err(protocol_error(
                "the append projected another accepted event than the admitted assertion",
            ));
        }
        let scope = &self.scope;
        let event_id = context.accepted_event_id;
        let event_bytes = digest_bytes(event_id.digest());

        // 1. Every support event must already be accepted in this scope, and
        //    none may be a collected item hidden from recall now, whether it
        //    was cited through support_items or listed directly.
        self.audit_support(transaction).await?;
        let direct_items = if self.links_served {
            audit_cited_events(
                transaction,
                scope,
                &self.support_event_ids,
                &self.cited_items,
            )
            .await?
        } else {
            Vec::new()
        };

        // 2. Reserve the key. A conflict means another transaction holds it.
        let reserved = sqlx::query_scalar::<_, String>(RESERVE_ASSERT_RECEIPT_SQL)
            .bind(scope.tenant_id)
            .bind(&self.key)
            .bind(&scope.project)
            .bind(&self.request)
            .bind(&event_bytes)
            .fetch_optional(&mut **transaction)
            .await?;
        if reserved.is_none() {
            return Ok(ProjectionOutcome::ReceiptRaced);
        }

        // 3-6. Exactly record's projection, bound to the event.
        require_active_model(transaction, scope, &self.model).await?;
        let mut claim = insert_claim_projection(
            transaction,
            scope,
            &self.input,
            &self.prepared,
            &self.passages,
            &self.model,
            json!({ "idempotency_key": self.key, "accepted_event_id": event_id }),
            Some(&event_bytes),
            None,
        )
        .await?;
        if self.links_served {
            let linked: Vec<ResolvedItemV1> = self
                .cited_items
                .iter()
                .chain(&direct_items)
                .cloned()
                .collect();
            insert_assert_links(transaction, scope, claim.id, event_id.digest(), &linked).await?;
        }
        let (conflicts_opened, conflict_detection) = detect_and_observe(
            transaction,
            scope,
            &mut claim,
            &self.input,
            &self.prepared,
            None,
        )
        .await?;
        let mut payload =
            claim_recorded_event_payload(claim.claim_key.as_deref(), conflict_detection);
        if let Some(payload) = payload.as_object_mut() {
            payload.insert("accepted_event_id".into(), json!(event_id));
        }
        insert_claim_recorded_event(transaction, scope, claim.id, Some(&self.key), payload).await?;

        // 7. Complete the receipt with the response a replay returns.
        let asserted = AssertedClaimMutation {
            mutation: ClaimMutation {
                operation: ASSERT_OPERATION.into(),
                claim,
                superseded: None,
                idempotent_replay: false,
                conflicts_opened,
                conflicts_resolved: Vec::new(),
                claims_restored: Vec::new(),
                reevaluation: None,
            },
            accepted_event: AcceptedEventRefV1 {
                event_id,
                epoch_id: context.position.epoch_id,
                shard: context.position.shard,
                committed_offset: context.position.committed_offset.as_u64(),
            },
        };
        let response = serde_json::to_value(&asserted)
            .map_err(|error| protocol_error(format!("serialize idempotency response: {error}")))?;
        let receipt = sqlx::query(FINISH_ASSERT_RECEIPT_SQL)
            .bind(scope.tenant_id)
            .bind(&self.key)
            .bind(&scope.project)
            .bind(&self.request)
            .bind(asserted.mutation.claim.id)
            .bind(response)
            .execute(&mut **transaction)
            .await?;
        if receipt.rows_affected() != 1 {
            return Err(protocol_error(
                "idempotency receipt reservation disappeared during assert",
            ));
        }
        Ok(ProjectionOutcome::Committed(Box::new(asserted)))
    }

    /// Refuse as `support_event_unknown` unless this scope's ledger already
    /// holds every support event, read in the append transaction.
    async fn audit_support(&self, transaction: &mut Transaction<'_, Postgres>) -> Result<()> {
        if self.support_event_ids.is_empty() {
            return Ok(());
        }
        let wanted = self
            .support_event_ids
            .iter()
            .map(|id| digest_bytes(id.digest()))
            .collect::<Vec<_>>();
        let known = sqlx::query_scalar::<_, Vec<u8>>(KNOWN_SUPPORT_EVENTS_SQL)
            .bind(self.scope.tenant_id)
            .bind(&self.scope.project)
            .bind(&wanted)
            .fetch_all(&mut **transaction)
            .await?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let unknown = self
            .support_event_ids
            .iter()
            .filter(|id| !known.contains(id.digest().as_bytes().as_slice()))
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if unknown.is_empty() {
            return Ok(());
        }
        Err(refusal(
            RefusalCode::SupportEventUnknown,
            "a support evidence event ID names no accepted event in this project",
            json!({ "unknown_event_ids": unknown }),
        ))
    }
}

#[async_trait]
impl AppendProjection for ClaimAssertProjection {
    async fn project(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: ProjectionContext,
    ) -> EvidenceAppendResult<()> {
        self.set_outcome(None);
        let outcome = self.write(transaction, context).await?;
        let raced = matches!(outcome, ProjectionOutcome::ReceiptRaced);
        self.set_outcome(Some(outcome));
        if raced {
            // Roll the event back with the reservation that lost.
            return Err(EvidenceAppendError::Storage(
                FleetError::IdempotencyConflict(
                    "the idempotency key was reserved by a concurrent mutation".into(),
                ),
            ));
        }
        Ok(())
    }
}

impl Replayable for AssertedClaimMutation {
    fn mark_replayed(&mut self) {
        self.mutation.idempotent_replay = true;
    }
}

/// What to do once the append returned.
#[derive(Debug)]
enum AppendResolution {
    /// The event and its projection committed; this is the response.
    Committed(Box<AssertedClaimMutation>),
    /// The key was reserved concurrently: replay its receipt, or report the
    /// key as used for another request.
    ReadReceipt,
    /// The identical accepted statement was already in the ledger, so the
    /// projection did not run.
    AlreadyAppended,
    Fail(FleetError),
}

/// Classify an append result together with what the projection recorded.
///
/// There is no semantic retry here: a moved head, an unavailable authority,
/// and a quarantine are each reported, never re-admitted.
fn resolve_append(
    appended: EvidenceAppendResult<AppendOutcome>,
    outcome: Option<ProjectionOutcome>,
) -> AppendResolution {
    match (appended, outcome) {
        (Ok(AppendOutcome::Appended { .. }), Some(ProjectionOutcome::Committed(asserted))) => {
            AppendResolution::Committed(asserted)
        }
        (Ok(AppendOutcome::Appended { .. }), _) => AppendResolution::Fail(protocol_error(
            "the accepted event committed without its claim projection",
        )),
        (Ok(AppendOutcome::Replayed { .. }), _) => AppendResolution::AlreadyAppended,
        (Ok(AppendOutcome::Quarantined { reason, .. }), _) => {
            AppendResolution::Fail(FleetError::Memory(format!(
                "the admitted claim event was quarantined: {reason:?}"
            )))
        }
        (Err(_), Some(ProjectionOutcome::ReceiptRaced)) => AppendResolution::ReadReceipt,
        (Err(error), _) => AppendResolution::Fail(append_failure(error)),
    }
}

/// Map an append failure. A moved head and an unusable authority are typed
/// refusals; a refusal the projection raised, and a storage failure, pass
/// through unchanged; anything else is internal.
fn append_failure(error: EvidenceAppendError) -> FleetError {
    match error {
        EvidenceAppendError::WitnessMismatch(kind)
        | EvidenceAppendError::StatementAuthority(kind) => refusal(
            RefusalCode::RegistryHeadChanged,
            "the active registry head changed before the assertion was appended; nothing was \
             written, so assert again",
            json!({ "mismatch": kind.as_str() }),
        ),
        EvidenceAppendError::AuthorityUnavailable(kind) => refusal(
            RefusalCode::WriterAuthorityUnavailable,
            format!("the writer authority is unavailable: {kind}"),
            json!({}),
        ),
        EvidenceAppendError::Storage(inner) => inner,
        other => other.into(),
    }
}

/// Map a failed re-verification of the pinned writer authority. A database
/// failure stays a database failure, so it is reported as unavailable
/// storage rather than as a verdict about the authority.
fn writer_authority_unavailable(error: WriterAuthorityError) -> FleetError {
    match error {
        WriterAuthorityError::Database(error) => FleetError::Database(error),
        WriterAuthorityError::Rejected(rejection) => refusal(
            RefusalCode::WriterAuthorityUnavailable,
            format!("the pinned writer authority did not verify: {rejection}"),
            json!({}),
        ),
        WriterAuthorityError::Contract(error) => refusal(
            RefusalCode::WriterAuthorityUnavailable,
            format!("the pinned writer authority is not a valid contract: {error}"),
            json!({}),
        ),
    }
}

/// An admission refusal, with the admission reason in `details.reason`. A
/// route and head from different packages means the head moved under the
/// route.
fn admission_refused(refusal_reason: RememberAdmissionRefusal) -> FleetError {
    let code = match refusal_reason.reason {
        RememberAdmissionRefusalReason::RegistryHeadMismatch => RefusalCode::RegistryHeadChanged,
        _ => RefusalCode::AssertionNotAdmitted,
    };
    refusal(
        code,
        refusal_reason.message,
        json!({ "reason": refusal_reason.reason.as_str() }),
    )
}

/// The refusal of an accepted statement that is already in the ledger.
/// `claim_id` is the claim it projects, when that projection is found.
fn already_asserted(claim_id: Option<i64>, event_id: AcceptedEventId) -> FleetError {
    refusal(
        RefusalCode::AlreadyAsserted,
        "this exact assertion is already accepted under another idempotency key; nothing was \
         written",
        json!({ "claim_id": claim_id, "accepted_event_id": event_id }),
    )
}

fn refusal(code: RefusalCode, message: impl Into<String>, details: Value) -> FleetError {
    LifecycleRefusal::new(code, message, details).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_ledger::{AuthorityUnavailableKind, WitnessMismatchKind};
    use crate::ledger::{Claim, ClaimKind, ClaimState};
    use crate::memory_contracts::bootstrap::{AppendPositionV1, CommittedOffsetV1, EpochId};
    use crate::memory_contracts::digest::{DigestDomain, domain_separated_digest};
    use crate::memory_contracts::quarantine::{QuarantineReasonV1, QuarantineRecordId};

    fn digest(label: &str) -> Sha256Digest {
        domain_separated_digest(DigestDomain::AcceptedEvent, label.as_bytes())
    }

    fn position() -> AppendPositionV1 {
        AppendPositionV1 {
            epoch_id: EpochId::from_digest(digest("epoch")),
            shard: 3,
            committed_offset: CommittedOffsetV1::new(7).unwrap(),
        }
    }

    fn event_id() -> AcceptedEventId {
        AcceptedEventId::from_digest(digest("event"))
    }

    fn asserted() -> AssertedClaimMutation {
        let now = DateTime::parse_from_rfc3339("2026-09-24T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        AssertedClaimMutation {
            mutation: ClaimMutation {
                operation: ASSERT_OPERATION.into(),
                claim: Claim {
                    id: 41,
                    project: "assert-unit".into(),
                    kind: ClaimKind::Decision,
                    claim_key: Some("claim-v2:key:attested".into()),
                    subject: Some("urn:ostk:entity:v1:repository:sha256:00".into()),
                    predicate: Some("mcp.remember.allowed_actions".into()),
                    value: Some(json!({ "kind": "boolean", "value": true })),
                    text: "assert is allowed".into(),
                    polarity: 1,
                    state: ClaimState::Active,
                    origin: OPERATOR_ASSERTED_ORIGIN.into(),
                    actor: Some("agent-a".into()),
                    confidence: 1.0,
                    valid_from: Some(now),
                    valid_to: None,
                    superseded_by: None,
                    revision: 1,
                    conflict_eligible: true,
                    created_at: now,
                    updated_at: now,
                    support: Vec::new(),
                    conflict_ids: Vec::new(),
                },
                superseded: None,
                idempotent_replay: false,
                conflicts_opened: Vec::new(),
                conflicts_resolved: Vec::new(),
                claims_restored: Vec::new(),
                reevaluation: None,
            },
            accepted_event: AcceptedEventRefV1 {
                event_id: event_id(),
                epoch_id: position().epoch_id,
                shard: position().shard,
                committed_offset: position().committed_offset.as_u64(),
            },
        }
    }

    fn refusal_of(error: &FleetError) -> &LifecycleRefusal {
        match error {
            FleetError::LifecycleRefused(refusal) => refusal,
            other => panic!("expected a typed refusal, got {other}"),
        }
    }

    fn failure(resolution: AppendResolution) -> FleetError {
        match resolution {
            AppendResolution::Fail(error) => error,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn an_appended_event_returns_the_projection_it_committed() {
        let appended = Ok(AppendOutcome::Appended {
            position: position(),
            chain_digest: digest("chain"),
        });
        let committed = Some(ProjectionOutcome::Committed(Box::new(asserted())));
        let AppendResolution::Committed(returned) = resolve_append(appended, committed) else {
            panic!("an appended event with its projection must commit");
        };
        assert_eq!(*returned, asserted());

        // An append that reports success without the projection's result is
        // a contradiction, never a silent success.
        let bare = Ok(AppendOutcome::Appended {
            position: position(),
            chain_digest: digest("chain"),
        });
        assert!(matches!(
            failure(resolve_append(bare, None)),
            FleetError::Memory(_)
        ));
    }

    #[test]
    fn a_moved_head_is_refused_as_registry_head_changed() {
        for error in [
            EvidenceAppendError::WitnessMismatch(WitnessMismatchKind::ActivationId),
            EvidenceAppendError::StatementAuthority(WitnessMismatchKind::CanonicalHeadBytes),
        ] {
            let error = failure(resolve_append(Err(error), None));
            let refusal = refusal_of(&error);
            assert_eq!(refusal.code, RefusalCode::RegistryHeadChanged);
            assert!(refusal.details["mismatch"].is_string());
        }
        // Even a projection that ran in an earlier, rolled-back attempt does
        // not turn a later refusal into a success.
        let error = failure(resolve_append(
            Err(EvidenceAppendError::WitnessMismatch(
                WitnessMismatchKind::Generation,
            )),
            Some(ProjectionOutcome::Committed(Box::new(asserted()))),
        ));
        assert_eq!(refusal_of(&error).code, RefusalCode::RegistryHeadChanged);
    }

    #[test]
    fn an_unusable_authority_is_refused_as_writer_authority_unavailable() {
        let error = failure(resolve_append(
            Err(EvidenceAppendError::AuthorityUnavailable(
                AuthorityUnavailableKind::NotActive,
            )),
            None,
        ));
        assert_eq!(
            refusal_of(&error).code,
            RefusalCode::WriterAuthorityUnavailable
        );
    }

    #[test]
    fn a_replayed_statement_is_already_asserted() {
        let resolution = resolve_append(
            Ok(AppendOutcome::Replayed {
                position: position(),
            }),
            None,
        );
        assert!(matches!(resolution, AppendResolution::AlreadyAppended));

        let error = already_asserted(Some(41), event_id());
        let refusal = refusal_of(&error);
        assert_eq!(refusal.code, RefusalCode::AlreadyAsserted);
        assert_eq!(refusal.details["claim_id"], json!(41));
        assert_eq!(refusal.details["accepted_event_id"], json!(event_id()));
    }

    #[test]
    fn a_quarantined_append_is_internal() {
        let error = failure(resolve_append(
            Ok(AppendOutcome::Quarantined {
                quarantine_id: QuarantineRecordId::from_digest(digest("quarantine")),
                reason: QuarantineReasonV1::IntegrityCollision,
            }),
            None,
        ));
        assert!(matches!(error, FleetError::Memory(_)), "{error}");
    }

    #[test]
    fn a_raced_reservation_re_reads_the_receipt() {
        let raced = Err(EvidenceAppendError::Storage(
            FleetError::IdempotencyConflict("raced".into()),
        ));
        assert!(matches!(
            resolve_append(raced, Some(ProjectionOutcome::ReceiptRaced)),
            AppendResolution::ReadReceipt
        ));
    }

    #[test]
    fn projection_refusals_and_storage_failures_pass_through() {
        let refused = EvidenceAppendError::Storage(refusal(
            RefusalCode::SupportEventUnknown,
            "unknown support",
            json!({}),
        ));
        let error = failure(resolve_append(Err(refused), None));
        assert_eq!(refusal_of(&error).code, RefusalCode::SupportEventUnknown);

        let storage = EvidenceAppendError::Storage(FleetError::Database(sqlx::Error::PoolTimedOut));
        assert!(matches!(
            failure(resolve_append(Err(storage), None)),
            FleetError::Database(_)
        ));

        let integrity = EvidenceAppendError::LedgerIntegrity("tampered".into());
        assert!(matches!(
            failure(resolve_append(Err(integrity), None)),
            FleetError::Memory(_)
        ));
    }

    #[test]
    fn admission_refusals_carry_their_reason() {
        let error = admission_refused(RememberAdmissionRefusal {
            reason: RememberAdmissionRefusalReason::TextInvalid,
            message: "text must not have leading or trailing whitespace".into(),
        });
        let refusal = refusal_of(&error);
        assert_eq!(refusal.code, RefusalCode::AssertionNotAdmitted);
        assert_eq!(refusal.details["reason"], json!("text_invalid"));

        let error = admission_refused(RememberAdmissionRefusal {
            reason: RememberAdmissionRefusalReason::RegistryHeadMismatch,
            message: "moved".into(),
        });
        assert_eq!(refusal_of(&error).code, RefusalCode::RegistryHeadChanged);
    }

    #[test]
    fn an_asserted_mutation_replays_with_its_accepted_event() {
        let stored = serde_json::to_value(asserted()).unwrap();
        assert_eq!(stored["operation"], json!(ASSERT_OPERATION));
        assert_eq!(stored["accepted_event"]["event_id"], json!(event_id()));
        let mut replayed: AssertedClaimMutation = serde_json::from_value(stored).unwrap();
        replayed.mark_replayed();
        assert!(replayed.mutation.idempotent_replay);
        assert_eq!(replayed.accepted_event, asserted().accepted_event);
    }
}
