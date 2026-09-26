//! Agent capture: `remember(action="capture")` (ADR 0008 D10).
//!
//! An agent often holds MCP connectors of its own (Slack, Linear, Granola, a
//! browser) and reads items through them while it works. Capture relays what
//! it read into the same collected-item sink every collector uses, so the
//! fleet can recall it, and the agent can cite it at once. What an agent
//! relays is only *reported*: the collector never read it from the provider.
//!
//! # Who captures
//!
//! Every capture a `serve` process makes is its agent's
//! (`FLEET_RECALL_AGENT`), through `connector.collected.capture`:
//!
//! * the ingress principal and attester are `agent.<agent>`, and the attester
//!   is inside every staged revision, so two agents' captures of one item are
//!   two attestations and a capture never collapses onto a pull;
//! * the collector instance is `capture.<agent>`, whose status row (`owner =
//!   capture`, `coverage_role = none`) never counts toward an absence verdict;
//! * an agent name that is not a contract id, or is longer than 120 bytes, is
//!   lowercased with every other byte replaced by `-`, cut, and suffixed with
//!   `.` and 16 hex characters of its SHA-256 ([`CaptureIdentityV1`]), so two
//!   agents never share a principal.
//!
//! # Audience: never the agent's word
//!
//! The sink decides every item's audience (ADR 0008 D6). A capture is
//! admitted only into a container a verified collector or an operator import
//! recorded as visible to the project (`verified_container`), or into a scope
//! the operator lists in `FLEET_RECALL_COLLECTED_CAPTURE_SCOPES`
//! (`operator_capture_scope`); a withdrawn container refuses it; a container
//! whose kind names a direct conversation (`slack.im`, `slack.mpim`, ...) is
//! refused as `direct_message` whatever scope the operator listed, even
//! `"*"`; and the agent's `visibility` can only narrow: `private` and `dm`
//! withhold the item. A capture neither records, withdraws, nor lifts
//! anything.
//!
//! # One capture
//!
//! 1. The request is checked before any I/O ([`PreparedCaptureV1::prepare`]):
//!    1 to 32 items whose texts together are at most 768 KiB of UTF-8 (a
//!    capture is one MCP frame of at most 1 MiB), each with its `https` URL
//!    at the provider, text of at most 262,144 characters (the server splits
//!    it), a provider clock, and a lifecycle that is not a tombstone: an
//!    agent relays what it read, and a deletion is reported only by a
//!    verified collector or an operator import.
//! 2. A receipt already committed under the key is replayed (below).
//! 3. The writer authority is verified and must bind
//!    `connector.collected.capture`; a generation-2 head refuses as
//!    `capture_unavailable`, naming `--target generation-3`.
//! 4. One serializable transaction (retried only on 40001) reserves the
//!    receipt (operation `capture`), stages every item through the sink, one
//!    [`PreparedStageV1`] per provider scope, and writes a **provisional**
//!    response naming every item's stage ids.
//! 5. `enabled`: each staged row is drained in its own append
//!    ([`CollectedItemSink::drain_stage_ids`]), and the admitted rows are
//!    then projected in the call, bodies, lexical, and dense, by the same
//!    projectors the worker runs, within a ten-second budget
//!    ([`CAPTURE_PROJECTION_BUDGET`]): the agent can recall what it captured
//!    at once, and the scope's absence verdict does not read
//!    `body_projection_lag` until a worker tick. `stage_only`: the rows wait
//!    for the worker's `collect` step, and `serve` holds no content key.
//! 6. The receipt's response is finalized with each item's disposition:
//!    `admitted` (with its accepted event ids, one per part, in order),
//!    `staged` (a row still waits for a drain), `replayed` (every part was
//!    already admitted before this capture), or `withheld` with the reason
//!    (the audience refusal, `redaction_withheld`, `validation_failed`,
//!    `oversize`, `admission_refused`, or `quarantined`); an `enabled`
//!    capture that admitted something also reports its `projection`
//!    ([`CaptureProjectionV1`]).
//!
//! # Replays
//!
//! The same key and request return the final response, marked
//! `idempotent_replay`; another request under a used key is an idempotency
//! conflict. A receipt still provisional (a capture that stopped after its
//! staging committed) is finished by the replay: its listed rows are drained
//! and the response finalized, once, by whichever call gets there first. The
//! same item under a new key stages nothing new and is `replayed`, with the
//! events the first capture appended.
//!
//! # What the receipt keeps
//!
//! The request is `{scope, request_digest}` and never an item's text; the
//! response holds identities, digests, dispositions, and counts. The redacted
//! text lives only in the governed content store and the body plane. The
//! request digest is taken over the request with every secret the collector
//! redactor finds replaced, so neither it nor the delivery ids derived from
//! it let anyone who can read them confirm a guess of a redacted secret.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, Row as _, Transaction};

use crate::body_store::{
    BodyProjectionRepository as _, CockroachBodyProjectionRepository, GovernedContentResolver,
    reference_parser_key_v1,
};
use crate::collectors::audience::{AudiencePolicyV1, CaptureScopeV1};
use crate::collectors::binding::{CollectedConnectorBindingV1, CollectorInstanceV1};
use crate::collectors::cockroach::framed_sha256;
use crate::collectors::draft::{CollectedItemDraftV1, collection_record, has_hidden_scalar};
use crate::collectors::redaction::{CollectorRedactorV1, scan_collected_secrets};
use crate::collectors::sink::{
    CollectedDrainContextV1, CollectedItemSink, DeadLetterReasonV1, OutboxRowStateV1,
    PreparedStageV1, StageContextV1, StageDraftV1, StagedItemV1,
};
use crate::collectors::status::{
    CollectorOutcomeV1, CollectorOwnerV1, CollectorSourceStatusV1, CoverageRoleV1,
};
use crate::config::{CollectedCaptureConfig, CollectedCaptureModeV1, WriterAuthorityConfig};
use crate::context::FleetScope;
use crate::error::{FleetError, Result};
use crate::evidence_ledger::{ContentKeyEncryptionKey, content_kek_from_lookup};
use crate::ledger::{LifecycleRefusal, RefusalCode};
use crate::memory_contracts::collected_item::{
    BoundedTextV1, CollectedItemInputV1, CollectionModeV1, ItemLifecycleV1, MAX_LABEL_BYTES,
    MAX_PROVIDER_URL_BYTES, MAX_SCOPE_ID_BYTES, ProviderKindV1, derive_item_key,
};
use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::digest::Sha256Digest;
use crate::projectors::{
    CockroachDenseProjector, CockroachLexicalProjector, DEFAULT_PROJECTION_BATCH,
    DenseProjector as _, EmbeddingProvider, LexicalProjector as _,
};
use crate::redaction::REDACTION_PLACEHOLDER;
use crate::registry_witness::{
    VerifiedWriterAuthority, WriterAuthorityError, WriterAuthorityRuntime,
};
use crate::store::cockroach::{
    COLLECTED_ITEMS_SCHEMA_VERSION, DatabaseCapabilities, RetryPolicy, with_serializable_retry,
};
use crate::worker::probe_capture_privileges;

/// Most items one capture carries.
pub const MAX_CAPTURE_ITEMS: usize = 32;

/// Longest text of one captured item, in characters (Unicode scalar values,
/// which JSON Schema's `maxLength` counts); the server splits it into parts
/// of at most 32 KiB.
pub const MAX_CAPTURE_TEXT_CHARS: usize = 256 * 1024;

/// Most bytes of UTF-8 text one capture's items carry together.
///
/// A capture is one `remember` call, and the only transport, MCP over stdio,
/// drops any frame over 1 MiB (`MAX_MCP_FRAME_BYTES`) before it is
/// dispatched. 768 KiB of text leaves the frame room for every other field
/// and the JSON around it, so a request the server accepts is one the
/// transport carries.
pub const MAX_CAPTURE_TOTAL_TEXT_BYTES: usize = 768 * 1024;

/// The digest domain of a capture's request: its canonical JSON with every
/// secret the collector redactor finds replaced, so a digest kept in a
/// receipt or a delivery id is never a fingerprint of a redacted secret.
const CAPTURE_REQUEST_DIGEST_DOMAIN: &str = "ostk-collected-capture-request-v2";

/// Rounds of redaction [`redacted_for_digest`] runs over one string before
/// it replaces the whole string: a replacement that leaves a new match
/// behind is vanishingly rare, and the bound keeps the loop finite.
const DIGEST_REDACTION_ROUNDS: usize = 4;

/// The receipt operation of a capture.
pub const CAPTURE_OPERATION: &str = "capture";

/// Prefix of the principal, and attester, an agent captures as.
const CAPTURE_PRINCIPAL_PREFIX: &str = "agent.";

/// Prefix of the collector instance an agent captures under.
const CAPTURE_INSTANCE_PREFIX: &str = "capture.";

/// Longest agent part of a capture identity: `capture.` plus it fits a
/// 128-byte contract id.
const MAX_CAPTURE_AGENT_BYTES: usize = 120;

/// Hex characters of the agent name's SHA-256 a lossy identity carries.
const CAPTURE_AGENT_DIGEST_HEX: usize = 16;

/// Longest idempotency key a receipt holds.
const MAX_CAPTURE_KEY_BYTES: usize = 256;

/// How long a capture status row stays current. A capture is never coverage,
/// so it only has to satisfy migration 0033's bound.
const CAPTURE_STALE_AFTER_SECONDS: u64 = 86_400;

/// Version of the provisional response a receipt holds while a capture's
/// rows drain.
const PROVISIONAL_SCHEMA_VERSION: u32 = 1;

const SELECT_RECEIPT_SQL: &str = "SELECT project, operation, request, response \
     FROM memory_mutation_receipts \
     WHERE tenant_id = $1 AND idempotency_key = $2";
/// The tenant-wide key is reserved first, as `record` reserves it; the
/// provisional response is written in the same transaction.
const RESERVE_RECEIPT_SQL: &str = "INSERT INTO memory_mutation_receipts (\
         tenant_id, idempotency_key, project, request, operation\
     ) VALUES ($1, $2, $3, $4, 'capture') \
     ON CONFLICT (tenant_id, idempotency_key) DO NOTHING \
     RETURNING idempotency_key";
const WRITE_PROVISIONAL_SQL: &str = "UPDATE memory_mutation_receipts SET response = $5 \
     WHERE tenant_id = $1 AND idempotency_key = $2 \
       AND project = $3 AND request = $4 AND operation = 'capture'";
/// Only a provisional response is finalized, so two calls finishing one
/// capture agree on the first one's answer.
const FINALIZE_SQL: &str = "UPDATE memory_mutation_receipts SET response = $5 \
     WHERE tenant_id = $1 AND idempotency_key = $2 \
       AND project = $3 AND request = $4 AND operation = 'capture' \
       AND response->'provisional' IS NOT NULL";

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// The principal and collector instance one agent captures as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureIdentityV1 {
    /// `agent.<agent>`: the ingress principal and the attester recorded in
    /// every captured revision.
    pub principal: ContractId,
    /// `capture.<agent>`: the collector instance every captured row and the
    /// capture status row name.
    pub instance: ContractId,
}

impl CaptureIdentityV1 {
    /// The capture identity of the fleet agent `agent`. See the module
    /// documentation for how a name that is not a contract id is carried.
    ///
    /// # Errors
    ///
    /// Never for a non-empty agent; an empty one is not a fleet agent.
    pub fn for_agent(agent: &str) -> Result<Self> {
        if agent.is_empty() {
            return Err(FleetError::Configuration(
                "an agent captures under a non-empty FLEET_RECALL_AGENT".to_owned(),
            ));
        }
        let part = capture_agent_part(agent);
        Ok(Self {
            principal: ContractId::new(format!("{CAPTURE_PRINCIPAL_PREFIX}{part}"))?,
            instance: ContractId::new(format!("{CAPTURE_INSTANCE_PREFIX}{part}"))?,
        })
    }
}

/// The agent part of a capture identity: the agent name itself when it is a
/// contract-id tail of at most [`MAX_CAPTURE_AGENT_BYTES`], else a sanitized
/// prefix and a digest of the exact name.
fn capture_agent_part(agent: &str) -> String {
    let sanitized: String = agent
        .chars()
        .map(|scalar| {
            let lower = scalar.to_ascii_lowercase();
            if lower.is_ascii_lowercase()
                || lower.is_ascii_digit()
                || matches!(lower, '_' | '-' | '.')
            {
                lower
            } else {
                '-'
            }
        })
        .collect();
    if sanitized == agent && agent.len() <= MAX_CAPTURE_AGENT_BYTES {
        return sanitized;
    }
    let digest = hex::encode(Sha256::digest(agent.as_bytes()));
    // Every sanitized scalar is one ASCII byte.
    let keep = MAX_CAPTURE_AGENT_BYTES - 1 - CAPTURE_AGENT_DIGEST_HEX;
    let prefix: String = sanitized.chars().take(keep).collect();
    format!("{prefix}.{}", &digest[..CAPTURE_AGENT_DIGEST_HEX])
}

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

/// `remember(action="capture")` as an agent sends it, besides the action,
/// scope, and idempotency key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRequestV1 {
    /// 1 to [`MAX_CAPTURE_ITEMS`] items, each as an import line carries it,
    /// with its provider `url` required.
    pub items: Vec<CollectedItemInputV1>,
    /// The tool the agent read the items through (`slack.conversations_history`,
    /// an MCP tool name): a label recorded with each item, never authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

/// One captured item, checked and turned into a draft.
#[derive(Debug, Clone)]
struct PreparedItemV1 {
    draft: CollectedItemDraftV1,
    item_key: Sha256Digest,
    delivery_id: Vec<u8>,
}

/// A capture request checked before any I/O.
#[derive(Debug, Clone)]
pub struct PreparedCaptureV1 {
    request_digest: Sha256Digest,
    via: Option<String>,
    items: Vec<PreparedItemV1>,
}

impl PreparedCaptureV1 {
    /// Check `request` and turn each item into a draft. Nothing here reads a
    /// database; a refusal names the first item and rule it broke.
    ///
    /// # Errors
    ///
    /// A message for the caller: no items or more than
    /// [`MAX_CAPTURE_ITEMS`]; texts together over
    /// [`MAX_CAPTURE_TOTAL_TEXT_BYTES`]; an empty or over-long `via`; an item
    /// without an `https` URL, with empty text or text over
    /// [`MAX_CAPTURE_TEXT_CHARS`], with a tombstone lifecycle, with a provider
    /// scope id that is not 1 to 256 bytes of plain text, or that the draft
    /// refuses (no provider clock, a clock that is not RFC 3339).
    pub fn prepare(request: &CaptureRequestV1) -> std::result::Result<Self, String> {
        if request.items.is_empty() || request.items.len() > MAX_CAPTURE_ITEMS {
            return Err(format!(
                "a capture carries 1 to {MAX_CAPTURE_ITEMS} items, got {}",
                request.items.len()
            ));
        }
        let total_text: usize = request.items.iter().map(|item| item.text.len()).sum();
        if total_text > MAX_CAPTURE_TOTAL_TEXT_BYTES {
            return Err(format!(
                "the items' texts together are {total_text} bytes of UTF-8; one capture carries \
                 at most {MAX_CAPTURE_TOTAL_TEXT_BYTES}, so the call fits one 1 MiB MCP frame: \
                 send the rest in another capture"
            ));
        }
        if let Some(via) = &request.via {
            check_via(via)?;
        }
        let request_digest = digest_request(request)?;
        let mut items = Vec::with_capacity(request.items.len());
        for (index, input) in request.items.iter().enumerate() {
            let at = |message: &str| format!("items[{index}]: {message}");
            let url = input
                .url
                .as_deref()
                .ok_or_else(|| at("url is required: the item's https link at its provider"))?;
            if !url.starts_with("https://") || url.len() > MAX_PROVIDER_URL_BYTES {
                return Err(at(&format!(
                    "url must be an https URL of at most {MAX_PROVIDER_URL_BYTES} bytes"
                )));
            }
            if input.lifecycle.is_some_and(ItemLifecycleV1::is_tombstone) {
                return Err(at(
                    "a capture relays an item you read; a deletion is reported only by a \
                     verified collector or an operator import",
                ));
            }
            if input.text.trim().is_empty() {
                return Err(at("text is required: the item as you read it"));
            }
            if input.text.chars().count() > MAX_CAPTURE_TEXT_CHARS {
                return Err(at(&format!(
                    "text is at most {MAX_CAPTURE_TEXT_CHARS} characters; the server splits it"
                )));
            }
            let scope = &input.provider_scope_id;
            if BoundedTextV1::<MAX_SCOPE_ID_BYTES>::new(scope.clone()).is_err()
                || has_hidden_scalar(scope)
                || !scan_collected_secrets(scope).is_empty()
            {
                return Err(at(&format!(
                    "provider_scope_id is 1 to {MAX_SCOPE_ID_BYTES} bytes of NFC text with no \
                     control, hidden scalar, or secret shape"
                )));
            }
            let draft = CollectedItemDraftV1::from_input(input.clone())
                .map_err(|refusal| at(&refusal.to_string()))?;
            let item_key = derive_item_key(
                &draft.provider,
                &draft.provider_scope_id,
                &draft.object_kind,
                &draft.external_id,
            );
            // The request digest and the item's position: the transport
            // delivery a capture's rows carry.
            let mut delivery_id = request_digest.as_bytes().to_vec();
            delivery_id.extend_from_slice(&u32::try_from(index).unwrap_or(u32::MAX).to_be_bytes());
            items.push(PreparedItemV1 {
                draft,
                item_key,
                delivery_id,
            });
        }
        Ok(Self {
            request_digest,
            via: request.via.clone(),
            items,
        })
    }

    /// The digest the receipt keeps in place of the request.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    /// The items' indices grouped by provider scope, in order of first
    /// appearance.
    fn groups(&self) -> Vec<((ProviderKindV1, String), Vec<usize>)> {
        let mut groups: Vec<((ProviderKindV1, String), Vec<usize>)> = Vec::new();
        for (index, item) in self.items.iter().enumerate() {
            let key = (
                item.draft.provider.clone(),
                item.draft.provider_scope_id.clone(),
            );
            match groups.iter_mut().find(|(group, _)| *group == key) {
                Some((_, indices)) => indices.push(index),
                None => groups.push((key, vec![index])),
            }
        }
        groups
    }
}

/// The digest a receipt keeps in place of `request`: its canonical JSON with
/// every secret the collector redactor finds, in any string, replaced by the
/// placeholder. The sink stages only redacted text, so two requests that
/// differ only in a secret it removes are the same capture; and the digest
/// kept durably (the receipt, every delivery id, every admitted event's
/// provider delivery id) confirms no guess of what was redacted.
fn digest_request(request: &CaptureRequestV1) -> std::result::Result<Sha256Digest, String> {
    let mut value = serde_json::to_value(request)
        .map_err(|error| format!("the capture request does not serialize: {error}"))?;
    redact_strings(&mut value);
    let bytes = serde_json::to_vec(&value)
        .map_err(|error| format!("the capture request does not serialize: {error}"))?;
    Ok(framed_sha256(CAPTURE_REQUEST_DIGEST_DOMAIN, &[&bytes]))
}

/// Replace every secret in every string of `value`.
fn redact_strings(value: &mut Value) {
    match value {
        Value::String(text) => {
            if let Some(redacted) = redacted_for_digest(text) {
                *text = redacted;
            }
        }
        Value::Array(values) => values.iter_mut().for_each(redact_strings),
        Value::Object(fields) => fields.values_mut().for_each(redact_strings),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// `text` with every finding of the collector redactor's scan replaced by
/// the placeholder, unredactable ones included, until none remains; `None`
/// when it holds none.
fn redacted_for_digest(text: &str) -> Option<String> {
    let mut findings = scan_collected_secrets(text);
    if findings.is_empty() {
        return None;
    }
    let mut current = text.to_owned();
    for _ in 0..DIGEST_REDACTION_ROUNDS {
        let mut redacted = String::with_capacity(current.len());
        let mut cursor = 0_usize;
        for finding in &findings {
            // Matchers stop on ASCII bytes, so every range is a char boundary;
            // a violation replaces the whole string instead of panicking.
            let Some(prefix) = current.get(cursor..finding.byte_start) else {
                return Some(REDACTION_PLACEHOLDER.to_owned());
            };
            redacted.push_str(prefix);
            redacted.push_str(REDACTION_PLACEHOLDER);
            cursor = finding.byte_end;
        }
        let Some(tail) = current.get(cursor..) else {
            return Some(REDACTION_PLACEHOLDER.to_owned());
        };
        redacted.push_str(tail);
        findings = scan_collected_secrets(&redacted);
        if findings.is_empty() {
            return Some(redacted);
        }
        current = redacted;
    }
    Some(REDACTION_PLACEHOLDER.to_owned())
}

/// Refuse a tool label a capture could not record: blank, longer than
/// [`MAX_LABEL_BYTES`], or not a bounded line once sanitized.
fn check_via(via: &str) -> std::result::Result<(), String> {
    let refused = || {
        format!("via is 1 to {MAX_LABEL_BYTES} bytes naming the tool the items were read through")
    };
    if via.trim().is_empty() || via.len() > MAX_LABEL_BYTES {
        return Err(refused());
    }
    let (Ok(instance), Ok(attester)) = (
        ContractId::new(format!("{CAPTURE_INSTANCE_PREFIX}via")),
        ContractId::new(format!("{CAPTURE_PRINCIPAL_PREFIX}via")),
    ) else {
        return Err(refused());
    };
    collection_record(
        CollectionModeV1::Capture,
        instance,
        Some(attester),
        Some(via),
    )
    .map(|_| ())
    .map_err(|_| refused())
}

// ---------------------------------------------------------------------------
// The response
// ---------------------------------------------------------------------------

/// What a capture did with one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureDispositionV1 {
    /// Every part is admitted, and this capture staged or admitted it.
    Admitted,
    /// A part still waits for a drain: the worker's `collect` step admits it.
    Staged,
    /// Every part was already admitted before this capture: the same item,
    /// attested by the same agent, under another key.
    Replayed,
    /// Refused; `withheld_reason` says why. Nothing of it is recallable.
    Withheld,
}

/// One item of a capture's answer, in request order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedItemV1 {
    /// The item's identity: what `recall(get, kind=item)` takes.
    pub item_id: Sha256Digest,
    /// The version's identity; absent for an item withheld before sealing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<Sha256Digest>,
    /// The first part's version URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    pub disposition: CaptureDispositionV1,
    /// Why the item was withheld: an audience refusal (`audience_refused`,
    /// `audience_unverified`, `container_withdrawn`, ...), or
    /// `redaction_withheld`, `validation_failed`, `oversize`,
    /// `admission_refused`, `quarantined`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld_reason: Option<String>,
    /// The accepted events of the parts admitted so far, in part order: what
    /// `remember(assert)` cites as support.
    pub accepted_event_ids: Vec<Sha256Digest>,
    /// Ranges the collector redactor replaced across the item's fields.
    pub redacted_ranges: u32,
}

/// What an `enabled` capture projected before answering, so the items it
/// admitted are recalled in the same call and the scope's absence verdict
/// never waits on a worker tick for them (ADR 0008 D10).
///
/// Each projector consumes the scope's pending rows from its own cursor,
/// this capture's among them, so the counts can exceed the capture's parts
/// when a worker left rows behind; they are what the pass did, not a
/// per-item receipt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureProjectionV1 {
    /// Accepted events the body projector consumed into bodies.
    pub bodies: u64,
    /// Bodies the lexical projector made searchable.
    pub lexical: u64,
    /// Lexical rows the dense projector embedded.
    pub dense: u64,
    /// Every tier ran to its end within [`CAPTURE_PROJECTION_BUDGET`]. When
    /// false, a tier failed, was not configured, or ran out of budget; what
    /// it committed stands, and the worker's `project` and `embed` steps
    /// finish the rest.
    pub complete: bool,
}

/// A capture's answer: the receipt's final response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureResponseV1 {
    /// Always `capture`.
    pub operation: String,
    pub items: Vec<CapturedItemV1>,
    /// Whether this answer replays a committed receipt.
    pub idempotent_replay: bool,
    /// What the call projected after admitting the items; only an `enabled`
    /// capture that admitted something carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<CaptureProjectionV1>,
}

/// How long an `enabled` capture spends projecting its admitted rows before
/// answering: the whole of the MCP edge's 30-second request deadline is not
/// spent on a step the worker will finish anyway.
pub const CAPTURE_PROJECTION_BUDGET: Duration = Duration::from_secs(10);

/// The projectors an `enabled` capture runs over its admitted rows: the same
/// three the worker's `project` and `embed` steps run, bound to the same
/// scope, so a capture's bodies are recalled before the next tick. Their
/// writes are per-event serializable transactions with compare-and-set
/// cursors, so running them beside a worker tick is safe: each row is
/// projected once, by whichever gets there first.
struct CaptureProjectorsV1 {
    bodies: Arc<CockroachBodyProjectionRepository>,
    lexical: CockroachLexicalProjector,
    dense: Option<CockroachDenseProjector>,
}

impl CaptureProjectorsV1 {
    /// Bind the projectors for `scope` under the writer authority `serve`
    /// verified: the body projector opens the governed content store with
    /// `kek` under the authority's semantic scope, as the worker's does.
    fn new(
        pool: PgPool,
        scope: &FleetScope,
        authority: &WriterAuthorityRuntime,
        kek: ContentKeyEncryptionKey,
        embedding: Option<Arc<dyn EmbeddingProvider>>,
        retry: RetryPolicy,
    ) -> Self {
        let resolver = GovernedContentResolver::new(
            pool.clone(),
            scope.tenant_id,
            scope.project.clone(),
            authority.semantic_scope().clone(),
            kek,
        );
        let bodies = Arc::new(CockroachBodyProjectionRepository::new(
            pool.clone(),
            scope.tenant_id,
            scope.project.clone(),
            reference_parser_key_v1(),
            Arc::new(resolver),
            retry,
        ));
        let lexical = CockroachLexicalProjector::new(
            pool.clone(),
            scope.tenant_id,
            scope.project.clone(),
            DEFAULT_PROJECTION_BATCH,
            retry,
        );
        let dense = embedding.map(|provider| {
            CockroachDenseProjector::new(
                pool,
                scope.tenant_id,
                scope.project.clone(),
                provider,
                DEFAULT_PROJECTION_BATCH,
                retry,
            )
        });
        Self {
            bodies,
            lexical,
            dense,
        }
    }

    /// Run bodies, then lexical, then dense, each from its own cursor, within
    /// one shared budget. A tier that fails is logged and leaves the
    /// projection incomplete; the tiers after it still run, since each keeps
    /// its own cursor. A tier that runs out of budget is dropped mid-pass:
    /// every event it committed stands, and the rest is the worker's.
    async fn project(&self) -> CaptureProjectionV1 {
        let deadline = tokio::time::Instant::now() + CAPTURE_PROJECTION_BUDGET;
        let mut projection = CaptureProjectionV1 {
            complete: true,
            ..CaptureProjectionV1::default()
        };
        match tokio::time::timeout_at(deadline, self.bodies.project_pending()).await {
            Ok(Ok(summary)) => projection.bodies = summary.events_projected,
            Ok(Err(error)) => {
                tracing::warn!(%error, "a capture could not project its bodies; the worker will");
                projection.complete = false;
            }
            Err(_) => return Self::out_of_budget("bodies", projection),
        }
        match tokio::time::timeout_at(deadline, self.lexical.project_pending()).await {
            Ok(Ok(summary)) => projection.lexical = summary.rows_indexed,
            Ok(Err(error)) => {
                tracing::warn!(%error, "a capture could not project its lexical rows; the worker will");
                projection.complete = false;
            }
            Err(_) => return Self::out_of_budget("lexical", projection),
        }
        let Some(dense) = &self.dense else {
            tracing::warn!(
                "a capture has no embedding provider, so its dense rows wait for the worker"
            );
            projection.complete = false;
            return projection;
        };
        match tokio::time::timeout_at(deadline, dense.embed_pending()).await {
            Ok(Ok(summary)) => projection.dense = summary.rows_indexed,
            Ok(Err(error)) => {
                tracing::warn!(%error, "a capture could not embed its dense rows; the worker will");
                projection.complete = false;
            }
            Err(_) => return Self::out_of_budget("dense", projection),
        }
        projection
    }

    fn out_of_budget(tier: &str, mut projection: CaptureProjectionV1) -> CaptureProjectionV1 {
        tracing::warn!(
            tier,
            budget_seconds = CAPTURE_PROJECTION_BUDGET.as_secs(),
            "a capture ran out of projection budget; what it committed stands and the worker finishes the rest"
        );
        projection.complete = false;
        projection
    }
}

/// What [`ItemCapture::capture`] returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureOutcomeV1 {
    /// The response, as `remember`'s `data`.
    pub response: Value,
    /// Whether it replays a committed receipt.
    pub replayed: bool,
}

/// One item of a provisional response: what finishing it needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionalItemV1 {
    item_id: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version_id: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
    stage_ids: Vec<Sha256Digest>,
    already_admitted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    withheld_reason: Option<String>,
    redacted_ranges: u32,
}

/// The response a receipt holds from staging until the capture is finished.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionalCaptureV1 {
    schema_version: u32,
    items: Vec<ProvisionalItemV1>,
}

impl ProvisionalCaptureV1 {
    /// Every row the capture staged or found, of the items not withheld.
    fn stage_ids(&self) -> Vec<Sha256Digest> {
        self.items
            .iter()
            .filter(|item| item.withheld_reason.is_none())
            .flat_map(|item| item.stage_ids.iter().copied())
            .collect()
    }

    fn to_value(&self) -> Result<Value> {
        Ok(
            json!({ "provisional": serde_json::to_value(self).map_err(|error| {
            FleetError::Protocol(format!("a provisional capture response does not serialize: {error}"))
        })? }),
        )
    }
}

/// The reason a staging refusal is reported under: an audience refusal's own
/// label (`audience_refused`, `audience_unverified`, ...), else the dead
/// letter's reason.
fn withheld_reason(reason: DeadLetterReasonV1, diagnostic: &str) -> String {
    if reason == DeadLetterReasonV1::AudienceRefused {
        diagnostic.to_owned()
    } else {
        reason.as_str().to_owned()
    }
}

/// Each item's disposition, from its provisional record and the states of its
/// rows now.
fn settle(
    provisional: &ProvisionalCaptureV1,
    states: &BTreeMap<Sha256Digest, OutboxRowStateV1>,
) -> CaptureResponseV1 {
    let items = provisional
        .items
        .iter()
        .map(|item| {
            let mut captured = CapturedItemV1 {
                item_id: item.item_id,
                version_id: item.version_id,
                uri: item.uri.clone(),
                disposition: CaptureDispositionV1::Withheld,
                withheld_reason: item.withheld_reason.clone(),
                accepted_event_ids: Vec::new(),
                redacted_ranges: item.redacted_ranges,
            };
            if item.withheld_reason.is_some() {
                return captured;
            }
            let parts: Vec<Option<&OutboxRowStateV1>> =
                item.stage_ids.iter().map(|id| states.get(id)).collect();
            captured.accepted_event_ids = parts
                .iter()
                .filter_map(|state| match state {
                    Some(OutboxRowStateV1::Admitted(event)) => Some(*event),
                    _ => None,
                })
                .collect();
            let refused = |wanted: OutboxRowStateV1| parts.contains(&Some(&wanted));
            if refused(OutboxRowStateV1::DeadLettered) {
                captured.withheld_reason =
                    Some(DeadLetterReasonV1::AdmissionRefused.as_str().to_owned());
            } else if refused(OutboxRowStateV1::Quarantined) {
                captured.withheld_reason = Some("quarantined".to_owned());
            } else if !parts.is_empty() && captured.accepted_event_ids.len() == parts.len() {
                captured.disposition = if item.already_admitted {
                    CaptureDispositionV1::Replayed
                } else {
                    CaptureDispositionV1::Admitted
                };
            } else {
                captured.disposition = CaptureDispositionV1::Staged;
            }
            captured
        })
        .collect();
    CaptureResponseV1 {
        operation: CAPTURE_OPERATION.to_owned(),
        items,
        idempotent_replay: false,
        projection: None,
    }
}

/// A committed final response, marked as the replay it now is.
fn replayed(mut response: Value) -> CaptureOutcomeV1 {
    if let Some(object) = response.as_object_mut() {
        object.insert("idempotent_replay".into(), Value::Bool(true));
    }
    CaptureOutcomeV1 {
        response,
        replayed: true,
    }
}

// ---------------------------------------------------------------------------
// The receipt
// ---------------------------------------------------------------------------

/// A committed capture receipt.
enum StoredCaptureV1 {
    /// Staged; the rows it names still have to be drained and the response
    /// finalized.
    Provisional(ProvisionalCaptureV1),
    /// Finished: the response to replay.
    Final(Value),
}

/// The canonical request a receipt binds: the trusted scope attribution and
/// the request's digest, never its text.
fn capture_request(scope: &FleetScope, request_digest: &Sha256Digest) -> Value {
    json!({
        "scope": {
            "project": scope.project,
            "agent": scope.agent,
            "session_id": scope.session_id,
            "privacy_tier": scope.privacy_tier,
        },
        "request_digest": request_digest,
    })
}

/// Decode a committed receipt as this request's. A receipt for another
/// project, operation, or request is an idempotency conflict.
fn decode_receipt(row: &PgRow, project: &str, request: &Value) -> Result<StoredCaptureV1> {
    let receipt_project: String = row.try_get("project")?;
    let operation: String = row.try_get("operation")?;
    let original: Value = row.try_get("request")?;
    if receipt_project != project || operation != CAPTURE_OPERATION || original != *request {
        return Err(FleetError::IdempotencyConflict(
            "idempotency key was already used for a different mutation".into(),
        ));
    }
    let response: Option<Value> = row.try_get("response")?;
    let response = response.ok_or_else(|| {
        FleetError::Memory("a committed capture receipt has no response".to_owned())
    })?;
    match response.get("provisional") {
        Some(provisional) => Ok(StoredCaptureV1::Provisional(
            serde_json::from_value(provisional.clone()).map_err(|error| {
                FleetError::Memory(format!(
                    "a provisional capture receipt does not decode: {error}"
                ))
            })?,
        )),
        None => Ok(StoredCaptureV1::Final(response)),
    }
}

async fn select_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: uuid::Uuid,
    key: &str,
) -> Result<Option<PgRow>> {
    Ok(sqlx::query(SELECT_RECEIPT_SQL)
        .bind(tenant_id)
        .bind(key)
        .fetch_optional(&mut **transaction)
        .await?)
}

/// What the staging transaction found or did.
enum ReservationV1 {
    /// This call reserved the key and staged the items.
    Reserved(ProvisionalCaptureV1),
    /// The key was already committed.
    Existing(StoredCaptureV1),
}

/// One provider scope's items, prepared for the staging transaction.
struct StagingGroupV1 {
    stage: PreparedStageV1,
    indices: Vec<usize>,
    binding: CollectedConnectorBindingV1,
}

/// Everything the staging transaction runs, owned, so a serialization retry
/// runs it again from the same inputs.
struct StagingPlanV1 {
    sink: CollectedItemSink,
    tenant_id: uuid::Uuid,
    project: String,
    key: String,
    request: Value,
    item_keys: Vec<Sha256Digest>,
    groups: Vec<StagingGroupV1>,
}

impl StagingPlanV1 {
    /// Reserve the key, stage every group, and write the provisional
    /// response, in `transaction`.
    async fn run(&self, transaction: &mut Transaction<'_, Postgres>) -> Result<ReservationV1> {
        if let Some(row) = select_receipt(transaction, self.tenant_id, &self.key).await? {
            return decode_receipt(&row, &self.project, &self.request).map(ReservationV1::Existing);
        }
        let reserved: Option<String> = sqlx::query_scalar(RESERVE_RECEIPT_SQL)
            .bind(self.tenant_id)
            .bind(&self.key)
            .bind(&self.project)
            .bind(&self.request)
            .fetch_optional(&mut **transaction)
            .await?;
        if reserved.is_none() {
            let row = select_receipt(transaction, self.tenant_id, &self.key)
                .await?
                .ok_or_else(|| {
                    FleetError::Memory("a concurrently reserved capture receipt disappeared".into())
                })?;
            return decode_receipt(&row, &self.project, &self.request).map(ReservationV1::Existing);
        }
        let provisional = self.stage(transaction).await?;
        let written = sqlx::query(WRITE_PROVISIONAL_SQL)
            .bind(self.tenant_id)
            .bind(&self.key)
            .bind(&self.project)
            .bind(&self.request)
            .bind(provisional.to_value()?)
            .execute(&mut **transaction)
            .await?
            .rows_affected();
        if written != 1 {
            return Err(FleetError::Memory(
                "the capture receipt reservation disappeared during staging".to_owned(),
            ));
        }
        Ok(ReservationV1::Reserved(provisional))
    }

    async fn stage(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<ProvisionalCaptureV1> {
        let mut items: Vec<Option<ProvisionalItemV1>> = vec![None; self.item_keys.len()];
        let mut unchanged = Vec::new();
        for group in &self.groups {
            let outcome = group.stage.run(transaction).await?;
            if outcome.items.len() != group.indices.len() {
                return Err(FleetError::Memory(
                    "the sink answered for another number of captured items".to_owned(),
                ));
            }
            for (&index, staged) in group.indices.iter().zip(&outcome.items) {
                let item = match staged {
                    StagedItemV1::Staged {
                        item_key,
                        version_key,
                        stage_ids,
                        new_rows,
                        redaction,
                    } => {
                        let uri = stage_ids
                            .first()
                            .map(|stage_id| group.binding.canonical_resource_uri(stage_id))
                            .transpose()
                            .map_err(|error| {
                                FleetError::Memory(format!(
                                    "a captured part has no version URI: {error}"
                                ))
                            })?
                            .map(|uri| uri.to_string());
                        if *new_rows == 0 {
                            unchanged.push(index);
                        }
                        ProvisionalItemV1 {
                            item_id: *item_key,
                            version_id: Some(*version_key),
                            uri,
                            stage_ids: stage_ids.clone(),
                            already_admitted: false,
                            withheld_reason: None,
                            redacted_ranges: redaction.redacted_ranges,
                        }
                    }
                    StagedItemV1::Refused { reason, diagnostic } => ProvisionalItemV1 {
                        item_id: self.item_keys[index],
                        version_id: None,
                        uri: None,
                        stage_ids: Vec::new(),
                        already_admitted: false,
                        withheld_reason: Some(withheld_reason(*reason, diagnostic)),
                        redacted_ranges: 0,
                    },
                };
                items[index] = Some(item);
            }
        }
        let mut items = items
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| FleetError::Memory("a captured item was not staged".to_owned()))?;
        // An item that staged no new row was captured before: it replays when
        // every part was already admitted then.
        let known: Vec<Sha256Digest> = unchanged
            .iter()
            .flat_map(|index| items[*index].stage_ids.iter().copied())
            .collect();
        if !known.is_empty() {
            let states = self.sink.row_states_in(transaction, &known).await?;
            for index in unchanged {
                let item = &mut items[index];
                item.already_admitted = item
                    .stage_ids
                    .iter()
                    .all(|id| matches!(states.get(id), Some(OutboxRowStateV1::Admitted(_))));
            }
        }
        Ok(ProvisionalCaptureV1 {
            schema_version: PROVISIONAL_SCHEMA_VERSION,
            items,
        })
    }
}

// ---------------------------------------------------------------------------
// The runtime
// ---------------------------------------------------------------------------

/// Agent capture over one scope.
#[async_trait]
pub trait ItemCapture: Send + Sync {
    /// Capture `request` under `idempotency_key` for `scope`'s agent. See the
    /// module documentation.
    async fn capture(
        &self,
        scope: &FleetScope,
        request: &PreparedCaptureV1,
        idempotency_key: &str,
    ) -> Result<CaptureOutcomeV1>;
}

/// Agent capture through the collected-item sink of one physical scope,
/// under the writer authority `serve` verified.
pub struct CockroachCapture {
    pool: PgPool,
    scope: FleetScope,
    sink: CollectedItemSink,
    authority: WriterAuthorityRuntime,
    identity: CaptureIdentityV1,
    mode: CollectedCaptureModeV1,
    scopes: Vec<CaptureScopeV1>,
    kek: Option<ContentKeyEncryptionKey>,
    /// The projectors an `enabled` capture runs after its drain; `None` in
    /// `stage_only`, where the worker admits and projects.
    projectors: Option<CaptureProjectorsV1>,
    retry: RetryPolicy,
}

impl std::fmt::Debug for CockroachCapture {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachCapture")
            .field("scope", &self.scope)
            .field("identity", &self.identity)
            .field("mode", &self.mode)
            .field("capture_scopes", &self.scopes.len())
            .field("projects", &self.projectors.is_some())
            .finish_non_exhaustive()
    }
}

fn refusal(code: RefusalCode, message: impl Into<String>) -> FleetError {
    LifecycleRefusal::new(code, message, json!({ "action": CAPTURE_OPERATION })).into()
}

fn writer_authority_unavailable(error: WriterAuthorityError) -> FleetError {
    match error {
        WriterAuthorityError::Database(error) => FleetError::Database(error),
        WriterAuthorityError::Rejected(rejection) => refusal(
            RefusalCode::WriterAuthorityUnavailable,
            format!("the pinned writer authority did not verify: {rejection}"),
        ),
        WriterAuthorityError::Contract(error) => refusal(
            RefusalCode::WriterAuthorityUnavailable,
            format!("the pinned writer authority is not a valid contract: {error}"),
        ),
    }
}

impl CockroachCapture {
    /// The identity this runtime captures as.
    #[must_use]
    pub const fn identity(&self) -> &CaptureIdentityV1 {
        &self.identity
    }

    /// Whether this runtime admits in the call or leaves rows to the worker.
    #[must_use]
    pub const fn mode(&self) -> CollectedCaptureModeV1 {
        self.mode
    }

    async fn verify(&self) -> Result<VerifiedWriterAuthority> {
        self.authority
            .verify()
            .await
            .map_err(writer_authority_unavailable)
    }

    /// The receipt under `key`, read outside any transaction.
    async fn read_receipt(&self, key: &str, request: &Value) -> Result<Option<StoredCaptureV1>> {
        let row: Option<PgRow> = sqlx::query(SELECT_RECEIPT_SQL)
            .bind(self.scope.tenant_id)
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref()
            .map(|row| decode_receipt(row, &self.scope.project, request))
            .transpose()
    }

    /// Bind the capture connector, and prepare one staging per provider
    /// scope under it.
    fn plan(
        &self,
        verified: &VerifiedWriterAuthority,
        prepared: &PreparedCaptureV1,
        key: &str,
        request: &Value,
    ) -> Result<StagingPlanV1> {
        let connector = CollectionModeV1::Capture.connector_schema_id();
        let active = verified
            .bind_connector(&ContractId::new(connector)?)
            .map_err(|error| {
                refusal(
                    RefusalCode::CaptureUnavailable,
                    format!(
                        "the active registry package does not admit {connector} ({error}); the \
                         operator runs `ostk-authority-install apply --target generation-3`"
                    ),
                )
            })?;
        let redactor = CollectorRedactorV1::from_active_package(&active).map_err(|error| {
            refusal(
                RefusalCode::CaptureUnavailable,
                format!("the active registry package promises no collector redaction: {error}"),
            )
        })?;
        let policy = AudiencePolicyV1::default();
        let groups = prepared.groups();
        let last = groups.len().saturating_sub(1);
        let mut staged = Vec::with_capacity(groups.len());
        for (position, ((provider, provider_scope_id), indices)) in groups.into_iter().enumerate() {
            let instance = CollectorInstanceV1 {
                connector_instance_id: self.identity.instance.clone(),
                provider: provider.clone(),
                provider_scope_id: BoundedTextV1::new(provider_scope_id)?,
            };
            let binding = CollectedConnectorBindingV1::resolve(
                &active,
                CollectionModeV1::Capture,
                self.identity.principal.clone(),
                instance.clone(),
            )
            .map_err(|error| {
                refusal(
                    RefusalCode::CaptureUnavailable,
                    format!("the capture connector does not bind: {error}"),
                )
            })?;
            let drafts: Vec<StageDraftV1> = indices
                .iter()
                .map(|index| StageDraftV1 {
                    draft: prepared.items[*index].draft.clone(),
                    // Never the agent's word: the sink derives a direct
                    // conversation's audience from the container kind.
                    provider_audience: None,
                    delivery_id: prepared.items[*index].delivery_id.clone(),
                })
                .collect();
            // The instance's status row is written once per capture, by its
            // last provider scope's staging.
            let status = (position == last).then(|| CollectorSourceStatusV1 {
                instance: self.identity.instance.clone(),
                provider: instance.provider.clone(),
                provider_scope_id: instance.provider_scope_id.clone(),
                mode: CollectionModeV1::Capture,
                coverage_role: CoverageRoleV1::None,
                owner: CollectorOwnerV1::Capture,
                stale_after_seconds: CAPTURE_STALE_AFTER_SECONDS,
                outcome: CollectorOutcomeV1::Ok,
                reconciled: false,
                error: None,
            });
            let stage = self.sink.prepare_stage(
                &drafts,
                &StageContextV1 {
                    instance: &instance,
                    principal: &self.identity.principal,
                    mode: CollectionModeV1::Capture,
                    attester: Some(&self.identity.principal),
                    via: prepared.via.as_deref(),
                    redactor: &redactor,
                    policy: &policy,
                    capture_scopes: &self.scopes,
                    pass_seq: None,
                    container_observations: &[],
                    cursor_advances: &[],
                    source_status: status.as_ref(),
                },
            )?;
            staged.push(StagingGroupV1 {
                stage,
                indices,
                binding,
            });
        }
        Ok(StagingPlanV1 {
            sink: self.sink.clone(),
            tenant_id: self.scope.tenant_id,
            project: self.scope.project.clone(),
            key: key.to_owned(),
            request: request.clone(),
            item_keys: prepared.items.iter().map(|item| item.item_key).collect(),
            groups: staged,
        })
    }

    /// Drain a staged capture's rows (when `enabled`), settle each item, and
    /// finalize the receipt, once.
    async fn finish(
        &self,
        key: &str,
        request: &Value,
        provisional: &ProvisionalCaptureV1,
        verified: Option<VerifiedWriterAuthority>,
    ) -> Result<CaptureOutcomeV1> {
        let stage_ids = provisional.stage_ids();
        if self.mode == CollectedCaptureModeV1::Enabled && !stage_ids.is_empty() {
            let kek = self.kek.as_ref().ok_or_else(|| {
                FleetError::Configuration(
                    "capture is enabled without FLEET_RECALL_CONTENT_KEK_HEX".to_owned(),
                )
            })?;
            let verified = match verified {
                Some(verified) => verified,
                // The key is already spent on the staged rows, so a head that
                // does not verify now is an unknown outcome to retry under
                // the same key, never a refusal.
                None => self.authority.verify().await.map_err(|error| match error {
                    WriterAuthorityError::Database(error) => FleetError::Database(error),
                    error => FleetError::Memory(format!(
                        "a capture is staged under this key, but the writer authority \
                             did not verify to admit it: {error}"
                    )),
                })?,
            };
            let context = CollectedDrainContextV1 {
                verified: &verified,
                ledger: self.authority.ledger().as_ref(),
                control_scope: self.authority.control_scope(),
                kek,
            };
            self.sink.drain_stage_ids(&context, &stage_ids).await?;
        }
        // Project what the drain admitted before answering, so the items are
        // recalled in this call and the scope's absence verdict does not
        // wait on a worker tick for them. A row the drain refused leaves
        // nothing to project; the pass is cheap then.
        let projection = match &self.projectors {
            Some(projectors) if !stage_ids.is_empty() => Some(projectors.project().await),
            _ => None,
        };
        let states = self.sink.row_states(&stage_ids).await?;
        let mut settled = settle(provisional, &states);
        settled.projection = projection;
        let response = serde_json::to_value(settled).map_err(|error| {
            FleetError::Protocol(format!("a capture response does not serialize: {error}"))
        })?;
        let (tenant_id, project, key_owned, request_owned, response_owned) = (
            self.scope.tenant_id,
            self.scope.project.clone(),
            Arc::new(key.to_owned()),
            Arc::new(request.clone()),
            Arc::new(response.clone()),
        );
        let finalized = with_serializable_retry(&self.pool, self.retry, move |transaction| {
            let (project, key, request, response) = (
                project.clone(),
                Arc::clone(&key_owned),
                Arc::clone(&request_owned),
                Arc::clone(&response_owned),
            );
            Box::pin(async move {
                Ok(sqlx::query(FINALIZE_SQL)
                    .bind(tenant_id)
                    .bind(key.as_str())
                    .bind(&project)
                    .bind(request.as_ref())
                    .bind(response.as_ref())
                    .execute(&mut **transaction)
                    .await?
                    .rows_affected())
            })
        })
        .await?;
        if finalized == 1 {
            return Ok(CaptureOutcomeV1 {
                response,
                replayed: false,
            });
        }
        // Another call finished this capture first: its answer is the one.
        match self.read_receipt(key, request).await? {
            Some(StoredCaptureV1::Final(response)) => Ok(replayed(response)),
            _ => Err(FleetError::Memory(
                "a capture receipt was neither provisional nor final".to_owned(),
            )),
        }
    }
}

#[async_trait]
impl ItemCapture for CockroachCapture {
    async fn capture(
        &self,
        scope: &FleetScope,
        prepared: &PreparedCaptureV1,
        idempotency_key: &str,
    ) -> Result<CaptureOutcomeV1> {
        if scope.tenant_id != self.scope.tenant_id
            || scope.project != self.scope.project
            || scope.agent != self.scope.agent
        {
            return Err(FleetError::InvalidScope(
                "a capture is made by the deployment-bound agent in its own scope".to_owned(),
            ));
        }
        let key = idempotency_key.trim();
        if key.is_empty() || key.len() > MAX_CAPTURE_KEY_BYTES {
            return Err(FleetError::InvalidScope(format!(
                "idempotency_key must be between 1 and {MAX_CAPTURE_KEY_BYTES} bytes"
            )));
        }
        let request = capture_request(scope, &prepared.request_digest);
        // A non-transactional fast path answers a committed capture without
        // verifying anything. The staging transaction reads the key again,
        // so a concurrent first capture stays at-most-once.
        match self.read_receipt(key, &request).await? {
            Some(StoredCaptureV1::Final(response)) => return Ok(replayed(response)),
            Some(StoredCaptureV1::Provisional(provisional)) => {
                return self.finish(key, &request, &provisional, None).await;
            }
            None => {}
        }
        let verified = self.verify().await?;
        let plan = Arc::new(self.plan(&verified, prepared, key, &request)?);
        let reservation = with_serializable_retry(&self.pool, self.retry, move |transaction| {
            let plan = Arc::clone(&plan);
            Box::pin(async move { plan.run(transaction).await })
        })
        .await?;
        match reservation {
            ReservationV1::Existing(StoredCaptureV1::Final(response)) => Ok(replayed(response)),
            ReservationV1::Reserved(provisional)
            | ReservationV1::Existing(StoredCaptureV1::Provisional(provisional)) => {
                self.finish(key, &request, &provisional, Some(verified))
                    .await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

/// Whether this writer serves `remember(action="capture")`, as
/// `recall(status).remember_capture` reports it.
///
/// Present only when `FLEET_RECALL_COLLECTED_CAPTURE` is not `disabled` (or
/// does not parse); a writer with capture disabled reports nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureStatusV1 {
    pub served: bool,
    /// `stage_only` or `enabled`; absent when the switch did not parse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<CollectedCaptureModeV1>,
    /// Why capture is off. Absent when it is served.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The principal and collector instance captures are recorded under,
    /// when served.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<CaptureIdentityV1>,
    /// How many capture scopes the operator declared, when served.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_scopes: Option<usize>,
}

impl CaptureStatusV1 {
    fn off(mode: Option<CollectedCaptureModeV1>, reason: String) -> Self {
        tracing::error!(
            reason = %reason,
            "remember(capture) is off: FLEET_RECALL_COLLECTED_CAPTURE is set but capture cannot be served; serving recall and remember without it"
        );
        Self {
            served: false,
            mode,
            reason: Some(reason),
            identity: None,
            capture_scopes: None,
        }
    }
}

/// What `serve` does about `remember(action="capture")`.
#[derive(Debug)]
pub enum CaptureStartup {
    /// Capture is configured and every startup check passed.
    Served(Arc<CockroachCapture>, CaptureStatusV1),
    /// Capture is configured but cannot be served; `serve` starts without it
    /// and reports why.
    Off(CaptureStatusV1),
    /// `FLEET_RECALL_COLLECTED_CAPTURE` is `disabled` (the default).
    NotConfigured,
}

impl CaptureStartup {
    /// The capture to serve, if any, and the status to report.
    #[must_use]
    pub fn into_parts(self) -> (Option<Arc<dyn ItemCapture>>, Option<CaptureStatusV1>) {
        match self {
            Self::Served(capture, status) => (Some(capture as Arc<dyn ItemCapture>), Some(status)),
            Self::Off(status) => (None, Some(status)),
            Self::NotConfigured => (None, None),
        }
    }
}

/// Start agent capture for `scope` under the process environment. See
/// [`start_collected_capture_with`].
pub async fn start_collected_capture(
    pool: PgPool,
    capabilities: &DatabaseCapabilities,
    scope: &FleetScope,
    retry: RetryPolicy,
    embedding: Option<Arc<dyn EmbeddingProvider>>,
) -> CaptureStartup {
    start_collected_capture_with(pool, capabilities, scope, retry, embedding, |name| {
        std::env::var(name).ok()
    })
    .await
}

/// Start agent capture for `scope` over an injected variable lookup.
///
/// Never fails: capture is additive, so a switch set to `disabled` (the
/// default) is [`CaptureStartup::NotConfigured`] and every other problem is
/// [`CaptureStartup::Off`] with its reason: a switch or scope list that does
/// not parse, a schema before migration 34, `enabled` without
/// `FLEET_RECALL_CONTENT_KEK_HEX` (only `enabled` reads it), missing or
/// unusable writer-authority pins, a login without capture's privileges
/// (for `enabled`, the projectors' too), an active package without
/// `connector.collected.capture`, or a capture instance another owner
/// already reports under.
///
/// `embedding` is the dense tier's provider under the process's pinned
/// model; an `enabled` capture embeds its admitted rows with it before
/// answering, and without one leaves them for the worker's `embed` step
/// (its projection then reports `complete: false`). `stage_only` ignores it.
pub async fn start_collected_capture_with(
    pool: PgPool,
    capabilities: &DatabaseCapabilities,
    scope: &FleetScope,
    retry: RetryPolicy,
    embedding: Option<Arc<dyn EmbeddingProvider>>,
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> CaptureStartup {
    let config = match CollectedCaptureConfig::from_lookup(&mut lookup) {
        Ok(config) => config,
        Err(error) => return CaptureStartup::Off(CaptureStatusV1::off(None, error.to_string())),
    };
    let mode = config.mode;
    if mode == CollectedCaptureModeV1::Disabled {
        return CaptureStartup::NotConfigured;
    }
    let off = |reason: String| CaptureStartup::Off(CaptureStatusV1::off(Some(mode), reason));
    let identity = match CaptureIdentityV1::for_agent(&scope.agent) {
        Ok(identity) => identity,
        Err(error) => return off(error.to_string()),
    };
    let CaptureInputsV1 {
        drain_kek,
        body_kek,
        pins,
    } = match inputs_before_io(mode, capabilities, &mut lookup) {
        Ok(inputs) => inputs,
        Err(reason) => return off(reason),
    };
    if let Err(error) = probe_capture_privileges(&pool, capabilities, mode).await {
        return off(startup_reason("capture's privileges did not verify", error));
    }
    let sink = match CollectedItemSink::new(pool.clone(), scope, retry) {
        Ok(sink) => sink,
        Err(error) => return off(error.to_string()),
    };
    match claimed_elsewhere(&sink, &identity.instance).await {
        Ok(Some(reason)) => return off(reason),
        Ok(None) => {}
        Err(error) => {
            return off(startup_reason(
                "the capture instance could not be read",
                error,
            ));
        }
    }
    let authority = match capture_authority(pool.clone(), scope, pins, retry).await {
        Ok(authority) => authority,
        Err(reason) => return off(reason),
    };
    // `enabled` projects what it admits in the call; the body projector
    // needs its own copy of the content key, which is not `Clone`.
    let projectors = body_kek.map(|kek| {
        CaptureProjectorsV1::new(pool.clone(), scope, &authority, kek, embedding, retry)
    });
    tracing::info!(
        mode = mode.as_str(),
        principal = %identity.principal,
        instance = %identity.instance,
        projects = projectors.is_some(),
        "serving remember(capture) under the verified writer authority"
    );
    let status = CaptureStatusV1 {
        served: true,
        mode: Some(mode),
        reason: None,
        identity: Some(identity.clone()),
        capture_scopes: Some(config.scopes.len()),
    };
    CaptureStartup::Served(
        Arc::new(CockroachCapture {
            pool,
            scope: scope.clone(),
            sink,
            authority,
            identity,
            mode,
            scopes: config.scopes,
            kek: drain_kek,
            projectors,
            retry,
        }),
        status,
    )
}

/// What capture startup reads before any I/O.
struct CaptureInputsV1 {
    /// The content key the drain seals with; `enabled` only.
    drain_kek: Option<ContentKeyEncryptionKey>,
    /// The same key, parsed again for the body projector (the key is not
    /// `Clone`); `enabled` only.
    body_kek: Option<ContentKeyEncryptionKey>,
    pins: WriterAuthorityConfig,
}

/// What capture startup decides before any I/O: the schema is recent enough,
/// the content key is present exactly when `enabled` needs it, and the
/// writer-authority pins are configured.
fn inputs_before_io(
    mode: CollectedCaptureModeV1,
    capabilities: &DatabaseCapabilities,
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> std::result::Result<CaptureInputsV1, String> {
    if !capabilities.supports_schema_version(COLLECTED_ITEMS_SCHEMA_VERSION) {
        return Err(format!(
            "capture needs the schema through migration {COLLECTED_ITEMS_SCHEMA_VERSION}, but \
             this database has reached {}; run `ostk-fleet-recall migrate`",
            capabilities.schema_version
        ));
    }
    let mut kek = || -> std::result::Result<ContentKeyEncryptionKey, String> {
        content_kek_from_lookup(&mut lookup)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| {
                "FLEET_RECALL_COLLECTED_CAPTURE=enabled admits and projects captures in serve, \
                 which needs FLEET_RECALL_CONTENT_KEK_HEX; stage_only leaves admission to the \
                 worker and needs no key"
                    .to_owned()
            })
    };
    // The drain seals with one copy and the body projector opens with
    // another: the key is not `Clone`, so it is parsed twice, as the worker
    // parses it for its ingest and bodies steps.
    let (drain_kek, body_kek) = if mode == CollectedCaptureModeV1::Enabled {
        (Some(kek()?), Some(kek()?))
    } else {
        (None, None)
    };
    let pins = WriterAuthorityConfig::from_lookup(&mut lookup)
        .map_err(|error| format!("the writer-authority pins are invalid: {error}"))?
        .ok_or_else(|| {
            "capture needs the writer-authority pins that `ostk-authority-install apply` prints"
                .to_owned()
        })?;
    Ok(CaptureInputsV1 {
        drain_kek,
        body_kek,
        pins,
    })
}

/// Start the writer authority under `pins`, and check that its active package
/// binds `connector.collected.capture`.
async fn capture_authority(
    pool: PgPool,
    scope: &FleetScope,
    pins: WriterAuthorityConfig,
    retry: RetryPolicy,
) -> std::result::Result<WriterAuthorityRuntime, String> {
    let (authority, _) = WriterAuthorityRuntime::start(pool, scope.clone(), pins, retry)
        .await
        .map_err(|error| super::serve::start_reason(&error))?;
    let verified = authority
        .verify()
        .await
        .map_err(|error| super::serve::verify_reason(&error))?;
    let connector = CollectionModeV1::Capture.connector_schema_id();
    ContractId::new(connector)
        .map_err(|error| error.to_string())
        .and_then(|schema| {
            verified
                .bind_connector(&schema)
                .map_err(|error| error.to_string())
        })
        .map_err(|error| {
            format!(
                "the active registry package does not admit {connector} ({error}); run \
                 `ostk-authority-install apply --target generation-3`"
            )
        })?;
    Ok(authority)
}

/// A startup failure as `recall(status)` reports it: a database failure is
/// logged and reported without its detail.
fn startup_reason(what: &str, error: FleetError) -> String {
    match error {
        FleetError::Database(error) => {
            tracing::error!(error = %error, "{what}");
            format!("{what}: the database could not be read by this login")
        }
        error => format!("{what}: {error}"),
    }
}

/// Why `instance` cannot be a capture instance: a worker source or a
/// collector of another owner already reports under it.
async fn claimed_elsewhere(
    sink: &CollectedItemSink,
    instance: &ContractId,
) -> Result<Option<String>> {
    if sink.worker_source_exists(instance).await? {
        return Ok(Some(format!(
            "the capture instance {instance} is a worker source (git, transcripts, or CI)"
        )));
    }
    Ok(sink
        .collector_source(instance)
        .await?
        .filter(|row| row.owner != CollectorOwnerV1::Capture.as_str())
        .map(|row| {
            format!(
                "the capture instance {instance} already reports as a {} collector",
                row.owner
            )
        }))
}

#[cfg(test)]
#[path = "capture_tests.rs"]
mod tests;
