use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;

use crate::evidence_recall::ContentTrustV1;
use crate::item_recall::ItemSuppressionV1;
use crate::ledger::{canonical_json, claim_key_from_parts, normalize_key_part};
use crate::memory_contracts::bootstrap::EpochId;
use crate::memory_contracts::collected_item::{MAX_PROVIDER_URL_BYTES, TrustTierV1};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::discrepancy::{DismissalReasonKindV1, WaiverReasonKindV1};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::{FleetError, Result};

// `memory_claims` are projected into `memory_chunks`, whose generated
// `TSVECTOR` rejects lexemes above CockroachDB's 16,383-byte limit. Validate at
// the domain boundary so a schema-valid remember call cannot fail only after
// embedding and entering its serializable mutation.
const MAX_TSVECTOR_INPUT_LEXEME_BYTES: usize = 16_000;
/// Largest compact serialized claim value a claim row stores.
pub const MAX_CLAIM_VALUE_SERIALIZED_BYTES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    Observation,
    Note,
    Decision,
    Fact,
    Constraint,
    Preference,
    Procedure,
    OpenQuestion,
}

impl ClaimKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Note => "note",
            Self::Decision => "decision",
            Self::Fact => "fact",
            Self::Constraint => "constraint",
            Self::Preference => "preference",
            Self::Procedure => "procedure",
            Self::OpenQuestion => "open_question",
        }
    }

    #[must_use]
    pub const fn is_conflict_eligible(self) -> bool {
        matches!(
            self,
            Self::Decision | Self::Fact | Self::Constraint | Self::Preference | Self::Procedure
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimState {
    Active,
    Disputed,
    Unsupported,
    Superseded,
    Retracted,
    Suppressed,
    Expired,
}

impl ClaimState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disputed => "disputed",
            Self::Unsupported => "unsupported",
            Self::Superseded => "superseded",
            Self::Retracted => "retracted",
            Self::Suppressed => "suppressed",
            Self::Expired => "expired",
        }
    }

    #[must_use]
    pub const fn is_current(self) -> bool {
        matches!(self, Self::Active | Self::Disputed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSupportInput {
    pub source_config_id: String,
    pub source: String,
    pub source_id: String,
    pub chunk_id: Option<String>,
    pub content_sha256: Option<String>,
    pub excerpt: Option<String>,
    #[serde(default = "default_support_relation")]
    pub relation: String,
}

fn default_support_relation() -> String {
    "supports".into()
}

/// Most collected items one claim cites: `record`'s item support entries
/// share [`ClaimInput`]'s 32-entry support bound, and `assert` takes at most
/// this many `support_items` (ADR 0008 D11).
pub const MAX_SUPPORT_ITEMS: usize = 32;

/// The `source_config_id` of a `record` item citation's opaque support row.
///
/// Its `source` is [`ITEM_SUPPORT_SOURCE`] and its `source_id` the lowercase
/// hex of the citation's random link id; which item it cites lives only in
/// the private `memory_claim_item_links_v1`, never in a publication table
/// (ADR 0008 D11).
pub const ITEM_SUPPORT_SOURCE_CONFIG_ID: &str = "fleet.item";
/// The `source` of the opaque support row an item citation writes.
pub const ITEM_SUPPORT_SOURCE: &str = "item-link";

/// A collected item a claim cites (ADR 0008 D11).
///
/// Exactly one of the item's id (its presented version is cited), one exact
/// version's id, or the item's `https` provider URL (its presented version is
/// cited). The ids are what `recall(kind=item)` and `remember(capture)`
/// return.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ItemRefV1 {
    /// `{"item_id": "<64 hex>"}`: the item's presented version.
    ItemId(Sha256Digest),
    /// `{"version_id": "<64 hex>"}`: exactly this version.
    VersionId(Sha256Digest),
    /// `{"url": "https://..."}`: the presented version of the item whose
    /// provider URL this is.
    Url(String),
}

impl ItemRefV1 {
    /// Check the reference's shape before any I/O.
    ///
    /// # Errors
    ///
    /// A URL that is not `https://`, is longer than a stored provider URL may
    /// be, or holds whitespace or a control character.
    pub fn validate(&self) -> Result<()> {
        let Self::Url(url) = self else {
            return Ok(());
        };
        if !url.starts_with("https://")
            || url.len() > MAX_PROVIDER_URL_BYTES
            || url
                .chars()
                .any(|scalar| scalar.is_whitespace() || scalar.is_control())
        {
            return Err(FleetError::Memory(format!(
                "a support item url must be an https URL of at most {MAX_PROVIDER_URL_BYTES} bytes \
                 with no whitespace"
            )));
        }
        Ok(())
    }
}

/// One `record` support entry that cites a collected item instead of a
/// corpus chunk (ADR 0008 D11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemSupportInputV1 {
    pub item: ItemRefV1,
    #[serde(default = "default_support_relation")]
    pub relation: String,
}

impl ItemSupportInputV1 {
    /// Check the reference and the relation before any I/O.
    ///
    /// # Errors
    ///
    /// As [`ItemRefV1::validate`], or a relation that is empty, has leading
    /// or trailing whitespace, or exceeds 64 bytes.
    pub fn validate(&self) -> Result<()> {
        self.item.validate()?;
        if self.relation.trim().is_empty()
            || self.relation != self.relation.trim()
            || self.relation.len() > 64
        {
            return Err(FleetError::Memory(
                "an item support relation must be 1 to 64 bytes with no leading or trailing \
                 whitespace"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// One collected item a claim cites, expanded (ADR 0008 D11).
///
/// It is read through the private claim item links: only the private
/// writer's `recall(get, kind=claim)` returns it, and the publication reader
/// never reads the links.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CitedItemV1 {
    /// The citation's link id, 32 lowercase hex characters: the `source_id`
    /// of the opaque support row a `record` citation wrote.
    pub link_id: String,
    /// The claim action that cited the item: `assert` or `record`.
    pub via: String,
    pub relation: String,
    pub item_id: Sha256Digest,
    /// The version cited.
    pub version_id: Sha256Digest,
    /// The cited version's URI (its first cited part's `canonical_resource_id`):
    /// `recall(get, kind=item)` with it, or with `version_id`, returns exactly
    /// the cited bytes.
    pub uri: String,
    pub provider: String,
    pub object_kind: String,
    pub external_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_url: Option<String>,
    /// The tier the cited parts were admitted through: `verified` (pull,
    /// push), or `reported` (capture, import) when any part was reported.
    pub trust: TrustTierV1,
    /// Whether the cited version is still the item's presented version.
    pub current: bool,
    /// Why the item is withheld from recall now, when it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<ItemSuppressionV1>,
    /// The accepted evidence events of the cited parts, in part order.
    pub accepted_event_ids: Vec<Sha256Digest>,
    /// The content digest of each cited part, in the same order as
    /// `accepted_event_ids`: the bytes the claim cited, whatever the item
    /// says now.
    pub content_digests: Vec<Sha256Digest>,
    /// Always `untrusted_third_party`: the ids, URL, and kinds above are a
    /// provider's, an importer's, or an agent's strings, to read as data.
    pub content_trust: ContentTrustV1,
}

/// The collected items one claim cites (ADR 0008 D11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimItemSupportV1 {
    /// Each citation, oldest first.
    pub items: Vec<CitedItemV1>,
    /// Distinct contents among the cited items still visible: each item
    /// counts once however many of its versions are cited (its current one's
    /// content when that is cited), and items with identical text (an echo,
    /// a cross-post, a copy) count once.
    pub independent_sources: u64,
    /// The claim has more link rows than one read returns.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// One `record` support entry: a corpus snapshot, exactly as before, or a
/// collected item.
///
/// It serializes untagged, so a corpus entry's bytes (and so every stored
/// `record` receipt's request) are exactly a [`ClaimSupportInput`]'s. It
/// deserializes an object that names `item` as an [`ItemSupportInputV1`] and
/// every other value as a [`ClaimSupportInput`], each with unknown fields
/// denied, so a corpus entry is checked exactly as strictly, and refused with
/// exactly the message, as before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum SupportInputV1 {
    Corpus(ClaimSupportInput),
    Item(ItemSupportInputV1),
}

impl<'de> Deserialize<'de> for SupportInputV1 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let cites_item = value
            .as_object()
            .is_some_and(|fields| fields.contains_key("item"));
        if cites_item {
            serde_json::from_value(value).map(Self::Item)
        } else {
            serde_json::from_value(value).map(Self::Corpus)
        }
        .map_err(de::Error::custom)
    }
}

impl From<ClaimSupportInput> for SupportInputV1 {
    fn from(support: ClaimSupportInput) -> Self {
        Self::Corpus(support)
    }
}

impl SupportInputV1 {
    /// The corpus snapshot, when this entry is one.
    #[must_use]
    pub const fn as_corpus(&self) -> Option<&ClaimSupportInput> {
        match self {
            Self::Corpus(support) => Some(support),
            Self::Item(_) => None,
        }
    }

    /// The item citation, when this entry is one.
    #[must_use]
    pub const fn as_item(&self) -> Option<&ItemSupportInputV1> {
        match self {
            Self::Item(support) => Some(support),
            Self::Corpus(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimInput {
    pub kind: ClaimKind,
    pub text: String,
    pub subject: Option<String>,
    pub predicate: Option<String>,
    pub value: Option<Value>,
    #[serde(default = "default_polarity")]
    pub polarity: i16,
    #[serde(default = "default_origin")]
    pub origin: String,
    pub actor: Option<String>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_to: Option<DateTime<Utc>>,
    /// Corpus snapshots and, where the deployment serves claim item links,
    /// collected items (ADR 0008 D11); at most 32 in all.
    #[serde(default)]
    pub support: Vec<SupportInputV1>,
}

const fn default_polarity() -> i16 {
    1
}

fn default_origin() -> String {
    "operator_asserted".into()
}

const fn default_confidence() -> f64 {
    1.0
}

impl ClaimInput {
    #[allow(clippy::too_many_lines)] // centralized wire/domain validation keeps limits consistent
    pub fn validate(&self) -> Result<()> {
        let text = self.text.trim();
        if text.is_empty() {
            return Err(FleetError::Memory("claim text must not be empty".into()));
        }
        if text.len() > 100_000 {
            return Err(FleetError::Memory(
                "claim text must not exceed 100,000 bytes".into(),
            ));
        }
        if self.text != text {
            return Err(FleetError::Memory(
                "claim text must not have leading or trailing whitespace".into(),
            ));
        }
        if let Some(lexeme) = self
            .text
            .split_whitespace()
            .find(|lexeme| lexeme.len() > MAX_TSVECTOR_INPUT_LEXEME_BYTES)
        {
            return Err(FleetError::Memory(format!(
                "claim text contains a whitespace-delimited lexeme of {} UTF-8 bytes; the limit is {MAX_TSVECTOR_INPUT_LEXEME_BYTES} bytes",
                lexeme.len()
            )));
        }
        if !matches!(self.polarity, -1 | 1) {
            return Err(FleetError::Memory("claim polarity must be -1 or 1".into()));
        }
        if !self.confidence.is_finite() || !(0.0..=1.0).contains(&self.confidence) {
            return Err(FleetError::Memory(
                "claim confidence must be finite and between 0 and 1".into(),
            ));
        }
        if let (Some(from), Some(to)) = (self.valid_from, self.valid_to)
            && to <= from
        {
            return Err(FleetError::Memory(
                "valid_to must be after valid_from".into(),
            ));
        }
        if self
            .subject
            .as_ref()
            .is_some_and(|value| value.len() > 1_024)
            || self
                .predicate
                .as_ref()
                .is_some_and(|value| value.len() > 1_024)
        {
            return Err(FleetError::Memory(
                "claim subject and predicate must not exceed 1024 bytes".into(),
            ));
        }
        if self.origin.trim().is_empty() || self.origin.len() > 256 {
            return Err(FleetError::Memory(
                "claim origin must be between 1 and 256 bytes".into(),
            ));
        }
        if self.origin != self.origin.trim() {
            return Err(FleetError::Memory(
                "claim origin must not have leading or trailing whitespace".into(),
            ));
        }
        if !matches!(
            self.origin.as_str(),
            "operator_asserted" | "source_derived" | "legacy_unverified"
        ) {
            return Err(FleetError::Memory(format!(
                "unsupported claim origin: {}",
                self.origin
            )));
        }
        if self
            .value
            .as_ref()
            .is_some_and(|value| value.to_string().len() > MAX_CLAIM_VALUE_SERIALIZED_BYTES)
        {
            return Err(FleetError::Memory(
                "claim value must not exceed 100,000 serialized bytes".into(),
            ));
        }
        if self
            .actor
            .as_ref()
            .is_some_and(|actor| actor.trim().is_empty() || actor.len() > 256)
        {
            return Err(FleetError::Memory(
                "claim actor must be between 1 and 256 bytes when present".into(),
            ));
        }
        if self.support.len() > 32 {
            return Err(FleetError::Memory(
                "a claim may have at most 32 support records".into(),
            ));
        }
        for support in &self.support {
            let support = match support {
                SupportInputV1::Corpus(support) => support,
                SupportInputV1::Item(item) => {
                    item.validate()?;
                    continue;
                }
            };
            if support.source.trim().is_empty()
                || support.source_id.trim().is_empty()
                || support.source_config_id.trim().is_empty()
                || support.relation.trim().is_empty()
            {
                return Err(FleetError::Memory(
                    "claim support source_config_id, source, source_id, and relation must not be empty"
                        .into(),
                ));
            }
            if support.source.len() > 256
                || support.source_id.len() > 4_096
                || support.source_config_id.len() > 256
                || support.relation.len() > 64
                || support
                    .chunk_id
                    .as_ref()
                    .is_some_and(|chunk_id| chunk_id.trim().is_empty() || chunk_id.len() > 256)
                || support
                    .excerpt
                    .as_ref()
                    .is_some_and(|excerpt| excerpt.len() > 8_000)
            {
                return Err(FleetError::Memory(
                    "claim support exceeds a field-size limit".into(),
                ));
            }
            if support.chunk_id.is_some()
                && !support.content_sha256.as_ref().is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            {
                return Err(FleetError::Memory(
                    "chunk-backed claim support content_sha256 must be a 64-character hex digest"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    /// The collected items this claim's support cites, in order.
    pub fn item_support(&self) -> impl Iterator<Item = &ItemSupportInputV1> {
        self.support.iter().filter_map(SupportInputV1::as_item)
    }

    /// Whether any support entry cites a collected item.
    #[must_use]
    pub fn cites_items(&self) -> bool {
        self.item_support().next().is_some()
    }

    pub(crate) fn prepare(&self) -> Result<PreparedClaim> {
        self.validate()?;
        let subject = self.subject.as_deref().map(normalize_key_part);
        let predicate = self.predicate.as_deref().map(normalize_key_part);
        let claim_key = match (&subject, &predicate) {
            (Some(subject), Some(predicate)) => claim_key_from_parts(subject, predicate),
            _ => None,
        };
        let value = self.value.as_ref().map(canonical_json);
        let conflict_eligible =
            claim_key.is_some() && value.is_some() && self.kind.is_conflict_eligible();
        Ok(PreparedClaim {
            subject,
            predicate,
            claim_key,
            value,
            conflict_eligible,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedClaim {
    pub subject: Option<String>,
    pub predicate: Option<String>,
    pub claim_key: Option<String>,
    pub value: Option<Value>,
    pub conflict_eligible: bool,
}

/// How many lifecycle-current claims of a project still carry a claim key
/// written under the earlier normalizer.
///
/// That normalizer kept `_`, so `include_transcript_default::x` never met
/// `include-transcript-default::x`. A row is legacy iff
/// `claim_key_from_parts(subject, predicate)` differs from its stored key;
/// `remember(assert)`'s `claim-v2:` keys are never counted. No migration
/// rewrites keys: a supersede moves a legacy claim onto its current key, and
/// `recall(status)` reports this count so the detection gap is visible until
/// then.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LegacyClaimKeysV1 {
    /// Legacy rows found, at most the scan bound.
    pub count: usize,
    /// The bounded scan filled up, so `count` is a lower bound.
    pub bound_exceeded: bool,
    /// The first legacy rows found (at most [`MAX_LEGACY_CLAIM_KEY_SAMPLE`]),
    /// so an operator can name what to supersede.
    pub sample: Vec<LegacyClaimKeySampleV1>,
}

/// Legacy-key rows `recall(status)` names.
pub const MAX_LEGACY_CLAIM_KEY_SAMPLE: usize = 10;

/// One lifecycle-current claim still keyed under the earlier normalizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyClaimKeySampleV1 {
    pub claim_id: i64,
    /// The stored key, as the detector compares it.
    pub claim_key: String,
    pub actor: Option<String>,
}

/// Claims one exact-key lookup (`recall(get, kind=claim, key=…)`) reads
/// before reporting a cut: the detector's own comparison bound.
pub const MAX_KEY_LOOKUP_CLAIMS: usize = 256;

/// Largest canonical `value` an exact-key lookup carries per claim; a larger
/// one is reported elided and read whole by `get` with the claim's id.
pub const MAX_KEY_LOOKUP_VALUE_BYTES: usize = 16 * 1024;

/// One claim of an exact-key lookup: the claim as `get` returns it, with its
/// support and current conflicts, plus whether its value was elided.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyClaimV1 {
    #[serde(flatten)]
    pub claim: Claim,
    /// The claim's canonical value was larger than
    /// [`MAX_KEY_LOOKUP_VALUE_BYTES`] and is left out.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub value_elided: bool,
}

/// Every claim on one exact key, oldest first: the lifecycle-current ones,
/// or every state with `include_history`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimsForKeyV1 {
    pub claims: Vec<KeyClaimV1>,
    /// More claims carry the key than [`MAX_KEY_LOOKUP_CLAIMS`]; the ones
    /// returned are the oldest.
    pub truncated: bool,
}

/// Lifecycle events one claim `get` reads before reporting a cut.
pub const MAX_CLAIM_HISTORY_EVENTS: usize = 256;

/// One row of a claim's lifecycle log (`memory_claim_events`), as
/// `recall(get, kind=claim)` returns it: who moved the claim between which
/// states, why, and what the transition named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimLifecycleEventV1 {
    pub event_id: String,
    /// `recorded` for the claim's birth (`to_state` active, no reason), then
    /// `state_transition` for every logged transition.
    pub kind: String,
    /// The agent whose mutation wrote it: the author for a retract or
    /// supersede, the recording agent for a detected conflict, the closer
    /// for a restore.
    pub actor: Option<String>,
    /// `conflict_detected`, `retracted_by_author`, `superseded_by_author`,
    /// or a close's restore reason.
    pub reason: Option<String>,
    pub from_state: Option<String>,
    pub to_state: Option<String>,
    /// The claim revision the transition left behind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_before: Option<i64>,
    /// For `superseded_by_author`, the successor the author wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_claim_id: Option<i64>,
    /// For `conflict_detected` and a close's restore, the conflict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict_id: Option<i64>,
    /// For a successor's `recorded` event, the predecessor it superseded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<i64>,
    /// The audit note the author sent with the mutation, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
    /// The stored payload was larger than the read bound, so the fields
    /// above that come from it are absent.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub payload_elided: bool,
}

/// A claim's lifecycle history, in event order, with the predecessor it
/// superseded when it is a successor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimHistoryV1 {
    pub events: Vec<ClaimLifecycleEventV1>,
    /// Older events exist than the bounded history returns.
    pub truncated: bool,
    /// The claim this one superseded: the same key's claim whose
    /// `superseded_by` names it.
    pub supersedes: Option<i64>,
}

/// Open conflicts `recall(status)` counts before reporting a lower bound.
pub const MAX_OPEN_CONFLICT_ROWS: usize = 256;

/// One open conflict as the status read sees it: what the lifecycle overlay
/// needs to say whether it is acknowledged or waived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenConflictRowV1 {
    pub id: i64,
    pub revision: i64,
    pub member_count: i64,
    pub detected_at: DateTime<Utc>,
}

/// The project's open conflicts, oldest first, bounded by
/// [`MAX_OPEN_CONFLICT_ROWS`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpenConflictsV1 {
    pub rows: Vec<OpenConflictRowV1>,
    /// More conflicts are open than the bound; the counts are lower bounds.
    pub bound_exceeded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimSupport {
    pub id: i64,
    pub source_config_id: String,
    pub source: String,
    pub source_id: String,
    pub chunk_id: Option<String>,
    pub content_sha256: Option<String>,
    pub excerpt: Option<String>,
    pub relation: String,
    pub state: String,
    pub observed_at: DateTime<Utc>,
    pub invalidated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub id: i64,
    pub project: String,
    pub kind: ClaimKind,
    pub claim_key: Option<String>,
    pub subject: Option<String>,
    pub predicate: Option<String>,
    pub value: Option<Value>,
    pub text: String,
    pub polarity: i16,
    pub state: ClaimState,
    pub origin: String,
    pub actor: Option<String>,
    pub confidence: f64,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_to: Option<DateTime<Utc>>,
    pub superseded_by: Option<i64>,
    pub revision: i64,
    pub conflict_eligible: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub support: Vec<ClaimSupport>,
    #[serde(default)]
    pub conflict_ids: Vec<i64>,
}

impl Claim {
    #[must_use]
    pub fn embedding_passages(&self) -> Vec<String> {
        const MAX_PASSAGES: usize = 12;
        const MAX_PASSAGE_CHARS: usize = 1_000;

        let metadata = self.embedding_metadata();
        let mut passages = self
            .text
            .split("\n\n")
            .map(str::trim)
            .filter(|paragraph| !paragraph.is_empty())
            .flat_map(|paragraph| split_passage(paragraph, MAX_PASSAGE_CHARS))
            .collect::<Vec<_>>();
        if passages.is_empty() {
            passages.push(self.text.clone());
        }
        if passages.len() > MAX_PASSAGES {
            let last = passages.len() - 1;
            passages = (0..MAX_PASSAGES)
                .map(|index| passages[index * last / (MAX_PASSAGES - 1)].clone())
                .collect();
        }
        passages
            .into_iter()
            .map(|passage| {
                if metadata.is_empty() {
                    passage
                } else {
                    format!("{passage}\n{metadata}")
                }
            })
            .collect()
    }

    fn embedding_metadata(&self) -> String {
        let mut fields = vec![format!("kind: {}", self.kind.as_str())];
        if let Some(subject) = self.subject.as_deref().filter(|value| !value.is_empty()) {
            fields.push(format!("subject: {subject}"));
        }
        if let Some(predicate) = self.predicate.as_deref().filter(|value| !value.is_empty()) {
            fields.push(format!("predicate: {predicate}"));
        }
        if let Some(value) = &self.value {
            let rendered = value.to_string();
            if rendered != self.text.trim() && rendered.chars().count() <= 500 {
                fields.push(format!("value: {rendered}"));
            }
        }
        fields.join("\n")
    }
}

fn split_passage(text: &str, max_chars: usize) -> Vec<String> {
    let chars = text.chars().collect::<Vec<_>>();
    if chars.len() <= max_chars {
        return vec![text.to_string()];
    }
    chars
        .chunks(max_chars)
        .map(|chunk| chunk.iter().collect())
        .collect()
}

/// Largest canonical `value` a claim search hit carries; a larger one is
/// elided with `value_elided: true` and read whole by `get`.
pub const MAX_CLAIM_HIT_VALUE_BYTES: usize = 2_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticClaimHit {
    pub claim: Claim,
    pub similarity: f64,
    pub passage_index: i32,
    pub matched_passage: String,
    /// The claim's revision, repeated beside the claim so a hit can be
    /// superseded or retracted without a second read.
    #[serde(default)]
    pub revision: i64,
    /// The claim's author, repeated beside the claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// The claim's canonical value was larger than
    /// [`MAX_CLAIM_HIT_VALUE_BYTES`] and is left out; `get` returns it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub value_elided: bool,
    /// The claim's support rows are left out of the hit; `get` returns them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub support_elided: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Conflict {
    pub id: i64,
    pub project: String,
    pub claim_key: String,
    pub kind: String,
    pub state: String,
    pub detector: String,
    pub rationale: String,
    pub revision: i64,
    pub detected_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_kind: Option<String>,
    pub resolution_reason: Option<String>,
    /// Total durable member count, including members omitted from this bounded
    /// response projection.
    #[serde(default)]
    pub member_count: usize,
    /// True when `members` contains only a bounded prefix of durable members.
    #[serde(default)]
    pub members_truncated: bool,
    /// True when at least one returned member's large canonical value was
    /// elided. The durable claim remains unchanged and can be fetched by ID.
    #[serde(default)]
    pub member_values_elided: bool,
    pub members: Vec<Claim>,
    /// Query-local claim IDs that caused this conflict to be selected. This is
    /// not durable conflict state and is projected separately in retrieval
    /// diagnostics, so it never appears in the public conflict envelope.
    #[serde(skip)]
    pub(crate) trigger_claim_ids: Vec<i64>,
    /// The serving lifecycle overlay (ADR 0004), attached only on the private
    /// writer after a separate post-read. Absent everywhere else, so
    /// publication bytes are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<ConflictLifecycleOverlay>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimMutation {
    pub operation: String,
    pub claim: Claim,
    /// The predecessor a `supersede` retired in favour of `claim`. Omitted
    /// otherwise, so record responses and stored receipts keep their bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded: Option<SupersededClaim>,
    pub idempotent_replay: bool,
    pub conflicts_opened: Vec<i64>,
    pub conflicts_resolved: Vec<i64>,
    /// Disputed claims a detector-verified close returned to `active`. Omitted
    /// when empty so record responses and stored receipts keep their bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims_restored: Vec<i64>,
    /// How a lifecycle change re-evaluated the key's open v2 conflict. Absent
    /// for record and whenever no open v2 conflict was re-evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reevaluation: Option<ConflictReevaluation>,
}

/// Where the accepted event an asserted claim was projected from sits in the
/// general accepted-event ledger (`memory_evidence_events`).
///
/// `event_id` is the semantic accepted-event identity; the rest is the
/// physical append position, which is never part of that identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedEventRefV1 {
    pub event_id: AcceptedEventId,
    pub epoch_id: EpochId,
    pub shard: u16,
    pub committed_offset: u64,
}

/// The committed result of `remember(action="assert")`: the claim mutation
/// exactly as record shapes it, plus the accepted event it projects.
///
/// This, not [`ClaimMutation`], is the stored receipt response of an assert,
/// so a record response or receipt never gains an `accepted_event` key and a
/// replayed assert returns the event it committed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssertedClaimMutation {
    #[serde(flatten)]
    pub mutation: ClaimMutation,
    pub accepted_event: AcceptedEventRefV1,
}

/// The predecessor claim of a committed `supersede`, as that mutation left it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupersededClaim {
    pub id: i64,
    pub state: ClaimState,
    /// The predecessor's revision after the transition to `superseded`.
    pub revision: i64,
    /// The successor claim that replaced it.
    pub superseded_by: i64,
}

/// An owner lifecycle target: the claim and the revision the caller last read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimTarget {
    pub claim_id: i64,
    pub expected_revision: i64,
}

/// A lifecycle request as parsed by a writer that does not serve its action.
/// That writer still replays a receipt committed for exactly this request.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LifecycleReplayRequest<'a> {
    Retract {
        target: ClaimTarget,
        reason: Option<&'a str>,
    },
    Supersede {
        target: ClaimTarget,
        reason: Option<&'a str>,
        successor: &'a ClaimInput,
    },
    Acknowledge {
        target: ConflictTarget,
        reason: Option<&'a str>,
    },
    Resolve {
        target: ConflictTarget,
        retract_claim_ids: &'a [i64],
        reason: Option<&'a str>,
    },
    Dismiss {
        target: ConflictTarget,
        terms: DismissalTerms<'a>,
    },
    Waive {
        target: ConflictTarget,
        terms: WaiverTerms<'a>,
    },
}

/// An adjudicator's dismissal of a conflict: the closed reason vocabulary of
/// the discrepancy contract and a required, bounded rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DismissalTerms<'a> {
    pub reason_kind: DismissalReasonKindV1,
    pub rationale: &'a str,
}

/// An adjudicator's waiver of a conflict's current episode. The database
/// clock turns the hours into its expiry and optional review time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaiverTerms<'a> {
    pub reason_kind: WaiverReasonKindV1,
    pub rationale: &'a str,
    /// 1..=2160.
    pub expires_in_hours: u16,
    /// 1..=`expires_in_hours` when present.
    pub review_in_hours: Option<u16>,
}

/// A replayed lifecycle result: a claim mutation for `retract`/`supersede`,
/// a conflict mutation for the conflict actions.
#[derive(Debug, Clone, PartialEq)]
pub enum LifecycleMutation {
    Claim(ClaimMutation),
    Conflict(ConflictMutation),
}

/// A conflict lifecycle target and the view the caller last read.
///
/// `expected_member_count` is required for `resolve`: an open conflict gains
/// members without a revision change, so the count guards the view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictTarget {
    pub conflict_id: i64,
    pub expected_revision: i64,
    pub expected_member_count: Option<i64>,
}

/// One row of the per-conflict lifecycle log (migration 0029).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictLifecycleEvent {
    /// Position in this conflict's log, from 1 without gaps.
    pub seq: i64,
    /// `acknowledged`, `waived`, `resolved`, or `dismissed`.
    pub kind: String,
    /// `agent`, or `detector` for a detector-verified close.
    pub actor_kind: String,
    pub actor: String,
    /// The mutation that wrote it, e.g. `conflict_acknowledge` or `retract`.
    pub operation: String,
    /// The conflict revision the event was decided against.
    pub episode_revision: i64,
    /// The conflict revision the event left: the same for an overlay event,
    /// one more for a close.
    pub result_revision: i64,
    pub reason_kind: Option<String>,
    pub rationale: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub review_by: Option<DateTime<Utc>>,
    /// The conflict's durable member count when the event was written.
    pub member_count: i64,
    pub created_at: DateTime<Utc>,
    /// The bounded event detail (for a close, its cause and restored claims).
    /// Present on a mutation's own event and in history; omitted from the
    /// overlay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    /// True when history omitted an oversized payload.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub payload_elided: bool,
}

/// What a conflict action (`acknowledge`, concession `resolve`, or an
/// adjudicator's `dismiss` or `waive`) did to one conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictMutation {
    /// The remember action: `acknowledge`, `resolve`, `dismiss`, or `waive`.
    pub operation: String,
    pub conflict_id: i64,
    /// The conflict's state after the mutation.
    pub conflict_state: String,
    /// The conflict's revision after the mutation.
    pub conflict_revision: i64,
    pub member_count: i64,
    /// False when the request committed but changed nothing (an agent's
    /// second acknowledgement of the same episode).
    pub applied: bool,
    /// `acknowledged`, `already_acknowledged`, `resolved`, `dismissed`, or
    /// `waived`.
    pub status: Option<String>,
    /// The lifecycle event this mutation appended, when it appended one.
    pub lifecycle_event: Option<ConflictLifecycleEvent>,
    /// The caller's own claims a concession retracted.
    #[serde(default)]
    pub claims_retracted: Vec<i64>,
    /// Disputed members a verified close or a dismissal returned to `active`.
    #[serde(default)]
    pub claims_restored: Vec<i64>,
    #[serde(default)]
    pub conflicts_resolved: Vec<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reevaluation: Option<ConflictReevaluation>,
    pub idempotent_replay: bool,
}

/// An agent's acknowledgement of the current conflict episode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acknowledgement {
    pub actor: String,
    pub at: DateTime<Utc>,
    pub reason: Option<String>,
}

/// The latest waiver of the current episode and whether it still applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaiverView {
    pub actor: String,
    pub reason_kind: Option<String>,
    pub rationale: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub review_by: Option<DateTime<Utc>>,
    /// The review time has passed while the waiver is still active.
    pub review_due: bool,
    /// The member count the waiver was granted against.
    pub member_count: i64,
    pub active: bool,
    /// `expired` or `membership_changed` when the waiver no longer applies.
    pub void_reason: Option<String>,
}

/// Who closed a closed conflict, from its logged close event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureView {
    pub actor_kind: String,
    pub actor: String,
    pub operation: String,
    pub reason_kind: Option<String>,
    pub at: DateTime<Utc>,
}

/// The lifecycle state an agent reads beside a conflict row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictLifecycleOverlay {
    /// `open`, `acknowledged`, `waived`, `resolved`, or `dismissed`.
    pub state: String,
    /// ADR 0003's read-side state: `open`, `waived`, or `clear`.
    pub read_side: String,
    /// The conflict revision whose events this overlay reads: the current
    /// revision of an open conflict, the closed episode's otherwise.
    pub episode_revision: i64,
    pub acknowledged_by: Vec<Acknowledgement>,
    pub acknowledgers_truncated: bool,
    pub waiver: Option<WaiverView>,
    pub closed_by: Option<ClosureView>,
    /// A closed conflict whose close was not logged (for example one closed
    /// before the lifecycle log existed).
    pub closed_unlogged: bool,
    /// The database time the overlay was evaluated at.
    pub evaluated_at: DateTime<Utc>,
}

/// Revisions the conflict passed through without a logged event, such as a
/// reopen by `record` or a close before the lifecycle log existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionGap {
    pub from_revision: i64,
    pub to_revision: i64,
}

/// A conflict's newest lifecycle events, in event order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictHistory {
    pub events: Vec<ConflictLifecycleEvent>,
    /// True when older events exist than the bounded history returns.
    pub truncated: bool,
}

/// The lifecycle events of several conflict episodes, read in one statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictLifecycleRows {
    /// The newest events (at most 32) of each requested episode, newest
    /// first, then the episode's latest waiver when it is older than those,
    /// keyed by conflict id.
    pub events: std::collections::HashMap<i64, Vec<ConflictLifecycleEvent>>,
    /// The conflicts whose episode has more events than the overlay reads.
    pub truncated: std::collections::BTreeSet<i64>,
    /// The database time of the read.
    pub evaluated_at: DateTime<Utc>,
}

/// The detector's verdict on a key's open v2 conflict after a lifecycle change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictReevaluation {
    pub conflict_id: i64,
    /// `closed`, `still_open`, or `divergent` (Rust and SQL disagreed, so the
    /// conflict was conservatively left open).
    pub outcome: String,
    /// The conflict revision after this mutation.
    pub conflict_revision: i64,
    pub remaining_pair_count: usize,
    /// At most 32 remaining incompatible `[lower, higher]` claim id pairs.
    pub remaining_pairs: Vec<[i64; 2]>,
    /// Current incompatible pairs left out because an adjudicator already
    /// dismissed them in this conflict. Omitted when zero, so responses and
    /// stored receipts from before adjudication keep their bytes.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub excluded_dismissed_pairs: usize,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if passes a reference
const fn is_zero(count: &usize) -> bool {
    *count == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictCoverage {
    pub detector: String,
    pub scope: String,
    pub complete: bool,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn input() -> ClaimInput {
        ClaimInput {
            kind: ClaimKind::Decision,
            text: "Use CockroachDB for fleet memory".into(),
            subject: Some("  Fleet   Store ".into()),
            predicate: Some(" Database Choice ".into()),
            value: Some(serde_json::json!({"z": 2, "a": 1})),
            polarity: 1,
            origin: "operator_asserted".into(),
            actor: Some("architect".into()),
            confidence: 1.0,
            valid_from: None,
            valid_to: None,
            support: Vec::new(),
        }
    }

    fn record_mutation() -> ClaimMutation {
        let at = DateTime::parse_from_rfc3339("2026-09-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        ClaimMutation {
            operation: "record".into(),
            claim: Claim {
                id: 41,
                project: "project".into(),
                kind: ClaimKind::Fact,
                claim_key: Some("fleet::database".into()),
                subject: Some("fleet".into()),
                predicate: Some("database".into()),
                value: Some(serde_json::json!("cockroachdb")),
                text: "The fleet database is CockroachDB.".into(),
                polarity: 1,
                state: ClaimState::Active,
                origin: "operator_asserted".into(),
                actor: Some("agent".into()),
                confidence: 1.0,
                valid_from: None,
                valid_to: None,
                superseded_by: None,
                revision: 1,
                conflict_eligible: true,
                created_at: at,
                updated_at: at,
                support: Vec::new(),
                conflict_ids: Vec::new(),
            },
            superseded: None,
            idempotent_replay: false,
            conflicts_opened: Vec::new(),
            conflicts_resolved: Vec::new(),
            claims_restored: Vec::new(),
            reevaluation: None,
        }
    }

    #[test]
    fn record_mutation_serialization_is_byte_stable() {
        let encoded = serde_json::to_value(record_mutation()).unwrap();
        let keys = encoded
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "claim",
                "conflicts_opened",
                "conflicts_resolved",
                "idempotent_replay",
                "operation",
            ]),
            "a record mutation must not gain lifecycle keys"
        );

        let mut retract = record_mutation();
        retract.operation = "retract".into();
        retract.claims_restored = vec![42];
        retract.reevaluation = Some(ConflictReevaluation {
            conflict_id: 9,
            outcome: "closed".into(),
            conflict_revision: 4,
            remaining_pair_count: 0,
            remaining_pairs: Vec::new(),
            excluded_dismissed_pairs: 0,
        });
        let encoded = serde_json::to_value(&retract).unwrap();
        assert_eq!(encoded["claims_restored"], serde_json::json!([42]));
        assert_eq!(encoded["reevaluation"]["outcome"], "closed");
        assert!(
            encoded["reevaluation"]
                .get("excluded_dismissed_pairs")
                .is_none(),
            "no exclusion keeps the pre-adjudication reevaluation bytes"
        );
        let mut excluding = retract.clone();
        if let Some(reevaluation) = excluding.reevaluation.as_mut() {
            reevaluation.excluded_dismissed_pairs = 2;
        }
        let encoded_excluding = serde_json::to_value(&excluding).unwrap();
        assert_eq!(
            encoded_excluding["reevaluation"]["excluded_dismissed_pairs"],
            2
        );
        assert_eq!(
            serde_json::from_value::<ClaimMutation>(encoded_excluding).unwrap(),
            excluding
        );
        assert!(encoded.get("superseded").is_none());
        assert_eq!(
            serde_json::from_value::<ClaimMutation>(encoded).unwrap(),
            retract
        );

        let mut supersede = retract;
        supersede.operation = "supersede".into();
        supersede.superseded = Some(SupersededClaim {
            id: 40,
            state: ClaimState::Superseded,
            revision: 3,
            superseded_by: 41,
        });
        let encoded = serde_json::to_value(&supersede).unwrap();
        assert_eq!(
            encoded["superseded"],
            serde_json::json!({
                "id": 40, "state": "superseded", "revision": 3, "superseded_by": 41,
            })
        );
        assert_eq!(
            serde_json::from_value::<ClaimMutation>(encoded).unwrap(),
            supersede
        );
    }

    #[test]
    fn old_receipts_decode_without_new_fields() {
        let mut stored = serde_json::to_value(record_mutation()).unwrap();
        let object = stored.as_object_mut().unwrap();
        object.remove("superseded");
        object.remove("claims_restored");
        object.remove("reevaluation");
        let decoded: ClaimMutation = serde_json::from_value(stored).unwrap();
        assert_eq!(decoded, record_mutation());
    }

    #[test]
    fn prepares_recall_compatible_claim_key() {
        let prepared = input().prepare().unwrap();
        assert_eq!(prepared.subject.as_deref(), Some("fleet-store"));
        assert_eq!(prepared.predicate.as_deref(), Some("database-choice"));
        assert_eq!(
            prepared.claim_key.as_deref(),
            Some("fleet-store::database-choice")
        );
        assert!(prepared.conflict_eligible);
        assert_eq!(prepared.value.unwrap().to_string(), r#"{"a":1,"z":2}"#);

        // Underscores, hyphens, and whitespace are one separator, so the two
        // spellings of the trial's transcript setting share one key.
        let mut underscored = input();
        underscored.subject = Some("include_transcript_default".into());
        underscored.predicate = Some("Enabled".into());
        let mut spaced = input();
        spaced.subject = Some("include-transcript default".into());
        spaced.predicate = Some("enabled".into());
        let underscored = underscored.prepare().unwrap();
        let spaced = spaced.prepare().unwrap();
        assert_eq!(
            underscored.claim_key.as_deref(),
            Some("include-transcript-default::enabled")
        );
        assert_eq!(underscored.claim_key, spaced.claim_key);
        assert_eq!(underscored.subject, spaced.subject);

        // Parts that are only separators leave the claim keyless and outside
        // the detector.
        let mut separators = input();
        separators.subject = Some("_-_ ".into());
        let separators = separators.prepare().unwrap();
        assert_eq!(separators.subject.as_deref(), Some(""));
        assert_eq!(separators.claim_key, None);
        assert!(!separators.conflict_eligible);
    }

    #[test]
    fn unstructured_notes_do_not_open_conflicts() {
        let mut value = input();
        value.kind = ClaimKind::Note;
        assert!(!value.prepare().unwrap().conflict_eligible);
    }

    #[test]
    fn rejects_invalid_validity_window() {
        let mut value = input();
        let now = Utc::now();
        value.valid_from = Some(now);
        value.valid_to = Some(now);
        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_text_that_cockroach_tsvector_cannot_index() {
        let mut value = input();
        value.text = "é".repeat(MAX_TSVECTOR_INPUT_LEXEME_BYTES / 2);
        assert!(value.validate().is_ok());

        value.text.push('é');
        let error = value.validate().unwrap_err();
        assert!(error.to_string().contains("16002 UTF-8 bytes"));
    }

    #[test]
    fn chunk_backed_support_requires_bounded_identity_and_sha256_shape() {
        let support = ClaimSupportInput {
            source_config_id: "rich-demo:docs:v1".into(),
            source: "markdown".into(),
            source_id: "docs/ARCHITECTURE.md".into(),
            chunk_id: Some("chunk-1".into()),
            content_sha256: Some("a".repeat(64)),
            excerpt: Some("source-backed claim".into()),
            relation: "supports".into(),
        };
        let with = |edit: &dyn Fn(&mut ClaimSupportInput)| {
            let mut edited = support.clone();
            edit(&mut edited);
            let mut value = input();
            value.support.push(edited.into());
            value
        };
        assert!(with(&|_| {}).validate().is_ok());
        assert!(
            with(&|support| support.chunk_id = Some(" ".into()))
                .validate()
                .is_err()
        );
        assert!(
            with(&|support| support.content_sha256 = Some("not-a-sha256".into()))
                .validate()
                .is_err()
        );
        assert!(
            with(&|support| support.content_sha256 = None)
                .validate()
                .is_err()
        );

        // External citations remain compatible when no local chunk identity
        // is asserted; their provider-specific digest is not reinterpreted.
        assert!(with(&|support| support.chunk_id = None).validate().is_ok());
    }

    #[test]
    fn a_corpus_support_entry_keeps_its_bytes_and_its_strictness() {
        let corpus = json!({
            "source_config_id": "rich-demo:docs:v1",
            "source": "markdown",
            "source_id": "docs/ARCHITECTURE.md",
            "chunk_id": null,
            "content_sha256": null,
            "excerpt": null,
            "relation": "supports"
        });
        let parsed: SupportInputV1 = serde_json::from_value(corpus.clone()).unwrap();
        assert!(matches!(parsed, SupportInputV1::Corpus(_)));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), corpus);
        // A corpus entry is refused exactly as a ClaimSupportInput is.
        let mut unknown = corpus;
        unknown["extra"] = json!(1);
        let refused = serde_json::from_value::<SupportInputV1>(unknown.clone()).unwrap_err();
        let legacy = serde_json::from_value::<ClaimSupportInput>(unknown).unwrap_err();
        assert_eq!(refused.to_string(), legacy.to_string());
        let missing = json!({ "source": "markdown" });
        assert_eq!(
            serde_json::from_value::<SupportInputV1>(missing.clone())
                .unwrap_err()
                .to_string(),
            serde_json::from_value::<ClaimSupportInput>(missing)
                .unwrap_err()
                .to_string()
        );
    }

    #[test]
    fn an_item_support_entry_names_exactly_one_reference() {
        let id = "ab".repeat(32);
        for (reference, expected) in [
            (
                json!({ "item_id": id }),
                ItemRefV1::ItemId(id.parse().unwrap()),
            ),
            (
                json!({ "version_id": id }),
                ItemRefV1::VersionId(id.parse().unwrap()),
            ),
            (
                json!({ "url": "https://acme.slack.com/archives/C1/p1" }),
                ItemRefV1::Url("https://acme.slack.com/archives/C1/p1".into()),
            ),
        ] {
            let parsed: SupportInputV1 =
                serde_json::from_value(json!({ "item": reference })).unwrap();
            let SupportInputV1::Item(item) = &parsed else {
                panic!("an item entry parses as one");
            };
            assert_eq!(item.item, expected);
            assert_eq!(item.relation, "supports");
            assert!(item.validate().is_ok());
        }
        for refused in [
            json!({ "item": { "item_id": id, "url": "https://a.example/x" } }),
            json!({ "item": { "item_key": id } }),
            json!({ "item": { "item_id": id }, "source": "markdown" }),
            json!({ "item": { "item_id": "AB".repeat(32) } }),
        ] {
            assert!(
                serde_json::from_value::<SupportInputV1>(refused.clone()).is_err(),
                "{refused}"
            );
        }
        for invalid in [
            ItemSupportInputV1 {
                item: ItemRefV1::Url("http://acme.example/x".into()),
                relation: "supports".into(),
            },
            ItemSupportInputV1 {
                item: ItemRefV1::Url("https://acme.example/a b".into()),
                relation: "supports".into(),
            },
            ItemSupportInputV1 {
                item: ItemRefV1::ItemId(id.parse().unwrap()),
                relation: " supports".into(),
            },
            ItemSupportInputV1 {
                item: ItemRefV1::ItemId(id.parse().unwrap()),
                relation: "r".repeat(65),
            },
        ] {
            let mut value = input();
            value.support.push(SupportInputV1::Item(invalid.clone()));
            assert!(value.validate().is_err(), "{invalid:?}");
        }
        let mut value = input();
        value.support.push(SupportInputV1::Item(ItemSupportInputV1 {
            item: ItemRefV1::ItemId(id.parse().unwrap()),
            relation: "supports".into(),
        }));
        assert!(value.validate().is_ok());
        assert!(value.cites_items());
        assert!(!input().cites_items());
    }
}
