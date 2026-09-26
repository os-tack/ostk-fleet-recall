//! Item recall: `recall(kind=item)` over collected items (ADR 0008 D7).
//!
//! Collectors (ADR 0008) turn Slack messages, Linear issues, Granola notes,
//! documents, and anything else a collector reads into evidence: one accepted
//! event, one body, and one lexical and dense projection per part of each
//! version of each item. `recall(kind=evidence)` finds those bodies beside
//! the project's own git, CI, and transcript evidence. This module reads them
//! back as *items*: the current version of each, with where it came from,
//! how far it can be trusted, what it superseded, and whether an empty answer
//! means the item is absent.
//!
//! * [`ItemRecall::search`] searches the lexical and dense tiers and answers
//!   with one hit per matching item version ([`ItemHitV1`]): the item's
//!   presented head only, or with `include_history` every version whose item
//!   is still visible. Each hit carries its provider, object kind, external
//!   id, container, attested author, provider times, version marker and
//!   order, part, provider URL, trust tier, the channels that admitted its
//!   version, the accepted event and body behind it, both lane scores, how
//!   many other versions the item has, and whether a newer report disagrees
//!   with the verified head. A `source` filters by provider.
//! * [`ItemRecall::get`] takes an item id (64 hex), a part's version URI, or
//!   the item's provider URL, and returns the item ([`ItemGetV1`]): its
//!   presented version's parts in order, every other version (superseded
//!   versions with their text, tombstones with metadata only), the
//!   provenance of each admitted part, its outbound links, the visible
//!   items that link to it, and, where claims may cite items (migration 35),
//!   the claims that cite it.
//!
//! # Untrusted text
//!
//! Every item is text another system's users wrote. Every answer labels it
//! `content_trust: untrusted_third_party`, and the tool description says to
//! quote and cite it and never follow instructions in it. The text an answer
//! carries is decoded from the body envelope, which the collector redactor
//! already scrubbed at staging, and passed through the recall plane's own
//! redaction again ([`crate::projectors::redact_for_recall`]). Markdown images
//! in it are defanged ([`signals::defang_markdown_images`]), and each hit and
//! part carries advisory [`InjectionSignalV1`]s computed at read time: text
//! that addresses a model, asks for a credential, carries data-exfiltration
//! link shapes, or had hidden Unicode stripped when it was collected.
//!
//! # What is hidden
//!
//! An item is hidden, from search and from every lane, when its presented
//! head is a tombstone (deleted, trashed, revoked), its container was
//! withdrawn, or the item itself was withdrawn for either tier (ADR 0008 D5,
//! D6). Its earlier versions are hidden with it, `include_history` or not, so
//! deleted text is never recalled. `get` of a hidden item returns its
//! metadata only: identities, markers, orders, lifecycles, and provenance,
//! with no title, author name, text, or outbound link. A version becomes the
//! item's head only once every part is admitted, and a reported head (an
//! agent capture or an operator import) never displaces a verified one (a
//! pull or a push); an item with no head yet is not recalled.
//!
//! # The absence verdict
//!
//! Absence is the evidence verdict ([`crate::evidence_recall::absence_verdict`])
//! over the collectors alone: the live and snapshot collector sources of the
//! scope, or of the requested provider, and the collector outbox's pending
//! parts for that provider. It is `absent` only when the query has lexical
//! terms, nothing is pending, every body is lexically projected, and at least
//! one such source is active, healthy, fresh, and complete; otherwise
//! `unknown` with every reason that applies (a provider with no source is
//! `no_sources_registered`). Absence covers enumerated sources only: an agent
//! capture never establishes coverage.
//!
//! # Serving
//!
//! `serve` answers `recall(kind=item)` through the [`ItemRecall`]
//! [`start_item_recall`] returns, when it returns one: wherever the schema
//! has reached migration 34 and the writer login may read every table in
//! [`ITEM_RECALL_TABLES`] ([`probe_item_recall`]). Nothing is advertised
//! unless it is served. Item recall reads private base tables only, so the
//! publication process never builds it.

mod cockroach;
mod serve;
pub mod signals;

use std::str::FromStr as _;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::Result;
use crate::evidence_recall::{
    AbsenceV1, ContentTrustV1, EVIDENCE_SNIPPET_CHARS, EvidenceDenseLaneV1, EvidenceMatchV1,
    EvidenceReadinessV1, EvidenceSourcesV1,
};
use crate::memory_contracts::collected_item::{
    CollectionModeV1, ItemLifecycleV1, MAX_PROVIDER_URL_BYTES, ProviderKindV1, TrustTierV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::store::cockroach::COLLECTED_ITEMS_SCHEMA_VERSION;

pub use cockroach::{
    CockroachItemRecall, ITEM_RECALL_TABLES, ItemRecallCapability, probe_item_recall,
};
pub use serve::{start_item_recall, start_item_recall_citing};
pub use signals::{InjectionSignalV1, defang_markdown_images, injection_signals};

/// First schema item recall can read: migration 34 completes the collector
/// tables (the item withdrawals the suppression predicate reads).
pub const ITEM_RECALL_SCHEMA_VERSION: i64 = COLLECTED_ITEMS_SCHEMA_VERSION;

/// Most hits one search returns.
pub const MAX_ITEM_SEARCH_LIMIT: usize = 100;

/// Characters of text a hit's snippet carries.
pub const ITEM_SNIPPET_CHARS: usize = EVIDENCE_SNIPPET_CHARS;

/// Bytes of text one `get` returns across every part of every version.
///
/// Parts past it carry their metadata only, and the answer says it was cut,
/// so a long history stays well inside the MCP edge's tool-result budget.
pub const MAX_ITEM_GET_TEXT_BYTES: usize = 384 * 1024;

/// Admitted part rows one `get` reads, newest provider order first; an item
/// with more reports its history as truncated.
pub const MAX_ITEM_GET_ROWS: usize = 4_096;

/// Items linking to one item that one `get` lists.
pub const MAX_ITEM_LINKS_IN: usize = 256;

/// Claim citations of one item that one `get` lists.
pub const MAX_ITEM_CITATIONS: usize = 256;

/// Longest version URI `get` accepts: migration 33's bound on
/// `canonical_resource_id`.
pub const MAX_VERSION_URI_BYTES: usize = 256;

/// What `recall(get, kind=item)` was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemReferenceV1 {
    /// A 64-hex item id: a hit's `item_id`.
    Item(Sha256Digest),
    /// A part's version URI: a hit's `uri`.
    VersionUri(String),
    /// The item's provider URL.
    ProviderUrl(String),
}

impl ItemReferenceV1 {
    /// Parse a `get` id: 64 lowercase hex characters, a `urn:` version URI,
    /// or an `https://` provider URL.
    ///
    /// # Errors
    ///
    /// A static message naming the three accepted forms.
    pub fn parse(value: &str) -> std::result::Result<Self, &'static str> {
        const FORMS: &str = "an item id must be a hit's item_id (64 lowercase hex characters), a \
                             version URI (urn:...), or the item's https provider URL";
        if let Ok(digest) = Sha256Digest::from_str(value) {
            return Ok(Self::Item(digest));
        }
        if value.starts_with("urn:") && value.len() <= MAX_VERSION_URI_BYTES {
            return Ok(Self::VersionUri(value.to_owned()));
        }
        if value.starts_with("https://") && value.len() <= MAX_PROVIDER_URL_BYTES {
            return Ok(Self::ProviderUrl(value.to_owned()));
        }
        Err(FORMS)
    }
}

/// One item search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSearchRequestV1 {
    /// The query text.
    pub query: String,
    /// Only items of this provider.
    pub provider: Option<ProviderKindV1>,
    /// Every visible version, not only each item's presented head.
    pub include_history: bool,
    /// Most hits, 1 to [`MAX_ITEM_SEARCH_LIMIT`].
    pub limit: usize,
}

/// The container an item lives in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemContainerRefV1 {
    pub kind: String,
    pub id: String,
    /// The container's current label: the one its collector recorded last,
    /// else the one the version carried.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Who the provider says wrote the item. `attested` is always true: the
/// collector reports it, this memory never authenticates it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemAuthorRefV1 {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    pub kind: String,
    pub attested: bool,
}

/// Which version of the item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemVersionRefV1 {
    /// The provider's version marker.
    pub marker: String,
    /// The provider's order for the version, in microseconds.
    pub order: u64,
    pub lifecycle: ItemLifecycleV1,
}

/// Which part of the version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemPartRefV1 {
    pub ordinal: u32,
    pub count: u32,
    /// Where in the source the part sits (a heading path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
}

/// One recalled item version.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ItemHitV1 {
    /// The item's identity digest; `get` takes it.
    pub item_id: Sha256Digest,
    /// The version's identity digest.
    pub version_id: Sha256Digest,
    /// The matching part's version URI; `get` takes it.
    pub uri: String,
    pub provider: String,
    pub object_kind: String,
    /// The provider-stable id.
    pub external_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The first [`ITEM_SNIPPET_CHARS`] characters of the matching part's
    /// text, redacted and with markdown images defanged.
    pub snippet: String,
    pub snippet_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<ItemContainerRefV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<ItemAuthorRefV1>,
    /// When the provider says the item was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    /// When the provider says this version was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    pub version: ItemVersionRefV1,
    pub part: ItemPartRefV1,
    /// A display link to the item at the provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_url: Option<String>,
    /// The tier the matching part was admitted through: `verified` (pull,
    /// push) or `reported` (capture, import).
    pub trust: TrustTierV1,
    /// Every channel that admitted this version.
    pub collection_modes: Vec<CollectionModeV1>,
    /// Whether this version is the item's presented head; false only for a
    /// hit `include_history` added.
    pub current: bool,
    /// The accepted evidence event that admitted the matching part.
    pub accepted_event_id: Sha256Digest,
    /// The matching part's body; `recall(get, kind=evidence)` takes it.
    pub body_id: Sha256Digest,
    pub matched_by: EvidenceMatchV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lexical_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dense_similarity: Option<f32>,
    /// Versions of the item other than the presented one.
    pub superseded_versions: u64,
    /// A reported version newer than the verified head differs from it.
    pub disagreement: bool,
    /// Always `untrusted_third_party`.
    pub content_trust: ContentTrustV1,
    /// Advisory signals about the matching part's text and title.
    pub injection_signals: Vec<InjectionSignalV1>,
}

/// How far collection and projection have caught up, as of one item search.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemReadinessV1 {
    /// Collected item parts, of the requested provider, staged and not yet
    /// admitted.
    pub items_awaiting_admission: u64,
    /// Signed webhook hints, of the requested provider, received and not yet
    /// settled (ADR 0008 D12); absent before migration 36, or when this login
    /// cannot read the queue.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints_awaiting_fetch: Option<u64>,
    /// The schema has the hint queue and this login cannot read it: an empty
    /// answer is unknown.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub hints_unreadable: bool,
    /// Accepted evidence events the body projector has not consumed yet.
    pub events_awaiting_body_projection: u64,
    /// Every body has been through the lexical projector.
    pub lexical_current: bool,
    /// Every lexically searchable body also has an embedding.
    pub dense_current: bool,
    pub dense_lane: EvidenceDenseLaneV1,
    /// Server time of the readiness read.
    pub as_of: DateTime<Utc>,
}

impl ItemReadinessV1 {
    /// The same facts as an evidence readiness, for the shared verdict and
    /// warnings: no transcript turn bears on an item.
    #[must_use]
    pub const fn as_evidence(&self) -> EvidenceReadinessV1 {
        EvidenceReadinessV1 {
            events_awaiting_body_projection: self.events_awaiting_body_projection,
            transcript_turns_awaiting_admission: 0,
            items_awaiting_admission: Some(self.items_awaiting_admission),
            hints_awaiting_fetch: self.hints_awaiting_fetch,
            hints_unreadable: self.hints_unreadable,
            collector_state_unreadable: false,
            lexical_current: self.lexical_current,
            dense_current: self.dense_current,
            dense_lane: self.dense_lane,
            as_of: self.as_of,
        }
    }
}

/// One item search's answer.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ItemSearchV1 {
    pub hits: Vec<ItemHitV1>,
    pub readiness: ItemReadinessV1,
    /// The live and snapshot collectors of the scope, or of the requested
    /// provider.
    pub sources: EvidenceSourcesV1,
    pub absence: AbsenceV1,
}

/// The item one `get` returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemSummaryV1 {
    pub item_id: Sha256Digest,
    pub provider: String,
    pub provider_scope_id: String,
    pub object_kind: String,
    pub external_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<ItemContainerRefV1>,
    /// The external id of the thread's root item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_root_external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_url: Option<String>,
    /// The presented head's tier.
    pub trust: TrustTierV1,
    /// The presented head's lifecycle.
    pub lifecycle: ItemLifecycleV1,
    /// A reported version newer than the verified head differs from it.
    pub disagreement: bool,
    /// Distinct versions the history holds.
    pub versions: u64,
}

/// Why an item is withheld from recall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemSuppressionV1 {
    /// Its presented head is a tombstone: deleted, trashed, or revoked.
    Deleted,
    /// Its container's audience narrowed and it was withdrawn.
    ContainerWithdrawn,
    /// Its own audience narrowed and it was withdrawn.
    ItemWithdrawn,
}

/// One part of one version, with its text when the answer may carry it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemPartTextV1 {
    pub ordinal: u32,
    pub count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    /// The part's version URI.
    pub uri: String,
    pub accepted_event_id: Sha256Digest,
    pub body_id: Sha256Digest,
    /// Redacted, with markdown images defanged. Absent for a tombstone, for
    /// a hidden item, and past [`MAX_ITEM_GET_TEXT_BYTES`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub injection_signals: Vec<InjectionSignalV1>,
}

/// Who admitted one part, and how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemProvenanceV1 {
    pub part_ordinal: u32,
    pub mode: CollectionModeV1,
    /// The collector instance that staged it.
    pub collector_instance: String,
    /// The agent that attested a capture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester: Option<String>,
    pub trust: TrustTierV1,
    pub admitted_at: DateTime<Utc>,
    pub accepted_event_id: Sha256Digest,
}

/// One version of the item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemVersionRecordV1 {
    pub version_id: Sha256Digest,
    pub marker: String,
    pub order: u64,
    pub lifecycle: ItemLifecycleV1,
    /// Whether this is the presented head's version.
    pub current: bool,
    /// Why this version's text is withheld when the item as a whole is not:
    /// the container it was admitted in has since been withdrawn
    /// (`container_withdrawn`), so its text, title, and author are not shown,
    /// as evidence recall withholds its bodies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<ItemSuppressionV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<ItemAuthorRefV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    /// The admitted parts, in order: one per ordinal, the presented tier's
    /// copy first.
    pub parts: Vec<ItemPartTextV1>,
    /// Every admission of every part of the version.
    pub provenance: Vec<ItemProvenanceV1>,
}

/// One outbound link of the presented version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemLinkOutV1 {
    pub rel: String,
    pub target: String,
}

/// A visible item whose presented version links to this one's provider URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemLinkInV1 {
    pub item_id: Sha256Digest,
    pub provider: String,
    pub object_kind: String,
    pub external_id: String,
    pub rel: String,
}

/// A claim that cites the item (ADR 0008 D11): `remember(assert)`'s
/// `support_items` or a `record` support entry `{item: ...}` named it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemCitationV1 {
    pub claim_id: i64,
    /// The claim action that cited the item: `assert` or `record`.
    pub via: String,
    pub relation: String,
    /// The version the claim cites.
    pub version_id: Sha256Digest,
    /// The claim's lifecycle state now (`active`, `disputed`, `superseded`,
    /// `retracted`, ...).
    pub claim_state: String,
    pub cited_at: DateTime<Utc>,
}

/// One item, as `recall(get, kind=item)` returns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemGetV1 {
    pub item: ItemSummaryV1,
    /// Always `untrusted_third_party`.
    pub content_trust: ContentTrustV1,
    /// Why the item is withheld; when set, the answer is metadata only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<ItemSuppressionV1>,
    /// The version a version URI or provider URL named.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_version_id: Option<Sha256Digest>,
    /// The presented head's version.
    pub current: ItemVersionRecordV1,
    /// Every other version, the greatest provider order first: superseded
    /// versions with their text, tombstones with metadata only.
    pub history: Vec<ItemVersionRecordV1>,
    /// The item has more admitted parts than [`MAX_ITEM_GET_ROWS`].
    pub history_truncated: bool,
    /// Some part's text was left out to stay within
    /// [`MAX_ITEM_GET_TEXT_BYTES`].
    pub text_truncated: bool,
    /// The presented version's outbound links; empty for a hidden item.
    pub links_out: Vec<ItemLinkOutV1>,
    /// Visible items linking to this item's provider URL.
    pub links_in: Vec<ItemLinkInV1>,
    /// The claims that cite the item, oldest citation first, where this
    /// deployment serves claim item links (ADR 0008 D11); absent elsewhere,
    /// so the answer keeps its bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cited_by: Option<Vec<ItemCitationV1>>,
    /// More claims cite the item than [`MAX_ITEM_CITATIONS`].
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub cited_by_truncated: bool,
}

/// Item recall over one scope.
#[async_trait]
pub trait ItemRecall: Send + Sync {
    /// Search item versions, with the dense lane when `query_vector` is given
    /// and the lane is served.
    async fn search(
        &self,
        request: &ItemSearchRequestV1,
        query_vector: Option<Vec<f32>>,
    ) -> Result<ItemSearchV1>;

    /// One item by reference; `None` when no presented item matches it in
    /// this scope.
    async fn get(&self, reference: &ItemReferenceV1) -> Result<Option<ItemGetV1>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_get_id_is_an_item_id_a_version_uri_or_a_provider_url() {
        let id = "ab".repeat(32);
        assert_eq!(
            ItemReferenceV1::parse(&id),
            Ok(ItemReferenceV1::Item(Sha256Digest::from_str(&id).unwrap()))
        );
        let uri = "urn:ostk:version:v1:collected.item_version:sha256:00";
        assert_eq!(
            ItemReferenceV1::parse(uri),
            Ok(ItemReferenceV1::VersionUri(uri.to_owned()))
        );
        let url = "https://acme.slack.com/archives/C07PLATENG1/p1790006860001100";
        assert_eq!(
            ItemReferenceV1::parse(url),
            Ok(ItemReferenceV1::ProviderUrl(url.to_owned()))
        );
        for refused in [
            "AB".repeat(32),
            "http://acme.example/x".to_owned(),
            format!("urn:{}", "x".repeat(MAX_VERSION_URI_BYTES)),
            "42".to_owned(),
            String::new(),
        ] {
            assert!(ItemReferenceV1::parse(&refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn item_readiness_feeds_the_evidence_verdict_without_transcripts() {
        let readiness = ItemReadinessV1 {
            items_awaiting_admission: 2,
            hints_awaiting_fetch: Some(3),
            hints_unreadable: false,
            events_awaiting_body_projection: 1,
            lexical_current: true,
            dense_current: false,
            dense_lane: EvidenceDenseLaneV1::Used,
            as_of: DateTime::from_timestamp(1_790_000_000, 0).unwrap(),
        };
        let evidence = readiness.as_evidence();
        assert_eq!(evidence.items_awaiting_admission, Some(2));
        assert_eq!(evidence.hints_awaiting_fetch, Some(3));
        assert_eq!(evidence.transcript_turns_awaiting_admission, 0);
        assert_eq!(evidence.events_awaiting_body_projection, 1);
        assert!(!evidence.collector_state_unreadable);
        assert!(!evidence.hints_unreadable);
        let unreadable = ItemReadinessV1 {
            hints_awaiting_fetch: None,
            hints_unreadable: true,
            ..readiness
        };
        assert!(unreadable.as_evidence().hints_unreadable);
    }
}
