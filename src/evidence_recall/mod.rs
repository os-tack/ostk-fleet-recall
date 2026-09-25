//! Evidence recall: the private-plane read side of the Stage-5 projections
//! (ADR 0006).
//!
//! The memory worker (`src/worker`) admits git history, agent transcripts, and
//! CI runs as accepted evidence and projects them into bodies and the lexical
//! and dense recall tiers. This module reads them back for an agent, and says
//! how far the answer can be trusted:
//!
//! * [`EvidenceHitV1`]: each recalled body, with the lanes that matched it, a
//!   bounded snippet of its recall text, its media type, and the accepted event
//!   that first produced it.
//! * [`EvidenceReadinessV1`]: how far ingestion and projection have caught up
//!   (events still waiting for the body projector, transcript turns still
//!   waiting in the outbox, whether the lexical and dense tiers cover every
//!   body).
//! * [`EvidenceSourcesV1`]: every active source the worker reports on, with
//!   its last outcome, whether its last completed check is stale, and its
//!   newest coverage cursor.
//! * [`AbsenceV1`]: whether an empty answer means the evidence is absent, or
//!   only that nothing was found.
//!
//! # The absence verdict
//!
//! Any hit makes the verdict `present`. With no hit, the verdict is `absent`
//! only when all of these hold (see [`absence_verdict`]):
//!
//! * the query has lexical terms, because absence is defined over the lexical
//!   tier;
//! * no accepted evidence event is waiting for the body projector, and no
//!   transcript turn is waiting in the outbox;
//! * every body has been through the lexical projector;
//! * at least one source is active, and every active source's last outcome is
//!   not `failed`, its last completed check exists and is not older than its
//!   `stale_after_seconds`, and its newest coverage cursor is `complete`;
//! * the source listing was not cut short.
//!
//! Anything else is `unknown`, with every [`AbsenceReasonV1`] that applies.
//! The dense tier never blocks `absent`: it is reported, not required.
//!
//! "Complete" is the newest coverage cursor of each source. For git that is
//! the latest observed ref target; for CI, the latest window of runs; for a
//! transcript, the latest drained slice of its file, not the whole file (older
//! slices keep their own cursors). Freshness comes from the worker's status
//! row, not from the cursor: a git ref that has not moved is not re-observed,
//! but each tick that checks it records the check.
//!
//! A verdict is only as sound as the order of its reads. The sources are read
//! first, then readiness, then the recall lanes: a check the source listing
//! saw committed its events before that read, readiness then sees them either
//! pending or projected, and the lanes then search a lexical tier at least as
//! new as the one readiness counted. Reading readiness after the lanes could
//! count a body the lanes never searched.
//!
//! # What the text is
//!
//! A snippet and a fetched body carry the lexical tier's recall text, never
//! the stored body bytes: that text is normalized and has every secret-shaped
//! range replaced before it is written, and the body keeps the provider's
//! exact bytes. The body plane holds every projectable `evidence.accepted`
//! event in the scope, so a spec check's git blob fact is recalled like the
//! worker's. An observer-run record names no source-object version, so it has
//! no body and is never recalled (ADR 0006 D8).
//!
//! # Serving
//!
//! `serve` answers `recall(kind=evidence)` through the [`EvidenceRecall`]
//! [`start_evidence_recall`] returns, when it returns one.
//! [`probe_evidence_recall`] mints the [`EvidenceRecallCapability`] a
//! [`CockroachEvidenceRecall`] needs, once, at startup. It checks the schema
//! has reached migration 30 and that the login may read every table this
//! module reads, and it disables the dense lane for the process when the
//! scope's dense tier already holds vectors of a model other than the one the
//! process embeds queries with. Whether or not it does, every dense query
//! compares the query vector only with vectors that model embedded, so a
//! worker that starts writing another model's vectors later never makes a
//! cross-model comparison. A deployment therefore runs one embedding model.
//! The worker's embed step only embeds bodies that have no vector, so a
//! model change leaves the old vectors in place: re-embedding them is not
//! shipped yet. Evidence recall reads private base tables only, so the
//! publication process never builds it.

mod cockroach;
mod serve;
mod verdict;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};

use crate::error::Result;
use crate::memory_contracts::coverage::CoverageCompletenessV1;
use crate::memory_contracts::digest::Sha256Digest;
use crate::projectors::{RowVisibilityClassV1, fold_lexical_characters};
use crate::store::cockroach::MEMORY_WORKER_SCHEMA_VERSION;
use crate::worker::{WorkerSourceKindV1, WorkerSourceOutcomeV1};

pub use cockroach::{
    CockroachEvidenceRecall, EVIDENCE_RECALL_TABLES, EvidenceRecallCapability,
    probe_evidence_recall,
};
pub use serve::start_evidence_recall;
pub use verdict::absence_verdict;

/// First schema evidence recall can read: migration 30 creates the worker
/// status table the absence verdict depends on.
pub const EVIDENCE_RECALL_SCHEMA_VERSION: i64 = MEMORY_WORKER_SCHEMA_VERSION;

/// Most hits one search returns.
pub const MAX_EVIDENCE_SEARCH_LIMIT: usize = 100;

/// Most active sources one answer lists. A scope with more is reported as
/// truncated, and its verdict is `unknown`.
pub const MAX_EVIDENCE_SOURCES: usize = 256;

/// Characters of recall text a hit's snippet carries.
pub const EVIDENCE_SNIPPET_CHARS: usize = 600;

/// Bytes of a source's last error an answer carries.
pub const MAX_EVIDENCE_SOURCE_ERROR_BYTES: usize = 256;

/// Longest query word, in bytes, handed to the text-search parser.
///
/// `CockroachDB` refuses a lexeme longer than 2046 bytes (SQLSTATE 54000), so
/// no indexed body can hold one. Lowercasing can lengthen a word, so the
/// bound leaves room. Dropping a word only widens the match, because the
/// query's words are all required.
pub const MAX_EVIDENCE_QUERY_WORD_BYTES: usize = 1024;

/// The query text evidence recall hands to `plainto_tsquery`.
///
/// The query is first folded exactly as the lexical projector folds the text
/// it indexes ([`fold_lexical_characters`]: NFC composition, whitespace
/// folding, control scalars dropped), so a decomposed (NFD) spelling of an
/// indexed word, or one a control scalar interrupts, still matches it.
///
/// `CockroachDB` 26.2's `plainto_tsquery` parses some punctuation as query
/// syntax, so `error: foo (bar)` or `a & b` fails with SQLSTATE 42601 instead of
/// searching for their words. Its `to_tsvector` splits indexed text on every
/// character that is not a letter or digit. This keeps exactly the runs of
/// letters and digits, joined by single spaces, which is what the indexed side
/// would have made of the same text, and drops a run longer than
/// [`MAX_EVIDENCE_QUERY_WORD_BYTES`]. What remains can still have no lexical
/// terms (every word a stopword); the database decides that.
#[must_use]
pub fn lexical_query_text(query: &str) -> String {
    fold_lexical_characters(query)
        .split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty() && word.len() <= MAX_EVIDENCE_QUERY_WORD_BYTES)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The dense lane's state for one read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDenseLaneV1 {
    /// Served; this read ran no query (a status read).
    Available,
    /// Served, and this search ran it.
    Used,
    /// Served, but this search carried no query vector.
    NoQueryVector,
    /// Not served by this process: the scope's dense tier holds vectors of
    /// another model, which a query vector from this model cannot be compared
    /// with.
    DisabledForeignModel,
}

/// How far ingestion and projection have caught up, as of one read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceReadinessV1 {
    /// Accepted evidence events the body projector has not consumed yet.
    pub events_awaiting_body_projection: u64,
    /// Transcript turns staged in the outbox and not yet admitted.
    pub transcript_turns_awaiting_admission: u64,
    /// Every body has been through the lexical projector.
    pub lexical_current: bool,
    /// Every lexically searchable body also has an embedding.
    pub dense_current: bool,
    pub dense_lane: EvidenceDenseLaneV1,
    /// Server time of the readiness read.
    pub as_of: DateTime<Utc>,
}

/// A source's newest coverage cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceCoverageV1 {
    pub completeness: CoverageCompletenessV1,
    /// The observed provider-sequence ranges, half-open `[start, end)`.
    pub observed: Vec<[u64; 2]>,
    /// The target range, half-open `[start, end)`.
    pub target: [u64; 2],
    /// When the cursor last advanced.
    pub as_of: DateTime<Utc>,
}

/// Which connector a listed source belongs to. The wire value is the status
/// row's stored `source_kind`, exactly as stored.
///
/// Decoded tolerantly: a kind this build does not know (one a later collector
/// writes, or one a newer binary's migration admits) decodes to
/// [`Self::Other`] rather than failing the read. Refusing it would fail every
/// evidence search in the scope over one label, and an unknown kind is not a
/// reason to trust its source any more or less: it still counts toward the
/// failed, stale, never-checked, and incomplete reasons of the absence
/// verdict exactly like a known one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceSourceKindV1 {
    Git,
    Transcript,
    Ci,
    /// A kind this build does not know, carrying the stored string.
    Other(String),
}

impl EvidenceSourceKindV1 {
    /// Decode a stored `source_kind`; an unknown value is [`Self::Other`].
    #[must_use]
    pub fn from_stored(stored: &str) -> Self {
        [
            WorkerSourceKindV1::Git,
            WorkerSourceKindV1::Transcript,
            WorkerSourceKindV1::Ci,
        ]
        .into_iter()
        .find(|kind| kind.as_str() == stored)
        .map_or_else(|| Self::Other(stored.to_owned()), Self::from)
    }

    /// The stored `source_kind` this kind was decoded from.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Git => WorkerSourceKindV1::Git.as_str(),
            Self::Transcript => WorkerSourceKindV1::Transcript.as_str(),
            Self::Ci => WorkerSourceKindV1::Ci.as_str(),
            Self::Other(stored) => stored,
        }
    }
}

impl From<WorkerSourceKindV1> for EvidenceSourceKindV1 {
    fn from(kind: WorkerSourceKindV1) -> Self {
        match kind {
            WorkerSourceKindV1::Git => Self::Git,
            WorkerSourceKindV1::Transcript => Self::Transcript,
            WorkerSourceKindV1::Ci => Self::Ci,
        }
    }
}

impl Serialize for EvidenceSourceKindV1 {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// One active source, as the worker last reported it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceSourceV1 {
    pub connector_instance: String,
    pub kind: EvidenceSourceKindV1,
    /// The status row's state; only `active` sources are listed.
    pub state: String,
    pub last_outcome: WorkerSourceOutcomeV1,
    /// The last tick that completed a check (`ok` or `unchanged`); `None` when
    /// no tick ever has.
    pub last_checked_at: Option<DateTime<Utc>>,
    /// The last error, cut to [`MAX_EVIDENCE_SOURCE_ERROR_BYTES`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// The last completed check is older than the source's
    /// `stale_after_seconds`. False when there was none.
    pub stale: bool,
    /// The newest coverage cursor; `None` when the source has minted none.
    pub coverage: Option<EvidenceCoverageV1>,
}

/// The active sources, in instance order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceSourcesV1 {
    pub active: Vec<EvidenceSourceV1>,
    /// More than [`MAX_EVIDENCE_SOURCES`] sources are active; only the first
    /// are listed.
    pub truncated: bool,
}

/// Which lanes matched a hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceMatchV1 {
    Lexical,
    Dense,
    LexicalAndDense,
}

/// One recalled body.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EvidenceHitV1 {
    /// The body's content address; `get` takes it.
    pub id: Sha256Digest,
    pub matched_by: EvidenceMatchV1,
    /// `ts_rank` of the lexical lane, when it matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lexical_score: Option<f32>,
    /// Cosine similarity of the dense lane, when it matched at or above the
    /// dense floor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dense_similarity: Option<f32>,
    pub media_type: String,
    /// The first [`EVIDENCE_SNIPPET_CHARS`] characters of the recall text.
    pub snippet: String,
    pub snippet_truncated: bool,
    /// The accepted evidence event that first produced this body.
    pub first_accepted_event_id: Sha256Digest,
}

/// One body's full recall text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceBodyV1 {
    pub id: Sha256Digest,
    pub media_type: String,
    /// The lexical tier's recall text (at most 256 KiB); empty for a body with
    /// no derivable text.
    pub text: String,
    pub text_bytes: u64,
    #[serde(serialize_with = "visibility_label")]
    pub visibility_class: RowVisibilityClassV1,
    pub first_accepted_event_id: Sha256Digest,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's serialize_with passes a reference
fn visibility_label<S: Serializer>(
    class: &RowVisibilityClassV1,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(class.as_str())
}

/// What an empty or non-empty answer means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbsenceVerdictV1 {
    /// Something matched.
    Present,
    /// Nothing matched, over a current lexical tier fed by fresh, complete,
    /// healthy sources.
    Absent,
    /// Nothing matched, but that does not show absence; the reasons say why.
    Unknown,
}

/// Why an empty answer is `unknown` rather than `absent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbsenceReasonV1 {
    /// Every query word is a stopword or punctuation, so the lexical lane,
    /// over which absence is defined, could not run.
    QueryHasNoLexicalTerms,
    /// Accepted evidence is waiting for the body projector.
    BodyProjectionLag,
    /// Transcript turns are waiting in the outbox.
    IngestOutboxPending,
    /// Some body has not been through the lexical projector.
    LexicalProjectionLag,
    /// No source is active in this scope.
    NoSourcesRegistered,
    /// A source's last attempt failed.
    SourceFailed,
    /// A source's last completed check is older than its staleness bound.
    SourceStale,
    /// A source has never completed a check.
    SourceNeverChecked,
    /// A source's newest coverage cursor is not complete, or it has none.
    IncompleteCoverage,
    /// Not every active source was listed.
    ListingTruncated,
}

/// The absence verdict of one search.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AbsenceV1 {
    pub verdict: AbsenceVerdictV1,
    /// Empty unless the verdict is `unknown`.
    pub reasons: Vec<AbsenceReasonV1>,
    /// The oldest last completed check among the active sources: what the
    /// answer can be no newer than. `None` when no source has completed one.
    pub as_of: Option<DateTime<Utc>>,
}

/// One search's answer.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EvidenceSearchV1 {
    pub hits: Vec<EvidenceHitV1>,
    pub readiness: EvidenceReadinessV1,
    pub sources: EvidenceSourcesV1,
    pub absence: AbsenceV1,
}

/// Readiness and sources, with no query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceStatusV1 {
    pub readiness: EvidenceReadinessV1,
    pub sources: EvidenceSourcesV1,
}

/// Evidence recall over one scope.
#[async_trait]
pub trait EvidenceRecall: Send + Sync {
    /// Recall bodies for `query`, with the dense lane when `query_vector` is
    /// given and the lane is served, at most `limit` (1 to
    /// [`MAX_EVIDENCE_SEARCH_LIMIT`]) of them.
    async fn search(
        &self,
        query: &str,
        query_vector: Option<Vec<f32>>,
        limit: usize,
    ) -> Result<EvidenceSearchV1>;

    /// One body's recall text by its content address; `None` when no body
    /// with that address has been lexically projected in this scope.
    async fn get(&self, id: Sha256Digest) -> Result<Option<EvidenceBodyV1>>;

    /// Readiness and sources.
    async fn status(&self) -> Result<EvidenceStatusV1>;
}

#[cfg(test)]
mod tests {
    use unicode_normalization::UnicodeNormalization as _;

    use super::*;

    #[test]
    fn query_text_keeps_letter_and_digit_runs() {
        assert_eq!(lexical_query_text("error: foo (bar)"), "error foo bar");
        assert_eq!(lexical_query_text("a & b | !c"), "a b c");
        assert_eq!(lexical_query_text("path/to/file.rs"), "path to file rs");
        assert_eq!(lexical_query_text("  café  x²  日本語 "), "café x² 日本語");
        assert_eq!(lexical_query_text("?!()"), "");
    }

    #[test]
    fn query_text_is_folded_like_the_text_the_lexical_tier_indexes() {
        // A decomposed spelling matches the composed word the index holds:
        // a combining mark is not alphanumeric, so splitting before
        // composing would cut "résumé" into "re" and "sume".
        assert_eq!(lexical_query_text("re\u{301}sume\u{301}"), "résumé");
        assert_eq!(
            lexical_query_text("cafe\u{301} re\u{301}sume\u{301}"),
            "café résumé"
        );
        // The index drops a control scalar and joins the halves around it.
        assert_eq!(lexical_query_text("zephy\u{7}rine"), "zephyrine");
        // Whatever the spelling, the query's words are the indexed text's.
        for text in [
            "Document the cafe\u{301} policy\r\n\tnow",
            "ｆｕｌｌｗｉｄｔｈ Å\u{30a} ok",
            "a\u{0}b c\u{85}d",
        ] {
            assert_eq!(
                lexical_query_text(text),
                lexical_query_text(&fold_lexical_characters(text)),
                "{text:?}"
            );
            assert_eq!(
                lexical_query_text(text),
                lexical_query_text(&text.nfc().collect::<String>()),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_stored_source_kind_decodes_tolerantly_and_serializes_as_stored() {
        for (stored, kind) in [
            ("git", EvidenceSourceKindV1::Git),
            ("transcript", EvidenceSourceKindV1::Transcript),
            ("ci", EvidenceSourceKindV1::Ci),
            (
                "collected.slack",
                EvidenceSourceKindV1::Other("collected.slack".to_owned()),
            ),
        ] {
            let decoded = EvidenceSourceKindV1::from_stored(stored);
            assert_eq!(decoded, kind);
            assert_eq!(decoded.as_str(), stored);
            assert_eq!(
                serde_json::to_value(&decoded).unwrap(),
                serde_json::json!(stored)
            );
        }
        // A known kind is only ever its own variant, never `Other`.
        assert_eq!(
            EvidenceSourceKindV1::from_stored(WorkerSourceKindV1::Ci.as_str()),
            EvidenceSourceKindV1::from(WorkerSourceKindV1::Ci)
        );
    }

    #[test]
    fn query_text_drops_a_word_no_index_can_hold() {
        let long = "a".repeat(MAX_EVIDENCE_QUERY_WORD_BYTES + 1);
        let kept = "b".repeat(MAX_EVIDENCE_QUERY_WORD_BYTES);
        assert_eq!(
            lexical_query_text(&format!("zephyrine {long} {kept}")),
            format!("zephyrine {kept}")
        );
    }
}
