//! Bespoke JSONL parser for local agent transcripts (W2-TRANS).
//!
//! A Claude session file is newline-delimited JSON: one object per line, in
//! append order. This parser turns those bytes into an ordered list of
//! [`ParsedTurnV1`] values, each carrying the exact half-open byte
//! [`SourceSpanV1`] of the line it came from.
//!
//! # Why the parser is an identity, not an implementation detail
//!
//! Which parser produced a turn — its artifact, its version, and the exact
//! configuration digest that selects its normalization — is part of that turn's
//! representation identity, so the parser publishes a frozen [`ParserKeyV1`]
//! ([`transcript_parser_key_v1`]) rather than being anonymous. The canonicalizer
//! mixes that key's digest into every turn's `immutable_revision`
//! ([`super::canonicalizer::TranscriptTurnRevisionPreimageV1`]), which flows into
//! the canonical-resource URI, the source-fact ID, and therefore the
//! representation key. Re-parsing the same bytes under a different parser key
//! yields a DIFFERENT representation, never a silent in-place reinterpretation.
//!
//! The declared normalization rules are the ones this parser actually applies:
//! [`NormalizationRuleV1::NewlineLf`] (CRLF and lone CR collapse to LF) and
//! [`NormalizationRuleV1::TrailingWhitespaceTrim`] (trailing spaces and tabs are
//! stripped from every line, and trailing blank lines from the whole turn). No
//! other transformation happens, so the declared set is exhaustive rather than
//! aspirational.
//!
//! # Fail-closed parsing
//!
//! An unparseable line, an unknown record `type`, a malformed timestamp, or a
//! record missing a field the identity needs is a
//! [`TranscriptConnectorError::MalformedTranscript`] that aborts the whole
//! batch. Nothing partial is staged: a batch that cannot be parsed in full
//! advances no cursor and writes no outbox row.

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::memory_contracts::chunk_identity::{
    NormalizationRuleV1, ParserKeyV1, SourceSpanV1, source_span_digest,
};
use crate::memory_contracts::common::CanonicalTimestamp;
use crate::memory_contracts::digest::Sha256Digest;

use super::error::{TranscriptConnectorError, TranscriptConnectorResult};

/// `schema_version` of every chunk-identity value this parser mints.
const CHUNK_IDENTITY_SCHEMA_VERSION: u32 = 1;

/// Version of the transcript parser. Bumping it is a new parser identity and
/// therefore a new representation for every turn it re-parses.
pub const TRANSCRIPT_PARSER_VERSION: u32 = 1;

/// Exact configuration label whose digest becomes the parser key's
/// `configuration_digest`. It names every choice that changes output bytes.
const TRANSCRIPT_PARSER_CONFIGURATION: &str = "ostk-transcript-jsonl:v1;records=user,assistant;skips=system,summary;\
     keys=sessionId|session_id,uuid,timestamp,message.content;\
     blocks=text-only;join=lf;normalize=newline_lf,trailing_whitespace_trim";

const TRANSCRIPT_PARSER_ARTIFACT: &str = "ostk-transcript-jsonl-parser";

/// Largest transcript file this parser will accept in one batch (8 MiB). A
/// larger file is refused rather than partially parsed.
pub const MAX_TRANSCRIPT_BYTES: usize = 8 * 1024 * 1024;

/// Largest number of turns one batch may carry.
pub const MAX_TURNS_PER_BATCH: usize = 4_096;

/// Plain SHA-256 of a fixed label. Deliberately not domain-separated: these are
/// opaque parser-configuration identities, not a content identity in any frozen
/// preimage (the same convention [`crate::body_store`] uses).
fn label_digest(label: &str) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(label.as_bytes()).into())
}

/// The frozen parser key of the transcript connector.
#[must_use]
pub fn transcript_parser_key_v1() -> ParserKeyV1 {
    ParserKeyV1 {
        schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
        parser_artifact_digest: label_digest(TRANSCRIPT_PARSER_ARTIFACT),
        parser_version: TRANSCRIPT_PARSER_VERSION,
        configuration_digest: label_digest(TRANSCRIPT_PARSER_CONFIGURATION),
        // Strictly sorted, as ParserKeyV1::validate requires: NewlineLf is
        // declared before TrailingWhitespaceTrim in NormalizationRuleV1.
        declared_normalization_rules: vec![
            NormalizationRuleV1::NewlineLf,
            NormalizationRuleV1::TrailingWhitespaceTrim,
        ],
    }
}

/// A second parser key, identical except for its version and configuration.
///
/// It exists so the "parser identity is part of representation identity"
/// property can be proven as ordinary software: canonicalizing the same turn
/// under this key must produce a different revision, source-fact ID, and
/// representation key. It is never used by the production collector.
#[must_use]
pub fn transcript_parser_key_v2() -> ParserKeyV1 {
    ParserKeyV1 {
        schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
        parser_artifact_digest: label_digest(TRANSCRIPT_PARSER_ARTIFACT),
        parser_version: TRANSCRIPT_PARSER_VERSION + 1,
        configuration_digest: label_digest(
            "ostk-transcript-jsonl:v2;records=user,assistant;skips=system,summary;\
             blocks=text-only;join=lf;normalize=newline_lf",
        ),
        declared_normalization_rules: vec![NormalizationRuleV1::NewlineLf],
    }
}

/// Closed set of transcript record kinds.
///
/// Closed on purpose: an unrecognized `type` must abort the batch rather than be
/// silently skipped, because a skipped record is an invisible coverage hole.
/// `System` and `Summary` records carry no turn and are counted, not dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TranscriptRecordKind {
    User,
    Assistant,
    System,
    Summary,
}

/// Which side of the conversation a turn came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptRoleV1 {
    /// A turn authored by the human operator.
    User,
    /// A turn authored by the agent.
    Assistant,
}

impl TranscriptRoleV1 {
    /// Stable wire label, used inside the canonical turn body.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }
}

/// One decoded transcript line. Unknown fields are tolerated on purpose: the
/// on-disk session format is owned by the agent runtime, not by this repository,
/// and that tolerance is named in the parser's configuration digest.
#[derive(Debug, Deserialize)]
struct TranscriptRecordV1 {
    #[serde(rename = "type")]
    kind: TranscriptRecordKind,
    /// Claude session files spell this `sessionId`; the `snake_case` alias is
    /// accepted so a hand-written fixture is not a different format. Both names
    /// are part of the parser's configuration digest.
    #[serde(default, rename = "sessionId", alias = "session_id")]
    session_id: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    message: Option<TranscriptMessageV1>,
}

#[derive(Debug, Deserialize)]
struct TranscriptMessageV1 {
    #[serde(default)]
    content: Option<TranscriptContentV1>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TranscriptContentV1 {
    Text(String),
    Blocks(Vec<TranscriptBlockV1>),
}

#[derive(Debug, Deserialize)]
struct TranscriptBlockV1 {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: Option<String>,
}

/// One parsed conversational turn plus the exact source bytes it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTurnV1 {
    /// Session the turn belongs to, as the transcript declares it.
    pub session_id: String,
    /// Provider-side unique identifier of this turn.
    pub turn_uid: String,
    /// Which side authored the turn.
    pub role: TranscriptRoleV1,
    /// Zero-based position of this turn among the turns of the batch's source.
    pub ordinal: u32,
    /// When the turn occurred, in exact canonical UTC.
    pub occurred_at: CanonicalTimestamp,
    /// Normalized turn text (pre-redaction).
    pub text: String,
    /// Half-open byte range of the source line, with its raw-byte digest.
    pub span: SourceSpanV1,
}

/// Everything one parse of one transcript source produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTranscriptV1 {
    /// Turns, in source order.
    pub turns: Vec<ParsedTurnV1>,
    /// Records that carried no turn (`system`, `summary`), counted so a
    /// coverage gap can never hide behind a silent skip.
    pub skipped_records: u32,
    /// Byte offset one past the last line this parse consumed.
    pub consumed_bytes: u64,
    /// Number of newline-delimited lines consumed.
    pub consumed_lines: u32,
    /// Digest of exactly the bytes this parse consumed.
    pub source_digest: Sha256Digest,
}

fn malformed(source_id: &str, line_ordinal: u32, reason: &'static str) -> TranscriptConnectorError {
    TranscriptConnectorError::MalformedTranscript {
        source_id: source_id.to_owned(),
        line_ordinal,
        reason,
    }
}

/// Collapse CRLF and lone CR to LF, strip trailing spaces/tabs from each line,
/// then drop trailing blank lines. Exactly the two declared normalization rules.
fn normalize(raw: &str) -> String {
    let lf = raw.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines: Vec<&str> = lf
        .split('\n')
        .map(|line| line.trim_end_matches([' ', '\t']))
        .collect();
    while lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

fn extract_text(content: Option<&TranscriptContentV1>) -> String {
    match content {
        None => String::new(),
        Some(TranscriptContentV1::Text(text)) => normalize(text),
        Some(TranscriptContentV1::Blocks(blocks)) => {
            let joined = blocks
                .iter()
                .filter(|block| block.kind == "text")
                .filter_map(|block| block.text.as_deref())
                .collect::<Vec<_>>()
                .join("\n");
            normalize(&joined)
        }
    }
}

/// Convert a provider RFC-3339 timestamp into the exact canonical wire form,
/// truncated to microseconds so it survives a `TIMESTAMPTZ` round trip (the
/// EVID-03 alignment the admission seam requires).
fn canonical_micros(raw: &str) -> Option<CanonicalTimestamp> {
    let parsed = chrono::DateTime::parse_from_rfc3339(raw)
        .ok()?
        .with_timezone(&chrono::Utc);
    let truncated = parsed.timestamp_micros();
    let aligned = chrono::DateTime::from_timestamp_micros(truncated)?;
    CanonicalTimestamp::from_datetime(&aligned).ok()
}

/// Where one record's line sits in its source, so a turn can carry the exact
/// half-open byte span it was parsed from.
struct LineContext<'line> {
    source_id: &'line str,
    line_ordinal: u32,
    byte_start: usize,
    byte_end: usize,
    line: &'line [u8],
    ordinal: u32,
}

/// Turn one decoded record into a [`ParsedTurnV1`], refusing closed on any
/// field the turn's identity needs and does not have.
fn build_turn(
    context: &LineContext<'_>,
    record: TranscriptRecordV1,
    role: TranscriptRoleV1,
) -> TranscriptConnectorResult<ParsedTurnV1> {
    let (source_id, line_ordinal) = (context.source_id, context.line_ordinal);
    let session_id = record
        .session_id
        .filter(|value| !value.is_empty())
        .ok_or_else(|| malformed(source_id, line_ordinal, "record has no session id"))?;
    let turn_uid = record
        .uuid
        .filter(|value| !value.is_empty())
        .ok_or_else(|| malformed(source_id, line_ordinal, "record has no turn uid"))?;
    let occurred_at = record
        .timestamp
        .as_deref()
        .and_then(canonical_micros)
        .ok_or_else(|| malformed(source_id, line_ordinal, "record has no canonical timestamp"))?;
    let text = extract_text(
        record
            .message
            .as_ref()
            .and_then(|message| message.content.as_ref()),
    );
    if text.is_empty() {
        return Err(malformed(
            source_id,
            line_ordinal,
            "record carries no extractable text",
        ));
    }
    let span = SourceSpanV1 {
        schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
        byte_start: u64::try_from(context.byte_start)
            .map_err(|_| malformed(source_id, line_ordinal, "span start is out of range"))?,
        byte_end: u64::try_from(context.byte_end)
            .map_err(|_| malformed(source_id, line_ordinal, "span end is out of range"))?,
        span_digest: source_span_digest(context.line),
        ordinal: context.ordinal,
    };
    span.validate()?;
    Ok(ParsedTurnV1 {
        session_id,
        turn_uid,
        role,
        ordinal: context.ordinal,
        occurred_at,
        text,
        span,
    })
}

/// Bound the source and place the durable cursor inside it, before a single
/// line is framed.
///
/// A source larger than the batch bound, or one that has SHRUNK below the
/// offset the cursor already covers, is refused whole: a partial parse of
/// either would renumber the turns that follow.
fn bounded_resume_offset(
    source_id: &str,
    bytes: &[u8],
    resume_from: u64,
) -> TranscriptConnectorResult<usize> {
    if bytes.len() > MAX_TRANSCRIPT_BYTES {
        return Err(malformed(
            source_id,
            0,
            "transcript exceeds the batch bound",
        ));
    }
    let resume = usize::try_from(resume_from)
        .map_err(|_| malformed(source_id, 0, "resume offset is out of range"))?;
    if resume > bytes.len() {
        return Err(malformed(
            source_id,
            0,
            "transcript is shorter than the durable cursor",
        ));
    }
    Ok(resume)
}

/// Parse one transcript source in full.
///
/// `resume_from` is the byte offset the durable cursor already covers; bytes
/// before it are re-read to keep line framing exact but produce no turns, and
/// `first_ordinal` continues the source's turn numbering. A source that shrank
/// below `resume_from`, or whose prefix no longer frames the same lines, is a
/// closed [`TranscriptConnectorError::MalformedTranscript`] rather than a
/// silently re-numbered stream.
pub fn parse_transcript(
    source_id: &str,
    bytes: &[u8],
    resume_from: u64,
    first_ordinal: u32,
) -> TranscriptConnectorResult<ParsedTranscriptV1> {
    let resume = bounded_resume_offset(source_id, bytes, resume_from)?;

    let mut turns = Vec::new();
    let mut skipped_records = 0_u32;
    let mut ordinal = first_ordinal;
    let mut line_ordinal = 0_u32;
    let mut offset = 0_usize;
    let mut consumed = 0_usize;

    while offset < bytes.len() {
        let end = bytes[offset..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |index| offset + index);
        let line = &bytes[offset..end];
        // A line with no terminating LF is a partial write: stop before it and
        // leave the cursor where the last complete line ended.
        let terminated = end < bytes.len();
        if !terminated {
            if !line.is_empty() {
                break;
            }
            offset = end;
            continue;
        }
        let next = end + 1;
        line_ordinal = line_ordinal
            .checked_add(1)
            .ok_or_else(|| malformed(source_id, u32::MAX, "line count overflow"))?;

        if line.is_empty() {
            consumed = next;
            offset = next;
            continue;
        }
        // Bytes the cursor already covers are framed but not re-emitted.
        if end <= resume {
            consumed = next;
            offset = next;
            continue;
        }
        if offset < resume {
            return Err(malformed(
                source_id,
                line_ordinal,
                "durable cursor does not land on a line boundary",
            ));
        }

        let record: TranscriptRecordV1 = serde_json::from_slice(line)
            .map_err(|_| malformed(source_id, line_ordinal, "line is not a transcript record"))?;
        let role = match record.kind {
            TranscriptRecordKind::User => TranscriptRoleV1::User,
            TranscriptRecordKind::Assistant => TranscriptRoleV1::Assistant,
            TranscriptRecordKind::System | TranscriptRecordKind::Summary => {
                skipped_records = skipped_records
                    .checked_add(1)
                    .ok_or_else(|| malformed(source_id, line_ordinal, "skip count overflow"))?;
                consumed = next;
                offset = next;
                continue;
            }
        };

        turns.push(build_turn(
            &LineContext {
                source_id,
                line_ordinal,
                byte_start: offset,
                byte_end: end,
                line,
                ordinal,
            },
            record,
            role,
        )?);
        if turns.len() > MAX_TURNS_PER_BATCH {
            return Err(malformed(
                source_id,
                line_ordinal,
                "batch exceeds the turn bound",
            ));
        }
        ordinal = ordinal
            .checked_add(1)
            .ok_or_else(|| malformed(source_id, line_ordinal, "turn ordinal overflow"))?;
        consumed = next;
        offset = next;
    }

    Ok(ParsedTranscriptV1 {
        turns,
        skipped_records,
        consumed_bytes: u64::try_from(consumed)
            .map_err(|_| malformed(source_id, line_ordinal, "consumed offset is out of range"))?,
        consumed_lines: line_ordinal,
        source_digest: Sha256Digest::from_bytes(Sha256::digest(&bytes[..consumed]).into()),
    })
}

#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;
