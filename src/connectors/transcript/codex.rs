//! Frozen Codex rollout adapter, separate from Claude's parser identity.
//!
//! Codex documents `transcript_path` as an unstable interface:
//! <https://learn.chatgpt.com/docs/hooks#common-input-fields>
//! This version accepts native `session_meta` and `response_item/message` records,
//! preserves raw byte spans, and ignores duplicate `event_msg` renderings and
//! tool/reasoning material. Unknown response items carrying content fail closed.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::parser::{bounded_resume_offset, canonical_micros, normalize};
use super::{
    MAX_TURNS_PER_BATCH, ParsedTranscriptV1, ParsedTurnV1, TranscriptConnectorError,
    TranscriptConnectorResult, TranscriptRoleV1, transcript_parser_key_v4,
};
use crate::memory_contracts::chunk_identity::{ParserKeyV1, SourceSpanV1, source_span_digest};
use crate::memory_contracts::digest::Sha256Digest;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TranscriptFormat {
    #[default]
    ClaudeCode,
    Codex,
}

impl TranscriptFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
        }
    }
    #[must_use]
    pub fn parser_key(self) -> ParserKeyV1 {
        match self {
            Self::ClaudeCode => transcript_parser_key_v4(),
            Self::Codex => codex_parser_key_v1(),
        }
    }
}

#[must_use]
pub fn codex_parser_key_v1() -> ParserKeyV1 {
    let mut key = transcript_parser_key_v4();
    key.parser_version = 1;
    key.parser_artifact_digest =
        Sha256Digest::from_bytes(Sha256::digest(b"ostk-codex-rollout-parser").into());
    key.configuration_digest = Sha256Digest::from_bytes(Sha256::digest(b"codex-rollout:v1;session=session_meta.payload.id;turn=response_item.message;roles=user,assistant;blocks=input_text,output_text,text;uid=id-or-byte-offset-sha256;timestamp=outer;skip=events,tools,reasoning,metadata;unknown_content=refuse;normalize=claude-v4;spans=original").into());
    key
}

fn malformed(source: &str, line: u32, reason: &'static str) -> TranscriptConnectorError {
    TranscriptConnectorError::MalformedTranscript {
        source_id: source.into(),
        line_ordinal: line,
        reason,
    }
}

/// Parse native Codex rollout JSONL, never the different `codex exec --json`
/// stdout event stream. Prefix records recover session identity after restart.
#[allow(clippy::too_many_lines)] // Keep cursor, framing and session identity in one bounded pass.
pub fn parse_codex_transcript(
    source: &str,
    bytes: &[u8],
    resume_from: u64,
    first_ordinal: u32,
) -> TranscriptConnectorResult<ParsedTranscriptV1> {
    let resume = bounded_resume_offset(source, bytes, resume_from)?;
    let mut parsed = ParsedTranscriptV1 {
        turns: Vec::new(),
        skipped_records: 0,
        records_unknown_skipped: 0,
        unknown_kinds: Vec::new(),
        consumed_bytes: 0,
        consumed_lines: 0,
        source_digest: Sha256Digest::from_bytes([0; 32]),
    };
    let mut session: Option<String> = None;
    let mut offset = 0;
    let mut ordinal = first_ordinal;
    for terminated in bytes.split_inclusive(|b| *b == b'\n') {
        if terminated.last() != Some(&b'\n') {
            break;
        }
        let end = offset + terminated.len();
        let line = &terminated[..terminated.len() - 1];
        parsed.consumed_lines = parsed
            .consumed_lines
            .checked_add(1)
            .ok_or_else(|| malformed(source, u32::MAX, "line count overflow"))?;
        let line_no = parsed.consumed_lines;
        if !line.is_empty() {
            let record: Value = serde_json::from_slice(line)
                .map_err(|_| malformed(source, line_no, "invalid Codex JSON record"))?;
            let kind = record
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| malformed(source, line_no, "Codex record has no type"))?;
            let payload = &record["payload"];
            if session.is_none() && kind != "session_meta" {
                return Err(malformed(
                    source,
                    line_no,
                    "Codex rollout must begin with session metadata",
                ));
            }
            if kind == "session_meta" {
                let id = payload
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty() && id.len() <= 256)
                    .ok_or_else(|| {
                        malformed(source, line_no, "Codex session metadata has no id")
                    })?;
                if session.as_deref().is_some_and(|prior| prior != id) {
                    return Err(malformed(source, line_no, "Codex session identity changed"));
                }
                session = Some(id.into());
            }
            if offset >= resume {
                let turn = codex_turn(
                    source,
                    line_no,
                    offset,
                    line,
                    &record,
                    session.as_deref(),
                    ordinal,
                )?;
                if let Some(turn) = turn {
                    parsed.turns.push(turn);
                    if parsed.turns.len() > MAX_TURNS_PER_BATCH {
                        return Err(malformed(source, line_no, "batch exceeds the turn bound"));
                    }
                    ordinal = ordinal
                        .checked_add(1)
                        .ok_or_else(|| malformed(source, line_no, "turn ordinal overflow"))?;
                } else {
                    parsed.skipped_records = parsed.skipped_records.saturating_add(1);
                    if !matches!(
                        kind,
                        "session_meta"
                            | "response_item"
                            | "event_msg"
                            | "turn_context"
                            | "compacted"
                            | "world_state"
                            | "token_usage_record"
                            | "inter_agent_communication_metadata"
                    ) {
                        parsed.records_unknown_skipped =
                            parsed.records_unknown_skipped.saturating_add(1);
                        let kind: String = kind.chars().take(80).collect();
                        if parsed.unknown_kinds.len() < super::MAX_REPORTED_UNKNOWN_KINDS
                            && !parsed.unknown_kinds.contains(&kind)
                        {
                            parsed.unknown_kinds.push(kind);
                            parsed.unknown_kinds.sort();
                        }
                    }
                }
            } else if end > resume {
                return Err(malformed(
                    source,
                    line_no,
                    "durable cursor does not land on a line boundary",
                ));
            }
        }
        parsed.consumed_bytes = end as u64;
        offset = end;
    }
    parsed.source_digest = Sha256Digest::from_bytes(Sha256::digest(&bytes[..offset]).into());
    Ok(parsed)
}

#[allow(clippy::too_many_arguments)] // source coordinates and parser state stay explicit
fn codex_turn(
    source: &str,
    line_no: u32,
    offset: usize,
    line: &[u8],
    record: &Value,
    session: Option<&str>,
    ordinal: u32,
) -> TranscriptConnectorResult<Option<ParsedTurnV1>> {
    if record["type"] != "response_item" {
        return Ok(None);
    }
    let payload = &record["payload"];
    if payload["type"] != "message" {
        if payload.get("content").is_some() {
            return Err(malformed(
                source,
                line_no,
                "unknown Codex content-bearing response item",
            ));
        }
        return Ok(None);
    }
    let role = match payload["role"].as_str() {
        Some("user") => TranscriptRoleV1::User,
        Some("assistant") => TranscriptRoleV1::Assistant,
        Some("system" | "developer") => return Ok(None),
        _ => return Err(malformed(source, line_no, "unknown Codex message role")),
    };
    let blocks = payload["content"]
        .as_array()
        .ok_or_else(|| malformed(source, line_no, "Codex message has no content array"))?;
    let mut text = Vec::new();
    for block in blocks {
        match block["type"].as_str() {
            Some("input_text" | "output_text" | "text") => text.push(
                block["text"]
                    .as_str()
                    .ok_or_else(|| malformed(source, line_no, "Codex text block has no text"))?,
            ),
            Some("input_image" | "image" | "audio" | "input_audio" | "encrypted_content") => {}
            _ => return Err(malformed(source, line_no, "unknown Codex content block")),
        }
    }
    let text = normalize(&text.join("\n"));
    if text.is_empty() {
        return Ok(None);
    }
    let session_id = session
        .ok_or_else(|| malformed(source, line_no, "Codex message precedes session metadata"))?
        .to_owned();
    let occurred_at = record["timestamp"]
        .as_str()
        .and_then(canonical_micros)
        .ok_or_else(|| malformed(source, line_no, "Codex message has no canonical timestamp"))?;
    let turn_uid = match payload["id"].as_str() {
        Some(id) if !id.is_empty() && id.len() <= 256 => id.to_owned(),
        _ => format!("line-{offset}-{}", hex::encode(Sha256::digest(line))),
    };
    let span = SourceSpanV1 {
        schema_version: 1,
        byte_start: offset as u64,
        byte_end: (offset + line.len()) as u64,
        span_digest: source_span_digest(line),
        ordinal,
    };
    span.validate()?;
    Ok(Some(ParsedTurnV1 {
        session_id,
        turn_uid,
        role,
        ordinal,
        occurred_at,
        text,
        span,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        [serde_json::json!({"timestamp":"2026-09-27T18:00:00Z","type":"session_meta","payload":{"id":"session-1","cli_version":"0.118.0"}}),
         serde_json::json!({"timestamp":"2026-09-27T18:00:01Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"preserve this marker"}]}}),
         serde_json::json!({"timestamp":"2026-09-27T18:00:02Z","type":"event_msg","payload":{"type":"user_message","message":"preserve this marker"}}),
         serde_json::json!({"timestamp":"2026-09-27T18:00:03Z","type":"response_item","payload":{"type":"message","id":"reply-1","role":"assistant","content":[{"type":"output_text","text":"confirmed"}]}})]
         .into_iter().flat_map(|v| format!("{v}\n").into_bytes()).collect()
    }
    #[test]
    fn rollout_preserves_spans_and_resume_without_duplicate_event_messages() {
        let bytes = fixture();
        let full = parse_codex_transcript("rollout", &bytes, 0, 0).unwrap();
        assert_eq!(full.turns.len(), 2);
        assert_eq!(full.turns[0].session_id, "session-1");
        assert_eq!(full.turns[1].turn_uid, "reply-1");
        let at = full.turns[0].span.byte_end + 1;
        let resumed = parse_codex_transcript("rollout", &bytes, at, 1).unwrap();
        assert_eq!(resumed.turns, full.turns[1..]);
        assert_ne!(codex_parser_key_v1(), transcript_parser_key_v4());
        assert!(parse_codex_transcript("rollout", &bytes, at - 2, 1).is_err());
        let partial = parse_codex_transcript("rollout", &bytes[..bytes.len() - 1], 0, 0).unwrap();
        assert_eq!(partial.turns.len(), 1);
    }
    #[test]
    fn missing_metadata_and_unknown_content_fail_closed() {
        let bytes = fixture();
        let first = bytes.iter().position(|b| *b == b'\n').unwrap() + 1;
        assert!(parse_codex_transcript("rollout", &bytes[first..], 0, 0).is_err());
        let text = String::from_utf8(bytes)
            .unwrap()
            .replace("input_text", "future_text");
        assert!(parse_codex_transcript("rollout", text.as_bytes(), 0, 0).is_err());
    }
}
