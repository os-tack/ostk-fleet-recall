use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ledger::{canonical_json, normalize_key_part};
use crate::{FleetError, Result};

// `memory_claims` are projected into `memory_chunks`, whose generated
// `TSVECTOR` rejects lexemes above CockroachDB's 16,383-byte limit. Validate at
// the domain boundary so a schema-valid remember call cannot fail only after
// embedding and entering its serializable mutation.
const MAX_TSVECTOR_INPUT_LEXEME_BYTES: usize = 16_000;

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
    #[serde(default)]
    pub support: Vec<ClaimSupportInput>,
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
            .is_some_and(|value| value.to_string().len() > 100_000)
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

    pub(crate) fn prepare(&self) -> Result<PreparedClaim> {
        self.validate()?;
        let subject = self.subject.as_deref().map(normalize_key_part);
        let predicate = self.predicate.as_deref().map(normalize_key_part);
        let claim_key = match (&subject, &predicate) {
            (Some(subject), Some(predicate)) if !subject.is_empty() && !predicate.is_empty() => {
                Some(format!("{subject}::{predicate}"))
            }
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticClaimHit {
    pub claim: Claim,
    pub similarity: f64,
    pub passage_index: i32,
    pub matched_passage: String,
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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimMutation {
    pub operation: String,
    pub claim: Claim,
    pub idempotent_replay: bool,
    pub conflicts_opened: Vec<i64>,
    pub conflicts_resolved: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictCoverage {
    pub detector: String,
    pub scope: String,
    pub complete: bool,
}

#[cfg(test)]
mod tests {
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
        let mut value = input();
        value.support.push(ClaimSupportInput {
            source_config_id: "rich-demo:docs:v1".into(),
            source: "markdown".into(),
            source_id: "docs/ARCHITECTURE.md".into(),
            chunk_id: Some("chunk-1".into()),
            content_sha256: Some("a".repeat(64)),
            excerpt: Some("source-backed claim".into()),
            relation: "supports".into(),
        });
        assert!(value.validate().is_ok());

        value.support[0].chunk_id = Some(" ".into());
        assert!(value.validate().is_err());
        value.support[0].chunk_id = Some("chunk-1".into());
        value.support[0].content_sha256 = Some("not-a-sha256".into());
        assert!(value.validate().is_err());
        value.support[0].content_sha256 = None;
        assert!(value.validate().is_err());

        // External citations remain compatible when no local chunk identity
        // is asserted; their provider-specific digest is not reinterpreted.
        value.support[0].chunk_id = None;
        assert!(value.validate().is_ok());
    }
}
