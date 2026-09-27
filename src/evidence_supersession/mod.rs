//! The at-rest supersession pass: closing the pre-profile-3 residual for git
//! facts (ADR 0006 D9, amendment of 2026-09-27).
//!
//! Facts are content-addressed, so a git fact admitted before redaction
//! profile 3 keeps its raw rendering at rest: the governed content object
//! (`memory_content_objects.encrypted_bytes`, under the content key), the
//! projected body (`memory_body_objects_v1.body_bytes`, plaintext), and the
//! rows derived from that body. The read plane redacts what it serves, and
//! every re-presentation of the fact on a full walk lands in quarantine as a
//! preimage disagreement, but the raw bytes stay where the writer login can
//! read them without the key.
//!
//! This pass rewrites each such fact once:
//!
//! 1. it opens the raw content with the key, redacts the fact under the
//!    active package's guarantee exactly as the git ingress does today, and,
//!    when redaction changed anything, admits the redacted rendering through
//!    the same `admit_evidence` seam every connector uses, with a
//!    `supersedes` lineage naming the raw representation key;
//! 2. it appends that successor through the ledger, and in the SAME
//!    serializable transaction stores the successor's governed content and
//!    removes the raw representation's body plane (occurrences, spans, the
//!    bodies no other occurrence still references and their lexical, dense,
//!    and visibility rows, the raw parse-run manifest and generation
//!    pointer) and, when no other accepted event shares the digest, the raw
//!    content object;
//! 3. it leaves the raw accepted event row untouched: its digests are the
//!    tombstone, and its `canonical_event` never held the text.
//!
//! What the pass does NOT do is decided here too, and reported rather than
//! hidden: a transcript turn's revision closes over its body digest and the
//! transcript outbox keeps a copy of its candidate, so a raw transcript turn
//! is counted (`transcript_turns_raw_at_rest`) and left for a later pass; a
//! content object shared with an accepted event that has no successor stays
//! (`content_shared_skipped`); a fact whose provider instance is not in the
//! sources file cannot be re-rendered under a binding and is counted
//! (`source_unbound`); `memory_source_commit_membership_v1` keeps the raw
//! event's linkage (it names revisions, not text); and the content object's
//! wrapped DEK is deleted with the row rather than nulled, because the column
//! is NOT NULL and this pass adds no migration for it.
//!
//! The pass is separately privileged: `fleet_supersession`
//! (`deploy/cockroach/supersession-role-grants.sql`) holds the DELETEs on the
//! body plane and the content store that `fleet_runtime` deliberately never
//! holds, and the binary `ostk-evidence-supersede` is the only caller. It is
//! idempotent: a second run finds the successor by the raw representation's
//! digest (`skipped_with_successor`) and repeats the erase, which then removes
//! nothing. `--dry-run` computes every decision and writes nothing.
//!
//! [`cockroach`] holds the database side; this module holds the report and
//! the pure decisions it is built from, which are tested without a database.

pub mod cockroach;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::connectors::git::GIT_FACT_MEDIA_TYPE;
use crate::redaction::RedactionOutcomeV1;
use crate::worker::WorkerSourcesV1;

pub use cockroach::run_supersession;

/// Media type of a transcript turn's governed content.
pub const TRANSCRIPT_MEDIA_TYPE: &str = "application.json";

/// The operation label every report carries.
pub const SUPERSESSION_OPERATION: &str = "apply";

/// Whether the run wrote anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupersessionStateV1 {
    /// Every decision was carried out.
    Applied,
    /// Every decision was computed; nothing was written.
    DryRun,
}

/// What one run of the pass did (or, dry, would do), as one JSON line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupersessionReportV1 {
    /// Always [`SUPERSESSION_OPERATION`].
    pub operation: String,
    pub state: SupersessionStateV1,
    /// The redaction profile every successor was rendered under
    /// (`crate::redaction::REDACTION_PROFILE_VERSION`).
    pub redaction_profile: u32,
    /// Accepted evidence events of the scope the worklist read.
    pub events_scanned: u64,
    /// Of those, git facts.
    pub git_facts_scanned: u64,
    /// Git facts whose redacted successor was appended (would be, dry) and
    /// whose raw representation was erased.
    pub superseded: u64,
    /// Git facts already superseded before this run; their erase was
    /// repeated and removed nothing new.
    pub skipped_with_successor: u64,
    /// Git facts the active profile leaves byte-identical: nothing to do.
    pub unchanged_under_profile: u64,
    /// Superseded git facts whose raw content object was left in place
    /// because another accepted event without a successor still references
    /// the same digest.
    pub content_shared_skipped: u64,
    /// Git facts whose provider instance no source in the sources file
    /// binds, so no successor could be rendered.
    pub source_unbound: u64,
    /// Successors the ledger refused into quarantine. The binary exits 1
    /// when this is non-zero.
    pub quarantined: u64,
    /// Transcript turns whose stored text the active profile would change:
    /// raw at rest and deferred to a later pass, never rewritten here.
    pub transcript_turns_raw_at_rest: u64,
    /// Body rows removed (`memory_body_objects_v1`).
    pub bodies_removed: u64,
    /// Rows removed per table, in table-name order.
    pub rows_removed: BTreeMap<String, u64>,
}

impl SupersessionReportV1 {
    /// A report for one run before any event was scanned.
    #[must_use]
    pub fn new(dry_run: bool) -> Self {
        Self {
            operation: SUPERSESSION_OPERATION.to_owned(),
            state: if dry_run {
                SupersessionStateV1::DryRun
            } else {
                SupersessionStateV1::Applied
            },
            redaction_profile: crate::redaction::REDACTION_PROFILE_VERSION,
            events_scanned: 0,
            git_facts_scanned: 0,
            superseded: 0,
            skipped_with_successor: 0,
            unchanged_under_profile: 0,
            content_shared_skipped: 0,
            source_unbound: 0,
            quarantined: 0,
            transcript_turns_raw_at_rest: 0,
            bodies_removed: 0,
            rows_removed: BTreeMap::new(),
        }
    }

    /// Fold one erase's per-table counts in.
    pub fn absorb(&mut self, removed: &BTreeMap<&'static str, u64>) {
        for (table, rows) in removed {
            if *rows == 0 {
                continue;
            }
            *self.rows_removed.entry((*table).to_owned()).or_default() += rows;
            if *table == cockroach::BODY_TABLE {
                self.bodies_removed += rows;
            }
        }
    }
}

/// One run's inputs.
#[derive(Debug, Clone, Copy)]
pub struct SupersessionRequestV1<'request> {
    /// The worker's sources file: every git source it names is bound to the
    /// active package, and a fact is re-rendered only under the binding whose
    /// provider instance it was admitted from.
    pub sources: &'request WorkerSourcesV1,
    /// Compute every decision, write nothing.
    pub dry_run: bool,
}

/// What kind of accepted evidence event the worklist is looking at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKindV1 {
    /// A git fact: the pass acts on it.
    GitFact,
    /// A transcript turn: counted when raw at rest, never rewritten.
    TranscriptTurn,
    /// Anything else (a CI run, an observer record): ignored.
    Other,
}

/// Classify one event by the media type its governed content declares.
#[must_use]
pub fn classify_media_type(media_type: &str) -> EventKindV1 {
    if media_type == GIT_FACT_MEDIA_TYPE {
        EventKindV1::GitFact
    } else if media_type == TRANSCRIPT_MEDIA_TYPE {
        EventKindV1::TranscriptTurn
    } else {
        EventKindV1::Other
    }
}

/// What to do with one git fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitFactDecisionV1 {
    /// A successor already exists: repeat the idempotent erase and count
    /// `skipped_with_successor`.
    SkipWithSuccessor,
    /// The profile leaves the fact byte-identical: count
    /// `unchanged_under_profile`.
    UnchangedUnderProfile,
    /// Append the redacted successor and erase the raw representation.
    Supersede,
}

/// Decide one git fact from whether a successor exists and whether the
/// active profile changes it. The successor probe is consulted first: it is
/// one index seek and does not need the content opened.
#[must_use]
pub const fn decide_git_fact(successor_exists: bool, redacted: bool) -> GitFactDecisionV1 {
    if successor_exists {
        GitFactDecisionV1::SkipWithSuccessor
    } else if redacted {
        GitFactDecisionV1::Supersede
    } else {
        GitFactDecisionV1::UnchangedUnderProfile
    }
}

/// Whether the active profile would change a stored transcript turn's text:
/// a withheld text, or a replacement anywhere in it. Equal text is not raw
/// at rest.
#[must_use]
pub fn transcript_text_is_raw_at_rest(stored_text: &str, outcome: &RedactionOutcomeV1) -> bool {
    outcome.staged_text() != Some(stored_text)
}

/// How many accepted events reference one content digest, and how many of
/// those have (or in this run gain) a `supersedes` successor.
///
/// The content object under a digest can be deleted only once EVERY event
/// referencing it has a successor: a raw event without one would otherwise
/// re-derive its raw body from a content object the projector can still
/// open, or, with the object gone, park the body-plane watermark on a
/// `MissingSourceContent` it cannot pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContentReferencesV1 {
    /// Accepted evidence events of the scope whose content has this digest.
    pub total: u64,
    /// Of those, the ones with a successor after this run.
    pub resolved: u64,
}

impl ContentReferencesV1 {
    /// Whether the digest is referenced by more than one accepted event.
    #[must_use]
    pub const fn shared(&self) -> bool {
        self.total > 1
    }

    /// Whether the content object may now be deleted.
    #[must_use]
    pub const fn releasable(&self) -> bool {
        self.total > 0 && self.resolved == self.total
    }

    /// Whether this event's erase may delete the content object inline: the
    /// digest is referenced by this event alone.
    #[must_use]
    pub const fn sole_reference(&self) -> bool {
        self.total == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redaction::{REDACTION_PLACEHOLDER, RedactionDispositionV1};

    #[test]
    fn media_types_route_git_facts_and_transcript_turns_and_ignore_the_rest() {
        assert_eq!(
            classify_media_type("application.ostk-git-fact-v1"),
            EventKindV1::GitFact
        );
        assert_eq!(
            classify_media_type("application.json"),
            EventKindV1::TranscriptTurn
        );
        assert_eq!(
            classify_media_type("application.ostk-observer-run-record-v1"),
            EventKindV1::Other
        );
        assert_eq!(classify_media_type(""), EventKindV1::Other);
    }

    #[test]
    fn a_successor_wins_over_redaction_and_an_unchanged_fact_is_left_alone() {
        assert_eq!(
            decide_git_fact(true, true),
            GitFactDecisionV1::SkipWithSuccessor
        );
        assert_eq!(
            decide_git_fact(true, false),
            GitFactDecisionV1::SkipWithSuccessor
        );
        assert_eq!(decide_git_fact(false, true), GitFactDecisionV1::Supersede);
        assert_eq!(
            decide_git_fact(false, false),
            GitFactDecisionV1::UnchangedUnderProfile
        );
    }

    #[test]
    fn a_transcript_turn_is_raw_at_rest_when_the_profile_would_change_it() {
        let unchanged = RedactionOutcomeV1 {
            disposition: RedactionDispositionV1::Stage {
                text: "plain".into(),
            },
            classes: Vec::new(),
            redacted_ranges: 0,
        };
        assert!(!transcript_text_is_raw_at_rest("plain", &unchanged));
        let replaced = RedactionOutcomeV1 {
            disposition: RedactionDispositionV1::Stage {
                text: format!("token {REDACTION_PLACEHOLDER}"),
            },
            classes: Vec::new(),
            redacted_ranges: 1,
        };
        assert!(transcript_text_is_raw_at_rest("token abc", &replaced));
        let withheld = crate::redaction::redact(
            "-----BEGIN RSA PRIVATE KEY-----\nEXAMPLE-NOT-A-KEY\n-----END RSA PRIVATE KEY-----",
        );
        assert!(withheld.staged_text().is_none());
        assert!(transcript_text_is_raw_at_rest("anything", &withheld));
    }

    #[test]
    fn a_shared_content_object_is_released_only_once_every_reference_has_a_successor() {
        let sole = ContentReferencesV1 {
            total: 1,
            resolved: 0,
        };
        assert!(sole.sole_reference());
        assert!(!sole.shared());
        assert!(!sole.releasable());

        let half = ContentReferencesV1 {
            total: 2,
            resolved: 1,
        };
        assert!(half.shared());
        assert!(!half.sole_reference());
        assert!(!half.releasable());

        let all = ContentReferencesV1 {
            total: 2,
            resolved: 2,
        };
        assert!(all.releasable());
        assert!(!ContentReferencesV1::default().releasable());
    }

    #[test]
    fn the_report_folds_erase_counts_and_names_its_state() {
        let mut report = SupersessionReportV1::new(true);
        assert_eq!(report.state, SupersessionStateV1::DryRun);
        assert_eq!(report.operation, "apply");
        assert_eq!(report.redaction_profile, 3);
        report.absorb(&BTreeMap::from([
            (cockroach::BODY_TABLE, 2),
            ("memory_chunk_occurrences_v1", 3),
            ("memory_content_objects", 0),
        ]));
        report.absorb(&BTreeMap::from([(cockroach::BODY_TABLE, 1)]));
        assert_eq!(report.bodies_removed, 3);
        assert_eq!(report.rows_removed["memory_body_objects_v1"], 3);
        assert_eq!(report.rows_removed["memory_chunk_occurrences_v1"], 3);
        assert!(
            !report.rows_removed.contains_key("memory_content_objects"),
            "a zero count is not a row removed"
        );
        let wire = serde_json::to_value(SupersessionReportV1::new(false)).unwrap();
        assert_eq!(wire["state"], "applied");
        assert_eq!(wire["superseded"], 0);
        assert!(wire["rows_removed"].as_object().unwrap().is_empty());
    }
}
