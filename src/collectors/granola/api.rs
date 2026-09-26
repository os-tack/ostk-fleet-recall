//! The Granola public API the collector reads, over the provider HTTP seam
//! (ADR 0008 D8).
//!
//! Three reads, each a `GET` with the API key as a `Bearer` token:
//!
//! * `notes` ([`GranolaApiV1::notes_page`]): one page of the notes the key
//!   can read, updated after an instant when one is given, paged on `cursor`
//!   while `hasMore`;
//! * `notes/{id}` ([`GranolaApiV1::note`]): one note, with
//!   `include=transcript` when the collector reads transcripts;
//! * `notes/{id}/transcript` ([`GranolaApiV1::transcript_page`]): one page of
//!   a transcript too large to come with its note (the note answered `413`).
//!
//! [`GranolaCallErrorV1`] tells a rate limit (`429`), a refused key (`401`,
//! `403`, which fail the pass), a note the key can no longer read (`404`,
//! which never tombstones anything), a transcript too large to come inline
//! (`413`), and any other failure apart. A listing's notes are parsed one by
//! one, so one malformed entry is one dead letter rather than a lost page.
//! Every request first waits for the [`RequestPacerV1`]: at most
//! [`GRANOLA_REQUESTS_PER_SECOND`] start in any one second.
//!
//! A note's private notes (`private_notes_text`, `private_notes_markdown`)
//! and its attendees are deliberately not fields of [`GranolaNoteV1`]: they
//! are never read into anything.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::collectors::cockroach::framed_sha256;
use crate::collectors::http::{ProviderHttpErrorV1, ProviderHttpV1};
use crate::memory_contracts::digest::Sha256Digest;

/// Requests the collector starts in any one second, at most: Granola's
/// documented sustained rate.
pub const GRANOLA_REQUESTS_PER_SECOND: usize = 5;

/// The window [`GRANOLA_REQUESTS_PER_SECOND`] counts over.
const PACER_WINDOW: Duration = Duration::from_secs(1);

/// Why one Granola call gave no usable answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GranolaCallErrorV1 {
    /// Rate-limited: HTTP 429.
    #[error("Granola rate-limited the call")]
    RateLimited,
    /// The key is unusable: HTTP 401 or 403.
    #[error("Granola refused the API key (HTTP {0})")]
    Credential(u16),
    /// The key cannot read the note (any more): HTTP 404.
    #[error("Granola does not show the note to the key")]
    NotFound,
    /// The answer is too large to come in one response: HTTP 413, or larger
    /// than the seam reads.
    #[error("the answer is too large to come in one response")]
    TooLarge,
    /// The request failed below Granola's own answer.
    #[error("{0}")]
    Http(ProviderHttpErrorV1),
    /// The answer is not the documented shape.
    #[error("Granola's answer is malformed: {0}")]
    Malformed(&'static str),
}

impl From<ProviderHttpErrorV1> for GranolaCallErrorV1 {
    fn from(error: ProviderHttpErrorV1) -> Self {
        match error {
            ProviderHttpErrorV1::RateLimited { .. } => Self::RateLimited,
            ProviderHttpErrorV1::Status {
                status: status @ (401 | 403),
            } => Self::Credential(status),
            ProviderHttpErrorV1::Status { status: 404 } => Self::NotFound,
            ProviderHttpErrorV1::Status { status: 413 } | ProviderHttpErrorV1::TooLarge => {
                Self::TooLarge
            }
            other => Self::Http(other),
        }
    }
}

/// A note's owner.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct GranolaOwnerV1 {
    /// Their name.
    #[serde(default)]
    pub name: Option<String>,
    /// Their email address.
    #[serde(default)]
    pub email: Option<String>,
}

/// The calendar event a note was taken in.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct GranolaCalendarEventV1 {
    /// The event's title.
    #[serde(default)]
    pub event_title: Option<String>,
    /// The calendar's id of the event.
    #[serde(default)]
    pub calendar_event_id: Option<String>,
}

/// A folder a note is in.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct GranolaFolderV1 {
    /// The folder id (`fol_...`).
    pub id: String,
    /// Its name: a label.
    #[serde(default)]
    pub name: Option<String>,
}

/// Who spoke one transcript segment, as Granola attributes it.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
pub struct GranolaSpeakerV1 {
    /// `microphone` (the note's owner) or `speaker` (the others).
    #[serde(default)]
    pub source: Option<String>,
    /// `me` or `them`.
    #[serde(default)]
    pub attribution: Option<String>,
    /// A name, when Granola knows it.
    #[serde(default)]
    pub name: Option<String>,
    /// A diarization label (`Speaker B`), when Granola told speakers apart.
    #[serde(default)]
    pub diarization_label: Option<String>,
}

/// One transcript segment.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct GranolaSegmentV1 {
    /// Who spoke it.
    #[serde(default)]
    pub speaker: Option<GranolaSpeakerV1>,
    /// What was said.
    #[serde(default)]
    pub text: Option<String>,
    /// When it started (RFC 3339).
    #[serde(default)]
    pub start_time: Option<String>,
    /// When it ended (RFC 3339).
    #[serde(default)]
    pub end_time: Option<String>,
}

/// Lengths only: a segment is provider content.
impl std::fmt::Debug for GranolaSegmentV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GranolaSegmentV1")
            .field("text_bytes", &self.text.as_deref().map_or(0, str::len))
            .field("start_time", &self.start_time)
            .finish_non_exhaustive()
    }
}

/// One note, as `notes/{id}` answers it. Only what the collector maps is a
/// field: never the private notes or the attendees.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct GranolaNoteV1 {
    /// The note id (`not_...`).
    pub id: String,
    /// Its title.
    #[serde(default)]
    pub title: Option<String>,
    /// Its owner.
    #[serde(default)]
    pub owner: Option<GranolaOwnerV1>,
    /// When it was created (RFC 3339).
    pub created_at: String,
    /// When it last changed (RFC 3339): its version.
    pub updated_at: String,
    /// Its page in Granola.
    #[serde(default)]
    pub web_url: Option<String>,
    /// The calendar event it was taken in.
    #[serde(default)]
    pub calendar_event: Option<GranolaCalendarEventV1>,
    /// The folders it is in.
    #[serde(default)]
    pub folder_membership: Option<Vec<GranolaFolderV1>>,
    /// The AI summary as plain text.
    #[serde(default)]
    pub summary_text: Option<String>,
    /// The AI summary as markdown.
    #[serde(default)]
    pub summary_markdown: Option<String>,
    /// The transcript, when it was asked for and came inline.
    #[serde(default)]
    pub transcript: Option<Vec<GranolaSegmentV1>>,
}

/// Identity and lengths only: a note is provider content.
impl std::fmt::Debug for GranolaNoteV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GranolaNoteV1")
            .field("id", &self.id)
            .field("updated_at", &self.updated_at)
            .field(
                "summary_bytes",
                &self
                    .summary_markdown
                    .as_deref()
                    .or(self.summary_text.as_deref())
                    .map_or(0, str::len),
            )
            .field("segments", &self.transcript.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

impl GranolaNoteV1 {
    /// The folders the note is in.
    #[must_use]
    pub fn folders(&self) -> &[GranolaFolderV1] {
        self.folder_membership.as_deref().unwrap_or_default()
    }
}

/// One note of a listing: its id and version.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ListedNoteV1 {
    /// The note id.
    pub id: String,
    /// When it last changed (RFC 3339).
    pub updated_at: String,
}

/// One entry of a listing: a note, or the digest of what did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListEntryV1 {
    /// The note.
    Note(ListedNoteV1),
    /// An entry that is not the documented shape: the digest of its JSON.
    Malformed(Sha256Digest),
}

/// One page of a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotesPageV1 {
    /// Its entries, in Granola's order.
    pub notes: Vec<ListEntryV1>,
    /// Where the next page starts, when there is one.
    pub next_cursor: Option<String>,
    /// Granola said there is more but gave no cursor: the listing cannot be
    /// read to its end.
    pub unfinished: bool,
}

/// One page of a transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptPageV1 {
    /// Its segments, in order.
    pub segments: Vec<GranolaSegmentV1>,
    /// Where the next page starts, when there is one.
    pub next_cursor: Option<String>,
    /// Granola said there is more but gave no cursor.
    pub unfinished: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotesAnswerV1 {
    notes: Vec<serde_json::Value>,
    #[serde(default)]
    has_more: bool,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TranscriptAnswerV1 {
    #[serde(default)]
    transcript: Vec<GranolaSegmentV1>,
    #[serde(default)]
    has_more: bool,
    #[serde(default)]
    cursor: Option<String>,
}

/// The next cursor of a page, and whether the page promised more with none.
fn next(has_more: bool, cursor: Option<String>) -> (Option<String>, bool) {
    let cursor = cursor.filter(|cursor| !cursor.is_empty());
    (
        cursor.clone().filter(|_| has_more),
        has_more && cursor.is_none(),
    )
}

fn notes_page(answer: NotesAnswerV1) -> NotesPageV1 {
    let (next_cursor, unfinished) = next(answer.has_more, answer.cursor);
    let notes = answer
        .notes
        .into_iter()
        .map(|value| {
            let digest = framed_sha256(
                "ostk-granola-listed-note-v1",
                &[serde_json::to_string(&value).unwrap_or_default().as_bytes()],
            );
            serde_json::from_value::<ListedNoteV1>(value)
                .map_or(ListEntryV1::Malformed(digest), ListEntryV1::Note)
        })
        .collect();
    NotesPageV1 {
        notes,
        next_cursor,
        unfinished,
    }
}

/// At most `limit` request starts in any window: a client-side rate limit.
#[derive(Debug)]
pub struct RequestPacerV1 {
    limit: usize,
    window: Duration,
    starts: Mutex<VecDeque<Instant>>,
    waits: AtomicU64,
}

impl RequestPacerV1 {
    /// A pacer admitting `limit` (at least 1) starts per `window`.
    #[must_use]
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit: limit.max(1),
            window,
            starts: Mutex::new(VecDeque::new()),
            waits: AtomicU64::new(0),
        }
    }

    /// How long a request that would start at `now` must wait, given the
    /// recent `starts`; `None` records the start and lets it go.
    fn delay(
        starts: &mut VecDeque<Instant>,
        now: Instant,
        limit: usize,
        window: Duration,
    ) -> Option<Duration> {
        while starts
            .front()
            .is_some_and(|start| now.saturating_duration_since(*start) >= window)
        {
            starts.pop_front();
        }
        if starts.len() < limit {
            starts.push_back(now);
            return None;
        }
        starts
            .front()
            .map(|oldest| (*oldest + window).saturating_duration_since(now))
    }

    /// Wait until one more request may start, and record its start.
    pub async fn wait(&self) {
        loop {
            let delay = {
                let mut starts = self.starts.lock().unwrap_or_else(PoisonError::into_inner);
                Self::delay(&mut starts, Instant::now(), self.limit, self.window)
            };
            let Some(delay) = delay else {
                return;
            };
            self.waits.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(delay).await;
        }
    }

    /// How many times a request waited.
    #[must_use]
    pub fn waits(&self) -> u64 {
        self.waits.load(Ordering::Relaxed)
    }
}

/// The public API over one key.
#[derive(Debug, Clone)]
pub struct GranolaApiV1 {
    http: ProviderHttpV1,
    page_size: String,
    pacer: Arc<RequestPacerV1>,
}

impl GranolaApiV1 {
    /// The API over `http`, listing `page_size` notes per page, at
    /// [`GRANOLA_REQUESTS_PER_SECOND`].
    #[must_use]
    pub fn new(http: ProviderHttpV1, page_size: u32) -> Self {
        Self {
            http,
            page_size: page_size.to_string(),
            pacer: Arc::new(RequestPacerV1::new(
                GRANOLA_REQUESTS_PER_SECOND,
                PACER_WINDOW,
            )),
        }
    }

    /// How many requests waited for the pacer so far.
    #[must_use]
    pub fn paced_waits(&self) -> u64 {
        self.pacer.waits()
    }

    async fn call(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<Vec<u8>, GranolaCallErrorV1> {
        self.pacer.wait().await;
        Ok(self.http.get(path, query).await?.body)
    }

    /// One page of the notes the key can read, updated after
    /// `updated_after` (RFC 3339) when it is given.
    ///
    /// # Errors
    ///
    /// Every [`GranolaCallErrorV1`] but [`GranolaCallErrorV1::NotFound`]
    /// in practice.
    pub async fn notes_page(
        &self,
        updated_after: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<NotesPageV1, GranolaCallErrorV1> {
        let mut query = vec![("page_size", self.page_size.as_str())];
        if let Some(updated_after) = updated_after {
            query.push(("updated_after", updated_after));
        }
        if let Some(cursor) = cursor {
            query.push(("cursor", cursor));
        }
        let body = self.call("notes", &query).await?;
        let answer: NotesAnswerV1 = serde_json::from_slice(&body)
            .map_err(|_| GranolaCallErrorV1::Malformed("not a notes listing"))?;
        Ok(notes_page(answer))
    }

    /// One note, with its transcript inline when `include_transcript`.
    /// `id` must already be a checked note id.
    ///
    /// # Errors
    ///
    /// Every [`GranolaCallErrorV1`]; [`GranolaCallErrorV1::TooLarge`] when
    /// the transcript must be paged instead.
    pub async fn note(
        &self,
        id: &str,
        include_transcript: bool,
    ) -> Result<GranolaNoteV1, GranolaCallErrorV1> {
        let query: &[(&str, &str)] = if include_transcript {
            &[("include", "transcript")]
        } else {
            &[]
        };
        let body = self.call(&format!("notes/{id}"), query).await?;
        let note: GranolaNoteV1 = serde_json::from_slice(&body)
            .map_err(|_| GranolaCallErrorV1::Malformed("not a note"))?;
        if note.id != id {
            return Err(GranolaCallErrorV1::Malformed(
                "the answer describes another note",
            ));
        }
        Ok(note)
    }

    /// One page of a note's transcript. `id` must already be a checked note
    /// id.
    ///
    /// # Errors
    ///
    /// Every [`GranolaCallErrorV1`].
    pub async fn transcript_page(
        &self,
        id: &str,
        cursor: Option<&str>,
    ) -> Result<TranscriptPageV1, GranolaCallErrorV1> {
        let query: Vec<(&str, &str)> = cursor
            .map(|cursor| ("cursor", cursor))
            .into_iter()
            .collect();
        let body = self.call(&format!("notes/{id}/transcript"), &query).await?;
        let answer: TranscriptAnswerV1 = serde_json::from_slice(&body)
            .map_err(|_| GranolaCallErrorV1::Malformed("not a transcript page"))?;
        let (next_cursor, unfinished) = next(answer.has_more, answer.cursor);
        Ok(TranscriptPageV1 {
            segments: answer.transcript,
            next_cursor,
            unfinished,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = include_str!("fixtures/list_notes.json");
    const NOTE: &str = include_str!("fixtures/get_note.json");
    const TRANSCRIPT: &str = include_str!("fixtures/transcript_page.json");

    #[test]
    fn the_recorded_listing_parses_note_by_note() {
        let page = notes_page(serde_json::from_str(LIST).unwrap());
        assert_eq!(
            page.notes,
            [ListEntryV1::Note(ListedNoteV1 {
                id: "not_1d3tmYTlCICgjy".into(),
                updated_at: "2026-09-21T15:41:09.001Z".into(),
            })]
        );
        assert_eq!(page.next_cursor, None);
        assert!(!page.unfinished);

        let mixed = notes_page(
            serde_json::from_str(
                r#"{"notes":[{"id":"not_a","updated_at":"2026-09-21T15:41:09Z"},{"id":7}],
                    "hasMore":true,"cursor":"eyJwIjoyfQ=="}"#,
            )
            .unwrap(),
        );
        assert!(matches!(mixed.notes[0], ListEntryV1::Note(_)));
        assert!(matches!(mixed.notes[1], ListEntryV1::Malformed(_)));
        assert_eq!(mixed.next_cursor.as_deref(), Some("eyJwIjoyfQ=="));
        let promised = notes_page(serde_json::from_str(r#"{"notes":[],"hasMore":true}"#).unwrap());
        assert!(promised.unfinished && promised.next_cursor.is_none());
        let ended = notes_page(
            serde_json::from_str(r#"{"notes":[],"hasMore":false,"cursor":"x"}"#).unwrap(),
        );
        assert_eq!(ended.next_cursor, None, "hasMore=false ends the listing");
    }

    #[test]
    fn the_recorded_note_parses_and_its_private_notes_are_never_read() {
        let mut value: serde_json::Value = serde_json::from_str(NOTE).unwrap();
        value["private_notes_text"] = serde_json::json!("PRIVATE-MARKER never read");
        value["private_notes_markdown"] = serde_json::json!("**PRIVATE-MARKER**");
        let note: GranolaNoteV1 = serde_json::from_value(value).unwrap();
        assert_eq!(note.id, "not_1d3tmYTlCICgjy");
        assert_eq!(note.updated_at, "2026-09-21T15:41:09.001Z");
        assert_eq!(note.folders()[0].id, "fol_4y6LduVdwSKC27");
        assert_eq!(note.folders()[0].name.as_deref(), Some("Platform"));
        assert!(
            note.summary_markdown
                .as_deref()
                .unwrap()
                .contains("Retry budget")
        );
        let transcript = note.transcript.as_ref().unwrap();
        assert_eq!(transcript.len(), 3);
        assert_eq!(
            transcript[2]
                .speaker
                .as_ref()
                .unwrap()
                .diarization_label
                .as_deref(),
            Some("Speaker B")
        );
        assert!(!format!("{note:?}").contains("PRIVATE-MARKER"));
        assert!(!format!("{note:?}").contains("Retry budget"));
    }

    #[test]
    fn the_recorded_transcript_page_keeps_its_cursor() {
        let answer: TranscriptAnswerV1 = serde_json::from_str(TRANSCRIPT).unwrap();
        let (next_cursor, unfinished) = next(answer.has_more, answer.cursor);
        assert_eq!(answer.transcript.len(), 2);
        assert_eq!(next_cursor.as_deref(), Some("eyJvZmZzZXQiOjJ9"));
        assert!(!unfinished);
    }

    #[test]
    fn statuses_are_classified() {
        let status = |status| GranolaCallErrorV1::from(ProviderHttpErrorV1::Status { status });
        assert_eq!(status(401), GranolaCallErrorV1::Credential(401));
        assert_eq!(status(403), GranolaCallErrorV1::Credential(403));
        assert_eq!(status(404), GranolaCallErrorV1::NotFound);
        assert_eq!(status(413), GranolaCallErrorV1::TooLarge);
        assert_eq!(
            GranolaCallErrorV1::from(ProviderHttpErrorV1::TooLarge),
            GranolaCallErrorV1::TooLarge
        );
        assert_eq!(
            GranolaCallErrorV1::from(ProviderHttpErrorV1::RateLimited {
                retry_after_seconds: Some(1)
            }),
            GranolaCallErrorV1::RateLimited
        );
        assert!(matches!(status(502), GranolaCallErrorV1::Http(_)));
    }

    #[test]
    fn the_pacer_admits_five_starts_in_any_second() {
        let window = Duration::from_secs(1);
        let origin = Instant::now();
        let mut starts = VecDeque::new();
        for offset in 0..5 {
            let now = origin + Duration::from_millis(offset * 10);
            assert_eq!(RequestPacerV1::delay(&mut starts, now, 5, window), None);
        }
        let sixth = origin + Duration::from_millis(100);
        assert_eq!(
            RequestPacerV1::delay(&mut starts, sixth, 5, window),
            Some(Duration::from_millis(900)),
            "the sixth waits until the first leaves the window"
        );
        let later = origin + Duration::from_millis(1_000);
        assert_eq!(
            RequestPacerV1::delay(&mut starts, later, 5, window),
            None,
            "once the first start is a second old, one more may go"
        );
        assert_eq!(starts.len(), 5);
    }

    #[tokio::test]
    async fn the_pacer_waits_rather_than_bursting() {
        let pacer = RequestPacerV1::new(2, Duration::from_millis(50));
        let started = Instant::now();
        for _ in 0..3 {
            pacer.wait().await;
        }
        assert!(started.elapsed() >= Duration::from_millis(45));
        assert_eq!(pacer.waits(), 1);
    }
}
