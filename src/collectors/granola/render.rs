//! Granola notes as drafts (ADR 0008 D8).
//!
//! * **Identity.** A note gives up to two items, both with the note id
//!   (`not_...`) as external id: its AI summary, object kind `note_summary`,
//!   and, when the collector reads transcripts, its transcript, object kind
//!   `transcript`. The container is the listed folder the note is in
//!   (`granola.folder`, labelled with the folder's name), or the key's
//!   workspace (`granola.workspace`, the provider scope id) when every note
//!   the key reads is declared visible.
//! * **Versions.** A note has no version marker of its own that also tells a
//!   regenerated summary apart, so the default rule applies: the marker is
//!   `o<order>:sha256:<content digest>`, where the order is the note's
//!   `updated_at` in microseconds; `updated_at` plus the content digest. A
//!   summary regenerated under the same `updated_at` is ordered by the
//!   collector at the instant it was first observed, so it does not tie
//!   with the version it replaces.
//! * **Summary.** `summary_markdown` (markdown), else `summary_text` (plain);
//!   a note with neither has no summary item. The title is the note's. The
//!   author is the note's owner, by email (the only id Granola gives), with
//!   kind `ai_summary`: a model wrote the text. The calendar event (by its
//!   calendar id, labelled with its title) and every `http(s)` link in the
//!   summary are outbound links; the note's `web_url` is its provider url.
//! * **Transcript.** One `[hh:mm:ss] speaker: text` line per segment: the UTC
//!   time the segment started, then the speaker's name, else its diarization
//!   label, else `Me` or `Them` as Granola attributes it. The lines are
//!   packed into sections of at most 32 KiB, cut only between segments, each
//!   anchored at its first segment's time, so every part starts at a segment.
//!   The author is the note's owner, kind `human`.
//! * **Never mapped.** A note's private notes and its attendees are not even
//!   read ([`super::api::GranolaNoteV1`] has no field for them).
//! * **Tombstones.** A note missing from two consecutive complete listings is
//!   `revoked` ([`tombstone_draft`]): no text, at the order the memory holds.

use chrono::{DateTime, Utc};

use crate::collectors::draft::{
    CollectedItemDraftV1, DraftAuthorV1, DraftContainerV1, DraftLinkV1, DraftSectionV1,
};
use crate::collectors::linear::render::markdown_links;
use crate::memory_contracts::collected_item::{
    AuthorKindV1, ItemLifecycleV1, LinkRelV1, MAX_LINKS, MAX_PART_TEXT_BYTES, ObjectKindV1,
    ProviderKindV1, TextFormatV1, provider_timestamp, timestamp_micros,
};
use crate::memory_contracts::common::CanonicalTimestamp;

use super::api::{GranolaNoteV1, GranolaSegmentV1, GranolaSpeakerV1};

/// The provider kind.
pub const GRANOLA_PROVIDER: &str = "granola";

/// The object kind of a note's AI summary.
pub const SUMMARY_OBJECT_KIND: &str = "note_summary";

/// The object kind of a note's transcript.
pub const TRANSCRIPT_OBJECT_KIND: &str = "transcript";

/// The container kind of a listed folder.
pub const FOLDER_CONTAINER_KIND: &str = "granola.folder";

/// The container kind of a key's whole workspace.
pub const WORKSPACE_CONTAINER_KIND: &str = "granola.workspace";

/// The longest id body after its prefix.
const MAX_ID_BODY_BYTES: usize = 32;

/// How a segment with no start time is stamped.
const UNKNOWN_TIME: &str = "--:--:--";

/// Where a note's items are staged: the instance, and the container the
/// collector chose for the note.
#[derive(Clone, Copy)]
pub struct GranolaNoteContextV1<'a> {
    /// The provider kind (`granola`).
    pub provider: &'a ProviderKindV1,
    /// The provider scope id: the operator's pin for the key's workspace.
    pub provider_scope_id: &'a str,
    /// The note's container.
    pub container: Option<&'a DraftContainerV1>,
}

/// Whether `value` is `prefix` then 1 to 32 ASCII letters and digits: what
/// a Granola id is (`not_1d3tmYTlCICgjy`, `fol_4y6LduVdwSKC27`), checked before
/// it is ever part of a request path.
#[must_use]
pub fn is_granola_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|body| {
        !body.is_empty()
            && body.len() <= MAX_ID_BODY_BYTES
            && body.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })
}

/// Whether `value` is a note id.
#[must_use]
pub fn is_note_id(value: &str) -> bool {
    is_granola_id(value, "not_")
}

/// Whether `value` is a folder id.
#[must_use]
pub fn is_folder_id(value: &str) -> bool {
    is_granola_id(value, "fol_")
}

fn token<T>(parsed: crate::memory_contracts::ContractResult<T>) -> T {
    parsed.unwrap_or_else(|_| unreachable!("the Granola kinds are valid tokens"))
}

/// A Granola clock, and its order in microseconds.
///
/// # Errors
///
/// A static diagnostic when it is not an RFC 3339 timestamp with an order.
pub fn clock(value: &str) -> Result<(CanonicalTimestamp, u64), &'static str> {
    let timestamp =
        provider_timestamp(value).map_err(|_| "a Granola clock is not an RFC 3339 timestamp")?;
    let micros = timestamp_micros(&timestamp).map_err(|_| "a Granola clock has no order")?;
    Ok((timestamp, micros))
}

/// Every run of whitespace as one space, trimmed: a segment or a speaker as
/// one line.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn time_of_day(value: &str) -> Option<String> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|instant| instant.with_timezone(&Utc).format("%H:%M:%S").to_string())
}

/// Who spoke a segment: the speaker's name, else its diarization label, else
/// `Me` or `Them` as Granola attributes it (or by its audio source), else
/// `Unknown`.
#[must_use]
pub fn speaker_label(speaker: Option<&GranolaSpeakerV1>) -> String {
    let Some(speaker) = speaker else {
        return "Unknown".to_owned();
    };
    for named in [&speaker.name, &speaker.diarization_label] {
        let line = named.as_deref().map(one_line).unwrap_or_default();
        if !line.is_empty() {
            return line;
        }
    }
    let attributed = speaker.attribution.as_deref().map(str::to_ascii_lowercase);
    let source = speaker.source.as_deref().map(str::to_ascii_lowercase);
    match (attributed.as_deref(), source.as_deref()) {
        (Some("me"), _) | (None, Some("microphone")) => "Me",
        (Some("them"), _) | (None, Some("speaker")) => "Them",
        _ => "Unknown",
    }
    .to_owned()
}

/// One segment as a transcript line, or `None` when it says nothing.
#[must_use]
pub fn segment_line(segment: &GranolaSegmentV1) -> Option<String> {
    let text = one_line(segment.text.as_deref()?);
    if text.is_empty() {
        return None;
    }
    let time = segment
        .start_time
        .as_deref()
        .and_then(time_of_day)
        .unwrap_or_else(|| UNKNOWN_TIME.to_owned());
    Some(format!(
        "[{time}] {}: {text}",
        speaker_label(segment.speaker.as_ref())
    ))
}

/// A transcript as sections of at most [`MAX_PART_TEXT_BYTES`], cut only
/// between segments.
///
/// Every section but the last ends with the line break before the next
/// segment, so the sections concatenate to the whole transcript. A single
/// segment longer than a part is its own section, and only it is split
/// inside. Each section is anchored at its first segment's time.
#[must_use]
pub fn transcript_sections(segments: &[GranolaSegmentV1]) -> Vec<DraftSectionV1> {
    let mut sections = Vec::new();
    let mut text = String::new();
    let mut anchor: Option<String> = None;
    for segment in segments {
        let Some(line) = segment_line(segment) else {
            continue;
        };
        if !text.is_empty() && text.len() + line.len() + 1 > MAX_PART_TEXT_BYTES {
            sections.push(DraftSectionV1 {
                anchor: anchor.take(),
                span: None,
                text: std::mem::take(&mut text),
            });
        }
        if text.is_empty() {
            anchor = segment.start_time.as_deref().and_then(time_of_day);
        }
        text.push_str(&line);
        text.push('\n');
    }
    if !text.is_empty() {
        text.pop();
        sections.push(DraftSectionV1 {
            anchor,
            span: None,
            text,
        });
    }
    sections
}

fn push_link(links: &mut Vec<DraftLinkV1>, rel: &str, target: &str, label: Option<&str>) {
    let target = target.trim();
    if target.is_empty()
        || links.len() >= MAX_LINKS
        || links.iter().any(|link| link.target == target)
    {
        return;
    }
    links.push(DraftLinkV1 {
        rel: token(LinkRelV1::new(rel)),
        target: target.to_owned(),
        label: label
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(str::to_owned),
    });
}

fn owner(note: &GranolaNoteV1, kind: AuthorKindV1) -> Option<DraftAuthorV1> {
    let owner = note.owner.as_ref()?;
    let email = owner
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| !email.is_empty())?;
    Some(DraftAuthorV1 {
        id: email.to_ascii_lowercase(),
        display: owner.name.clone(),
        kind,
    })
}

fn title(note: &GranolaNoteV1) -> Option<String> {
    note.title
        .as_deref()
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .map(str::to_owned)
}

/// The note's page, when it is an https URL: a display link only.
fn provider_url(note: &GranolaNoteV1) -> Option<String> {
    note.web_url
        .as_deref()
        .map(str::trim)
        .filter(|url| url.starts_with("https://"))
        .map(str::to_owned)
}

/// A note's two clocks and its order.
struct NoteClocksV1 {
    created_at: CanonicalTimestamp,
    updated_at: CanonicalTimestamp,
    order_micros: u64,
}

fn note_clocks(note: &GranolaNoteV1) -> Result<NoteClocksV1, &'static str> {
    if !is_note_id(&note.id) {
        return Err("a Granola note id is not a note id");
    }
    let (created_at, _) = clock(&note.created_at)?;
    let (updated_at, order_micros) = clock(&note.updated_at)?;
    Ok(NoteClocksV1 {
        created_at,
        updated_at,
        order_micros,
    })
}

fn base_draft(
    context: &GranolaNoteContextV1<'_>,
    note: &GranolaNoteV1,
    clocks: NoteClocksV1,
    object_kind: &str,
) -> CollectedItemDraftV1 {
    CollectedItemDraftV1 {
        provider: context.provider.clone(),
        provider_scope_id: context.provider_scope_id.to_owned(),
        object_kind: token(ObjectKindV1::new(object_kind)),
        external_id: note.id.clone(),
        marker: None,
        order_micros: clocks.order_micros,
        lifecycle: ItemLifecycleV1::Live,
        container: context.container.cloned(),
        thread: None,
        author: None,
        created_at: Some(clocks.created_at),
        updated_at: Some(clocks.updated_at),
        title: title(note),
        sections: Vec::new(),
        text_format: TextFormatV1::Plain,
        links: Vec::new(),
        provider_url: provider_url(note),
        visibility: None,
    }
}

/// A note's AI summary as a draft, or `None` when the note has no summary.
///
/// # Errors
///
/// A static diagnostic when the note's id or clocks are not what Granola
/// documents; the collector dead-letters it.
pub fn summary_draft(
    context: &GranolaNoteContextV1<'_>,
    note: &GranolaNoteV1,
) -> Result<Option<CollectedItemDraftV1>, &'static str> {
    let clocks = note_clocks(note)?;
    let present = |text: &Option<String>| {
        text.as_deref()
            .map(str::trim_end)
            .filter(|text| !text.trim().is_empty())
            .map(str::to_owned)
    };
    let (text, format) = if let Some(markdown) = present(&note.summary_markdown) {
        (markdown, TextFormatV1::Markdown)
    } else if let Some(plain) = present(&note.summary_text) {
        (plain, TextFormatV1::Plain)
    } else {
        return Ok(None);
    };
    let mut links = Vec::new();
    if let Some(event) = &note.calendar_event
        && let Some(id) = &event.calendar_event_id
    {
        push_link(
            &mut links,
            "calendar_event",
            id,
            event.event_title.as_deref(),
        );
    }
    for (url, label) in markdown_links(&text) {
        push_link(&mut links, "url", &url, label.as_deref());
    }
    let mut draft = base_draft(context, note, clocks, SUMMARY_OBJECT_KIND);
    draft.author = owner(note, AuthorKindV1::AiSummary);
    draft.sections = vec![DraftSectionV1::whole(text)];
    draft.text_format = format;
    draft.links = links;
    Ok(Some(draft))
}

/// A note's transcript as a draft, or `None` when no segment says anything.
///
/// # Errors
///
/// As [`summary_draft`].
pub fn transcript_draft(
    context: &GranolaNoteContextV1<'_>,
    note: &GranolaNoteV1,
    segments: &[GranolaSegmentV1],
) -> Result<Option<CollectedItemDraftV1>, &'static str> {
    let clocks = note_clocks(note)?;
    let sections = transcript_sections(segments);
    if sections.is_empty() {
        return Ok(None);
    }
    let mut draft = base_draft(context, note, clocks, TRANSCRIPT_OBJECT_KIND);
    draft.author = owner(note, AuthorKindV1::Human);
    draft.sections = sections;
    draft.text_format = TextFormatV1::TranscriptSegment;
    Ok(Some(draft))
}

/// A `revoked` tombstone of one of a note's items, at `order_micros`: no
/// text, title, links, or author.
#[must_use]
pub fn tombstone_draft(
    context: &GranolaNoteContextV1<'_>,
    object_kind: &str,
    external_id: &str,
    order_micros: u64,
) -> CollectedItemDraftV1 {
    CollectedItemDraftV1 {
        provider: context.provider.clone(),
        provider_scope_id: context.provider_scope_id.to_owned(),
        object_kind: token(ObjectKindV1::new(object_kind)),
        external_id: external_id.to_owned(),
        marker: None,
        order_micros,
        lifecycle: ItemLifecycleV1::Revoked,
        container: context.container.cloned(),
        thread: None,
        author: None,
        created_at: None,
        updated_at: None,
        title: None,
        sections: Vec::new(),
        text_format: if object_kind == TRANSCRIPT_OBJECT_KIND {
            TextFormatV1::TranscriptSegment
        } else {
            TextFormatV1::Markdown
        },
        links: Vec::new(),
        provider_url: None,
        visibility: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::draft::{SealContextV1, collection_record, seal};
    use crate::collectors::test_support::redactor;
    use crate::memory_contracts::collected_item::{
        AudienceBasisV1, CollectionModeV1, ContainerKindV1,
    };
    use crate::memory_contracts::common::ContractId;

    const NOTE: &str = include_str!("fixtures/get_note.json");
    const SCOPE: &str = "workspace.acme-robotics";

    fn note() -> GranolaNoteV1 {
        serde_json::from_str(NOTE).unwrap()
    }

    fn folder() -> DraftContainerV1 {
        DraftContainerV1 {
            kind: ContainerKindV1::new(FOLDER_CONTAINER_KIND).unwrap(),
            id: "fol_4y6LduVdwSKC27".into(),
            label: Some("Platform".into()),
        }
    }

    fn drafts(note: &GranolaNoteV1) -> (CollectedItemDraftV1, CollectedItemDraftV1) {
        let provider = ProviderKindV1::new(GRANOLA_PROVIDER).unwrap();
        let container = folder();
        let context = GranolaNoteContextV1 {
            provider: &provider,
            provider_scope_id: SCOPE,
            container: Some(&container),
        };
        (
            summary_draft(&context, note).unwrap().unwrap(),
            transcript_draft(&context, note, note.transcript.as_deref().unwrap())
                .unwrap()
                .unwrap(),
        )
    }

    fn segment(start: &str, text: &str) -> GranolaSegmentV1 {
        GranolaSegmentV1 {
            speaker: Some(GranolaSpeakerV1 {
                source: Some("speaker".into()),
                attribution: Some("them".into()),
                name: None,
                diarization_label: None,
            }),
            text: Some(text.to_owned()),
            start_time: Some(start.to_owned()),
            end_time: None,
        }
    }

    #[test]
    fn the_recorded_note_is_a_summary_and_a_transcript_of_one_note() {
        let (summary, transcript) = drafts(&note());
        for draft in [&summary, &transcript] {
            assert_eq!(draft.external_id, "not_1d3tmYTlCICgjy");
            assert_eq!(
                draft.marker, None,
                "the default marker: updated_at + digest"
            );
            assert_eq!(draft.order_micros, 1_790_005_269_001_000);
            assert_eq!(draft.title.as_deref(), Some("Ingest reliability sync"));
            assert!(draft.container.as_ref() == Some(&folder()));
            assert_eq!(
                draft.provider_url.as_deref(),
                Some("https://notes.granola.ai/d/f3e45e0f-24cc-480b-9a6c-8b1f5e3d7a2c")
            );
            let author = draft.author.as_ref().unwrap();
            assert_eq!(author.id, "carol@acme-robotics.example");
            assert_eq!(author.display.as_deref(), Some("Carol Diaz"));
        }
        assert_eq!(summary.object_kind.as_str(), SUMMARY_OBJECT_KIND);
        assert_eq!(summary.text_format, TextFormatV1::Markdown);
        assert_eq!(
            summary.author.as_ref().unwrap().kind,
            AuthorKindV1::AiSummary
        );
        assert!(
            summary.sections[0]
                .text
                .starts_with("### Decisions\n- Retry budget: **5**")
        );
        assert_eq!(
            summary
                .links
                .iter()
                .map(|link| (
                    link.rel.as_str(),
                    link.target.as_str(),
                    link.label.as_deref()
                ))
                .collect::<Vec<_>>(),
            [(
                "calendar_event",
                "2su99n6iiik37iiknmb5t4fkfh_20260921T150000Z",
                Some("Ingest reliability sync")
            )]
        );

        assert_eq!(transcript.object_kind.as_str(), TRANSCRIPT_OBJECT_KIND);
        assert_eq!(transcript.text_format, TextFormatV1::TranscriptSegment);
        assert_eq!(
            transcript.author.as_ref().unwrap().kind,
            AuthorKindV1::Human
        );
        assert_eq!(transcript.sections.len(), 1);
        assert_eq!(transcript.sections[0].anchor.as_deref(), Some("15:02:10"));
        assert_eq!(
            transcript.sections[0].text,
            "[15:02:10] Carol Diaz: Okay, retry budget. Alice, you wanted five?\n\
             [15:02:14] Them: Five with jitter, three was too aggressive on flaky runners.\n\
             [15:02:20] Speaker B: I'm worried about p99, but fine for now."
        );
    }

    #[test]
    fn a_note_without_a_summary_or_segments_has_no_such_item_and_a_bad_note_is_refused() {
        let provider = ProviderKindV1::new(GRANOLA_PROVIDER).unwrap();
        let context = GranolaNoteContextV1 {
            provider: &provider,
            provider_scope_id: SCOPE,
            container: None,
        };
        let mut plain = note();
        plain.summary_markdown = Some("  \n".into());
        let summary = summary_draft(&context, &plain).unwrap().unwrap();
        assert_eq!(summary.text_format, TextFormatV1::Plain);
        assert!(
            summary.sections[0]
                .text
                .starts_with("Agreed retry budget of 5")
        );
        plain.summary_text = None;
        assert_eq!(summary_draft(&context, &plain).unwrap(), None);
        let silent = [segment("2026-09-21T15:00:00Z", " \n ")];
        assert_eq!(transcript_draft(&context, &plain, &silent).unwrap(), None);

        let mut broken = note();
        broken.updated_at = "yesterday".into();
        assert!(summary_draft(&context, &broken).is_err());
        let mut foreign = note();
        foreign.id = "../notes/not_x".into();
        assert!(summary_draft(&context, &foreign).is_err());
        let mut plain_url = note();
        plain_url.web_url = Some("http://notes.granola.ai/d/x".into());
        assert_eq!(
            summary_draft(&context, &plain_url)
                .unwrap()
                .unwrap()
                .provider_url,
            None,
            "only an https page is a provider url"
        );
    }

    #[test]
    fn speakers_are_named_labelled_or_attributed() {
        let speaker = |value: serde_json::Value| -> GranolaSpeakerV1 {
            serde_json::from_value(value).unwrap()
        };
        for (value, label) in [
            (
                serde_json::json!({"source": "microphone", "attribution": "me", "name": "Carol\nDiaz"}),
                "Carol Diaz",
            ),
            (
                serde_json::json!({"source": "speaker", "diarization_label": "Speaker B"}),
                "Speaker B",
            ),
            (
                serde_json::json!({"source": "speaker", "attribution": "them"}),
                "Them",
            ),
            (serde_json::json!({"source": "microphone"}), "Me"),
            (serde_json::json!({"attribution": "ME", "name": "  "}), "Me"),
            (serde_json::json!({}), "Unknown"),
        ] {
            assert_eq!(
                speaker_label(Some(&speaker(value.clone()))),
                label,
                "{value}"
            );
        }
        assert_eq!(speaker_label(None), "Unknown");
        let mut untimed = segment("not a time", "a line\nthat wrapped");
        assert_eq!(
            segment_line(&untimed).as_deref(),
            Some("[--:--:--] Them: a line that wrapped")
        );
        untimed.text = None;
        assert_eq!(segment_line(&untimed), None);
    }

    #[test]
    fn a_long_transcript_is_split_into_parts_at_segment_boundaries() {
        let sentence = "the retry budget stays at five with full jitter and a capped backoff ";
        let segments: Vec<GranolaSegmentV1> = (0..700)
            .map(|index| {
                segment(
                    &format!("2026-09-21T15:{:02}:{:02}Z", (index / 60) % 60, index % 60),
                    &format!("{index}: {}", sentence.repeat(1 + index % 3)),
                )
            })
            .collect();
        let lines: Vec<String> = segments.iter().filter_map(segment_line).collect();
        let whole = lines.join("\n");
        assert!(whole.len() > 3 * MAX_PART_TEXT_BYTES);

        let sections = transcript_sections(&segments);
        assert!(sections.len() >= 4);
        assert_eq!(
            sections
                .iter()
                .map(|section| section.text.as_str())
                .collect::<String>(),
            whole,
            "the sections concatenate to the transcript"
        );
        for (index, section) in sections.iter().enumerate() {
            assert!(section.text.len() <= MAX_PART_TEXT_BYTES);
            assert!(
                section.text.starts_with('['),
                "a section starts at a segment"
            );
            let last = index + 1 == sections.len();
            assert_eq!(section.text.ends_with('\n'), !last);
            let first_time = &section.text[1..9];
            assert_eq!(section.anchor.as_deref(), Some(first_time));
        }

        // Sealed, every part is one section: the cuts stay between segments.
        let provider = ProviderKindV1::new(GRANOLA_PROVIDER).unwrap();
        let mut long = note();
        long.transcript = Some(segments);
        let context = GranolaNoteContextV1 {
            provider: &provider,
            provider_scope_id: SCOPE,
            container: None,
        };
        let draft = transcript_draft(&context, &long, long.transcript.as_deref().unwrap())
            .unwrap()
            .unwrap();
        let redactor = redactor();
        let collection = collection_record(
            CollectionModeV1::Pull,
            ContractId::new("granola.acme").unwrap(),
            None,
            None,
        )
        .unwrap();
        let sealed = seal(
            &draft,
            &SealContextV1 {
                redactor: &redactor,
                audience: AudienceBasisV1::OperatorDeclared,
                collection: &collection,
            },
        )
        .unwrap();
        assert_eq!(sealed.parts.len(), sections.len());
        for part in &sealed.parts {
            let text = part.envelope.text.as_str();
            assert!(text.starts_with('[') && text.len() <= MAX_PART_TEXT_BYTES);
            assert!(
                text.ends_with('\n') || part.envelope.part.ordinal + 1 == part.envelope.part.count
            );
        }
    }

    #[test]
    fn a_tombstone_is_revoked_metadata_only() {
        let provider = ProviderKindV1::new(GRANOLA_PROVIDER).unwrap();
        let container = folder();
        let context = GranolaNoteContextV1 {
            provider: &provider,
            provider_scope_id: SCOPE,
            container: Some(&container),
        };
        let tombstone = tombstone_draft(&context, TRANSCRIPT_OBJECT_KIND, "not_1d3tmYTlCICgjy", 42);
        assert_eq!(tombstone.lifecycle, ItemLifecycleV1::Revoked);
        assert!(tombstone.sections.is_empty() && tombstone.title.is_none());
        assert_eq!(tombstone.order_micros, 42);
        assert_eq!(tombstone.object_kind.as_str(), TRANSCRIPT_OBJECT_KIND);
    }

    #[test]
    fn ids_are_checked_exactly() {
        assert!(is_note_id("not_1d3tmYTlCICgjy"));
        assert!(is_folder_id("fol_4y6LduVdwSKC27"));
        for bad in [
            "not_",
            "fol_4y6LduVdwSKC27",
            "not_a/b",
            "not_a..b",
            "not_a?b",
            "not_é",
        ] {
            assert!(!is_note_id(bad), "{bad}");
        }
        assert!(!is_note_id(&format!("not_{}", "a".repeat(33))));
        assert!(!is_folder_id("Platform"));
    }
}
