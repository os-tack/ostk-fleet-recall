//! The `items-jsonl` import format: one [`CollectedItemInputV1`] per line
//! (ADR 0008 D9).
//!
//! A line is the same plain-text item an agent capture carries, with no scope
//! and no channel of its own: the import's instance pins the provider and the
//! provider scope, and every line must name exactly those. What a line may
//! not do is decided here, before a draft exists, and becomes a digest-only
//! dead letter:
//!
//! | Line | Dead letter |
//! |---|---|
//! | longer than [`MAX_IMPORT_LINE_BYTES`], not JSON, or not a collected-item input | `parse_failed` |
//! | another provider or provider scope than the instance's | `validation_failed` (`provider_scope_mismatch`) |
//! | neither `updated_at` nor `created_at` | `validation_failed` |
//! | a clock that is not RFC 3339, or anything else the draft refuses | `validation_failed` |
//!
//! Blank lines are skipped. What a draft may not be (a secret in an id, a
//! `visibility` of `private` or `dm`, text past the part bound) is the sink's
//! to decide, as for every collector. A container whose kind names a direct
//! conversation (a last segment of `im`, `mpim`, `dm`, `group_dm`, or
//! `direct_message`, such as Slack's `slack.im`) carries a direct-message
//! audience, so its items are refused whatever the operator declared: an
//! export is never a way to admit a direct conversation.
//!
//! [`LineReader`] reads a file line by line within the bound, hashing every
//! byte it reads, so the whole file's digest is known once the last line is
//! read without holding the file in memory.

use std::collections::BTreeMap;
use std::io::{self, BufRead};

use sha2::{Digest as _, Sha256};

use crate::collectors::audience::ProviderAudienceV1;
use crate::collectors::binding::CollectorInstanceV1;
use crate::collectors::draft::{CollectedItemDraftV1, has_hidden_scalar};
use crate::collectors::redaction::scan_collected_secrets;
use crate::collectors::sink::{ContainerObservationV1, DeadLetterReasonV1};
use crate::memory_contracts::collected_item::{
    BoundedTextV1, CollectedItemInputV1, ContainerKindV1, MAX_LABEL_BYTES, derive_container_key,
};
use crate::memory_contracts::digest::Sha256Digest;

/// The format name `collect import --format` takes.
pub const ITEMS_JSONL_FORMAT: &str = "items-jsonl";

/// Longest line an import reads (4 MiB): room for an item whose text fills
/// every part of a version, escaped as JSON.
pub const MAX_IMPORT_LINE_BYTES: usize = 4 * 1024 * 1024;

/// Most lines one import file holds, blank ones included.
pub const MAX_IMPORT_LINES: u64 = 100_000;

/// The diagnostic of a line that names another provider scope.
pub const PROVIDER_SCOPE_MISMATCH: &str =
    "provider_scope_mismatch: the item's provider scope is not the collector instance's";

/// Last container-kind segments that name a direct conversation.
const DIRECT_CONTAINER_SEGMENTS: [&str; 5] = ["im", "mpim", "dm", "group_dm", "direct_message"];

/// One line of an import file.
#[derive(Clone, PartialEq, Eq)]
pub enum RawLineV1 {
    /// A line within the bound, without its line terminator.
    Line {
        /// Its 1-based line number.
        number: u64,
        /// Its bytes.
        bytes: Vec<u8>,
    },
    /// A line past [`MAX_IMPORT_LINE_BYTES`]: only its digest was kept.
    Oversize {
        /// Its 1-based line number.
        number: u64,
        /// The SHA-256 of its bytes.
        digest: Sha256Digest,
    },
}

/// Lengths only: a line is provider content.
impl std::fmt::Debug for RawLineV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Line { number, bytes } => formatter
                .debug_struct("Line")
                .field("number", number)
                .field("bytes", &bytes.len())
                .finish(),
            Self::Oversize { number, digest } => formatter
                .debug_struct("Oversize")
                .field("number", number)
                .field("digest", digest)
                .finish(),
        }
    }
}

/// Reads an import file line by line, within [`MAX_IMPORT_LINE_BYTES`], and
/// hashes every byte it reads.
pub struct LineReader<R> {
    inner: R,
    file: Sha256,
    number: u64,
}

impl<R: BufRead> LineReader<R> {
    /// A reader over `inner`, from its first byte.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            file: Sha256::new(),
            number: 0,
        }
    }

    /// The next line, or `None` at the end of the file. A trailing `\r` is
    /// not part of a line.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub fn next_line(&mut self) -> io::Result<Option<RawLineV1>> {
        let mut bytes = Vec::new();
        let mut overflow: Option<Sha256> = None;
        let mut read_any = false;
        loop {
            let available = self.inner.fill_buf()?;
            if available.is_empty() {
                break;
            }
            read_any = true;
            let (taken, terminated) = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or((available.len(), false), |index| (index + 1, true));
            let chunk = &available[..taken];
            self.file.update(chunk);
            let content = if terminated {
                &chunk[..chunk.len() - 1]
            } else {
                chunk
            };
            if let Some(hash) = overflow.as_mut() {
                hash.update(content);
            } else if bytes.len() + content.len() > MAX_IMPORT_LINE_BYTES {
                let mut hash = Sha256::new();
                hash.update(&bytes);
                hash.update(content);
                bytes = Vec::new();
                overflow = Some(hash);
            } else {
                bytes.extend_from_slice(content);
            }
            self.inner.consume(taken);
            if terminated {
                break;
            }
        }
        if !read_any {
            return Ok(None);
        }
        self.number += 1;
        let number = self.number;
        if let Some(hash) = overflow {
            return Ok(Some(RawLineV1::Oversize {
                number,
                digest: Sha256Digest::from_bytes(hash.finalize().into()),
            }));
        }
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        Ok(Some(RawLineV1::Line { number, bytes }))
    }

    /// Lines read so far.
    #[must_use]
    pub const fn lines(&self) -> u64 {
        self.number
    }

    /// The SHA-256 of every byte read.
    #[must_use]
    pub fn digest(self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.file.finalize().into())
    }
}

/// The SHA-256 of one line's bytes: the payload digest of its dead letter.
#[must_use]
pub fn line_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

/// Whether a container kind names a direct conversation.
#[must_use]
pub fn is_direct_container_kind(kind: &ContainerKindV1) -> bool {
    kind.as_str()
        .rsplit('.')
        .next()
        .is_some_and(|segment| DIRECT_CONTAINER_SEGMENTS.contains(&segment))
}

/// One item line, ready to stage.
#[derive(Debug, Clone)]
pub struct ImportItemV1 {
    /// The draft.
    pub draft: CollectedItemDraftV1,
    /// A direct-message audience for a direct conversation's container.
    pub provider_audience: Option<ProviderAudienceV1>,
    /// The container's key in the instance's scope.
    pub container: Option<Sha256Digest>,
}

/// One line refused before it became a draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRefusalV1 {
    /// The dead letter's reason.
    pub reason: DeadLetterReasonV1,
    /// A static diagnostic; never the line's text.
    pub diagnostic: String,
    /// The line's digest.
    pub payload_digest: Sha256Digest,
    /// The container the line names in the instance's scope, when it names
    /// one there.
    pub container: Option<Sha256Digest>,
}

/// What one line is.
#[derive(Debug, Clone)]
pub enum ImportLineV1 {
    /// Only whitespace.
    Blank,
    /// An item to stage.
    Item(Box<ImportItemV1>),
    /// A line refused before it became a draft.
    Refused(ImportRefusalV1),
}

fn refused(
    reason: DeadLetterReasonV1,
    diagnostic: impl Into<String>,
    bytes: &[u8],
    container: Option<Sha256Digest>,
) -> ImportLineV1 {
    ImportLineV1::Refused(ImportRefusalV1 {
        reason,
        diagnostic: diagnostic.into(),
        payload_digest: line_digest(bytes),
        container,
    })
}

/// Decide what one line is, for an import into `instance`. See the module
/// documentation.
#[must_use]
pub fn classify_line(bytes: &[u8], instance: &CollectorInstanceV1) -> ImportLineV1 {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return ImportLineV1::Blank;
    }
    let Ok(input) = CollectedItemInputV1::parse(bytes) else {
        return refused(
            DeadLetterReasonV1::ParseFailed,
            "the line is not a collected-item input",
            bytes,
            None,
        );
    };
    if input.provider != instance.provider
        || input.provider_scope_id != instance.provider_scope_id.as_str()
    {
        return refused(
            DeadLetterReasonV1::ValidationFailed,
            PROVIDER_SCOPE_MISMATCH,
            bytes,
            None,
        );
    }
    let container = input.container.as_ref().map(|container| {
        derive_container_key(
            &instance.provider,
            instance.provider_scope_id.as_str(),
            &container.kind,
            &container.id,
        )
    });
    if input.updated_at.is_none() && input.created_at.is_none() {
        return refused(
            DeadLetterReasonV1::ValidationFailed,
            "an imported item needs updated_at or created_at",
            bytes,
            container,
        );
    }
    let direct = input
        .container
        .as_ref()
        .is_some_and(|container| is_direct_container_kind(&container.kind));
    match CollectedItemDraftV1::from_input(input) {
        Ok(draft) => ImportLineV1::Item(Box::new(ImportItemV1 {
            draft,
            provider_audience: direct.then_some(ProviderAudienceV1::DirectMessage),
            container,
        })),
        Err(refusal) => refused(
            DeadLetterReasonV1::of_refusal(refusal),
            refusal.to_string(),
            bytes,
            container,
        ),
    }
}

/// What one import file says about one container of the instance's scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedContainerV1 {
    /// Its kind.
    pub kind: ContainerKindV1,
    /// Its provider-stable id.
    pub id: String,
    /// The label of its newest item that has one.
    pub label: Option<String>,
    label_order: Option<u64>,
    /// Whether an item in it carries a `private` or `dm` visibility.
    pub hint_refused: bool,
    /// Whether its kind names a direct conversation.
    pub direct: bool,
}

impl ScannedContainerV1 {
    /// The observation an import records for the container, or `None` when
    /// it records none: an item in it was declared private or direct, or its
    /// id is not one a container row can hold (the sink refuses those items
    /// on their own).
    ///
    /// A direct conversation is observed as one, so it is recorded withdrawn
    /// and nothing can later be captured into it. Every other container is
    /// observed as the operator declared it: visible to the project.
    #[must_use]
    pub fn observation(&self) -> Option<ContainerObservationV1> {
        let observable = !has_hidden_scalar(&self.id)
            && BoundedTextV1::<MAX_LABEL_BYTES>::new(self.id.clone()).is_ok()
            && scan_collected_secrets(&self.id).is_empty();
        if !observable || (self.hint_refused && !self.direct) {
            return None;
        }
        Some(ContainerObservationV1 {
            kind: self.kind.clone(),
            id: self.id.clone(),
            label: self.label.clone(),
            provider_audience: if self.direct {
                ProviderAudienceV1::DirectMessage
            } else {
                ProviderAudienceV1::OperatorScoped
            },
        })
    }
}

/// What a first read of an import file learned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportScanV1 {
    /// The SHA-256 of the whole file.
    pub file_sha256: Sha256Digest,
    /// Lines read, blank ones included.
    pub lines: u64,
    /// The containers its items name in the instance's scope, by key.
    pub containers: BTreeMap<Sha256Digest, ScannedContainerV1>,
}

/// Read an import file once: its digest, its line count, and what its items
/// say about their containers.
///
/// # Errors
///
/// A read failure, or a file of more than [`MAX_IMPORT_LINES`] lines.
pub fn scan<R: BufRead>(inner: R, instance: &CollectorInstanceV1) -> io::Result<ImportScanV1> {
    let mut reader = LineReader::new(inner);
    let mut containers: BTreeMap<Sha256Digest, ScannedContainerV1> = BTreeMap::new();
    while let Some(line) = reader.next_line()? {
        if reader.lines() > MAX_IMPORT_LINES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("an import file holds at most {MAX_IMPORT_LINES} lines"),
            ));
        }
        let RawLineV1::Line { bytes, .. } = line else {
            continue;
        };
        let ImportLineV1::Item(item) = classify_line(&bytes, instance) else {
            continue;
        };
        let (Some(key), Some(container)) = (item.container, item.draft.container.as_ref()) else {
            continue;
        };
        let entry = containers.entry(key).or_insert_with(|| ScannedContainerV1 {
            kind: container.kind.clone(),
            id: container.id.clone(),
            label: None,
            label_order: None,
            hint_refused: false,
            direct: is_direct_container_kind(&container.kind),
        });
        entry.hint_refused |= item
            .draft
            .visibility
            .is_some_and(crate::memory_contracts::collected_item::VisibilityHintV1::refuses);
        if let Some(label) = &container.label
            && entry
                .label_order
                .is_none_or(|order| item.draft.order_micros >= order)
        {
            entry.label = Some(label.clone());
            entry.label_order = Some(item.draft.order_micros);
        }
    }
    Ok(ImportScanV1 {
        lines: reader.lines(),
        file_sha256: reader.digest(),
        containers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_contracts::collected_item::ProviderKindV1;
    use crate::memory_contracts::common::ContractId;

    fn instance() -> CollectorInstanceV1 {
        CollectorInstanceV1 {
            connector_instance_id: ContractId::new("import.slack").unwrap(),
            provider: ProviderKindV1::new("slack").unwrap(),
            provider_scope_id: BoundedTextV1::new("T07ACME0001").unwrap(),
        }
    }

    fn line(extra: &str) -> String {
        format!(
            r#"{{"provider":"slack","provider_scope_id":"T07ACME0001","object_kind":"message","external_id":"C1:1.0","container":{{"kind":"slack.channel","id":"C1","label":"general"}},"text":"hello"{extra}}}"#
        )
    }

    fn reason(line: &ImportLineV1) -> (DeadLetterReasonV1, String) {
        match line {
            ImportLineV1::Refused(refusal) => (refusal.reason, refusal.diagnostic.clone()),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_line_is_an_item_only_in_the_instance_scope_and_with_a_provider_clock() {
        let item = classify_line(
            line(r#","updated_at":"2026-09-21T16:04:05Z""#).as_bytes(),
            &instance(),
        );
        let ImportLineV1::Item(item) = item else {
            panic!("an item: {item:?}");
        };
        assert!(item.container.is_some());
        assert_eq!(item.provider_audience, None);

        let foreign =
            line(r#","updated_at":"2026-09-21T16:04:05Z""#).replace("T07ACME0001", "T07OTHER001");
        let (reason_of, diagnostic) = reason(&classify_line(foreign.as_bytes(), &instance()));
        assert_eq!(reason_of, DeadLetterReasonV1::ValidationFailed);
        assert!(diagnostic.starts_with("provider_scope_mismatch"));

        let clockless = classify_line(line("").as_bytes(), &instance());
        assert_eq!(reason(&clockless).0, DeadLetterReasonV1::ValidationFailed);
        // An explicit order is no provider clock.
        let ordered = line(r#","version":{"order_micros":1}"#);
        assert_eq!(
            reason(&classify_line(ordered.as_bytes(), &instance())).0,
            DeadLetterReasonV1::ValidationFailed
        );
        let bad_clock = line(r#","updated_at":"yesterday""#);
        assert_eq!(
            reason(&classify_line(bad_clock.as_bytes(), &instance())).0,
            DeadLetterReasonV1::ValidationFailed
        );
        for garbage in ["{", "[1]", r#"{"provider":"slack"}"#] {
            assert_eq!(
                reason(&classify_line(garbage.as_bytes(), &instance())).0,
                DeadLetterReasonV1::ParseFailed
            );
        }
        assert!(matches!(
            classify_line(b" \t", &instance()),
            ImportLineV1::Blank
        ));
    }

    #[test]
    fn a_direct_conversation_carries_a_direct_message_audience() {
        for kind in ["slack.im", "slack.mpim", "teams.group_dm", "x.dm"] {
            assert!(is_direct_container_kind(
                &ContainerKindV1::new(kind).unwrap()
            ));
        }
        for kind in ["slack.channel", "linear.team", "docs.root", "slack.image"] {
            assert!(!is_direct_container_kind(
                &ContainerKindV1::new(kind).unwrap()
            ));
        }
        let direct =
            line(r#","updated_at":"2026-09-21T16:04:05Z""#).replace("slack.channel", "slack.im");
        let ImportLineV1::Item(item) = classify_line(direct.as_bytes(), &instance()) else {
            panic!("a direct conversation's item is still a draft; the sink refuses it");
        };
        assert_eq!(
            item.provider_audience,
            Some(ProviderAudienceV1::DirectMessage)
        );
    }

    #[test]
    fn the_reader_bounds_lines_and_hashes_the_whole_file() {
        let long = "x".repeat(MAX_IMPORT_LINE_BYTES + 1);
        let file = format!("a\r\n\n{long}\nlast");
        let mut reader = LineReader::new(file.as_bytes());
        let mut lines = Vec::new();
        while let Some(line) = reader.next_line().unwrap() {
            lines.push(line);
        }
        assert_eq!(
            lines[0],
            RawLineV1::Line {
                number: 1,
                bytes: b"a".to_vec()
            }
        );
        assert_eq!(
            lines[1],
            RawLineV1::Line {
                number: 2,
                bytes: Vec::new()
            }
        );
        assert_eq!(
            lines[2],
            RawLineV1::Oversize {
                number: 3,
                digest: line_digest(long.as_bytes())
            }
        );
        assert_eq!(
            lines[3],
            RawLineV1::Line {
                number: 4,
                bytes: b"last".to_vec()
            }
        );
        assert_eq!(reader.digest(), line_digest(file.as_bytes()));
    }

    #[test]
    fn a_scan_observes_containers_as_declared_unless_an_item_narrows_them() {
        let public = line(r#","updated_at":"2026-09-21T16:04:05Z""#);
        let relabelled = public
            .replace("C1:1.0", "C1:2.0")
            .replace("general", "renamed")
            .replace("16:04:05", "17:00:00");
        let private = line(r#","updated_at":"2026-09-21T16:04:05Z","visibility":"private""#)
            .replace("\"C1\"", "\"C2\"");
        let direct = public
            .replace("slack.channel", "slack.im")
            .replace("\"C1\"", "\"D1\"");
        let file = [public, relabelled, private, direct].join("\n");
        let scan = scan(file.as_bytes(), &instance()).unwrap();
        assert_eq!(scan.lines, 4);
        let observed: BTreeMap<String, (Option<String>, ProviderAudienceV1)> = scan
            .containers
            .values()
            .filter_map(ScannedContainerV1::observation)
            .map(|observation| {
                (
                    observation.id,
                    (observation.label, observation.provider_audience),
                )
            })
            .collect();
        assert_eq!(
            observed,
            BTreeMap::from([
                (
                    "C1".to_owned(),
                    (
                        Some("renamed".to_owned()),
                        ProviderAudienceV1::OperatorScoped
                    )
                ),
                (
                    "D1".to_owned(),
                    (
                        Some("general".to_owned()),
                        ProviderAudienceV1::DirectMessage
                    )
                ),
            ])
        );
    }
}
