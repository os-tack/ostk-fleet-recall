//! The `slack-export` import format: a Slack workspace export, as a
//! directory or a zip archive (ADR 0008 D9).
//!
//! An export holds `channels.json` (public channels), `groups.json` (private
//! channels), `dms.json` and `mpims.json` (direct conversations), and one
//! folder per conversation, named after it, of day files
//! (`YYYY-MM-DD.json`, each an array of messages in the Web API's shape).
//! This format reads, in order:
//!
//! 1. `channels.json` and `groups.json`; folder names are mutable labels, so
//!    each folder is mapped to its channel's id through them;
//! 2. every public channel, and every private channel the operator lists with
//!    `--private-container`, in id order, each day file in date order. A
//!    private channel that is not listed is never opened: it is recorded as a
//!    withdrawn container and nothing of it is staged. `dms.json`,
//!    `mpims.json`, and any folder no channel names are never read.
//!
//! Every message becomes a draft exactly as the pull collector makes it
//! ([`crate::collectors::slack::render`]), so a message imported and the same
//! message pulled are one item, and a file link's own token (`?t=xoxe-...`,
//! which exports carry) is stripped. A message is recorded once per
//! `(channel, ts)`. A day file that is not an array of messages, and a
//! message that is not the documented shape, are digest-only dead letters
//! that leave their channel partial. Each channel read is one container of
//! the import's snapshot.
//!
//! **Bounds.** A zip holds at most 100,000 entries, one entry is at most 64
//! MiB, and one read of the export is at most 2 GiB, whatever the archive's
//! headers claim: every entry is read through a limit. A directory export is
//! read under the same bounds, and a symlink in it is never followed.
//!
//! The export is read twice, like every import: once to digest it (the digest
//! of every entry read, framed by name, in order), once to stage it. An
//! export that changed between the reads is refused.

use std::collections::{BTreeSet, VecDeque};
use std::fs::File;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::collectors::audience::ProviderAudienceV1;
use crate::collectors::binding::CollectorInstanceV1;
use crate::collectors::cockroach::framed_sha256;
use crate::collectors::sink::{ContainerObservationV1, DeadLetterReasonV1};
use crate::collectors::slack::render::{
    CHANNEL_CONTAINER_KIND, MessageDraftV1, SlackChannelContextV1, SlackMessageV1, SlackTsV1,
    message_draft, message_external_id, tombstone_draft,
};
use crate::memory_contracts::collected_item::{ContainerKindV1, derive_container_key};
use crate::memory_contracts::digest::Sha256Digest;

use super::jsonl::{ImportItemV1, ImportLineV1, ImportRefusalV1};

/// The format name `collect import --format` takes.
pub const SLACK_EXPORT_FORMAT: &str = "slack-export";

/// Entries a zip export holds at most (and files a directory export reads).
pub const MAX_EXPORT_ENTRIES: usize = 100_000;

/// Bytes one entry holds at most: 64 MiB.
pub const MAX_EXPORT_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

/// Bytes one read of an export reads at most: 2 GiB.
pub const MAX_EXPORT_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Whether a file name is a day file: `YYYY-MM-DD.json`.
fn is_day_file(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 15
        && &bytes[10..] == b".json"
        && bytes[..10].iter().enumerate().all(|(index, byte)| {
            if index == 4 || index == 7 {
                *byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        })
}

/// Whether a channel name can be a folder of the export: no separator, not
/// hidden, not empty.
fn is_folder_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && !name.contains(['/', '\\', '\0'])
}

/// Whether a channel id is one: `C...` or `G...`, upper-case letters and
/// digits.
fn is_channel_id(id: &str) -> bool {
    id.len() >= 3
        && id.len() <= 32
        && id.starts_with(['C', 'G'])
        && id
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

/// Where the export is.
enum ArchiveV1 {
    Directory(PathBuf),
    Zip {
        archive: Box<zip::ZipArchive<File>>,
        /// The folder the export sits in inside the archive (`""`, or one
        /// folder and `/`).
        prefix: String,
    },
}

/// How much one read of the export has read.
#[derive(Debug, Default)]
struct BudgetV1 {
    entries: usize,
    bytes: u64,
}

impl BudgetV1 {
    fn spend(&mut self, bytes: usize) -> io::Result<()> {
        self.entries += 1;
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        if self.entries > MAX_EXPORT_ENTRIES {
            return Err(invalid(format!(
                "a Slack export is read from at most {MAX_EXPORT_ENTRIES} entries"
            )));
        }
        if self.bytes > MAX_EXPORT_TOTAL_BYTES {
            return Err(invalid(format!(
                "a Slack export holds at most {MAX_EXPORT_TOTAL_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

fn zip_error(error: zip::result::ZipError) -> io::Error {
    match error {
        zip::result::ZipError::Io(error) => error,
        other => invalid(format!("the Slack export archive: {other}")),
    }
}

/// Read at most the entry bound from `reader`.
fn bounded_read(reader: impl io::Read, name: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_EXPORT_ENTRY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_EXPORT_ENTRY_BYTES {
        return Err(invalid(format!(
            "the Slack export entry {name} is larger than {MAX_EXPORT_ENTRY_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

impl ArchiveV1 {
    fn open(path: &Path) -> io::Result<Self> {
        if std::fs::metadata(path)?.is_dir() {
            return Ok(Self::Directory(path.to_path_buf()));
        }
        let archive = zip::ZipArchive::new(File::open(path)?).map_err(zip_error)?;
        if archive.len() > MAX_EXPORT_ENTRIES {
            return Err(invalid(format!(
                "a Slack export archive holds at most {MAX_EXPORT_ENTRIES} entries"
            )));
        }
        // The export sits at the archive's top, or in one folder.
        let prefix = archive
            .file_names()
            .filter_map(|name| name.strip_suffix("channels.json"))
            .filter(|prefix| {
                prefix.is_empty() || (prefix.ends_with('/') && prefix.matches('/').count() == 1)
            })
            .min_by_key(|prefix| prefix.len())
            .map(str::to_owned)
            .ok_or_else(|| invalid("the archive is not a Slack export: it has no channels.json"))?;
        Ok(Self::Zip {
            archive: Box::new(archive),
            prefix,
        })
    }

    /// One entry by its name inside the export, or `None` when it is absent.
    fn read(&mut self, name: &str, budget: &mut BudgetV1) -> io::Result<Option<Vec<u8>>> {
        let bytes = match self {
            Self::Directory(root) => {
                let path = root.join(name);
                match std::fs::symlink_metadata(&path) {
                    Ok(metadata) if metadata.is_file() => {
                        Some(bounded_read(File::open(&path)?, name)?)
                    }
                    Ok(_) => None,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error),
                }
            }
            Self::Zip { archive, prefix } => match archive.by_name(&format!("{prefix}{name}")) {
                Ok(entry) if entry.is_file() => Some(bounded_read(entry, name)?),
                Ok(_) | Err(zip::result::ZipError::FileNotFound) => None,
                Err(error) => return Err(zip_error(error)),
            },
        };
        if let Some(bytes) = &bytes {
            budget.spend(bytes.len())?;
        }
        Ok(bytes)
    }

    /// The day files of one channel's folder, in date order.
    fn day_files(&self, folder: &str) -> io::Result<Vec<String>> {
        let mut days: Vec<String> = match self {
            // A channel folder that is a symlink (or anything but a real
            // directory) is never followed.
            Self::Directory(root)
                if !std::fs::symlink_metadata(root.join(folder))
                    .is_ok_and(|metadata| metadata.is_dir()) =>
            {
                Vec::new()
            }
            Self::Directory(root) => match std::fs::read_dir(root.join(folder)) {
                Ok(entries) => {
                    let mut days = Vec::new();
                    for entry in entries {
                        let entry = entry?;
                        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                            continue;
                        };
                        if is_day_file(&name) && entry.file_type()?.is_file() {
                            days.push(name);
                        }
                    }
                    days
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
                Err(error) => return Err(error),
            },
            Self::Zip { archive, prefix } => {
                let folder = format!("{prefix}{folder}/");
                archive
                    .file_names()
                    .filter_map(|name| name.strip_prefix(&folder))
                    .filter(|name| is_day_file(name))
                    .map(str::to_owned)
                    .collect()
            }
        };
        days.sort();
        days.dedup();
        Ok(days)
    }
}

/// One channel of `channels.json` or `groups.json`; only its id and name are
/// read.
#[derive(Debug, Clone, Deserialize)]
struct ChannelEntryV1 {
    id: String,
    name: String,
}

/// One channel of the export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedChannelV1 {
    /// Its id.
    pub id: String,
    /// Its name: its folder, and its container's label.
    pub name: String,
    /// Listed in `groups.json`.
    pub private: bool,
    /// Its container key in the instance's scope.
    pub key: Sha256Digest,
}

impl ExportedChannelV1 {
    /// What the export says about who can read it.
    #[must_use]
    pub const fn audience(&self) -> ProviderAudienceV1 {
        if self.private {
            ProviderAudienceV1::Restricted
        } else {
            ProviderAudienceV1::ScopePublic
        }
    }

    /// Its container observation; a withheld channel keeps no label.
    #[must_use]
    pub fn observation(&self, labelled: bool) -> ContainerObservationV1 {
        ContainerObservationV1 {
            kind: ContainerKindV1::new(CHANNEL_CONTAINER_KIND)
                .unwrap_or_else(|_| unreachable!("the channel kind is a valid token")),
            id: self.id.clone(),
            label: labelled.then(|| self.name.clone()),
            provider_audience: self.audience(),
        }
    }
}

/// The channel being read.
struct CurrentV1 {
    channel: usize,
    days: VecDeque<String>,
    messages: VecDeque<serde_json::Value>,
    seen: BTreeSet<String>,
}

/// Reads an export's messages in order, one record each, digesting every
/// entry it reads.
pub struct SlackExportRecordsV1 {
    archive: ArchiveV1,
    instance: CollectorInstanceV1,
    channels: Vec<ExportedChannelV1>,
    withheld: Vec<ExportedChannelV1>,
    next_channel: usize,
    current: Option<CurrentV1>,
    number: u64,
    hasher: Sha256,
    budget: BudgetV1,
}

impl std::fmt::Debug for SlackExportRecordsV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SlackExportRecordsV1")
            .field("channels", &self.channels.len())
            .field("withheld", &self.withheld.len())
            .field("number", &self.number)
            .finish_non_exhaustive()
    }
}

fn hash_entry(hasher: &mut Sha256, name: &str, bytes: Option<&[u8]>) {
    hasher.update(u64::try_from(name.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(name.as_bytes());
    match bytes {
        Some(bytes) => {
            hasher.update([1]);
            hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(bytes);
        }
        None => hasher.update([0]),
    }
}

impl SlackExportRecordsV1 {
    /// Open the export at `path` for `instance`: read its channel lists and
    /// decide which channels are read. `private_containers` lists the private
    /// channels the operator admits.
    ///
    /// # Errors
    ///
    /// An unreadable export, one past its bounds, or one whose channel lists
    /// are not the documented shape.
    pub fn open(
        path: &Path,
        instance: &CollectorInstanceV1,
        private_containers: &[String],
    ) -> io::Result<Self> {
        let mut archive = ArchiveV1::open(path)?;
        let mut hasher = Sha256::new();
        let mut budget = BudgetV1::default();
        let mut listed = Vec::new();
        for (list, private) in [("channels.json", false), ("groups.json", true)] {
            let bytes = archive.read(list, &mut budget)?;
            hash_entry(&mut hasher, list, bytes.as_deref());
            let Some(bytes) = bytes else {
                if private {
                    continue;
                }
                return Err(invalid("not a Slack export: it has no channels.json"));
            };
            let entries: Vec<ChannelEntryV1> = serde_json::from_slice(&bytes)
                .map_err(|_| invalid(format!("{list} is not an array of channels")))?;
            listed.extend(entries.into_iter().map(|entry| (entry, private)));
        }
        let kind = ContainerKindV1::new(CHANNEL_CONTAINER_KIND)
            .map_err(|_| invalid("the channel container kind"))?;
        let mut ids = BTreeSet::new();
        let mut folders = BTreeSet::new();
        let mut channels = Vec::new();
        let mut withheld = Vec::new();
        for (entry, private) in listed {
            if !is_channel_id(&entry.id) {
                return Err(invalid(format!(
                    "the export lists a channel whose id {:?} is not a channel id",
                    entry.id
                )));
            }
            if !ids.insert(entry.id.clone()) || !folders.insert(entry.name.clone()) {
                return Err(invalid(format!(
                    "the export lists channel {} or its name twice",
                    entry.id
                )));
            }
            if !is_folder_name(&entry.name) {
                return Err(invalid(format!(
                    "the export names channel {} with a name that is no folder",
                    entry.id
                )));
            }
            let channel = ExportedChannelV1 {
                key: derive_container_key(
                    &instance.provider,
                    instance.provider_scope_id.as_str(),
                    &kind,
                    &entry.id,
                ),
                id: entry.id,
                name: entry.name,
                private,
            };
            if private && !private_containers.contains(&channel.id) {
                withheld.push(channel);
            } else {
                channels.push(channel);
            }
        }
        channels.sort_by(|left, right| left.id.cmp(&right.id));
        withheld.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(Self {
            archive,
            instance: instance.clone(),
            channels,
            withheld,
            next_channel: 0,
            current: None,
            number: 0,
            hasher,
            budget,
        })
    }

    /// The channels whose messages are read, in id order.
    #[must_use]
    pub fn channels(&self) -> &[ExportedChannelV1] {
        &self.channels
    }

    /// The private channels the operator did not list: never read.
    #[must_use]
    pub fn withheld(&self) -> &[ExportedChannelV1] {
        &self.withheld
    }

    /// Records returned so far.
    #[must_use]
    pub const fn records(&self) -> u64 {
        self.number
    }

    /// The digest of every entry read.
    #[must_use]
    pub fn digest(self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.hasher.finalize().into())
    }

    /// The next record and its number, or `None` once every channel is read.
    ///
    /// # Errors
    ///
    /// An unreadable entry, or a read past the export's bounds.
    pub fn next_record(&mut self) -> io::Result<Option<(u64, ImportLineV1)>> {
        loop {
            if let Some(mut current) = self.current.take() {
                if let Some(value) = current.messages.pop_front() {
                    self.number += 1;
                    let channel = &self.channels[current.channel];
                    let record = message_record(&self.instance, channel, value, &mut current.seen);
                    self.current = Some(current);
                    return Ok(Some((self.number, record)));
                }
                if let Some(day) = current.days.pop_front() {
                    let channel = self.channels[current.channel].clone();
                    let name = format!("{}/{day}", channel.name);
                    let bytes = self.archive.read(&name, &mut self.budget)?;
                    hash_entry(&mut self.hasher, &name, bytes.as_deref());
                    let bytes = bytes.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("the Slack export entry {name} vanished while it was read"),
                        )
                    })?;
                    let parsed = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes);
                    let Ok(messages) = parsed else {
                        self.current = Some(current);
                        self.number += 1;
                        return Ok(Some((
                            self.number,
                            ImportLineV1::Refused(ImportRefusalV1 {
                                reason: DeadLetterReasonV1::ParseFailed,
                                diagnostic: "a Slack export day file is not an array of messages"
                                    .to_owned(),
                                payload_digest: framed_sha256(
                                    "ostk-slack-export-day-v1",
                                    &[name.as_bytes(), &bytes],
                                ),
                                container: Some(channel.key),
                            }),
                        )));
                    };
                    current.messages = messages.into();
                    self.current = Some(current);
                    continue;
                }
            }
            let Some(channel) = self.channels.get(self.next_channel) else {
                return Ok(None);
            };
            let days = self.archive.day_files(&channel.name)?;
            self.current = Some(CurrentV1 {
                channel: self.next_channel,
                days: days.into(),
                messages: VecDeque::new(),
                seen: BTreeSet::new(),
            });
            self.next_channel += 1;
        }
    }
}

/// One message of one channel as a record.
fn message_record(
    instance: &CollectorInstanceV1,
    channel: &ExportedChannelV1,
    value: serde_json::Value,
    seen: &mut BTreeSet<String>,
) -> ImportLineV1 {
    let payload_digest = framed_sha256(
        "ostk-slack-export-message-v1",
        &[
            channel.id.as_bytes(),
            serde_json::to_string(&value).unwrap_or_default().as_bytes(),
        ],
    );
    let refused = |reason: DeadLetterReasonV1, diagnostic: &str| {
        ImportLineV1::Refused(ImportRefusalV1 {
            reason,
            diagnostic: diagnostic.to_owned(),
            payload_digest,
            container: Some(channel.key),
        })
    };
    let Ok(message) = serde_json::from_value::<SlackMessageV1>(value) else {
        return refused(
            DeadLetterReasonV1::ParseFailed,
            "a Slack export message is not the documented shape",
        );
    };
    let Some(ts) = SlackTsV1::parse(&message.ts) else {
        return refused(
            DeadLetterReasonV1::ValidationFailed,
            "a Slack message ts is not <seconds>.<6 digits>",
        );
    };
    if !seen.insert(ts.as_str().to_owned()) {
        return ImportLineV1::Blank;
    }
    let context = SlackChannelContextV1 {
        provider: &instance.provider,
        provider_scope_id: instance.provider_scope_id.as_str(),
        channel_id: &channel.id,
        channel_label: Some(&channel.name),
        workspace_url: None,
    };
    let (draft, tombstone) = match message_draft(&context, &message) {
        MessageDraftV1::Item(draft) => (*draft, false),
        MessageDraftV1::Tombstone => {
            let external_id = message_external_id(&channel.id, ts.as_str());
            (
                tombstone_draft(&context, &external_id, None, ts.micros()),
                true,
            )
        }
        MessageDraftV1::Skip => return ImportLineV1::Blank,
    };
    ImportLineV1::Item(Box::new(ImportItemV1 {
        draft,
        provider_audience: Some(channel.audience()),
        container: Some(channel.key),
        // The export's deleted root carries only its original `ts`; an
        // earlier import may hold an edit of it at a later order.
        at_least_held_order: tombstone,
    }))
}

/// What a first read of an export learned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackExportScanV1 {
    /// The digest of every entry read.
    pub digest: Sha256Digest,
    /// Records read.
    pub records: u64,
    /// The channels read, in id order.
    pub channels: Vec<ExportedChannelV1>,
    /// The private channels not listed: never read.
    pub withheld: Vec<ExportedChannelV1>,
}

/// Read the export once, to its end: its digest and its channels.
///
/// # Errors
///
/// As [`SlackExportRecordsV1::open`] and [`SlackExportRecordsV1::next_record`].
pub fn scan(
    path: &Path,
    instance: &CollectorInstanceV1,
    private_containers: &[String],
) -> io::Result<SlackExportScanV1> {
    let mut records = SlackExportRecordsV1::open(path, instance, private_containers)?;
    while records.next_record()?.is_some() {}
    Ok(SlackExportScanV1 {
        records: records.records(),
        channels: records.channels.clone(),
        withheld: records.withheld.clone(),
        digest: records.digest(),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;
    use crate::memory_contracts::collected_item::{BoundedTextV1, ProviderKindV1};
    use crate::memory_contracts::common::ContractId;

    fn instance() -> CollectorInstanceV1 {
        CollectorInstanceV1 {
            connector_instance_id: ContractId::new("import.slack").unwrap(),
            provider: ProviderKindV1::new("slack").unwrap(),
            provider_scope_id: BoundedTextV1::new("T07ACME0001").unwrap(),
        }
    }

    /// A file link carrying a placeholder file token (`xoxe-` shaped, never a
    /// real credential).
    fn secret_file_link() -> String {
        "https://files.slack.com/files-pri/T07ACME0001-F1/plan.md?t=xoxe-EXAMPLE-NOT-A-FILE-TOKEN"
            .to_owned()
    }

    /// An export's entries, by name.
    fn entries() -> Vec<(String, String)> {
        let message = |ts: &str, text: &str| serde_json::json!({"type": "message", "user": "U07ALICE001", "ts": ts, "text": text});
        vec![
            (
                "channels.json".into(),
                serde_json::json!([
                    {"id": "C07PLATENG1", "name": "plat-eng"},
                    {"id": "C07GENERAL1", "name": "general"}
                ])
                .to_string(),
            ),
            (
                "groups.json".into(),
                serde_json::json!([
                    {"id": "G07SECRET01", "name": "secret-team"},
                    {"id": "G07LISTED01", "name": "listed-team"}
                ])
                .to_string(),
            ),
            (
                "dms.json".into(),
                serde_json::json!([{"id": "D07DIRECT01", "members": ["U1", "U2"]}]).to_string(),
            ),
            (
                "plat-eng/2026-09-21.json".into(),
                serde_json::json!([
                    message("1790006645.000200", "retry budget is 3"),
                    {"type": "message", "subtype": "channel_join", "user": "U2",
                     "ts": "1790006646.000000", "text": "<@U2> has joined"},
                    {"type": "message", "user": "U07BOB0002", "ts": "1790006860.001100",
                     "thread_ts": "1790006645.000200", "text": "see the plan",
                     "files": [{"name": "plan.md", "url_private": secret_file_link()}]}
                ])
                .to_string(),
            ),
            (
                "plat-eng/2026-09-20.json".into(),
                serde_json::json!([message("1790000000.000100", "an older day")]).to_string(),
            ),
            ("general/2026-09-21.json".into(), "not json".into()),
            (
                "secret-team/2026-09-21.json".into(),
                serde_json::json!([message("1790006700.000000", "the secret plan")]).to_string(),
            ),
            (
                "listed-team/2026-09-21.json".into(),
                serde_json::json!([message("1790006800.000000", "listed")]).to_string(),
            ),
            (
                "D07DIRECT01/2026-09-21.json".into(),
                serde_json::json!([message("1790006900.000000", "a direct message")]).to_string(),
            ),
        ]
    }

    fn directory() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for (name, text) in entries() {
            let path = root.path().join(&name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        root
    }

    fn zip_of(prefix: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = zip::ZipWriter::new(file.reopen().unwrap());
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, text) in entries() {
            writer
                .start_file(format!("{prefix}{name}"), options)
                .unwrap();
            writer.write_all(text.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
        file
    }

    fn read_all(path: &Path) -> (Vec<(u64, ImportLineV1)>, SlackExportScanV1) {
        let listed = ["G07LISTED01".to_owned()];
        let mut records = SlackExportRecordsV1::open(path, &instance(), &listed).unwrap();
        let mut all = Vec::new();
        while let Some(record) = records.next_record().unwrap() {
            all.push(record);
        }
        (all, scan(path, &instance(), &listed).unwrap())
    }

    fn texts(records: &[(u64, ImportLineV1)]) -> Vec<String> {
        records
            .iter()
            .filter_map(|(_, record)| match record {
                ImportLineV1::Item(item) => Some(item.draft.sections[0].text.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_directory_export_reads_listed_channels_by_id_and_days_in_order() {
        let root = directory();
        let (records, scan) = read_all(root.path());
        let ids: Vec<&str> = scan
            .channels
            .iter()
            .map(|channel| channel.id.as_str())
            .collect();
        assert_eq!(ids, ["C07GENERAL1", "C07PLATENG1", "G07LISTED01"]);
        assert_eq!(scan.withheld.len(), 1);
        assert_eq!(scan.withheld[0].id, "G07SECRET01");
        assert_eq!(
            texts(&records),
            [
                "an older day",
                "retry budget is 3",
                "see the plan",
                "listed"
            ]
        );
        let all_text = format!("{records:?}");
        assert!(!all_text.contains("secret plan"));
        assert!(!all_text.contains("direct message"));
        // The day file that is not JSON is one refusal in its channel.
        let refused: Vec<&ImportRefusalV1> = records
            .iter()
            .filter_map(|(_, record)| match record {
                ImportLineV1::Refused(refusal) => Some(refusal),
                _ => None,
            })
            .collect();
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].reason, DeadLetterReasonV1::ParseFailed);
        assert_eq!(refused[0].container, Some(scan.channels[0].key));
        // The join is skipped; the file link lost its token; the reply is a
        // reply of its root.
        let reply = records
            .iter()
            .find_map(|(_, record)| match record {
                ImportLineV1::Item(item) if item.draft.external_id.ends_with("001100") => {
                    Some(item.clone())
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(
            reply.draft.links[0].target,
            "https://files.slack.com/files-pri/T07ACME0001-F1/plan.md"
        );
        assert_eq!(
            reply.draft.thread.as_ref().unwrap().root_external_id,
            "C07PLATENG1:1790006645.000200"
        );
        assert_eq!(
            reply.provider_audience,
            Some(ProviderAudienceV1::ScopePublic)
        );
        assert_eq!(scan.records, u64::try_from(records.len()).unwrap());
    }

    #[test]
    fn a_zip_export_reads_the_same_records_at_its_top_or_in_one_folder() {
        let root = directory();
        let (from_directory, directory_scan) = read_all(root.path());
        for prefix in ["", "Acme Slack export Sep 21 2026/"] {
            let archive = zip_of(prefix);
            let (from_zip, zip_scan) = read_all(archive.path());
            assert_eq!(texts(&from_zip), texts(&from_directory), "{prefix:?}");
            assert_eq!(zip_scan.channels, directory_scan.channels);
            assert_eq!(
                zip_scan.digest, directory_scan.digest,
                "the digest is over entry names and bytes, not their container"
            );
        }
        let not_an_export = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(not_an_export.path(), b"PK not really").unwrap();
        assert!(SlackExportRecordsV1::open(not_an_export.path(), &instance(), &[]).is_err());
    }

    #[test]
    fn a_changed_export_has_another_digest_and_bad_lists_are_refused() {
        let root = directory();
        let before = scan(root.path(), &instance(), &[]).unwrap().digest;
        std::fs::write(
            root.path().join("plat-eng/2026-09-22.json"),
            serde_json::json!([]).to_string(),
        )
        .unwrap();
        assert_ne!(scan(root.path(), &instance(), &[]).unwrap().digest, before);

        for (channels, needle) in [
            (serde_json::json!({"id": "C1"}), "not an array"),
            (
                serde_json::json!([{"id": "D07DIRECT01", "name": "dm"}]),
                "not a channel id",
            ),
            (
                serde_json::json!([{"id": "C07A", "name": "a"}, {"id": "C07A", "name": "b"}]),
                "twice",
            ),
            (
                serde_json::json!([{"id": "C07A", "name": "../escape"}]),
                "no folder",
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            std::fs::write(root.path().join("channels.json"), channels.to_string()).unwrap();
            let error = SlackExportRecordsV1::open(root.path(), &instance(), &[]).unwrap_err();
            assert!(error.to_string().contains(needle), "{channels}: {error}");
        }
        let empty = tempfile::tempdir().unwrap();
        assert!(SlackExportRecordsV1::open(empty.path(), &instance(), &[]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_export_never_follows_a_symlink() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("2026-09-21.json"),
            serde_json::json!([{"type": "message", "user": "U1", "ts": "1790006999.000000",
                                "text": "outside the export"}])
            .to_string(),
        )
        .unwrap();
        let root = directory();
        // `general` becomes a link to a folder outside the export, and a day
        // of `plat-eng` a link to a file outside it.
        std::fs::remove_dir_all(root.path().join("general")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("general")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("2026-09-21.json"),
            root.path().join("plat-eng/2026-09-22.json"),
        )
        .unwrap();
        let (records, scan) = read_all(root.path());
        assert_eq!(scan.channels.len(), 3, "the channel stays in the domain");
        assert!(!texts(&records).iter().any(|text| text.contains("outside")));
        assert!(
            records
                .iter()
                .all(|(_, record)| !matches!(record, ImportLineV1::Refused(_))),
            "the general day file that is not JSON is no longer reached"
        );
    }

    /// The export the README quickstart imports
    /// (`tests/fixtures/collected/slack-export`) reads its public channel's
    /// thread, and never its unlisted private channel or its direct
    /// conversation, and its file link loses the export's token.
    #[test]
    fn the_quickstart_export_fixture_reads_only_its_public_channel() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/collected/slack-export");
        let mut records = SlackExportRecordsV1::open(&root, &instance(), &[]).unwrap();
        let mut all = Vec::new();
        while let Some(record) = records.next_record().unwrap() {
            all.push(record);
        }
        let channels: Vec<&str> = records.channels().iter().map(|c| c.id.as_str()).collect();
        let withheld: Vec<&str> = records.withheld().iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            (channels.as_slice(), withheld.as_slice()),
            (&["C07PLATENG1"][..], &["G07PLATSEC1"][..])
        );
        let texts = texts(&all);
        assert_eq!(texts.len(), 4, "{texts:?}");
        assert!(
            texts
                .iter()
                .any(|text| text.contains("retry budget is 5 attempts"))
        );
        let everything = format!("{all:?}");
        for never in ["Private channel", "Direct message", "xoxe-"] {
            assert!(!everything.contains(never), "{never}");
        }
    }

    #[test]
    fn a_day_file_name_is_a_date() {
        assert!(is_day_file("2026-09-21.json"));
        for bad in [
            "2026-9-21.json",
            "2026-09-21.jsn",
            "users.json",
            "../2026-09-21.json",
        ] {
            assert!(!is_day_file(bad), "{bad}");
        }
    }
}
