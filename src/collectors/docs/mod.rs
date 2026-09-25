//! The documents-directory collector: provider `docs` (ADR 0008 D8).
//!
//! One instance reads one directory tree, the root, as one container
//! (`docs.root`, id = the instance's provider scope id). The operator declares
//! it visible to the project (`audience.operator_declared`, required): a
//! documents root has no provider audience of its own.
//!
//! Every pass is a full enumeration, and so a reconciliation:
//!
//! * **Listing.** A depth-first walk of the root in byte order of names,
//!   files whose extension (any case) is listed in `extensions`, skipping
//!   names that begin with `.`. A symlink is followed only when it resolves to
//!   a regular file inside the root ([`within_root`]); a symlinked directory is
//!   never descended, so the walk has no cycle and never leaves the root. The
//!   listing stops at `max_files`, and a listing that stops there, or that
//!   could not read a directory or a name, is partial.
//! * **Items.** One item per file, object kind `document`, whose external id
//!   is the file's relative path with `/` separators, in NFC. A file is
//!   staged only when its content differs from the newest version the memory
//!   knows of it (the head, or a version still pending from a pass that did
//!   not get to drain it): its version marker is `o<pass instant>:sha256:
//!   <content digest>` and its order is the pass instant, so unchanged files
//!   stage nothing, and reverting content mints a new version. File times are
//!   never read.
//! * **Parts.** Markdown is split into sections by its headings, each part
//!   anchored at its heading path with the exact byte span it came from; its
//!   front matter gives the title and status ([`markdown`]). Other text is
//!   split at blank lines.
//! * **Refusals.** A file over `max_file_bytes` is an `oversize` dead letter
//!   and one that is not UTF-8 a `parse_failed` one, and either leaves the
//!   root partial. A file that is empty or only whitespace holds nothing to
//!   recall and is skipped; one the memory held text for is hidden like a
//!   deleted one.
//! * **Deletes.** A live document missing from a complete enumeration gets a
//!   tombstone (`deleted`) at the pass instant. A partial listing never
//!   tombstones anything.

pub mod markdown;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization as _;

use crate::error::{FleetError, Result};
use crate::memory_contracts::collected_item::{
    ContainerKindV1, ItemLifecycleV1, ObjectKindV1, ProviderKindV1, TextFormatV1,
};
use crate::memory_contracts::coverage::CoverageProofMethodV1;
use crate::memory_contracts::digest::Sha256Digest;
use crate::worker::CollectorSourceV1;

use super::CollectorAdapterV1;
use super::audience::ProviderAudienceV1;
use super::binding::CollectorInstanceV1;
use super::cockroach::framed_sha256;
use super::draft::{CollectedItemDraftV1, DraftContainerV1, DraftSectionV1};
use super::pull::{
    ContainerOutcomeV1, ListingBoundV1, PageStager, PartialReasonV1, PullCollectorV1,
    PullPassInputV1, PullPassOutcomeV1, PulledItemV1,
};
use super::sink::{ContainerObservationV1, DeadLetterReasonV1, KnownVersionV1};

/// The provider kind.
pub const DOCS_PROVIDER: &str = "docs";

/// The object kind of one file.
pub const DOCUMENT_OBJECT_KIND: &str = "document";

/// The container kind of the root.
pub const DOCS_CONTAINER_KIND: &str = "docs.root";

/// The extensions a root may list.
pub const DOCS_EXTENSIONS: [&str; 5] = ["md", "markdown", "txt", "rst", "adoc"];

/// Bytes of one file read at most, unless the settings say otherwise.
pub const DEFAULT_DOCS_MAX_FILE_BYTES: u64 = 1_048_576;

/// The largest `max_file_bytes`: 64 parts of 32 KiB.
pub const MAX_DOCS_MAX_FILE_BYTES: u64 = 2_097_152;

/// Files one pass lists at most, unless the settings say otherwise.
pub const DEFAULT_DOCS_MAX_FILES: usize = 5_000;

/// The largest `max_files`.
pub const MAX_DOCS_MAX_FILES: usize = 100_000;

/// Items staged per page.
const PAGE_ITEMS: usize = 64;

/// Every counter a documents pass reports.
pub const DOCS_COUNTERS: [&str; 9] = [
    "files_listed",
    "files_staged",
    "files_unchanged",
    "files_deleted",
    "files_empty",
    "files_dead_lettered",
    "files_unreadable",
    "symlinks_skipped",
    "listing_truncated",
];

fn default_extensions() -> Vec<String> {
    DOCS_EXTENSIONS
        .iter()
        .map(|extension| (*extension).to_owned())
        .collect()
}

const fn default_max_file_bytes() -> u64 {
    DEFAULT_DOCS_MAX_FILE_BYTES
}

const fn default_max_files() -> usize {
    DEFAULT_DOCS_MAX_FILES
}

/// A documents root's settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocsSettingsV1 {
    /// The directory; relative to the worker's working directory when not
    /// absolute.
    pub root: PathBuf,
    /// Which file extensions are documents; a subset of [`DOCS_EXTENSIONS`].
    #[serde(default = "default_extensions")]
    pub extensions: Vec<String>,
    /// Larger files are dead-lettered.
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,
    /// A listing stops here, and is then partial.
    #[serde(default = "default_max_files")]
    pub max_files: usize,
}

impl DocsSettingsV1 {
    /// Parse and validate one source's settings.
    ///
    /// # Errors
    ///
    /// A message naming the first refused setting.
    pub fn from_source(source: &CollectorSourceV1) -> std::result::Result<Self, String> {
        let settings: Self =
            serde_json::from_value(serde_json::Value::Object(source.settings.clone()))
                .map_err(|error| format!("settings: {error}"))?;
        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> std::result::Result<(), String> {
        if self.root.as_os_str().is_empty() {
            return Err("settings.root is empty".to_owned());
        }
        if self.extensions.is_empty() {
            return Err("settings.extensions lists no extension".to_owned());
        }
        let mut seen = BTreeSet::new();
        for extension in &self.extensions {
            if !DOCS_EXTENSIONS.contains(&extension.as_str()) {
                return Err(format!(
                    "settings.extensions: {extension:?} is not one of {}",
                    DOCS_EXTENSIONS.join(", ")
                ));
            }
            if !seen.insert(extension) {
                return Err(format!("settings.extensions lists {extension:?} twice"));
            }
        }
        if !(1..=MAX_DOCS_MAX_FILE_BYTES).contains(&self.max_file_bytes) {
            return Err(format!(
                "settings.max_file_bytes must be between 1 and {MAX_DOCS_MAX_FILE_BYTES}"
            ));
        }
        if !(1..=MAX_DOCS_MAX_FILES).contains(&self.max_files) {
            return Err(format!(
                "settings.max_files must be between 1 and {MAX_DOCS_MAX_FILES}"
            ));
        }
        Ok(())
    }

    fn lists(&self, name: &str) -> bool {
        Path::new(name)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                let lowered = extension.to_ascii_lowercase();
                self.extensions.contains(&lowered)
            })
    }
}

/// The documents adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct DocsAdapterV1;

impl CollectorAdapterV1 for DocsAdapterV1 {
    fn provider(&self) -> &'static str {
        DOCS_PROVIDER
    }

    fn validate(&self, source: &CollectorSourceV1) -> std::result::Result<(), String> {
        DocsSettingsV1::from_source(source)?;
        if !source.audience.operator_declared {
            return Err(
                "a documents root has no provider audience: set audience.operator_declared to \
                 true to declare it visible to the whole project"
                    .to_owned(),
            );
        }
        if !source.audience.private_containers.is_empty() {
            return Err(
                "a documents root is one container and lists no private containers".to_owned(),
            );
        }
        Ok(())
    }

    fn pull(
        &self,
        source: &CollectorSourceV1,
    ) -> std::result::Result<Option<Box<dyn PullCollectorV1>>, String> {
        Ok(Some(Box::new(DocsPullV1 {
            settings: DocsSettingsV1::from_source(source)?,
        })))
    }
}

/// Whether `resolved` lies inside `root`, component by component: both are
/// canonical paths, so `/work/specs-old` is not inside `/work/specs`.
#[must_use]
pub fn within_root(root: &Path, resolved: &Path) -> bool {
    resolved.starts_with(root)
}

/// One document the listing found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedDocumentV1 {
    /// The external id: the relative path, `/`-separated, NFC.
    pub relative: String,
    /// Where to read it.
    pub path: PathBuf,
}

/// What one walk of the root found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DocsListingV1 {
    /// The documents, in walk order, at most `max_files`.
    pub documents: Vec<ListedDocumentV1>,
    /// The walk stopped at `max_files`.
    pub truncated: bool,
    /// Directories, entries, or names that could not be read.
    pub unreadable: u64,
    /// Symlinks not followed.
    pub symlinks_skipped: u64,
}

impl DocsListingV1 {
    /// Whether the walk saw every document under the root.
    #[must_use]
    pub const fn complete(&self) -> bool {
        !self.truncated && self.unreadable == 0
    }
}

/// Walk the root. See the module documentation.
///
/// # Errors
///
/// When the root itself cannot be resolved or is not a directory: a pass
/// that cannot see the root is a failure, never an empty listing that would
/// tombstone every document.
pub fn list_documents(settings: &DocsSettingsV1) -> std::io::Result<DocsListingV1> {
    let root = std::fs::canonicalize(&settings.root)?;
    if !std::fs::metadata(&root)?.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            "the documents root is not a directory",
        ));
    }
    let mut listing = DocsListingV1::default();
    let mut ids = BTreeSet::new();
    walk(&root, &root, "", settings, &mut listing, &mut ids);
    Ok(listing)
}

fn walk(
    root: &Path,
    directory: &Path,
    prefix: &str,
    settings: &DocsSettingsV1,
    listing: &mut DocsListingV1,
    ids: &mut BTreeSet<String>,
) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        listing.unreadable += 1;
        return;
    };
    let mut names = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => names.push((entry.file_name(), entry.path())),
            Err(_) => listing.unreadable += 1,
        }
    }
    names.sort();
    for (name, path) in names {
        if listing.truncated {
            return;
        }
        let Some(name) = name.to_str() else {
            // A name that is not UTF-8 can be no external id: a directory
            // so named, or a document, leaves the listing incomplete.
            let lossy = name.to_string_lossy();
            let directory = std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir());
            if !lossy.starts_with('.') && (directory || settings.lists(&lossy)) {
                listing.unreadable += 1;
            }
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            listing.unreadable += 1;
            continue;
        };
        let relative: String = if prefix.is_empty() {
            name.nfc().collect()
        } else {
            format!("{prefix}/{}", name.nfc().collect::<String>())
        };
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            walk(root, &path, &relative, settings, listing, ids);
            continue;
        }
        let target = if file_type.is_symlink() {
            match std::fs::canonicalize(&path) {
                Ok(target)
                    if within_root(root, &target)
                        && std::fs::metadata(&target).is_ok_and(|meta| meta.is_file()) =>
                {
                    target
                }
                _ => {
                    listing.symlinks_skipped += 1;
                    continue;
                }
            }
        } else if file_type.is_file() {
            path
        } else {
            continue;
        };
        if !settings.lists(name) {
            continue;
        }
        if !ids.insert(relative.clone()) {
            // Two names that normalize to one id: neither can be told apart.
            listing.unreadable += 1;
            continue;
        }
        if listing.documents.len() == settings.max_files {
            listing.truncated = true;
            return;
        }
        listing.documents.push(ListedDocumentV1 {
            relative,
            path: target,
        });
    }
}

/// What reading one document gave.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DocumentReadV1 {
    Text(String),
    /// Larger than the bound: the digest of the relative path and the bytes
    /// read.
    TooLarge(Sha256Digest),
    /// Not UTF-8: the digest of the relative path and the bytes.
    NotUtf8(Sha256Digest),
}

fn read_document(relative: &str, path: &Path, max_bytes: u64) -> std::io::Result<DocumentReadV1> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let digest = |bytes: &[u8]| framed_sha256("ostk-docs-file-v1", &[relative.as_bytes(), bytes]);
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Ok(DocumentReadV1::TooLarge(digest(&bytes)));
    }
    Ok(match String::from_utf8(bytes) {
        Ok(text) => DocumentReadV1::Text(text),
        Err(error) => DocumentReadV1::NotUtf8(digest(error.as_bytes())),
    })
}

/// The documents pull collector for one configured root.
#[derive(Debug, Clone)]
pub struct DocsPullV1 {
    settings: DocsSettingsV1,
}

impl DocsPullV1 {
    /// A collector over `settings`.
    #[must_use]
    pub const fn new(settings: DocsSettingsV1) -> Self {
        Self { settings }
    }
}

fn token<T>(parsed: crate::memory_contracts::ContractResult<T>) -> Result<T> {
    parsed.map_err(FleetError::from)
}

/// Everything one pass builds drafts with.
struct DocsPassV1<'a> {
    instance: &'a CollectorInstanceV1,
    provider: ProviderKindV1,
    object_kind: ObjectKindV1,
    container: DraftContainerV1,
    container_key: Sha256Digest,
    order: u64,
}

impl DocsPassV1<'_> {
    fn draft(
        &self,
        external_id: &str,
        lifecycle: ItemLifecycleV1,
        title: Option<String>,
        sections: Vec<DraftSectionV1>,
        text_format: TextFormatV1,
    ) -> CollectedItemDraftV1 {
        CollectedItemDraftV1 {
            provider: self.provider.clone(),
            provider_scope_id: self.instance.provider_scope_id.as_str().to_owned(),
            object_kind: self.object_kind.clone(),
            external_id: external_id.to_owned(),
            marker: None,
            order_micros: self.order,
            lifecycle,
            container: Some(self.container.clone()),
            thread: None,
            author: None,
            created_at: None,
            updated_at: None,
            title,
            sections,
            text_format,
            links: Vec::new(),
            provider_url: None,
            visibility: None,
        }
    }

    /// One document's draft: markdown by its headings, other text by its
    /// paragraphs, each section with its exact byte span.
    fn document(&self, relative: &str, text: &str) -> CollectedItemDraftV1 {
        let file_name = relative.rsplit('/').next().unwrap_or(relative).to_owned();
        let markdown = Path::new(relative)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                matches!(extension.to_ascii_lowercase().as_str(), "md" | "markdown")
            });
        let (title, sections, format) = if markdown {
            let outline = markdown::outline_markdown(text);
            (outline.title(), outline.sections, TextFormatV1::Markdown)
        } else {
            (None, markdown::outline_plain(text), TextFormatV1::Plain)
        };
        let sections = sections
            .into_iter()
            .map(|section| DraftSectionV1 {
                anchor: section.anchor,
                span: Some([
                    u64::try_from(section.start).unwrap_or(u64::MAX),
                    u64::try_from(section.end).unwrap_or(u64::MAX),
                ]),
                text: text[section.start..section.end].to_owned(),
            })
            .collect();
        self.draft(
            relative,
            ItemLifecycleV1::Live,
            Some(title.unwrap_or(file_name)),
            sections,
            format,
        )
    }

    fn tombstone(&self, relative: &str) -> PulledItemV1 {
        PulledItemV1 {
            draft: self.draft(
                relative,
                ItemLifecycleV1::Deleted,
                None,
                Vec::new(),
                TextFormatV1::Plain,
            ),
            provider_audience: Some(ProviderAudienceV1::OperatorScoped),
        }
    }
}

/// Stage `page` (and, the first time, the root's observation), leaving the
/// page empty.
async fn flush(
    stager: &mut PageStager<'_>,
    page: &mut Vec<PulledItemV1>,
    observation: &mut Option<ContainerObservationV1>,
) -> Result<()> {
    let observations: Vec<ContainerObservationV1> = observation.take().into_iter().collect();
    stager
        .stage_page(std::mem::take(page), &[], &observations)
        .await?;
    Ok(())
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[async_trait]
impl PullCollectorV1 for DocsPullV1 {
    fn counter_keys(&self) -> &'static [&'static str] {
        &DOCS_COUNTERS
    }

    fn proof_method(&self) -> CoverageProofMethodV1 {
        CoverageProofMethodV1::EnumeratedSnapshot
    }

    fn observation_audience(&self) -> ProviderAudienceV1 {
        ProviderAudienceV1::OperatorScoped
    }

    #[allow(clippy::too_many_lines)] // one linear list -> read -> compare -> stage -> tombstone pass
    async fn pass(
        &self,
        input: &PullPassInputV1<'_>,
        stager: &mut PageStager<'_>,
    ) -> Result<PullPassOutcomeV1> {
        let instance = input.instance;
        let kind = token(ContainerKindV1::new(DOCS_CONTAINER_KIND))?;
        let scope = instance.provider_scope_id.as_str();
        let label = self
            .settings
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned);
        let pass = DocsPassV1 {
            instance,
            provider: token(ProviderKindV1::new(DOCS_PROVIDER))?,
            object_kind: token(ObjectKindV1::new(DOCUMENT_OBJECT_KIND))?,
            container: DraftContainerV1 {
                kind: kind.clone(),
                id: scope.to_owned(),
                label: label.clone(),
            },
            container_key: stager.container_key(&kind, scope),
            order: input.pass_order_micros,
        };
        let root = Some(pass.container_key);
        let listing = {
            let settings = self.settings.clone();
            tokio::task::spawn_blocking(move || list_documents(&settings))
                .await
                .map_err(|_| FleetError::Memory("the documents listing did not finish".into()))?
                .map_err(|error| {
                    FleetError::Configuration(format!(
                        "documents root {} cannot be listed: {error}",
                        self.settings.root.display()
                    ))
                })?
        };
        let known: BTreeMap<String, KnownVersionV1> =
            stager.known_versions(&pass.object_kind).await?;
        let mut counters: BTreeMap<&'static str, u64> =
            DOCS_COUNTERS.iter().map(|key| (*key, 0)).collect();
        let mut bump = |key: &'static str| *counters.entry(key).or_insert(0) += 1;
        let mut observation = Some(ContainerObservationV1 {
            kind,
            id: scope.to_owned(),
            label,
            provider_audience: ProviderAudienceV1::OperatorScoped,
        });
        let mut page = Vec::with_capacity(PAGE_ITEMS);
        let mut listed = BTreeSet::new();
        for document in &listing.documents {
            listed.insert(document.relative.as_str());
            let read = {
                let (relative, path) = (document.relative.clone(), document.path.clone());
                let max = self.settings.max_file_bytes;
                tokio::task::spawn_blocking(move || read_document(&relative, &path, max))
                    .await
                    .map_err(|_| FleetError::Memory("a document read did not finish".into()))?
            };
            let known = known.get(&document.relative);
            let live = known.filter(|known| !known.lifecycle.is_tombstone());
            match read {
                Err(_) => {
                    // Listed but unreadable now (removed mid-pass, a
                    // permission): the root is partial, and the document is
                    // not tombstoned.
                    bump("files_unreadable");
                    stager.mark_partial(root, PartialReasonV1::Unreadable);
                }
                Ok(DocumentReadV1::TooLarge(digest)) => {
                    bump("files_dead_lettered");
                    stager
                        .dead_letter(
                            root,
                            DeadLetterReasonV1::Oversize,
                            digest,
                            "a document is larger than the root's max_file_bytes",
                        )
                        .await?;
                }
                Ok(DocumentReadV1::NotUtf8(digest)) => {
                    bump("files_dead_lettered");
                    stager
                        .dead_letter(
                            root,
                            DeadLetterReasonV1::ParseFailed,
                            digest,
                            "a document is not UTF-8",
                        )
                        .await?;
                }
                Ok(DocumentReadV1::Text(text)) if text.trim().is_empty() => {
                    if live.is_some() {
                        bump("files_deleted");
                        page.push(pass.tombstone(&document.relative));
                    } else {
                        bump("files_empty");
                    }
                }
                Ok(DocumentReadV1::Text(text)) => {
                    let draft = pass.document(&document.relative, &text);
                    if let Some(known) = live
                        && stager.content_digest(&draft) == Some(known.content_digest)
                    {
                        bump("files_unchanged");
                        stager.keep(root, known);
                        continue;
                    }
                    bump("files_staged");
                    page.push(PulledItemV1 {
                        draft,
                        provider_audience: Some(ProviderAudienceV1::OperatorScoped),
                    });
                }
            }
            if page.len() >= PAGE_ITEMS {
                flush(stager, &mut page, &mut observation).await?;
            }
        }
        if listing.complete() {
            for (relative, known) in &known {
                if listed.contains(relative.as_str()) || known.lifecycle.is_tombstone() {
                    continue;
                }
                bump("files_deleted");
                page.push(pass.tombstone(relative));
                if page.len() >= PAGE_ITEMS {
                    flush(stager, &mut page, &mut observation).await?;
                }
            }
        }
        if !page.is_empty() || observation.is_some() {
            flush(stager, &mut page, &mut observation).await?;
        }
        counters.insert("files_listed", count(listing.documents.len()));
        counters.insert("symlinks_skipped", listing.symlinks_skipped);
        counters.insert("listing_truncated", u64::from(listing.truncated));
        let bound = if listing.truncated {
            ListingBoundV1::Truncated(PartialReasonV1::ListingBound)
        } else if listing.unreadable > 0 {
            ListingBoundV1::Truncated(PartialReasonV1::Unreadable)
        } else {
            ListingBoundV1::Complete
        };
        Ok(PullPassOutcomeV1 {
            containers: vec![ContainerOutcomeV1 {
                ordinal: 0,
                container_key: root,
                listing: bound,
            }],
            reconcile: true,
            counters,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(root: &Path, max_files: usize) -> DocsSettingsV1 {
        DocsSettingsV1 {
            root: root.to_path_buf(),
            extensions: vec!["md".into(), "txt".into()],
            max_file_bytes: 1_024,
            max_files,
        }
    }

    fn relatives(listing: &DocsListingV1) -> Vec<&str> {
        listing
            .documents
            .iter()
            .map(|document| document.relative.as_str())
            .collect()
    }

    #[test]
    fn within_root_compares_whole_components() {
        let root = Path::new("/work/specs");
        assert!(within_root(root, Path::new("/work/specs/adr/0001.md")));
        assert!(within_root(root, Path::new("/work/specs")));
        assert!(!within_root(root, Path::new("/work/specs-old/0001.md")));
        assert!(!within_root(root, Path::new("/work/other/0001.md")));
        assert!(!within_root(root, Path::new("/work")));
    }

    #[test]
    fn the_listing_walks_in_name_order_and_never_follows_a_symlink_out_of_the_root() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.md"), "outside text").unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("adr")).unwrap();
        std::fs::write(root.path().join("adr/0002.md"), "two").unwrap();
        std::fs::write(root.path().join("adr/0001.md"), "one").unwrap();
        std::fs::write(root.path().join("b.txt"), "plain").unwrap();
        std::fs::write(root.path().join("image.png"), "not a document").unwrap();
        std::fs::write(root.path().join(".hidden.md"), "hidden").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.md"),
            root.path().join("escape.md"),
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape-dir")).unwrap();
        std::os::unix::fs::symlink(root.path().join("b.txt"), root.path().join("inside.txt"))
            .unwrap();
        std::os::unix::fs::symlink(root.path(), root.path().join("loop")).unwrap();

        let listing = list_documents(&settings(root.path(), 100)).unwrap();
        assert_eq!(
            relatives(&listing),
            ["adr/0001.md", "adr/0002.md", "b.txt", "inside.txt"]
        );
        assert_eq!(listing.symlinks_skipped, 3);
        assert!(listing.complete());
    }

    #[test]
    fn the_listing_stops_at_max_files_and_is_then_partial() {
        let root = tempfile::tempdir().unwrap();
        for name in ["a.md", "b.md", "c.md"] {
            std::fs::write(root.path().join(name), name).unwrap();
        }
        let listing = list_documents(&settings(root.path(), 2)).unwrap();
        assert_eq!(relatives(&listing), ["a.md", "b.md"]);
        assert!(listing.truncated);
        assert!(!listing.complete());
        let exact = list_documents(&settings(root.path(), 3)).unwrap();
        assert!(exact.complete());
    }

    #[test]
    fn a_missing_root_is_an_error_never_an_empty_listing() {
        let root = tempfile::tempdir().unwrap();
        let gone = root.path().join("missing");
        assert!(list_documents(&settings(&gone, 10)).is_err());
        let file = root.path().join("file.md");
        std::fs::write(&file, "x").unwrap();
        assert!(list_documents(&settings(&file, 10)).is_err());
    }

    #[test]
    fn a_read_tells_text_from_oversize_and_non_utf8() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("doc.md");
        std::fs::write(&path, "fine text").unwrap();
        assert_eq!(
            read_document("doc.md", &path, 100).unwrap(),
            DocumentReadV1::Text("fine text".into())
        );
        assert!(matches!(
            read_document("doc.md", &path, 4).unwrap(),
            DocumentReadV1::TooLarge(_)
        ));
        std::fs::write(&path, [0x66, 0xff, 0xfe]).unwrap();
        assert!(matches!(
            read_document("doc.md", &path, 100).unwrap(),
            DocumentReadV1::NotUtf8(_)
        ));
    }

    fn source(settings: &serde_json::Value, declared: bool) -> CollectorSourceV1 {
        serde_json::from_value(serde_json::json!({
            "provider": "docs",
            "connector_principal": "principal.docs",
            "connector_instance": "docs.specs",
            "provider_scope_id": "specs",
            "audience": {"operator_declared": declared},
            "settings": settings
        }))
        .unwrap()
    }

    #[test]
    fn settings_are_closed_and_bounded_and_the_root_must_be_declared() {
        let adapter = DocsAdapterV1;
        let good = serde_json::json!({
            "root": "/work/specs", "extensions": ["md"], "max_file_bytes": 1_048_576,
            "max_files": 5_000
        });
        adapter.validate(&source(&good, true)).unwrap();
        let defaults =
            DocsSettingsV1::from_source(&source(&serde_json::json!({"root": "/work/specs"}), true))
                .unwrap();
        assert_eq!(defaults.extensions, DOCS_EXTENSIONS);
        assert_eq!(defaults.max_file_bytes, DEFAULT_DOCS_MAX_FILE_BYTES);
        assert_eq!(defaults.max_files, DEFAULT_DOCS_MAX_FILES);

        let undeclared = adapter.validate(&source(&good, false)).unwrap_err();
        assert!(undeclared.contains("operator_declared"), "{undeclared}");
        for (bad, needle) in [
            (serde_json::json!({}), "root"),
            (serde_json::json!({"root": "/r", "follow": true}), "follow"),
            (
                serde_json::json!({"root": "/r", "extensions": ["pdf"]}),
                "pdf",
            ),
            (
                serde_json::json!({"root": "/r", "extensions": []}),
                "extensions",
            ),
            (
                serde_json::json!({"root": "/r", "extensions": ["md", "md"]}),
                "twice",
            ),
            (
                serde_json::json!({"root": "/r", "max_files": 0}),
                "max_files",
            ),
            (
                serde_json::json!({"root": "/r", "max_file_bytes": MAX_DOCS_MAX_FILE_BYTES + 1}),
                "max_file_bytes",
            ),
        ] {
            let message = adapter.validate(&source(&bad, true)).unwrap_err();
            assert!(message.contains(needle), "{bad}: {message}");
        }
    }

    #[test]
    fn a_markdown_document_is_anchored_sections_with_exact_spans() {
        let instance = CollectorInstanceV1 {
            connector_instance_id: crate::memory_contracts::common::ContractId::new("docs.specs")
                .unwrap(),
            provider: ProviderKindV1::new("docs").unwrap(),
            provider_scope_id: crate::memory_contracts::collected_item::BoundedTextV1::new("specs")
                .unwrap(),
        };
        let pass = DocsPassV1 {
            instance: &instance,
            provider: ProviderKindV1::new("docs").unwrap(),
            object_kind: ObjectKindV1::new(DOCUMENT_OBJECT_KIND).unwrap(),
            container: DraftContainerV1 {
                kind: ContainerKindV1::new(DOCS_CONTAINER_KIND).unwrap(),
                id: "specs".into(),
                label: None,
            },
            container_key: Sha256Digest::from_bytes([1; 32]),
            order: 1_790_000_000_000_000,
        };
        let text =
            "---\ntitle: Retry budgets\nstatus: draft\n---\n# Retry\nthree\n## Backoff\njitter\n";
        let draft = pass.document("adr/retry.md", text);
        assert_eq!(
            draft.title.as_deref(),
            Some("Retry budgets (status: draft)")
        );
        assert_eq!(draft.text_format, TextFormatV1::Markdown);
        assert_eq!(
            draft.marker, None,
            "the sink marks it o<pass>:sha256:<digest>"
        );
        let anchors: Vec<Option<&str>> = draft
            .sections
            .iter()
            .map(|section| section.anchor.as_deref())
            .collect();
        assert_eq!(anchors, [None, Some("Retry"), Some("Retry > Backoff")]);
        for section in &draft.sections {
            let [start, end] = section.span.unwrap();
            assert_eq!(
                &text[usize::try_from(start).unwrap()..usize::try_from(end).unwrap()],
                section.text
            );
        }
        let plain = pass.document("notes/todo.txt", "one\n\ntwo\n");
        assert_eq!(plain.title.as_deref(), Some("todo.txt"));
        assert_eq!(plain.text_format, TextFormatV1::Plain);
        let tombstone = pass.tombstone("adr/retry.md");
        assert_eq!(tombstone.draft.lifecycle, ItemLifecycleV1::Deleted);
        assert!(tombstone.draft.sections.is_empty());
    }
}
