//! Drafts, and sealing a draft into staged envelopes: the pure half of the sink.
//!
//! A collector produces a [`CollectedItemDraftV1`]: the envelope's shape with
//! raw provider text of any length. A draft exists only in memory and never
//! prints its text (its `Debug` shows lengths). [`seal`] is everything the sink
//! does to a draft before a byte is durable, in order:
//!
//! 1. **validate** the identity fields exactly (they are provider ids, so they
//!    are refused, never altered) and the lifecycle;
//! 2. **sanitize** every text field ([`sanitize_text`], [`sanitize_line`]);
//! 3. **redact** every text field with the [`CollectorRedactorV1`] (title,
//!    text, link targets and labels, the provider URL, the author's display
//!    name, the container label, the part anchors) and refuse an id that holds
//!    a secret shape, since an id cannot be redacted;
//! 4. **split** each section into parts of at most [`MAX_PART_TEXT_BYTES`], at
//!    a paragraph break, else a line break, else whitespace;
//! 5. **seal** one canonical [`CollectedItemEnvelopeV1`] per part and derive
//!    its staging id, the immutable revision.
//!
//! The audience is decided before sealing ([`super::audience::classify`]) and
//! handed in; sealing never widens it.
//!
//! A refusal ([`ItemRefusalV1`]) names a dead-letter reason and a static
//! diagnostic. It never carries provider text.

use std::collections::BTreeSet;
use std::ops::Range;

use crate::memory_contracts::collected_item::{
    AudienceBasisV1, AuthorKindV1, BoundedTextV1, COLLECTED_ITEM_SCHEMA_VERSION,
    CollectedItemEnvelopeV1, CollectedItemInputV1, CollectedScalarClassV1, CollectedTextV1,
    CollectedTitleV1, CollectionModeV1, ContainerKindV1, ItemAudienceV1, ItemAuthorV1,
    ItemCollectionV1, ItemContainerV1, ItemLifecycleV1, ItemLinkV1, ItemPartV1, ItemRedactionV1,
    ItemThreadV1, ItemVersionV1, LinkRelV1, MAX_ANCHOR_BYTES, MAX_EXTERNAL_ID_BYTES,
    MAX_LABEL_BYTES, MAX_LINK_TARGET_BYTES, MAX_LINKS, MAX_MARKER_BYTES, MAX_PART_TEXT_BYTES,
    MAX_PARTS, MAX_PROVIDER_URL_BYTES, MAX_SCOPE_ID_BYTES, MAX_TITLE_BYTES, ObjectKindV1,
    ProviderKindV1, RedactionClassLabelV1, TextFormatV1, VisibilityHintV1,
    classify_collected_scalar, default_version_marker, derive_container_key, derive_content_digest,
    derive_item_key, derive_version_key, provider_timestamp, timestamp_micros,
};
use crate::memory_contracts::common::CanonicalTimestamp;
use crate::memory_contracts::digest::Sha256Digest;

use super::redaction::{CollectorDispositionV1, CollectorRedactorV1};
use super::text::{sanitize_line, sanitize_text, truncate_on_char_boundary};

/// One section of a draft's text: a hard boundary no part crosses.
///
/// A plain item has one section. A document collector gives one section per
/// heading, with the heading path as its anchor and its raw-source byte span.
#[derive(Clone, PartialEq, Eq)]
pub struct DraftSectionV1 {
    /// Where in the source the section sits (a heading path).
    pub anchor: Option<String>,
    /// The half-open raw-source byte range the section came from.
    pub span: Option<[u64; 2]>,
    /// The raw section text.
    pub text: String,
}

impl DraftSectionV1 {
    /// One unanchored section.
    #[must_use]
    pub const fn whole(text: String) -> Self {
        Self {
            anchor: None,
            span: None,
            text,
        }
    }
}

/// A draft container.
#[derive(Clone, PartialEq, Eq)]
pub struct DraftContainerV1 {
    /// What kind of container.
    pub kind: ContainerKindV1,
    /// The provider-stable id.
    pub id: String,
    /// A display label.
    pub label: Option<String>,
}

/// A draft thread.
#[derive(Clone, PartialEq, Eq)]
pub struct DraftThreadV1 {
    /// External id of the thread root.
    pub root_external_id: String,
    /// External id of the item replied to.
    pub parent_external_id: Option<String>,
}

/// A draft author.
#[derive(Clone, PartialEq, Eq)]
pub struct DraftAuthorV1 {
    /// The provider-stable author id.
    pub id: String,
    /// A display name.
    pub display: Option<String>,
    /// What the provider says the author is.
    pub kind: AuthorKindV1,
}

/// A draft link.
#[derive(Clone, PartialEq, Eq)]
pub struct DraftLinkV1 {
    /// The relation.
    pub rel: LinkRelV1,
    /// The target.
    pub target: String,
    /// Display text.
    pub label: Option<String>,
}

/// One item as a collector read it: the envelope's shape, raw text of any
/// length, in memory only.
#[derive(Clone, PartialEq, Eq)]
pub struct CollectedItemDraftV1 {
    /// The provider kind.
    pub provider: ProviderKindV1,
    /// The provider scope id.
    pub provider_scope_id: String,
    /// The object kind.
    pub object_kind: ObjectKindV1,
    /// The provider-stable id.
    pub external_id: String,
    /// The provider's own version marker; `None` takes the default marker rule.
    pub marker: Option<String>,
    /// The provider's order for this version, in microseconds.
    pub order_micros: u64,
    /// The lifecycle state.
    pub lifecycle: ItemLifecycleV1,
    /// The container.
    pub container: Option<DraftContainerV1>,
    /// The thread.
    pub thread: Option<DraftThreadV1>,
    /// The author.
    pub author: Option<DraftAuthorV1>,
    /// When the provider says the item was created.
    pub created_at: Option<CanonicalTimestamp>,
    /// When the provider says this version was made.
    pub updated_at: Option<CanonicalTimestamp>,
    /// The raw title.
    pub title: Option<String>,
    /// The raw text, in sections.
    pub sections: Vec<DraftSectionV1>,
    /// How the text is formatted.
    pub text_format: TextFormatV1,
    /// Outbound links.
    pub links: Vec<DraftLinkV1>,
    /// The item's link at the provider.
    pub provider_url: Option<String>,
    /// A visibility hint from an importer or an agent; read by the audience
    /// decision, never sealed.
    pub visibility: Option<VisibilityHintV1>,
}

/// Lengths and identity only: a draft is provider content and is never logged.
impl std::fmt::Debug for CollectedItemDraftV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CollectedItemDraftV1")
            .field("provider", &self.provider.as_str())
            .field("object_kind", &self.object_kind.as_str())
            .field("lifecycle", &self.lifecycle.as_str())
            .field("order_micros", &self.order_micros)
            .field("sections", &self.sections.len())
            .field(
                "text_bytes",
                &self
                    .sections
                    .iter()
                    .map(|section| section.text.len())
                    .sum::<usize>(),
            )
            .field("links", &self.links.len())
            .finish_non_exhaustive()
    }
}

/// Why an item was not sealed. Carries a static diagnostic, never content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ItemRefusalV1 {
    /// The item breaks a rule of the envelope contract.
    #[error("validation failed: {0}")]
    Validation(&'static str),
    /// The item needs more than [`MAX_PARTS`] parts.
    #[error("the item needs {parts} parts; at most {MAX_PARTS} are admitted")]
    Oversize {
        /// Parts the item would need.
        parts: usize,
    },
    /// A secret shape remained after redaction, or sits in an id.
    #[error("redaction withheld the item: {class} in {field}")]
    RedactionWithheld {
        /// Which field.
        field: &'static str,
        /// The class that forced it.
        class: &'static str,
    },
}

impl ItemRefusalV1 {
    /// The dead-letter reason this refusal is recorded under.
    #[must_use]
    pub const fn dead_letter_reason(self) -> &'static str {
        match self {
            Self::Validation(_) => "validation_failed",
            Self::Oversize { .. } => "oversize",
            Self::RedactionWithheld { .. } => "redaction_withheld",
        }
    }
}

type SealResult<T> = Result<T, ItemRefusalV1>;

impl CollectedItemDraftV1 {
    /// Turn one plain-text input (a JSONL import line, an agent capture item)
    /// into a draft.
    ///
    /// Clocks are read in any RFC 3339 form and truncated to microseconds. The
    /// order is the explicit `version.order_micros`, else `updated_at`, else
    /// `created_at`; an input with none of them has no order and is refused.
    pub fn from_input(input: CollectedItemInputV1) -> SealResult<Self> {
        let created_at = input
            .created_at
            .as_deref()
            .map(provider_timestamp)
            .transpose()
            .map_err(|_| ItemRefusalV1::Validation("created_at is not an RFC 3339 timestamp"))?;
        let updated_at = input
            .updated_at
            .as_deref()
            .map(provider_timestamp)
            .transpose()
            .map_err(|_| ItemRefusalV1::Validation("updated_at is not an RFC 3339 timestamp"))?;
        let explicit_order = input
            .version
            .as_ref()
            .and_then(|version| version.order_micros);
        let order_micros = if let Some(order) = explicit_order {
            order
        } else {
            let clock = updated_at.as_ref().or(created_at.as_ref()).ok_or(
                ItemRefusalV1::Validation(
                    "an item needs version.order_micros, updated_at, or created_at to be ordered",
                ),
            )?;
            timestamp_micros(clock)
                .map_err(|_| ItemRefusalV1::Validation("a provider clock has no order"))?
        };
        Ok(Self {
            provider: input.provider,
            provider_scope_id: input.provider_scope_id,
            object_kind: input.object_kind,
            external_id: input.external_id,
            marker: input.version.and_then(|version| version.marker),
            order_micros,
            lifecycle: input.lifecycle.unwrap_or(ItemLifecycleV1::Live),
            container: input.container.map(|container| DraftContainerV1 {
                kind: container.kind,
                id: container.id,
                label: container.label,
            }),
            thread: input.thread.map(|thread| DraftThreadV1 {
                root_external_id: thread.root_external_id,
                parent_external_id: thread.parent_external_id,
            }),
            author: input.author.map(|author| DraftAuthorV1 {
                id: author.id,
                display: author.display,
                kind: author.kind.unwrap_or(AuthorKindV1::Unknown),
            }),
            created_at,
            updated_at,
            title: input.title,
            sections: vec![DraftSectionV1::whole(input.text)],
            text_format: input.text_format.unwrap_or(TextFormatV1::Plain),
            links: input
                .links
                .into_iter()
                .map(|link| DraftLinkV1 {
                    rel: link.rel,
                    target: link.target,
                    label: link.label,
                })
                .collect(),
            provider_url: input.url,
            visibility: input.visibility,
        })
    }

    /// The container id, for the audience decision.
    #[must_use]
    pub fn container_id(&self) -> Option<&str> {
        self.container
            .as_ref()
            .map(|container| container.id.as_str())
    }
}

/// Split `text` into consecutive byte ranges of at most `max` bytes that
/// concatenate back to `text`.
///
/// Each cut falls after the last paragraph break (`\n\n`) inside the limit,
/// else after the last line break, else after the last whitespace scalar, else
/// on the last `char` boundary. Transcript segments are lines, so a transcript
/// splits at segment boundaries. An empty text is one empty range.
#[must_use]
pub fn split_text(text: &str, max: usize) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = 0_usize;
    while text.len() - start > max {
        let mut limit = start + max;
        while limit > start && !text.is_char_boundary(limit) {
            limit -= 1;
        }
        if limit == start {
            // A bound smaller than one scalar: take that scalar whole rather
            // than loop forever.
            limit = start + text[start..].chars().next().map_or(1, char::len_utf8);
        }
        let window = &text[start..limit];
        let cut = window
            .rfind("\n\n")
            .map(|index| index + 2)
            .or_else(|| window.rfind('\n').map(|index| index + 1))
            .or_else(|| {
                window
                    .char_indices()
                    .rev()
                    .find(|(_, scalar)| scalar.is_whitespace())
                    .map(|(index, scalar)| index + scalar.len_utf8())
            })
            .filter(|cut| *cut > 0)
            .unwrap_or(window.len());
        ranges.push(start..start + cut);
        start += cut;
    }
    if start < text.len() || ranges.is_empty() {
        ranges.push(start..text.len());
    }
    ranges
}

/// What the sink supplies to seal a draft.
#[derive(Debug, Clone, Copy)]
pub struct SealContextV1<'a> {
    /// The redactor, under the active package's guarantee.
    pub redactor: &'a CollectorRedactorV1,
    /// The audience basis [`super::audience::classify`] admitted the item on.
    pub audience: AudienceBasisV1,
    /// The channel, instance, and (for a capture) attester and tool label.
    pub collection: &'a ItemCollectionV1,
}

/// One sealed part: an envelope, its exact canonical bytes, and its staging id.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedPartV1 {
    /// `immutable_revision`, the outbox primary key.
    pub stage_id: Sha256Digest,
    /// The envelope.
    pub envelope: CollectedItemEnvelopeV1,
    /// Its canonical bytes: the governed payload.
    pub canonical_envelope: Vec<u8>,
}

/// Identity only: the envelope is provider content.
impl std::fmt::Debug for SealedPartV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SealedPartV1")
            .field("stage_id", &self.stage_id)
            .field("ordinal", &self.envelope.part.ordinal)
            .field("envelope_bytes", &self.canonical_envelope.len())
            .finish()
    }
}

/// One item version, sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedItemV1 {
    /// The item key.
    pub item_key: Sha256Digest,
    /// The version key.
    pub version_key: Sha256Digest,
    /// The content digest over the title and every part's text.
    pub content_digest: Sha256Digest,
    /// The container key, when the item has a container.
    pub container_key: Option<Sha256Digest>,
    /// The version's provider order.
    pub provider_order: u64,
    /// What sanitizing and redacting did.
    pub redaction: ItemRedactionV1,
    /// Every part, in order.
    pub parts: Vec<SealedPartV1>,
}

impl SealedItemV1 {
    /// Every staging id, in part order.
    #[must_use]
    pub fn stage_ids(&self) -> Vec<Sha256Digest> {
        self.parts.iter().map(|part| part.stage_id).collect()
    }
}

/// Sanitize, redact, split, and seal one draft.
pub fn seal(draft: &CollectedItemDraftV1, context: &SealContextV1<'_>) -> SealResult<SealedItemV1> {
    require_clocks(draft)?;
    let mut sealer = Sealer::new(context.redactor);
    let fields = SealedFieldsV1::from_draft(draft, context, &mut sealer)?;
    let (pieces, whole_text) = split_sections(&fields.sections, draft.lifecycle.is_tombstone())?;
    let count = u32::try_from(pieces.len())
        .ok()
        .filter(|count| *count <= MAX_PARTS)
        .ok_or(ItemRefusalV1::Oversize {
            parts: pieces.len(),
        })?;

    let content_digest = derive_content_digest(
        fields.title.as_ref().map(CollectedTextV1::as_str),
        &whole_text,
    );
    let marker = match fields.marker.clone() {
        Some(marker) => marker,
        None => BoundedTextV1::new(default_version_marker(draft.order_micros, &content_digest))
            .map_err(|_| ItemRefusalV1::Validation("the default version marker is not bounded"))?,
    };
    let item_key = derive_item_key(
        &draft.provider,
        fields.scope.as_str(),
        &draft.object_kind,
        fields.external_id.as_str(),
    );
    let version_key =
        derive_version_key(&item_key, marker.as_str(), draft.lifecycle, &content_digest);
    let container_key = fields.container.as_ref().map(|container| {
        derive_container_key(
            &draft.provider,
            fields.scope.as_str(),
            &container.kind,
            container.id.as_str(),
        )
    });
    let redaction = sealer.into_redaction()?;

    let mut parts = Vec::with_capacity(pieces.len());
    for (ordinal, piece) in (0_u32..).zip(pieces) {
        let envelope = CollectedItemEnvelopeV1 {
            schema_version: COLLECTED_ITEM_SCHEMA_VERSION,
            provider: draft.provider.clone(),
            provider_scope_id: fields.scope.clone(),
            object_kind: draft.object_kind.clone(),
            external_id: fields.external_id.clone(),
            version: ItemVersionV1 {
                marker: marker.clone(),
                order_micros: draft.order_micros,
            },
            lifecycle: draft.lifecycle,
            part: ItemPartV1 {
                ordinal,
                count,
                anchor: piece.anchor,
                span: piece.span,
            },
            container: fields.container.clone(),
            thread: fields.thread.clone(),
            author: fields.author.clone(),
            created_at: draft.created_at.clone(),
            updated_at: draft.updated_at.clone(),
            title: fields.title.clone(),
            text: CollectedTextV1::new(piece.text)
                .map_err(|_| ItemRefusalV1::Validation("a part is not sanitized text"))?,
            text_format: draft.text_format,
            content_digest,
            links: fields.links.clone(),
            provider_url: fields.provider_url.clone(),
            audience: ItemAudienceV1 {
                basis: context.audience,
                container_key,
            },
            redaction: redaction.clone(),
            collection: context.collection.clone(),
        };
        let canonical_envelope = envelope.canonical_bytes().map_err(|_| {
            ItemRefusalV1::Validation("the envelope failed the collected-item contract")
        })?;
        parts.push(SealedPartV1 {
            stage_id: envelope.immutable_revision(),
            envelope,
            canonical_envelope,
        });
    }
    Ok(SealedItemV1 {
        item_key,
        version_key,
        content_digest,
        container_key,
        provider_order: draft.order_micros,
        redaction,
        parts,
    })
}

/// Every field of a draft, sanitized, redacted, and bounded.
struct SealedFieldsV1 {
    scope: BoundedTextV1<MAX_SCOPE_ID_BYTES>,
    external_id: BoundedTextV1<MAX_EXTERNAL_ID_BYTES>,
    marker: Option<BoundedTextV1<MAX_MARKER_BYTES>>,
    title: Option<CollectedTitleV1>,
    sections: Vec<SealedSectionV1>,
    links: Vec<ItemLinkV1>,
    container: Option<ItemContainerV1>,
    thread: Option<ItemThreadV1>,
    author: Option<ItemAuthorV1>,
    provider_url: Option<BoundedTextV1<MAX_PROVIDER_URL_BYTES>>,
}

impl SealedFieldsV1 {
    fn from_draft(
        draft: &CollectedItemDraftV1,
        context: &SealContextV1<'_>,
        sealer: &mut Sealer<'_>,
    ) -> SealResult<Self> {
        let scope =
            sealer.exact::<MAX_SCOPE_ID_BYTES>("provider_scope_id", &draft.provider_scope_id)?;
        let external_id =
            sealer.exact::<MAX_EXTERNAL_ID_BYTES>("external_id", &draft.external_id)?;
        let marker = draft
            .marker
            .as_deref()
            .map(|marker| sealer.exact::<MAX_MARKER_BYTES>("version.marker", marker))
            .transpose()?;
        if let Some(via) = &context.collection.via {
            sealer.exact::<MAX_LABEL_BYTES>("collection.via", via.as_str())?;
        }
        // A tombstone is metadata only: the text, title, and links a deleted
        // item last had are never staged, whatever the collector passed along.
        let tombstone = draft.lifecycle.is_tombstone();
        let (title, sections, links) = if tombstone {
            (None, Vec::new(), Vec::new())
        } else {
            let title = sealer
                .display::<MAX_TITLE_BYTES>("title", draft.title.as_deref())?
                .map(|title| CollectedTextV1::new(title.as_str()))
                .transpose()
                .map_err(|_| ItemRefusalV1::Validation("the title is not sanitized text"))?;
            (
                title,
                sealer.sections(&draft.sections)?,
                sealer.links(&draft.links)?,
            )
        };
        Ok(Self {
            scope,
            external_id,
            marker,
            title,
            sections,
            links,
            container: draft
                .container
                .as_ref()
                .map(|container| sealer.container(container))
                .transpose()?,
            thread: draft
                .thread
                .as_ref()
                .map(|thread| sealer.thread(thread))
                .transpose()?,
            author: draft
                .author
                .as_ref()
                .map(|author| sealer.author(author))
                .transpose()?,
            provider_url: draft
                .provider_url
                .as_deref()
                .map(|url| sealer.provider_url(url))
                .transpose()?,
        })
    }
}

/// One part's worth of sealed text, before it becomes an envelope.
struct PieceV1 {
    anchor: Option<BoundedTextV1<MAX_ANCHOR_BYTES>>,
    span: Option<[u64; 2]>,
    text: String,
}

/// Split every section into parts; an empty section is no part, and only a
/// tombstone may have none. Returns the parts and the whole item text they
/// concatenate to.
fn split_sections(
    sections: &[SealedSectionV1],
    tombstone: bool,
) -> SealResult<(Vec<PieceV1>, String)> {
    let mut pieces = Vec::new();
    let mut whole_text = String::new();
    for section in sections {
        whole_text.push_str(&section.text);
        if section.text.is_empty() {
            continue;
        }
        for range in split_text(&section.text, MAX_PART_TEXT_BYTES) {
            pieces.push(PieceV1 {
                anchor: section.anchor.clone(),
                span: section.span,
                text: section.text[range].to_owned(),
            });
        }
    }
    if pieces.is_empty() {
        if !tombstone {
            return Err(ItemRefusalV1::Validation(
                "only a tombstone may have empty text",
            ));
        }
        pieces.push(PieceV1 {
            anchor: None,
            span: None,
            text: String::new(),
        });
    }
    Ok((pieces, whole_text))
}

/// Provider clocks must survive the database's microsecond precision, and an
/// item cannot be updated before it was created.
fn require_clocks(draft: &CollectedItemDraftV1) -> SealResult<()> {
    for clock in [&draft.created_at, &draft.updated_at].into_iter().flatten() {
        if !clock.is_microsecond_aligned() {
            return Err(ItemRefusalV1::Validation(
                "provider clocks must be microsecond aligned",
            ));
        }
    }
    if let (Some(created), Some(updated)) = (&draft.created_at, &draft.updated_at)
        && updated < created
    {
        return Err(ItemRefusalV1::Validation(
            "an item cannot be updated before it was created",
        ));
    }
    if draft.order_micros > crate::memory_contracts::canonical::MAX_SAFE_INTEGER.unsigned_abs() {
        return Err(ItemRefusalV1::Validation(
            "the version order is outside the safe integer range",
        ));
    }
    Ok(())
}

/// One sealed section: sanitized, redacted text with its anchor and span.
struct SealedSectionV1 {
    anchor: Option<BoundedTextV1<MAX_ANCHOR_BYTES>>,
    span: Option<[u64; 2]>,
    text: String,
}

/// Runs every field through sanitize and redact, and tallies what they did.
struct Sealer<'a> {
    redactor: &'a CollectorRedactorV1,
    hidden_scalars_removed: u32,
    replaced_scalars: u32,
    redacted_ranges: u32,
    classes: BTreeSet<&'static str>,
}

impl<'a> Sealer<'a> {
    const fn new(redactor: &'a CollectorRedactorV1) -> Self {
        Self {
            redactor,
            hidden_scalars_removed: 0,
            replaced_scalars: 0,
            redacted_ranges: 0,
            classes: BTreeSet::new(),
        }
    }

    /// Redact one already-sanitized text, or refuse the item.
    fn redact(&mut self, field: &'static str, sanitized: &str) -> SealResult<String> {
        let outcome = self.redactor.redact(sanitized);
        self.redacted_ranges = self.redacted_ranges.saturating_add(outcome.redacted_ranges);
        self.classes
            .extend(outcome.classes.iter().map(|class| class.as_str()));
        match outcome.disposition {
            CollectorDispositionV1::Stage { text } => Ok(text),
            CollectorDispositionV1::Withhold { class } => Err(ItemRefusalV1::RedactionWithheld {
                field,
                class: class.as_str(),
            }),
        }
    }

    const fn tally(&mut self, hidden: u32, replaced: u32) {
        self.hidden_scalars_removed = self.hidden_scalars_removed.saturating_add(hidden);
        self.replaced_scalars = self.replaced_scalars.saturating_add(replaced);
    }

    /// A multi-line text: sanitize, then redact.
    fn text(&mut self, field: &'static str, raw: &str) -> SealResult<String> {
        let sanitized = sanitize_text(raw);
        self.tally(sanitized.hidden_scalars_removed, sanitized.replaced_scalars);
        self.redact(field, &sanitized.text)
    }

    /// A single line: sanitize as a line, then redact.
    fn line(&mut self, field: &'static str, raw: &str) -> SealResult<String> {
        let sanitized = sanitize_line(raw);
        self.tally(sanitized.hidden_scalars_removed, sanitized.replaced_scalars);
        self.redact(field, &sanitized.text)
    }

    /// A display string: a line, shortened to its bound on a char boundary,
    /// and dropped when nothing is left.
    fn display<const MAX: usize>(
        &mut self,
        field: &'static str,
        raw: Option<&str>,
    ) -> SealResult<Option<BoundedTextV1<MAX>>> {
        let Some(raw) = raw else {
            return Ok(None);
        };
        let line = truncate_on_char_boundary(self.line(field, raw)?, MAX);
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            return Ok(None);
        }
        // Shortening a clean string can complete a shape whose end depends on
        // what follows it (a key id is exactly so many scalars, then a
        // boundary), so the shortened form is scanned again.
        if let Some(finding) = self.redactor.scan(trimmed).first() {
            return Err(ItemRefusalV1::RedactionWithheld {
                field,
                class: finding.class.as_str(),
            });
        }
        BoundedTextV1::new(trimmed)
            .map(Some)
            .map_err(|_| ItemRefusalV1::Validation("a display string is not a bounded line"))
    }

    /// An exact provider id: refused when it is not a bounded canonical line,
    /// when it holds a hidden scalar (a TAG-block, bidi, or zero-width
    /// character the sanitizer would strip from text), and when it holds a
    /// secret shape, since an id can be neither altered nor redacted.
    fn exact<const MAX: usize>(
        &self,
        field: &'static str,
        raw: &str,
    ) -> SealResult<BoundedTextV1<MAX>> {
        if has_hidden_scalar(raw) {
            return Err(ItemRefusalV1::Validation(
                "an id or marker holds a hidden scalar",
            ));
        }
        let value = BoundedTextV1::new(raw)
            .map_err(|_| ItemRefusalV1::Validation("an id or marker is not a bounded NFC line"))?;
        if let Some(finding) = self.redactor.scan(raw).first() {
            return Err(ItemRefusalV1::RedactionWithheld {
                field,
                class: finding.class.as_str(),
            });
        }
        Ok(value)
    }

    /// A link target or URL: a line, redacted, refused when over its bound.
    fn target<const MAX: usize>(
        &mut self,
        field: &'static str,
        raw: &str,
    ) -> SealResult<BoundedTextV1<MAX>> {
        let line = self.line(field, raw)?;
        BoundedTextV1::new(line).map_err(|_| {
            ItemRefusalV1::Validation("a link target or url is empty or over its bound")
        })
    }

    fn sections(&mut self, sections: &[DraftSectionV1]) -> SealResult<Vec<SealedSectionV1>> {
        sections
            .iter()
            .map(|section| {
                if let Some([start, end]) = section.span
                    && start > end
                {
                    return Err(ItemRefusalV1::Validation("a section span is not ordered"));
                }
                Ok(SealedSectionV1 {
                    anchor: self
                        .display::<MAX_ANCHOR_BYTES>("part.anchor", section.anchor.as_deref())?,
                    span: section.span,
                    text: self.text("text", &section.text)?,
                })
            })
            .collect()
    }

    fn links(&mut self, links: &[DraftLinkV1]) -> SealResult<Vec<ItemLinkV1>> {
        if links.len() > MAX_LINKS {
            return Err(ItemRefusalV1::Validation(
                "an item carries at most 64 links",
            ));
        }
        links
            .iter()
            .map(|link| {
                Ok(ItemLinkV1 {
                    rel: link.rel.clone(),
                    target: self.target::<MAX_LINK_TARGET_BYTES>("links.target", &link.target)?,
                    label: self.display::<MAX_LABEL_BYTES>("links.label", link.label.as_deref())?,
                })
            })
            .collect()
    }

    fn container(&mut self, container: &DraftContainerV1) -> SealResult<ItemContainerV1> {
        Ok(ItemContainerV1 {
            kind: container.kind.clone(),
            id: self.exact::<MAX_LABEL_BYTES>("container.id", &container.id)?,
            label: self
                .display::<MAX_LABEL_BYTES>("container.label", container.label.as_deref())?,
        })
    }

    fn thread(&self, thread: &DraftThreadV1) -> SealResult<ItemThreadV1> {
        Ok(ItemThreadV1 {
            root_external_id: self.exact::<MAX_EXTERNAL_ID_BYTES>(
                "thread.root_external_id",
                &thread.root_external_id,
            )?,
            parent_external_id: thread
                .parent_external_id
                .as_deref()
                .map(|parent| {
                    self.exact::<MAX_EXTERNAL_ID_BYTES>("thread.parent_external_id", parent)
                })
                .transpose()?,
        })
    }

    fn author(&mut self, author: &DraftAuthorV1) -> SealResult<ItemAuthorV1> {
        Ok(ItemAuthorV1 {
            id: self.exact::<MAX_LABEL_BYTES>("author.id", &author.id)?,
            display: self
                .display::<MAX_LABEL_BYTES>("author.display", author.display.as_deref())?,
            kind: author.kind,
        })
    }

    fn provider_url(&mut self, url: &str) -> SealResult<BoundedTextV1<MAX_PROVIDER_URL_BYTES>> {
        let url = self.target::<MAX_PROVIDER_URL_BYTES>("provider_url", url)?;
        if !url.as_str().starts_with("https://") {
            return Err(ItemRefusalV1::Validation("a provider url must be https"));
        }
        Ok(url)
    }

    fn into_redaction(self) -> SealResult<ItemRedactionV1> {
        let classes = self
            .classes
            .into_iter()
            .map(RedactionClassLabelV1::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ItemRefusalV1::Validation("a redaction class label is not a token"))?;
        Ok(ItemRedactionV1 {
            profile_version: self.redactor.profile_version(),
            redacted_ranges: self.redacted_ranges,
            classes,
            hidden_scalars_removed: self.hidden_scalars_removed,
            replaced_scalars: self.replaced_scalars,
        })
    }
}

/// Whether `value` holds a scalar the sanitizer strips as hidden: invisible
/// text that would make an id read differently from what it is, or hide a
/// secret shape from the scan.
#[must_use]
pub fn has_hidden_scalar(value: &str) -> bool {
    value
        .chars()
        .any(|scalar| classify_collected_scalar(scalar) == CollectedScalarClassV1::Hidden)
}

/// The collection record a sink hands to [`seal`] for one channel.
///
/// `attester` is required for a capture and refused otherwise, exactly as the
/// envelope contract checks, so a sink cannot build a context that seals
/// nothing.
pub fn collection_record(
    mode: CollectionModeV1,
    collector_instance: crate::memory_contracts::common::ContractId,
    attester: Option<crate::memory_contracts::common::ContractId>,
    via: Option<&str>,
) -> SealResult<ItemCollectionV1> {
    if attester.is_some() != (mode == CollectionModeV1::Capture) {
        return Err(ItemRefusalV1::Validation(
            "an attester is recorded exactly for a capture",
        ));
    }
    if via.is_some() && mode != CollectionModeV1::Capture {
        return Err(ItemRefusalV1::Validation(
            "only a capture records the tool it came through",
        ));
    }
    let via = via
        .map(|via| {
            let line = truncate_on_char_boundary(sanitize_line(via).text, MAX_LABEL_BYTES);
            BoundedTextV1::new(line.trim_end())
                .map_err(|_| ItemRefusalV1::Validation("the tool label is not a bounded line"))
        })
        .transpose()?;
    Ok(ItemCollectionV1 {
        mode,
        collector_instance,
        attester,
        via,
    })
}

#[cfg(test)]
#[path = "draft_tests.rs"]
mod tests;
