//! The collected-item envelope (ADR 0008): one normalized shape for anything a
//! collector reads, whatever the provider.
//!
//! A Slack message, a Linear issue or comment, a Granola note, a document from
//! a directory, and an item an agent relays from its own connectors all become
//! the same [`CollectedItemEnvelopeV1`]. The envelope is canonical JSON under
//! the frozen profile, and its exact bytes are the governed payload the
//! `connector.collected.*` connectors admit, so one admission path, one body
//! projection, and one lexical rendering serve every provider.
//!
//! # What is in the envelope, and what is not
//!
//! * **No scope.** The tenant and project come from the writer credential at
//!   admission, never from a payload (EVID-04).
//! * **Text is hex.** The canonical profile admits no control scalar in a
//!   string, and provider text has newlines. `title` and `text` therefore carry
//!   the lowercase hex of the exact redacted, sanitized UTF-8, exactly as the
//!   git connector carries a commit message. A canonical envelope consequently
//!   holds no raw newline, so the body projector's reference parser yields
//!   exactly one body per envelope and `body_content_id = body_digest(envelope)`.
//! * **Nothing volatile.** Reactions, reply counts, unfurls, presence, read
//!   state, and any provider token never enter an envelope, so re-reading an
//!   unchanged item reproduces it byte for byte.
//!
//! # Identity for mutable items
//!
//! A provider item changes: a message is edited, an issue is updated, a
//! document is rewritten. The identity algebra keeps the generation-2 pattern:
//! every PART of every VERSION of an item, read through one channel, is one
//! immutable revision with its own content-addressed URI, and continuity across
//! versions comes from [`derive_item_key`] plus the current-view heads.
//!
//! | Digest | Preimage (length-framed) |
//! |---|---|
//! | `item_key` | provider, provider scope id, object kind, external id |
//! | content digest | title presence, title, text (the whole item, or one part) |
//! | `version_key` | item key, version marker, lifecycle, content digest |
//! | `immutable_revision` | 1, version key, collection mode, attester, part ordinal, part count, part digest |
//! | `container_key` | provider, provider scope id, container kind, container id |
//!
//! Mutable labels (a channel name, `ENG-412`, a document title's display form)
//! sit outside every digest, so renaming one mints nothing. The collection mode
//! and, for a capture, the attesting principal are inside the revision, so a
//! capture and a pull of the same message, or two agents' captures of it, are
//! separate source facts rather than one collapsing onto the other.
//!
//! **Marker rule.** A version marker is the provider's own when it has one
//! (Slack `edited.ts` or `ts`, Linear `updatedAt`, Granola `updated_at`).
//! Otherwise it is [`default_version_marker`], `o<order_micros>:sha256:<content
//! digest>`, taken when that content was first observed, so reverting content
//! from A to B and back to A mints a third version rather than a primary-key
//! no-op.
//!
//! [`CollectedItemInputV1`] is the plain-text, human- and agent-writable form a
//! JSONL import line or an agent capture carries. It is never staged as is:
//! collectors turn it into a draft that is sanitized, redacted, and split
//! before any envelope exists.

use std::fmt;

use chrono::{DateTime, SubsecRound as _, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use unicode_normalization::is_nfc;

use super::{
    ContractError, ContractResult,
    canonical::{MAX_SAFE_INTEGER, decode_typed_canonical, encode_canonical, is_forbidden_scalar},
    common::{CanonicalTimestamp, ContractId},
    digest::{DigestDomain, Sha256Digest, framed_digest},
    generation3_registry::COLLECTED_ITEM_FAMILY,
};

/// Media type every collected-item body asserts, and the one the lexical
/// projector renders text-first.
pub const COLLECTED_ITEM_MEDIA_TYPE: &str = "application.ostk-collected-item-v1";
/// `schema_version` of [`CollectedItemEnvelopeV1`] and the revision preimage.
pub const COLLECTED_ITEM_SCHEMA_VERSION: u32 = 1;
/// Largest part text, in raw UTF-8 bytes: its hex is exactly the canonical
/// profile's largest string.
pub const MAX_PART_TEXT_BYTES: usize = 32_768;
/// Largest title, in raw UTF-8 bytes.
pub const MAX_TITLE_BYTES: usize = 4_096;
/// Most parts one item version may be split into.
pub const MAX_PARTS: u32 = 64;
/// Most links one envelope carries.
pub const MAX_LINKS: usize = 64;
/// Most redaction class labels one envelope records.
pub const MAX_REDACTION_CLASSES: usize = 64;
/// Largest provider scope id (an operator pin).
pub const MAX_SCOPE_ID_BYTES: usize = 256;
/// Largest provider-stable external id.
pub const MAX_EXTERNAL_ID_BYTES: usize = 1_024;
/// Largest version marker.
pub const MAX_MARKER_BYTES: usize = 256;
/// Largest single-line label: a container label, an author id or display
/// name, a container id, a link label, an agent tool label.
pub const MAX_LABEL_BYTES: usize = 256;
/// Largest part anchor (a heading path).
pub const MAX_ANCHOR_BYTES: usize = 1_024;
/// Largest link target.
pub const MAX_LINK_TARGET_BYTES: usize = 2_048;
/// Largest display URL.
pub const MAX_PROVIDER_URL_BYTES: usize = 2_048;

// ---------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------

fn schema(message: impl Into<String>) -> ContractError {
    ContractError::Schema(message.into())
}

/// Whether `value` is a lowercase token: a first byte in `a-z`, then `a-z`,
/// `0-9`, and the punctuation `extra` allows, at most `max` bytes in all.
fn is_token(value: &str, max: usize, extra: &[u8]) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= max
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || extra.contains(byte))
}

macro_rules! token_type {
    ($(#[$meta:meta])* $name:ident, $max:expr, $extra:expr, $label:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validate one token.
            pub fn new(value: impl Into<String>) -> ContractResult<Self> {
                let value = value.into();
                if !is_token(&value, $max, $extra) {
                    return Err(schema(concat!("invalid ", $label)));
                }
                Ok(Self(value))
            }

            /// The token.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = ContractError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

token_type!(
    /// A provider kind, `^[a-z][a-z0-9_-]{0,31}$`: `docs`, `slack`, `linear`,
    /// `granola`, `notion`, and any later one. The provider is data, never a
    /// registry entry (ADR 0008 D1).
    ProviderKindV1,
    32,
    b"_-",
    "provider kind"
);
token_type!(
    /// An object kind, `^[a-z][a-z0-9_.-]{0,63}$`: `message`, `issue`,
    /// `comment`, `note_summary`, `transcript`, `document`,
    /// `collector_observation`.
    ObjectKindV1,
    64,
    b"_.-",
    "object kind"
);
token_type!(
    /// A container kind, with the object-kind syntax: `slack.channel`,
    /// `linear.team`, `granola.folder`, `docs.root`.
    ContainerKindV1,
    64,
    b"_.-",
    "container kind"
);
token_type!(
    /// A link relation, with the object-kind syntax: `url`, `project`,
    /// `relative`, `file`, `calendar_event`.
    LinkRelV1,
    64,
    b"_.-",
    "link relation"
);
token_type!(
    /// One redaction class label an envelope records (metadata only, never
    /// matched bytes): `aws_access_key_id`, `slack_token`, ...
    RedactionClassLabelV1,
    64,
    b"_",
    "redaction class label"
);

/// Whether one string is canonical single-line text: NFC, and free of every
/// scalar the canonical profile refuses (controls included).
fn is_canonical_line(value: &str) -> bool {
    is_nfc(value) && !value.chars().any(is_forbidden_scalar)
}

/// A non-empty, single-line, NFC string of at most `MAX` bytes: an id, a
/// label, a marker, a URL.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BoundedTextV1<const MAX: usize = MAX_LABEL_BYTES>(String);

impl<const MAX: usize> BoundedTextV1<MAX> {
    /// Validate one bounded string. It is refused, never truncated: a caller
    /// that may shorten a display string does so before building one.
    pub fn new(value: impl Into<String>) -> ContractResult<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX {
            return Err(schema(format!(
                "bounded text must be 1 to {MAX} bytes, got {}",
                value.len()
            )));
        }
        if !is_canonical_line(&value) {
            return Err(schema(
                "bounded text must be NFC with no control, noncharacter, or private-use scalar",
            ));
        }
        Ok(Self(value))
    }

    /// The string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const MAX: usize> TryFrom<String> for BoundedTextV1<MAX> {
    type Error = ContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<const MAX: usize> From<BoundedTextV1<MAX>> for String {
    fn from(value: BoundedTextV1<MAX>) -> Self {
        value.0
    }
}

impl<const MAX: usize> fmt::Display for BoundedTextV1<MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// How one scalar of collected text is treated by the sanitizer, and which
/// forms a sanitized text may contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectedScalarClassV1 {
    /// Kept as is.
    Keep,
    /// `\n` or `\t`: kept, the only controls collected text keeps.
    KeptControl,
    /// `\r`: a line ending, folded to `\n`.
    CarriageReturn,
    /// Invisible and removed: the TAG block (U+E0000 to U+E007F), the
    /// `Bidi_Control` scalars (U+061C, U+200E, U+200F, U+202A to U+202E,
    /// U+2066 to U+2069), zero-width U+200B to U+200D, U+2060 to U+2064, and
    /// U+FEFF. These are how hidden instructions ride in text an agent will
    /// read, so they never reach an envelope.
    Hidden,
    /// Any other control scalar: folded to one space.
    Control,
    /// A private-use scalar or a noncharacter: replaced with U+FFFD, and the
    /// item is marked lossy.
    Replaced,
}

/// Classify one scalar of collected text.
#[must_use]
pub fn classify_collected_scalar(value: char) -> CollectedScalarClassV1 {
    let code = u32::from(value);
    match value {
        '\n' | '\t' => CollectedScalarClassV1::KeptControl,
        '\r' => CollectedScalarClassV1::CarriageReturn,
        _ if (0xe_0000..=0xe_007f).contains(&code)
            || matches!(
                code,
                0x061c
                    | 0x200b..=0x200f
                    | 0x202a..=0x202e
                    | 0x2060..=0x2064
                    | 0x2066..=0x2069
                    | 0xfeff
            ) =>
        {
            CollectedScalarClassV1::Hidden
        }
        _ if value.is_control() => CollectedScalarClassV1::Control,
        _ if (0xfdd0..=0xfdef).contains(&code)
            || code & 0xffff >= 0xfffe
            || (0xe000..=0xf8ff).contains(&code)
            || (0xf_0000..=0xf_fffd).contains(&code)
            || (0x10_0000..=0x10_fffd).contains(&code) =>
        {
            CollectedScalarClassV1::Replaced
        }
        _ => CollectedScalarClassV1::Keep,
    }
}

/// Whether `value` is already in the sanitizer's output form: NFC, with no
/// scalar the sanitizer would remove, fold, or replace.
#[must_use]
pub fn is_sanitized_text(value: &str) -> bool {
    is_nfc(value)
        && value.chars().all(|scalar| {
            matches!(
                classify_collected_scalar(scalar),
                CollectedScalarClassV1::Keep | CollectedScalarClassV1::KeptControl
            )
        })
}

/// Sanitized, redacted item text, carried on the wire as the lowercase hex of
/// its exact UTF-8 bytes, at most `MAX` raw bytes.
///
/// It may be empty (a tombstone's text is). It must already be sanitized
/// ([`is_sanitized_text`]): an envelope never carries hidden Unicode, a raw
/// control, or a private-use scalar, whichever collector built it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CollectedTextV1<const MAX: usize = MAX_PART_TEXT_BYTES>(String);

/// A collected title: the same wire form as [`CollectedTextV1`], at most
/// [`MAX_TITLE_BYTES`].
pub type CollectedTitleV1 = CollectedTextV1<MAX_TITLE_BYTES>;

impl<const MAX: usize> CollectedTextV1<MAX> {
    /// Validate one sanitized text.
    pub fn new(value: impl Into<String>) -> ContractResult<Self> {
        let value = value.into();
        if value.len() > MAX {
            return Err(schema(format!(
                "collected text exceeds {MAX} bytes, got {}",
                value.len()
            )));
        }
        if !is_sanitized_text(&value) {
            return Err(schema("collected text is not sanitized"));
        }
        Ok(Self(value))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the text is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<const MAX: usize> Serialize for CollectedTextV1<MAX> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0.as_bytes()))
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for CollectedTextV1<MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() % 2 != 0
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(D::Error::custom(
                "collected text must be lowercase even-length hex",
            ));
        }
        let bytes = hex::decode(encoded).map_err(D::Error::custom)?;
        let text = String::from_utf8(bytes)
            .map_err(|_| D::Error::custom("collected text is not UTF-8"))?;
        Self::new(text).map_err(D::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------

macro_rules! closed_vocabulary {
    ($(#[$meta:meta])* $name:ident { $($(#[$variant_meta:meta])* $variant:ident => $label:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($(#[$variant_meta])* $variant,)+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// The exact wire and stored label.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                }
            }

            /// Parse a stored label. Unknown labels are refused.
            pub fn parse(value: &str) -> ContractResult<Self> {
                match value {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(schema(format!(concat!("not a ", stringify!($name), ": {}"), value))),
                }
            }
        }
    };
}

closed_vocabulary!(
    /// Where one item version stands in its provider's lifecycle.
    ItemLifecycleV1 {
        /// Present and never edited.
        Live => "live",
        /// Present and edited at least once.
        Edited => "edited",
        /// Archived but still present and searchable (a Linear `archivedAt`).
        Archived => "archived",
        /// Deleted by the provider, or missing from enough complete
        /// enumerations. A tombstone.
        Deleted => "deleted",
        /// Moved to the provider's trash. A tombstone.
        Trashed => "trashed",
        /// No longer readable with the collector's credential. A tombstone.
        Revoked => "revoked",
    }
);

impl ItemLifecycleV1 {
    /// Whether a version in this state hides the item: its text is empty and,
    /// once it is the presented head, every earlier version's text is withheld
    /// from recall.
    #[must_use]
    pub const fn is_tombstone(self) -> bool {
        matches!(self, Self::Deleted | Self::Trashed | Self::Revoked)
    }
}

closed_vocabulary!(
    /// What the provider says the author is. Attested by the collector, never
    /// authenticated by this memory.
    AuthorKindV1 {
        /// A person.
        Human => "human",
        /// A provider bot user.
        Bot => "bot",
        /// A provider app or integration.
        App => "app",
        /// Someone outside the provider scope.
        External => "external",
        /// Text a provider's model wrote (a Granola summary).
        AiSummary => "ai_summary",
        /// An agent.
        Agent => "agent",
        /// Not stated.
        Unknown => "unknown",
    }
);

closed_vocabulary!(
    /// How the text of an item is formatted.
    TextFormatV1 {
        /// Plain text.
        Plain => "plain",
        /// Markdown.
        Markdown => "markdown",
        /// Slack `mrkdwn`, rendered to text (mentions resolved to ids, link
        /// labels kept, entities unescaped).
        SlackMrkdwnRendered => "slack_mrkdwn_rendered",
        /// Transcript segments, one `[hh:mm:ss] speaker: text` line each.
        TranscriptSegment => "transcript_segment",
    }
);

closed_vocabulary!(
    /// Why an item is visible to the whole project. Always derived by the
    /// server from provider facts and operator configuration; there is no
    /// agent-declared basis.
    AudienceBasisV1 {
        /// The provider says every member of its scope can read it (a public,
        /// unshared Slack channel).
        ProviderPublic => "provider_public",
        /// A team inside the provider scope is public (a Linear team with
        /// `visibility=public`).
        TeamPublic => "team_public",
        /// The operator declared the source, or this container of it, visible
        /// to the project.
        OperatorDeclared => "operator_declared",
        /// A capture into a container a verified collector or an operator
        /// import already recorded as visible to the project.
        VerifiedContainer => "verified_container",
        /// A capture into a provider scope or container the operator listed as
        /// a capture scope.
        OperatorCaptureScope => "operator_capture_scope",
    }
);

closed_vocabulary!(
    /// The trust channel an item arrived through. It selects the connector
    /// schema, so it is governance, not data.
    CollectionModeV1 {
        /// A worker pulled it from the provider's API.
        Pull => "pull",
        /// A signed provider notification caused it.
        Push => "push",
        /// An agent relayed it from its own connectors.
        Capture => "capture",
        /// An operator imported it from an export or a file.
        Import => "import",
    }
);

impl CollectionModeV1 {
    /// The `connector.collected.*` schema id this channel admits under.
    #[must_use]
    pub const fn connector_schema_id(self) -> &'static str {
        match self {
            Self::Pull => COLLECTED_ITEM_FAMILY.pull_connector,
            Self::Push => COLLECTED_ITEM_FAMILY.push_connector,
            Self::Capture => COLLECTED_ITEM_FAMILY.capture_connector,
            Self::Import => COLLECTED_ITEM_FAMILY.import_connector,
        }
    }

    /// The trust tier items from this channel are presented under.
    #[must_use]
    pub const fn trust_tier(self) -> TrustTierV1 {
        match self {
            Self::Pull | Self::Push => TrustTierV1::Verified,
            Self::Capture | Self::Import => TrustTierV1::Reported,
        }
    }
}

closed_vocabulary!(
    /// Whether the collector itself read the item from the provider.
    TrustTierV1 {
        /// Pulled or pushed by a collector holding the provider credential.
        Verified => "verified",
        /// Reported by an agent or an operator file. A reported head never
        /// displaces a verified one.
        Reported => "reported",
    }
);

closed_vocabulary!(
    /// The visibility an importer or an agent declares for an item. It can
    /// only narrow what the server derives: `private` and `dm` refuse the item,
    /// and no value widens anything.
    VisibilityHintV1 {
        /// A public channel.
        PublicChannel => "public_channel",
        /// A public team.
        TeamPublic => "team_public",
        /// Visible to the project.
        Project => "project",
        /// A document.
        Document => "document",
        /// Restricted to some members of the provider scope.
        Private => "private",
        /// A direct or group-direct conversation.
        Dm => "dm",
    }
);

impl VisibilityHintV1 {
    /// Whether the hint alone refuses the item.
    #[must_use]
    pub const fn refuses(self) -> bool {
        matches!(self, Self::Private | Self::Dm)
    }
}

// ---------------------------------------------------------------------------
// The envelope
// ---------------------------------------------------------------------------

/// Which version of the item this is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemVersionV1 {
    /// The provider's own version marker, or [`default_version_marker`].
    pub marker: BoundedTextV1<MAX_MARKER_BYTES>,
    /// The provider's order for this version in microseconds, never the
    /// arrival time.
    pub order_micros: u64,
}

/// Which part of the version this envelope carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemPartV1 {
    /// Zero-based position of the part.
    pub ordinal: u32,
    /// How many parts the version has, `1..=64`.
    pub count: u32,
    /// Where in the source the part sits (a heading path).
    pub anchor: Option<BoundedTextV1<MAX_ANCHOR_BYTES>>,
    /// The half-open raw-source byte range the part's section came from.
    pub span: Option<[u64; 2]>,
}

/// The container an item lives in: a channel, a team, a folder, a root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemContainerV1 {
    /// What kind of container.
    pub kind: ContainerKindV1,
    /// The provider-stable container id.
    pub id: BoundedTextV1,
    /// The container's current display label; mutable, outside every digest.
    pub label: Option<BoundedTextV1>,
}

/// The conversation an item belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemThreadV1 {
    /// External id of the thread's root item.
    pub root_external_id: BoundedTextV1<MAX_EXTERNAL_ID_BYTES>,
    /// External id of the item this one replies to, when not the root.
    pub parent_external_id: Option<BoundedTextV1<MAX_EXTERNAL_ID_BYTES>>,
}

/// Who the provider says wrote the item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemAuthorV1 {
    /// The provider-stable author id.
    pub id: BoundedTextV1,
    /// A display name.
    pub display: Option<BoundedTextV1>,
    /// What the provider says the author is.
    pub kind: AuthorKindV1,
}

/// One outbound link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemLinkV1 {
    /// The relation.
    pub rel: LinkRelV1,
    /// The target: a URL or a provider reference.
    pub target: BoundedTextV1<MAX_LINK_TARGET_BYTES>,
    /// The link's display text, searchable.
    pub label: Option<BoundedTextV1>,
}

/// Why the item may be admitted to the whole project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemAudienceV1 {
    /// The server-derived basis.
    pub basis: AudienceBasisV1,
    /// The container key, present exactly when the item has a container.
    pub container_key: Option<Sha256Digest>,
}

/// What sanitizing and redacting the item did. Counts and class labels only,
/// never matched bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemRedactionV1 {
    /// The collector redaction profile version that ran.
    pub profile_version: u32,
    /// Ranges replaced with the redaction placeholder across every field.
    pub redacted_ranges: u32,
    /// Secret classes detected, strictly sorted.
    pub classes: Vec<RedactionClassLabelV1>,
    /// Hidden scalars removed by the sanitizer across every field.
    pub hidden_scalars_removed: u32,
    /// Private-use scalars and noncharacters replaced with U+FFFD. Nonzero
    /// marks the item lossy.
    pub replaced_scalars: u32,
}

/// How the item was collected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemCollectionV1 {
    /// The trust channel.
    pub mode: CollectionModeV1,
    /// The collector instance that staged it.
    pub collector_instance: ContractId,
    /// The principal that attested a capture; present exactly for capture.
    pub attester: Option<ContractId>,
    /// The tool an agent says it read the item through; capture only, and a
    /// label, not authority.
    pub via: Option<BoundedTextV1>,
}

/// One part of one version of one collected item, read through one channel.
///
/// Its canonical bytes are the governed payload the `connector.collected.*`
/// connectors admit. See the module docs for what it carries and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectedItemEnvelopeV1 {
    /// Always [`COLLECTED_ITEM_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The provider kind.
    pub provider: ProviderKindV1,
    /// The operator-pinned scope inside the provider: a Slack `team_id`, a
    /// Linear organization UUID, a Granola workspace pin, a documents root id.
    pub provider_scope_id: BoundedTextV1<MAX_SCOPE_ID_BYTES>,
    /// The object kind.
    pub object_kind: ObjectKindV1,
    /// The provider-stable id, never a label.
    pub external_id: BoundedTextV1<MAX_EXTERNAL_ID_BYTES>,
    /// The version.
    pub version: ItemVersionV1,
    /// The lifecycle state of this version.
    pub lifecycle: ItemLifecycleV1,
    /// Which part this is.
    pub part: ItemPartV1,
    /// The container.
    pub container: Option<ItemContainerV1>,
    /// The thread.
    pub thread: Option<ItemThreadV1>,
    /// The author, as the provider attests it.
    pub author: Option<ItemAuthorV1>,
    /// When the provider says the item was created.
    pub created_at: Option<CanonicalTimestamp>,
    /// When the provider says this version was made.
    pub updated_at: Option<CanonicalTimestamp>,
    /// The redacted, sanitized title.
    pub title: Option<CollectedTitleV1>,
    /// This part's redacted, sanitized text; empty exactly for a tombstone.
    pub text: CollectedTextV1,
    /// How the text is formatted.
    pub text_format: TextFormatV1,
    /// The content digest of the whole version: its title and every part's
    /// text, in order.
    pub content_digest: Sha256Digest,
    /// Outbound links.
    pub links: Vec<ItemLinkV1>,
    /// A display link to the item at the provider; `https` only.
    pub provider_url: Option<BoundedTextV1<MAX_PROVIDER_URL_BYTES>>,
    /// Why the item may be admitted.
    pub audience: ItemAudienceV1,
    /// What sanitizing and redacting did.
    pub redaction: ItemRedactionV1,
    /// How the item was collected.
    pub collection: ItemCollectionV1,
}

impl CollectedItemEnvelopeV1 {
    /// Check every rule one envelope can check on its own.
    ///
    /// A multi-part version's content digest covers parts this envelope does
    /// not hold, so it is checked here only for a one-part version; a sink
    /// builds all parts from one text and cannot disagree with itself.
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != COLLECTED_ITEM_SCHEMA_VERSION {
            return Err(schema("unsupported collected item schema version"));
        }
        let safe = MAX_SAFE_INTEGER.unsigned_abs();
        if self.version.order_micros > safe {
            return Err(schema("version order is outside the safe integer range"));
        }
        self.validate_part(safe)?;
        self.validate_lifecycle()?;
        self.validate_clocks()?;
        if self.links.len() > MAX_LINKS {
            return Err(schema(format!("an item carries at most {MAX_LINKS} links")));
        }
        if self
            .provider_url
            .as_ref()
            .is_some_and(|url| !url.as_str().starts_with("https://"))
        {
            return Err(schema("a provider url must be https"));
        }
        if self.audience.container_key != self.container_key() {
            return Err(schema(
                "the audience container key is not the item's derived container key",
            ));
        }
        self.validate_collection()?;
        self.validate_redaction()?;
        if self.part.count == 1 && self.content_digest != self.part_digest() {
            return Err(schema(
                "a one-part version's content digest must be its part digest",
            ));
        }
        Ok(())
    }

    fn validate_part(&self, safe: u64) -> ContractResult<()> {
        let part = &self.part;
        if part.count == 0 || part.count > MAX_PARTS || part.ordinal >= part.count {
            return Err(schema(format!(
                "part ordinal must be below a count of 1 to {MAX_PARTS}"
            )));
        }
        if let Some([start, end]) = part.span
            && (start > end || end > safe)
        {
            return Err(schema("a part span must be an ordered safe-integer range"));
        }
        Ok(())
    }

    fn validate_lifecycle(&self) -> ContractResult<()> {
        if self.lifecycle.is_tombstone() {
            if !self.text.is_empty() || self.title.is_some() || self.part.count != 1 {
                return Err(schema(
                    "a tombstone is one part with no title and empty text",
                ));
            }
        } else if self.text.is_empty() {
            return Err(schema("only a tombstone may have empty text"));
        }
        if self.title.as_ref().is_some_and(CollectedTextV1::is_empty) {
            return Err(schema("a title, when present, is not empty"));
        }
        Ok(())
    }

    fn validate_clocks(&self) -> ContractResult<()> {
        for clock in [&self.created_at, &self.updated_at].into_iter().flatten() {
            if !clock.is_microsecond_aligned() {
                return Err(schema("provider clocks must be microsecond aligned"));
            }
        }
        if let (Some(created), Some(updated)) = (&self.created_at, &self.updated_at)
            && updated < created
        {
            return Err(schema("an item cannot be updated before it was created"));
        }
        Ok(())
    }

    fn validate_collection(&self) -> ContractResult<()> {
        let mode = self.collection.mode;
        if self.collection.attester.is_some() != (mode == CollectionModeV1::Capture) {
            return Err(schema("an attester is recorded exactly for a capture"));
        }
        if self.collection.via.is_some() && mode != CollectionModeV1::Capture {
            return Err(schema("only a capture records the tool it came through"));
        }
        let basis = self.audience.basis;
        let consistent = match mode {
            CollectionModeV1::Pull | CollectionModeV1::Push => matches!(
                basis,
                AudienceBasisV1::ProviderPublic
                    | AudienceBasisV1::TeamPublic
                    | AudienceBasisV1::OperatorDeclared
            ),
            CollectionModeV1::Import => basis == AudienceBasisV1::OperatorDeclared,
            CollectionModeV1::Capture => matches!(
                basis,
                AudienceBasisV1::VerifiedContainer | AudienceBasisV1::OperatorCaptureScope
            ),
        };
        if !consistent {
            return Err(schema(format!(
                "audience basis {} is not one the {} channel can derive",
                basis.as_str(),
                mode.as_str()
            )));
        }
        Ok(())
    }

    fn validate_redaction(&self) -> ContractResult<()> {
        let redaction = &self.redaction;
        if redaction.profile_version == 0 {
            return Err(schema("a redaction profile version is positive"));
        }
        if redaction.classes.len() > MAX_REDACTION_CLASSES
            || redaction
                .classes
                .windows(2)
                .any(|pair| pair[0].as_str() >= pair[1].as_str())
        {
            return Err(ContractError::NonCanonicalSet {
                field: "redaction.classes",
            });
        }
        Ok(())
    }

    /// [`Self::validate`], plus the one rule that needs the staging clock:
    /// the provider clock is not ahead of the observation. A provider that
    /// reports a version made after the read that saw it is reporting
    /// something no collector could have observed, so the item is not staged
    /// (`clock_ahead`) rather than back-dated.
    pub fn validate_observed(&self, observed_at: &CanonicalTimestamp) -> ContractResult<()> {
        self.validate()?;
        if self.occurred_at(observed_at) > *observed_at {
            return Err(schema("the provider clock is ahead of the observation"));
        }
        Ok(())
    }

    /// Validate and emit the exact canonical bytes: the governed payload.
    pub fn canonical_bytes(&self) -> ContractResult<Vec<u8>> {
        self.validate()?;
        encode_canonical(self)
    }

    /// Decode exact canonical bytes, then validate.
    pub fn decode(bytes: &[u8]) -> ContractResult<Self> {
        let envelope: Self = decode_typed_canonical(bytes)?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// The item key: identity across every version and channel.
    #[must_use]
    pub fn item_key(&self) -> Sha256Digest {
        derive_item_key(
            &self.provider,
            self.provider_scope_id.as_str(),
            &self.object_kind,
            self.external_id.as_str(),
        )
    }

    /// The digest of this part's title and text.
    #[must_use]
    pub fn part_digest(&self) -> Sha256Digest {
        derive_content_digest(
            self.title.as_ref().map(CollectedTextV1::as_str),
            self.text.as_str(),
        )
    }

    /// The version key.
    #[must_use]
    pub fn version_key(&self) -> Sha256Digest {
        derive_version_key(
            &self.item_key(),
            self.version.marker.as_str(),
            self.lifecycle,
            &self.content_digest,
        )
    }

    /// The immutable revision, which is also the staging id.
    #[must_use]
    pub fn immutable_revision(&self) -> Sha256Digest {
        derive_immutable_revision(&RevisionCoordinatesV1 {
            version_key: self.version_key(),
            mode: self.collection.mode,
            attester: self.collection.attester.as_ref(),
            part_ordinal: self.part.ordinal,
            part_count: self.part.count,
            part_digest: self.part_digest(),
        })
    }

    /// The container key, when the item has a container.
    #[must_use]
    pub fn container_key(&self) -> Option<Sha256Digest> {
        self.container.as_ref().map(|container| {
            derive_container_key(
                &self.provider,
                self.provider_scope_id.as_str(),
                &container.kind,
                container.id.as_str(),
            )
        })
    }

    /// The provider's own clock for this version: when it was updated, else
    /// when it was created.
    #[must_use]
    pub fn provider_time(&self) -> Option<&CanonicalTimestamp> {
        self.updated_at.as_ref().or(self.created_at.as_ref())
    }

    /// `occurred_at` for an admission observed at `observed_at`: the provider
    /// clock, or the observation itself when the provider states none.
    #[must_use]
    pub fn occurred_at(&self, observed_at: &CanonicalTimestamp) -> CanonicalTimestamp {
        self.provider_time()
            .cloned()
            .unwrap_or_else(|| observed_at.clone())
    }

    /// `<provider>.<object_kind>.revision`: the logical event key.
    #[must_use]
    pub fn logical_event_key(&self) -> String {
        format!("{}.{}.revision", self.provider, self.object_kind)
    }

    /// The trust tier of the channel.
    #[must_use]
    pub const fn trust_tier(&self) -> TrustTierV1 {
        self.collection.mode.trust_tier()
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// `item_key = D{provider, provider_scope_id, object_kind, external_id}`.
#[must_use]
pub fn derive_item_key(
    provider: &ProviderKindV1,
    provider_scope_id: &str,
    object_kind: &ObjectKindV1,
    external_id: &str,
) -> Sha256Digest {
    framed_digest(
        DigestDomain::CollectedItemKeyV1,
        &[
            provider.as_str().as_bytes(),
            provider_scope_id.as_bytes(),
            object_kind.as_str().as_bytes(),
            external_id.as_bytes(),
        ],
    )
}

/// The content digest of one title and one text: over the whole version for
/// `content_digest`, over one part for the part digest a revision binds.
#[must_use]
pub fn derive_content_digest(title: Option<&str>, text: &str) -> Sha256Digest {
    let (presence, title): (&[u8], &str) = title.map_or((&[0], ""), |title| (&[1], title));
    framed_digest(
        DigestDomain::CollectedItemContentV1,
        &[presence, title.as_bytes(), text.as_bytes()],
    )
}

/// `version_key = D{item_key, marker, lifecycle, content_digest}`.
#[must_use]
pub fn derive_version_key(
    item_key: &Sha256Digest,
    marker: &str,
    lifecycle: ItemLifecycleV1,
    content_digest: &Sha256Digest,
) -> Sha256Digest {
    framed_digest(
        DigestDomain::CollectedItemVersionV1,
        &[
            item_key.as_bytes(),
            marker.as_bytes(),
            lifecycle.as_str().as_bytes(),
            content_digest.as_bytes(),
        ],
    )
}

/// Everything one immutable revision is a function of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevisionCoordinatesV1<'a> {
    /// The version.
    pub version_key: Sha256Digest,
    /// The channel.
    pub mode: CollectionModeV1,
    /// The attesting principal of a capture.
    pub attester: Option<&'a ContractId>,
    /// The part's position.
    pub part_ordinal: u32,
    /// How many parts the version has.
    pub part_count: u32,
    /// The part's own content digest.
    pub part_digest: Sha256Digest,
}

/// `immutable_revision = stage_id = D{1, version_key, mode, attester or "",
/// part ordinal, part count, part digest}`.
#[must_use]
pub fn derive_immutable_revision(coordinates: &RevisionCoordinatesV1<'_>) -> Sha256Digest {
    framed_digest(
        DigestDomain::CollectedItemRevisionV1,
        &[
            &COLLECTED_ITEM_SCHEMA_VERSION.to_be_bytes(),
            coordinates.version_key.as_bytes(),
            coordinates.mode.as_str().as_bytes(),
            coordinates
                .attester
                .map_or("", ContractId::as_str)
                .as_bytes(),
            &coordinates.part_ordinal.to_be_bytes(),
            &coordinates.part_count.to_be_bytes(),
            coordinates.part_digest.as_bytes(),
        ],
    )
}

/// `container_key = D{provider, provider_scope_id, container kind, container id}`.
#[must_use]
pub fn derive_container_key(
    provider: &ProviderKindV1,
    provider_scope_id: &str,
    kind: &ContainerKindV1,
    id: &str,
) -> Sha256Digest {
    framed_digest(
        DigestDomain::CollectedContainerKeyV1,
        &[
            provider.as_str().as_bytes(),
            provider_scope_id.as_bytes(),
            kind.as_str().as_bytes(),
            id.as_bytes(),
        ],
    )
}

/// The manifest digest over the version keys one reconciliation pass
/// admitted, in the order it admitted them.
#[must_use]
pub fn derive_observation_manifest(version_keys: &[Sha256Digest]) -> Sha256Digest {
    let parts: Vec<&[u8]> = version_keys
        .iter()
        .map(|key| key.as_bytes().as_slice())
        .collect();
    framed_digest(DigestDomain::CollectedObservationManifestV1, &parts)
}

/// The marker of a version whose provider has none of its own:
/// `o<order_micros>:sha256:<content digest>`.
#[must_use]
pub fn default_version_marker(order_micros: u64, content_digest: &Sha256Digest) -> String {
    format!("o{order_micros}:sha256:{content_digest}")
}

/// Read one provider timestamp in any RFC 3339 form and return its canonical
/// UTC form, truncated to microseconds (the precision every stored clock
/// keeps).
pub fn provider_timestamp(value: &str) -> ContractResult<CanonicalTimestamp> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| schema("a provider timestamp is not RFC 3339"))?
        .with_timezone(&Utc)
        .trunc_subsecs(6);
    CanonicalTimestamp::from_datetime(&parsed)
}

/// Microseconds since the Unix epoch of one canonical timestamp; refused
/// before the epoch or past the safe integer range.
pub fn timestamp_micros(value: &CanonicalTimestamp) -> ContractResult<u64> {
    let parsed = DateTime::parse_from_rfc3339(value.as_str())
        .map_err(|_| schema("timestamp is not canonical UTC"))?;
    let micros = u64::try_from(parsed.timestamp_micros())
        .map_err(|_| schema("a provider clock before the Unix epoch has no order"))?;
    if micros > MAX_SAFE_INTEGER.unsigned_abs() {
        return Err(schema("a provider clock is outside the safe integer range"));
    }
    Ok(micros)
}

// ---------------------------------------------------------------------------
// Plain-text input: a JSONL import line, an agent capture item
// ---------------------------------------------------------------------------

/// An explicit version, when the writer of an input knows the provider's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemVersionInputV1 {
    /// The provider's own marker; absent means [`default_version_marker`].
    #[serde(default)]
    pub marker: Option<String>,
    /// The provider's order in microseconds; absent means `updated_at`, else
    /// `created_at`.
    #[serde(default)]
    pub order_micros: Option<u64>,
}

/// A container, in plain text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemContainerInputV1 {
    /// What kind of container.
    pub kind: ContainerKindV1,
    /// The provider-stable container id.
    pub id: String,
    /// A display label.
    #[serde(default)]
    pub label: Option<String>,
}

/// A thread, in plain text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemThreadInputV1 {
    /// External id of the thread's root.
    pub root_external_id: String,
    /// External id of the item replied to.
    #[serde(default)]
    pub parent_external_id: Option<String>,
}

/// An author, in plain text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemAuthorInputV1 {
    /// The provider-stable author id.
    pub id: String,
    /// A display name.
    #[serde(default)]
    pub display: Option<String>,
    /// What the provider says the author is; absent means `unknown`.
    #[serde(default)]
    pub kind: Option<AuthorKindV1>,
}

/// A link, in plain text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemLinkInputV1 {
    /// The relation.
    pub rel: LinkRelV1,
    /// The target.
    pub target: String,
    /// The link's display text.
    #[serde(default)]
    pub label: Option<String>,
}

/// One item as an importer or an agent writes it: plain text, lenient RFC 3339
/// clocks, defaults for everything a writer may not know.
///
/// It declares nothing about audience except an optional `visibility` hint,
/// which can only narrow; the server derives the audience. It carries no scope,
/// no collection mode, and no attester: those come from the trusted context
/// that stages it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectedItemInputV1 {
    /// The provider kind.
    pub provider: ProviderKindV1,
    /// The provider scope id; must equal the staging instance's.
    pub provider_scope_id: String,
    /// The object kind.
    pub object_kind: ObjectKindV1,
    /// The provider-stable id.
    pub external_id: String,
    /// An explicit version.
    #[serde(default)]
    pub version: Option<ItemVersionInputV1>,
    /// The lifecycle state; absent means `live`.
    #[serde(default)]
    pub lifecycle: Option<ItemLifecycleV1>,
    /// The container.
    #[serde(default)]
    pub container: Option<ItemContainerInputV1>,
    /// The thread.
    #[serde(default)]
    pub thread: Option<ItemThreadInputV1>,
    /// The author.
    #[serde(default)]
    pub author: Option<ItemAuthorInputV1>,
    /// When the provider says the item was created (RFC 3339).
    #[serde(default)]
    pub created_at: Option<String>,
    /// When the provider says this version was made (RFC 3339).
    #[serde(default)]
    pub updated_at: Option<String>,
    /// The title.
    #[serde(default)]
    pub title: Option<String>,
    /// The text, of any length; the server splits it. Empty for a tombstone.
    #[serde(default)]
    pub text: String,
    /// How the text is formatted; absent means `plain`.
    #[serde(default)]
    pub text_format: Option<TextFormatV1>,
    /// Outbound links.
    #[serde(default)]
    pub links: Vec<ItemLinkInputV1>,
    /// The item's link at the provider.
    #[serde(default)]
    pub url: Option<String>,
    /// A visibility hint that can only narrow the derived audience.
    #[serde(default)]
    pub visibility: Option<VisibilityHintV1>,
}

impl CollectedItemInputV1 {
    /// Parse one JSON input (a JSONL line, a capture item). Unknown and
    /// duplicate fields are refused.
    ///
    /// Not the canonical decoder: an input is plain provider text, with
    /// newlines and whatever Unicode the provider held, and the sanitizer is
    /// what makes it canonical.
    pub fn parse(bytes: &[u8]) -> ContractResult<Self> {
        serde_json::from_slice(bytes).map_err(|error| schema(error.to_string()))
    }
}

#[cfg(test)]
#[path = "collected_item_tests.rs"]
pub(crate) mod tests;
