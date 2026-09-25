//! The collector redactor: the crate's shared secret matchers plus the
//! credential shapes collected sources carry, applied before anything is
//! staged (EVID-05).
//!
//! Collected text is where provider credentials leak: a Slack message quoting
//! a bot token, a Linear comment pasting an API key, a meeting transcript
//! reading out a webhook secret, a file link that carries its own access
//! token. [`CollectorRedactorV1`] runs the shared [`scan_secrets`] set and the
//! closed [`ProviderSecretClassV1`] set together, with the shared discipline:
//!
//! 1. an unredactable finding (a private key block) withholds the text whole;
//! 2. every other finding is replaced with [`REDACTION_PLACEHOLDER`];
//! 3. the result is scanned again by both sets, and any residual withholds the
//!    text rather than staging a partial redaction.
//!
//! The shared matchers and the lexical projector's `redact_for_recall` are
//! unchanged by this module, so the lexical normalization version and every
//! transcript turn already admitted keep their identities. Only collected
//! items see the provider classes, and [`COLLECTOR_REDACTION_PROFILE_VERSION`]
//! names this set in every envelope, so a later, stricter set is a new profile
//! a head can move to.
//!
//! A redactor is only built from a [`RedactionGuaranteeV1`], the proof that the
//! active package's redaction policy promises redaction before the durable
//! outbox, so a collector cannot stage without one.
//!
//! The matchers are hand-written, like the shared ones: no regex dependency,
//! and every shape is a small explicit scan with a positive and a negative
//! test.

use crate::evidence_ledger::ActiveStage4Package;
use crate::redaction::{
    REDACTION_PLACEHOLDER, RedactionGuaranteeV1, RedactionPolicyError, SecretClassV1, scan_secrets,
};

/// The collector redaction profile every envelope records.
///
/// Profile 2 adds a Linear webhook signing secret (`lin_wh_`) and Slack's
/// browser-session tokens (`xoxc-`, `xoxd-`) to profile 1's set. A version
/// sealed under profile 1 at the same provider order is an older rendering,
/// so a re-read moves the head to the profile-2 one (ADR 0008 D5).
pub const COLLECTOR_REDACTION_PROFILE_VERSION: u32 = 2;

/// Credential shapes collected sources carry, beyond the shared set.
///
/// Closed, like [`SecretClassV1`]: a shape not listed here is not detected,
/// and the residual re-scan is what keeps a partial neutralization from being
/// staged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderSecretClassV1 {
    /// A Slack token: `xoxa-`, `xoxb-`, `xoxc-`, `xoxe-`, `xoxo-`, `xoxp-`,
    /// `xoxr-`, `xoxs-`, and the `xoxd-` session cookie (URL-encoded).
    SlackToken,
    /// A Slack app-level token, `xapp-`.
    SlackAppToken,
    /// The secret path of a Slack incoming webhook,
    /// `hooks.slack.com/services/...`.
    SlackWebhookUrl,
    /// A Slack file link's own token, `?t=xoxe-...`.
    SlackFileToken,
    /// A Linear personal API key, `lin_api_`.
    LinearApiKey,
    /// A Linear OAuth token, `lin_oauth_`.
    LinearOauthToken,
    /// A Linear webhook signing secret, `lin_wh_`.
    LinearWebhookSecret,
    /// A Granola API key, `grn_`.
    GranolaApiKey,
    /// A Standard Webhooks signing secret, `whsec_`.
    WebhookSigningSecret,
    /// A GitHub token: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`.
    GithubToken,
    /// A Google API key, `AIza`.
    GoogleApiKey,
    /// An Anthropic API key, `sk-ant-`.
    AnthropicApiKey,
    /// An `OpenAI`-style secret key, `sk-` or `sk-proj-`.
    OpenaiApiKey,
    /// A signed JSON Web Token: three base64url segments, header and payload
    /// both JSON objects.
    JsonWebToken,
}

impl ProviderSecretClassV1 {
    /// Stable label, recorded in an envelope's redaction classes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SlackToken => "slack_token",
            Self::SlackAppToken => "slack_app_token",
            Self::SlackWebhookUrl => "slack_webhook_url",
            Self::SlackFileToken => "slack_file_token",
            Self::LinearApiKey => "linear_api_key",
            Self::LinearOauthToken => "linear_oauth_token",
            Self::LinearWebhookSecret => "linear_webhook_secret",
            Self::GranolaApiKey => "granola_api_key",
            Self::WebhookSigningSecret => "webhook_signing_secret",
            Self::GithubToken => "github_token",
            Self::GoogleApiKey => "google_api_key",
            Self::AnthropicApiKey => "anthropic_api_key",
            Self::OpenaiApiKey => "openai_api_key",
            Self::JsonWebToken => "json_web_token",
        }
    }
}

/// One class the collector redactor can report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CollectedSecretClassV1 {
    /// A shape of the crate's shared set.
    Shared(SecretClassV1),
    /// A provider credential shape.
    Provider(ProviderSecretClassV1),
}

impl CollectedSecretClassV1 {
    /// Stable label, recorded in an envelope's redaction classes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shared(class) => class.as_str(),
            Self::Provider(class) => class.as_str(),
        }
    }

    /// Whether replacing the matched range can salvage the text.
    #[must_use]
    pub const fn is_redactable(self) -> bool {
        match self {
            Self::Shared(class) => class.is_redactable(),
            Self::Provider(_) => true,
        }
    }
}

/// One detected secret-shaped byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectedSecretFindingV1 {
    /// Which shape matched.
    pub class: CollectedSecretClassV1,
    /// Inclusive start byte offset.
    pub byte_start: usize,
    /// Exclusive end byte offset.
    pub byte_end: usize,
}

/// What the collector redactor decided about one text.
#[derive(Clone, PartialEq, Eq)]
pub enum CollectorDispositionV1 {
    /// Clean or fully redacted; safe to stage.
    Stage {
        /// The redacted text; equal to the input when nothing matched.
        text: String,
    },
    /// Not stageable at all.
    Withhold {
        /// The class that forced the refusal.
        class: CollectedSecretClassV1,
    },
}

/// Prints the disposition and never the text.
impl std::fmt::Debug for CollectorDispositionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stage { text } => formatter
                .debug_struct("Stage")
                .field("text_bytes", &text.len())
                .finish(),
            Self::Withhold { class } => formatter
                .debug_struct("Withhold")
                .field("class", &class.as_str())
                .finish(),
        }
    }
}

/// The outcome of redacting one text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorRedactionV1 {
    /// What to do with the text.
    pub disposition: CollectorDispositionV1,
    /// Classes found in the original text, sorted and deduplicated.
    pub classes: Vec<CollectedSecretClassV1>,
    /// Ranges replaced.
    pub redacted_ranges: u32,
}

/// The redactor every collector stages through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorRedactorV1 {
    guarantee: RedactionGuaranteeV1,
}

impl CollectorRedactorV1 {
    /// A redactor under a proven guarantee.
    #[must_use]
    pub const fn new(guarantee: RedactionGuaranteeV1) -> Self {
        Self { guarantee }
    }

    /// Read the guarantee out of the active package, then build the redactor.
    pub fn from_active_package(active: &ActiveStage4Package) -> Result<Self, RedactionPolicyError> {
        RedactionGuaranteeV1::from_active_package(active).map(Self::new)
    }

    /// The guarantee this redactor runs under.
    #[must_use]
    pub const fn guarantee(&self) -> &RedactionGuaranteeV1 {
        &self.guarantee
    }

    /// The profile this redactor implements.
    #[must_use]
    pub const fn profile_version(&self) -> u32 {
        COLLECTOR_REDACTION_PROFILE_VERSION
    }

    /// Every finding of both sets, sorted and merged.
    #[must_use]
    pub fn scan(&self, text: &str) -> Vec<CollectedSecretFindingV1> {
        scan_collected_secrets(text)
    }

    /// Redact one text, then prove the result clean.
    ///
    /// Every class that matched is reported, including one whose range merged
    /// into another's; each merged range is replaced once.
    #[must_use]
    pub fn redact(&self, text: &str) -> CollectorRedactionV1 {
        let findings = scan_unmerged(text);
        let mut classes: Vec<CollectedSecretClassV1> =
            findings.iter().map(|finding| finding.class).collect();
        classes.sort_unstable();
        classes.dedup();
        replace_and_verify(text, &merge(findings), classes)
    }
}

/// Replace every finding, then re-scan with both sets: a residual withholds.
///
/// Separate from the scan so the re-scan is provably the last word even when
/// the findings it is handed do not cover every credential in the text.
fn replace_and_verify(
    text: &str,
    findings: &[CollectedSecretFindingV1],
    classes: Vec<CollectedSecretClassV1>,
) -> CollectorRedactionV1 {
    let redacted_ranges = u32::try_from(findings.len()).unwrap_or(u32::MAX);
    let withhold = |class| CollectorRedactionV1 {
        disposition: CollectorDispositionV1::Withhold { class },
        classes: classes.clone(),
        redacted_ranges,
    };
    if let Some(finding) = findings
        .iter()
        .find(|finding| !finding.class.is_redactable())
    {
        return withhold(finding.class);
    }
    let mut redacted = String::with_capacity(text.len());
    let mut cursor = 0_usize;
    for finding in findings {
        // Matchers stop on ASCII bytes, so every range is a char boundary;
        // get() keeps a violation a refusal rather than a panic.
        let Some(prefix) = text.get(cursor..finding.byte_start) else {
            return withhold(finding.class);
        };
        redacted.push_str(prefix);
        redacted.push_str(REDACTION_PLACEHOLDER);
        cursor = finding.byte_end;
    }
    let Some(tail) = text.get(cursor..) else {
        let class = findings.last().map_or(
            CollectedSecretClassV1::Shared(SecretClassV1::ApiKeyAssignment),
            |finding| finding.class,
        );
        return withhold(class);
    };
    redacted.push_str(tail);
    if let Some(residual) = scan_collected_secrets(&redacted).first() {
        return withhold(residual.class);
    }
    CollectorRedactionV1 {
        disposition: CollectorDispositionV1::Stage { text: redacted },
        classes,
        redacted_ranges,
    }
}

/// Every finding of the shared set and the provider set, merged so one
/// replacement neutralizes every class that matched there.
#[must_use]
pub fn scan_collected_secrets(text: &str) -> Vec<CollectedSecretFindingV1> {
    merge(scan_unmerged(text))
}

/// Every finding of both sets, as each matcher reported it.
fn scan_unmerged(text: &str) -> Vec<CollectedSecretFindingV1> {
    let mut findings: Vec<CollectedSecretFindingV1> = scan_secrets(text)
        .into_iter()
        .map(|finding| CollectedSecretFindingV1 {
            class: CollectedSecretClassV1::Shared(finding.class),
            byte_start: finding.byte_start,
            byte_end: finding.byte_end,
        })
        .collect();
    findings.extend(scan_provider_secrets(text.as_bytes()));
    findings
}

/// Sort and merge overlapping findings into the widest ranges.
fn merge(mut findings: Vec<CollectedSecretFindingV1>) -> Vec<CollectedSecretFindingV1> {
    findings.sort_by_key(|finding| (finding.byte_start, std::cmp::Reverse(finding.byte_end)));
    let mut merged: Vec<CollectedSecretFindingV1> = Vec::with_capacity(findings.len());
    for finding in findings {
        match merged.last_mut() {
            Some(previous) if finding.byte_start < previous.byte_end => {
                previous.byte_end = previous.byte_end.max(finding.byte_end);
                // An unredactable class anywhere in the merged range wins, so
                // merging can never turn a withhold into a replacement.
                if !finding.class.is_redactable() {
                    previous.class = finding.class;
                }
            }
            _ => merged.push(finding),
        }
    }
    merged
}

/// Which bytes may continue a token of one shape.
#[derive(Debug, Clone, Copy)]
enum TokenBytes {
    /// `A-Z a-z 0-9`.
    Alphanumeric,
    /// Alphanumerics and `-`.
    AlphanumericDash,
    /// Alphanumerics, `-`, and `_` (base64url).
    Base64Url,
    /// Alphanumerics and `_`.
    AlphanumericUnderscore,
    /// Alphanumerics, `+`, `/`, `=` (base64).
    Base64,
    /// Alphanumerics, `/`, `_`, `-` (a URL path).
    UrlPath,
    /// Alphanumerics, `-`, `%`, `/`, `+`, `=` (a URL-encoded cookie value).
    CookieValue,
}

impl TokenBytes {
    const fn accepts(self, byte: u8) -> bool {
        byte.is_ascii_alphanumeric()
            || match self {
                Self::Alphanumeric => false,
                Self::AlphanumericDash => byte == b'-',
                Self::Base64Url => matches!(byte, b'-' | b'_'),
                Self::AlphanumericUnderscore => byte == b'_',
                Self::Base64 => matches!(byte, b'+' | b'/' | b'='),
                Self::UrlPath => matches!(byte, b'/' | b'_' | b'-'),
                Self::CookieValue => matches!(byte, b'-' | b'%' | b'/' | b'+' | b'='),
            }
    }
}

/// One prefixed credential shape.
struct PrefixRule {
    class: ProviderSecretClassV1,
    prefixes: &'static [&'static [u8]],
    body: TokenBytes,
    min_body: usize,
    /// Require the byte before the prefix to be neither alphanumeric nor `_`,
    /// so `task-...` never reads as `sk-...`.
    word_boundary: bool,
    /// Bytes of the prefix kept visible (the host of a webhook URL, the `?t=`
    /// of a file link); the rest of the match is replaced.
    keep_prefix: usize,
    /// Require an uppercase letter, a lowercase letter, and a digit in the
    /// body: generated keys have all three, prose that merely starts with the
    /// prefix rarely does.
    mixed: bool,
}

const PREFIX_RULES: &[PrefixRule] = &[
    PrefixRule {
        class: ProviderSecretClassV1::SlackToken,
        prefixes: &[
            b"xoxa-", b"xoxb-", b"xoxc-", b"xoxe-", b"xoxo-", b"xoxp-", b"xoxr-", b"xoxs-",
        ],
        body: TokenBytes::AlphanumericDash,
        min_body: 8,
        word_boundary: true,
        keep_prefix: 0,
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::SlackToken,
        prefixes: &[b"xoxd-"],
        body: TokenBytes::CookieValue,
        min_body: 8,
        word_boundary: true,
        keep_prefix: 0,
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::SlackAppToken,
        prefixes: &[b"xapp-"],
        body: TokenBytes::AlphanumericDash,
        min_body: 8,
        word_boundary: true,
        keep_prefix: 0,
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::SlackWebhookUrl,
        prefixes: &[b"hooks.slack.com/services/"],
        body: TokenBytes::UrlPath,
        min_body: 8,
        word_boundary: true,
        keep_prefix: b"hooks.slack.com/services/".len(),
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::SlackFileToken,
        prefixes: &[b"?t=xoxe-", b"&t=xoxe-"],
        body: TokenBytes::AlphanumericDash,
        min_body: 8,
        word_boundary: false,
        keep_prefix: 3,
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::LinearApiKey,
        prefixes: &[b"lin_api_"],
        body: TokenBytes::Alphanumeric,
        min_body: 16,
        word_boundary: true,
        keep_prefix: 0,
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::LinearOauthToken,
        prefixes: &[b"lin_oauth_"],
        body: TokenBytes::Alphanumeric,
        min_body: 16,
        word_boundary: true,
        keep_prefix: 0,
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::LinearWebhookSecret,
        prefixes: &[b"lin_wh_"],
        body: TokenBytes::Alphanumeric,
        min_body: 16,
        word_boundary: true,
        keep_prefix: 0,
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::GranolaApiKey,
        prefixes: &[b"grn_"],
        body: TokenBytes::Base64Url,
        min_body: 16,
        word_boundary: true,
        keep_prefix: 0,
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::WebhookSigningSecret,
        prefixes: &[b"whsec_"],
        body: TokenBytes::Base64,
        min_body: 16,
        word_boundary: true,
        keep_prefix: 0,
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::GithubToken,
        prefixes: &[b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_"],
        body: TokenBytes::Alphanumeric,
        min_body: 30,
        word_boundary: true,
        keep_prefix: 0,
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::GithubToken,
        prefixes: &[b"github_pat_"],
        body: TokenBytes::AlphanumericUnderscore,
        min_body: 22,
        word_boundary: true,
        keep_prefix: 0,
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::GoogleApiKey,
        prefixes: &[b"AIza"],
        body: TokenBytes::Base64Url,
        min_body: 30,
        word_boundary: true,
        keep_prefix: 0,
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::AnthropicApiKey,
        prefixes: &[b"sk-ant-"],
        body: TokenBytes::Base64Url,
        min_body: 20,
        word_boundary: true,
        keep_prefix: 0,
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::OpenaiApiKey,
        prefixes: &[b"sk-proj-"],
        body: TokenBytes::Base64Url,
        min_body: 20,
        word_boundary: true,
        keep_prefix: 0,
        mixed: false,
    },
    PrefixRule {
        class: ProviderSecretClassV1::OpenaiApiKey,
        prefixes: &[b"sk-"],
        body: TokenBytes::Base64Url,
        min_body: 20,
        word_boundary: true,
        keep_prefix: 0,
        mixed: true,
    },
];

const fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn has_mixed_classes(body: &[u8]) -> bool {
    body.iter().any(u8::is_ascii_uppercase)
        && body.iter().any(u8::is_ascii_lowercase)
        && body.iter().any(u8::is_ascii_digit)
}

fn scan_prefix_rule(bytes: &[u8], rule: &PrefixRule, findings: &mut Vec<CollectedSecretFindingV1>) {
    for prefix in rule.prefixes {
        let mut index = 0_usize;
        while index + prefix.len() <= bytes.len() {
            let boundary_ok = !rule.word_boundary || index == 0 || !is_word_byte(bytes[index - 1]);
            if !boundary_ok || !bytes[index..].starts_with(prefix) {
                index += 1;
                continue;
            }
            let body_start = index + prefix.len();
            let mut cursor = body_start;
            while bytes
                .get(cursor)
                .is_some_and(|byte| rule.body.accepts(*byte))
            {
                cursor += 1;
            }
            let body = &bytes[body_start..cursor];
            // `sk-ant-` belongs to its own rule; the generic `sk-` shape must
            // not report an Anthropic key as a second class.
            let claimed_elsewhere = rule.class == ProviderSecretClassV1::OpenaiApiKey
                && *prefix == b"sk-"
                && (body.starts_with(b"ant-") || body.starts_with(b"proj-"));
            if body.len() >= rule.min_body
                && (!rule.mixed || has_mixed_classes(body))
                && !claimed_elsewhere
            {
                findings.push(CollectedSecretFindingV1 {
                    class: CollectedSecretClassV1::Provider(rule.class),
                    byte_start: index + rule.keep_prefix,
                    byte_end: cursor,
                });
                index = cursor;
                continue;
            }
            index += 1;
        }
    }
}

/// Minimum length of each JWT segment before a triple counts.
const MIN_JWT_SEGMENT: usize = 8;

/// A base64url segment starting at `start`; returns its end.
fn base64url_segment_end(bytes: &[u8], start: usize) -> usize {
    let mut cursor = start;
    while bytes
        .get(cursor)
        .is_some_and(|byte| TokenBytes::Base64Url.accepts(*byte))
    {
        cursor += 1;
    }
    cursor
}

/// `eyJ<header>.eyJ<payload>.<signature>`: a header and a payload that both
/// decode as JSON objects, and a signature.
fn scan_json_web_tokens(bytes: &[u8], findings: &mut Vec<CollectedSecretFindingV1>) {
    const OBJECT: &[u8] = b"eyJ";
    let mut index = 0_usize;
    while index + OBJECT.len() <= bytes.len() {
        let boundary_ok = index == 0 || !is_word_byte(bytes[index - 1]);
        if !boundary_ok || !bytes[index..].starts_with(OBJECT) {
            index += 1;
            continue;
        }
        let header_end = base64url_segment_end(bytes, index);
        let payload_start = header_end + 1;
        let is_triple = header_end - index >= MIN_JWT_SEGMENT
            && bytes.get(header_end) == Some(&b'.')
            && bytes
                .get(payload_start..)
                .is_some_and(|rest| rest.starts_with(OBJECT));
        if !is_triple {
            index += 1;
            continue;
        }
        let payload_end = base64url_segment_end(bytes, payload_start);
        let signature_start = payload_end + 1;
        let signature_end = base64url_segment_end(bytes, signature_start.min(bytes.len()));
        if payload_end - payload_start >= MIN_JWT_SEGMENT
            && bytes.get(payload_end) == Some(&b'.')
            && signature_end.saturating_sub(signature_start) >= MIN_JWT_SEGMENT
        {
            findings.push(CollectedSecretFindingV1 {
                class: CollectedSecretClassV1::Provider(ProviderSecretClassV1::JsonWebToken),
                byte_start: index,
                byte_end: signature_end,
            });
            index = signature_end;
            continue;
        }
        index += 1;
    }
}

/// Every finding of the provider set, unmerged.
fn scan_provider_secrets(bytes: &[u8]) -> Vec<CollectedSecretFindingV1> {
    let mut findings = Vec::new();
    for rule in PREFIX_RULES {
        scan_prefix_rule(bytes, rule, &mut findings);
    }
    scan_json_web_tokens(bytes, &mut findings);
    findings
}

#[cfg(test)]
#[path = "redaction_tests.rs"]
mod tests;
