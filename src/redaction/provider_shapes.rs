//! The provider credential shapes: prefixed tokens and signed JSON Web Tokens.
//!
//! These matchers first lived beside the collectors, because collected text is
//! where provider credentials were first seen leaking: a Slack message quoting
//! a bot token, a Linear comment pasting an API key, a meeting transcript
//! reading out a webhook secret. They were lifted here under
//! [`crate::redaction`] once the trial showed the same shapes reaching the
//! transcript and git connectors untouched: a credential is a credential
//! wherever it appears, and the crate has one secret boundary, not one per
//! ingress.
//!
//! Every shape is a small explicit scan with a stated prefix, body alphabet,
//! and minimum body length, and each has a positive and a negative test in
//! `provider_shapes_tests.rs`. No regex dependency, like the shared set.

use super::{CollectedSecretClassV1, CollectedSecretFindingV1};

/// Credential shapes providers mint, beyond the shared set.
///
/// Closed, like [`super::SecretClassV1`]: a shape not listed here is not
/// detected, and the residual re-scan is what keeps a partial neutralization
/// from being staged.
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
    /// A Stripe secret or restricted key: `sk_live_`, `sk_test_`, `rk_live_`,
    /// `rk_test_`.
    StripeKey,
    /// A signed JSON Web Token: three base64url segments, header and payload
    /// both JSON objects.
    JsonWebToken,
}

impl ProviderSecretClassV1 {
    /// Every provider class, for tests that must cover the whole set.
    pub const ALL: [Self; 15] = [
        Self::SlackToken,
        Self::SlackAppToken,
        Self::SlackWebhookUrl,
        Self::SlackFileToken,
        Self::LinearApiKey,
        Self::LinearOauthToken,
        Self::LinearWebhookSecret,
        Self::GranolaApiKey,
        Self::WebhookSigningSecret,
        Self::GithubToken,
        Self::GoogleApiKey,
        Self::AnthropicApiKey,
        Self::OpenaiApiKey,
        Self::StripeKey,
        Self::JsonWebToken,
    ];

    /// Stable label, recorded in an envelope's redaction classes and in
    /// connector reports.
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
            Self::StripeKey => "stripe_key",
            Self::JsonWebToken => "json_web_token",
        }
    }
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
    // Profile 3. Stripe keys are alphanumeric after the prefix; a live key's
    // body is far longer than 16, and the bound is what keeps a prose mention
    // of the `sk_live_` prefix from becoming a finding.
    PrefixRule {
        class: ProviderSecretClassV1::StripeKey,
        prefixes: &[b"sk_live_", b"sk_test_", b"rk_live_", b"rk_test_"],
        body: TokenBytes::Alphanumeric,
        min_body: 16,
        word_boundary: true,
        keep_prefix: 0,
        mixed: false,
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

/// Every finding of the provider set, as each matcher reported it (unmerged).
pub fn scan_provider_secrets(bytes: &[u8]) -> Vec<CollectedSecretFindingV1> {
    let mut findings = Vec::new();
    for rule in PREFIX_RULES {
        scan_prefix_rule(bytes, rule, &mut findings);
    }
    scan_json_web_tokens(bytes, &mut findings);
    findings
}

#[cfg(test)]
#[path = "provider_shapes_tests.rs"]
mod tests;
