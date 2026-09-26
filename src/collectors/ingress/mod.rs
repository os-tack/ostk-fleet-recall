//! Stage-7 ingress: signed provider webhooks, kept as hints (ADR 0008 D12).
//!
//! A provider's webhook tells the memory that something changed; it is never
//! the memory's word for what changed. `ostk-fleet-recall ingress`
//! ([`server`]) receives each delivery on the private plane, verifies its
//! signature over the exact bytes received ([`signature`]), and keeps a
//! **hint**: which provider object changed, by id, and nothing of its
//! content. The worker's `collect` step then re-reads the object through the
//! collector's own pull adapter, under the collector's own credential and
//! audience rules, and stages what it read through the sink like any pull; a
//! deletion becomes a push-mode tombstone for an item the memory already
//! holds. A hint settles only in the transaction that stages what it caused,
//! so settling it is the transport queue's acknowledgement
//! (`docs/DYNAMIC_MEMORY_ARCHITECTURE.md`, "Ingestion and projections").
//!
//! ```text
//! POST /v1/hooks/{connector_instance}
//!   -> body limit (413, `oversize` dead letter)
//!   -> signature over the raw bytes, injected clock (401, `invalid_signature` | `stale_signature`)
//!   -> parse (400, `parse_failed`) -> scope pin (403, `unauthorized_scope`)
//!   -> hint (upsert | delete, ids only) | ignored | Slack challenge
//!   -> INSERT memory_ingress_deliveries_v1 ON CONFLICT DO NOTHING
//!   -> 200 after the commit; 503 when the database failed
//! ```
//!
//! * [`base64`] is strict RFC 4648 base64, written here rather than taken
//!   from a crate: a Standard Webhooks entry is either one exact tag or
//!   ignored.
//! * [`signature`] verifies Slack, Linear, and Standard Webhooks (Granola)
//!   signatures with `ring::hmac::verify`.
//! * [`deliveries`] derives the dedupe key and a rejection's dead-letter key,
//!   and holds the receiver's statements.
//! * [`server`] is the axum receiver and its configuration.
//! * Each provider's adapter maps its own deliveries
//!   ([`PushVerifierV1`]: `slack::push`, `linear::push`, `granola::push`) and
//!   re-reads the object a hint names ([`super::pull::ObjectFetcherV1`]).
//!
//! The receiver logs in as a member of `fleet_ingress_receiver`
//! (`deploy/cockroach/ingress-receiver-role-grants.sql`), which may only read
//! and insert deliveries and dead letters: it holds no content key, no writer
//! pins, and no grant on evidence, content, items, or the outbox.

pub mod base64;
pub mod deliveries;
pub mod server;
pub mod signature;

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::sink::DeadLetterReasonV1;
use signature::SignatureFailureV1;

/// Where the receiver listens unless told otherwise: loopback only.
pub const DEFAULT_INGRESS_LISTEN: &str = "127.0.0.1:8787";

/// The largest request body the receiver reads, unless told otherwise
/// (1 MiB).
pub const DEFAULT_INGRESS_MAX_BODY_BYTES: usize = 1_048_576;

/// The largest body limit an operator may set (16 MiB).
pub const MAX_INGRESS_MAX_BODY_BYTES: usize = 16 * 1_048_576;

/// The receiver's database URL: the `fleet_ingress` login.
pub const INGRESS_DATABASE_URL_ENV: &str = "FLEET_RECALL_INGRESS_DATABASE_URL";

/// Where the receiver listens.
pub const INGRESS_LISTEN_ENV: &str = "FLEET_RECALL_INGRESS_LISTEN";

/// The receiver's body limit, in bytes.
pub const INGRESS_MAX_BODY_BYTES_ENV: &str = "FLEET_RECALL_INGRESS_MAX_BODY_BYTES";

/// The route every delivery is posted to.
pub const INGRESS_ROUTE: &str = "/v1/hooks/{connector_instance}";

/// Longest `event_kind` a delivery row keeps.
pub const MAX_EVENT_KIND_BYTES: usize = 64;

/// Longest external id a hint names.
pub const MAX_HINT_EXTERNAL_ID_BYTES: usize = 1_024;

/// Longest container id a hint names.
pub const MAX_HINT_CONTAINER_ID_BYTES: usize = 256;

/// A collector's webhook, as the sources file configures it: the variable
/// holding the signing secret, never the secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorPushV1 {
    /// The environment variable holding the provider's signing secret, in
    /// the collector's own namespace (`FLEET_RECALL_SLACK_SIGNING_SECRET`).
    pub signing_secret_env: String,
}

/// What one hint asks the worker to do with the object it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HintKindV1 {
    /// Re-read the object through the pull adapter and stage what it reads.
    Upsert,
    /// The provider deleted the object: a push-mode tombstone for an item
    /// the memory holds.
    Delete,
}

impl HintKindV1 {
    /// The stored kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Delete => "delete",
        }
    }

    /// A stored kind.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "upsert" => Some(Self::Upsert),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }
}

/// One hint: which provider object changed, by id only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressHintV1 {
    /// Upsert or delete.
    pub kind: HintKindV1,
    /// The object kind the collector stages it as (`message`, `issue`).
    pub object_kind: String,
    /// The provider-stable id the collector stages it under.
    pub external_id: String,
    /// Its container, when the delivery names it.
    pub container_id: Option<String>,
    /// When the provider says the change happened: a deletion's order.
    pub provider_event_at: DateTime<Utc>,
}

/// What a verified delivery is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryMappingV1 {
    /// A change to one object the collectors read.
    Hint(IngressHintV1),
    /// Nothing the collectors read, or a direct conversation: kept with no
    /// ids, so its replay is recognized.
    Ignored,
    /// Slack's URL verification: the challenge to echo.
    Challenge(String),
}

/// One delivery whose signature verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeliveryV1 {
    /// The id the provider signed (a Slack `event_id`, the digest of a
    /// Linear body, a `webhook-id`): the dedupe key is derived from it.
    pub signed_id: Vec<u8>,
    /// A bounded label of what the provider sent ([`event_kind`]).
    pub event_kind: String,
    /// What it maps to.
    pub mapping: DeliveryMappingV1,
}

/// Why a delivery is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryRefusalV1 {
    /// The signature is missing or does not verify.
    InvalidSignature,
    /// The signature verifies over a timestamp outside the window.
    StaleSignature,
    /// The signed body is not the provider's documented shape.
    Malformed,
    /// The signed body names another provider scope than the instance's.
    UnauthorizedScope,
}

impl DeliveryRefusalV1 {
    /// The HTTP status the receiver answers with.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::InvalidSignature | Self::StaleSignature => 401,
            Self::Malformed => 400,
            Self::UnauthorizedScope => 403,
        }
    }

    /// The dead letter's reason.
    #[must_use]
    pub const fn reason(self) -> DeadLetterReasonV1 {
        match self {
            Self::InvalidSignature => DeadLetterReasonV1::InvalidSignature,
            Self::StaleSignature => DeadLetterReasonV1::StaleSignature,
            Self::Malformed => DeadLetterReasonV1::ParseFailed,
            Self::UnauthorizedScope => DeadLetterReasonV1::UnauthorizedScope,
        }
    }

    /// The dead letter's static diagnostic.
    #[must_use]
    pub const fn diagnostic(self) -> &'static str {
        match self {
            Self::InvalidSignature => "a webhook delivery's signature did not verify",
            Self::StaleSignature => "a webhook delivery was signed outside the timestamp window",
            Self::Malformed => "a signed webhook delivery is not the provider's documented shape",
            Self::UnauthorizedScope => {
                "a signed webhook delivery names another provider scope than the instance's"
            }
        }
    }
}

impl From<SignatureFailureV1> for DeliveryRefusalV1 {
    fn from(failure: SignatureFailureV1) -> Self {
        match failure {
            SignatureFailureV1::Invalid => Self::InvalidSignature,
            SignatureFailureV1::Stale => Self::StaleSignature,
        }
    }
}

/// A webhook signing key. Never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningKeyV1(Vec<u8>);

impl SigningKeyV1 {
    /// The key's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SigningKeyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SigningKeyV1")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// One delivery, as received, with what its instance pins.
#[derive(Debug, Clone, Copy)]
pub struct PushRequestV1<'a> {
    /// The request's headers.
    pub headers: &'a HeaderMap,
    /// The raw body, exactly as received.
    pub body: &'a [u8],
    /// The instance's pinned provider scope.
    pub provider_scope_id: &'a str,
    /// The instance's signing key.
    pub key: &'a SigningKeyV1,
    /// The receiver's clock for this request.
    pub now: DateTime<Utc>,
}

/// One provider's webhook: how its signature is checked and what a delivery
/// maps to. A provider with one is a row of [`super::ADAPTERS`] whose
/// adapter returns it from `push()`.
pub trait PushVerifierV1: Send + Sync {
    /// The key a configured secret gives: its bytes, unless the provider
    /// encodes it.
    ///
    /// # Errors
    ///
    /// A message when the secret gives no key.
    fn signing_key(&self, secret: &str) -> Result<SigningKeyV1, String> {
        if secret.is_empty() {
            return Err("the signing secret is empty".to_owned());
        }
        Ok(SigningKeyV1(secret.as_bytes().to_vec()))
    }

    /// Verify one delivery's signature over its raw body, then map it.
    ///
    /// # Errors
    ///
    /// [`DeliveryRefusalV1`].
    fn accept(&self, request: &PushRequestV1<'_>) -> Result<VerifiedDeliveryV1, DeliveryRefusalV1>;
}

/// A key from bytes a provider's [`PushVerifierV1::signing_key`] decoded.
#[must_use]
pub const fn signing_key_from(bytes: Vec<u8>) -> SigningKeyV1 {
    SigningKeyV1(bytes)
}

/// One header's value, when it is visible ASCII.
#[must_use]
pub fn header<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// A bounded label of what a provider sent: `parts` joined by `.`, each
/// kept to letters, digits, `_`, `-`, and `.`, at most
/// [`MAX_EVENT_KIND_BYTES`] bytes; `unknown` when nothing is left.
#[must_use]
pub fn event_kind(parts: &[&str]) -> String {
    let mut label = String::new();
    for part in parts {
        let kept: String = part
            .chars()
            .filter(|scalar| scalar.is_ascii_alphanumeric() || matches!(scalar, '_' | '-' | '.'))
            .collect();
        if kept.is_empty() {
            continue;
        }
        if !label.is_empty() {
            label.push('.');
        }
        label.push_str(&kept);
    }
    label.truncate(MAX_EVENT_KIND_BYTES);
    if label.is_empty() {
        "unknown".to_owned()
    } else {
        label
    }
}

/// Whether `value` can be an id a hint names: 1 to `limit` bytes, no
/// control character.
#[must_use]
pub fn is_hint_id(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_event_kind_is_a_bounded_label() {
        assert_eq!(
            event_kind(&["message", "message_changed"]),
            "message.message_changed"
        );
        assert_eq!(event_kind(&["Issue", "update"]), "Issue.update");
        assert_eq!(event_kind(&["note.edited"]), "note.edited");
        assert_eq!(event_kind(&["<script>", ""]), "script");
        assert_eq!(event_kind(&["", "!!"]), "unknown");
        assert_eq!(event_kind(&[&"x".repeat(100)]).len(), MAX_EVENT_KIND_BYTES);
    }

    #[test]
    fn a_hint_kind_round_trips() {
        for kind in [HintKindV1::Upsert, HintKindV1::Delete] {
            assert_eq!(HintKindV1::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(HintKindV1::parse("remove"), None);
    }

    #[test]
    fn a_signing_key_never_prints() {
        let key = signing_key_from(b"EXAMPLE-NOT-A-SIGNING-SECRET".to_vec());
        assert!(!format!("{key:?}").contains("EXAMPLE"));
    }
}
