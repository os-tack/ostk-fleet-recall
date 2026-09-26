//! Webhook signatures, verified over the exact bytes received (ADR 0008 D12).
//!
//! Every provider signs its raw request body with a secret only it and the
//! operator hold, and every check here is `ring::hmac::verify`, so the tag is
//! compared in constant time. The clock is the caller's, injected, so a test
//! pins it and the receiver reads it once per request.
//!
//! | Provider | Signature | Timestamp window |
//! |---|---|---|
//! | Slack | `X-Slack-Signature: v0=<hex>`, HMAC-SHA256 over `v0:{X-Slack-Request-Timestamp}:{body}` | ±300 s |
//! | Linear | `Linear-Signature: <hex>`, HMAC-SHA256 over the body; the body's signed `webhookTimestamp` (ms) is the clock | ±60 s |
//! | Standard Webhooks (Granola) | `webhook-signature: v1,<base64> ...`, HMAC-SHA256 keyed by the decoded `whsec_` secret over `{webhook-id}.{webhook-timestamp}.{body}`; any `v1` entry may match | ±300 s |
//!
//! A signature that does not verify is [`SignatureFailureV1::Invalid`]; a
//! verified signature over a timestamp outside the window is
//! [`SignatureFailureV1::Stale`], so an old delivery replayed with its own
//! signature is refused. A timestamp is checked only after the tag verifies,
//! so an unsigned request never learns anything from the window.

use chrono::{DateTime, Utc};
use ring::hmac;

use super::base64;

/// How far a Slack request's timestamp may be from the receiver's clock.
pub const SLACK_WINDOW_SECONDS: i64 = 300;

/// How far a Linear delivery's `webhookTimestamp` may be from the
/// receiver's clock, in milliseconds.
pub const LINEAR_WINDOW_MILLIS: i64 = 60_000;

/// How far a Standard Webhooks timestamp may be from the receiver's clock.
pub const STANDARD_WEBHOOKS_WINDOW_SECONDS: i64 = 300;

/// The prefix of a Standard Webhooks secret.
pub const STANDARD_WEBHOOKS_SECRET_PREFIX: &str = "whsec_";

/// Longest `webhook-id` accepted.
const MAX_WEBHOOK_ID_BYTES: usize = 256;

/// Signature entries one `webhook-signature` header may carry.
const MAX_SIGNATURE_ENTRIES: usize = 16;

/// Why a delivery's signature is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFailureV1 {
    /// Missing, malformed, or not made with the instance's secret.
    Invalid,
    /// Made with the secret, over a timestamp outside the window.
    Stale,
}

fn key(secret: &[u8]) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, secret)
}

/// Exactly 64 hexadecimal digits, as the 32 bytes of one SHA-256 tag.
fn hex_tag(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut tag = [0_u8; 32];
    hex::decode_to_slice(text, &mut tag).ok()?;
    Some(tag)
}

/// A decimal count of seconds or milliseconds since the epoch, digits only.
fn epoch(text: &str) -> Option<i64> {
    if text.is_empty() || text.len() > 18 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn within_millis(signed_millis: i64, now: DateTime<Utc>, window: i64) -> bool {
    now.timestamp_millis()
        .checked_sub(signed_millis)
        .is_some_and(|skew| skew.abs() <= window)
}

/// Verify a Slack request: `X-Slack-Signature` over
/// `v0:{X-Slack-Request-Timestamp}:{body}`.
///
/// # Errors
///
/// [`SignatureFailureV1`].
pub fn verify_slack(
    secret: &[u8],
    timestamp: Option<&str>,
    signature: Option<&str>,
    body: &[u8],
    now: DateTime<Utc>,
) -> Result<(), SignatureFailureV1> {
    let (Some(timestamp), Some(signature)) = (timestamp, signature) else {
        return Err(SignatureFailureV1::Invalid);
    };
    let seconds = epoch(timestamp).ok_or(SignatureFailureV1::Invalid)?;
    let tag = signature
        .strip_prefix("v0=")
        .and_then(hex_tag)
        .ok_or(SignatureFailureV1::Invalid)?;
    let mut message = Vec::with_capacity(4 + timestamp.len() + body.len());
    message.extend_from_slice(b"v0:");
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b':');
    message.extend_from_slice(body);
    hmac::verify(&key(secret), &message, &tag).map_err(|_| SignatureFailureV1::Invalid)?;
    let signed = seconds
        .checked_mul(1_000)
        .ok_or(SignatureFailureV1::Stale)?;
    if within_millis(signed, now, SLACK_WINDOW_SECONDS * 1_000) {
        Ok(())
    } else {
        Err(SignatureFailureV1::Stale)
    }
}

/// Verify a Linear delivery's `Linear-Signature` over its body. The
/// timestamp is inside the signed body: check it with
/// [`linear_timestamp_fresh`] once the body is parsed.
///
/// # Errors
///
/// [`SignatureFailureV1::Invalid`].
pub fn verify_linear(
    secret: &[u8],
    signature: Option<&str>,
    body: &[u8],
) -> Result<(), SignatureFailureV1> {
    let tag = signature
        .and_then(hex_tag)
        .ok_or(SignatureFailureV1::Invalid)?;
    hmac::verify(&key(secret), body, &tag).map_err(|_| SignatureFailureV1::Invalid)
}

/// Whether a verified Linear body's `webhookTimestamp` (milliseconds) is
/// within the window.
///
/// # Errors
///
/// [`SignatureFailureV1::Stale`].
pub fn linear_timestamp_fresh(
    webhook_timestamp_millis: i64,
    now: DateTime<Utc>,
) -> Result<(), SignatureFailureV1> {
    if within_millis(webhook_timestamp_millis, now, LINEAR_WINDOW_MILLIS) {
        Ok(())
    } else {
        Err(SignatureFailureV1::Stale)
    }
}

/// The HMAC key of a Standard Webhooks secret: the base64 after `whsec_`.
/// `None` when it does not decode, or decodes to nothing.
#[must_use]
pub fn standard_webhooks_key(secret: &str) -> Option<Vec<u8>> {
    let encoded = secret
        .strip_prefix(STANDARD_WEBHOOKS_SECRET_PREFIX)
        .unwrap_or(secret);
    base64::decode(encoded).filter(|key| !key.is_empty())
}

/// The headers of one Standard Webhooks delivery.
#[derive(Debug, Clone, Copy)]
pub struct StandardWebhookHeadersV1<'a> {
    /// `webhook-id`.
    pub id: Option<&'a str>,
    /// `webhook-timestamp`, in seconds.
    pub timestamp: Option<&'a str>,
    /// `webhook-signature`: space-separated `v1,<base64>` entries.
    pub signature: Option<&'a str>,
}

/// Verify a Standard Webhooks delivery under the decoded secret `key`: any
/// `v1` entry that decodes and matches admits it; an entry that does not
/// decode is ignored.
///
/// # Errors
///
/// [`SignatureFailureV1`].
pub fn verify_standard_webhooks(
    key_bytes: &[u8],
    headers: StandardWebhookHeadersV1<'_>,
    body: &[u8],
    now: DateTime<Utc>,
) -> Result<(), SignatureFailureV1> {
    let (Some(id), Some(timestamp), Some(signature)) =
        (headers.id, headers.timestamp, headers.signature)
    else {
        return Err(SignatureFailureV1::Invalid);
    };
    if id.is_empty() || id.len() > MAX_WEBHOOK_ID_BYTES {
        return Err(SignatureFailureV1::Invalid);
    }
    let seconds = epoch(timestamp).ok_or(SignatureFailureV1::Invalid)?;
    let mut message = Vec::with_capacity(id.len() + timestamp.len() + 2 + body.len());
    message.extend_from_slice(id.as_bytes());
    message.push(b'.');
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);
    let key = key(key_bytes);
    let verified = signature
        .split(' ')
        .take(MAX_SIGNATURE_ENTRIES)
        .filter_map(|entry| entry.strip_prefix("v1,"))
        .filter_map(base64::decode)
        .filter(|tag| tag.len() == 32)
        .any(|tag| hmac::verify(&key, &message, &tag).is_ok());
    if !verified {
        return Err(SignatureFailureV1::Invalid);
    }
    let signed = seconds
        .checked_mul(1_000)
        .ok_or(SignatureFailureV1::Stale)?;
    if within_millis(signed, now, STANDARD_WEBHOOKS_WINDOW_SECONDS * 1_000) {
        Ok(())
    } else {
        Err(SignatureFailureV1::Stale)
    }
}

/// Sign `message` under `secret`: what a provider sends, for tests and fake
/// providers.
#[must_use]
pub fn sign(secret: &[u8], message: &[u8]) -> Vec<u8> {
    hmac::sign(&key(secret), message).as_ref().to_vec()
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use serde_json::Value;

    use super::*;

    const SLACK_CHANGED: &str = include_str!("../slack/fixtures/event_message_changed.json");
    const SLACK_DELETED: &str = include_str!("../slack/fixtures/event_message_deleted.json");
    const LINEAR_UPDATE: &str = include_str!("../linear/fixtures/webhook_issue_update.json");
    const LINEAR_REMOVE: &str = include_str!("../linear/fixtures/webhook_comment_remove.json");
    const GRANOLA_EDITED: &str = include_str!("../granola/fixtures/webhook_note_updated.json");

    /// One recorded, signed delivery: its headers, secret, and raw body.
    struct Recorded {
        value: Value,
    }

    impl Recorded {
        fn new(fixture: &str) -> Self {
            Self {
                value: serde_json::from_str(fixture).unwrap(),
            }
        }

        fn header(&self, name: &str) -> Option<&str> {
            self.value["headers"][name].as_str()
        }

        fn secret(&self) -> &str {
            self.value["signing_secret"].as_str().unwrap()
        }

        fn body(&self) -> &[u8] {
            self.value["raw_body"].as_str().unwrap().as_bytes()
        }
    }

    fn at(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0).unwrap()
    }

    fn flipped(body: &[u8]) -> Vec<u8> {
        let mut changed = body.to_vec();
        let middle = changed.len() / 2;
        changed[middle] ^= 0x01;
        changed
    }

    fn slack(
        recorded: &Recorded,
        secret: &str,
        body: &[u8],
        now: i64,
    ) -> Result<(), SignatureFailureV1> {
        verify_slack(
            secret.as_bytes(),
            recorded.header("X-Slack-Request-Timestamp"),
            recorded.header("X-Slack-Signature"),
            body,
            at(now),
        )
    }

    #[test]
    fn the_recorded_slack_events_verify_and_nothing_else_does() {
        for (fixture, signed_at) in [
            (SLACK_CHANGED, 1_790_008_201),
            (SLACK_DELETED, 1_790_064_001),
        ] {
            let recorded = Recorded::new(fixture);
            let secret = recorded.secret();
            assert_eq!(slack(&recorded, secret, recorded.body(), signed_at), Ok(()));
            assert_eq!(
                slack(
                    &recorded,
                    secret,
                    recorded.body(),
                    signed_at + SLACK_WINDOW_SECONDS
                ),
                Ok(())
            );
            assert_eq!(
                slack(&recorded, secret, &flipped(recorded.body()), signed_at),
                Err(SignatureFailureV1::Invalid),
                "one changed byte"
            );
            assert_eq!(
                slack(
                    &recorded,
                    "EXAMPLE-NOT-THE-SECRET",
                    recorded.body(),
                    signed_at
                ),
                Err(SignatureFailureV1::Invalid),
                "another secret"
            );
            assert_eq!(
                slack(
                    &recorded,
                    secret,
                    recorded.body(),
                    signed_at + SLACK_WINDOW_SECONDS + 1
                ),
                Err(SignatureFailureV1::Stale)
            );
            assert_eq!(
                slack(
                    &recorded,
                    secret,
                    recorded.body(),
                    signed_at - SLACK_WINDOW_SECONDS - 1
                ),
                Err(SignatureFailureV1::Stale)
            );
            // The timestamp is signed: moving it breaks the signature.
            assert_eq!(
                verify_slack(
                    secret.as_bytes(),
                    Some(&(signed_at + 1).to_string()),
                    recorded.header("X-Slack-Signature"),
                    recorded.body(),
                    at(signed_at),
                ),
                Err(SignatureFailureV1::Invalid)
            );
            for (timestamp, signature) in [
                (None, recorded.header("X-Slack-Signature")),
                (recorded.header("X-Slack-Request-Timestamp"), None),
                (Some("-5"), recorded.header("X-Slack-Signature")),
                (recorded.header("X-Slack-Request-Timestamp"), Some("v1=00")),
            ] {
                assert_eq!(
                    verify_slack(
                        secret.as_bytes(),
                        timestamp,
                        signature,
                        recorded.body(),
                        at(signed_at)
                    ),
                    Err(SignatureFailureV1::Invalid)
                );
            }
        }
    }

    #[test]
    fn the_recorded_linear_deliveries_verify_and_their_signed_clock_is_checked() {
        for fixture in [LINEAR_UPDATE, LINEAR_REMOVE] {
            let recorded = Recorded::new(fixture);
            let secret = recorded.secret().as_bytes();
            let signature = recorded.header("Linear-Signature");
            assert_eq!(verify_linear(secret, signature, recorded.body()), Ok(()));
            assert_eq!(
                verify_linear(secret, signature, &flipped(recorded.body())),
                Err(SignatureFailureV1::Invalid)
            );
            assert_eq!(
                verify_linear(b"lin_wh_EXAMPLENOTTHESECRET", signature, recorded.body()),
                Err(SignatureFailureV1::Invalid)
            );
            assert_eq!(
                verify_linear(secret, None, recorded.body()),
                Err(SignatureFailureV1::Invalid)
            );
            let body: Value = serde_json::from_slice(recorded.body()).unwrap();
            let signed = body["webhookTimestamp"].as_i64().unwrap();
            let now = |millis: i64| Utc.timestamp_millis_opt(millis).unwrap();
            assert_eq!(linear_timestamp_fresh(signed, now(signed)), Ok(()));
            assert_eq!(
                linear_timestamp_fresh(signed, now(signed + LINEAR_WINDOW_MILLIS)),
                Ok(())
            );
            assert_eq!(
                linear_timestamp_fresh(signed, now(signed + LINEAR_WINDOW_MILLIS + 1)),
                Err(SignatureFailureV1::Stale)
            );
            assert_eq!(
                linear_timestamp_fresh(signed, now(signed - LINEAR_WINDOW_MILLIS - 1)),
                Err(SignatureFailureV1::Stale)
            );
        }
    }

    fn granola(
        key: &[u8],
        recorded: &Recorded,
        signature: Option<&str>,
        body: &[u8],
        now: i64,
    ) -> Result<(), SignatureFailureV1> {
        verify_standard_webhooks(
            key,
            StandardWebhookHeadersV1 {
                id: recorded.header("webhook-id"),
                timestamp: recorded.header("webhook-timestamp"),
                signature,
            },
            body,
            at(now),
        )
    }

    #[test]
    fn the_recorded_standard_webhook_verifies_under_its_decoded_secret() {
        let recorded = Recorded::new(GRANOLA_EDITED);
        let key = standard_webhooks_key(recorded.secret()).expect("the whsec_ secret decodes");
        let signature = recorded.header("webhook-signature");
        let signed_at = 1_790_075_101;
        assert_eq!(
            granola(&key, &recorded, signature, recorded.body(), signed_at),
            Ok(())
        );
        assert_eq!(
            granola(
                &key,
                &recorded,
                signature,
                &flipped(recorded.body()),
                signed_at
            ),
            Err(SignatureFailureV1::Invalid)
        );
        assert_eq!(
            granola(
                b"not the key",
                &recorded,
                signature,
                recorded.body(),
                signed_at
            ),
            Err(SignatureFailureV1::Invalid)
        );
        assert_eq!(
            granola(
                &key,
                &recorded,
                signature,
                recorded.body(),
                signed_at + STANDARD_WEBHOOKS_WINDOW_SECONDS + 1
            ),
            Err(SignatureFailureV1::Stale)
        );
        // The raw secret is not the key: it must be decoded.
        assert_eq!(
            granola(
                recorded.secret().as_bytes(),
                &recorded,
                signature,
                recorded.body(),
                signed_at
            ),
            Err(SignatureFailureV1::Invalid)
        );
    }

    #[test]
    fn any_v1_entry_may_match_and_a_malformed_one_is_ignored() {
        let recorded = Recorded::new(GRANOLA_EDITED);
        let key = standard_webhooks_key(recorded.secret()).unwrap();
        let good = recorded.header("webhook-signature").unwrap();
        let tag = good.strip_prefix("v1,").unwrap();
        let signed_at = 1_790_075_101;
        let other = base64::encode(&[7_u8; 32]);
        for header in [
            format!("v1,@@not-base64@@ {good}"),
            format!("v1,{} {good}", &tag[..tag.len() - 1]),
            format!("v1,{other} {good}"),
            format!("v2,{tag} {good}"),
            format!("{good} v1,{other}"),
        ] {
            assert_eq!(
                granola(&key, &recorded, Some(&header), recorded.body(), signed_at),
                Ok(()),
                "{header}"
            );
        }
        for header in [
            format!("v1,@@not-base64@@ v1,{other}"),
            format!("v2,{tag}"),
            format!("v1,{}", &tag[..tag.len() - 1]),
            String::new(),
        ] {
            assert_eq!(
                granola(&key, &recorded, Some(&header), recorded.body(), signed_at),
                Err(SignatureFailureV1::Invalid),
                "{header}"
            );
        }
    }

    #[test]
    fn a_secret_that_does_not_decode_has_no_key() {
        assert!(standard_webhooks_key("whsec_EXAMPLEEXAMPLEEXAMPLEEXAMPLE").is_some());
        assert_eq!(standard_webhooks_key("whsec_"), None);
        assert_eq!(standard_webhooks_key("whsec_not base64"), None);
    }
}
