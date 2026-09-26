//! Slack Events API deliveries as hints (ADR 0008 D12).
//!
//! Every request is signed with the app's signing secret
//! (`X-Slack-Signature` over `v0:{timestamp}:{body}`, ±300 s;
//! [`crate::collectors::ingress::signature::verify_slack`]). Once it verifies:
//!
//! | Delivery | Maps to |
//! |---|---|
//! | `url_verification` | the challenge, echoed |
//! | `event_callback` of another `team_id` than the pin | refused, `unauthorized_scope` |
//! | a `message` in an `im` or `mpim` (or a `D...` channel) | ignored, stored with no ids |
//! | `message` (no subtype), `thread_broadcast`, `bot_message`, `file_share`, `me_message` | upsert `<channel>:<ts>` |
//! | `message_changed` | upsert `<channel>:<message.ts>` |
//! | `message_deleted` | delete `<channel>:<deleted_ts>`, at the event's `event_ts` |
//! | anything else | ignored |
//!
//! The signed id is the delivery's `event_id` (the digest of the body for a
//! `url_verification`, which has none), so Slack's retries of one event are
//! one row. Slack's legacy verification `token` in the body is never read.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::collectors::ingress::signature::verify_slack;
use crate::collectors::ingress::{
    DeliveryMappingV1, DeliveryRefusalV1, HintKindV1, IngressHintV1, MAX_HINT_CONTAINER_ID_BYTES,
    PushRequestV1, PushVerifierV1, VerifiedDeliveryV1, event_kind, header,
};

use super::render::{ITEM_SUBTYPES, MESSAGE_OBJECT_KIND, SlackTsV1, message_external_id};

/// The Slack webhook.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlackPushV1;

/// The one Slack webhook.
pub static SLACK_PUSH: SlackPushV1 = SlackPushV1;

/// Longest challenge echoed.
const MAX_CHALLENGE_BYTES: usize = 256;

/// Longest `event_id` taken as the signed id.
const MAX_EVENT_ID_BYTES: usize = 64;

#[derive(Deserialize)]
struct EnvelopeV1 {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    team_id: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
    #[serde(default)]
    event_time: Option<i64>,
    #[serde(default)]
    challenge: Option<String>,
    #[serde(default)]
    event: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct InnerMessageV1 {
    #[serde(default)]
    ts: Option<String>,
}

#[derive(Deserialize)]
struct EventV1 {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    subtype: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    channel_type: Option<String>,
    #[serde(default)]
    ts: Option<String>,
    #[serde(default)]
    event_ts: Option<String>,
    #[serde(default)]
    deleted_ts: Option<String>,
    #[serde(default)]
    message: Option<InnerMessageV1>,
}

/// Whether `value` is a Slack channel id: upper-case letters and digits.
fn is_channel_id(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= MAX_HINT_CONTAINER_ID_BYTES.min(32)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn micros_instant(micros: u64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp_micros(i64::try_from(micros).ok()?)
}

/// When the event happened: its `event_ts`, else its `ts`, else the
/// envelope's `event_time`.
fn event_instant(event: &EventV1, event_time: Option<i64>) -> Option<DateTime<Utc>> {
    event
        .event_ts
        .as_deref()
        .or(event.ts.as_deref())
        .and_then(SlackTsV1::parse)
        .and_then(|ts| micros_instant(ts.micros()))
        .or_else(|| event_time.and_then(|seconds| DateTime::from_timestamp(seconds, 0)))
}

/// Map one `event_callback`'s event.
fn map_event(
    event: &EventV1,
    event_time: Option<i64>,
) -> Result<(String, DeliveryMappingV1), DeliveryRefusalV1> {
    if event.kind != "message" {
        return Ok((
            event_kind(&["event", &event.kind]),
            DeliveryMappingV1::Ignored,
        ));
    }
    let subtype = event.subtype.as_deref();
    let label = event_kind(&["message", subtype.unwrap_or("")]);
    let direct = matches!(event.channel_type.as_deref(), Some("im" | "mpim"))
        || event
            .channel
            .as_deref()
            .is_some_and(|channel| channel.starts_with('D'));
    if direct {
        // Never listed, fetched, or staged: kept only so its replay is
        // recognized, with no channel, no ts, and no event time.
        return Ok((label, DeliveryMappingV1::Ignored));
    }
    let (kind, ts) = match subtype {
        None => (HintKindV1::Upsert, event.ts.as_deref()),
        Some(subtype) if ITEM_SUBTYPES.contains(&subtype) => {
            (HintKindV1::Upsert, event.ts.as_deref())
        }
        Some("message_changed") => (
            HintKindV1::Upsert,
            event
                .message
                .as_ref()
                .and_then(|message| message.ts.as_deref()),
        ),
        Some("message_deleted") => (HintKindV1::Delete, event.deleted_ts.as_deref()),
        Some(_) => return Ok((label, DeliveryMappingV1::Ignored)),
    };
    let channel = event
        .channel
        .as_deref()
        .filter(|channel| is_channel_id(channel))
        .ok_or(DeliveryRefusalV1::Malformed)?;
    let ts = ts
        .and_then(SlackTsV1::parse)
        .ok_or(DeliveryRefusalV1::Malformed)?;
    let provider_event_at = event_instant(event, event_time).ok_or(DeliveryRefusalV1::Malformed)?;
    Ok((
        label,
        DeliveryMappingV1::Hint(IngressHintV1 {
            kind,
            object_kind: MESSAGE_OBJECT_KIND.to_owned(),
            external_id: message_external_id(channel, ts.as_str()),
            container_id: Some(channel.to_owned()),
            provider_event_at,
        }),
    ))
}

impl PushVerifierV1 for SlackPushV1 {
    fn accept(&self, request: &PushRequestV1<'_>) -> Result<VerifiedDeliveryV1, DeliveryRefusalV1> {
        verify_slack(
            request.key.as_bytes(),
            header(request.headers, "x-slack-request-timestamp"),
            header(request.headers, "x-slack-signature"),
            request.body,
            request.now,
        )?;
        let envelope: EnvelopeV1 =
            serde_json::from_slice(request.body).map_err(|_| DeliveryRefusalV1::Malformed)?;
        let body_digest = Sha256::digest(request.body).to_vec();
        match envelope.kind.as_str() {
            "url_verification" => {
                let challenge = envelope
                    .challenge
                    .filter(|challenge| {
                        !challenge.is_empty()
                            && challenge.len() <= MAX_CHALLENGE_BYTES
                            && challenge.bytes().all(|byte| byte.is_ascii_graphic())
                    })
                    .ok_or(DeliveryRefusalV1::Malformed)?;
                Ok(VerifiedDeliveryV1 {
                    signed_id: body_digest,
                    event_kind: event_kind(&["url_verification"]),
                    mapping: DeliveryMappingV1::Challenge(challenge),
                })
            }
            "event_callback" => {
                if envelope.team_id.as_deref() != Some(request.provider_scope_id) {
                    return Err(DeliveryRefusalV1::UnauthorizedScope);
                }
                let event_id = envelope
                    .event_id
                    .filter(|id| {
                        !id.is_empty()
                            && id.len() <= MAX_EVENT_ID_BYTES
                            && id.bytes().all(|byte| byte.is_ascii_alphanumeric())
                    })
                    .ok_or(DeliveryRefusalV1::Malformed)?;
                let event: EventV1 = envelope
                    .event
                    .and_then(|event| serde_json::from_value(event).ok())
                    .ok_or(DeliveryRefusalV1::Malformed)?;
                let (label, mapping) = map_event(&event, envelope.event_time)?;
                Ok(VerifiedDeliveryV1 {
                    signed_id: event_id.into_bytes(),
                    event_kind: label,
                    mapping,
                })
            }
            other => {
                // Rate-limit notices and anything newer: signed, but nothing
                // the collectors read.
                if envelope
                    .team_id
                    .as_deref()
                    .is_some_and(|team| team != request.provider_scope_id)
                {
                    return Err(DeliveryRefusalV1::UnauthorizedScope);
                }
                Ok(VerifiedDeliveryV1 {
                    signed_id: body_digest,
                    event_kind: event_kind(&[other]),
                    mapping: DeliveryMappingV1::Ignored,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use chrono::TimeZone as _;
    use serde_json::{Value, json};

    use super::*;
    use crate::collectors::ingress::signature::sign;
    use crate::collectors::ingress::signing_key_from;

    const CHANGED: &str = include_str!("fixtures/event_message_changed.json");
    const DELETED: &str = include_str!("fixtures/event_message_deleted.json");
    const TEAM: &str = "T07ACME0001";
    const SECRET: &str = "EXAMPLE-NOT-A-SIGNING-SECRET";

    fn headers(value: &Value) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in value["headers"].as_object().unwrap() {
            headers.insert(
                HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()).unwrap(),
                HeaderValue::from_str(value.as_str().unwrap()).unwrap(),
            );
        }
        headers
    }

    fn accept_fixture(fixture: &str, pin: &str) -> Result<VerifiedDeliveryV1, DeliveryRefusalV1> {
        let value: Value = serde_json::from_str(fixture).unwrap();
        let signed_at: i64 = value["headers"]["X-Slack-Request-Timestamp"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let key = signing_key_from(
            value["signing_secret"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
        );
        SLACK_PUSH.accept(&PushRequestV1 {
            headers: &headers(&value),
            body: value["raw_body"].as_str().unwrap().as_bytes(),
            provider_scope_id: pin,
            key: &key,
            now: Utc.timestamp_opt(signed_at, 0).unwrap(),
        })
    }

    /// A body signed now with the test secret.
    fn signed(body: &Value) -> (HeaderMap, Vec<u8>, DateTime<Utc>) {
        let now = Utc.timestamp_opt(1_790_008_201, 0).unwrap();
        let body = serde_json::to_vec(body).unwrap();
        let timestamp = now.timestamp().to_string();
        let mut message = format!("v0:{timestamp}:").into_bytes();
        message.extend_from_slice(&body);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-slack-request-timestamp",
            HeaderValue::from_str(&timestamp).unwrap(),
        );
        headers.insert(
            "x-slack-signature",
            HeaderValue::from_str(&format!(
                "v0={}",
                hex::encode(sign(SECRET.as_bytes(), &message))
            ))
            .unwrap(),
        );
        (headers, body, now)
    }

    fn accept(body: &Value) -> Result<VerifiedDeliveryV1, DeliveryRefusalV1> {
        let (headers, body, now) = signed(body);
        let key = signing_key_from(SECRET.as_bytes().to_vec());
        SLACK_PUSH.accept(&PushRequestV1 {
            headers: &headers,
            body: &body,
            provider_scope_id: TEAM,
            key: &key,
            now,
        })
    }

    fn callback(event: &Value) -> Value {
        json!({"type": "event_callback", "team_id": TEAM, "event_id": "Ev07TEST0001",
               "event_time": 1_790_008_200, "event": event})
    }

    fn hint(delivery: &VerifiedDeliveryV1) -> &IngressHintV1 {
        match &delivery.mapping {
            DeliveryMappingV1::Hint(hint) => hint,
            other => panic!("expected a hint, got {other:?}"),
        }
    }

    #[test]
    fn the_recorded_edit_is_an_upsert_of_the_edited_message() {
        let delivery = accept_fixture(CHANGED, TEAM).unwrap();
        assert_eq!(delivery.signed_id, b"Ev07CHG00001");
        assert_eq!(delivery.event_kind, "message.message_changed");
        let hint = hint(&delivery);
        assert_eq!(hint.kind, HintKindV1::Upsert);
        assert_eq!(hint.object_kind, "message");
        assert_eq!(hint.external_id, "C07PLATENG1:1790006860.001100");
        assert_eq!(hint.container_id.as_deref(), Some("C07PLATENG1"));
        assert_eq!(
            hint.provider_event_at.timestamp_micros(),
            1_790_008_200_000_300
        );
    }

    #[test]
    fn the_recorded_deletion_is_a_delete_at_the_event_time() {
        let delivery = accept_fixture(DELETED, TEAM).unwrap();
        let hint = hint(&delivery);
        assert_eq!(hint.kind, HintKindV1::Delete);
        assert_eq!(hint.external_id, "C07PLATENG1:1790011800.000900");
        assert_eq!(
            hint.provider_event_at.timestamp_micros(),
            1_790_064_000_000_100
        );
    }

    #[test]
    fn another_team_is_refused_as_unauthorized_scope() {
        assert_eq!(
            accept_fixture(CHANGED, "T07OTHER001"),
            Err(DeliveryRefusalV1::UnauthorizedScope)
        );
    }

    #[test]
    fn new_messages_and_broadcasts_are_upserts_and_direct_messages_are_ignored_without_ids() {
        for subtype in [None, Some("thread_broadcast"), Some("bot_message")] {
            let mut event = json!({"type": "message", "channel": "C07PLATENG1",
                                   "channel_type": "channel", "ts": "1790008100.000100",
                                   "event_ts": "1790008100.000100", "text": "retry budget"});
            if let Some(subtype) = subtype {
                event["subtype"] = json!(subtype);
            }
            let delivery = accept(&callback(&event)).unwrap();
            assert_eq!(hint(&delivery).external_id, "C07PLATENG1:1790008100.000100");
        }
        for (channel, channel_type) in [("D07DIRECT01", "im"), ("G07GROUP001", "mpim")] {
            let event = json!({"type": "message", "channel": channel, "channel_type": channel_type,
                               "ts": "1790008100.000100", "text": "private words"});
            let delivery = accept(&callback(&event)).unwrap();
            assert_eq!(delivery.mapping, DeliveryMappingV1::Ignored);
            assert!(!delivery.event_kind.contains(channel));
        }
        for event in [
            json!({"type": "message", "subtype": "channel_join", "channel": "C07PLATENG1",
                   "ts": "1790008100.000100"}),
            json!({"type": "reaction_added", "item": {"channel": "C07PLATENG1"}}),
        ] {
            assert_eq!(
                accept(&callback(&event)).unwrap().mapping,
                DeliveryMappingV1::Ignored
            );
        }
    }

    #[test]
    fn a_url_verification_is_echoed_and_a_malformed_event_refused() {
        let delivery = accept(&json!({"type": "url_verification",
                                      "challenge": "EXAMPLE-CHALLENGE-NOT-A-SECRET"}))
        .unwrap();
        assert_eq!(
            delivery.mapping,
            DeliveryMappingV1::Challenge("EXAMPLE-CHALLENGE-NOT-A-SECRET".to_owned())
        );
        for body in [
            json!({"type": "url_verification"}),
            callback(&json!({"type": "message", "channel": "C07PLATENG1", "ts": "1.5"})),
            callback(&json!({"type": "message", "channel": "general", "ts": "1790008100.000100"})),
            json!({"type": "event_callback", "team_id": TEAM,
                   "event": {"type": "message", "channel": "C07PLATENG1", "ts": "1790008100.000100"}}),
        ] {
            assert_eq!(accept(&body), Err(DeliveryRefusalV1::Malformed), "{body}");
        }
    }
}
