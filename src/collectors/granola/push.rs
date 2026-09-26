//! Granola webhook deliveries as hints (ADR 0008 D12).
//!
//! Granola signs its webhooks the Standard Webhooks way: `webhook-signature`
//! holds `v1,<base64>` entries of HMAC-SHA256 over
//! `{webhook-id}.{webhook-timestamp}.{body}`, keyed by the base64 after the
//! secret's `whsec_` prefix, within ±300 s
//! ([`crate::collectors::ingress::signature::verify_standard_webhooks`]).
//! Once it verifies:
//!
//! | `event_type` | Maps to |
//! |---|---|
//! | `note.generated`, `note.edited`, `note.access_granted` | upsert the note (its summary and, when read, its transcript) |
//! | anything else | ignored |
//!
//! The payload names no workspace, so the key is the instance's only pin: a
//! delivery signed with it is the instance's. The signed id is the
//! `webhook-id`. A note's deletion or lost access is never a webhook's word:
//! only two complete listings without the note tombstone it.

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::collectors::ingress::signature::{
    StandardWebhookHeadersV1, standard_webhooks_key, verify_standard_webhooks,
};
use crate::collectors::ingress::{
    DeliveryMappingV1, DeliveryRefusalV1, HintKindV1, IngressHintV1, PushRequestV1, PushVerifierV1,
    SigningKeyV1, VerifiedDeliveryV1, event_kind, header, signing_key_from,
};

use super::render::{SUMMARY_OBJECT_KIND, is_note_id};

/// The Granola webhook.
#[derive(Debug, Clone, Copy, Default)]
pub struct GranolaPushV1;

/// The one Granola webhook.
pub static GRANOLA_PUSH: GranolaPushV1 = GranolaPushV1;

/// The event types that mean a note's content or its visibility to the key
/// may have changed.
const UPSERT_EVENTS: [&str; 3] = ["note.generated", "note.edited", "note.access_granted"];

#[derive(Deserialize)]
struct EventV1 {
    event_type: String,
    #[serde(default)]
    note_id: Option<String>,
    #[serde(default)]
    occurred_at: Option<DateTime<Utc>>,
}

impl PushVerifierV1 for GranolaPushV1 {
    fn signing_key(&self, secret: &str) -> Result<SigningKeyV1, String> {
        standard_webhooks_key(secret)
            .map(signing_key_from)
            .ok_or_else(|| {
                "the Granola signing secret is not a whsec_ secret (whsec_ and padded base64)"
                    .to_owned()
            })
    }

    fn accept(&self, request: &PushRequestV1<'_>) -> Result<VerifiedDeliveryV1, DeliveryRefusalV1> {
        let id = header(request.headers, "webhook-id");
        let timestamp = header(request.headers, "webhook-timestamp");
        verify_standard_webhooks(
            request.key.as_bytes(),
            StandardWebhookHeadersV1 {
                id,
                timestamp,
                signature: header(request.headers, "webhook-signature"),
            },
            request.body,
            request.now,
        )?;
        let signed_id = id
            .ok_or(DeliveryRefusalV1::InvalidSignature)?
            .as_bytes()
            .to_vec();
        let event: EventV1 =
            serde_json::from_slice(request.body).map_err(|_| DeliveryRefusalV1::Malformed)?;
        let label = event_kind(&[&event.event_type]);
        if !UPSERT_EVENTS.contains(&event.event_type.as_str()) {
            return Ok(VerifiedDeliveryV1 {
                signed_id,
                event_kind: label,
                mapping: DeliveryMappingV1::Ignored,
            });
        }
        let note = event
            .note_id
            .filter(|note| is_note_id(note))
            .ok_or(DeliveryRefusalV1::Malformed)?;
        let provider_event_at = event
            .occurred_at
            .or_else(|| {
                timestamp
                    .and_then(|seconds| seconds.parse::<i64>().ok())
                    .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
            })
            .ok_or(DeliveryRefusalV1::Malformed)?;
        Ok(VerifiedDeliveryV1 {
            signed_id,
            event_kind: label,
            mapping: DeliveryMappingV1::Hint(IngressHintV1 {
                kind: HintKindV1::Upsert,
                object_kind: SUMMARY_OBJECT_KIND.to_owned(),
                external_id: note,
                container_id: None,
                provider_event_at,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use chrono::TimeZone as _;
    use serde_json::{Value, json};

    use super::*;
    use crate::collectors::ingress::base64;
    use crate::collectors::ingress::signature::sign;

    const EDITED: &str = include_str!("fixtures/webhook_note_updated.json");

    fn recorded() -> Value {
        serde_json::from_str(EDITED).unwrap()
    }

    fn accept(value: &Value, body: &[u8]) -> Result<VerifiedDeliveryV1, DeliveryRefusalV1> {
        let mut headers = HeaderMap::new();
        for (name, value) in value["headers"].as_object().unwrap() {
            headers.insert(
                HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()).unwrap(),
                HeaderValue::from_str(value.as_str().unwrap()).unwrap(),
            );
        }
        let key = GRANOLA_PUSH
            .signing_key(value["signing_secret"].as_str().unwrap())
            .unwrap();
        let signed_at: i64 = value["headers"]["webhook-timestamp"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        GRANOLA_PUSH.accept(&PushRequestV1 {
            headers: &headers,
            body,
            provider_scope_id: "granola.acme",
            key: &key,
            now: Utc.timestamp_opt(signed_at, 0).unwrap(),
        })
    }

    #[test]
    fn the_recorded_edit_is_an_upsert_of_the_note() {
        let value = recorded();
        let delivery = accept(&value, value["raw_body"].as_str().unwrap().as_bytes()).unwrap();
        assert_eq!(delivery.signed_id, b"msg_2mKr8fQxLp7Ta3Vb9Zc1");
        assert_eq!(delivery.event_kind, "note.edited");
        let DeliveryMappingV1::Hint(hint) = delivery.mapping else {
            panic!("expected a hint");
        };
        assert_eq!(hint.kind, HintKindV1::Upsert);
        assert_eq!(hint.object_kind, "note_summary");
        assert_eq!(hint.external_id, "not_1d3tmYTlCICgjy");
        assert_eq!(
            hint.provider_event_at,
            Utc.with_ymd_and_hms(2026, 9, 22, 11, 5, 0).unwrap()
        );
    }

    /// `value` with `body`, signed again under the recorded secret.
    fn resigned(body: &Value) -> (Value, Vec<u8>) {
        let mut value = recorded();
        let body = serde_json::to_vec(body).unwrap();
        let key = standard_webhooks_key(value["signing_secret"].as_str().unwrap()).unwrap();
        let mut message = format!(
            "{}.{}.",
            value["headers"]["webhook-id"].as_str().unwrap(),
            value["headers"]["webhook-timestamp"].as_str().unwrap()
        )
        .into_bytes();
        message.extend_from_slice(&body);
        value["headers"]["webhook-signature"] =
            json!(format!("v1,{}", base64::encode(&sign(&key, &message))));
        (value, body)
    }

    #[test]
    fn other_events_are_ignored_and_a_bad_note_id_refused() {
        let (value, body) = resigned(&json!({"event_type": "calendar.synced", "note_id": null}));
        assert_eq!(
            accept(&value, &body).unwrap().mapping,
            DeliveryMappingV1::Ignored
        );
        let (value, body) = resigned(&json!({"event_type": "note.generated", "note_id": "fol_1"}));
        assert_eq!(accept(&value, &body), Err(DeliveryRefusalV1::Malformed));
    }

    #[test]
    fn a_secret_without_a_decodable_key_is_refused() {
        assert!(GRANOLA_PUSH.signing_key("whsec_not base64").is_err());
        assert!(
            GRANOLA_PUSH
                .signing_key("whsec_EXAMPLEEXAMPLEEXAMPLEEXAMPLE")
                .is_ok()
        );
    }
}
