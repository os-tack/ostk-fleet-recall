//! Linear webhook deliveries as hints (ADR 0008 D12).
//!
//! Linear signs the raw body with the webhook's secret (`Linear-Signature`,
//! hex HMAC-SHA256) and puts its own clock inside the signed body
//! (`webhookTimestamp`, milliseconds), which must be within ±60 s
//! ([`crate::collectors::ingress::signature`]). Once both hold, the body's
//! `organizationId` must be the instance's pin, and:
//!
//! | Delivery | Maps to |
//! |---|---|
//! | `Issue` or `Comment`, `create` or `update` | upsert the issue or comment by its id |
//! | `Issue` or `Comment`, `remove` | delete it, at the signed `webhookTimestamp` |
//! | anything else | ignored |
//!
//! The signed id is the digest of the body: the `Linear-Delivery` header is
//! not signed, so it is never trusted as identity. The data's text (a title,
//! a body) is never kept; the worker re-reads the object through the API.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::collectors::ingress::signature::{linear_timestamp_fresh, verify_linear};
use crate::collectors::ingress::{
    DeliveryMappingV1, DeliveryRefusalV1, HintKindV1, IngressHintV1, PushRequestV1, PushVerifierV1,
    VerifiedDeliveryV1, event_kind, header,
};

use super::render::{COMMENT_OBJECT_KIND, ISSUE_OBJECT_KIND, is_linear_id};

/// The Linear webhook.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinearPushV1;

/// The one Linear webhook.
pub static LINEAR_PUSH: LinearPushV1 = LinearPushV1;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeliveryV1 {
    action: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    organization_id: Option<String>,
    webhook_timestamp: i64,
    #[serde(default)]
    data: Option<DataV1>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DataV1 {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
}

impl PushVerifierV1 for LinearPushV1 {
    fn accept(&self, request: &PushRequestV1<'_>) -> Result<VerifiedDeliveryV1, DeliveryRefusalV1> {
        verify_linear(
            request.key.as_bytes(),
            header(request.headers, "linear-signature"),
            request.body,
        )?;
        let delivery: DeliveryV1 =
            serde_json::from_slice(request.body).map_err(|_| DeliveryRefusalV1::Malformed)?;
        linear_timestamp_fresh(delivery.webhook_timestamp, request.now)?;
        if !delivery
            .organization_id
            .as_deref()
            .is_some_and(|organization| {
                organization.eq_ignore_ascii_case(request.provider_scope_id)
            })
        {
            return Err(DeliveryRefusalV1::UnauthorizedScope);
        }
        let signed_id = Sha256::digest(request.body).to_vec();
        let label = event_kind(&[&delivery.kind, &delivery.action]);
        let object_kind = match delivery.kind.as_str() {
            "Issue" => ISSUE_OBJECT_KIND,
            "Comment" => COMMENT_OBJECT_KIND,
            _ => {
                return Ok(VerifiedDeliveryV1 {
                    signed_id,
                    event_kind: label,
                    mapping: DeliveryMappingV1::Ignored,
                });
            }
        };
        let kind = match delivery.action.as_str() {
            "create" | "update" => HintKindV1::Upsert,
            "remove" => HintKindV1::Delete,
            _ => {
                return Ok(VerifiedDeliveryV1 {
                    signed_id,
                    event_kind: label,
                    mapping: DeliveryMappingV1::Ignored,
                });
            }
        };
        let data = delivery.data.ok_or(DeliveryRefusalV1::Malformed)?;
        let id = data
            .id
            .filter(|id| is_linear_id(id))
            .ok_or(DeliveryRefusalV1::Malformed)?;
        let provider_event_at = DateTime::<Utc>::from_timestamp_millis(delivery.webhook_timestamp)
            .ok_or(DeliveryRefusalV1::Malformed)?;
        Ok(VerifiedDeliveryV1 {
            signed_id,
            event_kind: label,
            mapping: DeliveryMappingV1::Hint(IngressHintV1 {
                kind,
                object_kind: object_kind.to_owned(),
                external_id: id,
                // A comment's container is its issue's team, which the
                // delivery does not name; the worker reads it.
                container_id: (object_kind == ISSUE_OBJECT_KIND)
                    .then_some(data.team_id)
                    .flatten()
                    .filter(|team| is_linear_id(team)),
                provider_event_at,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};
    use chrono::TimeZone as _;
    use serde_json::{Value, json};

    use super::*;
    use crate::collectors::ingress::signature::sign;
    use crate::collectors::ingress::signing_key_from;

    const UPDATE: &str = include_str!("fixtures/webhook_issue_update.json");
    const REMOVE: &str = include_str!("fixtures/webhook_comment_remove.json");
    const ORG: &str = "0a9c0000-0000-4000-8000-0000000ac3e1";
    const SECRET: &str = "lin_wh_EXAMPLENOTASIGNINGSECRET";

    fn accept_body(
        body: &[u8],
        signature: &str,
        pin: &str,
        now_millis: i64,
    ) -> Result<VerifiedDeliveryV1, DeliveryRefusalV1> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "linear-signature",
            HeaderValue::from_str(signature).unwrap(),
        );
        let key = signing_key_from(SECRET.as_bytes().to_vec());
        LINEAR_PUSH.accept(&PushRequestV1 {
            headers: &headers,
            body,
            provider_scope_id: pin,
            key: &key,
            now: Utc.timestamp_millis_opt(now_millis).unwrap(),
        })
    }

    fn accept_fixture(fixture: &str, pin: &str) -> Result<VerifiedDeliveryV1, DeliveryRefusalV1> {
        let value: Value = serde_json::from_str(fixture).unwrap();
        assert_eq!(value["signing_secret"], SECRET);
        let body = value["raw_body"].as_str().unwrap();
        let signed: Value = serde_json::from_str(body).unwrap();
        accept_body(
            body.as_bytes(),
            value["headers"]["Linear-Signature"].as_str().unwrap(),
            pin,
            signed["webhookTimestamp"].as_i64().unwrap(),
        )
    }

    fn hint(delivery: &VerifiedDeliveryV1) -> &IngressHintV1 {
        match &delivery.mapping {
            DeliveryMappingV1::Hint(hint) => hint,
            other => panic!("expected a hint, got {other:?}"),
        }
    }

    #[test]
    fn the_recorded_issue_update_is_an_upsert_of_the_issue_in_its_team() {
        let delivery = accept_fixture(UPDATE, ORG).unwrap();
        assert_eq!(delivery.event_kind, "Issue.update");
        assert_eq!(delivery.signed_id.len(), 32, "the body's digest");
        let hint = hint(&delivery);
        assert_eq!(hint.kind, HintKindV1::Upsert);
        assert_eq!(hint.object_kind, "issue");
        assert_eq!(hint.external_id, "7c3e1a52-9b4d-4f6e-8a21-3d5c7e9f1b20");
        assert_eq!(
            hint.container_id.as_deref(),
            Some("4e6b8d0f-1a2b-4c3d-9e8f-7a6b5c4d3e2f")
        );
    }

    #[test]
    fn the_recorded_comment_removal_is_a_delete_at_the_signed_time() {
        let delivery = accept_fixture(REMOVE, ORG).unwrap();
        let hint = hint(&delivery);
        assert_eq!(hint.kind, HintKindV1::Delete);
        assert_eq!(hint.object_kind, "comment");
        assert_eq!(hint.external_id, "d4e5f6a7-0000-4000-8000-00000000c002");
        assert_eq!(hint.container_id, None);
        assert_eq!(hint.provider_event_at.timestamp_millis(), 1_790_071_200_250);
    }

    #[test]
    fn another_organization_is_refused_and_other_types_ignored() {
        assert_eq!(
            accept_fixture(UPDATE, "1b2c0000-0000-4000-8000-000000000bad"),
            Err(DeliveryRefusalV1::UnauthorizedScope)
        );
        let now = 1_790_070_067_400_i64;
        for (body, expected) in [
            (
                json!({"action": "create", "type": "Reaction", "organizationId": ORG,
                       "webhookTimestamp": now, "data": {"id": "r1"}}),
                Ok(DeliveryMappingV1::Ignored),
            ),
            (
                json!({"action": "restore", "type": "Issue", "organizationId": ORG,
                       "webhookTimestamp": now, "data": {"id": "i1"}}),
                Ok(DeliveryMappingV1::Ignored),
            ),
            (
                json!({"action": "update", "type": "Issue", "organizationId": ORG,
                       "webhookTimestamp": now, "data": {"id": "not an id!"}}),
                Err(DeliveryRefusalV1::Malformed),
            ),
            (
                json!({"action": "update", "type": "Issue", "webhookTimestamp": now,
                       "data": {"id": "i1"}}),
                Err(DeliveryRefusalV1::UnauthorizedScope),
            ),
            (
                json!({"action": "update", "type": "Issue", "organizationId": ORG,
                       "webhookTimestamp": now - 61_000, "data": {"id": "i1"}}),
                Err(DeliveryRefusalV1::StaleSignature),
            ),
        ] {
            let body = serde_json::to_vec(&body).unwrap();
            let signature = hex::encode(sign(SECRET.as_bytes(), &body));
            assert_eq!(
                accept_body(&body, &signature, ORG, now).map(|delivery| delivery.mapping),
                expected
            );
        }
    }
}
