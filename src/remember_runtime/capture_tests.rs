use std::collections::{BTreeMap, HashMap};

use ostk_recall_core::PrivacyTier;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use super::*;

fn item(extra: &Value) -> CollectedItemInputV1 {
    let mut base = json!({
        "provider": "slack",
        "provider_scope_id": "T07ACME0001",
        "object_kind": "message",
        "external_id": "C07PLATENG1:1790006860.001100",
        "container": {"kind": "slack.channel", "id": "C07PLATENG1"},
        "updated_at": "2026-09-20T10:00:00Z",
        "text": "the retry budget is five",
        "url": "https://acme.slack.com/archives/C07PLATENG1/p1790006860001100",
    });
    for (name, value) in extra.as_object().expect("an object of overrides") {
        if value.is_null() {
            base.as_object_mut().unwrap().remove(name);
        } else {
            base[name] = value.clone();
        }
    }
    CollectedItemInputV1::parse(base.to_string().as_bytes()).expect("a collected-item input")
}

fn request(items: Vec<CollectedItemInputV1>) -> CaptureRequestV1 {
    CaptureRequestV1 { items, via: None }
}

fn refusal(request: &CaptureRequestV1) -> String {
    PreparedCaptureV1::prepare(request).expect_err("the request is refused")
}

#[test]
fn a_contract_id_agent_captures_under_its_own_name() {
    let identity = CaptureIdentityV1::for_agent("agent-a").unwrap();
    assert_eq!(identity.principal.as_str(), "agent.agent-a");
    assert_eq!(identity.instance.as_str(), "capture.agent-a");
    // The same principal the event-first assert attributes to.
    assert_eq!(
        identity.principal,
        crate::remember_runtime::actor_for_agent("agent-a").unwrap()
    );
}

#[test]
fn any_other_agent_name_is_sanitized_and_suffixed_with_its_digest() {
    let upper = CaptureIdentityV1::for_agent("Agent A").unwrap();
    let lower = CaptureIdentityV1::for_agent("agent-a").unwrap();
    assert!(upper.principal.as_str().starts_with("agent.agent-a."));
    assert_eq!(
        upper.principal.as_str().len(),
        "agent.agent-a.".len() + CAPTURE_AGENT_DIGEST_HEX
    );
    // Two agents never share a principal, however alike their names read.
    assert_ne!(upper, lower);
    assert_ne!(
        CaptureIdentityV1::for_agent("Agent A").unwrap(),
        CaptureIdentityV1::for_agent("AGENT A").unwrap()
    );
    let long = "a".repeat(300);
    let identity = CaptureIdentityV1::for_agent(&long).unwrap();
    assert!(identity.instance.as_str().len() <= 128);
    assert!(identity.principal.as_str().len() <= 128);
    let unicode = CaptureIdentityV1::for_agent("agént").unwrap();
    assert!(unicode.instance.as_str().starts_with("capture.ag-nt."));
    assert!(CaptureIdentityV1::for_agent("").is_err());
}

#[test]
fn a_capture_request_is_checked_before_any_io() {
    let prepared = PreparedCaptureV1::prepare(&request(vec![item(&json!({}))])).unwrap();
    assert_eq!(prepared.items.len(), 1);
    assert_eq!(prepared.items[0].delivery_id.len(), 36);

    assert!(refusal(&request(Vec::new())).contains("1 to 32 items"));
    assert!(refusal(&request(vec![item(&json!({})); MAX_CAPTURE_ITEMS + 1])).contains("33"));
    for (overrides, expected) in [
        (json!({"url": null}), "url is required"),
        (json!({"url": "http://acme.example/x"}), "https"),
        (json!({"text": "  "}), "text is required"),
        (
            json!({"text": "x".repeat(MAX_CAPTURE_TEXT_BYTES + 1)}),
            "at most 262144 bytes",
        ),
        (json!({"lifecycle": "deleted", "text": ""}), "deletion"),
        (json!({"lifecycle": "revoked"}), "deletion"),
        (json!({"provider_scope_id": ""}), "provider_scope_id"),
        (
            json!({"provider_scope_id": "xoxb-EXAMPLE-NOT-A-TOKEN"}),
            "secret shape",
        ),
        (
            json!({"updated_at": null}),
            "an item needs version.order_micros, updated_at, or created_at",
        ),
        (json!({"updated_at": "yesterday"}), "updated_at"),
    ] {
        let message = refusal(&request(vec![item(&json!({})), item(&overrides)]));
        assert!(message.starts_with("items[1]: "), "{message}");
        assert!(message.contains(expected), "{overrides}: {message}");
    }
    let via = |via: &str| CaptureRequestV1 {
        items: vec![item(&json!({}))],
        via: Some(via.to_owned()),
    };
    assert!(refusal(&via(" ")).contains("via"));
    assert!(refusal(&via(&"v".repeat(257))).contains("via"));
    assert!(PreparedCaptureV1::prepare(&via("slack.conversations_history")).is_ok());
    // An edited or archived item is captured like a live one.
    assert!(
        PreparedCaptureV1::prepare(&request(vec![item(&json!({"lifecycle": "edited"}))])).is_ok()
    );
}

#[test]
fn the_request_digest_covers_every_item_and_the_tool_label() {
    let digest = |request: &CaptureRequestV1| {
        PreparedCaptureV1::prepare(request)
            .unwrap()
            .request_digest()
    };
    let base = request(vec![item(&json!({}))]);
    assert_eq!(digest(&base), digest(&base.clone()));
    assert_ne!(
        digest(&base),
        digest(&request(vec![item(
            &json!({"text": "the retry budget is six"})
        )]))
    );
    assert_ne!(
        digest(&base),
        digest(&CaptureRequestV1 {
            via: Some("slack.read".into()),
            ..base.clone()
        })
    );
    // The receipt keeps the digest and the trusted scope, never the text.
    let scope = FleetScope::new(
        Uuid::now_v7(),
        "project",
        "agent-a",
        None,
        PrivacyTier::T1Project,
    )
    .unwrap();
    let receipt = capture_request(&scope, &digest(&base)).to_string();
    assert!(!receipt.contains("retry budget"), "{receipt}");
    assert!(receipt.contains(&digest(&base).to_string()), "{receipt}");
}

#[test]
fn items_are_grouped_by_provider_scope_in_order() {
    let prepared = PreparedCaptureV1::prepare(&request(vec![
        item(&json!({})),
        item(&json!({
            "provider": "linear",
            "provider_scope_id": "acme",
            "object_kind": "issue",
            "external_id": "c3d4",
            "container": null,
        })),
        item(&json!({"external_id": "C07PLATENG1:1790006861.000100"})),
    ]))
    .unwrap();
    let groups: Vec<(String, Vec<usize>)> = prepared
        .groups()
        .into_iter()
        .map(|((provider, scope), indices)| (format!("{provider}/{scope}"), indices))
        .collect();
    assert_eq!(
        groups,
        [
            ("slack/T07ACME0001".to_owned(), vec![0, 2]),
            ("linear/acme".to_owned(), vec![1]),
        ]
    );
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn provisional_item(stage_ids: &[u8], already_admitted: bool) -> ProvisionalItemV1 {
    ProvisionalItemV1 {
        item_id: digest(0x01),
        version_id: Some(digest(0x02)),
        uri: Some("urn:ostk:version:v1:collected_item_version:sha256:00".into()),
        stage_ids: stage_ids.iter().map(|byte| digest(*byte)).collect(),
        already_admitted,
        withheld_reason: None,
        redacted_ranges: 1,
    }
}

#[test]
fn each_item_is_settled_from_its_rows() {
    let provisional = ProvisionalCaptureV1 {
        schema_version: PROVISIONAL_SCHEMA_VERSION,
        items: vec![
            provisional_item(&[0x10, 0x11], false),
            provisional_item(&[0x20], true),
            provisional_item(&[0x30, 0x31], false),
            provisional_item(&[0x40], false),
            provisional_item(&[0x50], false),
            ProvisionalItemV1 {
                version_id: None,
                uri: None,
                stage_ids: Vec::new(),
                withheld_reason: Some("audience_unverified".into()),
                redacted_ranges: 0,
                ..provisional_item(&[], false)
            },
        ],
    };
    let states = BTreeMap::from([
        (digest(0x10), OutboxRowStateV1::Admitted(digest(0xa0))),
        (digest(0x11), OutboxRowStateV1::Admitted(digest(0xa1))),
        (digest(0x20), OutboxRowStateV1::Admitted(digest(0xb0))),
        (digest(0x30), OutboxRowStateV1::Admitted(digest(0xc0))),
        (digest(0x31), OutboxRowStateV1::Pending),
        (digest(0x40), OutboxRowStateV1::DeadLettered),
        (digest(0x50), OutboxRowStateV1::Quarantined),
    ]);
    let settled = settle(&provisional, &states);
    assert_eq!(settled.operation, "capture");
    assert!(!settled.idempotent_replay);
    let summary: Vec<(CaptureDispositionV1, Option<&str>, usize)> = settled
        .items
        .iter()
        .map(|item| {
            (
                item.disposition,
                item.withheld_reason.as_deref(),
                item.accepted_event_ids.len(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (CaptureDispositionV1::Admitted, None, 2),
            (CaptureDispositionV1::Replayed, None, 1),
            (CaptureDispositionV1::Staged, None, 1),
            (CaptureDispositionV1::Withheld, Some("admission_refused"), 0),
            (CaptureDispositionV1::Withheld, Some("quarantined"), 0),
            (
                CaptureDispositionV1::Withheld,
                Some("audience_unverified"),
                0
            ),
        ]
    );
    // Event ids follow part order.
    assert_eq!(
        settled.items[0].accepted_event_ids,
        [digest(0xa0), digest(0xa1)]
    );
    // An item already admitted when captured, then read pending (impossible,
    // but never claimed admitted): staged.
    let pending = settle(
        &ProvisionalCaptureV1 {
            schema_version: PROVISIONAL_SCHEMA_VERSION,
            items: vec![provisional_item(&[0x60], true)],
        },
        &BTreeMap::new(),
    );
    assert_eq!(pending.items[0].disposition, CaptureDispositionV1::Staged);
}

#[test]
fn an_audience_refusal_is_withheld_under_its_own_label() {
    assert_eq!(
        withheld_reason(DeadLetterReasonV1::AudienceRefused, "audience_unverified"),
        "audience_unverified"
    );
    assert_eq!(
        withheld_reason(DeadLetterReasonV1::RedactionWithheld, "a static diagnostic"),
        "redaction_withheld"
    );
}

#[test]
fn a_replay_is_the_stored_response_marked_as_a_replay() {
    let stored = serde_json::to_value(CaptureResponseV1 {
        operation: "capture".into(),
        items: Vec::new(),
        idempotent_replay: false,
    })
    .unwrap();
    let outcome = replayed(stored.clone());
    assert!(outcome.replayed);
    let mut expected = stored;
    expected["idempotent_replay"] = json!(true);
    assert_eq!(outcome.response, expected);
}

#[test]
fn a_provisional_response_round_trips_and_is_told_apart_from_a_final_one() {
    let provisional = ProvisionalCaptureV1 {
        schema_version: PROVISIONAL_SCHEMA_VERSION,
        items: vec![provisional_item(&[0x10], false)],
    };
    let value = provisional.to_value().unwrap();
    let decoded: ProvisionalCaptureV1 =
        serde_json::from_value(value["provisional"].clone()).unwrap();
    assert_eq!(decoded, provisional);
    assert_eq!(decoded.stage_ids(), [digest(0x10)]);
}

// ---------------------------------------------------------------------------
// Startup decisions made before any I/O
// ---------------------------------------------------------------------------

/// A pool that fails any use: every case here must decide before I/O.
fn unreachable_pool() -> PgPool {
    PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy("postgresql://root@127.0.0.1:1/unreachable")
        .unwrap()
}

fn capabilities(schema_version: i64) -> DatabaseCapabilities {
    DatabaseCapabilities {
        version: "CockroachDB CCL v26.2.3".into(),
        vector_index_enabled: true,
        lexical_index_enabled: true,
        conflict_membership_index_enabled: true,
        claim_support_chunk_index_enabled: true,
        cosine_distance_supported: true,
        schema_version,
    }
}

async fn start(schema_version: i64, variables: &[(&str, &str)]) -> CaptureStartup {
    let variables: HashMap<String, String> = variables
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    let scope = FleetScope::new(
        Uuid::now_v7(),
        "project",
        "agent-a",
        None,
        PrivacyTier::T1Project,
    )
    .unwrap();
    start_collected_capture_with(
        unreachable_pool(),
        &capabilities(schema_version),
        &scope,
        RetryPolicy::default(),
        |name| variables.get(name).cloned(),
    )
    .await
}

fn off(startup: CaptureStartup) -> CaptureStatusV1 {
    let CaptureStartup::Off(status) = startup else {
        panic!("expected capture off, got {startup:?}");
    };
    assert!(!status.served);
    assert!(status.identity.is_none());
    status
}

#[tokio::test]
async fn capture_is_not_configured_unless_switched_on() {
    assert!(matches!(
        start(34, &[]).await,
        CaptureStartup::NotConfigured
    ));
    assert!(matches!(
        start(34, &[(COLLECTED_CAPTURE, "disabled")]).await,
        CaptureStartup::NotConfigured
    ));
    let (capture, status) = start(34, &[]).await.into_parts();
    assert!(capture.is_none() && status.is_none());
}

const COLLECTED_CAPTURE: &str = "FLEET_RECALL_COLLECTED_CAPTURE";
const PINS: [(&str, &str); 3] = [
    ("FLEET_RECALL_CONTRACT_TENANT_NAMESPACE", "tenant.acme"),
    ("FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE", "project.recall"),
    (
        "FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST",
        "abababababababababababababababababababababababababababababababab",
    ),
];

#[tokio::test]
async fn capture_that_cannot_be_served_is_off_with_its_reason_before_io() {
    let status = off(start(34, &[(COLLECTED_CAPTURE, "on")]).await);
    assert!(status.mode.is_none());
    assert!(
        status
            .reason
            .as_deref()
            .unwrap()
            .contains(COLLECTED_CAPTURE),
        "{status:?}"
    );

    let status = off(start(33, &[(COLLECTED_CAPTURE, "stage_only")]).await);
    assert_eq!(status.mode, Some(CollectedCaptureModeV1::StageOnly));
    assert!(status.reason.as_deref().unwrap().contains("migration 34"));

    // Only enabled reads the content key, and it needs one.
    let mut enabled = vec![(COLLECTED_CAPTURE, "enabled")];
    enabled.extend(PINS);
    let status = off(start(34, &enabled).await);
    assert!(
        status
            .reason
            .as_deref()
            .unwrap()
            .contains("FLEET_RECALL_CONTENT_KEK_HEX"),
        "{status:?}"
    );

    let status = off(start(34, &[(COLLECTED_CAPTURE, "stage_only")]).await);
    assert!(
        status
            .reason
            .as_deref()
            .unwrap()
            .contains("writer-authority pins"),
        "{status:?}"
    );

    let status = off(start(
        34,
        &[
            (COLLECTED_CAPTURE, "stage_only"),
            ("FLEET_RECALL_COLLECTED_CAPTURE_SCOPES", "[{}]"),
        ],
    )
    .await);
    assert!(
        status
            .reason
            .as_deref()
            .unwrap()
            .contains("FLEET_RECALL_COLLECTED_CAPTURE_SCOPES"),
        "{status:?}"
    );
    assert_eq!(
        serde_json::to_value(&status).unwrap()["served"],
        json!(false)
    );
}
