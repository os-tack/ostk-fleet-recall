//! The sink's pure parts: dead-letter identity, draft fingerprints, and the
//! reasons refusals are recorded under.

use super::*;
use crate::collectors::draft::DraftSectionV1;
use crate::memory_contracts::collected_item::{ObjectKindV1, TextFormatV1};

fn draft(text: &str) -> CollectedItemDraftV1 {
    CollectedItemDraftV1 {
        provider: ProviderKindV1::new("docs").unwrap(),
        provider_scope_id: "docs.acme.specs".into(),
        object_kind: ObjectKindV1::new("document").unwrap(),
        external_id: "retry-budget.md".into(),
        marker: None,
        order_micros: 1_790_000_000_000_000,
        lifecycle: ItemLifecycleV1::Live,
        container: None,
        thread: None,
        author: None,
        created_at: None,
        updated_at: None,
        title: None,
        sections: vec![DraftSectionV1::whole(text.into())],
        text_format: TextFormatV1::Markdown,
        links: Vec::new(),
        provider_url: None,
        visibility: None,
    }
}

#[test]
fn recording_one_refusal_twice_is_one_dead_letter() {
    let payload = draft_digest(&draft("retry budget"));
    let stage = Sha256Digest::from_bytes([7; 32]);
    let first = dead_letter_id(
        "docs.specs",
        DeadLetterReasonV1::AudienceRefused,
        &payload,
        None,
    );
    assert_eq!(
        first,
        dead_letter_id(
            "docs.specs",
            DeadLetterReasonV1::AudienceRefused,
            &payload,
            None
        )
    );
    // Another instance, reason, payload, or stage id is another letter.
    for other in [
        dead_letter_id(
            "docs.other",
            DeadLetterReasonV1::AudienceRefused,
            &payload,
            None,
        ),
        dead_letter_id("docs.specs", DeadLetterReasonV1::ClockAhead, &payload, None),
        dead_letter_id(
            "docs.specs",
            DeadLetterReasonV1::AudienceRefused,
            &draft_digest(&draft("retry budget, edited")),
            None,
        ),
        dead_letter_id(
            "docs.specs",
            DeadLetterReasonV1::AudienceRefused,
            &payload,
            Some(&stage),
        ),
    ] {
        assert_ne!(first, other);
    }
}

#[test]
fn a_draft_fingerprint_follows_its_content_and_identity() {
    let base = draft("retry budget");
    assert_eq!(draft_digest(&base), draft_digest(&base.clone()));
    let mut moved = base.clone();
    moved.external_id = "retry-budget-v2.md".into();
    assert_ne!(draft_digest(&base), draft_digest(&moved));
    let mut retitled = base.clone();
    retitled.title = Some("Retry budget".into());
    assert_ne!(draft_digest(&base), draft_digest(&retitled));
    let mut reordered = base.clone();
    reordered.order_micros += 1;
    assert_ne!(draft_digest(&base), draft_digest(&reordered));
}

#[test]
fn a_sealing_refusal_is_recorded_under_its_own_reason() {
    assert_eq!(
        DeadLetterReasonV1::of_refusal(ItemRefusalV1::Validation("x")),
        DeadLetterReasonV1::ValidationFailed
    );
    assert_eq!(
        DeadLetterReasonV1::of_refusal(ItemRefusalV1::Oversize { parts: 65 }),
        DeadLetterReasonV1::Oversize
    );
    let withheld = ItemRefusalV1::RedactionWithheld {
        field: "text",
        class: "slack_token",
    };
    assert_eq!(
        DeadLetterReasonV1::of_refusal(withheld).as_str(),
        withheld.dead_letter_reason()
    );
}

#[test]
fn a_cursor_prints_no_state() {
    let cursor = CursorAdvanceV1 {
        domain_key: "C07PLATENG1".into(),
        cursor_state: b"next_cursor=dGVhbTpDMDYxRkE1UEI=".to_vec(),
        high_water_order: Some(1),
        pass_seq: 2,
    };
    let printed = format!("{cursor:?}");
    assert!(!printed.contains("dGVhbT"), "{printed}");
    assert!(printed.contains("cursor_state_bytes"));
}
