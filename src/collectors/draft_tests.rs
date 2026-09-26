//! Sealing drafts: the fixtures seal, identity behaves, every field is
//! sanitized and redacted, splitting is lossless, and the golden vectors are
//! what the pipeline produces.

use super::*;
use crate::collectors::redaction::ProviderSecretClassV1;
use crate::collectors::test_support::redactor;
use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::collected_item::{
    CollectedItemInputV1, ItemCollectionV1, derive_content_digest,
};
use crate::memory_contracts::common::ContractId;
use crate::redaction::REDACTION_PLACEHOLDER;

const FIXTURES: [(&str, &str); 4] = [
    (
        "docs",
        include_str!("../../tests/fixtures/collected/items-docs.jsonl"),
    ),
    (
        "slack",
        include_str!("../../tests/fixtures/collected/items-slack.jsonl"),
    ),
    (
        "linear",
        include_str!("../../tests/fixtures/collected/items-linear.jsonl"),
    ),
    (
        "granola",
        include_str!("../../tests/fixtures/collected/items-granola.jsonl"),
    ),
];

const VECTORS_PATH: &str = "contracts/dynamic-memory/v3/collected-items/vectors.jsonl";

fn collection(mode: CollectionModeV1) -> ItemCollectionV1 {
    let attester =
        (mode == CollectionModeV1::Capture).then(|| ContractId::new("agent.alice").unwrap());
    collection_record(
        mode,
        ContractId::new("collector.test").unwrap(),
        attester,
        None,
    )
    .unwrap()
}

fn basis(mode: CollectionModeV1) -> AudienceBasisV1 {
    match mode {
        CollectionModeV1::Pull | CollectionModeV1::Push => AudienceBasisV1::ProviderPublic,
        CollectionModeV1::Import => AudienceBasisV1::OperatorDeclared,
        CollectionModeV1::Capture => AudienceBasisV1::VerifiedContainer,
    }
}

fn seal_as(draft: &CollectedItemDraftV1, mode: CollectionModeV1) -> SealResult<SealedItemV1> {
    let redactor = redactor();
    let collection = collection(mode);
    seal(
        draft,
        &SealContextV1 {
            redactor: &redactor,
            audience: basis(mode),
            collection: &collection,
        },
    )
}

fn message(text: &str) -> CollectedItemDraftV1 {
    CollectedItemDraftV1 {
        provider: ProviderKindV1::new("slack").unwrap(),
        provider_scope_id: "T07ACME0001".into(),
        object_kind: ObjectKindV1::new("message").unwrap(),
        external_id: "C07PLATENG1:1790007122.004300".into(),
        marker: Some("1790007122.004300".into()),
        order_micros: 1_790_007_122_004_300,
        lifecycle: ItemLifecycleV1::Live,
        container: Some(DraftContainerV1 {
            kind: ContainerKindV1::new("slack.channel").unwrap(),
            id: "C07PLATENG1".into(),
            label: Some("plat-eng".into()),
        }),
        thread: Some(DraftThreadV1 {
            root_external_id: "C07PLATENG1:1790006645.000200".into(),
            parent_external_id: None,
        }),
        author: Some(DraftAuthorV1 {
            id: "U07CAROL003".into(),
            display: Some("Carol Diaz".into()),
            kind: AuthorKindV1::Human,
        }),
        created_at: Some(CanonicalTimestamp::parse("2026-09-21T16:12:02.004300000Z").unwrap()),
        updated_at: None,
        title: None,
        sections: vec![DraftSectionV1::whole(text.to_owned())],
        text_format: TextFormatV1::SlackMrkdwnRendered,
        links: vec![DraftLinkV1 {
            rel: LinkRelV1::new("url").unwrap(),
            target: "https://linear.app/acme-robotics/issue/ENG-412".into(),
            label: Some("ENG-412".into()),
        }],
        provider_url: Some(
            "https://acme-robotics.slack.com/archives/C07PLATENG1/p1790007122004300".into(),
        ),
        visibility: None,
    }
}

fn only_part(sealed: &SealedItemV1) -> &SealedPartV1 {
    assert_eq!(sealed.parts.len(), 1);
    &sealed.parts[0]
}

#[test]
fn every_fixture_line_seals_and_the_topic_is_findable() {
    for (provider, lines) in FIXTURES {
        let mut mentions_topic = false;
        for line in lines.lines() {
            let input = CollectedItemInputV1::parse(line.as_bytes()).unwrap_or_else(|error| {
                panic!("a {provider} fixture line does not parse: {error}")
            });
            assert_eq!(input.provider.as_str(), provider);
            let draft = CollectedItemDraftV1::from_input(input).unwrap();
            let sealed = seal_as(&draft, CollectionModeV1::Import).unwrap();
            for part in &sealed.parts {
                let text = part.envelope.text.as_str().to_lowercase();
                let title = part
                    .envelope
                    .title
                    .as_ref()
                    .map_or_else(String::new, |title| title.as_str().to_lowercase());
                mentions_topic |= text.contains("retry budget") || title.contains("retry budget");
            }
        }
        assert!(
            mentions_topic,
            "the {provider} fixture never mentions the retry budget"
        );
    }
}

#[test]
fn an_input_without_any_clock_has_no_order_and_is_refused() {
    let line = br#"{"provider":"docs","provider_scope_id":"root","object_kind":"document","external_id":"a.md","text":"x"}"#;
    let input = CollectedItemInputV1::parse(line).unwrap();
    assert_eq!(
        CollectedItemDraftV1::from_input(input)
            .unwrap_err()
            .dead_letter_reason(),
        "validation_failed"
    );
}

#[test]
fn a_draft_never_prints_its_text() {
    let draft = message("the secret plan is retry budget five");
    let printed = format!("{draft:?}");
    assert!(!printed.contains("secret plan"));
    let sealed = seal_as(&draft, CollectionModeV1::Pull).unwrap();
    assert!(!format!("{sealed:?}").contains("secret plan"));
}

#[test]
fn a_pull_and_a_capture_of_one_version_share_the_version_not_the_revision() {
    let draft = message("Decision: retry budget is 5 attempts with jitter");
    let pull = seal_as(&draft, CollectionModeV1::Pull).unwrap();
    let capture = seal_as(&draft, CollectionModeV1::Capture).unwrap();
    assert_eq!(pull.item_key, capture.item_key);
    assert_eq!(pull.version_key, capture.version_key);
    assert_ne!(pull.stage_ids(), capture.stage_ids());

    let redactor = redactor();
    let bob = collection_record(
        CollectionModeV1::Capture,
        ContractId::new("collector.test").unwrap(),
        Some(ContractId::new("agent.bob").unwrap()),
        Some("slack-mcp:conversations_replies"),
    )
    .unwrap();
    let by_bob = seal(
        &draft,
        &SealContextV1 {
            redactor: &redactor,
            audience: AudienceBasisV1::OperatorCaptureScope,
            collection: &bob,
        },
    )
    .unwrap();
    assert_ne!(capture.stage_ids(), by_bob.stage_ids(), "two attesters");
}

#[test]
fn a_collection_record_matches_its_channel() {
    let instance = || ContractId::new("collector.test").unwrap();
    assert!(collection_record(CollectionModeV1::Capture, instance(), None, None).is_err());
    assert!(
        collection_record(
            CollectionModeV1::Pull,
            instance(),
            Some(ContractId::new("agent.alice").unwrap()),
            None
        )
        .is_err()
    );
    assert!(collection_record(CollectionModeV1::Import, instance(), None, Some("tool")).is_err());
}

#[test]
fn renaming_the_container_or_the_author_mints_nothing() {
    let draft = message("Decision: retry budget is 5 attempts with jitter");
    let mut renamed = draft.clone();
    renamed.container.as_mut().unwrap().label = Some("platform-eng".into());
    renamed.author.as_mut().unwrap().display = Some("C. Diaz".into());
    let before = seal_as(&draft, CollectionModeV1::Pull).unwrap();
    let after = seal_as(&renamed, CollectionModeV1::Pull).unwrap();
    assert_eq!(before.version_key, after.version_key);
    assert_eq!(before.stage_ids(), after.stage_ids());
    assert_eq!(before.container_key, after.container_key);
}

#[test]
fn a_to_b_to_a_under_the_default_marker_mints_three_versions() {
    let mut draft = message("A");
    draft.marker = None;
    let mut keys = Vec::new();
    let mut contents = Vec::new();
    for (order, text) in [(1_u64, "A"), (2, "B"), (3, "A")] {
        draft.order_micros = order;
        draft.sections = vec![DraftSectionV1::whole(text.to_owned())];
        let sealed = seal_as(&draft, CollectionModeV1::Pull).unwrap();
        let envelope = &only_part(&sealed).envelope;
        assert_eq!(
            envelope.version.marker.as_str(),
            format!("o{order}:sha256:{}", sealed.content_digest)
        );
        keys.push(sealed.version_key);
        contents.push(sealed.content_digest);
    }
    assert_eq!(contents[0], contents[2], "the same content");
    assert_ne!(keys[0], keys[1]);
    assert_ne!(keys[1], keys[2]);
    assert_ne!(keys[0], keys[2], "reverting mints a third version");
}

#[test]
fn new_content_under_the_same_marker_is_a_new_version() {
    let five = seal_as(&message("retry budget is 5"), CollectionModeV1::Pull).unwrap();
    let three = seal_as(&message("retry budget is 3"), CollectionModeV1::Pull).unwrap();
    assert_eq!(five.item_key, three.item_key);
    assert_ne!(five.version_key, three.version_key);
}

#[test]
fn hidden_unicode_is_stripped_and_counted_across_fields() {
    let mut draft = message("retry\u{200b} budget\u{e0041}\u{e0042} is 5");
    draft.title = Some("Deci\u{202e}sion".into());
    let sealed = seal_as(&draft, CollectionModeV1::Pull).unwrap();
    let envelope = &only_part(&sealed).envelope;
    assert_eq!(envelope.text.as_str(), "retry budget is 5");
    assert_eq!(envelope.title.as_ref().unwrap().as_str(), "Decision");
    assert_eq!(envelope.redaction.hidden_scalars_removed, 4);
    assert_eq!(envelope.redaction.replaced_scalars, 0);
}

#[test]
fn a_planted_credential_is_redacted_in_every_text_field() {
    let credential = "xoxb-EXAMPLE-NOT-A-TOKEN";
    let mut draft = message(&format!("the bot token is {credential}, rotate it"));
    draft.title = Some(format!("leak {credential}"));
    draft.links = vec![DraftLinkV1 {
        rel: LinkRelV1::new("url").unwrap(),
        target: format!("https://example.com/hook?key={credential}"),
        label: Some(format!("label {credential}")),
    }];
    draft.provider_url = Some(format!("https://example.com/item?token={credential}"));
    draft.author.as_mut().unwrap().display = Some(format!("bot {credential}"));
    draft.container.as_mut().unwrap().label = Some(format!("chan {credential}"));
    let sealed = seal_as(&draft, CollectionModeV1::Pull).unwrap();
    let part = only_part(&sealed);
    let bytes = String::from_utf8(part.canonical_envelope.clone()).unwrap();
    let decoded_text = part.envelope.text.as_str();
    assert!(
        !bytes.contains(credential),
        "a credential reached the envelope"
    );
    assert!(!decoded_text.contains(credential));
    assert!(
        !part
            .envelope
            .title
            .as_ref()
            .unwrap()
            .as_str()
            .contains(credential)
    );
    assert!(decoded_text.contains(REDACTION_PLACEHOLDER));
    assert_eq!(part.envelope.redaction.redacted_ranges, 7);
    assert!(
        part.envelope
            .redaction
            .classes
            .iter()
            .any(|class| class.as_str() == ProviderSecretClassV1::SlackToken.as_str())
    );
}

#[test]
fn each_provider_class_is_redacted_in_title_url_and_link_targets() {
    for credential in [
        "xoxp-EXAMPLE-NOT-A-TOKEN",
        "xapp-EXAMPLE-NOT-A-TOKEN",
        "lin_api_EXAMPLENOTAREALKEYEXAMPLENOTAREAL",
        "lin_oauth_EXAMPLENOTAREALKEYEXAMPLE",
        "grn_EXAMPLE_NOT_A_KEY",
        "whsec_EXAMPLENOTASECRET",
        "ghp_EXAMPLENOTAREALTOKENEXAMPLENOTAREAL",
        "github_pat_EXAMPLE_NOT_A_REAL_TOKEN_EXAMPLE",
        "AIzaEXAMPLE_NOT_A_REAL_KEY_EXAMPLE_NOT",
        "sk-ant-EXAMPLE-NOT-A-REAL-KEY",
        "sk-proj-EXAMPLE-NOT-A-REAL-KEY",
    ] {
        let mut draft = message("plain text");
        draft.title = Some(format!("t {credential}"));
        draft.provider_url = Some(format!("https://example.com/?v={credential}"));
        draft.links[0].target = format!("https://example.com/{credential}");
        let sealed = seal_as(&draft, CollectionModeV1::Pull).unwrap();
        let bytes = String::from_utf8(only_part(&sealed).canonical_envelope.clone()).unwrap();
        let title = only_part(&sealed).envelope.title.clone().unwrap();
        assert!(
            !bytes.contains(credential),
            "{credential} reached the envelope"
        );
        assert!(
            !title.as_str().contains(credential),
            "{credential} reached the title"
        );
    }
}

#[test]
fn a_credential_in_an_id_withholds_the_item() {
    let credential = "lin_api_EXAMPLENOTAREALKEYEXAMPLENOTAREAL";
    let mut draft = message("plain text");
    draft.external_id = format!("issue:{credential}");
    let refusal = seal_as(&draft, CollectionModeV1::Pull).unwrap_err();
    assert_eq!(refusal.dead_letter_reason(), "redaction_withheld");
    assert!(!refusal.to_string().contains(credential));
}

#[test]
fn an_unredactable_secret_withholds_the_item() {
    let draft = message(
        "key follows\n-----BEGIN RSA PRIVATE KEY-----\nEXAMPLE-NOT-A-KEY\n-----END RSA PRIVATE KEY-----",
    );
    let refusal = seal_as(&draft, CollectionModeV1::Pull).unwrap_err();
    assert_eq!(
        refusal,
        ItemRefusalV1::RedactionWithheld {
            field: "text",
            class: "private_key_block"
        }
    );
}

#[test]
fn splitting_is_lossless_and_prefers_paragraphs() {
    let paragraph = "retry budget ".repeat(200);
    let text = [paragraph.as_str(); 30].join("\n\n");
    let ranges = split_text(&text, MAX_PART_TEXT_BYTES);
    assert!(ranges.len() > 1);
    let rebuilt: String = ranges.iter().map(|range| &text[range.clone()]).collect();
    assert_eq!(rebuilt, text);
    for range in &ranges[..ranges.len() - 1] {
        assert!(range.len() <= MAX_PART_TEXT_BYTES);
        assert!(
            text[range.clone()].ends_with("\n\n"),
            "cut at a paragraph break"
        );
    }
    // Lines, then whitespace, then a char boundary when nothing better exists.
    assert_eq!(split_text("aa\nbb\ncc", 4), vec![0..3, 3..6, 6..8]);
    assert_eq!(split_text("aaa bbb", 5), vec![0..4, 4..7]);
    assert_eq!(split_text("\u{e9}\u{e9}\u{e9}", 3), vec![0..2, 2..4, 4..6]);
    assert_eq!(split_text("", 5), vec![0..0]);
}

#[test]
fn a_long_item_seals_as_ordered_parts_with_one_content_digest() {
    let paragraph = "The ingest worker retries a failed source with full jitter. ".repeat(100);
    let text = [paragraph.as_str(); 12].join("\n\n");
    let mut draft = message(&text);
    draft.title = Some("Retry budget".into());
    let sealed = seal_as(&draft, CollectionModeV1::Pull).unwrap();
    assert!(sealed.parts.len() > 1);
    let count = u32::try_from(sealed.parts.len()).unwrap();
    let mut rebuilt = String::new();
    for (ordinal, part) in (0_u32..).zip(&sealed.parts) {
        assert_eq!(part.envelope.part.ordinal, ordinal);
        assert_eq!(part.envelope.part.count, count);
        assert_eq!(part.envelope.content_digest, sealed.content_digest);
        assert!(part.envelope.text.as_str().len() <= MAX_PART_TEXT_BYTES);
        rebuilt.push_str(part.envelope.text.as_str());
    }
    assert_eq!(rebuilt, text);
    assert_eq!(
        sealed.content_digest,
        derive_content_digest(Some("Retry budget"), &text)
    );
    let unique: std::collections::BTreeSet<_> = sealed.stage_ids().into_iter().collect();
    assert_eq!(unique.len(), sealed.parts.len());
}

#[test]
fn sections_are_hard_boundaries_and_keep_their_anchor_and_span() {
    let mut draft = message("unused");
    draft.sections = vec![
        DraftSectionV1 {
            anchor: Some("Retry budget".into()),
            span: Some([0, 15]),
            text: "# Retry budget\n".into(),
        },
        DraftSectionV1 {
            anchor: None,
            span: None,
            text: String::new(),
        },
        DraftSectionV1 {
            anchor: Some("Retry budget > Decision".into()),
            span: Some([15, 40]),
            text: "## Decision\n\nFive, with jitter.\n".into(),
        },
    ];
    let sealed = seal_as(&draft, CollectionModeV1::Pull).unwrap();
    assert_eq!(sealed.parts.len(), 2, "an empty section is no part");
    let anchors: Vec<_> = sealed
        .parts
        .iter()
        .map(|part| {
            part.envelope
                .part
                .anchor
                .as_ref()
                .map(|anchor| anchor.as_str().to_owned())
        })
        .collect();
    assert_eq!(
        anchors,
        vec![
            Some("Retry budget".to_owned()),
            Some("Retry budget > Decision".to_owned())
        ]
    );
    assert_eq!(sealed.parts[1].envelope.part.span, Some([15, 40]));
}

#[test]
fn more_than_sixty_four_parts_is_oversize() {
    let mut draft = message("unused");
    draft.sections = (0..=MAX_PARTS)
        .map(|index| DraftSectionV1::whole(format!("section {index}")))
        .collect();
    assert_eq!(
        seal_as(&draft, CollectionModeV1::Pull).unwrap_err(),
        ItemRefusalV1::Oversize { parts: 65 }
    );
}

#[test]
fn a_tombstone_stages_metadata_only() {
    let mut draft = message("the last text a deleted message had");
    draft.lifecycle = ItemLifecycleV1::Deleted;
    draft.title = Some("a title".into());
    let sealed = seal_as(&draft, CollectionModeV1::Push).unwrap();
    let envelope = &only_part(&sealed).envelope;
    assert!(envelope.text.is_empty());
    assert!(envelope.title.is_none() && envelope.links.is_empty());
    assert!(
        !String::from_utf8(only_part(&sealed).canonical_envelope.clone())
            .unwrap()
            .contains(&hex::encode("deleted message"))
    );
}

#[test]
fn only_a_tombstone_may_be_empty() {
    assert_eq!(
        seal_as(&message(""), CollectionModeV1::Pull)
            .unwrap_err()
            .dead_letter_reason(),
        "validation_failed"
    );
}

#[test]
fn refused_ids_and_urls_are_validation_failures() {
    let mut not_nfc = message("x");
    not_nfc.external_id = "cafe\u{301}".into();
    let mut http = message("x");
    http.provider_url = Some("http://example.com/x".into());
    let mut too_many_links = message("x");
    too_many_links.links = (0..=MAX_LINKS)
        .map(|index| DraftLinkV1 {
            rel: LinkRelV1::new("url").unwrap(),
            target: format!("https://example.com/{index}"),
            label: None,
        })
        .collect();
    let mut backwards = message("x");
    backwards.updated_at =
        Some(CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap());
    for draft in [not_nfc, http, too_many_links, backwards] {
        assert_eq!(
            seal_as(&draft, CollectionModeV1::Pull)
                .unwrap_err()
                .dead_letter_reason(),
            "validation_failed"
        );
    }
}

#[test]
fn a_hidden_scalar_in_an_id_or_marker_is_refused_not_stripped() {
    // TAG-block letters spelling "IGN", a right-to-left override, and a
    // zero-width space: invisible to a reader, and able to break up a secret
    // shape the id scan would otherwise catch.
    for hidden in ["\u{e0049}\u{e0047}\u{e004e}", "\u{202e}", "\u{200b}"] {
        let mut in_external_id = message("x");
        in_external_id.external_id = format!("C07PLATENG1:1790006645.000200{hidden}");
        let mut in_author = message("x");
        if let Some(author) = in_author.author.as_mut() {
            author.id = format!("U07{hidden}AUTHOR");
        }
        let mut in_container = message("x");
        if let Some(container) = in_container.container.as_mut() {
            container.id = format!("C07{hidden}PLATENG1");
        }
        let mut in_thread = message("x");
        in_thread.thread = Some(DraftThreadV1 {
            root_external_id: format!("C07PLATENG1:1790006645.0002{hidden}00"),
            parent_external_id: None,
        });
        let mut in_marker = message("x");
        in_marker.marker = Some(format!("1790007122.004300{hidden}"));
        for draft in [
            in_external_id,
            in_author,
            in_container,
            in_thread,
            in_marker,
        ] {
            assert_eq!(
                seal_as(&draft, CollectionModeV1::Pull).unwrap_err(),
                ItemRefusalV1::Validation("an id or marker holds a hidden scalar")
            );
        }
    }
    // The same scalars in text are stripped and counted, as before.
    assert!(seal_as(&message("x\u{200b}y"), CollectionModeV1::Pull).is_ok());
}

/// The drafts the golden vectors are sealed from.
fn vector_cases() -> Vec<(
    &'static str,
    CollectedItemDraftV1,
    ItemCollectionV1,
    AudienceBasisV1,
)> {
    let instance = |id: &str| ContractId::new(id).unwrap();
    let pull =
        collection_record(CollectionModeV1::Pull, instance("slack.acme"), None, None).unwrap();
    let capture_by = |agent: &str| {
        collection_record(
            CollectionModeV1::Capture,
            instance("capture.agent"),
            Some(instance(agent)),
            Some("slack-mcp:conversations_replies"),
        )
        .unwrap()
    };
    let slack = message(
        "Decision: retry budget is 5 attempts with jitter; @U07ALICE001 will update ENG-412",
    );

    let linear_input = CollectedItemInputV1::parse(
        FIXTURES[2]
            .1
            .lines()
            .next()
            .expect("the linear fixture has an issue")
            .as_bytes(),
    )
    .unwrap();
    let linear = CollectedItemDraftV1::from_input(linear_input).unwrap();

    let mut docs = CollectedItemDraftV1::from_input(
        CollectedItemInputV1::parse(FIXTURES[0].1.lines().next().unwrap().as_bytes()).unwrap(),
    )
    .unwrap();
    docs.sections = vec![
        DraftSectionV1 {
            anchor: Some("Retry budget".into()),
            span: Some([62, 77]),
            text: "# Retry budget\n\n".into(),
        },
        DraftSectionV1 {
            anchor: Some("Retry budget > Decision".into()),
            span: Some([77, 265]),
            text: "## Decision\n\nThe ingest worker retries a failed source at most **5** times with full jitter.\n".into(),
        },
    ];

    let mut revoked = CollectedItemDraftV1::from_input(
        CollectedItemInputV1::parse(FIXTURES[3].1.lines().next().unwrap().as_bytes()).unwrap(),
    )
    .unwrap();
    revoked.lifecycle = ItemLifecycleV1::Revoked;
    revoked.order_micros += 1;

    vec![
        (
            "slack_message_pull",
            slack.clone(),
            pull,
            AudienceBasisV1::ProviderPublic,
        ),
        (
            "slack_message_capture_alice",
            slack.clone(),
            capture_by("agent.alice"),
            AudienceBasisV1::VerifiedContainer,
        ),
        (
            "slack_message_capture_bob",
            slack,
            capture_by("agent.bob"),
            AudienceBasisV1::VerifiedContainer,
        ),
        (
            "linear_issue_import",
            linear,
            collection_record(
                CollectionModeV1::Import,
                instance("linear.import"),
                None,
                None,
            )
            .unwrap(),
            AudienceBasisV1::OperatorDeclared,
        ),
        (
            "docs_document_two_parts_pull",
            docs,
            collection_record(CollectionModeV1::Pull, instance("docs.specs"), None, None).unwrap(),
            AudienceBasisV1::OperatorDeclared,
        ),
        (
            "granola_note_revoked_pull",
            revoked,
            collection_record(CollectionModeV1::Pull, instance("granola.acme"), None, None)
                .unwrap(),
            AudienceBasisV1::OperatorDeclared,
        ),
    ]
}

/// The golden vector file, exactly as the pipeline seals it.
fn sealed_vector_bytes() -> Vec<u8> {
    let redactor = redactor();
    let mut bytes = Vec::new();
    for (case, draft, collection, audience) in vector_cases() {
        let sealed = seal(
            &draft,
            &SealContextV1 {
                redactor: &redactor,
                audience,
                collection: &collection,
            },
        )
        .unwrap_or_else(|refusal| panic!("vector {case} does not seal: {refusal}"));
        for part in sealed.parts {
            let name = if part.envelope.part.count > 1 {
                format!("{case}_{}", part.envelope.part.ordinal)
            } else {
                case.to_owned()
            };
            let vector = crate::memory_contracts::collected_item::tests::CollectedItemVectorV1 {
                case: name,
                item_key: part.envelope.item_key(),
                version_key: part.envelope.version_key(),
                immutable_revision: part.stage_id,
                container_key: part.envelope.container_key(),
                envelope: part.envelope,
            };
            bytes.extend(encode_canonical(&vector).unwrap());
            bytes.push(b'\n');
        }
    }
    bytes
}

#[test]
fn the_golden_vectors_are_what_the_pipeline_seals() {
    let checked_in =
        include_bytes!("../../contracts/dynamic-memory/v3/collected-items/vectors.jsonl");
    assert!(
        sealed_vector_bytes() == checked_in,
        "the seal pipeline no longer reproduces {VECTORS_PATH}; an intended change is a new \
         envelope schema or redaction profile, regenerated with \
         `cargo test --lib -- --ignored regenerate_collected_item_vectors`"
    );
}

#[test]
#[ignore = "rewrites the checked-in golden vectors"]
fn regenerate_collected_item_vectors() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS_PATH);
    std::fs::write(&path, sealed_vector_bytes()).unwrap();
    println!("wrote {}", path.display());
}
