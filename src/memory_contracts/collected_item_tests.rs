//! The collected-item envelope contract: refusal paths, identity properties,
//! and the checked-in golden vectors.

use std::collections::BTreeMap;

use super::*;
use crate::memory_contracts::canonical::decode_typed_canonical;

/// Golden identity vectors: one canonical record per line.
const VECTORS: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/collected-items/vectors.jsonl");

/// One golden vector: an envelope and the digests it must derive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectedItemVectorV1 {
    pub case: String,
    pub envelope: CollectedItemEnvelopeV1,
    pub item_key: Sha256Digest,
    pub version_key: Sha256Digest,
    pub immutable_revision: Sha256Digest,
    pub container_key: Option<Sha256Digest>,
}

fn stamp(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).unwrap()
}

fn line<const MAX: usize>(value: &str) -> BoundedTextV1<MAX> {
    BoundedTextV1::new(value).unwrap()
}

fn sample() -> CollectedItemEnvelopeV1 {
    let provider = ProviderKindV1::new("slack").unwrap();
    let container = ItemContainerV1 {
        kind: ContainerKindV1::new("slack.channel").unwrap(),
        id: line("C07PLATENG1"),
        label: Some(line("plat-eng")),
    };
    let container_key =
        derive_container_key(&provider, "T07ACME0001", &container.kind, "C07PLATENG1");
    let text = CollectedTextV1::new("Decision: retry budget is 5 attempts with jitter").unwrap();
    CollectedItemEnvelopeV1 {
        schema_version: COLLECTED_ITEM_SCHEMA_VERSION,
        provider,
        provider_scope_id: line("T07ACME0001"),
        object_kind: ObjectKindV1::new("message").unwrap(),
        external_id: line("C07PLATENG1:1790007122.004300"),
        version: ItemVersionV1 {
            marker: line("1790007122.004300"),
            order_micros: 1_790_007_122_004_300,
        },
        lifecycle: ItemLifecycleV1::Live,
        part: ItemPartV1 {
            ordinal: 0,
            count: 1,
            anchor: None,
            span: None,
        },
        container: Some(container),
        thread: None,
        author: Some(ItemAuthorV1 {
            id: line("U07CAROL003"),
            display: None,
            kind: AuthorKindV1::Human,
        }),
        created_at: Some(stamp("2026-09-21T16:12:02.004300000Z")),
        updated_at: None,
        title: None,
        content_digest: derive_content_digest(None, text.as_str()),
        text,
        text_format: TextFormatV1::SlackMrkdwnRendered,
        links: Vec::new(),
        provider_url: None,
        audience: ItemAudienceV1 {
            basis: AudienceBasisV1::ProviderPublic,
            container_key: Some(container_key),
        },
        redaction: ItemRedactionV1 {
            profile_version: 1,
            redacted_ranges: 0,
            classes: Vec::new(),
            hidden_scalars_removed: 0,
            replaced_scalars: 0,
        },
        collection: ItemCollectionV1 {
            mode: CollectionModeV1::Pull,
            collector_instance: ContractId::new("slack.acme").unwrap(),
            attester: None,
            via: None,
        },
    }
}

fn refused(envelope: &CollectedItemEnvelopeV1, why: &str) {
    assert!(
        envelope.validate().is_err(),
        "accepted an envelope with {why}"
    );
    assert!(
        envelope.canonical_bytes().is_err(),
        "encoded an envelope with {why}"
    );
}

#[test]
fn the_sample_envelope_is_valid_and_round_trips_canonically() {
    let envelope = sample();
    let bytes = envelope.canonical_bytes().unwrap();
    assert_eq!(CollectedItemEnvelopeV1::decode(&bytes).unwrap(), envelope);
    // No raw newline, so the reference parser sees exactly one body.
    assert!(!bytes.contains(&b'\n'));
}

#[test]
fn envelope_refusal_paths() {
    let mut envelope = sample();
    envelope.schema_version = 2;
    refused(&envelope, "an unknown schema version");

    for (ordinal, count) in [(0, 0), (1, 1), (0, MAX_PARTS + 1)] {
        let mut envelope = sample();
        envelope.part.ordinal = ordinal;
        envelope.part.count = count;
        refused(&envelope, "a part outside its count");
    }

    let mut envelope = sample();
    envelope.part.span = Some([10, 5]);
    refused(&envelope, "a reversed span");

    let mut envelope = sample();
    envelope.version.order_micros = u64::MAX;
    refused(&envelope, "an order outside the safe integer range");

    let mut envelope = sample();
    envelope.text = CollectedTextV1::new("").unwrap();
    envelope.content_digest = derive_content_digest(None, "");
    refused(&envelope, "empty text on a live item");

    let mut envelope = sample();
    envelope.lifecycle = ItemLifecycleV1::Deleted;
    refused(&envelope, "text on a tombstone");

    let mut envelope = sample();
    envelope.title = Some(CollectedTextV1::new("").unwrap());
    refused(&envelope, "an empty title");

    let mut envelope = sample();
    envelope.links = (0..=MAX_LINKS)
        .map(|index| ItemLinkV1 {
            rel: LinkRelV1::new("url").unwrap(),
            target: line(&format!("https://example.com/{index}")),
            label: None,
        })
        .collect();
    refused(&envelope, "too many links");

    let mut envelope = sample();
    envelope.provider_url = Some(line("http://example.com/plain"));
    refused(&envelope, "a non-https provider url");

    let mut envelope = sample();
    envelope.audience.container_key = None;
    refused(&envelope, "a container key that is not the derived one");

    let mut envelope = sample();
    envelope.collection.attester = Some(ContractId::new("agent.alice").unwrap());
    refused(&envelope, "an attester on a pull");

    let mut envelope = sample();
    envelope.collection.mode = CollectionModeV1::Capture;
    envelope.audience.basis = AudienceBasisV1::VerifiedContainer;
    refused(&envelope, "a capture with no attester");

    let mut envelope = sample();
    envelope.collection.via = Some(line("slack-mcp"));
    refused(&envelope, "a tool label on a pull");

    let mut envelope = sample();
    envelope.audience.basis = AudienceBasisV1::OperatorCaptureScope;
    refused(&envelope, "a capture-only basis on a pull");

    let mut envelope = sample();
    envelope.collection.mode = CollectionModeV1::Import;
    refused(&envelope, "a provider basis on an import");

    let mut envelope = sample();
    envelope.redaction.classes = vec![
        RedactionClassLabelV1::new("slack_token").unwrap(),
        RedactionClassLabelV1::new("aws_access_key_id").unwrap(),
    ];
    refused(&envelope, "unsorted redaction classes");

    let mut envelope = sample();
    envelope.redaction.profile_version = 0;
    refused(&envelope, "a zero redaction profile");

    let mut envelope = sample();
    envelope.updated_at = Some(stamp("2026-09-21T16:00:00.000000000Z"));
    refused(&envelope, "an update before the creation");

    let mut envelope = sample();
    envelope.created_at = Some(stamp("2026-09-21T16:12:02.004300001Z"));
    refused(&envelope, "a clock finer than a microsecond");

    let mut envelope = sample();
    envelope.content_digest = Sha256Digest::ZERO;
    refused(
        &envelope,
        "a one-part content digest that is not the part digest",
    );
}

#[test]
fn a_provider_clock_ahead_of_the_observation_is_refused() {
    let envelope = sample();
    envelope
        .validate_observed(&stamp("2026-09-21T16:12:02.004300000Z"))
        .expect("occurred == observed is allowed");
    envelope
        .validate_observed(&stamp("2026-09-25T12:00:00.000000000Z"))
        .unwrap();
    assert!(
        envelope
            .validate_observed(&stamp("2026-09-21T16:12:02.004299000Z"))
            .is_err()
    );
    // With no provider clock, occurred is the observation itself.
    let mut unclocked = sample();
    unclocked.created_at = None;
    let observed = stamp("2026-09-25T12:00:00.000000000Z");
    unclocked.validate_observed(&observed).unwrap();
    assert_eq!(unclocked.occurred_at(&observed), observed);
}

#[test]
fn syntax_and_text_refusals_happen_at_construction() {
    for provider in ["", "Slack", "1slack", "slack.com", &"s".repeat(33)] {
        assert!(
            ProviderKindV1::new(provider).is_err(),
            "accepted {provider:?}"
        );
    }
    for kind in ["", "Message", "_message", &"m".repeat(65)] {
        assert!(ObjectKindV1::new(kind).is_err(), "accepted {kind:?}");
    }
    assert!(ObjectKindV1::new("note_summary").is_ok());
    assert!(ContainerKindV1::new("slack.channel").is_ok());

    assert!(BoundedTextV1::<8>::new("").is_err());
    assert!(BoundedTextV1::<8>::new("123456789").is_err());
    assert!(BoundedTextV1::<8>::new("two\nlines").is_err());
    assert!(BoundedTextV1::<8>::new("cafe\u{301}").is_err(), "not NFC");

    assert!(CollectedTextV1::<8>::new("123456789").is_err());
    assert!(CollectedTextV1::<64>::new("zero\u{200b}width").is_err());
    assert!(CollectedTextV1::<64>::new("bidi \u{202e}override").is_err());
    assert!(CollectedTextV1::<64>::new("bell\u{7}").is_err());
    assert!(CollectedTextV1::<64>::new("icon \u{e000}").is_err());
    assert!(CollectedTextV1::<64>::new("line one\n\tline two").is_ok());
}

#[test]
fn the_wire_decoder_refuses_what_the_constructors_refuse() {
    let bytes = sample().canonical_bytes().unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let hex_text = hex::encode("Decision: retry budget is 5 attempts with jitter");

    // Uppercase hex has another wire form than the canonical one.
    let upper = text.replace(&hex_text, &hex_text.to_uppercase());
    assert!(CollectedItemEnvelopeV1::decode(upper.as_bytes()).is_err());

    // Hidden Unicode cannot ride in through the hex either.
    let hidden = text.replace(&hex_text, &hex::encode("Decision\u{200b}: retry"));
    assert!(CollectedItemEnvelopeV1::decode(hidden.as_bytes()).is_err());

    // An unknown field, and an optional field omitted rather than null.
    let unknown = text.replacen('{', r#"{"aaa":1,"#, 1);
    assert!(CollectedItemEnvelopeV1::decode(unknown.as_bytes()).is_err());
    let omitted = text.replace(r#""thread":null,"#, "");
    assert!(CollectedItemEnvelopeV1::decode(omitted.as_bytes()).is_err());
}

#[test]
fn renaming_a_container_label_changes_no_digest() {
    let before = sample();
    let mut after = sample();
    after.container.as_mut().unwrap().label = Some(line("platform-eng"));
    assert_eq!(before.item_key(), after.item_key());
    assert_eq!(before.version_key(), after.version_key());
    assert_eq!(before.immutable_revision(), after.immutable_revision());
    assert_eq!(before.container_key(), after.container_key());
    assert_ne!(
        before.canonical_bytes().unwrap(),
        after.canonical_bytes().unwrap(),
        "the label is still carried, as an attribute"
    );
}

#[test]
fn new_content_under_the_same_marker_is_a_new_version() {
    let before = sample();
    let mut after = sample();
    after.text = CollectedTextV1::new("Decision: retry budget is 3 attempts").unwrap();
    after.content_digest = after.part_digest();
    assert_eq!(before.version.marker, after.version.marker);
    assert_eq!(before.item_key(), after.item_key());
    assert_ne!(before.version_key(), after.version_key());
    assert_ne!(before.immutable_revision(), after.immutable_revision());
}

#[test]
fn a_capture_and_a_pull_of_one_version_are_separate_revisions() {
    let pull = sample();
    let mut capture = sample();
    capture.collection.mode = CollectionModeV1::Capture;
    capture.collection.attester = Some(ContractId::new("agent.alice").unwrap());
    capture.audience.basis = AudienceBasisV1::VerifiedContainer;
    capture.validate().unwrap();
    assert_eq!(pull.version_key(), capture.version_key(), "one version");
    assert_ne!(pull.immutable_revision(), capture.immutable_revision());
    assert_eq!(pull.trust_tier(), TrustTierV1::Verified);
    assert_eq!(capture.trust_tier(), TrustTierV1::Reported);

    let mut second_agent = capture.clone();
    second_agent.collection.attester = Some(ContractId::new("agent.bob").unwrap());
    assert_ne!(
        capture.immutable_revision(),
        second_agent.immutable_revision(),
        "two agents' captures are two attestations"
    );
}

#[test]
fn every_part_of_a_version_has_its_own_revision() {
    let item_key = sample().item_key();
    let content = derive_content_digest(None, "one two");
    let version_key = derive_version_key(&item_key, "m", ItemLifecycleV1::Live, &content);
    let revision = |ordinal, text: &str| {
        derive_immutable_revision(&RevisionCoordinatesV1 {
            version_key,
            mode: CollectionModeV1::Pull,
            attester: None,
            part_ordinal: ordinal,
            part_count: 2,
            part_digest: derive_content_digest(None, text),
        })
    };
    assert_ne!(revision(0, "one "), revision(1, "two"));
    assert_ne!(revision(0, "one "), revision(1, "one "));
}

#[test]
fn a_to_b_to_a_under_the_default_marker_is_three_versions() {
    let item_key = sample().item_key();
    let a = derive_content_digest(None, "A");
    let b = derive_content_digest(None, "B");
    let versions: Vec<Sha256Digest> = [(1_u64, a), (2, b), (3, a)]
        .into_iter()
        .map(|(order, content)| {
            derive_version_key(
                &item_key,
                &default_version_marker(order, &content),
                ItemLifecycleV1::Live,
                &content,
            )
        })
        .collect();
    assert_ne!(versions[0], versions[1]);
    assert_ne!(versions[1], versions[2]);
    assert_ne!(
        versions[0], versions[2],
        "a revert is a new version, not a no-op"
    );
}

#[test]
fn the_domains_are_distinct() {
    let parts: &[&[u8]] = &[b"slack", b"T0", b"message", b"x"];
    let digests = [
        framed_digest(DigestDomain::CollectedItemKeyV1, parts),
        framed_digest(DigestDomain::CollectedItemContentV1, parts),
        framed_digest(DigestDomain::CollectedItemVersionV1, parts),
        framed_digest(DigestDomain::CollectedItemRevisionV1, parts),
        framed_digest(DigestDomain::CollectedContainerKeyV1, parts),
        framed_digest(DigestDomain::CollectedObservationManifestV1, parts),
    ];
    for (index, digest) in digests.iter().enumerate() {
        assert!(!digests[index + 1..].contains(digest));
    }
    assert_ne!(
        derive_observation_manifest(&[digests[0], digests[1]]),
        derive_observation_manifest(&[digests[1], digests[0]]),
        "a manifest is ordered"
    );
}

#[test]
fn provider_timestamps_are_canonical_and_microsecond_truncated() {
    assert_eq!(
        provider_timestamp("2026-09-22T09:41:07.113Z")
            .unwrap()
            .as_str(),
        "2026-09-22T09:41:07.113000000Z"
    );
    assert_eq!(
        provider_timestamp("2026-09-22T11:41:07.1234567+02:00")
            .unwrap()
            .as_str(),
        "2026-09-22T09:41:07.123456000Z"
    );
    assert!(provider_timestamp("22 Sep 2026").is_err());
    let stamp = provider_timestamp("2026-09-21T16:12:02.004300Z").unwrap();
    assert_eq!(timestamp_micros(&stamp).unwrap(), 1_790_007_122_004_300);
}

#[test]
fn an_input_line_is_parsed_strictly() {
    let line = br#"{"provider":"linear","provider_scope_id":"org","object_kind":"issue","external_id":"id-1","text":"Retry\nbudget","updated_at":"2026-09-22T09:41:07.113Z"}"#;
    let input = CollectedItemInputV1::parse(line).unwrap();
    assert_eq!(input.text, "Retry\nbudget");
    assert!(input.lifecycle.is_none() && input.links.is_empty());
    let unknown = br#"{"provider":"linear","provider_scope_id":"org","object_kind":"issue","external_id":"id-1","scope":"tenant.other"}"#;
    assert!(
        CollectedItemInputV1::parse(unknown).is_err(),
        "an input cannot name a scope"
    );
    let duplicate = br#"{"provider":"linear","provider":"slack","provider_scope_id":"org","object_kind":"issue","external_id":"id-1"}"#;
    assert!(CollectedItemInputV1::parse(duplicate).is_err());
}

/// The checked-in vectors, decoded strictly.
pub fn golden_vectors() -> Vec<CollectedItemVectorV1> {
    VECTORS
        .strip_suffix(b"\n")
        .expect("the vector file ends with one LF")
        .split(|byte| *byte == b'\n')
        .map(|record| decode_typed_canonical(record).expect("a vector is canonical"))
        .collect()
}

#[test]
fn the_golden_vectors_derive_their_recorded_identities() {
    let vectors = golden_vectors();
    assert!(!vectors.is_empty());
    // One sealing of one version through one channel: the parts that share
    // a content digest by construction.
    let mut versions: BTreeMap<(Sha256Digest, &str, Option<&str>), Vec<&CollectedItemEnvelopeV1>> =
        BTreeMap::new();
    for vector in &vectors {
        let envelope = &vector.envelope;
        envelope.validate().unwrap();
        assert_eq!(envelope.item_key(), vector.item_key, "{}", vector.case);
        assert_eq!(
            envelope.version_key(),
            vector.version_key,
            "{}",
            vector.case
        );
        assert_eq!(
            envelope.immutable_revision(),
            vector.immutable_revision,
            "{}",
            vector.case
        );
        assert_eq!(
            envelope.container_key(),
            vector.container_key,
            "{}",
            vector.case
        );
        let sealing = (
            vector.version_key,
            envelope.collection.mode.as_str(),
            envelope
                .collection
                .attester
                .as_ref()
                .map(ContractId::as_str),
        );
        versions.entry(sealing).or_default().push(envelope);
    }
    // A multi-part version's content digest covers every part, in order.
    for parts in versions.values() {
        let mut parts = parts.clone();
        parts.sort_by_key(|envelope| envelope.part.ordinal);
        let text: String = parts
            .iter()
            .map(|envelope| envelope.text.as_str())
            .collect();
        let first = parts[0];
        assert_eq!(parts.len(), first.part.count as usize);
        assert_eq!(
            first.content_digest,
            derive_content_digest(first.title.as_ref().map(CollectedTextV1::as_str), &text)
        );
    }
    let revisions: std::collections::BTreeSet<_> = vectors
        .iter()
        .map(|vector| vector.immutable_revision)
        .collect();
    assert_eq!(
        revisions.len(),
        vectors.len(),
        "every vector is its own revision"
    );
}
