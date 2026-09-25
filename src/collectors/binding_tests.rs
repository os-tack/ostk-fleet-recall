//! The collected connector binding: one connector per channel, version-form or
//! nothing, the pinned scope, three ordered clocks, and a candidate admission
//! accepts and the body plane reads as exactly one body.

use super::*;
use crate::body_store::{derive_parse_run, parse_source, reference_parser_key_v1};
use crate::collectors::draft::{
    CollectedItemDraftV1, DraftAuthorV1, DraftContainerV1, DraftSectionV1, SealContextV1,
    SealedItemV1, collection_record, seal,
};
use crate::collectors::test_support::{
    generation_three_active, generation_two_git_active, redactor,
};
use crate::evidence_ledger::{EvidenceAdmissionError, EvidenceAdmissionRequestV1, admit_evidence};
use crate::memory_contracts::collected_item::{
    AudienceBasisV1, AuthorKindV1, ContainerKindV1, ItemLifecycleV1, ObjectKindV1, TextFormatV1,
};
use crate::memory_contracts::common::frozen_profile_reference_v1;
use crate::memory_contracts::digest::body_digest;
use crate::memory_contracts::evidence_v2::RepresentationLineageV2;
use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;

const GENERATION_ONE_PACKAGE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");

fn instance(provider: &str, scope: &str, id: &str) -> CollectorInstanceV1 {
    CollectorInstanceV1 {
        connector_instance_id: ContractId::new(id).unwrap(),
        provider: ProviderKindV1::new(provider).unwrap(),
        provider_scope_id: BoundedTextV1::new(scope).unwrap(),
    }
}

fn slack_instance() -> CollectorInstanceV1 {
    instance("slack", "T07ACME0001", "slack.acme")
}

fn draft() -> CollectedItemDraftV1 {
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
        thread: None,
        author: Some(DraftAuthorV1 {
            id: "U07CAROL003".into(),
            display: None,
            kind: AuthorKindV1::Human,
        }),
        created_at: Some(stamp("2026-09-21T16:12:02.004300000Z")),
        updated_at: None,
        title: None,
        sections: vec![DraftSectionV1::whole(
            "Decision: retry budget is 5 attempts with jitter\n\nSecond paragraph.".into(),
        )],
        text_format: TextFormatV1::SlackMrkdwnRendered,
        links: Vec::new(),
        provider_url: None,
        visibility: None,
    }
}

fn sealed(mode: CollectionModeV1, instance_id: &str) -> SealedItemV1 {
    let redactor = redactor();
    let attester =
        (mode == CollectionModeV1::Capture).then(|| ContractId::new("agent.alice").unwrap());
    let collection =
        collection_record(mode, ContractId::new(instance_id).unwrap(), attester, None).unwrap();
    let audience = match mode {
        CollectionModeV1::Capture => AudienceBasisV1::VerifiedContainer,
        CollectionModeV1::Import => AudienceBasisV1::OperatorDeclared,
        CollectionModeV1::Pull | CollectionModeV1::Push => AudienceBasisV1::ProviderPublic,
    };
    seal(
        &draft(),
        &SealContextV1 {
            redactor: &redactor,
            audience,
            collection: &collection,
        },
    )
    .unwrap()
}

fn envelope_bytes(mode: CollectionModeV1) -> Vec<u8> {
    sealed(mode, "slack.acme").parts[0]
        .canonical_envelope
        .clone()
}

fn stamp(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).unwrap()
}

fn clocks() -> CollectedRowClocksV1 {
    CollectedRowClocksV1 {
        occurred_at: stamp("2026-09-21T16:12:02.004300000Z"),
        observed_at: stamp("2026-09-25T12:00:00.000000000Z"),
        received_at: stamp("2026-09-25T12:00:00.000000000Z"),
    }
}

fn binding(mode: CollectionModeV1) -> (ActiveStage4Package, CollectedConnectorBindingV1) {
    let active = generation_three_active(mode);
    let binding = CollectedConnectorBindingV1::resolve(
        &active,
        mode,
        ContractId::new("principal.slack").unwrap(),
        slack_instance(),
    )
    .expect("generation 3 carries every collected connector");
    (active, binding)
}

#[test]
fn every_channel_binds_its_own_connector_as_version_form() {
    for mode in CollectionModeV1::ALL {
        let (_, binding) = binding(*mode);
        let uri = binding.canonical_resource_uri(&Sha256Digest::ZERO).unwrap();
        assert_eq!(uri.identity_form(), IdentityForm::Version);
        assert_eq!(binding.mode(), *mode);
        assert_eq!(
            binding.provider_instance_uri().unwrap().identity_form(),
            IdentityForm::Entity
        );
    }
}

#[test]
fn a_package_narrowed_to_another_connector_is_refused() {
    // Generation 3 narrowed to the pull connector cannot admit a capture.
    let pull = generation_three_active(CollectionModeV1::Pull);
    let error = CollectedConnectorBindingV1::resolve(
        &pull,
        CollectionModeV1::Capture,
        ContractId::new("principal.capture").unwrap(),
        slack_instance(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        CollectedBindingError::ConnectorMismatch {
            expected: "connector.collected.capture",
            ..
        }
    ));
    // A generation-2 head carries no collected connector at all.
    let git = generation_two_git_active();
    assert!(matches!(
        CollectedConnectorBindingV1::resolve(
            &git,
            CollectionModeV1::Pull,
            ContractId::new("principal.slack").unwrap(),
            slack_instance(),
        ),
        Err(CollectedBindingError::ConnectorMismatch { .. })
    ));
}

#[test]
fn an_occurrence_form_canonical_resource_is_refused() {
    let generation_one = SemanticallyClosedSuccessorPackage::from_manifest_verified(
        ManifestVerifiedRegistryPackage::decode(
            GENERATION_ONE_PACKAGE.strip_suffix(b"\n").unwrap(),
            &frozen_profile_reference_v1(),
        )
        .unwrap(),
    )
    .unwrap();
    let push = ValidatedIdentityRecipe::from_package(
        generation_one.manifest_verified_package(),
        &ContractId::new("identity.github.push").unwrap(),
        3,
    )
    .unwrap();
    match require_version_form(&push).unwrap_err() {
        CollectedBindingError::CanonicalResourceNotVersionForm { recipe, form } => {
            assert_eq!(recipe, "identity.github.push");
            assert_eq!(form, IdentityForm::Occurrence);
        }
        other => panic!("expected a version-form refusal, got {other}"),
    }
}

#[test]
fn the_candidate_is_admitted_and_projects_as_exactly_one_body() {
    let (active, binding) = binding(CollectionModeV1::Pull);
    let bytes = envelope_bytes(CollectionModeV1::Pull);
    let ingress = binding.build(&bytes, &clocks(), b"page-digest", 1).unwrap();
    assert_eq!(&ingress.candidate.scope, active.scope());
    assert_eq!(ingress.canonical_payload, bytes);

    let admitted = admit_evidence(
        &active,
        EvidenceAdmissionRequestV1 {
            candidate: &ingress.candidate,
            locators: &ingress.locators,
            canonical_payload: &ingress.canonical_payload,
            delivery: ingress.delivery.clone(),
            lineage: RepresentationLineageV2::Origin,
        },
    )
    .expect("admission accepts the candidate, clocks included");
    assert_eq!(
        admitted
            .statement()
            .source_fact
            .immutable_revision
            .as_bytes(),
        ingress.stage_id.as_bytes()
    );

    // The envelope has no raw newline even though its text has a paragraph
    // break, so the reference parser sees one body: the whole envelope.
    assert_eq!(parse_source(&reference_parser_key_v1(), &bytes).len(), 1);
    let run = derive_parse_run(admitted.statement(), &bytes, &reference_parser_key_v1()).unwrap();
    assert_eq!(run.bodies.len(), 1);
    assert_eq!(run.bodies[0].content_sha256, body_digest(&bytes));
    assert_eq!(run.media_type.as_str(), COLLECTED_ITEM_MEDIA_TYPE);
}

#[test]
fn a_foreign_scope_is_refused() {
    let active = generation_three_active(CollectionModeV1::Pull);
    let bytes = envelope_bytes(CollectionModeV1::Pull);
    for pinned in [
        instance("slack", "T07OTHER999", "slack.acme"),
        instance("linear", "T07ACME0001", "slack.acme"),
    ] {
        let binding = CollectedConnectorBindingV1::resolve(
            &active,
            CollectionModeV1::Pull,
            ContractId::new("principal.slack").unwrap(),
            pinned,
        )
        .unwrap();
        assert!(matches!(
            binding.build(&bytes, &clocks(), b"page", 1),
            Err(CollectedBindingError::ScopeMismatch)
        ));
    }
}

#[test]
fn another_channel_or_instance_is_refused() {
    let (_, pull) = binding(CollectionModeV1::Pull);
    let capture_bytes = envelope_bytes(CollectionModeV1::Capture);
    assert!(matches!(
        pull.build(&capture_bytes, &clocks(), b"page", 1),
        Err(CollectedBindingError::ModeMismatch { .. })
    ));
    let other_instance = sealed(CollectionModeV1::Pull, "slack.other").parts[0]
        .canonical_envelope
        .clone();
    assert!(matches!(
        pull.build(&other_instance, &clocks(), b"page", 1),
        Err(CollectedBindingError::InstanceMismatch)
    ));
}

#[test]
fn clocks_are_aligned_ordered_and_the_envelopes_own() {
    let (_, binding) = binding(CollectionModeV1::Pull);
    let bytes = envelope_bytes(CollectionModeV1::Pull);

    let mut ahead = clocks();
    ahead.observed_at = stamp("2026-09-21T16:00:00.000000000Z");
    ahead.received_at = stamp("2026-09-21T16:00:00.000000000Z");
    assert!(matches!(
        binding.build(&bytes, &ahead, b"page", 1),
        Err(CollectedBindingError::ClockOrder(_))
    ));

    let mut inverted = clocks();
    inverted.received_at = stamp("2026-09-25T11:00:00.000000000Z");
    assert!(matches!(
        binding.build(&bytes, &inverted, b"page", 1),
        Err(CollectedBindingError::ClockOrder(_))
    ));

    let mut misaligned = clocks();
    misaligned.observed_at = stamp("2026-09-25T12:00:00.000000001Z");
    assert!(matches!(
        binding.build(&bytes, &misaligned, b"page", 1),
        Err(CollectedBindingError::ClockOrder(_))
    ));

    let mut restated = clocks();
    restated.occurred_at = stamp("2026-09-21T16:12:03.000000000Z");
    assert!(matches!(
        binding.build(&bytes, &restated, b"page", 1),
        Err(CollectedBindingError::ClockOrder(_))
    ));
}

#[test]
fn a_misaligned_candidate_would_be_refused_by_admission_too() {
    // The binding's clock check mirrors admission's: a candidate whose clock
    // is altered after building is refused by `admit_evidence` itself.
    let (active, binding) = binding(CollectionModeV1::Pull);
    let bytes = envelope_bytes(CollectionModeV1::Pull);
    let mut ingress = binding.build(&bytes, &clocks(), b"page", 1).unwrap();
    ingress.candidate.observed_at = stamp("2026-09-21T16:00:00.000000000Z");
    let refused = admit_evidence(
        &active,
        EvidenceAdmissionRequestV1 {
            candidate: &ingress.candidate,
            locators: &ingress.locators,
            canonical_payload: &ingress.canonical_payload,
            delivery: ingress.delivery.clone(),
            lineage: RepresentationLineageV2::Origin,
        },
    );
    assert!(matches!(
        refused,
        Err(EvidenceAdmissionError::ClockOrder(_))
    ));
}

#[test]
fn only_a_verified_channel_asserts_the_provider_author() {
    let (_, pull) = binding(CollectionModeV1::Pull);
    let pulled = pull
        .build(
            &envelope_bytes(CollectionModeV1::Pull),
            &clocks(),
            b"page",
            1,
        )
        .unwrap();
    assert_eq!(
        pulled.candidate.provider_actor_id.unwrap().as_bytes(),
        b"U07CAROL003"
    );
    let (_, capture) = binding(CollectionModeV1::Capture);
    let captured = capture
        .build(
            &envelope_bytes(CollectionModeV1::Capture),
            &clocks(),
            b"request",
            1,
        )
        .unwrap();
    assert!(captured.candidate.provider_actor_id.is_none());
}

#[test]
fn a_capture_and_a_pull_are_different_resources_under_one_item() {
    let (_, pull) = binding(CollectionModeV1::Pull);
    let (_, capture) = binding(CollectionModeV1::Capture);
    let pulled = pull
        .build(
            &envelope_bytes(CollectionModeV1::Pull),
            &clocks(),
            b"page",
            1,
        )
        .unwrap();
    let captured = capture
        .build(
            &envelope_bytes(CollectionModeV1::Capture),
            &clocks(),
            b"request",
            1,
        )
        .unwrap();
    assert_eq!(
        pulled.candidate.source_fact.provider_object_id,
        captured.candidate.source_fact.provider_object_id,
        "one item key"
    );
    assert_ne!(
        pulled.candidate.source_fact.canonical_resource_id,
        captured.candidate.source_fact.canonical_resource_id
    );
    assert_ne!(
        pulled.candidate.connector_schema,
        captured.candidate.connector_schema
    );
}

#[test]
fn two_builds_of_one_row_are_identical_and_the_delivery_id_is_bounded() {
    let (_, binding) = binding(CollectionModeV1::Pull);
    let bytes = envelope_bytes(CollectionModeV1::Pull);
    assert_eq!(
        binding.build(&bytes, &clocks(), b"page", 1).unwrap(),
        binding.build(&bytes, &clocks(), b"page", 1).unwrap(),
        "a re-drain is an exact replay"
    );
    assert!(matches!(
        binding.build(&bytes, &clocks(), b"", 1),
        Err(CollectedBindingError::DeliveryId)
    ));
    assert!(matches!(
        binding.build(&bytes, &clocks(), &[7; MAX_DELIVERY_ID_BYTES + 1], 1),
        Err(CollectedBindingError::DeliveryId)
    ));
}

#[test]
fn a_non_canonical_envelope_is_refused() {
    let (_, binding) = binding(CollectionModeV1::Pull);
    let mut bytes = envelope_bytes(CollectionModeV1::Pull);
    bytes.push(b' ');
    assert!(matches!(
        binding.build(&bytes, &clocks(), b"page", 1),
        Err(CollectedBindingError::Envelope(_))
    ));
}
