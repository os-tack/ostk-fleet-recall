use std::{collections::BTreeMap, str::FromStr};

use super::*;
use crate::memory_contracts::{canonical::decode_strict, registry::RegistryHeadV1};

const PROPOSAL_POSITIVE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/normative/proposal-positive.jsonl");
const PROPOSAL_POSITIVE_BOUNDED_INTERVAL_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/normative/proposal-positive-bounded-interval.jsonl"
);
const PROPOSAL_NEGATIVE_UNSORTED_PROPOSITIONS_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/normative/proposal-negative-unsorted-propositions.jsonl"
);
const PROPOSAL_NEGATIVE_OVERLAPPING_SPANS_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/normative/proposal-negative-overlapping-spans.jsonl"
);
const PROPOSAL_NEGATIVE_WRONG_RESOURCE_FORM_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/normative/proposal-negative-wrong-resource-form.jsonl"
);
const RECEIPT_POSITIVE_AUTHOR_PLUS_INDEPENDENT_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/normative/receipt-positive-author-plus-independent.jsonl"
);
const RECEIPT_NEGATIVE_AUTHOR_ONLY_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/normative/receipt-negative-author-only.jsonl"
);
const RECEIPT_NEGATIVE_AUTHOR_ONLY_HONEST_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/normative/receipt-negative-author-only-honest.jsonl"
);
const LIFECYCLE_ACTIVATION_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/normative/lifecycle-activation.jsonl");
const LIFECYCLE_SUPERSESSION_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/normative/lifecycle-supersession.jsonl");
const LIFECYCLE_NEGATIVE_MISSING_SUPERSEDES_TARGET_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/normative/lifecycle-negative-missing-supersedes-target.jsonl"
);
const LIFECYCLE_NEGATIVE_SELF_SUPERSESSION_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/normative/lifecycle-negative-self-supersession.jsonl"
);
const CONTESTED_POSITIVE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/normative/contested-positive.jsonl");
const CONTESTED_NEGATIVE_SINGLE_STATEMENT_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/normative/contested-negative-single-statement.jsonl"
);
const RETROACTIVE_POSITIVE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/normative/retroactive-correction-positive.jsonl"
);
const RETROACTIVE_NEGATIVE_NOT_RETROACTIVE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/normative/retroactive-correction-negative-not-retroactive.jsonl"
);
const RETROACTIVE_NEGATIVE_ORDINARY_POLICY_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/normative/retroactive-correction-negative-ordinary-policy.jsonl"
);
const VECTOR_SUITE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/normative/vector-suite.jsonl");

const EXPECTED_PROPOSAL_STATEMENT_ID: &str =
    "7bee4127c05077b62beab8c7bb1d0e2ae46b6db0e6045b6aeca45fedf2cc59b4";
const EXPECTED_RECEIPT_ID: &str =
    "d8ac4e408e6b707f144d08b8001d099e68459e227a0bb1b44dcec4ba6c29cf07";
const EXPECTED_LIFECYCLE_ACTIVATION_EVENT_ID: &str =
    "221748a0b211d49f11f1ce2e9a64214e214a8f401b9479975ec4b01e441402cc";
const EXPECTED_LIFECYCLE_SUPERSESSION_EVENT_ID: &str =
    "4a2b35d9bb149e8edae89ea8d9cc61c8d96075d56ba6299a882e602114c58ec7";
const EXPECTED_CONTESTED_ID: &str =
    "103d1d2b73e0a6f29b60ae47247aa473c6faaee60b4d952d785bcaf60c245f57";
const EXPECTED_PROPOSAL_BOUNDED_INTERVAL_STATEMENT_ID: &str =
    "e46f5ee01f2e5769c1e97a09b2839c5001ac6dfd876d306813d9326f7e3858ae";

// Exact raw sha256 over every fixture file's full bytes (including its
// trailing LF), pinned independently of any typed decode. This is the
// house pattern from `remember_v2.rs`'s
// `hard_coded_contract_vectors_match_independent_ids`: unlike the
// `EXPECTED_*_ID` domain-separated digests above (which only cover the
// 5 fixtures with a semantic identity function), every fixture in this
// directory — positive, negative, and the vector-suite manifest itself
// — gets a raw byte pin here, so any tamper to any fixture's bytes
// (including a negative fixture edited to fail for a different reason
// than its filename and vector-suite description claim) fails
// `all_fixtures_are_byte_frozen` even when the fixture still happens to
// decode and still happens to be rejected by `validate()`.
const PROPOSAL_POSITIVE_RAW_SHA256: &str =
    "8f8576ac7b4480d467183abc0e892235c2b423154a008019e5c8409b006f3b3e";
const PROPOSAL_POSITIVE_BOUNDED_INTERVAL_RAW_SHA256: &str =
    "2e99d00ed3d9aa3c9b9858f4316b0d15b08ca704937d63ed778a7ee939ac39dd";
const PROPOSAL_NEGATIVE_UNSORTED_PROPOSITIONS_RAW_SHA256: &str =
    "c3d6d6b00b0037f6888297ac5ea98b388028d91e1f11e4c5b3198eacec64cf25";
const PROPOSAL_NEGATIVE_OVERLAPPING_SPANS_RAW_SHA256: &str =
    "5042aa5938b6b4bda4d4eb0002a985d00ac253cc89b5e69258b1a567a6e25560";
const PROPOSAL_NEGATIVE_WRONG_RESOURCE_FORM_RAW_SHA256: &str =
    "b2c33b7c801edc0b92054d4bdfeca88e14595c66162ef561fd358e7b93505e72";
const RECEIPT_POSITIVE_AUTHOR_PLUS_INDEPENDENT_RAW_SHA256: &str =
    "a953be98bae5dd78600cba231911a142e8f927b71410456cff234b64bf47f2a8";
const RECEIPT_NEGATIVE_AUTHOR_ONLY_RAW_SHA256: &str =
    "c75d5ddcc775a7cf84c2e6c73ab1a2b4f8c1b2adb3054c0cf9cdead1eec590eb";
const RECEIPT_NEGATIVE_AUTHOR_ONLY_HONEST_RAW_SHA256: &str =
    "596e4ed80bb5527a97d4f8fe0aaff8893b5358244802dddc581442a71b7b3b1a";
const LIFECYCLE_ACTIVATION_RAW_SHA256: &str =
    "13e222e822903c06cee547b608a046498663b9ea387c1cc451a867a892f0c414";
const LIFECYCLE_SUPERSESSION_RAW_SHA256: &str =
    "4ff7e019554d73aeca3a3e6daadf7a4fc5667504208005daf8ddd0f79b017249";
const LIFECYCLE_NEGATIVE_MISSING_SUPERSEDES_TARGET_RAW_SHA256: &str =
    "29cd34788fdd8898a6404cc4f38107b5cadd680507d9efa0ca749576c3454874";
const LIFECYCLE_NEGATIVE_SELF_SUPERSESSION_RAW_SHA256: &str =
    "47ef8010322f0bf79001cf277af65370557f695deef9bbc83d1b02c629cf912d";
const CONTESTED_POSITIVE_RAW_SHA256: &str =
    "93e83ab63ca50f39143db6ba941c3090b8cf637a8ba2675f6b9666dcaff74183";
const CONTESTED_NEGATIVE_SINGLE_STATEMENT_RAW_SHA256: &str =
    "f3c9f130d32e6dcc667177d418be9bb3ba06403f21c69b2cdc08d249668ff0bf";
const RETROACTIVE_POSITIVE_RAW_SHA256: &str =
    "00f00120f66986b61c0fb15a0e0ed532dc55a9416e5f86461ac0a59ff8d81051";
const RETROACTIVE_NEGATIVE_NOT_RETROACTIVE_RAW_SHA256: &str =
    "baff312a248b10fec310d04aa12d13e5c119ad937afc0a2ca8e84aade847fdf1";
const RETROACTIVE_NEGATIVE_ORDINARY_POLICY_RAW_SHA256: &str =
    "5b37b425ca9b5a956ef29032d6a19eb739e304bd15f4dbd6baad3c86f84a75bb";
const VECTOR_SUITE_RAW_SHA256: &str =
    "88b8f67815a025c5225f626e60ab806a920e507e37ed335c82d8dec9a295a036";

fn raw_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    hex::encode(Sha256::digest(bytes))
}

fn record(artifact: &'static [u8]) -> &'static [u8] {
    let record = artifact
        .strip_suffix(b"\n")
        .expect("fixture must end in exactly one LF");
    assert!(!record.ends_with(b"\n"));
    record
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::from_str(value).unwrap()
}

fn label_digest(label: &str) -> Sha256Digest {
    domain_separated_digest(DigestDomain::RegistryEntry, label.as_bytes())
}

/// Digests are pseudo-random relative to their labels, so callers that
/// need a strictly sorted set (as `ContestedBindingV1` requires) must
/// sort the derived digests explicitly rather than relying on label
/// order to happen to match digest order.
fn sorted_label_digests(labels: &[&str]) -> Vec<Sha256Digest> {
    let mut digests: Vec<Sha256Digest> = labels.iter().copied().map(label_digest).collect();
    digests.sort();
    digests
}

fn resource(form: &str, kind: &str, label: &str) -> ResourceUri {
    format!("urn:ostk:{form}:v1:{kind}:sha256:{}", label_digest(label))
        .parse()
        .unwrap()
}

fn reference(id: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version: 1,
        entry_digest: label_digest(id),
    }
}

fn profile() -> ProfileReferenceV1 {
    crate::memory_contracts::common::frozen_profile_reference_v1()
}

fn scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.fixture").unwrap(),
        ContractId::new("project.fixture").unwrap(),
    )
}

fn registry_head(from: &str) -> RegistryHeadBindingV1 {
    RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: label_digest("activation"),
            package_digest: label_digest("registry-package"),
            activation_policy_digest: label_digest("activation-policy"),
        },
        effective_from: CanonicalTimestamp::parse(from).unwrap(),
        effective_until: None,
    }
}

fn proposal() -> NormativeBindingProposalV2 {
    NormativeBindingProposalV2 {
        schema_version: 2,
        profile: profile(),
        scope: scope(),
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        expected_active_binding_set_digest: None,
        repository_entity_id: resource("entity", "repository", "repo"),
        repository_version_id: resource("version", "repository_version", "commit"),
        blob_id: resource("occurrence", "git_blob", "blob"),
        exact_path_bytes: HexBytes::new(b"docs/SLO.md".to_vec()).unwrap(),
        source_spans: vec![SourceByteSpanV1 {
            start: 10,
            end: 80,
            selected_bytes_digest: label_digest("span"),
        }],
        parser_artifact_id: resource("occurrence", "artifact", "parser"),
        parser_configuration_digest: label_digest("parser-config"),
        propositions: vec![NormativePropositionV1 {
            predicate_schema: reference("slo.error_rate"),
            proposition_fingerprint: label_digest("proposition"),
        }],
        applicability_evaluator: reference("environment.selector"),
        applicability_selector: CanonicalValue::Object(BTreeMap::from([(
            "environment".into(),
            CanonicalValue::String("production".into()),
        )])),
        effective_from: CanonicalTimestamp::parse("2026-08-14T12:00:00.000000000Z").unwrap(),
        effective_until: None,
        registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
        explicitly_supersedes_statement_id: None,
        proposer_principal_id: ContractId::new("principal.agent").unwrap(),
        source_author_principal_id: ContractId::new("principal.author").unwrap(),
    }
}

/// A proposal whose effective interval is bounded on both ends, unlike
/// `proposal()` (and every fixture generated from it), which always
/// leaves `effective_until: None`. This exercises the closed form of
/// `intervals_overlap`'s `b_before_a_end` term (the branch that consults
/// the *proposal's own* upper bound, not just the compared binding's),
/// which no other fixture or inline proposal in this module reaches.
fn bounded_proposal() -> NormativeBindingProposalV2 {
    let mut proposal = proposal();
    proposal.effective_until =
        Some(CanonicalTimestamp::parse("2026-09-01T00:00:00.000000000Z").unwrap());
    proposal
}

fn receipt(
    statement_id: Sha256Digest,
    source_author: &str,
    approving_principals: &[&str],
    required_threshold: u16,
    satisfied: bool,
) -> NormativeActivationReceiptV2 {
    let mut approvals: Vec<EligibleApprovalV1> = approving_principals
        .iter()
        .map(|principal| EligibleApprovalV1 {
            attestation_id: label_digest(&format!("attestation.{principal}")),
            principal_id: ContractId::new(*principal).unwrap(),
            signer_key_id: ContractId::new(format!("key.{principal}")).unwrap(),
        })
        .collect();
    approvals.sort();
    NormativeActivationReceiptV2 {
        schema_version: 2,
        statement_id,
        source_author_principal_id: ContractId::new(source_author).unwrap(),
        eligible_approvals: approvals,
        required_threshold,
        separation_of_duty:
            NormativeActivationSeparationOfDutyV2::IndependentApprovalFromSourceAuthor,
        separation_of_duty_satisfied: satisfied,
        accepted_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
    }
}

// --- statement identity and shape ---

#[test]
fn statement_identity_changes_with_exact_source_span() {
    let first = proposal();
    let first_id = first.statement_id().unwrap();
    let mut shifted = first;
    shifted.source_spans[0].start += 1;
    assert_ne!(first_id, shifted.statement_id().unwrap());
}

#[test]
fn statement_identity_does_not_reuse_v1_domain() {
    let a = proposal();
    let v2_id = a.statement_id().unwrap();
    // The v1 preimage uses a different domain prefix even for identical
    // logical content; v2 must not collide with it.
    let v1_domain_id = domain_separated_digest(
        DigestDomain::NormativeBindingStatement,
        &encode_canonical(&a).unwrap(),
    );
    assert_ne!(v2_id, v1_domain_id);
}

#[test]
fn a_document_edit_produces_new_evidence_but_does_not_disturb_the_prior_binding() {
    // Two proposals over the same binding family with different exact
    // source spans (as after a document edit) mint distinct statement
    // IDs. Nothing in this contract layer retires the earlier one:
    // retirement/supersession is a separate signed lifecycle event.
    let original = proposal();
    let mut edited = proposal();
    edited.source_spans = vec![SourceByteSpanV1 {
        start: 12,
        end: 90,
        selected_bytes_digest: label_digest("span-after-edit"),
    }];
    assert_ne!(
        original.statement_id().unwrap(),
        edited.statement_id().unwrap()
    );
}

#[test]
fn set_fields_are_rejected_instead_of_silently_sorted() {
    let mut invalid = proposal();
    invalid.propositions = vec![
        NormativePropositionV1 {
            predicate_schema: reference("z"),
            proposition_fingerprint: label_digest("z"),
        },
        NormativePropositionV1 {
            predicate_schema: reference("a"),
            proposition_fingerprint: label_digest("a"),
        },
    ];
    assert!(invalid.validate().is_err());
}

#[test]
fn source_coordinates_and_resource_forms_fail_closed() {
    let mut overlapping = proposal();
    overlapping.source_spans.push(SourceByteSpanV1 {
        start: 79,
        end: 90,
        selected_bytes_digest: label_digest("overlap"),
    });
    assert!(overlapping.validate().is_err());

    let mut wrong_form = proposal();
    wrong_form.repository_version_id = resource("entity", "repository", "not-a-version");
    assert!(wrong_form.validate().is_err());

    let mut zero_supersession = proposal();
    zero_supersession.explicitly_supersedes_statement_id = Some(Sha256Digest::ZERO);
    assert!(zero_supersession.validate().is_err());
}

#[test]
fn applicability_selector_must_be_an_object() {
    let mut invalid = proposal();
    invalid.applicability_selector = CanonicalValue::String("production".into());
    assert!(invalid.validate().is_err());
}

/// APPL-01: an empty object `{}` is the canonical encoding of `any` in
/// most selector languages, so it must fail closed exactly like a
/// non-object selector rather than silently resolving every dimension
/// to `any`. Deleting the `.is_empty()` half of the `is_none_or` guard
/// (leaving only the "must be an object" check above) must fail this
/// test.
#[test]
fn empty_object_applicability_selector_fails_closed() {
    let mut invalid = proposal();
    invalid.applicability_selector = CanonicalValue::Object(BTreeMap::new());
    assert!(invalid.validate().is_err());
}

/// Mutation coverage: no fixture or inline proposal anywhere else in
/// this suite carries an empty `source_spans`, so merging this disjunct
/// with its neighbor via `&&` survives the whole suite without it.
#[test]
fn empty_source_spans_is_rejected() {
    let mut invalid = proposal();
    invalid.source_spans = Vec::new();
    assert!(invalid.validate().is_err());
}

/// Mutation coverage: the identical gap for `propositions.is_empty()`.
#[test]
fn empty_propositions_is_rejected() {
    let mut invalid = proposal();
    invalid.propositions = Vec::new();
    assert!(invalid.validate().is_err());
}

/// Mutation coverage: `source_spans.len() > MAX_SPANS` has no dedicated
/// vector. `MAX_SPANS + 1` non-overlapping, strictly increasing spans
/// are otherwise valid shape, so only the bound guard rejects them.
#[test]
fn too_many_source_spans_is_rejected() {
    let mut invalid = proposal();
    invalid.source_spans = (0..=MAX_SPANS as u64)
        .map(|i| SourceByteSpanV1 {
            start: i * 100,
            end: i * 100 + 50,
            selected_bytes_digest: label_digest(&format!("span-{i}")),
        })
        .collect();
    assert!(invalid.validate().is_err());
}

/// Mutation coverage: `propositions.len() > MAX_PROPOSITIONS` has no
/// dedicated vector. `MAX_PROPOSITIONS + 1` propositions sharing one
/// predicate schema with strictly sorted fingerprints are otherwise
/// valid shape.
#[test]
fn too_many_propositions_is_rejected() {
    let labels: Vec<String> = (0..=MAX_PROPOSITIONS)
        .map(|i| format!("proposition-{i}"))
        .collect();
    let label_refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    let mut invalid = proposal();
    invalid.propositions = sorted_label_digests(&label_refs)
        .into_iter()
        .map(|fingerprint| NormativePropositionV1 {
            predicate_schema: reference("slo.error_rate"),
            proposition_fingerprint: fingerprint,
        })
        .collect();
    assert!(invalid.validate().is_err());
}

/// Mutation coverage: merging the `blob_id`/`parser_artifact_id`
/// Occurrence-form checks via `&&` survives the whole suite because
/// `proposal-negative-wrong-resource-form.jsonl` only ever misshapes
/// `repository_version_id`; neither `blob_id` nor `parser_artifact_id`
/// has its own negative vector. This covers `blob_id` alone.
#[test]
fn blob_id_wrong_form_alone_is_rejected() {
    let mut invalid = proposal();
    invalid.blob_id = resource("entity", "git_blob", "blob");
    assert!(invalid.validate().is_err());
}

/// Mutation coverage: the `parser_artifact_id` half of the same pair.
#[test]
fn parser_artifact_id_wrong_form_alone_is_rejected() {
    let mut invalid = proposal();
    invalid.parser_artifact_id = resource("entity", "artifact", "parser");
    assert!(invalid.validate().is_err());
}

/// AUTH-04: a bounded effective interval whose `effective_until` is at or
/// before its own `effective_from` is invalid shape, regardless of the
/// two-binding overlap check below. Every other proposal fixture and
/// inline value in this module leaves `effective_until: None`, so this
/// is the only vector that reaches this guard at all.
#[test]
fn effective_until_at_or_before_effective_from_is_rejected() {
    let mut equal = bounded_proposal();
    equal.effective_until = Some(equal.effective_from.clone());
    assert!(equal.validate().is_err());

    let mut before = bounded_proposal();
    before.effective_until =
        Some(CanonicalTimestamp::parse("2020-01-01T00:00:00.000000000Z").unwrap());
    assert!(before.validate().is_err());
}

// --- stale composite CAS ---

#[test]
fn stale_composite_head_after_activation_policy_change_is_rejected() {
    let statement = proposal();
    let current = statement.expected_composite_head();
    assert!(statement.require_current_composite(&current).is_ok());

    let mut policy_changed = current;
    policy_changed.activation_policy_digest = label_digest("new-activation-policy");
    assert_eq!(
        statement.require_current_composite(&policy_changed),
        Err(ContractError::StaleRegistryHead)
    );

    let mut registry_changed = current;
    registry_changed.registry_package_digest = label_digest("new-registry-package");
    assert_eq!(
        statement.require_current_composite(&registry_changed),
        Err(ContractError::StaleRegistryHead)
    );

    let mut binding_set_changed = current;
    binding_set_changed.active_binding_set_digest = Some(label_digest("new-binding-set"));
    assert_eq!(
        statement.require_current_composite(&binding_set_changed),
        Err(ContractError::StaleRegistryHead)
    );
}

/// A caller that reaches for `require_current_composite` or
/// `require_non_conflicting_activation` without separately calling
/// `validate()` must not get an unconditional pass on a shape that is
/// otherwise invalid (a non-object selector here). Deleting the
/// `self.validate()?;` line at the top of either method must fail this
/// test.
#[test]
fn relational_helpers_reject_an_unvalidated_shape() {
    let mut invalid = proposal();
    invalid.applicability_selector = CanonicalValue::String("production".into());
    let current = invalid.expected_composite_head();
    assert!(invalid.require_current_composite(&current).is_err());
    assert!(
        invalid
            .require_non_conflicting_activation(
                &invalid.binding_family_id,
                label_digest("active-statement"),
                &CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
                None,
            )
            .is_err()
    );
}

// --- supersession vs. incompatible overlap ---

#[test]
fn explicit_supersession_of_an_overlapping_active_binding_is_accepted() {
    let active_statement_id = label_digest("active-statement");
    let mut successor = proposal();
    successor.explicitly_supersedes_statement_id = Some(active_statement_id);
    assert!(
        successor
            .require_non_conflicting_activation(
                &successor.binding_family_id,
                active_statement_id,
                &CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
                None,
            )
            .is_ok()
    );
}

#[test]
fn implicit_overlap_without_explicit_supersession_is_rejected() {
    let active_statement_id = label_digest("active-statement");
    let successor = proposal();
    assert!(
        successor
            .require_non_conflicting_activation(
                &successor.binding_family_id,
                active_statement_id,
                &CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
                None,
            )
            .is_err()
    );
}

#[test]
fn non_overlapping_interval_never_conflicts() {
    let active_statement_id = label_digest("active-statement");
    let successor = proposal();
    assert!(
        successor
            .require_non_conflicting_activation(
                &successor.binding_family_id,
                active_statement_id,
                &CanonicalTimestamp::parse("2020-01-01T00:00:00.000000000Z").unwrap(),
                Some(&CanonicalTimestamp::parse("2021-01-01T00:00:00.000000000Z").unwrap()),
            )
            .is_ok()
    );
}

#[test]
fn a_different_binding_family_never_conflicts() {
    let active_statement_id = label_digest("active-statement");
    let successor = proposal();
    let other_family = ContractId::new("slo.other.errors").unwrap();
    assert!(
        successor
            .require_non_conflicting_activation(
                &other_family,
                active_statement_id,
                &CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
                None,
            )
            .is_ok()
    );
}

/// AUTH-04: `intervals_overlap`'s `b_before_a_end` term consults the
/// *proposal's own* upper bound (`until_a`, i.e. `effective_until`) when
/// deciding overlap. Every other overlap test in this module uses
/// `proposal()`, whose `effective_until` is always `None`, so
/// `b_before_a_end` is unconditionally `true` there and this term is
/// never actually exercised. Here the active binding starts strictly
/// after the bounded proposal's own `effective_until`, so the two
/// intervals do not overlap and no explicit supersession is required.
/// Replacing `b_before_a_end` with a hard-coded `true` would make this
/// (currently non-conflicting) pair register as an incompatible overlap.
#[test]
fn bounded_proposal_ending_before_active_binding_starts_does_not_conflict() {
    let active_statement_id = label_digest("active-statement");
    let successor = bounded_proposal();
    assert!(
        successor
            .require_non_conflicting_activation(
                &successor.binding_family_id,
                active_statement_id,
                &CanonicalTimestamp::parse("2027-01-01T00:00:00.000000000Z").unwrap(),
                None,
            )
            .is_ok()
    );
}

/// The same bounded proposal against an active binding that starts
/// *inside* its `[effective_from, effective_until)` window is a genuine
/// overlap and is rejected absent an explicit supersession target.
#[test]
fn bounded_proposal_overlapping_active_binding_without_explicit_supersession_is_rejected() {
    let active_statement_id = label_digest("active-statement");
    let successor = bounded_proposal();
    assert!(
        successor
            .require_non_conflicting_activation(
                &successor.binding_family_id,
                active_statement_id,
                &CanonicalTimestamp::parse("2026-08-20T00:00:00.000000000Z").unwrap(),
                None,
            )
            .is_err()
    );
}

// --- separation of duty ---

/// The shared message for every structural receipt guard (schema
/// version, threshold not met, too many/too few approvals, unsorted or
/// non-unique approvals) — distinct from the separation-of-duty
/// re-derivation message below. Asserting on these exact strings
/// (rather than `is_err()`) pins *which* family of guard rejected a
/// receipt, so a vector documented as an AUTH-03 `SoD` failure cannot
/// silently start passing only because an unrelated structural guard
/// happens to reject it for a different reason first.
const RECEIPT_STRUCTURAL_GUARD_ERROR: &str = "invalid normative activation receipt v2";
const RECEIPT_SOD_MISMATCH_ERROR: &str =
    "declared separation-of-duty verdict does not match its declared approvals";
const PROPOSAL_STRUCTURAL_GUARD_ERROR: &str = "invalid normative binding proposal v2";

#[test]
fn author_only_approval_is_rejected() {
    // required_threshold == 1: the lone author approval already meets
    // the threshold, so the threshold guard at the top of `validate()`
    // cannot reject this receipt — rejection can only come from the
    // separation-of-duty re-derivation below it. This is the vector
    // AUTH-03 actually depends on: with `required_threshold >= 2`,
    // `approval_bindings_are_unique` already forces >= 2 distinct
    // principals whenever the threshold is met, so SoD is trivially
    // satisfied and never exercised.
    let statement_id = label_digest("statement");
    let author_only = receipt(
        statement_id,
        "principal.author",
        &["principal.author"],
        1,
        true,
    );
    assert_eq!(
        author_only.validate(),
        Err(ContractError::Schema(RECEIPT_SOD_MISMATCH_ERROR.into()))
    );
}

/// AUTH-03: the honest (declared false, derived false) quadrant. The two
/// vectors above only ever cover a *disagreeing* declared flag —
/// `author_only_approval_is_rejected` declares `true` when the derived
/// verdict is `false`, and `declared_satisfied_flag_disagreeing_with_approvals_is_rejected`
/// declares `false` when the derived verdict is `true`. Neither exercises
/// an author-only receipt that honestly declares `separation_of_duty_satisfied:
/// false`. `validate()`'s guard is
/// `derived_verdict != self.separation_of_duty_satisfied || !self.separation_of_duty_satisfied`:
/// the second disjunct is what rejects *this* receipt (derived and
/// declared agree, both `false`), and it is the disjunct a reviewer's
/// mutation test deleted while every existing test kept passing.
/// Deleting `|| !self.separation_of_duty_satisfied` makes this test the
/// one that fails, because after that deletion the (false, false) pair
/// satisfies `derived_verdict != self.separation_of_duty_satisfied ==
/// false` and `validate()` would return `Ok(())`.
#[test]
fn honestly_declared_unsatisfied_sod_with_author_only_approval_is_still_rejected() {
    let statement_id = label_digest("statement");
    let honestly_declared_unsatisfied = receipt(
        statement_id,
        "principal.author",
        &["principal.author"],
        1,
        false,
    );
    assert_eq!(
        honestly_declared_unsatisfied.validate(),
        Err(ContractError::Schema(RECEIPT_SOD_MISMATCH_ERROR.into()))
    );
}

#[test]
fn declared_satisfied_flag_disagreeing_with_approvals_is_rejected() {
    let statement_id = label_digest("statement");
    // Two eligible approvals meet the threshold, but the declared flag
    // falsely claims SoD was NOT satisfied even though an independent
    // approver is present; the receipt must re-derive, not trust, so a
    // disagreeing flag is itself invalid.
    let mismatched = receipt(
        statement_id,
        "principal.author",
        &["principal.author", "principal.independent"],
        2,
        false,
    );
    assert_eq!(
        mismatched.validate(),
        Err(ContractError::Schema(RECEIPT_SOD_MISMATCH_ERROR.into()))
    );
}

#[test]
fn author_plus_independent_approval_meeting_threshold_is_accepted() {
    let statement_id = label_digest("statement");
    let ok = receipt(
        statement_id,
        "principal.author",
        &["principal.author", "principal.independent"],
        2,
        true,
    );
    assert!(ok.validate().is_ok());
}

#[test]
fn threshold_not_met_is_rejected_even_with_independent_approval() {
    let statement_id = label_digest("statement");
    let under_threshold = receipt(
        statement_id,
        "principal.author",
        &["principal.independent"],
        2,
        true,
    );
    assert_eq!(
        under_threshold.validate(),
        Err(ContractError::Schema(RECEIPT_STRUCTURAL_GUARD_ERROR.into()))
    );
}

#[test]
fn duplicate_principal_or_key_is_rejected() {
    let statement_id = label_digest("statement");
    let mut duplicated = receipt(
        statement_id,
        "principal.author",
        &["principal.author", "principal.independent"],
        2,
        true,
    );
    duplicated.eligible_approvals[0].principal_id =
        duplicated.eligible_approvals[1].principal_id.clone();
    duplicated.eligible_approvals.sort();
    assert_eq!(
        duplicated.validate(),
        Err(ContractError::Schema(RECEIPT_STRUCTURAL_GUARD_ERROR.into()))
    );
}

// --- lifecycle events ---

#[test]
fn supersession_without_explicit_target_is_rejected() {
    let event = NormativeLifecycleEventV1 {
        schema_version: 1,
        kind: NormativeLifecycleKindV1::Supersession,
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        statement_id: label_digest("statement"),
        registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
        effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        supersedes_statement_id: None,
        waiver_reference_digest: None,
    };
    assert!(event.validate().is_err());
}

#[test]
fn activation_naming_a_supersession_target_is_rejected() {
    let event = NormativeLifecycleEventV1 {
        schema_version: 1,
        kind: NormativeLifecycleKindV1::Activation,
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        statement_id: label_digest("statement"),
        registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
        effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        supersedes_statement_id: Some(label_digest("prior-statement")),
        waiver_reference_digest: None,
    };
    assert!(event.validate().is_err());
}

/// AUTH-04: a supersession event may not name itself as its own
/// supersession target. Without this guard, a runtime applying this
/// event would retire the very statement it names as its own successor,
/// leaving the binding family with no active binding while appearing to
/// have executed a valid, policy-governed supersession. This mirrors the
/// self-reference guard already present on `RetroactiveCorrectionV1`
/// (`statement_id == superseded_as_known_statement_id`).
#[test]
fn a_supersession_event_naming_itself_as_its_own_target_is_rejected() {
    let statement_id = label_digest("statement");
    let self_referential = NormativeLifecycleEventV1 {
        schema_version: 1,
        kind: NormativeLifecycleKindV1::Supersession,
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        statement_id,
        registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
        effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        supersedes_statement_id: Some(statement_id),
        waiver_reference_digest: None,
    };
    assert!(self_referential.validate().is_err());
}

/// Zero-digest hygiene: `Sha256Digest::ZERO` is already rejected as a
/// `supersedes_statement_id` two lines above; it must be rejected as the
/// event's own `statement_id` for the same reason (a real digest is
/// never all-zero), consistent with `RetroactiveCorrectionV1` below.
#[test]
fn zero_statement_id_is_rejected() {
    let event = NormativeLifecycleEventV1 {
        schema_version: 1,
        kind: NormativeLifecycleKindV1::Activation,
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        statement_id: Sha256Digest::ZERO,
        registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
        effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        supersedes_statement_id: None,
        waiver_reference_digest: None,
    };
    assert!(event.validate().is_err());
}

#[test]
fn every_lifecycle_kind_produces_a_distinct_event_id() {
    let base =
        |kind: NormativeLifecycleKindV1, target: Option<Sha256Digest>| NormativeLifecycleEventV1 {
            schema_version: 1,
            kind,
            binding_family_id: ContractId::new("slo.home.errors").unwrap(),
            statement_id: label_digest("statement"),
            registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
            effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            supersedes_statement_id: target,
            waiver_reference_digest: None,
        };
    let ids = [
        base(NormativeLifecycleKindV1::Activation, None)
            .event_id()
            .unwrap(),
        base(NormativeLifecycleKindV1::Retirement, None)
            .event_id()
            .unwrap(),
        base(NormativeLifecycleKindV1::Retraction, None)
            .event_id()
            .unwrap(),
        base(NormativeLifecycleKindV1::Expiry, None)
            .event_id()
            .unwrap(),
        base(
            NormativeLifecycleKindV1::Supersession,
            Some(label_digest("prior-statement")),
        )
        .event_id()
        .unwrap(),
    ];
    for (index, left) in ids.iter().enumerate() {
        for right in &ids[index + 1..] {
            assert_ne!(left, right);
        }
    }
}

// --- contested ---

#[test]
fn two_independently_accepted_statements_with_unestablishable_ordering_are_contested() {
    let contested = ContestedBindingV1 {
        schema_version: 1,
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        contested_statement_ids: sorted_label_digests(&["statement-a", "statement-b"]),
        reason: NormativeContestReasonV1::IndependentlyAcceptedUnestablishableOrdering,
        detected_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        waiver_reference_digest: None,
    };
    assert!(contested.validate().is_ok());
    assert!(contested.dependent_comparison_is_unknown());
}

#[test]
fn a_single_statement_cannot_be_contested() {
    let mut single = ContestedBindingV1 {
        schema_version: 1,
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        contested_statement_ids: vec![label_digest("statement-a")],
        reason: NormativeContestReasonV1::LateOrCorrectiveEvidence,
        detected_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        waiver_reference_digest: None,
    };
    assert!(single.validate().is_err());
    single
        .contested_statement_ids
        .push(label_digest("statement-a"));
    assert!(
        single.validate().is_err(),
        "duplicate IDs are not two distinct statements"
    );
}

/// Zero-digest hygiene: a real statement ID is never `Sha256Digest::ZERO`,
/// consistent with the lifecycle event and retroactive-correction guards.
/// `ZERO` sorts first (all-zero bytes), so this vector is otherwise
/// strictly sorted and would validate but for the new zero-digest guard.
#[test]
fn a_zero_digest_among_contested_statements_is_rejected() {
    let with_zero = ContestedBindingV1 {
        schema_version: 1,
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        contested_statement_ids: vec![Sha256Digest::ZERO, label_digest("statement-a")],
        reason: NormativeContestReasonV1::LateOrCorrectiveEvidence,
        detected_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        waiver_reference_digest: None,
    };
    assert!(with_zero.validate().is_err());
}

// --- retroactive correction ---

#[test]
fn normal_policy_rejects_effective_time_before_accepted_time() {
    let effective_from = CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap();
    let accepted_at = CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap();
    assert_eq!(
        require_effective_not_before_accepted(&effective_from, &accepted_at),
        Err(ContractError::Schema(
            "normal activation policy forbids an effective time before the accepted time".into()
        ))
    );
}

#[test]
fn higher_threshold_retroactive_correction_appends_a_bitemporal_pair() {
    let correction = RetroactiveCorrectionV1 {
        schema_version: 1,
        statement_id: label_digest("corrected-statement"),
        superseded_as_known_statement_id: label_digest("prior-as-known-statement"),
        effective_from: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
        accepted_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        authorizing_policy: reference("normative.retroactive_correction_policy"),
        authorizing_policy_required_threshold: 3,
        normal_activation_policy: reference("normative.normal_activation_policy"),
        normal_activation_policy_required_threshold: 2,
    };
    assert!(correction.validate().is_ok());
    // The prior as-known conclusion's identity is untouched: this is an
    // append naming it, not a rewrite of it.
    assert_ne!(
        correction.statement_id,
        correction.superseded_as_known_statement_id
    );
}

#[test]
fn a_correction_whose_effective_time_is_not_actually_retroactive_is_rejected() {
    let not_retroactive = RetroactiveCorrectionV1 {
        schema_version: 1,
        statement_id: label_digest("corrected-statement"),
        superseded_as_known_statement_id: label_digest("prior-as-known-statement"),
        effective_from: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        accepted_at: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
        authorizing_policy: reference("normative.retroactive_correction_policy"),
        authorizing_policy_required_threshold: 3,
        normal_activation_policy: reference("normative.normal_activation_policy"),
        normal_activation_policy_required_threshold: 2,
    };
    assert!(not_retroactive.validate().is_err());
}

#[test]
fn a_correction_naming_itself_as_the_superseded_conclusion_is_rejected() {
    let same_id = label_digest("same-statement");
    let self_referential = RetroactiveCorrectionV1 {
        schema_version: 1,
        statement_id: same_id,
        superseded_as_known_statement_id: same_id,
        effective_from: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
        accepted_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        authorizing_policy: reference("normative.retroactive_correction_policy"),
        authorizing_policy_required_threshold: 3,
        normal_activation_policy: reference("normative.normal_activation_policy"),
        normal_activation_policy_required_threshold: 2,
    };
    assert!(self_referential.validate().is_err());
}

/// Zero-digest hygiene: neither `statement_id` nor
/// `superseded_as_known_statement_id` may be `Sha256Digest::ZERO`,
/// consistent with the lifecycle-event and contested-binding guards.
#[test]
fn a_zero_digest_statement_id_is_rejected() {
    let mut zero_new = RetroactiveCorrectionV1 {
        schema_version: 1,
        statement_id: Sha256Digest::ZERO,
        superseded_as_known_statement_id: label_digest("prior-as-known-statement"),
        effective_from: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
        accepted_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        authorizing_policy: reference("normative.retroactive_correction_policy"),
        authorizing_policy_required_threshold: 3,
        normal_activation_policy: reference("normative.normal_activation_policy"),
        normal_activation_policy_required_threshold: 2,
    };
    assert!(zero_new.validate().is_err());
    zero_new.statement_id = label_digest("corrected-statement");
    zero_new.superseded_as_known_statement_id = Sha256Digest::ZERO;
    assert!(zero_new.validate().is_err());
}

/// AUTH-04: a retroactive correction naming the *ordinary* activation
/// policy as its own authorizing policy must be rejected — "an
/// exceptional retroactive correction requires a separately named
/// higher-threshold policy" is a requirement on the correction record
/// itself, not merely documentation. Neutering the distinctness or
/// threshold-comparison guard in `RetroactiveCorrectionV1::validate`
/// must make this test fail.
#[test]
fn a_correction_authorized_by_the_ordinary_activation_policy_is_rejected() {
    let ordinary_policy_as_authorizer = RetroactiveCorrectionV1 {
        schema_version: 1,
        statement_id: label_digest("corrected-statement"),
        superseded_as_known_statement_id: label_digest("prior-as-known-statement"),
        effective_from: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
        accepted_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        authorizing_policy: reference("normative.normal_activation_policy"),
        authorizing_policy_required_threshold: 2,
        normal_activation_policy: reference("normative.normal_activation_policy"),
        normal_activation_policy_required_threshold: 2,
    };
    assert_eq!(
        ordinary_policy_as_authorizer.validate(),
        Err(ContractError::Schema(
            "invalid retroactive correction v1".into()
        ))
    );
}

/// A distinct authorizing policy is not sufficient by itself: it must
/// also declare a strictly higher threshold than the normal activation
/// policy it is exceptional relative to. A merely-distinct policy at an
/// equal or lower threshold is not "higher-threshold" and must still be
/// rejected.
#[test]
fn a_correction_authorized_at_an_equal_or_lower_threshold_is_rejected() {
    let equal_threshold = RetroactiveCorrectionV1 {
        schema_version: 1,
        statement_id: label_digest("corrected-statement"),
        superseded_as_known_statement_id: label_digest("prior-as-known-statement"),
        effective_from: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
        accepted_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        authorizing_policy: reference("normative.retroactive_correction_policy"),
        authorizing_policy_required_threshold: 2,
        normal_activation_policy: reference("normative.normal_activation_policy"),
        normal_activation_policy_required_threshold: 2,
    };
    assert_eq!(
        equal_threshold.validate(),
        Err(ContractError::Schema(
            "invalid retroactive correction v1".into()
        ))
    );

    let mut lower_threshold = equal_threshold;
    lower_threshold.authorizing_policy_required_threshold = 1;
    assert!(lower_threshold.validate().is_err());
}

// --- fixtures: byte-frozen positive and negative vectors ---

#[test]
fn fixture_proposal_positive_matches_expected_statement_id() {
    let fixture: NormativeBindingProposalV2 =
        decode_strict(record(PROPOSAL_POSITIVE_FIXTURE)).unwrap();
    assert_eq!(
        encode_canonical(&fixture).unwrap(),
        record(PROPOSAL_POSITIVE_FIXTURE)
    );
    assert_eq!(
        fixture.statement_id().unwrap(),
        digest(EXPECTED_PROPOSAL_STATEMENT_ID)
    );
}

#[test]
fn fixture_proposal_positive_bounded_interval_matches_expected_statement_id() {
    let fixture: NormativeBindingProposalV2 =
        decode_strict(record(PROPOSAL_POSITIVE_BOUNDED_INTERVAL_FIXTURE)).unwrap();
    assert!(fixture.effective_until.is_some());
    assert_eq!(
        encode_canonical(&fixture).unwrap(),
        record(PROPOSAL_POSITIVE_BOUNDED_INTERVAL_FIXTURE)
    );
    assert_eq!(
        fixture.statement_id().unwrap(),
        digest(EXPECTED_PROPOSAL_BOUNDED_INTERVAL_STATEMENT_ID)
    );
}

#[test]
fn fixture_proposal_negatives_fail_closed() {
    let unsorted: NormativeBindingProposalV2 =
        decode_strict(record(PROPOSAL_NEGATIVE_UNSORTED_PROPOSITIONS_FIXTURE)).unwrap();
    assert_eq!(
        unsorted.validate(),
        Err(ContractError::Schema(
            PROPOSAL_STRUCTURAL_GUARD_ERROR.into()
        ))
    );

    let overlapping: NormativeBindingProposalV2 =
        decode_strict(record(PROPOSAL_NEGATIVE_OVERLAPPING_SPANS_FIXTURE)).unwrap();
    assert_eq!(
        overlapping.validate(),
        Err(ContractError::Schema(
            PROPOSAL_STRUCTURAL_GUARD_ERROR.into()
        ))
    );

    let wrong_form: NormativeBindingProposalV2 =
        decode_strict(record(PROPOSAL_NEGATIVE_WRONG_RESOURCE_FORM_FIXTURE)).unwrap();
    assert_eq!(
        wrong_form.validate(),
        Err(ContractError::Schema(
            PROPOSAL_STRUCTURAL_GUARD_ERROR.into()
        ))
    );
}

#[test]
fn fixture_receipt_positive_matches_expected_receipt_id() {
    let fixture: NormativeActivationReceiptV2 =
        decode_strict(record(RECEIPT_POSITIVE_AUTHOR_PLUS_INDEPENDENT_FIXTURE)).unwrap();
    assert!(fixture.validate().is_ok());
    assert_eq!(
        encode_canonical(&fixture).unwrap(),
        record(RECEIPT_POSITIVE_AUTHOR_PLUS_INDEPENDENT_FIXTURE)
    );
    assert_eq!(fixture.receipt_id().unwrap(), digest(EXPECTED_RECEIPT_ID));
}

#[test]
fn fixture_receipt_negative_author_only_fails_closed() {
    let fixture: NormativeActivationReceiptV2 =
        decode_strict(record(RECEIPT_NEGATIVE_AUTHOR_ONLY_FIXTURE)).unwrap();
    assert!(fixture.validate().is_err());
}

/// The honest-declaration companion to the fixture above: this one
/// truthfully declares `separation_of_duty_satisfied: false` for the
/// same author-only, threshold-met shape. See
/// `honestly_declared_unsatisfied_sod_with_author_only_approval_is_still_rejected`
/// for why this quadrant matters independently of the falsely-declared
/// one.
#[test]
fn fixture_receipt_negative_author_only_honest_declaration_fails_closed() {
    let fixture: NormativeActivationReceiptV2 =
        decode_strict(record(RECEIPT_NEGATIVE_AUTHOR_ONLY_HONEST_FIXTURE)).unwrap();
    assert_eq!(
        fixture.validate(),
        Err(ContractError::Schema(RECEIPT_SOD_MISMATCH_ERROR.into()))
    );
}

#[test]
fn fixture_lifecycle_events_match_expected_ids() {
    let activation: NormativeLifecycleEventV1 =
        decode_strict(record(LIFECYCLE_ACTIVATION_FIXTURE)).unwrap();
    assert_eq!(
        encode_canonical(&activation).unwrap(),
        record(LIFECYCLE_ACTIVATION_FIXTURE)
    );
    assert_eq!(
        activation.event_id().unwrap(),
        digest(EXPECTED_LIFECYCLE_ACTIVATION_EVENT_ID)
    );

    let supersession: NormativeLifecycleEventV1 =
        decode_strict(record(LIFECYCLE_SUPERSESSION_FIXTURE)).unwrap();
    assert_eq!(
        supersession.event_id().unwrap(),
        digest(EXPECTED_LIFECYCLE_SUPERSESSION_EVENT_ID)
    );

    let negative: NormativeLifecycleEventV1 =
        decode_strict(record(LIFECYCLE_NEGATIVE_MISSING_SUPERSEDES_TARGET_FIXTURE)).unwrap();
    assert!(negative.validate().is_err());

    let self_referential: NormativeLifecycleEventV1 =
        decode_strict(record(LIFECYCLE_NEGATIVE_SELF_SUPERSESSION_FIXTURE)).unwrap();
    assert!(self_referential.validate().is_err());
}

#[test]
fn fixture_contested_positive_matches_expected_id_and_negative_fails_closed() {
    let positive: ContestedBindingV1 = decode_strict(record(CONTESTED_POSITIVE_FIXTURE)).unwrap();
    assert_eq!(
        encode_canonical(&positive).unwrap(),
        record(CONTESTED_POSITIVE_FIXTURE)
    );
    assert_eq!(
        positive.contested_id().unwrap(),
        digest(EXPECTED_CONTESTED_ID)
    );

    let negative: ContestedBindingV1 =
        decode_strict(record(CONTESTED_NEGATIVE_SINGLE_STATEMENT_FIXTURE)).unwrap();
    assert!(negative.validate().is_err());
}

#[test]
fn fixture_retroactive_correction_positive_and_negative() {
    let positive: RetroactiveCorrectionV1 =
        decode_strict(record(RETROACTIVE_POSITIVE_FIXTURE)).unwrap();
    assert!(positive.validate().is_ok());
    assert_eq!(
        encode_canonical(&positive).unwrap(),
        record(RETROACTIVE_POSITIVE_FIXTURE)
    );

    let negative: RetroactiveCorrectionV1 =
        decode_strict(record(RETROACTIVE_NEGATIVE_NOT_RETROACTIVE_FIXTURE)).unwrap();
    assert_eq!(
        negative.validate(),
        Err(ContractError::Schema(
            "invalid retroactive correction v1".into()
        ))
    );

    // AUTH-04: the ordinary activation policy cannot authorize its own
    // exception. This fixture is genuinely retroactive (its timestamps
    // alone would pass) but names `normative.normal_activation_policy`
    // as both `authorizing_policy` and `normal_activation_policy` at an
    // equal threshold, so it must still be rejected.
    let ordinary_policy: RetroactiveCorrectionV1 =
        decode_strict(record(RETROACTIVE_NEGATIVE_ORDINARY_POLICY_FIXTURE)).unwrap();
    assert!(ordinary_policy.effective_from < ordinary_policy.accepted_at);
    assert_eq!(
        ordinary_policy.validate(),
        Err(ContractError::Schema(
            "invalid retroactive correction v1".into()
        ))
    );
}

/// Every fixture in this directory — positive, negative, and the
/// vector-suite manifest — is pinned to an exact raw sha256 over its
/// full bytes (including the trailing LF), independent of whether it
/// happens to decode or happens to fail `validate()` for the reason its
/// filename claims. Tampering with any fixture's bytes (e.g. swapping
/// which field makes a negative fixture invalid, or fixing a negative
/// fixture into a passing one) fails this test even if every other
/// fixture-consuming test in this module still passes.
#[test]
#[allow(clippy::too_many_lines)] // enumerates every fixture in the directory
fn all_fixtures_are_byte_frozen() {
    for (bytes, expected_raw_sha256) in [
        (PROPOSAL_POSITIVE_FIXTURE, PROPOSAL_POSITIVE_RAW_SHA256),
        (
            PROPOSAL_POSITIVE_BOUNDED_INTERVAL_FIXTURE,
            PROPOSAL_POSITIVE_BOUNDED_INTERVAL_RAW_SHA256,
        ),
        (
            PROPOSAL_NEGATIVE_UNSORTED_PROPOSITIONS_FIXTURE,
            PROPOSAL_NEGATIVE_UNSORTED_PROPOSITIONS_RAW_SHA256,
        ),
        (
            PROPOSAL_NEGATIVE_OVERLAPPING_SPANS_FIXTURE,
            PROPOSAL_NEGATIVE_OVERLAPPING_SPANS_RAW_SHA256,
        ),
        (
            PROPOSAL_NEGATIVE_WRONG_RESOURCE_FORM_FIXTURE,
            PROPOSAL_NEGATIVE_WRONG_RESOURCE_FORM_RAW_SHA256,
        ),
        (
            RECEIPT_POSITIVE_AUTHOR_PLUS_INDEPENDENT_FIXTURE,
            RECEIPT_POSITIVE_AUTHOR_PLUS_INDEPENDENT_RAW_SHA256,
        ),
        (
            RECEIPT_NEGATIVE_AUTHOR_ONLY_FIXTURE,
            RECEIPT_NEGATIVE_AUTHOR_ONLY_RAW_SHA256,
        ),
        (
            RECEIPT_NEGATIVE_AUTHOR_ONLY_HONEST_FIXTURE,
            RECEIPT_NEGATIVE_AUTHOR_ONLY_HONEST_RAW_SHA256,
        ),
        (
            LIFECYCLE_ACTIVATION_FIXTURE,
            LIFECYCLE_ACTIVATION_RAW_SHA256,
        ),
        (
            LIFECYCLE_SUPERSESSION_FIXTURE,
            LIFECYCLE_SUPERSESSION_RAW_SHA256,
        ),
        (
            LIFECYCLE_NEGATIVE_MISSING_SUPERSEDES_TARGET_FIXTURE,
            LIFECYCLE_NEGATIVE_MISSING_SUPERSEDES_TARGET_RAW_SHA256,
        ),
        (
            LIFECYCLE_NEGATIVE_SELF_SUPERSESSION_FIXTURE,
            LIFECYCLE_NEGATIVE_SELF_SUPERSESSION_RAW_SHA256,
        ),
        (CONTESTED_POSITIVE_FIXTURE, CONTESTED_POSITIVE_RAW_SHA256),
        (
            CONTESTED_NEGATIVE_SINGLE_STATEMENT_FIXTURE,
            CONTESTED_NEGATIVE_SINGLE_STATEMENT_RAW_SHA256,
        ),
        (
            RETROACTIVE_POSITIVE_FIXTURE,
            RETROACTIVE_POSITIVE_RAW_SHA256,
        ),
        (
            RETROACTIVE_NEGATIVE_NOT_RETROACTIVE_FIXTURE,
            RETROACTIVE_NEGATIVE_NOT_RETROACTIVE_RAW_SHA256,
        ),
        (
            RETROACTIVE_NEGATIVE_ORDINARY_POLICY_FIXTURE,
            RETROACTIVE_NEGATIVE_ORDINARY_POLICY_RAW_SHA256,
        ),
        (VECTOR_SUITE_FIXTURE, VECTOR_SUITE_RAW_SHA256),
    ] {
        assert_eq!(raw_sha256(bytes), expected_raw_sha256);
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorSuiteEntryV1 {
    vector_id: ContractId,
    fixture_path: String,
    polarity: String,
    invariant_ids: Vec<String>,
    description: String,
}

#[test]
fn vector_suite_manifest_is_canonical_and_lists_every_fixture() {
    let suite_text = std::str::from_utf8(record(VECTOR_SUITE_FIXTURE)).unwrap();
    let entries: Vec<VectorSuiteEntryV1> = suite_text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(entries.len(), 26);
    for entry in &entries {
        assert!(!entry.invariant_ids.is_empty());
        assert!(
            entry.polarity == "positive" || entry.polarity == "negative",
            "unexpected polarity {}",
            entry.polarity
        );
        assert!(!entry.description.is_empty());
        assert!(
            entry.fixture_path == "inline"
                || entry
                    .fixture_path
                    .starts_with("contracts/dynamic-memory/v3/normative/")
        );
    }
    let unique_vector_ids: std::collections::BTreeSet<&ContractId> =
        entries.iter().map(|entry| &entry.vector_id).collect();
    assert_eq!(
        unique_vector_ids.len(),
        entries.len(),
        "vector_suite.jsonl must not repeat a vector_id"
    );
}

#[test]
#[ignore = "maintainer-only canonical fixture regeneration"]
#[allow(clippy::too_many_lines)] // constructs every fixture vector inline for clarity
fn regenerate_normative_v2_contract_artifacts() {
    use std::{fs, path::Path};

    fn framed(bytes: &[u8]) -> Vec<u8> {
        let mut framed = bytes.to_vec();
        framed.push(b'\n');
        framed
    }

    fn write(output: &Path, name: &str, bytes: &[u8]) {
        let framed = framed(bytes);
        eprintln!("{name} raw_sha256={}", raw_sha256(&framed));
        fs::write(output.join(name), framed).unwrap();
    }

    let output = std::env::var_os("NORMATIVE_V2_VECTOR_OUTPUT")
        .map(std::path::PathBuf::from)
        .expect("NORMATIVE_V2_VECTOR_OUTPUT is required");
    fs::create_dir_all(&output).unwrap();

    let base_proposal = proposal();
    write(
        &output,
        "proposal-positive.jsonl",
        &encode_canonical(&base_proposal).unwrap(),
    );

    // AUTH-04: unlike `base_proposal`, this one has a bounded
    // `effective_until`, exercising the closed form of the effective
    // interval and `intervals_overlap`'s `b_before_a_end` term.
    let bounded_interval = bounded_proposal();
    write(
        &output,
        "proposal-positive-bounded-interval.jsonl",
        &encode_canonical(&bounded_interval).unwrap(),
    );

    let mut unsorted_propositions = proposal();
    unsorted_propositions.propositions = vec![
        NormativePropositionV1 {
            predicate_schema: reference("z"),
            proposition_fingerprint: label_digest("z"),
        },
        NormativePropositionV1 {
            predicate_schema: reference("a"),
            proposition_fingerprint: label_digest("a"),
        },
    ];
    write(
        &output,
        "proposal-negative-unsorted-propositions.jsonl",
        &encode_canonical(&unsorted_propositions).unwrap(),
    );

    let mut overlapping_spans = proposal();
    overlapping_spans.source_spans.push(SourceByteSpanV1 {
        start: 79,
        end: 90,
        selected_bytes_digest: label_digest("overlap"),
    });
    write(
        &output,
        "proposal-negative-overlapping-spans.jsonl",
        &encode_canonical(&overlapping_spans).unwrap(),
    );

    let mut wrong_resource_form = proposal();
    wrong_resource_form.repository_version_id = resource("entity", "repository", "not-a-version");
    write(
        &output,
        "proposal-negative-wrong-resource-form.jsonl",
        &encode_canonical(&wrong_resource_form).unwrap(),
    );

    let statement_id = base_proposal.statement_id().unwrap();

    let receipt_positive = receipt(
        statement_id,
        "principal.author",
        &["principal.author", "principal.independent"],
        2,
        true,
    );
    write(
        &output,
        "receipt-positive-author-plus-independent.jsonl",
        &encode_canonical(&receipt_positive).unwrap(),
    );

    // required_threshold == 1: the lone author approval already meets
    // the threshold, so this fixture is rejected only by the
    // separation-of-duty re-derivation, not by the threshold guard —
    // see `author_only_approval_is_rejected`.
    let receipt_negative = receipt(
        statement_id,
        "principal.author",
        &["principal.author"],
        1,
        true,
    );
    write(
        &output,
        "receipt-negative-author-only.jsonl",
        &encode_canonical(&receipt_negative).unwrap(),
    );

    // AUTH-03: the honest companion to the fixture above — declares
    // `separation_of_duty_satisfied: false` truthfully for the same
    // author-only, threshold-met shape (the (declared false, derived
    // false) quadrant no other fixture or inline vector reaches).
    let receipt_negative_honest_declaration = receipt(
        statement_id,
        "principal.author",
        &["principal.author"],
        1,
        false,
    );
    write(
        &output,
        "receipt-negative-author-only-honest.jsonl",
        &encode_canonical(&receipt_negative_honest_declaration).unwrap(),
    );

    let activation_event = NormativeLifecycleEventV1 {
        schema_version: 1,
        kind: NormativeLifecycleKindV1::Activation,
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        statement_id,
        registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
        effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        supersedes_statement_id: None,
        waiver_reference_digest: None,
    };
    write(
        &output,
        "lifecycle-activation.jsonl",
        &encode_canonical(&activation_event).unwrap(),
    );

    let supersession_event = NormativeLifecycleEventV1 {
        schema_version: 1,
        kind: NormativeLifecycleKindV1::Supersession,
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        statement_id: label_digest("successor-statement"),
        registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
        effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        supersedes_statement_id: Some(statement_id),
        waiver_reference_digest: None,
    };
    write(
        &output,
        "lifecycle-supersession.jsonl",
        &encode_canonical(&supersession_event).unwrap(),
    );

    let lifecycle_negative = NormativeLifecycleEventV1 {
        schema_version: 1,
        kind: NormativeLifecycleKindV1::Supersession,
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        statement_id,
        registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
        effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        supersedes_statement_id: None,
        waiver_reference_digest: None,
    };
    write(
        &output,
        "lifecycle-negative-missing-supersedes-target.jsonl",
        &encode_canonical(&lifecycle_negative).unwrap(),
    );

    // AUTH-04: a supersession event may not name itself as its own
    // target — see `a_supersession_event_naming_itself_as_its_own_target_is_rejected`.
    let lifecycle_self_supersession = NormativeLifecycleEventV1 {
        schema_version: 1,
        kind: NormativeLifecycleKindV1::Supersession,
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        statement_id,
        registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
        effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        supersedes_statement_id: Some(statement_id),
        waiver_reference_digest: None,
    };
    write(
        &output,
        "lifecycle-negative-self-supersession.jsonl",
        &encode_canonical(&lifecycle_self_supersession).unwrap(),
    );

    let contested_positive = ContestedBindingV1 {
        schema_version: 1,
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        contested_statement_ids: sorted_label_digests(&[
            "independently-accepted-a",
            "independently-accepted-b",
        ]),
        reason: NormativeContestReasonV1::IndependentlyAcceptedUnestablishableOrdering,
        detected_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        waiver_reference_digest: None,
    };
    write(
        &output,
        "contested-positive.jsonl",
        &encode_canonical(&contested_positive).unwrap(),
    );

    let contested_negative = ContestedBindingV1 {
        schema_version: 1,
        binding_family_id: ContractId::new("slo.home.errors").unwrap(),
        contested_statement_ids: vec![label_digest("only-one-statement")],
        reason: NormativeContestReasonV1::LateOrCorrectiveEvidence,
        detected_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        waiver_reference_digest: None,
    };
    write(
        &output,
        "contested-negative-single-statement.jsonl",
        &encode_canonical(&contested_negative).unwrap(),
    );

    let retroactive_positive = RetroactiveCorrectionV1 {
        schema_version: 1,
        statement_id: label_digest("corrected-statement"),
        superseded_as_known_statement_id: label_digest("prior-as-known-statement"),
        effective_from: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
        accepted_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        authorizing_policy: reference("normative.retroactive_correction_policy"),
        authorizing_policy_required_threshold: 3,
        normal_activation_policy: reference("normative.normal_activation_policy"),
        normal_activation_policy_required_threshold: 2,
    };
    write(
        &output,
        "retroactive-correction-positive.jsonl",
        &encode_canonical(&retroactive_positive).unwrap(),
    );

    let retroactive_negative = RetroactiveCorrectionV1 {
        schema_version: 1,
        statement_id: label_digest("corrected-statement"),
        superseded_as_known_statement_id: label_digest("prior-as-known-statement"),
        effective_from: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        accepted_at: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
        authorizing_policy: reference("normative.retroactive_correction_policy"),
        authorizing_policy_required_threshold: 3,
        normal_activation_policy: reference("normative.normal_activation_policy"),
        normal_activation_policy_required_threshold: 2,
    };
    write(
        &output,
        "retroactive-correction-negative-not-retroactive.jsonl",
        &encode_canonical(&retroactive_negative).unwrap(),
    );

    // AUTH-04: naming the ordinary activation policy as the correction's
    // own authorizing policy (same entry_id, same threshold) must be
    // rejected even though the timestamps are genuinely retroactive.
    let retroactive_negative_ordinary_policy = RetroactiveCorrectionV1 {
        schema_version: 1,
        statement_id: label_digest("corrected-statement"),
        superseded_as_known_statement_id: label_digest("prior-as-known-statement"),
        effective_from: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
        accepted_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        authorizing_policy: reference("normative.normal_activation_policy"),
        authorizing_policy_required_threshold: 2,
        normal_activation_policy: reference("normative.normal_activation_policy"),
        normal_activation_policy_required_threshold: 2,
    };
    write(
        &output,
        "retroactive-correction-negative-ordinary-policy.jsonl",
        &encode_canonical(&retroactive_negative_ordinary_policy).unwrap(),
    );

    eprintln!("proposal_statement_id={statement_id}");
    eprintln!(
        "proposal_bounded_interval_statement_id={}",
        bounded_interval.statement_id().unwrap()
    );
    eprintln!("receipt_id={}", receipt_positive.receipt_id().unwrap());
    eprintln!(
        "lifecycle_activation_event_id={}",
        activation_event.event_id().unwrap()
    );
    eprintln!(
        "lifecycle_supersession_event_id={}",
        supersession_event.event_id().unwrap()
    );
    eprintln!(
        "contested_id={}",
        contested_positive.contested_id().unwrap()
    );
}
