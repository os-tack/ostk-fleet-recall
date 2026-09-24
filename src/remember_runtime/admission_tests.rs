//! Offline admission proofs over both compiled-in active packages.

use std::collections::BTreeMap;

use chrono::{DateTime, TimeDelta, Utc};

use super::*;
use crate::memory_contracts::digest::{DigestDomain, domain_separated_digest};
use crate::memory_contracts::identity::{
    CanonicalLocatorV1, DerivedResourceIdentityV1, derive_entity_from_components,
    derive_resource_uri,
};
use crate::memory_contracts::registry::RegistryHeadV1;
use crate::registry_witness::{compiled_generation_two_package, compiled_stage4_package};

const REPOSITORY_ID: &str = "908172635";
const COMMIT_OID: &str = "3d99ec111a583e80533cbbc0c06798bb628e0979";
const ENVIRONMENT_ID: &str = "production";

/// Run `check` once against each compiled-in package an active head may
/// activate: the frozen generation-1 Stage-4 package and generation 2.
fn for_each_package(check: impl Fn(&SemanticallyClosedSuccessorPackage)) {
    let stage4 = compiled_stage4_package().expect("the generation-1 package closes");
    check(stage4.successor_package());
    let generation_two = compiled_generation_two_package().expect("generation 2 closes");
    check(&generation_two);
}

fn contract_id(value: &str) -> ContractId {
    ContractId::new(value).unwrap()
}

fn scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        contract_id("tenant.acme"),
        contract_id("project.recall"),
    )
}

fn other_scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        contract_id("tenant.acme"),
        contract_id("project.other"),
    )
}

fn head(package: &SemanticallyClosedSuccessorPackage, activation: &str) -> RegistryHeadBindingV1 {
    RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: domain_separated_digest(
                DigestDomain::RegistryEntry,
                activation.as_bytes(),
            ),
            package_digest: package.package_digest(),
            activation_policy_digest: domain_separated_digest(
                DigestDomain::RegistryEntry,
                b"activation-policy",
            ),
        },
        effective_from: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
        effective_until: None,
    }
}

fn now() -> DateTime<Utc> {
    at("2026-09-24T12:00:00.123456789Z")
}

fn at(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}

fn components(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn input() -> RememberAssertInputV1 {
    RememberAssertInputV1 {
        predicate: None,
        kind: RememberAssertionKindV2::Decision,
        text: "remember(assert) is allowed at this commit in production.".into(),
        modality: PropositionModalityV1::Attested,
        polarity: ClaimPolarityV2::Affirms,
        value: CanonicalClaimValueV2::Boolean { value: true },
        subject: components(&[("provider_repository_id", REPOSITORY_ID)]),
        applicability: BTreeMap::from([
            (
                "repository_commit".to_owned(),
                components(&[("commit_oid", COMMIT_OID)]),
            ),
            (
                "runtime_environment".to_owned(),
                components(&[("environment_id", ENVIRONMENT_ID)]),
            ),
        ]),
        effective_from: None,
        effective_until: None,
        support_evidence_event_ids: Vec::new(),
    }
}

fn admit_as(
    package: &SemanticallyClosedSuccessorPackage,
    actor: &str,
    activation: &str,
    input: &RememberAssertInputV1,
) -> Result<AdmittedRememberAssertionV1, RememberAdmissionRefusal> {
    let route = resolve_assert_route(package).expect("the package has one assert route");
    admit_remember_assertion(
        &route,
        package,
        &head(package, activation),
        &scope(),
        &contract_id(actor),
        input,
        now(),
    )
}

fn admit(
    package: &SemanticallyClosedSuccessorPackage,
    input: &RememberAssertInputV1,
) -> Result<AdmittedRememberAssertionV1, RememberAdmissionRefusal> {
    admit_as(package, "agent.alpha", "activation.one", input)
}

fn refused(
    package: &SemanticallyClosedSuccessorPackage,
    input: &RememberAssertInputV1,
) -> RememberAdmissionRefusalReason {
    admit(package, input)
        .expect_err("the input must be refused")
        .reason
}

fn event_id(label: &str) -> AcceptedEventId {
    AcceptedEventId::from_digest(domain_separated_digest(
        DigestDomain::AcceptedEvent,
        label.as_bytes(),
    ))
}

#[test]
fn both_packages_resolve_the_one_route() {
    for_each_package(|package| {
        let route = resolve_assert_route(package).unwrap();
        assert_eq!(route.package_digest(), package.package_digest());
        assert_eq!(
            route.predicate_reference().entry_id.as_str(),
            "mcp.remember.allowed_actions"
        );
        assert_eq!(
            route.admission_reference().entry_id.as_str(),
            "remember.actor_assertion"
        );
        assert_eq!(
            route.dimension_derivation("repository_commit"),
            Some(DimensionDerivationV1::VersionUnderSubject)
        );
        assert_eq!(
            route.dimension_derivation("runtime_environment"),
            Some(DimensionDerivationV1::Entity)
        );
        assert_eq!(route.dimension_derivation("unknown"), None);

        let description = route.describe();
        assert_eq!(
            description.predicate.id.as_str(),
            "mcp.remember.allowed_actions"
        );
        assert_eq!(description.value_kind, "boolean");
        assert_eq!(
            description.modalities,
            [
                PropositionModalityV1::Attested,
                PropositionModalityV1::Intended
            ]
        );
        assert_eq!(
            description.subject_keys,
            [contract_id("provider_repository_id")]
        );
        assert_eq!(
            description.applicability_keys,
            BTreeMap::from([
                (
                    contract_id("repository_commit"),
                    vec![contract_id("commit_oid")]
                ),
                (
                    contract_id("runtime_environment"),
                    vec![contract_id("environment_id")]
                ),
            ])
        );
    });
}

#[test]
fn a_valid_assertion_admits_with_a_stable_identity() {
    for_each_package(|package| {
        let first = admit(package, &input()).unwrap();
        let again = admit(package, &input()).unwrap();
        assert_eq!(first.accepted_event_id(), again.accepted_event_id());
        assert_eq!(
            first.accepted_event_id(),
            first.admitted().statement().accepted_event_id().unwrap()
        );

        let other_actor = admit_as(package, "agent.beta", "activation.one", &input()).unwrap();
        assert_ne!(first.accepted_event_id(), other_actor.accepted_event_id());
        let other_head = admit_as(package, "agent.alpha", "activation.two", &input()).unwrap();
        assert_ne!(first.accepted_event_id(), other_head.accepted_event_id());

        let statement = first.admitted().statement();
        assert_eq!(statement.actor.principal_id.as_str(), "agent.alpha");
        assert_eq!(statement.registry, head(package, "activation.one"));
        assert_eq!(statement.scope, scope());
        assert_eq!(
            statement.admission_basis,
            RememberAdmissionBasisV2::AuthenticatedActor
        );
        assert_eq!(statement.claim.subject, *first.subject());
        assert_eq!(first.subject().identity_form(), IdentityForm::Entity);
        assert_eq!(first.subject().resource_kind().as_str(), "repository");
        let forms = first
            .applicability()
            .iter()
            .map(|dimension| {
                (
                    dimension.dimension_id.as_str(),
                    dimension.resource.identity_form(),
                    dimension.resource.resource_kind().as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            forms,
            [
                ("repository_commit", IdentityForm::Version, "commit"),
                ("runtime_environment", IdentityForm::Entity, "environment"),
            ]
        );
        let route = resolve_assert_route(package).unwrap();
        assert_eq!(first.predicate(), route.predicate_reference());
        assert_eq!(first.modality(), PropositionModalityV1::Attested);
        assert_eq!(first.publication_default(), PublicationDefaultV1::Denied);
        // The admitted statement is appendable as-is: it names exactly the
        // route's rule, carries the exact authored text, and has no support.
        assert_eq!(&statement.admission_rule, route.admission_reference());
        assert_eq!(
            statement.assertion_text_utf8_hex_chunks.as_str(),
            input().text
        );
        assert!(statement.support_evidence_event_ids.is_empty());
    });
}

#[test]
fn an_omitted_effective_from_is_the_server_clock_in_whole_microseconds() {
    for_each_package(|package| {
        let admitted = admit(package, &input()).unwrap();
        let interval = &admitted.admitted().statement().claim.effective_interval;
        assert_eq!(
            interval.effective_from.as_str(),
            "2026-09-24T12:00:00.123456000Z"
        );
        assert_eq!(interval.effective_until, None);

        // A past, bounded interval is admitted as sent.
        let mut bounded = input();
        bounded.effective_from = Some(at("2026-08-01T00:00:00Z"));
        bounded.effective_until = Some(at("2026-10-24T00:00:00Z"));
        let bounded = admit(package, &bounded).unwrap();
        let interval = &bounded.admitted().statement().claim.effective_interval;
        assert_eq!(
            interval.effective_from.as_str(),
            "2026-08-01T00:00:00.000000000Z"
        );
        assert!(interval.effective_until.is_some());
    });
}

#[test]
fn the_claim_key_is_the_coordinate_plus_modality() {
    for_each_package(|package| {
        let alpha = admit_as(package, "agent.alpha", "activation.one", &input()).unwrap();
        let mut disagreeing = input();
        disagreeing.value = CanonicalClaimValueV2::Boolean { value: false };
        disagreeing.text = "remember(assert) is not allowed at this commit in production.".into();
        let beta = admit_as(package, "agent.beta", "activation.one", &disagreeing).unwrap();
        // Same repository, commit, and environment: one key, so the conflict
        // detector compares the two values.
        assert_eq!(alpha.claim_key(), beta.claim_key());
        assert_eq!(alpha.subject(), beta.subject());
        assert_eq!(alpha.applicability(), beta.applicability());
        assert!(alpha.claim_key().starts_with("claim-v2:"));
        assert!(alpha.claim_key().ends_with(":attested"));

        let mut intention = input();
        intention.modality = PropositionModalityV1::Intended;
        let intended = admit(package, &intention).unwrap();
        assert_ne!(alpha.claim_key(), intended.claim_key());
        assert!(intended.claim_key().ends_with(":intended"));

        let mut other_commit = input();
        other_commit.applicability.insert(
            "repository_commit".into(),
            components(&[("commit_oid", "66ed86c0000000000000000000000000000000aa")]),
        );
        assert_ne!(
            alpha.claim_key(),
            admit(package, &other_commit).unwrap().claim_key()
        );
    });

    // Every recipe is carried byte for byte into generation 2, so the key an
    // agent asserted under generation 1 still names the same coordinate after
    // the upgrade.
    let stage4 = compiled_stage4_package().unwrap();
    let generation_two = compiled_generation_two_package().unwrap();
    assert_eq!(
        admit(stage4.successor_package(), &input())
            .unwrap()
            .claim_key(),
        admit(&generation_two, &input()).unwrap().claim_key()
    );
}

#[test]
#[allow(clippy::too_many_lines)] // one table row per refused input
fn each_invalid_input_is_refused_with_its_reason() {
    type Mutation = fn(&mut RememberAssertInputV1);
    let cases: [(&str, Mutation, RememberAdmissionRefusalReason); 17] = [
        (
            "future effective_from",
            |input| input.effective_from = Some(at("2026-09-24T12:00:01Z")),
            RememberAdmissionRefusalReason::EffectiveIntervalInvalid,
        ),
        (
            "sub-microsecond effective_from",
            |input| input.effective_from = Some(now() - TimeDelta::days(1)),
            RememberAdmissionRefusalReason::EffectiveIntervalInvalid,
        ),
        (
            "effective_until before effective_from",
            |input| input.effective_until = Some(at("2026-09-01T00:00:00Z")),
            RememberAdmissionRefusalReason::EffectiveIntervalInvalid,
        ),
        (
            "string value for a boolean predicate",
            |input| {
                input.value = CanonicalClaimValueV2::String {
                    value: crate::memory_contracts::remember_v2::CanonicalClaimTextV2::parse(
                        "true",
                    )
                    .unwrap(),
                };
            },
            RememberAdmissionRefusalReason::ValueInvalid,
        ),
        (
            "missing required dimension",
            |input| {
                input.applicability.remove("runtime_environment");
            },
            RememberAdmissionRefusalReason::LocatorInvalid,
        ),
        (
            "unknown dimension",
            |input| {
                input
                    .applicability
                    .insert("deployment_region".into(), components(&[("region", "eu")]));
            },
            RememberAdmissionRefusalReason::LocatorInvalid,
        ),
        (
            "unknown component key",
            |input| {
                input.subject.insert("owner".into(), "os-tack".into());
            },
            RememberAdmissionRefusalReason::LocatorInvalid,
        ),
        (
            "non-hex commit_oid",
            |input| {
                input.applicability.insert(
                    "repository_commit".into(),
                    components(&[("commit_oid", "HEAD")]),
                );
            },
            RememberAdmissionRefusalReason::LocatorInvalid,
        ),
        (
            "non-decimal repository id",
            |input| {
                input.subject = components(&[("provider_repository_id", "os-tack/recall")]);
            },
            RememberAdmissionRefusalReason::LocatorInvalid,
        ),
        (
            "observed modality",
            |input| input.modality = PropositionModalityV1::Observed,
            RememberAdmissionRefusalReason::ModalityNotAllowed,
        ),
        (
            "normative modality",
            |input| input.modality = PropositionModalityV1::Normative,
            RememberAdmissionRefusalReason::ModalityNotAllowed,
        ),
        (
            "trailing whitespace",
            |input| input.text.push(' '),
            RememberAdmissionRefusalReason::TextInvalid,
        ),
        (
            "lexeme over the full-text limit",
            |input| input.text = format!("see {}", "a".repeat(16_001)),
            RememberAdmissionRefusalReason::TextInvalid,
        ),
        (
            "forbidden control scalar",
            |input| input.text = "ring the \u{7} bell".into(),
            RememberAdmissionRefusalReason::TextInvalid,
        ),
        (
            "more than 256 support ids",
            |input| {
                input.support_evidence_event_ids =
                    (0..257).map(|index| event_id(&index.to_string())).collect();
            },
            RememberAdmissionRefusalReason::SupportInvalid,
        ),
        (
            "zero-digest support id",
            |input| {
                input.support_evidence_event_ids = vec![AcceptedEventId::from_digest(
                    crate::memory_contracts::digest::Sha256Digest::ZERO,
                )];
            },
            RememberAdmissionRefusalReason::SupportInvalid,
        ),
        (
            "mismatched predicate",
            |input| input.predicate = Some(contract_id("mcp.remember.other_predicate")),
            RememberAdmissionRefusalReason::PredicateMismatch,
        ),
    ];
    for_each_package(|package| {
        for (name, mutate, expected) in &cases {
            let mut candidate = input();
            mutate(&mut candidate);
            assert_eq!(refused(package, &candidate), *expected, "{name}");
        }
        // The future case is refused by the rule, not by alignment.
        let mut future = input();
        future.effective_from = Some(at("2026-09-24T12:00:01Z"));
        assert!(
            admit(package, &future)
                .unwrap_err()
                .message
                .contains("future-effective")
        );
    });
}

#[test]
fn support_ids_are_admitted_as_a_sorted_set_and_the_predicate_is_compare_only() {
    for_each_package(|package| {
        let mut supported = input();
        supported.predicate = Some(contract_id("mcp.remember.allowed_actions"));
        supported.support_evidence_event_ids = vec![event_id("b"), event_id("a"), event_id("b")];
        let admitted = admit(package, &supported).unwrap();
        let mut expected = vec![event_id("a"), event_id("b")];
        expected.sort_unstable();
        assert_eq!(
            admitted.admitted().statement().support_evidence_event_ids,
            expected
        );
        // Naming the routed predicate changes nothing about the statement's
        // identity beyond its support set.
        let mut unnamed = supported;
        unnamed.predicate = None;
        assert_eq!(
            admit(package, &unnamed).unwrap().accepted_event_id(),
            admitted.accepted_event_id()
        );
    });
}

#[test]
fn a_route_is_refused_under_a_head_that_activates_another_package() {
    let stage4 = compiled_stage4_package().unwrap();
    let generation_one = stage4.successor_package();
    let generation_two = compiled_generation_two_package().unwrap();
    let route = resolve_assert_route(generation_one).unwrap();
    for (package, head) in [
        // The head activates generation 2, the route is generation 1's.
        (&*generation_two, head(&generation_two, "activation.one")),
        // The package and route agree but the head names the other package.
        (generation_one, head(&generation_two, "activation.one")),
    ] {
        let refusal = admit_remember_assertion(
            &route,
            package,
            &head,
            &scope(),
            &contract_id("agent.alpha"),
            &input(),
            now(),
        )
        .unwrap_err();
        assert_eq!(
            refusal.reason,
            RememberAdmissionRefusalReason::RegistryHeadMismatch
        );
    }
}

#[test]
fn the_ergonomic_input_is_closed_and_defaults_to_affirms() {
    let parsed: RememberAssertInputV1 = serde_json::from_value(serde_json::json!({
        "kind": "decision",
        "text": "remember(assert) is allowed.",
        "modality": "attested",
        "value": {"kind": "boolean", "value": true},
        "subject": {"provider_repository_id": REPOSITORY_ID},
        "applicability": {
            "repository_commit": {"commit_oid": COMMIT_OID},
            "runtime_environment": {"environment_id": ENVIRONMENT_ID}
        }
    }))
    .unwrap();
    assert_eq!(parsed.polarity, ClaimPolarityV2::Affirms);
    assert_eq!(parsed.predicate, None);
    assert!(parsed.support_evidence_event_ids.is_empty());

    // An agent cannot smuggle a URI, an actor, or a rule through the input.
    for smuggled in ["subject_uri", "actor", "admission_rule", "registry"] {
        let mut value = serde_json::to_value(&parsed).unwrap();
        value[smuggled] = serde_json::json!("anything");
        assert!(
            serde_json::from_value::<RememberAssertInputV1>(value).is_err(),
            "{smuggled}"
        );
    }
}

/// The repository entity and commit recipe the D1 helper joins.
fn repository_and_commit(
    package: &SemanticallyClosedSuccessorPackage,
    scope: &AuthenticatedProjectScopeV1,
) -> (DerivedResourceIdentityV1, ValidatedIdentityRecipe) {
    let route = resolve_assert_route(package).unwrap();
    let predicate = route.contracts.predicate();
    let repository = derive_entity_from_components(
        package.manifest_verified_package(),
        &predicate.subject_identity.identity_recipe,
        scope,
        &components(&[("provider_repository_id", REPOSITORY_ID)]),
    )
    .unwrap();
    let commit_recipe = route
        .dimensions
        .iter()
        .find(|dimension| dimension.dimension_id.as_str() == "repository_commit")
        .unwrap()
        .recipe
        .clone();
    (repository, commit_recipe)
}

fn commit_locator(
    recipe: &ValidatedIdentityRecipe,
    parent: &DerivedResourceIdentityV1,
) -> CanonicalLocatorV1 {
    locator_from_components(
        recipe,
        &scope(),
        Some(parent.uri()),
        &components(&[("commit_oid", COMMIT_OID)]),
    )
    .unwrap()
}

#[test]
fn the_commit_derives_only_under_a_repository_parent_in_the_same_scope() {
    for_each_package(|package| {
        let (repository, commit) = repository_and_commit(package, &scope());
        let context = commit.derivation_context(&scope());
        let locator = commit_locator(&commit, &repository);

        let derived =
            derive_version_under_entity_parent(&context, &locator, &commit, &repository).unwrap();
        assert_eq!(derived.uri().identity_form(), IdentityForm::Version);
        // It is exactly the URI admission derives for this commit.
        let admitted = admit(package, &input()).unwrap();
        assert_eq!(admitted.applicability()[0].resource, *derived.uri());
        // The generic rule still refuses it (generation2_registry_tests pins
        // why): only the explicit cross-namespace helper derives a commit.
        assert!(derive_resource_uri(&context, &locator, &commit, Some(&repository)).is_err());

        // A parent of the wrong kind is refused, even when the locator names it.
        let environment = derive_entity_from_components(
            package.manifest_verified_package(),
            &resolve_assert_route(package)
                .unwrap()
                .contracts
                .predicate()
                .applicability_dimensions[1]
                .resource_identity
                .identity_recipe,
            &scope(),
            &components(&[("environment_id", ENVIRONMENT_ID)]),
        )
        .unwrap();
        assert!(
            derive_version_under_entity_parent(
                &context,
                &commit_locator(&commit, &environment),
                &commit,
                &environment,
            )
            .is_err()
        );

        // A repository derived in another scope is refused.
        let (foreign, _) = repository_and_commit(package, &other_scope());
        assert!(
            derive_version_under_entity_parent(
                &context,
                &commit_locator(&commit, &foreign),
                &commit,
                &foreign,
            )
            .is_err()
        );

        // A locator that names a different parent than the one supplied is
        // refused.
        assert!(derive_version_under_entity_parent(&context, &locator, &commit, &foreign).is_err());

        // So is a component that does not match the recipe.
        let mut mismatched = locator;
        mismatched.components[0].key = contract_id("provider_repository_id");
        assert!(
            derive_version_under_entity_parent(&context, &mismatched, &commit, &repository)
                .is_err()
        );
    });
}

#[test]
fn the_shared_entity_helper_matches_admission_and_checks_the_recipe_digest() {
    for_each_package(|package| {
        let route = resolve_assert_route(package).unwrap();
        let subject_recipe = route
            .contracts
            .predicate()
            .subject_identity
            .identity_recipe
            .clone();
        let repository = derive_entity_from_components(
            package.manifest_verified_package(),
            &subject_recipe,
            &scope(),
            &components(&[("provider_repository_id", REPOSITORY_ID)]),
        )
        .unwrap();
        assert_eq!(
            repository.uri(),
            admit(package, &input()).unwrap().subject()
        );

        let mut forged = subject_recipe;
        forged.entry_digest = domain_separated_digest(DigestDomain::RegistryEntry, b"forged");
        assert!(
            derive_entity_from_components(
                package.manifest_verified_package(),
                &forged,
                &scope(),
                &components(&[("provider_repository_id", REPOSITORY_ID)]),
            )
            .is_err()
        );
    });
}
