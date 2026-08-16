//! Connected proof for the private generic `N -> N+1` activation repository.
//!
//! Set the exact `FLEET_RECALL_TEST_DATABASE_URL` variable to a disposable
//! `CockroachDB` 26.2 database. The test is inert otherwise. It never starts a
//! database process, invokes Docker, or targets a cloud service.
//!
//! Every scope walks the whole real chain — bootstrap, genesis activation, the
//! frozen `0 -> 1` first successor — before any generic transition, so the
//! installed activation policy this runtime consumes is the one a live `0 -> 1`
//! ceremony actually stored, never a fixture head.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::future::join_all;
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisRepository, TrustedControlScope,
};
use ostk_fleet_recall::error::SuccessorActivationTimingKind;
use ostk_fleet_recall::memory_contracts::bootstrap::{
    AppendPositionV1, BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest,
    BootstrapReceiptV1, CommittedOffsetV1, VerifiedBootstrapReceipt, verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{decode_strict, encode_canonical};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, FixedHex32, FixedHex64,
    ProfileReferenceV1, RegistryReferenceV1, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest, framed_digest,
};
use ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId;
use ostk_fleet_recall::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use ostk_fleet_recall::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use ostk_fleet_recall::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, GenesisRegistryActivationApprovalSetV1,
    GenesisRegistryActivationApprovalV1, GenesisRegistryActivationStatementV1,
    GenesisRegistryAnchorV1, RegistryTestResultDigest, RegistryTestRunnerPin,
    VerifiedRegistryTestResult, genesis_activation_policy_digest,
    registry_activation_consistency_partition_key, verify_genesis_registry_activation,
    verify_registry_test_result,
};
use ostk_fleet_recall::memory_contracts::registry::{
    ManifestVerifiedRegistryPackage, RegistryEntryKind,
};
use ostk_fleet_recall::memory_contracts::stage4_target_package::SemanticallyClosedStage4Package;
use ostk_fleet_recall::memory_contracts::successor_activation::{
    SuccessorActivationPrincipalBinding, SuccessorRegistryActivationApprovalSetV1,
    SuccessorRegistryActivationApprovalV1, SuccessorRegistryActivationStatementV1,
    SuccessorRegistryTestRunnerPin,
};
use ostk_fleet_recall::memory_contracts::successor_generic::{
    GenericSuccessorActivationApprovalSetV2, GenericSuccessorActivationApprovalV2,
    GenericSuccessorActivationStatementId, GenericSuccessorActivationStatementV2,
    GenericSuccessorPrincipalBinding, GenericSuccessorTestRunnerPin,
    StructurallyClosedSuccessorTargetV2,
};
use ostk_fleet_recall::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;
use ostk_fleet_recall::memory_contracts::successor_policy::{
    ActivationSignatureAlgorithmV2, ActivationSignerBindingV2, GenesisSuccessorKeyBridgePin,
    GenesisSuccessorKeyBridgeV1,
};
use ostk_fleet_recall::registry_activation::{
    AcceptedGenericSuccessorActivation, CockroachGenericSuccessorRepository,
    CockroachGenesisActivationRepository, CockroachSuccessorActivationRepository,
    GenericSuccessorActivationCandidate, GenericSuccessorActivationInspection,
    GenericSuccessorActivationOutcome, GenericSuccessorRepository, GenesisActivationOutcome,
    GenesisActivationRepository, SuccessorActivationCandidate, SuccessorActivationOutcome,
    SuccessorActivationRepository,
};
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_fleet_recall::{FleetError, FleetScope};
use ostk_recall_core::PrivacyTier;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sqlx::{PgPool, Row};
use tokio::sync::Barrier;
use uuid::Uuid;

const GENESIS_PACKAGE: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");
const BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");
const GENESIS_TEST_RESULT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/genesis-activation/registry-test-result.jsonl");
const GENERATION_1_PACKAGE: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");
const GENERATION_1_TEST_RESULT: &[u8] = include_bytes!(
    "../contracts/dynamic-memory/v2/successor-activation/registry-test-result.jsonl"
);
const GENERATION_2_PACKAGE: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v3/successor-generic/generation-2-package.jsonl");
const GENERATION_2_TEST_RESULT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v3/successor-generic/activation-test-result.jsonl");

const GENESIS_TEST_RESULT_DIGEST: &str =
    "e91e08070250a722446195b76ee685a9697298b9fdce9809027f120c829b679d";
const GENESIS_RUNNER_ARTIFACT: &str =
    "c2e5b0653471d35e54600a8d3fbe5613aff4c04e911787c09a25e2b327d4bbbd";
const GENESIS_RUNNER_CONFIGURATION: &str =
    "1d12aabe349fd0013389f93bf1917b0de6bbd5d2bd7156c85faff0b97360686d";
const GENERATION_1_TEST_RESULT_DIGEST: &str =
    "e6783b2a018957a5861fe4e0670f55613d1ace35e381a6a9f5190ea9d7fbff8d";
const GENERATION_2_TEST_RESULT_DIGEST: &str =
    "92fa5a109739a2509c57104d50f0c13416295380aee9e7f81f860dad2d1d08d7";
const SUCCESSOR_RUNNER_ARTIFACT: &str =
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SUCCESSOR_RUNNER_CONFIGURATION: &str =
    "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";

const GENERIC_APPROVAL_PREFIX: &[u8] =
    b"ostk-registry-successor-activation-approval-signature-v2\0";
const BRIDGE_APPROVAL_PREFIX: &[u8] = b"ostk-registry-successor-activation-approval-signature-v1\0";
const PROPOSER: &str = "principal.proposer";
const AUTHOR: &str = "principal.author";

#[derive(Clone)]
struct ContractFixture {
    profile: ProfileReferenceV1,
    semantic_scope: AuthenticatedProjectScopeV1,
    genesis_package: SemanticallyClosedGenesisPackage,
    genesis_test_result: VerifiedRegistryTestResult,
    genesis_principal_binding: GenesisActivationPrincipalBinding,
    stage4: SemanticallyClosedStage4Package,
    generation_1: StructurallyClosedSuccessorTargetV2,
    generation_2: StructurallyClosedSuccessorTargetV2,
}

struct ActivatedRegistry {
    physical_scope: FleetScope,
    bootstrap: VerifiedBootstrapReceipt,
    bootstrap_receipt_digest: BootstrapReceiptDigest,
    generation_1_head: RegistryHeadBindingV1,
    generation_1_accepted_at: CanonicalTimestamp,
}

fn record(artifact: &'static [u8]) -> &'static [u8] {
    let body = artifact
        .strip_suffix(b"\n")
        .expect("contract JSONL must have exactly one framing LF");
    assert!(!body.ends_with(b"\n"));
    assert!(!body.contains(&b'\r'));
    body
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::from_str(value).expect("fixture digest must be lowercase SHA-256")
}

fn structurally_closed(
    artifact: &'static [u8],
    profile: &ProfileReferenceV1,
) -> StructurallyClosedSuccessorTargetV2 {
    let manifest = ManifestVerifiedRegistryPackage::decode(record(artifact), profile).unwrap();
    StructurallyClosedSuccessorTargetV2::from_manifest_verified(&manifest).unwrap()
}

fn fixture() -> ContractFixture {
    let profile = frozen_profile_reference_v1();
    let bootstrap_value: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
    let semantic_scope = bootstrap_value.statement.scope;
    let genesis_manifest =
        ManifestVerifiedRegistryPackage::decode(record(GENESIS_PACKAGE), &profile).unwrap();
    let genesis_package =
        SemanticallyClosedGenesisPackage::from_manifest_verified(genesis_manifest).unwrap();
    let genesis_test_result = verify_registry_test_result(
        record(GENESIS_TEST_RESULT),
        RegistryTestRunnerPin::from_trusted_config(
            digest(GENESIS_RUNNER_ARTIFACT),
            digest(GENESIS_RUNNER_CONFIGURATION),
            RegistryTestResultDigest::from_digest(digest(GENESIS_TEST_RESULT_DIGEST)),
        ),
        &profile,
        &genesis_package,
    )
    .unwrap();
    let stage4_manifest =
        ManifestVerifiedRegistryPackage::decode(record(GENERATION_1_PACKAGE), &profile).unwrap();
    let stage4 = SemanticallyClosedStage4Package::from_successor_package(
        SemanticallyClosedSuccessorPackage::from_manifest_verified(stage4_manifest).unwrap(),
    )
    .unwrap();
    ContractFixture {
        generation_1: structurally_closed(GENERATION_1_PACKAGE, &profile),
        generation_2: structurally_closed(GENERATION_2_PACKAGE, &profile),
        profile,
        semantic_scope,
        genesis_package,
        genesis_test_result,
        genesis_principal_binding: GenesisActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.operator").unwrap(),
            ContractId::new(AUTHOR).unwrap(),
        ),
        stage4,
    }
}

fn physical_scope(label: &str) -> FleetScope {
    FleetScope::new(
        Uuid::now_v7(),
        format!("generic-{label}-{}", Uuid::now_v7()),
        "generic-successor-connected-test",
        None,
        PrivacyTier::T1Project,
    )
    .unwrap()
}

fn trusted_scope(physical: &FleetScope, fixture: &ContractFixture) -> TrustedControlScope {
    TrustedControlScope::from_trusted_context(physical, fixture.semantic_scope.clone()).unwrap()
}

const fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 20,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(50),
    }
}

async fn server_time(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap()
}

fn canonical_time(value: DateTime<Utc>) -> CanonicalTimestamp {
    CanonicalTimestamp::from_datetime(&value).unwrap()
}

fn canonical_datetime(value: &CanonicalTimestamp) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value.as_str())
        .unwrap()
        .with_timezone(&Utc)
}

fn signer(principal: &str, seed: u8) -> ActivationSignerBindingV2 {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    ActivationSignerBindingV2 {
        principal_id: ContractId::new(principal).unwrap(),
        algorithm: ActivationSignatureAlgorithmV2::Ed25519,
        public_key: FixedHex32::from_bytes(pair.public_key().as_ref().try_into().unwrap()),
    }
}

fn detached_signature(prefix: &[u8], statement_id: Sha256Digest, seed: u8) -> FixedHex64 {
    let mut message = prefix.to_vec();
    message.extend_from_slice(statement_id.as_bytes());
    let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    FixedHex64::from_bytes(pair.sign(&message).as_ref().try_into().unwrap())
}

fn current_v1_policy_reference(fixture: &ContractFixture) -> RegistryReferenceV1 {
    let entry = fixture
        .genesis_package
        .manifest_verified_package()
        .package()
        .entries
        .iter()
        .find(|entry| entry.kind == RegistryEntryKind::ActivationPolicy)
        .unwrap();
    RegistryReferenceV1 {
        entry_id: entry.entry_id.clone(),
        version: entry.version,
        entry_digest: entry.digest().unwrap(),
    }
}

/// Walk bootstrap, genesis activation, and the frozen `0 -> 1` ceremony so the
/// generic runtime meets a real installed policy at generation one.
#[allow(clippy::too_many_lines)] // one helper keeps the whole real prefix visible
async fn activate_through_generation_one(
    pool: &PgPool,
    fixture: &ContractFixture,
    label: &str,
    seed_byte: u8,
) -> ActivatedRegistry {
    let physical_scope = physical_scope(label);

    let mut receipt: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
    receipt.statement.genesis_epoch.partition_recipe.seed = FixedHex32::from_bytes([seed_byte; 32]);
    let statement_id = receipt.statement.statement_id().unwrap();
    let mut message = b"ostk-bootstrap-approval-v1\0".to_vec();
    message.extend_from_slice(statement_id.digest().as_bytes());
    receipt.attestations = [1_u8, 2]
        .into_iter()
        .enumerate()
        .map(|(index, signer_seed)| BootstrapAttestationV1 {
            schema_version: 1,
            statement_id,
            signer_principal_id: ContractId::new(format!("principal.{}", index + 1)).unwrap(),
            signature: FixedHex64::from_bytes(
                Ed25519KeyPair::from_seed_unchecked(&[signer_seed; 32])
                    .unwrap()
                    .sign(&message)
                    .as_ref()
                    .try_into()
                    .unwrap(),
            ),
        })
        .collect();
    let canonical = encode_canonical(&receipt).unwrap();
    let bootstrap_receipt_digest = BootstrapReceiptDigest::from_digest(domain_separated_digest(
        DigestDomain::BootstrapReceipt,
        &canonical,
    ));
    let bootstrap = verify_pinned_bootstrap(
        &canonical,
        BootstrapPin::from_trusted_config(bootstrap_receipt_digest),
        &fixture.profile,
        &fixture.semantic_scope,
        &fixture.genesis_package,
    )
    .unwrap();

    CockroachGenesisRepository::new(
        pool.clone(),
        trusted_scope(&physical_scope, fixture),
        retry_policy(),
    )
    .bootstrap_genesis(&bootstrap, &fixture.genesis_package)
    .await
    .unwrap();

    let genesis_effective = canonical_time(server_time(pool).await);
    let genesis_statement = GenesisRegistryActivationStatementV1 {
        schema_version: 1,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        expected_anchor: GenesisRegistryAnchorV1::from_verified(
            &bootstrap,
            &fixture.genesis_package,
        )
        .unwrap(),
        package_digest: fixture.genesis_package.package_digest(),
        resulting_activation_policy_digest: genesis_activation_policy_digest(
            &fixture.genesis_package,
        )
        .unwrap(),
        effective_from: genesis_effective.clone(),
        effective_until: None,
        test_vector_result_digest: fixture.genesis_test_result.result_digest(),
        proposer_principal_id: ContractId::new("principal.operator").unwrap(),
        package_author_principal_id: ContractId::new(AUTHOR).unwrap(),
    };
    let genesis_statement_id = genesis_statement.statement_id().unwrap();
    let mut genesis_approvals = ["principal.1", "principal.2"]
        .into_iter()
        .zip([1_u8, 2])
        .map(|(principal, seed)| GenesisRegistryActivationApprovalV1 {
            schema_version: 1,
            statement_id: genesis_statement_id,
            signer_principal_id: ContractId::new(principal).unwrap(),
            signature: detached_signature(
                b"ostk-registry-activation-approval-signature-v1\0",
                genesis_statement_id.digest(),
                seed,
            ),
        })
        .collect::<Vec<_>>();
    genesis_approvals.sort_unstable();
    let genesis_request = verify_genesis_registry_activation(
        &encode_canonical(&genesis_statement).unwrap(),
        &encode_canonical(&GenesisRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id: genesis_statement_id,
            approvals: genesis_approvals,
        })
        .unwrap(),
        &bootstrap,
        &fixture.genesis_package,
        &fixture.genesis_test_result,
        &fixture.genesis_principal_binding,
    )
    .unwrap();
    let genesis_accepted = match CockroachGenesisActivationRepository::new(
        pool.clone(),
        trusted_scope(&physical_scope, fixture),
        retry_policy(),
        bootstrap.clone(),
        fixture.genesis_package.clone(),
        fixture.genesis_test_result.clone(),
        fixture.genesis_principal_binding.clone(),
    )
    .unwrap()
    .activate_genesis(&genesis_request)
    .await
    .unwrap()
    {
        GenesisActivationOutcome::Inserted(accepted)
        | GenesisActivationOutcome::ExactReplay(accepted) => accepted,
    };
    let genesis_head = RegistryHeadBindingV1 {
        head: genesis_accepted.registry_head,
        effective_from: genesis_effective,
        effective_until: None,
    };

    let bridge = GenesisSuccessorKeyBridgeV1 {
        schema_version: 1,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        genesis_registry_head: genesis_head.clone(),
        current_v1_activation_policy: current_v1_policy_reference(fixture),
        from_generation: 0,
        to_generation: 1,
        key_map: vec![signer("principal.alice", 1), signer("principal.bob", 2)],
    };
    let bridge_digest = bridge.bridge_digest().unwrap();
    let bridge_bytes = encode_canonical(&bridge).unwrap();

    tokio::time::sleep(Duration::from_millis(2)).await;
    let successor_effective = canonical_time(server_time(pool).await);
    let successor_statement = SuccessorRegistryActivationStatementV1 {
        schema_version: 1,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        expected_predecessor_head: genesis_head,
        current_v1_activation_policy: current_v1_policy_reference(fixture),
        target_package_digest: fixture.stage4.package_digest(),
        target_activation_policy: fixture
            .stage4
            .activation_policy()
            .registry_reference()
            .clone(),
        test_vector_result_digest: RegistryTestResultDigest::from_digest(digest(
            GENERATION_1_TEST_RESULT_DIGEST,
        )),
        genesis_successor_key_bridge_digest: bridge_digest,
        from_generation: 0,
        to_generation: 1,
        effective_from: successor_effective,
        effective_until: None,
        proposer_principal_id: ContractId::new("principal.operator").unwrap(),
        package_author_principal_id: ContractId::new(AUTHOR).unwrap(),
    };
    let successor_statement_id = successor_statement.statement_id().unwrap();
    let successor_approvals = SuccessorRegistryActivationApprovalSetV1 {
        schema_version: 1,
        statement_id: successor_statement_id,
        approvals: vec![
            SuccessorRegistryActivationApprovalV1 {
                schema_version: 1,
                statement_id: successor_statement_id,
                signer_principal_id: ContractId::new("principal.alice").unwrap(),
                signature: detached_signature(
                    BRIDGE_APPROVAL_PREFIX,
                    successor_statement_id.digest(),
                    1,
                ),
            },
            SuccessorRegistryActivationApprovalV1 {
                schema_version: 1,
                statement_id: successor_statement_id,
                signer_principal_id: ContractId::new("principal.bob").unwrap(),
                signature: detached_signature(
                    BRIDGE_APPROVAL_PREFIX,
                    successor_statement_id.digest(),
                    2,
                ),
            },
        ],
    };
    let candidate = SuccessorActivationCandidate::from_bounded_canonical_bytes(
        encode_canonical(&successor_statement).unwrap(),
        encode_canonical(&successor_approvals).unwrap(),
    )
    .unwrap();
    let accepted = match CockroachSuccessorActivationRepository::new(
        pool.clone(),
        trusted_scope(&physical_scope, fixture),
        retry_policy(),
        bootstrap.clone(),
        fixture.genesis_package.clone(),
        fixture.genesis_test_result.clone(),
        fixture.genesis_principal_binding.clone(),
        fixture.stage4.clone(),
        record(GENERATION_1_TEST_RESULT),
        SuccessorRegistryTestRunnerPin::from_trusted_config(
            digest(SUCCESSOR_RUNNER_ARTIFACT),
            digest(SUCCESSOR_RUNNER_CONFIGURATION),
            RegistryTestResultDigest::from_digest(digest(GENERATION_1_TEST_RESULT_DIGEST)),
        ),
        bridge_bytes,
        GenesisSuccessorKeyBridgePin::from_trusted_config(bridge_digest),
        SuccessorActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.operator").unwrap(),
            ContractId::new(AUTHOR).unwrap(),
        ),
    )
    .unwrap()
    .activate_first_successor(&candidate)
    .await
    .unwrap()
    {
        SuccessorActivationOutcome::Inserted(accepted) => accepted,
        SuccessorActivationOutcome::ExactReplay(_) => panic!("fresh first successor must insert"),
    };

    ActivatedRegistry {
        physical_scope,
        bootstrap,
        bootstrap_receipt_digest,
        generation_1_head: accepted.registry_head,
        generation_1_accepted_at: accepted.accepted_at,
    }
}

/// One generic ceremony's inputs, all of which the repository re-derives.
struct GenericCeremony {
    target: StructurallyClosedSuccessorTargetV2,
    canonical_target_package: &'static [u8],
    canonical_target_test_result: &'static [u8],
    runner_pin: GenericSuccessorTestRunnerPin,
}

fn generation_2_ceremony(fixture: &ContractFixture) -> GenericCeremony {
    GenericCeremony {
        target: fixture.generation_2.clone(),
        canonical_target_package: record(GENERATION_2_PACKAGE),
        canonical_target_test_result: record(GENERATION_2_TEST_RESULT),
        runner_pin: GenericSuccessorTestRunnerPin::from_trusted_config(
            digest(SUCCESSOR_RUNNER_ARTIFACT),
            digest(SUCCESSOR_RUNNER_CONFIGURATION),
            RegistryTestResultDigest::from_digest(digest(GENERATION_2_TEST_RESULT_DIGEST)),
        ),
    }
}

fn generation_1_ceremony(fixture: &ContractFixture) -> GenericCeremony {
    GenericCeremony {
        target: fixture.generation_1.clone(),
        canonical_target_package: record(GENERATION_1_PACKAGE),
        canonical_target_test_result: record(GENERATION_1_TEST_RESULT),
        runner_pin: GenericSuccessorTestRunnerPin::from_trusted_config(
            digest(SUCCESSOR_RUNNER_ARTIFACT),
            digest(SUCCESSOR_RUNNER_CONFIGURATION),
            RegistryTestResultDigest::from_digest(digest(GENERATION_1_TEST_RESULT_DIGEST)),
        ),
    }
}

fn generic_repository(
    pool: &PgPool,
    fixture: &ContractFixture,
    registry: &ActivatedRegistry,
    ceremony: &GenericCeremony,
    expected_head: &RegistryHeadBindingV1,
    author: &str,
) -> CockroachGenericSuccessorRepository {
    CockroachGenericSuccessorRepository::new(
        pool.clone(),
        trusted_scope(&registry.physical_scope, fixture),
        retry_policy(),
        registry.bootstrap_receipt_digest,
        ceremony.canonical_target_package.to_vec(),
        ceremony.canonical_target_test_result,
        ceremony.runner_pin,
        GenericSuccessorPrincipalBinding::from_trusted_config(
            ContractId::new(PROPOSER).unwrap(),
            ContractId::new(author).unwrap(),
        ),
        expected_head.clone(),
    )
    .unwrap()
}

fn generic_statement(
    fixture: &ContractFixture,
    ceremony: &GenericCeremony,
    installed_policy: &RegistryReferenceV1,
    expected_head: &RegistryHeadBindingV1,
    from_generation: u32,
    effective_from: CanonicalTimestamp,
    author: &str,
) -> GenericSuccessorActivationStatementV2 {
    GenericSuccessorActivationStatementV2 {
        schema_version: 2,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        expected_predecessor_head: expected_head.clone(),
        current_activation_policy: installed_policy.clone(),
        target_package_digest: ceremony.target.package_digest(),
        target_activation_policy: ceremony
            .target
            .activation_policy()
            .registry_reference()
            .clone(),
        test_vector_result_digest: ceremony.runner_pin_expected_result(),
        from_generation,
        to_generation: from_generation + 1,
        effective_from,
        effective_until: None,
        proposer_principal_id: ContractId::new(PROPOSER).unwrap(),
        package_author_principal_id: ContractId::new(author).unwrap(),
    }
}

impl GenericCeremony {
    fn runner_pin_expected_result(&self) -> RegistryTestResultDigest {
        // The pin is opaque by design; the fixture digest is the same value the
        // repository re-derives from the canonical result bytes.
        let expected = match self.canonical_target_test_result {
            bytes if bytes == record(GENERATION_2_TEST_RESULT) => GENERATION_2_TEST_RESULT_DIGEST,
            _ => GENERATION_1_TEST_RESULT_DIGEST,
        };
        RegistryTestResultDigest::from_digest(digest(expected))
    }
}

fn generic_approval(
    statement_id: GenericSuccessorActivationStatementId,
    principal: &str,
    seed: u8,
    prefix: &[u8],
) -> GenericSuccessorActivationApprovalV2 {
    GenericSuccessorActivationApprovalV2 {
        schema_version: 2,
        statement_id,
        signer_principal_id: ContractId::new(principal).unwrap(),
        signature: detached_signature(prefix, statement_id.digest(), seed),
    }
}

fn generic_candidate(
    statement: &GenericSuccessorActivationStatementV2,
    approvals: Vec<GenericSuccessorActivationApprovalV2>,
) -> GenericSuccessorActivationCandidate {
    let statement_id = statement.statement_id().unwrap();
    GenericSuccessorActivationCandidate::from_bounded_canonical_bytes(
        encode_canonical(statement).unwrap(),
        encode_canonical(&GenericSuccessorActivationApprovalSetV2 {
            schema_version: 2,
            statement_id,
            approvals,
        })
        .unwrap(),
    )
    .unwrap()
}

fn quorum(
    statement: &GenericSuccessorActivationStatementV2,
) -> Vec<GenericSuccessorActivationApprovalV2> {
    let statement_id = statement.statement_id().unwrap();
    vec![
        generic_approval(statement_id, "principal.alice", 1, GENERIC_APPROVAL_PREFIX),
        generic_approval(statement_id, "principal.bob", 2, GENERIC_APPROVAL_PREFIX),
    ]
}

async fn scoped_count(pool: &PgPool, table: &str, scope: &FleetScope) -> i64 {
    let query = format!("SELECT count(*)::INT8 FROM {table} WHERE tenant_id = $1 AND project = $2");
    sqlx::query_scalar(&query)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn append_chain(
    previous: Sha256Digest,
    event_id: AcceptedEventId,
    position: &AppendPositionV1,
) -> Sha256Digest {
    let position_bytes = encode_canonical(position).unwrap();
    framed_digest(
        DigestDomain::AppendChain,
        &[
            previous.as_bytes(),
            &position_bytes,
            event_id.digest().as_bytes(),
        ],
    )
}

fn activation_shard(fixture: &ContractFixture, registry: &ActivatedRegistry) -> u16 {
    let key = registry_activation_consistency_partition_key(&fixture.semantic_scope).unwrap();
    registry.bootstrap.partition_for(&key).unwrap()
}

/// Recompute the whole control-shard chain from genesis and require both the
/// stored per-event digests and the shard head to agree.
async fn assert_control_chain_verifies(
    pool: &PgPool,
    fixture: &ContractFixture,
    registry: &ActivatedRegistry,
    expected_registry_events: i64,
) {
    let shard = activation_shard(fixture, registry);
    let epoch_id = registry.bootstrap.epoch_id();
    let rows = sqlx::query(
        "SELECT committed_offset, event_id, previous_chain_digest, chain_digest \
         FROM memory_control_events WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 \
         AND shard = $4 ORDER BY committed_offset",
    )
    .bind(registry.physical_scope.tenant_id)
    .bind(&registry.physical_scope.project)
    .bind(epoch_id.digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(!rows.is_empty());
    let mut previous = registry.bootstrap.genesis_chain_digest(shard).unwrap();
    for row in &rows {
        let offset: i64 = row.get("committed_offset");
        let event_id = AcceptedEventId::from_digest(Sha256Digest::from_bytes(
            row.get::<Vec<u8>, _>("event_id").try_into().unwrap(),
        ));
        let stored_previous = Sha256Digest::from_bytes(
            row.get::<Vec<u8>, _>("previous_chain_digest")
                .try_into()
                .unwrap(),
        );
        assert_eq!(stored_previous, previous, "chain break at offset {offset}");
        let position = AppendPositionV1 {
            epoch_id,
            shard,
            committed_offset: CommittedOffsetV1::new(u64::try_from(offset).unwrap()).unwrap(),
        };
        let derived = append_chain(previous, event_id, &position);
        let stored =
            Sha256Digest::from_bytes(row.get::<Vec<u8>, _>("chain_digest").try_into().unwrap());
        assert_eq!(stored, derived, "chain digest mismatch at offset {offset}");
        previous = derived;
    }
    let head = sqlx::query(
        "SELECT last_committed_offset, chain_digest FROM memory_control_shard_heads \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4",
    )
    .bind(registry.physical_scope.tenant_id)
    .bind(&registry.physical_scope.project)
    .bind(epoch_id.digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        head.get::<i64, _>("last_committed_offset"),
        rows.last().unwrap().get::<i64, _>("committed_offset")
    );
    assert_eq!(
        Sha256Digest::from_bytes(head.get::<Vec<u8>, _>("chain_digest").try_into().unwrap()),
        previous
    );

    let key = registry_activation_consistency_partition_key(&fixture.semantic_scope).unwrap();
    let registry_events: i64 = sqlx::query_scalar(
        "SELECT count(*)::INT8 FROM memory_control_events WHERE tenant_id = $1 AND project = $2 \
         AND epoch_id = $3 AND consistency_family = 'registry.activation' \
         AND consistency_key_digest = $4",
    )
    .bind(registry.physical_scope.tenant_id)
    .bind(&registry.physical_scope.project)
    .bind(epoch_id.digest().as_bytes().to_vec())
    .bind(key.key_digest.as_bytes().to_vec())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(registry_events, expected_registry_events);
}

async fn assert_current_head(
    pool: &PgPool,
    registry: &ActivatedRegistry,
    accepted: &AcceptedGenericSuccessorActivation,
) {
    let row = sqlx::query(
        "SELECT head_state, generation, activation_id, package_digest, canonical_head \
         FROM memory_registry_current_heads_v2 WHERE tenant_id = $1 AND project = $2",
    )
    .bind(registry.physical_scope.tenant_id)
    .bind(&registry.physical_scope.project)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("head_state"), "active");
    assert_eq!(
        row.get::<i64, _>("generation"),
        i64::from(accepted.to_generation)
    );
    assert_eq!(
        Sha256Digest::from_bytes(row.get::<Vec<u8>, _>("activation_id").try_into().unwrap()),
        accepted.activation_id.digest()
    );
    assert_eq!(
        Sha256Digest::from_bytes(row.get::<Vec<u8>, _>("package_digest").try_into().unwrap()),
        accepted.registry_head.head.package_digest
    );
    assert_eq!(
        row.get::<Vec<u8>, _>("canonical_head"),
        encode_canonical(&accepted.registry_head).unwrap()
    );
}

async fn cleanup_scope(pool: &PgPool, scope: &FleetScope) {
    for statement in [
        "DELETE FROM memory_registry_current_heads_v2 WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM memory_registry_genesis_bridge_consumptions \
         WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM memory_registry_transitions WHERE tenant_id = $1 AND project = $2 \
         AND generation = 3",
        "DELETE FROM memory_registry_transitions WHERE tenant_id = $1 AND project = $2 \
         AND generation = 2",
        "DELETE FROM memory_registry_transitions WHERE tenant_id = $1 AND project = $2 \
         AND generation = 1",
        "DELETE FROM memory_registry_transitions WHERE tenant_id = $1 AND project = $2 \
         AND generation = 0",
        "DELETE FROM memory_registry_heads WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM memory_registry_activations WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM memory_control_events WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM memory_control_shard_heads WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM memory_control_log_epochs WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM memory_control_bootstraps WHERE tenant_id = $1 AND project = $2",
    ] {
        sqlx::query(statement)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .execute(pool)
            .await
            .unwrap();
    }
}

#[test]
fn frozen_generic_authority_has_two_eligible_signers_and_threshold_two() {
    let fixture = fixture();
    for target in [&fixture.generation_1, &fixture.generation_2] {
        let policy = target.activation_policy().policy();
        assert_eq!(policy.approval_threshold, 2);
        assert_eq!(
            policy
                .eligible_signers
                .iter()
                .map(|binding| binding.principal_id.as_str())
                .collect::<Vec<_>>(),
            ["principal.alice", "principal.bob"]
        );
    }
    // Governance is unchanged across the two packages; only the package moves.
    assert_eq!(
        fixture
            .generation_1
            .activation_policy()
            .registry_reference(),
        fixture
            .generation_2
            .activation_policy()
            .registry_reference()
    );
    assert_ne!(
        fixture.generation_1.package_digest(),
        fixture.generation_2.package_digest()
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one connected proof keeps the whole generation chain visible
async fn live_generic_successor_activation_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let fixture = fixture();
    let store = CockroachStore::connect(
        &database_url,
        physical_scope("migration"),
        PoolConfig::default(),
    )
    .await
    .unwrap();
    store.migrate().await.unwrap();
    let pool = store.pool().clone();
    let version: String = sqlx::query_scalar("SELECT version()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(version.contains("CockroachDB"));
    let migration_prefix: Vec<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE version BETWEEN 1 AND 17 AND success \
         ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(migration_prefix, (1_i64..=17).collect::<Vec<_>>());

    let installed_policy = fixture
        .generation_1
        .activation_policy()
        .registry_reference()
        .clone();

    // ---- main chain: 1 -> 2, replay, stale, rollback 2 -> 3, ABA ----
    let main = activate_through_generation_one(&pool, &fixture, "main", 41).await;
    let generation_2 = generation_2_ceremony(&fixture);
    let main_repository = generic_repository(
        &pool,
        &fixture,
        &main,
        &generation_2,
        &main.generation_1_head,
        AUTHOR,
    );

    assert!(matches!(
        main_repository.inspect_generic_successor(2).await.unwrap(),
        GenericSuccessorActivationInspection::Ready(_)
    ));

    // The complete prefix is mandatory. Move the genuine row rather than
    // synthesizing a checksum, and restore it before any assertion can abort.
    tokio::time::sleep(Duration::from_millis(2)).await;
    let statement_1_2 = generic_statement(
        &fixture,
        &generation_2,
        &installed_policy,
        &main.generation_1_head,
        1,
        canonical_time(server_time(&pool).await),
        AUTHOR,
    );
    let candidate_1_2 = generic_candidate(&statement_1_2, quorum(&statement_1_2));
    let moved = sqlx::query("UPDATE _sqlx_migrations SET version = 9999 WHERE version = 17")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(moved.rows_affected(), 1);
    let missing_prefix = main_repository
        .activate_generic_successor(&candidate_1_2)
        .await;
    let restored = sqlx::query("UPDATE _sqlx_migrations SET version = 17 WHERE version = 9999")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(restored.rows_affected(), 1);
    assert!(matches!(
        missing_prefix,
        Err(FleetError::SuccessorActivationCorrupt(_))
    ));
    assert_eq!(
        scoped_count(&pool, "memory_registry_transitions", &main.physical_scope).await,
        2
    );

    let inserted_2 = match main_repository
        .activate_generic_successor(&candidate_1_2)
        .await
        .unwrap()
    {
        GenericSuccessorActivationOutcome::Inserted(accepted) => *accepted,
        GenericSuccessorActivationOutcome::ExactReplay(_) => {
            panic!("fresh generic successor must insert")
        }
    };
    assert_eq!(inserted_2.from_generation, 1);
    assert_eq!(inserted_2.to_generation, 2);
    assert_eq!(inserted_2.predecessor_head, main.generation_1_head);
    assert_eq!(
        inserted_2.registry_head.head.package_digest,
        fixture.generation_2.package_digest()
    );
    assert_eq!(
        scoped_count(&pool, "memory_registry_transitions", &main.physical_scope).await,
        3
    );
    assert_current_head(&pool, &main, &inserted_2).await;
    assert_control_chain_verifies(&pool, &fixture, &main, 3).await;

    // Exact replay is one semantic effect (EVENT-01, REPLAY-01).
    assert_eq!(
        main_repository
            .activate_generic_successor(&candidate_1_2)
            .await
            .unwrap(),
        GenericSuccessorActivationOutcome::ExactReplay(Box::new(inserted_2.clone()))
    );
    assert_eq!(
        main_repository.inspect_generic_successor(2).await.unwrap(),
        GenericSuccessorActivationInspection::Accepted(Box::new(inserted_2.clone()))
    );
    assert_eq!(
        scoped_count(&pool, "memory_registry_transitions", &main.physical_scope).await,
        3
    );

    // A different generation 1 -> 2 statement is deterministically stale now.
    let stale_statement = generic_statement(
        &fixture,
        &generation_2,
        &installed_policy,
        &main.generation_1_head,
        1,
        canonical_time(server_time(&pool).await),
        AUTHOR,
    );
    assert_ne!(
        stale_statement.statement_id().unwrap(),
        statement_1_2.statement_id().unwrap()
    );
    assert!(matches!(
        main_repository
            .activate_generic_successor(&generic_candidate(
                &stale_statement,
                quorum(&stale_statement)
            ))
            .await,
        Err(FleetError::SuccessorActivationStale)
    ));

    // Rollback: activate the EARLIER package digest as generation 3. The head
    // repeats a package digest under a brand-new activation ID.
    let generation_1 = generation_1_ceremony(&fixture);
    let rollback_repository = generic_repository(
        &pool,
        &fixture,
        &main,
        &generation_1,
        &inserted_2.registry_head,
        AUTHOR,
    );
    tokio::time::sleep(Duration::from_millis(2)).await;
    let rollback_statement = generic_statement(
        &fixture,
        &generation_1,
        &installed_policy,
        &inserted_2.registry_head,
        2,
        canonical_time(server_time(&pool).await),
        AUTHOR,
    );
    let inserted_3 = match rollback_repository
        .activate_generic_successor(&generic_candidate(
            &rollback_statement,
            quorum(&rollback_statement),
        ))
        .await
        .unwrap()
    {
        GenericSuccessorActivationOutcome::Inserted(accepted) => *accepted,
        GenericSuccessorActivationOutcome::ExactReplay(_) => panic!("rollback must insert"),
    };
    assert_eq!(inserted_3.to_generation, 3);
    assert_eq!(
        inserted_3.registry_head.head.package_digest,
        main.generation_1_head.head.package_digest
    );
    assert_ne!(
        inserted_3.registry_head.head.activation_id,
        main.generation_1_head.head.activation_id
    );
    assert_current_head(&pool, &main, &inserted_3).await;
    assert_control_chain_verifies(&pool, &fixture, &main, 4).await;

    // ABA: the head now names package A again under a new activation ID, so a
    // statement written against the FIRST A is still stale even though its
    // package digest matches exactly.
    assert_eq!(
        inserted_3.registry_head.head.package_digest,
        main.generation_1_head.head.package_digest
    );
    // The repository is bound to the CURRENT (generation-three) head, so the
    // only thing that can make this stale is the statement naming the first
    // A head's activation ID.
    let aba_repository = generic_repository(
        &pool,
        &fixture,
        &main,
        &generation_2,
        &inserted_3.registry_head,
        AUTHOR,
    );
    let aba_statement = generic_statement(
        &fixture,
        &generation_2,
        &installed_policy,
        &main.generation_1_head,
        3,
        canonical_time(server_time(&pool).await),
        AUTHOR,
    );
    assert!(matches!(
        aba_repository
            .activate_generic_successor(&generic_candidate(&aba_statement, quorum(&aba_statement)))
            .await,
        Err(FleetError::SuccessorActivationStale)
    ));
    assert_eq!(
        scoped_count(&pool, "memory_registry_transitions", &main.physical_scope).await,
        4
    );

    // A statement that expects generation 0 or 1 after generation 3 exists.
    let ancient_repository = generic_repository(
        &pool,
        &fixture,
        &main,
        &generation_2,
        &main.generation_1_head,
        AUTHOR,
    );
    let ancient_statement = generic_statement(
        &fixture,
        &generation_2,
        &installed_policy,
        &main.generation_1_head,
        1,
        canonical_time(server_time(&pool).await),
        AUTHOR,
    );
    assert!(matches!(
        ancient_repository
            .activate_generic_successor(&generic_candidate(
                &ancient_statement,
                quorum(&ancient_statement)
            ))
            .await,
        Err(FleetError::SuccessorActivationStale)
    ));

    // ---- rejected ceremonies against a fresh generation-one head ----
    let rejected = activate_through_generation_one(&pool, &fixture, "rejected", 42).await;
    let rejected_repository = generic_repository(
        &pool,
        &fixture,
        &rejected,
        &generation_2,
        &rejected.generation_1_head,
        AUTHOR,
    );
    tokio::time::sleep(Duration::from_millis(2)).await;
    let rejected_statement = generic_statement(
        &fixture,
        &generation_2,
        &installed_policy,
        &rejected.generation_1_head,
        1,
        canonical_time(server_time(&pool).await),
        AUTHOR,
    );
    let rejected_statement_id = rejected_statement.statement_id().unwrap();

    // Below the installed threshold.
    assert!(
        rejected_repository
            .activate_generic_successor(&generic_candidate(
                &rejected_statement,
                vec![generic_approval(
                    rejected_statement_id,
                    "principal.alice",
                    1,
                    GENERIC_APPROVAL_PREFIX,
                )],
            ))
            .await
            .is_err()
    );

    // Approvals minted under the frozen 0 -> 1 bridge prefix verify against
    // nothing at generation one and later.
    assert!(
        rejected_repository
            .activate_generic_successor(&generic_candidate(
                &rejected_statement,
                vec![
                    generic_approval(
                        rejected_statement_id,
                        "principal.alice",
                        1,
                        BRIDGE_APPROVAL_PREFIX
                    ),
                    generic_approval(
                        rejected_statement_id,
                        "principal.bob",
                        2,
                        BRIDGE_APPROVAL_PREFIX
                    ),
                ],
            ))
            .await
            .is_err()
    );

    // The package author may not be counted as an approver.
    let author_repository = generic_repository(
        &pool,
        &fixture,
        &rejected,
        &generation_2,
        &rejected.generation_1_head,
        "principal.alice",
    );
    let author_statement = generic_statement(
        &fixture,
        &generation_2,
        &installed_policy,
        &rejected.generation_1_head,
        1,
        canonical_time(server_time(&pool).await),
        "principal.alice",
    );
    assert!(
        author_repository
            .activate_generic_successor(&generic_candidate(
                &author_statement,
                quorum(&author_statement)
            ))
            .await
            .is_err()
    );

    // Both closed timing failures, against a real predecessor acceptance time.
    let predecessor_accepted = canonical_datetime(&rejected.generation_1_accepted_at);
    let head_effective = canonical_datetime(&rejected.generation_1_head.effective_from);
    let early = head_effective + ChronoDuration::microseconds(1);
    assert!(
        early < predecessor_accepted,
        "the 0 -> 1 ceremony left no interval between effective and accepted time"
    );
    let early_statement = generic_statement(
        &fixture,
        &generation_2,
        &installed_policy,
        &rejected.generation_1_head,
        1,
        canonical_time(early),
        AUTHOR,
    );
    assert!(matches!(
        rejected_repository
            .activate_generic_successor(&generic_candidate(
                &early_statement,
                quorum(&early_statement)
            ))
            .await,
        Err(FleetError::SuccessorActivationTiming(
            SuccessorActivationTimingKind::BeforePredecessorAcceptance
        ))
    ));
    let future_statement = generic_statement(
        &fixture,
        &generation_2,
        &installed_policy,
        &rejected.generation_1_head,
        1,
        canonical_time(server_time(&pool).await + ChronoDuration::minutes(5)),
        AUTHOR,
    );
    assert!(matches!(
        rejected_repository
            .activate_generic_successor(&generic_candidate(
                &future_statement,
                quorum(&future_statement)
            ))
            .await,
        Err(FleetError::SuccessorActivationTiming(
            SuccessorActivationTimingKind::FutureEffective
        ))
    ));

    assert_eq!(
        scoped_count(
            &pool,
            "memory_registry_transitions",
            &rejected.physical_scope
        )
        .await,
        2,
        "a rejected ceremony wrote a transition"
    );

    // ---- fail closed without an active head ----
    let headless = activate_through_generation_one(&pool, &fixture, "headless", 43).await;
    let headless_repository = generic_repository(
        &pool,
        &fixture,
        &headless,
        &generation_2,
        &headless.generation_1_head,
        AUTHOR,
    );
    // head_state is not even representable outside 'active' yet, which is why a
    // contested/ambiguous projection has no runtime in this cycle.
    assert!(
        sqlx::query(
            "UPDATE memory_registry_current_heads_v2 SET head_state = 'ambiguous' \
             WHERE tenant_id = $1 AND project = $2",
        )
        .bind(headless.physical_scope.tenant_id)
        .bind(&headless.physical_scope.project)
        .execute(&pool)
        .await
        .is_err()
    );
    sqlx::query(
        "DELETE FROM memory_registry_current_heads_v2 WHERE tenant_id = $1 AND project = $2",
    )
    .bind(headless.physical_scope.tenant_id)
    .bind(&headless.physical_scope.project)
    .execute(&pool)
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(2)).await;
    let headless_statement = generic_statement(
        &fixture,
        &generation_2,
        &installed_policy,
        &headless.generation_1_head,
        1,
        canonical_time(server_time(&pool).await),
        AUTHOR,
    );
    assert!(matches!(
        headless_repository
            .activate_generic_successor(&generic_candidate(
                &headless_statement,
                quorum(&headless_statement)
            ))
            .await,
        Err(FleetError::SuccessorActivationNotReady)
    ));
    assert!(matches!(
        headless_repository.inspect_generic_successor(2).await,
        Err(FleetError::SuccessorActivationNotReady)
    ));

    // ---- a stored ceremony that differs from the candidate is a conflict ----
    let ceremony_scope = activate_through_generation_one(&pool, &fixture, "ceremony", 44).await;
    let ceremony_repository = generic_repository(
        &pool,
        &fixture,
        &ceremony_scope,
        &generation_2,
        &ceremony_scope.generation_1_head,
        AUTHOR,
    );
    tokio::time::sleep(Duration::from_millis(2)).await;
    let ceremony_statement = generic_statement(
        &fixture,
        &generation_2,
        &installed_policy,
        &ceremony_scope.generation_1_head,
        1,
        canonical_time(server_time(&pool).await),
        AUTHOR,
    );
    let ceremony_candidate = generic_candidate(&ceremony_statement, quorum(&ceremony_statement));
    ceremony_repository
        .activate_generic_successor(&ceremony_candidate)
        .await
        .unwrap();
    let ceremony_statement_id = ceremony_statement.statement_id().unwrap();
    let other_ceremony = encode_canonical(&GenericSuccessorActivationApprovalSetV2 {
        schema_version: 2,
        statement_id: ceremony_statement_id,
        approvals: vec![generic_approval(
            ceremony_statement_id,
            "principal.alice",
            1,
            GENERIC_APPROVAL_PREFIX,
        )],
    })
    .unwrap();
    let rewritten = sqlx::query(
        "UPDATE memory_registry_transitions SET canonical_approval_set = $3 \
         WHERE tenant_id = $1 AND project = $2 AND generation = 2",
    )
    .bind(ceremony_scope.physical_scope.tenant_id)
    .bind(&ceremony_scope.physical_scope.project)
    .bind(other_ceremony)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(rewritten.rows_affected(), 1);
    assert!(matches!(
        ceremony_repository
            .activate_generic_successor(&ceremony_candidate)
            .await,
        Err(FleetError::SuccessorActivationConflict(_))
    ));

    // ---- concurrency: exactly one commits ----
    let identical = activate_through_generation_one(&pool, &fixture, "identical", 45).await;
    let identical_repository = generic_repository(
        &pool,
        &fixture,
        &identical,
        &generation_2,
        &identical.generation_1_head,
        AUTHOR,
    );
    tokio::time::sleep(Duration::from_millis(2)).await;
    let identical_statement = generic_statement(
        &fixture,
        &generation_2,
        &installed_policy,
        &identical.generation_1_head,
        1,
        canonical_time(server_time(&pool).await),
        AUTHOR,
    );
    let identical_candidate = generic_candidate(&identical_statement, quorum(&identical_statement));
    let identical_barrier = Arc::new(Barrier::new(8));
    let identical_results = join_all((0..8).map(|_| {
        let barrier = Arc::clone(&identical_barrier);
        let repository = identical_repository.clone();
        let candidate = identical_candidate.clone();
        async move {
            barrier.wait().await;
            repository.activate_generic_successor(&candidate).await
        }
    }))
    .await;
    assert_eq!(
        identical_results
            .iter()
            .filter(|result| matches!(result, Ok(GenericSuccessorActivationOutcome::Inserted(_))))
            .count(),
        1
    );
    assert_eq!(
        identical_results
            .iter()
            .filter(|result| matches!(
                result,
                Ok(GenericSuccessorActivationOutcome::ExactReplay(_))
            ))
            .count(),
        7
    );
    assert_eq!(
        scoped_count(
            &pool,
            "memory_registry_transitions",
            &identical.physical_scope
        )
        .await,
        3
    );

    let distinct = activate_through_generation_one(&pool, &fixture, "distinct", 46).await;
    let distinct_repository = generic_repository(
        &pool,
        &fixture,
        &distinct,
        &generation_2,
        &distinct.generation_1_head,
        AUTHOR,
    );
    tokio::time::sleep(Duration::from_millis(2)).await;
    let distinct_base = server_time(&pool).await;
    let distinct_barrier = Arc::new(Barrier::new(8));
    let distinct_results = join_all((0_i64..8).map(|delta| {
        let statement = generic_statement(
            &fixture,
            &generation_2,
            &installed_policy,
            &distinct.generation_1_head,
            1,
            canonical_time(distinct_base - ChronoDuration::microseconds(delta)),
            AUTHOR,
        );
        let candidate = generic_candidate(&statement, quorum(&statement));
        let barrier = Arc::clone(&distinct_barrier);
        let repository = distinct_repository.clone();
        async move {
            barrier.wait().await;
            repository.activate_generic_successor(&candidate).await
        }
    }))
    .await;
    assert_eq!(
        distinct_results
            .iter()
            .filter(|result| matches!(result, Ok(GenericSuccessorActivationOutcome::Inserted(_))))
            .count(),
        1
    );
    assert_eq!(
        distinct_results
            .iter()
            .filter(|result| matches!(result, Err(FleetError::SuccessorActivationStale)))
            .count(),
        7
    );
    assert_eq!(
        scoped_count(
            &pool,
            "memory_registry_transitions",
            &distinct.physical_scope
        )
        .await,
        3
    );
    assert_control_chain_verifies(&pool, &fixture, &distinct, 3).await;

    for registry in [
        &main,
        &rejected,
        &headless,
        &ceremony_scope,
        &identical,
        &distinct,
    ] {
        cleanup_scope(&pool, &registry.physical_scope).await;
    }
}
