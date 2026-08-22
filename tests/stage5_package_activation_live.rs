//! Connected proof for the generation-2 (`stage5`) package: it composes and
//! closes offline, and its `1 -> 2` activation installs a durable, idempotent
//! generation-2 head through the generic successor runtime (W2-PKG).
//!
//! Set the exact `FLEET_RECALL_TEST_DATABASE_URL` variable to a disposable
//! `CockroachDB` 26.2 database. The connected portion is inert otherwise; it
//! never starts a database process, invokes Docker, or targets a cloud service.
//! The offline `stage5_package_*` tests run unconditionally.
//!
//! The connected scope walks the whole real chain — bootstrap, genesis
//! activation, the frozen `0 -> 1` first successor — before the generic
//! `1 -> 2` transition, so the installed activation policy is the one a live
//! `0 -> 1` ceremony actually stored, never a fixture head.

use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisRepository, TrustedControlScope,
};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1,
    verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{decode_strict, encode_canonical};
use ostk_fleet_recall::memory_contracts::chunk_identity::{NormalizationRuleV1, ParserKeyV1};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, FixedHex32, FixedHex64, HexBytes,
    ProfileReferenceV1, RegistryReferenceV1, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::coverage::{
    ConnectorInstanceCursorV2, CoverageCompletenessV1, CoverageFreshnessV1, CoverageProofBasisV1,
    CoverageProofMethodV1, CoverageProofV2, CoverageScopeV1, CoverageWindowV1, FreshnessStateV1,
    SequenceContinuityV1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest,
};
use ostk_fleet_recall::memory_contracts::evidence_v2::{
    ConnectorSchemaV2, ConsistencyKeyDerivationV1, ConsistencyPartitionFamilyV1,
    ConsistencyPartitionRecipeV1, RegistryHeadBindingV1, StructurallyResolvedConnectorSchemaV2,
};
use ostk_fleet_recall::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use ostk_fleet_recall::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, GenesisRegistryActivationApprovalSetV1,
    GenesisRegistryActivationApprovalV1, GenesisRegistryActivationStatementV1,
    GenesisRegistryAnchorV1, RegistryTestResultDigest, RegistryTestRunnerPin,
    VerifiedRegistryTestResult, genesis_activation_policy_digest,
    verify_genesis_registry_activation, verify_registry_test_result,
};
use ostk_fleet_recall::memory_contracts::identity::ResourceUri;
use ostk_fleet_recall::memory_contracts::registry::{
    ManifestVerifiedRegistryPackage, RegistryEntryKind, RegistryEntryV1,
};
use ostk_fleet_recall::memory_contracts::stage4_target_package::SemanticallyClosedStage4Package;
use ostk_fleet_recall::memory_contracts::stage5_target_package::{
    ParserContractV2, SemanticallyClosedStage5Package, Stage5PackageComponents, Stage5PackageError,
};
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
use ostk_recall_core::PrivacyTier;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sqlx::{PgPool, Row};
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
    generation_2: StructurallyClosedSuccessorTargetV2,
}

struct ActivatedRegistry {
    physical_scope: FleetScope,
    bootstrap_receipt_digest: BootstrapReceiptDigest,
    generation_1_head: RegistryHeadBindingV1,
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
        format!("stage5-{label}-{}", Uuid::now_v7()),
        "stage5-package-connected-test",
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
        bootstrap_receipt_digest,
        generation_1_head: accepted.registry_head,
    }
}

fn generic_repository(
    pool: &PgPool,
    fixture: &ContractFixture,
    registry: &ActivatedRegistry,
    expected_head: &RegistryHeadBindingV1,
) -> CockroachGenericSuccessorRepository {
    CockroachGenericSuccessorRepository::new(
        pool.clone(),
        trusted_scope(&registry.physical_scope, fixture),
        retry_policy(),
        registry.bootstrap_receipt_digest,
        record(GENERATION_2_PACKAGE).to_vec(),
        record(GENERATION_2_TEST_RESULT),
        GenericSuccessorTestRunnerPin::from_trusted_config(
            digest(SUCCESSOR_RUNNER_ARTIFACT),
            digest(SUCCESSOR_RUNNER_CONFIGURATION),
            RegistryTestResultDigest::from_digest(digest(GENERATION_2_TEST_RESULT_DIGEST)),
        ),
        GenericSuccessorPrincipalBinding::from_trusted_config(
            ContractId::new(PROPOSER).unwrap(),
            ContractId::new(AUTHOR).unwrap(),
        ),
        expected_head.clone(),
    )
    .unwrap()
}

fn generic_statement(
    fixture: &ContractFixture,
    installed_policy: &RegistryReferenceV1,
    expected_head: &RegistryHeadBindingV1,
    effective_from: CanonicalTimestamp,
) -> GenericSuccessorActivationStatementV2 {
    GenericSuccessorActivationStatementV2 {
        schema_version: 2,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        expected_predecessor_head: expected_head.clone(),
        current_activation_policy: installed_policy.clone(),
        target_package_digest: fixture.generation_2.package_digest(),
        target_activation_policy: fixture
            .generation_2
            .activation_policy()
            .registry_reference()
            .clone(),
        test_vector_result_digest: RegistryTestResultDigest::from_digest(digest(
            GENERATION_2_TEST_RESULT_DIGEST,
        )),
        from_generation: 1,
        to_generation: 2,
        effective_from,
        effective_until: None,
        proposer_principal_id: ContractId::new(PROPOSER).unwrap(),
        package_author_principal_id: ContractId::new(AUTHOR).unwrap(),
    }
}

fn generic_approval(
    statement_id: GenericSuccessorActivationStatementId,
    principal: &str,
    seed: u8,
) -> GenericSuccessorActivationApprovalV2 {
    GenericSuccessorActivationApprovalV2 {
        schema_version: 2,
        statement_id,
        signer_principal_id: ContractId::new(principal).unwrap(),
        signature: detached_signature(GENERIC_APPROVAL_PREFIX, statement_id.digest(), seed),
    }
}

fn generic_candidate(
    statement: &GenericSuccessorActivationStatementV2,
) -> GenericSuccessorActivationCandidate {
    let statement_id = statement.statement_id().unwrap();
    GenericSuccessorActivationCandidate::from_bounded_canonical_bytes(
        encode_canonical(statement).unwrap(),
        encode_canonical(&GenericSuccessorActivationApprovalSetV2 {
            schema_version: 2,
            statement_id,
            approvals: vec![
                generic_approval(statement_id, "principal.alice", 1),
                generic_approval(statement_id, "principal.bob", 2),
            ],
        })
        .unwrap(),
    )
    .unwrap()
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

async fn current_head_generation(pool: &PgPool, scope: &FleetScope) -> (String, i64) {
    let row = sqlx::query(
        "SELECT head_state, generation FROM memory_registry_current_heads_v2 \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .fetch_one(pool)
    .await
    .unwrap();
    (
        row.get::<String, _>("head_state"),
        row.get::<i64, _>("generation"),
    )
}

async fn cleanup_scope(pool: &PgPool, scope: &FleetScope) {
    for statement in [
        "DELETE FROM memory_registry_current_heads_v2 WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM memory_registry_genesis_bridge_consumptions \
         WHERE tenant_id = $1 AND project = $2",
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

// ---- offline stage5 package helpers (public-API only) ----

fn d(label: &str) -> Sha256Digest {
    domain_separated_digest(DigestDomain::RegistryEntry, label.as_bytes())
}

fn reg_ref(id: &str, version: u32, label: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version,
        entry_digest: d(label),
    }
}

fn connector_schema(schema_id: &str, scope_ok: bool) -> ConnectorSchemaV2 {
    ConnectorSchemaV2 {
        schema_version: 2,
        connector_schema_id: ContractId::new(schema_id).unwrap(),
        version: 2,
        provider_namespace: reg_ref(&format!("namespace.{schema_id}"), 1, schema_id),
        evidence_schema: reg_ref(&format!("evidence.{schema_id}"), 2, schema_id),
        provider_instance_identity_recipe: reg_ref(
            &format!("identity.{schema_id}.instance"),
            1,
            schema_id,
        ),
        canonical_resource_identity_recipe: reg_ref(
            &format!("identity.{schema_id}.resource"),
            2,
            schema_id,
        ),
        consistency_partition_recipe: ConsistencyPartitionRecipeV1 {
            schema_version: 1,
            recipe_id: ContractId::new("ostk.consistency.source_fact_id").unwrap(),
            recipe_version: 1,
            family: ConsistencyPartitionFamilyV1::SourceFact,
            key_derivation: ConsistencyKeyDerivationV1::SourceFactId,
        },
        authenticated_scope_required: scope_ok,
        delivery_id_in_semantic_identity: false,
        immutable_revision_required: true,
    }
}

fn connector_entry(schema: &ConnectorSchemaV2) -> RegistryEntryV1 {
    let body_bytes = encode_canonical(schema).unwrap();
    RegistryEntryV1 {
        schema_version: 1,
        kind: RegistryEntryKind::ConnectorSchema,
        entry_id: schema.connector_schema_id.clone(),
        version: schema.version,
        entry_schema_id: ContractId::new("registry.connector_schema").unwrap(),
        entry_schema_version: 2,
        body: decode_strict(&body_bytes).unwrap(),
        positive_vector_digest: d(&format!("{}-ok", schema.connector_schema_id.as_str())),
        negative_vector_digest: d(&format!("{}-bad", schema.connector_schema_id.as_str())),
    }
}

fn resolved(schema_id: &str) -> StructurallyResolvedConnectorSchemaV2 {
    StructurallyResolvedConnectorSchemaV2::from_registry_entry(&connector_entry(&connector_schema(
        schema_id, true,
    )))
    .unwrap()
}

fn cursor(instance_id: &str, byte: u8) -> ConnectorInstanceCursorV2 {
    ConnectorInstanceCursorV2 {
        connector_instance_id: ContractId::new(instance_id).unwrap(),
        cursor: HexBytes::new(vec![byte, byte, byte]).unwrap(),
        completeness: CoverageCompletenessV1::Complete,
        continuity: SequenceContinuityV1::Contiguous {},
    }
}

const STAGE5_TRANSCRIPT: &str = "connector.transcript";
const STAGE5_HISTORY: &str = "connector.version_history";
const STAGE5_TRANSCRIPT_INSTANCE: &str = "instance.transcript.main";
const STAGE5_HISTORY_INSTANCE: &str = "instance.history.main";

fn stage5_components(rules: Vec<NormalizationRuleV1>) -> Stage5PackageComponents {
    Stage5PackageComponents {
        transcript_connector: resolved(STAGE5_TRANSCRIPT)
            .bind_instance(ContractId::new(STAGE5_TRANSCRIPT_INSTANCE).unwrap())
            .unwrap(),
        version_history_connector: resolved(STAGE5_HISTORY)
            .bind_instance(ContractId::new(STAGE5_HISTORY_INSTANCE).unwrap())
            .unwrap(),
        coverage: CoverageProofV2 {
            schema_version: 2,
            scope: CoverageScopeV1 {
                scope: ResourceUri::from_str(&format!(
                    "urn:ostk:entity:v1:repository:sha256:{}",
                    "1".repeat(64)
                ))
                .unwrap(),
                revision: HexBytes::new(vec![0x22; 32]).unwrap(),
                window: CoverageWindowV1 {
                    window_start: CanonicalTimestamp::parse("2026-08-14T00:00:00.000000000Z")
                        .unwrap(),
                    window_end: CanonicalTimestamp::parse("2026-08-15T00:00:00.000000000Z")
                        .unwrap(),
                },
            },
            freshness: CoverageFreshnessV1 {
                state: FreshnessStateV1::Current,
                freshness_rule: reg_ref("coverage.freshness.default_rule", 1, "freshness"),
            },
            proof_basis: CoverageProofBasisV1 {
                method: CoverageProofMethodV1::ClosedCursorInterval,
                proof_method_registration: reg_ref(
                    "coverage.proof.cursor_interval",
                    1,
                    "proof-method",
                ),
            },
            observed_through: CanonicalTimestamp::parse("2026-08-15T00:00:00.000000000Z").unwrap(),
            instances: vec![
                cursor(STAGE5_HISTORY_INSTANCE, 0xAB),
                cursor(STAGE5_TRANSCRIPT_INSTANCE, 0xCD),
            ],
        },
        parser: ParserContractV2 {
            schema_version: 2,
            parser_contract_id: ContractId::new("parser.transcript_and_history").unwrap(),
            version: 3,
            parser_key: ParserKeyV1 {
                schema_version: 1,
                parser_artifact_digest: d("parser-artifact"),
                parser_version: 4,
                configuration_digest: d("parser-config"),
                declared_normalization_rules: rules,
            },
        },
        remember_predicate: reg_ref("mcp.remember.allowed_actions", 3, "remember-predicate"),
        remember_admission: reg_ref("remember.actor_assertion", 3, "remember-admission"),
        activation_policy: reg_ref("activation.default", 2, "activation-policy"),
        relation_proof: reg_ref("relation.repository_parent", 2, "relation-proof"),
        observer_admission: reg_ref("observer.default", 2, "observer-admission"),
        episode_policy: reg_ref("episode.default", 2, "episode-policy"),
        normative_binding: reg_ref("normative.default", 2, "normative-binding"),
    }
}

/// The generation-2 package composes, closes, round-trips, and fails closed on
/// a payload-selected connector and on a component-digest mismatch. Runs with no
/// database.
#[test]
fn stage5_package_closes_and_fails_closed_offline() {
    let package = SemanticallyClosedStage5Package::from_components(stage5_components(vec![
        NormalizationRuleV1::NewlineLf,
        NormalizationRuleV1::UnicodeNfc,
    ]))
    .unwrap();

    // Closure: canonical bytes round-trip to the same content-addressed digest.
    assert_eq!(
        SemanticallyClosedStage5Package::verify_canonical_bytes(package.canonical_bytes()).unwrap(),
        package.package_digest()
    );

    // A payload-selected connector scope cannot even resolve, so it can never
    // enter the package or reach activation.
    assert!(
        StructurallyResolvedConnectorSchemaV2::from_registry_entry(&connector_entry(
            &connector_schema(STAGE5_TRANSCRIPT, false),
        ))
        .is_err()
    );

    // A component-digest mismatch against the committed bytes fails closed.
    let tampered = stage5_components(vec![NormalizationRuleV1::WhitespaceCollapse]);
    assert_eq!(
        SemanticallyClosedStage5Package::from_canonical_bytes_and_components(
            package.canonical_bytes(),
            tampered,
        ),
        Err(Stage5PackageError::ComponentDigestMismatch)
    );
}

/// The generation-2 package activates `1 -> 2` through the generic runtime,
/// installs a durable generation-2 head, and re-activation is idempotent
/// (exact replay), never double-applied.
#[tokio::test]
async fn live_stage5_generation_two_activation_is_durable_and_idempotent() {
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

    let installed_policy = fixture
        .generation_2
        .activation_policy()
        .registry_reference()
        .clone();

    // The generation-2 package this activation installs composes and closes.
    let package = SemanticallyClosedStage5Package::from_components(stage5_components(vec![
        NormalizationRuleV1::NewlineLf,
    ]))
    .unwrap();
    assert_eq!(
        SemanticallyClosedStage5Package::verify_canonical_bytes(package.canonical_bytes()).unwrap(),
        package.package_digest()
    );

    let registry = activate_through_generation_one(&pool, &fixture, "main", 51).await;
    let repository = generic_repository(&pool, &fixture, &registry, &registry.generation_1_head);

    // Before activation, generation 2 is the next open slot.
    assert!(matches!(
        repository.inspect_generic_successor(2).await.unwrap(),
        GenericSuccessorActivationInspection::Ready(_)
    ));

    tokio::time::sleep(Duration::from_millis(2)).await;
    let statement = generic_statement(
        &fixture,
        &installed_policy,
        &registry.generation_1_head,
        canonical_time(server_time(&pool).await),
    );
    let candidate = generic_candidate(&statement);

    let inserted = match repository
        .activate_generic_successor(&candidate)
        .await
        .unwrap()
    {
        GenericSuccessorActivationOutcome::Inserted(accepted) => *accepted,
        GenericSuccessorActivationOutcome::ExactReplay(_) => {
            panic!("fresh generation-2 activation must insert")
        }
    };
    assert_eq!(inserted.from_generation, 1);
    assert_eq!(inserted.to_generation, 2);
    assert_eq!(inserted.predecessor_head, registry.generation_1_head);
    assert_eq!(
        inserted.registry_head.head.package_digest,
        fixture.generation_2.package_digest()
    );
    assert_eq!(
        scoped_count(
            &pool,
            "memory_registry_transitions",
            &registry.physical_scope
        )
        .await,
        3
    );
    assert_eq!(
        current_head_generation(&pool, &registry.physical_scope).await,
        ("active".to_string(), 2)
    );

    // inspect(2) now reports the durable, accepted transition.
    assert_inspect_accepted(&repository, &inserted).await;

    // Re-activating the exact same ceremony is idempotent: an exact replay of
    // the same effect, never a second transition row.
    assert_eq!(
        repository
            .activate_generic_successor(&candidate)
            .await
            .unwrap(),
        GenericSuccessorActivationOutcome::ExactReplay(Box::new(inserted.clone()))
    );
    assert_inspect_accepted(&repository, &inserted).await;
    assert_eq!(
        scoped_count(
            &pool,
            "memory_registry_transitions",
            &registry.physical_scope
        )
        .await,
        3,
        "idempotent re-activation must not double-apply"
    );

    cleanup_scope(&pool, &registry.physical_scope).await;
}

async fn assert_inspect_accepted(
    repository: &CockroachGenericSuccessorRepository,
    inserted: &AcceptedGenericSuccessorActivation,
) {
    match repository.inspect_generic_successor(2).await.unwrap() {
        GenericSuccessorActivationInspection::Accepted(accepted) => {
            assert_eq!(*accepted, inserted.clone());
        }
        GenericSuccessorActivationInspection::Ready(_) => {
            panic!("generation 2 must be durable after activation")
        }
    }
}
