//! Connected proof for the general accepted-event append repository (W1-APPEND).
//!
//! Set the exact `FLEET_RECALL_TEST_DATABASE_URL` variable to a disposable
//! `CockroachDB` 26.2 database. Every test here is inert otherwise. Nothing in
//! this file starts a database process, invokes Docker, or targets a cloud
//! service.
//!
//! # What is proven only at compile time
//!
//! Governance kinds are unconstructible: `AcceptedEventKindV1` is a closed
//! three-variant enum, `event_kind` is derived from the variant, and no
//! constructor accepts a free-form kind string. There is therefore no runtime
//! test here for "appending `control.bootstrap.accepted` is refused" — that
//! append cannot be *written* in Rust. The unit test
//! `evidence_ledger::appendable::tests::accepted_event_kinds_are_the_three_stage4_general_kinds`
//! pins the three admitted strings and asserts none of the governance kinds is
//! among them; migration 0018's
//! `memory_evidence_event_governance_exclusion` CHECK and the D2 grant boundary
//! are the two independent backstops behind that.

use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::future::join_all;
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisRepository, TrustedControlScope,
};
use ostk_fleet_recall::evidence_ledger::{
    AcceptedEventRepository, AppendOutcome, AppendProjection, AppendableAcceptedEvent,
    CockroachAcceptedEventRepository, EvidenceAppendError, EvidenceAppendResult,
    EvidenceDeliveryContextV1, NoProjection, ProjectionContext, ShardChainDivergenceKind,
    WitnessMismatchKind, WriterAuthoritySnapshot, WriterAuthorityWitness,
};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1, EpochId,
    GenesisLogEpochV1, VerifiedBootstrapReceipt, verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{decode_strict, encode_canonical};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, FixedHex32, FixedHex64, HexBytes,
    ProfileReferenceV1, RegistryReferenceV1, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest,
};
use ostk_fleet_recall::memory_contracts::evidence_v2::{
    EvidenceStatementV2, RegistryHeadBindingV1, StructurallyResolvedConnectorSchemaV2,
    derive_representation_key_v2, derive_source_fact_id_v2,
};
use ostk_fleet_recall::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use ostk_fleet_recall::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, GenesisRegistryActivationApprovalSetV1,
    GenesisRegistryActivationApprovalV1, GenesisRegistryActivationStatementV1,
    GenesisRegistryAnchorV1, RegistryTestResultDigest, RegistryTestRunnerPin,
    VerifiedRegistryTestResult, genesis_activation_policy_digest,
    verify_genesis_registry_activation, verify_registry_test_result,
};
use ostk_fleet_recall::memory_contracts::registry::{
    ManifestVerifiedRegistryPackage, RegistryEntryKind, RegistryEntryV1,
};
use ostk_fleet_recall::memory_contracts::relation::RelationAttestationEventV1;
use ostk_fleet_recall::memory_contracts::remember_v2::RememberAcceptedStatementV2;
use ostk_fleet_recall::memory_contracts::stage4_target_package::SemanticallyClosedStage4Package;
use ostk_fleet_recall::memory_contracts::successor_activation::{
    SuccessorActivationPrincipalBinding, SuccessorRegistryActivationApprovalSetV1,
    SuccessorRegistryActivationApprovalV1, SuccessorRegistryActivationStatementV1,
    SuccessorRegistryTestRunnerPin, verify_successor_registry_test_result,
};
use ostk_fleet_recall::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;
use ostk_fleet_recall::memory_contracts::successor_policy::{
    ActivationSignatureAlgorithmV2, ActivationSignerBindingV2, GenesisSuccessorKeyBridgeDigest,
    GenesisSuccessorKeyBridgePin, GenesisSuccessorKeyBridgeV1,
};
use ostk_fleet_recall::registry_activation::{
    CockroachGenesisActivationRepository, CockroachSuccessorActivationRepository,
    GenesisActivationOutcome, GenesisActivationRepository, SuccessorActivationCandidate,
    SuccessorActivationOutcome, SuccessorActivationRepository,
};
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_fleet_recall::{FleetError, FleetScope};
use ostk_recall_core::PrivacyTier;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row as _};
use tokio::sync::{Barrier, Mutex};
use uuid::Uuid;

const GENESIS_PACKAGE: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");
const BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");
const GENESIS_TEST_RESULT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/genesis-activation/registry-test-result.jsonl");
const TARGET_PACKAGE: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");
const SUCCESSOR_TEST_RESULT: &[u8] = include_bytes!(
    "../contracts/dynamic-memory/v2/successor-activation/registry-test-result.jsonl"
);
const CONNECTOR_ENTRY: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v2/evidence/connector-schema-v2-entry.jsonl");
const EVIDENCE_STATEMENT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v2/evidence/evidence-statement-v2.jsonl");
const RELATION_ATTESTATION: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v2/relation/declared-attestation-event.jsonl");
const REMEMBER_STATEMENT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v2/remember/remember-accepted-statement-v2.jsonl");

const GENESIS_TEST_RESULT_DIGEST: &str =
    "e91e08070250a722446195b76ee685a9697298b9fdce9809027f120c829b679d";
const GENESIS_RUNNER_ARTIFACT: &str =
    "c2e5b0653471d35e54600a8d3fbe5613aff4c04e911787c09a25e2b327d4bbbd";
const GENESIS_RUNNER_CONFIGURATION: &str =
    "1d12aabe349fd0013389f93bf1917b0de6bbd5d2bd7156c85faff0b97360686d";
const SUCCESSOR_TEST_RESULT_DIGEST: &str =
    "e6783b2a018957a5861fe4e0670f55613d1ace35e381a6a9f5190ea9d7fbff8d";
const SUCCESSOR_RUNNER_ARTIFACT: &str =
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SUCCESSOR_RUNNER_CONFIGURATION: &str =
    "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";

/// Exactly the relations ADR 0002 D2 adds to `fleet_runtime`, copied from
/// `deploy/cockroach/runtime-role-grants.sql`. The policy itself is a ceremony
/// with many preconditions, so the probe test replays only this grant list.
const RUNTIME_SELECT_INSERT: &[&str] = &[
    "public.memory_evidence_events",
    "public.memory_evidence_quarantine",
    "public.memory_content_objects",
];
const RUNTIME_SELECT_INSERT_UPDATE: &[&str] = &[
    "public.memory_evidence_shard_heads",
    "public.memory_relation_projection_v1",
    "public.memory_relation_projection_watermarks_v1",
];
const RUNTIME_SELECT_ONLY: &str = "public.memory_writer_authority_v1";

/// Each `#[tokio::test]` gets its own runtime, and a `PgPool` is bound to the
/// runtime that created it, so pools are never shared across tests. The schema
/// is shared, so migration is serialized and run exactly once per process.
static MIGRATED: Mutex<bool> = Mutex::const_new(false);

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

const fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 24,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(60),
    }
}

fn physical_scope(label: &str) -> FleetScope {
    FleetScope::new(
        Uuid::now_v7(),
        format!("evidence-{label}-{}", Uuid::now_v7()),
        "evidence-ledger-connected-test",
        None,
        PrivacyTier::T1Project,
    )
    .expect("connected-test scope must be valid")
}

async fn live_pool(database_url: &str) -> PgPool {
    let store = CockroachStore::connect(
        database_url,
        physical_scope("pool"),
        PoolConfig {
            max_connections: 10,
            ..PoolConfig::default()
        },
    )
    .await
    .expect("connected test must reach the disposable database");
    {
        let mut migrated = MIGRATED.lock().await;
        if !*migrated {
            store.migrate().await.expect("migration prefix must apply");
            *migrated = true;
        }
    }
    store.pool().clone()
}

async fn server_time(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(pool)
        .await
        .expect("database clock must be readable")
}

fn canonical_time(value: DateTime<Utc>) -> CanonicalTimestamp {
    CanonicalTimestamp::from_datetime(&value).expect("database clock must be canonical")
}

// ---------------------------------------------------------------------------
// Frozen contract fixtures and the bootstrap -> genesis -> successor ceremony.
// This mirrors tests/successor_activation_live.rs so every append below runs
// against a head that is the Stage-4 package at generation one.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ContractFixture {
    profile: ProfileReferenceV1,
    semantic_scope: AuthenticatedProjectScopeV1,
    genesis_package: SemanticallyClosedGenesisPackage,
    genesis_test_result: VerifiedRegistryTestResult,
    genesis_principal_binding: GenesisActivationPrincipalBinding,
    target: SemanticallyClosedStage4Package,
    connector: StructurallyResolvedConnectorSchemaV2,
}

fn fixture() -> ContractFixture {
    let profile = frozen_profile_reference_v1();
    let bootstrap_value: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
    let semantic_scope = bootstrap_value.statement.scope;
    let genesis_manifest =
        ManifestVerifiedRegistryPackage::decode(record(GENESIS_PACKAGE), &profile).unwrap();
    let genesis_package =
        SemanticallyClosedGenesisPackage::from_manifest_verified(genesis_manifest).unwrap();
    let genesis_runner_pin = RegistryTestRunnerPin::from_trusted_config(
        digest(GENESIS_RUNNER_ARTIFACT),
        digest(GENESIS_RUNNER_CONFIGURATION),
        RegistryTestResultDigest::from_digest(digest(GENESIS_TEST_RESULT_DIGEST)),
    );
    let genesis_test_result = verify_registry_test_result(
        record(GENESIS_TEST_RESULT),
        genesis_runner_pin,
        &profile,
        &genesis_package,
    )
    .unwrap();
    let target_manifest =
        ManifestVerifiedRegistryPackage::decode(record(TARGET_PACKAGE), &profile).unwrap();
    let target_successor =
        SemanticallyClosedSuccessorPackage::from_manifest_verified(target_manifest).unwrap();
    let target = SemanticallyClosedStage4Package::from_successor_package(target_successor).unwrap();
    let connector_entry: RegistryEntryV1 = decode_strict(record(CONNECTOR_ENTRY)).unwrap();
    let connector =
        StructurallyResolvedConnectorSchemaV2::from_registry_entry(&connector_entry).unwrap();
    ContractFixture {
        profile,
        semantic_scope,
        genesis_package,
        genesis_test_result,
        genesis_principal_binding: GenesisActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.operator").unwrap(),
            ContractId::new("principal.author").unwrap(),
        ),
        target,
        connector,
    }
}

fn signed_bootstrap(fixture: &ContractFixture, seed_byte: u8) -> VerifiedBootstrapReceipt {
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
    let receipt_digest = BootstrapReceiptDigest::from_digest(domain_separated_digest(
        DigestDomain::BootstrapReceipt,
        &canonical,
    ));
    verify_pinned_bootstrap(
        &canonical,
        BootstrapPin::from_trusted_config(receipt_digest),
        &fixture.profile,
        &fixture.semantic_scope,
        &fixture.genesis_package,
    )
    .unwrap()
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

fn genesis_approval(
    statement_id: ostk_fleet_recall::memory_contracts::genesis_activation::GenesisRegistryActivationStatementId,
    principal: &str,
    signer_seed: u8,
) -> GenesisRegistryActivationApprovalV1 {
    let mut message = b"ostk-registry-activation-approval-signature-v1\0".to_vec();
    message.extend_from_slice(statement_id.digest().as_bytes());
    let key = Ed25519KeyPair::from_seed_unchecked(&[signer_seed; 32]).unwrap();
    GenesisRegistryActivationApprovalV1 {
        schema_version: 1,
        statement_id,
        signer_principal_id: ContractId::new(principal).unwrap(),
        signature: FixedHex64::from_bytes(key.sign(&message).as_ref().try_into().unwrap()),
    }
}

fn successor_approval(
    statement_id: ostk_fleet_recall::memory_contracts::successor_activation::SuccessorRegistryActivationStatementId,
    principal: &str,
    seed: u8,
) -> SuccessorRegistryActivationApprovalV1 {
    let mut message = b"ostk-registry-successor-activation-approval-signature-v1\0".to_vec();
    message.extend_from_slice(statement_id.digest().as_bytes());
    let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    SuccessorRegistryActivationApprovalV1 {
        schema_version: 1,
        statement_id,
        signer_principal_id: ContractId::new(principal).unwrap(),
        signature: FixedHex64::from_bytes(pair.sign(&message).as_ref().try_into().unwrap()),
    }
}

/// One live scope whose registry head is the Stage-4 package at generation one.
struct Stage4Scope {
    pool: PgPool,
    physical_scope: FleetScope,
    trusted_scope: TrustedControlScope,
    bootstrap: VerifiedBootstrapReceipt,
    genesis_epoch: GenesisLogEpochV1,
    head: RegistryHeadBindingV1,
    repository: Arc<CockroachAcceptedEventRepository>,
    witness: WriterAuthorityWitness,
}

impl Stage4Scope {
    const fn epoch_id(&self) -> EpochId {
        self.witness.epoch_id()
    }
}

#[allow(clippy::too_many_lines)] // One linear ceremony; splitting it hides it.
async fn activate_stage4(
    pool: &PgPool,
    fixture: &ContractFixture,
    label: &str,
    seed: u8,
) -> Stage4Scope {
    let physical_scope = physical_scope(label);
    let bootstrap = signed_bootstrap(fixture, seed);
    let trusted_scope =
        TrustedControlScope::from_trusted_context(&physical_scope, fixture.semantic_scope.clone())
            .unwrap();

    CockroachGenesisRepository::new(pool.clone(), trusted_scope.clone(), retry_policy())
        .bootstrap_genesis(&bootstrap, &fixture.genesis_package)
        .await
        .unwrap();

    let genesis_effective = canonical_time(server_time(pool).await);
    let statement = GenesisRegistryActivationStatementV1 {
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
        package_author_principal_id: ContractId::new("principal.author").unwrap(),
    };
    let statement_id = statement.statement_id().unwrap();
    let mut approvals = vec![
        genesis_approval(statement_id, "principal.1", 1),
        genesis_approval(statement_id, "principal.2", 2),
    ];
    approvals.sort_unstable();
    let request = verify_genesis_registry_activation(
        &encode_canonical(&statement).unwrap(),
        &encode_canonical(&GenesisRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id,
            approvals,
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
        trusted_scope.clone(),
        retry_policy(),
        bootstrap.clone(),
        fixture.genesis_package.clone(),
        fixture.genesis_test_result.clone(),
        fixture.genesis_principal_binding.clone(),
    )
    .unwrap()
    .activate_genesis(&request)
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

    let signer = |principal: &str, seed: u8| {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        ActivationSignerBindingV2 {
            principal_id: ContractId::new(principal).unwrap(),
            algorithm: ActivationSignatureAlgorithmV2::Ed25519,
            public_key: FixedHex32::from_bytes(pair.public_key().as_ref().try_into().unwrap()),
        }
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
    let bridge_digest: GenesisSuccessorKeyBridgeDigest = bridge.bridge_digest().unwrap();
    let bridge_bytes = encode_canonical(&bridge).unwrap();

    tokio::time::sleep(Duration::from_millis(2)).await;
    let successor_effective = canonical_time(server_time(pool).await);
    let successor_runner_pin = SuccessorRegistryTestRunnerPin::from_trusted_config(
        digest(SUCCESSOR_RUNNER_ARTIFACT),
        digest(SUCCESSOR_RUNNER_CONFIGURATION),
        RegistryTestResultDigest::from_digest(digest(SUCCESSOR_TEST_RESULT_DIGEST)),
    );
    let successor_test_result = verify_successor_registry_test_result(
        record(SUCCESSOR_TEST_RESULT),
        successor_runner_pin,
        &fixture.target,
    )
    .unwrap();
    let successor_statement = SuccessorRegistryActivationStatementV1 {
        schema_version: 1,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        expected_predecessor_head: genesis_head,
        current_v1_activation_policy: current_v1_policy_reference(fixture),
        target_package_digest: fixture.target.package_digest(),
        target_activation_policy: fixture
            .target
            .activation_policy()
            .registry_reference()
            .clone(),
        test_vector_result_digest: successor_test_result.result_digest(),
        genesis_successor_key_bridge_digest: bridge_digest,
        from_generation: 0,
        to_generation: 1,
        effective_from: successor_effective.clone(),
        effective_until: None,
        proposer_principal_id: ContractId::new("principal.operator").unwrap(),
        package_author_principal_id: ContractId::new("principal.author").unwrap(),
    };
    let successor_statement_id = successor_statement.statement_id().unwrap();
    let candidate = SuccessorActivationCandidate::from_bounded_canonical_bytes(
        encode_canonical(&successor_statement).unwrap(),
        encode_canonical(&SuccessorRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id: successor_statement_id,
            approvals: vec![
                successor_approval(successor_statement_id, "principal.alice", 1),
                successor_approval(successor_statement_id, "principal.bob", 2),
            ],
        })
        .unwrap(),
    )
    .unwrap();
    let accepted = match CockroachSuccessorActivationRepository::new(
        pool.clone(),
        trusted_scope.clone(),
        retry_policy(),
        bootstrap.clone(),
        fixture.genesis_package.clone(),
        fixture.genesis_test_result.clone(),
        fixture.genesis_principal_binding.clone(),
        fixture.target.clone(),
        record(SUCCESSOR_TEST_RESULT),
        successor_runner_pin,
        bridge_bytes,
        GenesisSuccessorKeyBridgePin::from_trusted_config(bridge_digest),
        SuccessorActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.operator").unwrap(),
            ContractId::new("principal.author").unwrap(),
        ),
    )
    .unwrap()
    .activate_first_successor(&candidate)
    .await
    .unwrap()
    {
        SuccessorActivationOutcome::Inserted(accepted)
        | SuccessorActivationOutcome::ExactReplay(accepted) => accepted,
    };
    let head = accepted.registry_head;
    assert_eq!(head.effective_from, successor_effective);

    let repository = Arc::new(CockroachAcceptedEventRepository::new(
        pool.clone(),
        trusted_scope.clone(),
        retry_policy(),
    ));
    let witness = repository.read_writer_authority_witness().await.unwrap();
    assert_eq!(witness.generation(), 1, "the head must be generation one");
    assert_eq!(witness.head(), &head.head);
    assert_eq!(
        witness.head().package_digest,
        fixture.target.package_digest(),
        "the activated package must be the Stage-4 target"
    );

    Stage4Scope {
        genesis_epoch: bootstrap.receipt().statement.genesis_epoch.clone(),
        pool: pool.clone(),
        physical_scope,
        trusted_scope,
        bootstrap,
        head,
        repository,
        witness,
    }
}

// ---------------------------------------------------------------------------
// Accepted-event fixtures rebound to the live head.
// ---------------------------------------------------------------------------

fn evidence_statement(head: &RegistryHeadBindingV1) -> EvidenceStatementV2 {
    let mut statement: EvidenceStatementV2 = decode_strict(record(EVIDENCE_STATEMENT)).unwrap();
    statement.registry_head = head.clone();
    statement.representation.registry_head = head.clone();
    statement.representation_key = derive_representation_key_v2(&statement.representation).unwrap();
    statement.validate_shape().unwrap();
    statement
}

/// A distinct representation of the SAME source fact: the representation key
/// changes (so this is a new semantic object) while the consistency key, and
/// therefore the selected shard, stays put.
fn evidence_variant(head: &RegistryHeadBindingV1, marker: &str) -> EvidenceStatementV2 {
    let mut statement = evidence_statement(head);
    statement.representation.redaction_policy.entry_digest =
        domain_separated_digest(DigestDomain::RegistryEntry, marker.as_bytes());
    statement.representation_key = derive_representation_key_v2(&statement.representation).unwrap();
    statement.validate_shape().unwrap();
    statement
}

/// A different source fact, so a different consistency key and (usually) a
/// different shard.
fn evidence_other_source_fact(head: &RegistryHeadBindingV1, marker: &str) -> EvidenceStatementV2 {
    let mut statement = evidence_statement(head);
    statement.source_fact.logical_event_key = HexBytes::new(marker.as_bytes().to_vec()).unwrap();
    let source_fact_id = derive_source_fact_id_v2(&statement.source_fact).unwrap();
    statement.source_fact_id = source_fact_id;
    statement.representation.source_fact_id = source_fact_id;
    statement.representation_key = derive_representation_key_v2(&statement.representation).unwrap();
    statement.validate_shape().unwrap();
    statement
}

/// Same representation identity, different accepted bytes. EVENT-01 calls this
/// a preimage disagreement.
fn evidence_same_representation_other_bytes(
    head: &RegistryHeadBindingV1,
    occurred_at: &str,
) -> EvidenceStatementV2 {
    let mut statement = evidence_statement(head);
    statement.occurred_at = CanonicalTimestamp::parse(occurred_at).unwrap();
    statement.validate_shape().unwrap();
    statement
}

fn relation_attestation(head: &RegistryHeadBindingV1) -> RelationAttestationEventV1 {
    let mut event: RelationAttestationEventV1 =
        decode_strict(record(RELATION_ATTESTATION)).unwrap();
    event.edge.registry = head.clone();
    event.relation_fingerprint = event.edge.fingerprint().unwrap();
    event.validate_shape().unwrap();
    event
}

fn remember_statement(head: &RegistryHeadBindingV1) -> RememberAcceptedStatementV2 {
    let mut statement: RememberAcceptedStatementV2 =
        decode_strict(record(REMEMBER_STATEMENT)).unwrap();
    statement.registry = head.clone();
    statement.claim.registry = head.clone();
    statement.claim_fingerprint = statement.claim.fingerprint().unwrap();
    statement.validate_shape().unwrap();
    statement
}

fn delivery(attempt: u32) -> EvidenceDeliveryContextV1 {
    EvidenceDeliveryContextV1 {
        connector_principal_id: ContractId::new("connector.github").unwrap(),
        connector_instance_id: ContractId::new("connector.github.instance-1").unwrap(),
        transport_delivery_id: HexBytes::new(b"delivery-1".to_vec()).unwrap(),
        attempt_count: attempt,
    }
}

fn appendable_evidence(
    fixture: &ContractFixture,
    scope: &Stage4Scope,
    statement: &EvidenceStatementV2,
) -> AppendableAcceptedEvent {
    AppendableAcceptedEvent::evidence(statement, &fixture.connector, delivery(1), &scope.witness)
        .unwrap()
}

fn evidence_shard(
    fixture: &ContractFixture,
    scope: &Stage4Scope,
    statement: &EvidenceStatementV2,
) -> u16 {
    let key = statement
        .consistency_partition_key(&fixture.connector)
        .unwrap();
    scope.bootstrap.partition_for(&key).unwrap()
}

// ---------------------------------------------------------------------------
// Small SQL helpers (root only; never used by the least-privilege probe).
// ---------------------------------------------------------------------------

async fn scoped_count(pool: &PgPool, table: &str, scope: &FleetScope) -> i64 {
    let query = format!("SELECT count(*)::INT8 FROM {table} WHERE tenant_id = $1 AND project = $2");
    sqlx::query_scalar(&query)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn head_offset(pool: &PgPool, scope: &Stage4Scope, shard: u16) -> Option<i64> {
    sqlx::query_scalar(
        "SELECT last_committed_offset FROM memory_evidence_shard_heads \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .bind(scope.epoch_id().digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .fetch_optional(pool)
    .await
    .unwrap()
}

async fn authority_snapshot(scope: &Stage4Scope) -> WriterAuthoritySnapshot {
    let row = sqlx::query(
        "SELECT head_state, generation, activation_id, package_digest, activation_policy_digest, \
         log_epoch_id, partition_recipe_id, partition_recipe_version, partition_algorithm, \
         partition_seed, log_shard_count, contract_tenant_namespace, contract_project_namespace, \
         bootstrap_contract_tenant_namespace, bootstrap_contract_project_namespace \
         FROM memory_writer_authority_v1 WHERE tenant_id = $1 AND project = $2",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .fetch_one(&scope.pool)
    .await
    .unwrap();
    let fixed = |column: &str| -> Sha256Digest {
        Sha256Digest::from_bytes(row.get::<Vec<u8>, _>(column).try_into().unwrap())
    };
    let namespaces = |tenant: &str, project: &str| {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new(row.get::<String, _>(tenant)).unwrap(),
            ContractId::new(row.get::<String, _>(project)).unwrap(),
        )
    };
    WriterAuthoritySnapshot {
        head_state: row.get("head_state"),
        generation: u64::try_from(row.get::<i64, _>("generation")).unwrap(),
        activation_id: fixed("activation_id"),
        package_digest: fixed("package_digest"),
        activation_policy_digest: fixed("activation_policy_digest"),
        log_epoch_id: EpochId::from_digest(fixed("log_epoch_id")),
        partition_recipe_id: row.get("partition_recipe_id"),
        partition_recipe_version: u32::try_from(row.get::<i32, _>("partition_recipe_version"))
            .unwrap(),
        partition_algorithm: row.get("partition_algorithm"),
        partition_seed: FixedHex32::from_bytes(
            row.get::<Vec<u8>, _>("partition_seed").try_into().unwrap(),
        ),
        log_shard_count: u16::try_from(row.get::<i32, _>("log_shard_count")).unwrap(),
        head_scope: namespaces("contract_tenant_namespace", "contract_project_namespace"),
        bootstrap_scope: namespaces(
            "bootstrap_contract_tenant_namespace",
            "bootstrap_contract_project_namespace",
        ),
        genesis_epoch: scope.genesis_epoch.clone(),
    }
}

/// A projection that panics if it ever runs. Passing it to a replay proves the
/// replay branch never repeats the lifecycle effect the original append already
/// committed (EVENT-01, EVENT-03).
struct NeverRuns;

#[async_trait::async_trait]
impl AppendProjection for NeverRuns {
    async fn project(
        &self,
        _transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        _context: ProjectionContext,
    ) -> EvidenceAppendResult<()> {
        panic!("exact replay must not re-run the projection");
    }
}

/// Concurrent appends aimed at one shard.
const SAME_SHARD_APPENDS: usize = 8;

// ---------------------------------------------------------------------------
// Connected tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_single_append_and_shard_chain_audit_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "single", 41).await;

    let statement = evidence_statement(&scope.head);
    let shard = evidence_shard(&fixture, &scope, &statement);
    assert_eq!(head_offset(&pool, &scope, shard).await, None);

    let appendable = appendable_evidence(&fixture, &scope, &statement);
    let outcome = scope
        .repository
        .append(&scope.witness, &appendable, Arc::new(NoProjection))
        .await
        .unwrap();
    let AppendOutcome::Appended {
        position,
        chain_digest,
    } = outcome
    else {
        panic!("first append must be Appended, got {outcome:?}");
    };
    assert_eq!(position.epoch_id, scope.epoch_id());
    assert_eq!(position.shard, shard);
    assert_eq!(position.committed_offset.as_u64(), 1);
    assert_eq!(head_offset(&pool, &scope, shard).await, Some(1));

    let audit = scope
        .repository
        .audit_shard_chain(scope.epoch_id(), shard)
        .await
        .unwrap();
    assert!(audit.is_intact(), "fresh shard must audit clean: {audit:?}");
    assert_eq!(audit.verified_events, 1);
    assert_eq!(audit.head_offset, 1);
    assert_eq!(audit.head_chain_digest, chain_digest);
    assert_ne!(audit.genesis_chain_digest, chain_digest);

    // The evidence ledger holds exactly one row and the control ledger is
    // untouched by the append (D1: general kinds never enter it).
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        1
    );
    assert_eq!(
        scoped_count(&pool, "memory_control_events", &scope.physical_scope).await,
        3,
        "control ledger keeps only bootstrap plus the two activation events"
    );
}

#[tokio::test]
async fn live_all_three_stage4_kinds_append_and_audit_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "kinds", 42).await;

    let evidence = evidence_statement(&scope.head);
    let relation = relation_attestation(&scope.head);
    let remember = remember_statement(&scope.head);

    let appendables = vec![
        appendable_evidence(&fixture, &scope, &evidence),
        AppendableAcceptedEvent::relation_attestation(&relation, &scope.witness).unwrap(),
        AppendableAcceptedEvent::memory_claim(&remember, &scope.witness).unwrap(),
    ];
    let mut shards = Vec::new();
    for appendable in &appendables {
        let outcome = scope
            .repository
            .append(&scope.witness, appendable, Arc::new(NoProjection))
            .await
            .unwrap();
        let AppendOutcome::Appended { position, .. } = outcome else {
            panic!("each kind must append once, got {outcome:?}");
        };
        shards.push(position.shard);
    }
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        3
    );

    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT event_kind FROM memory_evidence_events \
         WHERE tenant_id = $1 AND project = $2 ORDER BY event_kind",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        kinds,
        vec![
            "evidence.accepted".to_owned(),
            "memory.claim.accepted".to_owned(),
            "relation.attestation.accepted".to_owned(),
        ]
    );
    let families: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT consistency_family FROM memory_evidence_events \
         WHERE tenant_id = $1 AND project = $2 ORDER BY consistency_family",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        families,
        vec![
            "claim".to_owned(),
            "relation".to_owned(),
            "source_fact".to_owned(),
        ],
        "each kind keeps the consistency family its own contract derives"
    );

    for shard in shards {
        let audit = scope
            .repository
            .audit_shard_chain(scope.epoch_id(), shard)
            .await
            .unwrap();
        assert!(
            audit.is_intact(),
            "shard {shard} must audit clean: {audit:?}"
        );
    }
}

#[tokio::test]
async fn live_exact_replay_is_a_no_op_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "replay", 43).await;

    let statement = evidence_statement(&scope.head);
    let shard = evidence_shard(&fixture, &scope, &statement);
    let appendable = appendable_evidence(&fixture, &scope, &statement);

    let AppendOutcome::Appended { position, .. } = scope
        .repository
        .append(&scope.witness, &appendable, Arc::new(NoProjection))
        .await
        .unwrap()
    else {
        panic!("first append must be Appended");
    };

    // A byte-identical rebuild, so this is a genuine at-least-once redelivery
    // rather than the same in-memory value.
    let redelivered = appendable_evidence(&fixture, &scope, &evidence_statement(&scope.head));
    assert_eq!(redelivered.canonical_event(), appendable.canonical_event());
    let replay = scope
        .repository
        .append(&scope.witness, &redelivered, Arc::new(NeverRuns))
        .await
        .unwrap();
    assert_eq!(replay, AppendOutcome::Replayed { position });

    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        1
    );
    assert_eq!(head_offset(&pool, &scope, shard).await, Some(1));
    assert!(
        scope
            .repository
            .audit_shard_chain(scope.epoch_id(), shard)
            .await
            .unwrap()
            .is_intact()
    );
}

#[tokio::test]
async fn live_integrity_collision_is_quarantined_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "collision", 44).await;

    let statement = evidence_statement(&scope.head);
    let shard = evidence_shard(&fixture, &scope, &statement);
    let appendable = appendable_evidence(&fixture, &scope, &statement);
    scope
        .repository
        .append(&scope.witness, &appendable, Arc::new(NoProjection))
        .await
        .unwrap();

    // An accepted-event ID is a digest of the very bytes stored beside it, so a
    // divergence under one ID can only be planted. Root does exactly that.
    let tampered = sqlx::query(
        "UPDATE memory_evidence_events SET canonical_event = $5 \
         WHERE tenant_id = $1 AND project = $2 AND event_id = $3 AND committed_offset = $4",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .bind(appendable.accepted_event_id().digest().as_bytes().to_vec())
    .bind(1_i64)
    .bind(encode_canonical(&evidence_variant(&scope.head, "collision-plant")).unwrap())
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(tampered.rows_affected(), 1);

    let outcome = scope
        .repository
        .append(&scope.witness, &appendable, Arc::new(NoProjection))
        .await
        .unwrap();
    let AppendOutcome::Quarantined {
        quarantine_id,
        reason,
    } = outcome
    else {
        panic!("a byte divergence under one event ID must quarantine, got {outcome:?}");
    };
    assert_eq!(
        reason,
        ostk_fleet_recall::memory_contracts::quarantine::QuarantineReasonV1::IntegrityCollision
    );

    assert_eq!(head_offset(&pool, &scope, shard).await, Some(1));
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        1
    );
    let stored: (String, Vec<u8>) = sqlx::query_as(
        "SELECT reason, canonical_payload_digest FROM memory_evidence_quarantine \
         WHERE tenant_id = $1 AND project = $2 AND quarantine_id = $3",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .bind(quarantine_id.digest().as_bytes().to_vec())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored.0, "integrity_collision");
    assert_eq!(stored.1.len(), 32);
    let has_payload_column: i64 = sqlx::query_scalar(
        "SELECT count(*)::INT8 FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'memory_evidence_quarantine' \
           AND column_name IN ('payload', 'canonical_payload', 'payload_bytes')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        has_payload_column, 0,
        "quarantine stores digests, not bytes"
    );
}

#[tokio::test]
async fn live_preimage_disagreement_is_quarantined_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "disagreement", 45).await;

    let first = evidence_statement(&scope.head);
    let shard = evidence_shard(&fixture, &scope, &first);
    let first_appendable = appendable_evidence(&fixture, &scope, &first);
    scope
        .repository
        .append(&scope.witness, &first_appendable, Arc::new(NoProjection))
        .await
        .unwrap();

    // Same source fact AND same representation identity, different accepted
    // bytes and therefore a different accepted-event ID: EVENT-01's literal
    // integrity condition.
    let second =
        evidence_same_representation_other_bytes(&scope.head, "2026-08-15T13:00:00.000000000Z");
    assert_eq!(second.representation_key, first.representation_key);
    assert_eq!(second.source_fact_id, first.source_fact_id);
    let second_appendable = appendable_evidence(&fixture, &scope, &second);
    assert_ne!(
        second_appendable.accepted_event_id(),
        first_appendable.accepted_event_id()
    );

    let outcome = scope
        .repository
        .append(&scope.witness, &second_appendable, Arc::new(NoProjection))
        .await
        .unwrap();
    let AppendOutcome::Quarantined {
        quarantine_id,
        reason,
    } = outcome
    else {
        panic!("a disagreeing preimage must quarantine, got {outcome:?}");
    };
    assert_eq!(
        reason,
        ostk_fleet_recall::memory_contracts::quarantine::QuarantineReasonV1::PreimageDisagreement
    );
    assert_eq!(head_offset(&pool, &scope, shard).await, Some(1));
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        1
    );
    let identity: (Option<Vec<u8>>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT source_fact_id, representation_key_digest FROM memory_evidence_quarantine \
         WHERE tenant_id = $1 AND project = $2 AND quarantine_id = $3",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .bind(quarantine_id.digest().as_bytes().to_vec())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        identity.0,
        Some(first.source_fact_id.digest().as_bytes().to_vec())
    );
    assert_eq!(
        identity.1,
        Some(first.representation_key.digest().as_bytes().to_vec())
    );

    // A DIFFERENT representation of the same source fact is a legitimate new
    // semantic object and still appends on the same shard.
    let superseding = evidence_variant(&scope.head, "disagreement-next");
    assert_eq!(
        evidence_shard(&fixture, &scope, &superseding),
        shard,
        "one source fact keeps one shard"
    );
    let outcome = scope
        .repository
        .append(
            &scope.witness,
            &appendable_evidence(&fixture, &scope, &superseding),
            Arc::new(NoProjection),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, AppendOutcome::Appended { .. }));
    assert_eq!(head_offset(&pool, &scope, shard).await, Some(2));
    assert!(
        scope
            .repository
            .audit_shard_chain(scope.epoch_id(), shard)
            .await
            .unwrap()
            .is_intact()
    );
}

#[tokio::test]
async fn live_concurrent_appends_to_one_shard_form_one_chain_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "concurrent", 46).await;

    let statements: Vec<EvidenceStatementV2> = (0..SAME_SHARD_APPENDS)
        .map(|index| evidence_variant(&scope.head, &format!("concurrent-{index}")))
        .collect();
    let shard = evidence_shard(&fixture, &scope, &statements[0]);
    for statement in &statements {
        assert_eq!(evidence_shard(&fixture, &scope, statement), shard);
    }

    let barrier = Arc::new(Barrier::new(SAME_SHARD_APPENDS));
    let handles = statements.iter().map(|statement| {
        let repository = Arc::clone(&scope.repository);
        let witness = scope.witness.clone();
        let appendable = appendable_evidence(&fixture, &scope, statement);
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            repository
                .append(&witness, &appendable, Arc::new(NoProjection))
                .await
        })
    });
    let mut offsets: Vec<u64> = join_all(handles)
        .await
        .into_iter()
        .map(|joined| match joined.unwrap().unwrap() {
            AppendOutcome::Appended { position, .. } => position.committed_offset.as_u64(),
            other => panic!("every concurrent append must succeed, got {other:?}"),
        })
        .collect();
    offsets.sort_unstable();
    assert_eq!(
        offsets,
        (1..=SAME_SHARD_APPENDS as u64).collect::<Vec<_>>(),
        "offsets must be exactly 1..=N with no gap and no reuse"
    );

    let audit = scope
        .repository
        .audit_shard_chain(scope.epoch_id(), shard)
        .await
        .unwrap();
    assert!(
        audit.is_intact(),
        "one chain must survive concurrency: {audit:?}"
    );
    assert_eq!(audit.verified_events, SAME_SHARD_APPENDS as u64);
    assert_eq!(audit.head_offset, SAME_SHARD_APPENDS as u64);
    assert_eq!(
        head_offset(&pool, &scope, shard).await,
        Some(i64::try_from(SAME_SHARD_APPENDS).unwrap())
    );
}

#[tokio::test]
async fn live_concurrent_appends_to_distinct_shards_keep_independent_heads_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "shards", 47).await;

    // Search the frozen source-fact space for two keys the activated recipe
    // sends to different shards; the recipe, not the test, decides.
    let mut chosen: Vec<(u16, EvidenceStatementV2)> = Vec::new();
    for index in 0..64_u32 {
        let statement = evidence_other_source_fact(&scope.head, &format!("shard-probe-{index}"));
        let shard = evidence_shard(&fixture, &scope, &statement);
        if !chosen.iter().any(|(taken, _)| *taken == shard) {
            chosen.push((shard, statement));
        }
        if chosen.len() == 2 {
            break;
        }
    }
    assert_eq!(chosen.len(), 2, "the recipe must reach at least two shards");

    let barrier = Arc::new(Barrier::new(chosen.len()));
    let handles = chosen.iter().map(|(_, statement)| {
        let repository = Arc::clone(&scope.repository);
        let witness = scope.witness.clone();
        let appendable = appendable_evidence(&fixture, &scope, statement);
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            repository
                .append(&witness, &appendable, Arc::new(NoProjection))
                .await
        })
    });
    for joined in join_all(handles).await {
        match joined.unwrap().unwrap() {
            AppendOutcome::Appended { position, .. } => {
                assert_eq!(position.committed_offset.as_u64(), 1);
            }
            other => panic!("each shard's first append must be offset one, got {other:?}"),
        }
    }

    for (shard, _) in &chosen {
        assert_eq!(head_offset(&pool, &scope, *shard).await, Some(1));
        let audit = scope
            .repository
            .audit_shard_chain(scope.epoch_id(), *shard)
            .await
            .unwrap();
        assert!(audit.is_intact());
        assert_eq!(audit.verified_events, 1);
    }
    assert_ne!(chosen[0].0, chosen[1].0);
    assert_eq!(
        scoped_count(&pool, "memory_evidence_shard_heads", &scope.physical_scope).await,
        2,
        "lazy seeding creates only the shards that were actually used"
    );
}

#[tokio::test]
async fn live_witness_mismatch_writes_nothing_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "witness", 48).await;

    let statement = evidence_statement(&scope.head);
    let appendable = appendable_evidence(&fixture, &scope, &statement);

    let mut snapshot = authority_snapshot(&scope).await;
    assert_eq!(snapshot.activation_id, scope.witness.head().activation_id);
    snapshot.activation_id = domain_separated_digest(DigestDomain::AcceptedEvent, b"not-the-head");
    let forged = WriterAuthorityWitness::from_authority_snapshot(snapshot).unwrap();

    let failure = scope
        .repository
        .append(&forged, &appendable, Arc::new(NoProjection))
        .await;
    assert!(
        matches!(
            failure,
            Err(EvidenceAppendError::WitnessMismatch(
                WitnessMismatchKind::ActivationId
            ))
        ),
        "a forged activation ID must fail closed, got {failure:?}"
    );

    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        0
    );
    assert_eq!(
        scoped_count(&pool, "memory_evidence_shard_heads", &scope.physical_scope).await,
        0,
        "the fence runs before the lazy head seed"
    );
    assert_eq!(
        scoped_count(&pool, "memory_evidence_quarantine", &scope.physical_scope).await,
        0
    );

    // A statement bound to a head the witness does not claim is refused before
    // any transaction opens at all.
    let stale_head = RegistryHeadBindingV1 {
        head: ostk_fleet_recall::memory_contracts::registry::RegistryHeadV1 {
            activation_id: domain_separated_digest(DigestDomain::AcceptedEvent, b"stale"),
            ..scope.head.head.clone()
        },
        effective_from: scope.head.effective_from.clone(),
        effective_until: None,
    };
    let stale = evidence_statement(&stale_head);
    assert!(matches!(
        AppendableAcceptedEvent::evidence(&stale, &fixture.connector, delivery(1), &scope.witness),
        Err(EvidenceAppendError::StatementAuthority(
            WitnessMismatchKind::ActivationId
        ))
    ));
}

#[tokio::test]
async fn live_chain_tamper_is_reported_by_the_audit_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "tamper", 49).await;

    let mut shard = 0;
    for index in 0..3_u32 {
        let statement = evidence_variant(&scope.head, &format!("tamper-{index}"));
        shard = evidence_shard(&fixture, &scope, &statement);
        scope
            .repository
            .append(
                &scope.witness,
                &appendable_evidence(&fixture, &scope, &statement),
                Arc::new(NoProjection),
            )
            .await
            .unwrap();
    }
    assert!(
        scope
            .repository
            .audit_shard_chain(scope.epoch_id(), shard)
            .await
            .unwrap()
            .is_intact()
    );

    let tampered = sqlx::query(
        "UPDATE memory_evidence_events SET chain_digest = $5 \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
           AND committed_offset = 2",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .bind(scope.epoch_id().digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .bind(
        domain_separated_digest(DigestDomain::AppendChain, b"tampered")
            .as_bytes()
            .to_vec(),
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(tampered.rows_affected(), 1);

    let audit = scope
        .repository
        .audit_shard_chain(scope.epoch_id(), shard)
        .await
        .unwrap();
    assert!(!audit.is_intact());
    let divergence = audit.divergence.unwrap();
    assert_eq!(divergence.committed_offset, 2);
    assert_eq!(
        divergence.kind,
        ShardChainDivergenceKind::ChainDigestMismatch
    );
    assert_eq!(
        audit.verified_events, 1,
        "the audit stops at the first fault"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Role creation, grants, proof, and teardown.
async fn live_least_privilege_probe_role_appends_without_control_grants_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "probe", 50).await;

    let role = format!("evidence_probe_{}", Uuid::now_v7().simple());
    let password = format!("probe-{}", Uuid::now_v7().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} WITH LOGIN PASSWORD '{password}'"
    ))
    .execute(&pool)
    .await
    .unwrap();

    let probe_result =
        run_probe_role(&database_url, &pool, &fixture, &scope, &role, &password).await;

    // CockroachDB refuses to drop a role that still holds a grant, so the
    // teardown mirrors the grant list exactly.
    for statement in [
        format!(
            "REVOKE ALL ON TABLE {}, {}, {RUNTIME_SELECT_ONLY} FROM {role}",
            RUNTIME_SELECT_INSERT.join(", "),
            RUNTIME_SELECT_INSERT_UPDATE.join(", ")
        ),
        format!("REVOKE ALL ON SCHEMA public FROM {role}"),
        format!("REVOKE ALL ON DATABASE fleet_recall FROM {role}"),
        format!("DROP ROLE IF EXISTS {role}"),
    ] {
        sqlx::query(&statement).execute(&pool).await.unwrap();
    }
    probe_result.unwrap();
}

#[allow(clippy::too_many_lines)] // Role grants, the append proof, and the denial proof.
async fn run_probe_role(
    database_url: &str,
    pool: &PgPool,
    fixture: &ContractFixture,
    scope: &Stage4Scope,
    role: &str,
    password: &str,
) -> Result<(), String> {
    // Exactly the ADR 0002 D2 grant list, copied from
    // deploy/cockroach/runtime-role-grants.sql. Nothing on any
    // memory_control_* or memory_registry_* base table.
    for statement in [
        format!("GRANT CONNECT ON DATABASE fleet_recall TO {role}"),
        format!("GRANT USAGE ON SCHEMA public TO {role}"),
        format!(
            "GRANT SELECT, INSERT ON TABLE {} TO {role}",
            RUNTIME_SELECT_INSERT.join(", ")
        ),
        format!(
            "GRANT SELECT, INSERT, UPDATE ON TABLE {} TO {role}",
            RUNTIME_SELECT_INSERT_UPDATE.join(", ")
        ),
        format!("GRANT SELECT ON TABLE {RUNTIME_SELECT_ONLY} TO {role}"),
    ] {
        sqlx::query(&statement)
            .execute(pool)
            .await
            .map_err(|error| format!("grant failed: {statement}: {error}"))?;
    }

    let probe_url = probe_database_url(database_url, role, password)?;
    let probe_pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&probe_url)
        .await
        .map_err(|error| format!("probe role could not connect: {error}"))?;

    let effective_role: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&probe_pool)
        .await
        .map_err(|error| format!("probe role identity read failed: {error}"))?;
    if effective_role != role {
        return Err(format!("probe connected as {effective_role}, not {role}"));
    }

    // The whole append path runs under those grants alone.
    let probe_repository = CockroachAcceptedEventRepository::new(
        probe_pool.clone(),
        scope.trusted_scope.clone(),
        retry_policy(),
    );
    let witness = probe_repository
        .read_writer_authority_witness()
        .await
        .map_err(|error| format!("probe could not read the authority view: {error}"))?;
    if witness.head() != scope.witness.head() {
        return Err("probe read a different head than root did".into());
    }
    let statement = evidence_statement(&scope.head);
    let appendable =
        AppendableAcceptedEvent::evidence(&statement, &fixture.connector, delivery(1), &witness)
            .map_err(|error| format!("probe could not admit the statement: {error}"))?;
    let outcome = probe_repository
        .append(&witness, &appendable, Arc::new(NoProjection))
        .await
        .map_err(|error| format!("probe append failed: {error}"))?;
    let AppendOutcome::Appended { position, .. } = outcome else {
        return Err(format!("probe append was not Appended: {outcome:?}"));
    };
    if position.committed_offset.as_u64() != 1 {
        return Err("probe append did not take offset one".into());
    }
    let audit = probe_repository
        .audit_shard_chain(scope.epoch_id(), position.shard)
        .await
        .map_err(|error| format!("probe audit failed: {error}"))?;
    if !audit.is_intact() {
        return Err(format!("probe audit found a divergence: {audit:?}"));
    }

    // And the governance ledger stays unreachable to it.
    for relation in [
        "memory_control_events",
        "memory_control_shard_heads",
        "memory_control_log_epochs",
        "memory_control_bootstraps",
        "memory_registry_current_heads_v2",
        "memory_registry_transitions",
    ] {
        let denied = sqlx::query(&format!("SELECT count(*) FROM public.{relation}"))
            .fetch_optional(&probe_pool)
            .await;
        let Err(sqlx::Error::Database(database)) = denied else {
            return Err(format!(
                "probe role unexpectedly read the governance relation {relation}"
            ));
        };
        if database.code().as_deref() != Some("42501") {
            return Err(format!(
                "probe read of {relation} failed with {:?}, not 42501",
                database.code()
            ));
        }
    }
    let denied_insert = sqlx::query(
        "INSERT INTO public.memory_control_events (tenant_id, project, epoch_id, shard, \
         committed_offset, event_id, event_schema_version, event_kind, semantic_object_digest, \
         consistency_family, consistency_key_digest, canonical_event, previous_chain_digest, \
         chain_digest, accepted_at) VALUES ($1, $2, $3, 0, 1, $3, 1, 'control.bootstrap.accepted', \
         $3, 'control.bootstrap', $3, $4, $3, $3, statement_timestamp())",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .bind(vec![0_u8; 32])
    .bind(vec![1_u8; 4])
    .execute(&probe_pool)
    .await;
    let Err(sqlx::Error::Database(database)) = denied_insert else {
        return Err("probe role unexpectedly inserted into the control ledger".into());
    };
    if database.code().as_deref() != Some("42501") {
        return Err(format!(
            "probe control insert failed with {:?}, not 42501",
            database.code()
        ));
    }

    probe_pool.close().await;
    Ok(())
}

/// Rewrite the disposable root URL into one the password-authenticated probe
/// role can use: same host, port, database, and CA, but no client certificate.
fn probe_database_url(database_url: &str, role: &str, password: &str) -> Result<String, String> {
    let mut url =
        url::Url::parse(database_url).map_err(|error| format!("test URL is not a URL: {error}"))?;
    let preserved: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key == "sslmode" || key == "sslrootcert")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.set_username(role)
        .map_err(|()| "test URL cannot carry a username".to_owned())?;
    url.set_password(Some(password))
        .map_err(|()| "test URL cannot carry a password".to_owned())?;
    url.query_pairs_mut().clear().extend_pairs(preserved);
    Ok(url.to_string())
}

#[test]
fn the_probe_grant_list_matches_the_runtime_policy() {
    let policy = include_str!("../deploy/cockroach/runtime-role-grants.sql");
    for relation in RUNTIME_SELECT_INSERT
        .iter()
        .chain(RUNTIME_SELECT_INSERT_UPDATE.iter())
        .chain(std::iter::once(&RUNTIME_SELECT_ONLY))
    {
        assert!(
            policy.contains(relation),
            "the probe grants a relation the runtime policy does not: {relation}"
        );
    }
    assert!(policy.contains("GRANT SELECT, INSERT ON TABLE"));
    assert!(policy.contains("GRANT SELECT, INSERT, UPDATE ON TABLE"));
    assert!(policy.contains("GRANT SELECT ON TABLE public.memory_writer_authority_v1"));
}

#[test]
fn fleet_error_conversion_keeps_storage_failures_distinguishable() {
    let storage = EvidenceAppendError::Storage(FleetError::Configuration("boom".into()));
    assert!(matches!(
        FleetError::from(storage),
        FleetError::Configuration(_)
    ));
    let closed = EvidenceAppendError::WitnessMismatch(WitnessMismatchKind::Generation);
    assert!(matches!(FleetError::from(closed), FleetError::Memory(_)));
}
