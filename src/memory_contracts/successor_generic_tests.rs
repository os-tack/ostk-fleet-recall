use std::{env, fs, path::Path};

use ring::signature::Ed25519KeyPair;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::memory_contracts::{
    common::frozen_profile_reference_v1,
    registry::{RegistryEntryV1, RegistryManifestEntryV1, RegistryPackageV1},
};

// Frozen inputs owned by earlier workstreams. They are read, never written.
const GENERATION_ONE_PACKAGE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");
const GENERATION_ONE_HEAD_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/successor-activation/activated-head.jsonl");
const ACTIVATION_POLICY_ENTRY_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/successor-policy/activation-policy-v2.jsonl");

const GENERATION_TWO_PACKAGE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/successor-generic/generation-2-package.jsonl"
);
const ACTIVATION_TEST_RESULT_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/successor-generic/activation-test-result.jsonl"
);
const ACTIVATION_STATEMENT_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/successor-generic/activation-statement.jsonl"
);
const ACTIVATION_APPROVAL_SET_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/successor-generic/activation-approval-set.jsonl"
);
const ACTIVATION_RECEIPT_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/successor-generic/activation-receipt.jsonl");
const ACTIVATED_HEAD_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/successor-generic/activated-head.jsonl");
const ACTIVATION_EVENT_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/successor-generic/activation-event.jsonl");
const ROLLBACK_TEST_RESULT_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/successor-generic/rollback-test-result.jsonl"
);
const ROLLBACK_STATEMENT_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/successor-generic/rollback-statement.jsonl");
const ROLLBACK_APPROVAL_SET_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/successor-generic/rollback-approval-set.jsonl"
);
const ROLLBACK_RECEIPT_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/successor-generic/rollback-receipt.jsonl");
const ROLLBACK_HEAD_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/successor-generic/rollback-activated-head.jsonl"
);
const ROLLBACK_EVENT_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/successor-generic/rollback-event.jsonl");
const RIVAL_STATEMENT_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/successor-generic/contested-rival-statement.jsonl"
);
const RIVAL_APPROVAL_SET_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/successor-generic/contested-rival-approval-set.jsonl"
);
const RIVAL_RECEIPT_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/successor-generic/contested-rival-receipt.jsonl"
);
const CONTESTED_SET_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/successor-generic/contested-set.jsonl");
const RESOLUTION_STATEMENT_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/successor-generic/contested-resolution-statement.jsonl"
);
const RESOLUTION_APPROVAL_SET_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/successor-generic/contested-resolution-approval-set.jsonl"
);
const RESOLUTION_RECEIPT_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/successor-generic/contested-resolution-receipt.jsonl"
);
const POSITIVE_VECTORS_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/successor-generic/positive-vectors.jsonl");
const NEGATIVE_VECTORS_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/successor-generic/negative-vectors.jsonl");
const VECTOR_SUITE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/successor-generic/vector-suite.jsonl");

/// The one-shot generation `0 -> 1` approval prefix. Approvals produced with
/// it must never verify here: generic transitions use no key bridge.
const BRIDGE_APPROVAL_SIGNATURE_PREFIX: &[u8] =
    b"ostk-registry-successor-activation-approval-signature-v1\0";

const SUITE_ID: &str = "registry.successor-generic.v2";
const FIXTURE_AUTHORITY: &str =
    "none; public fixture seeds and structural bytes never authorize a registry transition";

const RUNNER_ARTIFACT_DIGEST: &str =
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const RUNNER_CONFIGURATION_DIGEST: &str =
    "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";

const GENERATION_ONE_PACKAGE_DIGEST: &str =
    "16f98d5df93b74dab5b2188274cbd1da21d089ff7a64cd8fc29679946e7fe2c9";
const GENERATION_ONE_ACTIVATION_ID: &str =
    "60fe4eb627dab5e7798a22188218c308063de7eca121ea7f4b267f9ab23db4bb";
const ACTIVATION_POLICY_ENTRY_DIGEST: &str =
    "5611a4fea75d0a8132395bf6e3040ce97638a3447e290f5cabc183c1bb9faa6c";

const PREDECESSOR_ACCEPTED_AT: &str = "2026-08-15T04:10:00.000000000Z";
const GENERATION_TWO_TEST_COMPLETED_AT: &str = "2026-08-16T04:00:00.000000000Z";
const GENERATION_TWO_EFFECTIVE_FROM: &str = "2026-08-16T04:10:00.000000000Z";
const GENERATION_THREE_TEST_COMPLETED_AT: &str = "2026-08-17T04:00:00.000000000Z";
const GENERATION_THREE_EFFECTIVE_FROM: &str = "2026-08-17T04:10:00.000000000Z";
const RESOLUTION_EFFECTIVE_FROM: &str = "2026-08-18T04:10:00.000000000Z";

const GENERATION_TWO_PACKAGE_DIGEST: &str =
    "49fb2c6db81008b5ed8acd781e297e7d0a3ed49f6b1ff639618cd7d83296190a";
const GENERATION_TWO_STATEMENT_ID: &str =
    "64fd15dc659c800496ca3fa598b06a51d605b08788870f7acc1f35380f557bf6";
const GENERATION_TWO_ACTIVATION_ID: &str =
    "0fc0b1e4214c2c9e11f3ee63af05ea46de93e39a02aadd115cecaf4247ac7b31";
const GENERATION_TWO_ACCEPTED_EVENT_ID: &str =
    "2ddccbc871e8b4dd89c503d06fc8341254d6a4a6ec5957bf639ee20262b85597";
const ROLLBACK_STATEMENT_ID: &str =
    "c900386b859932a89cb9a221f8675baa46d9b19e37754b12328a1fbc58f96b84";
const ROLLBACK_ACTIVATION_ID: &str =
    "ac335f07967e0bb8861274984731b835caac5aebb5aca45b56bb05f769f4bcab";
const ROLLBACK_ACCEPTED_EVENT_ID: &str =
    "cf0352dc993c96ca710e49d521fc51805df532fbdf00ae1988e763b1ac68fb4f";
const RIVAL_STATEMENT_ID: &str = "4c82bb9903393f82c3c9f13e9ede86db576856e8aceac02a1f5d6492a8d949e1";
const RIVAL_ACTIVATION_ID: &str =
    "a0468c76b84897e6783ca0e0f2c7ef1edc36a8ee00a5cf4e8ee6144ed7fc0118";
const CONTESTED_SET_ID: &str = "6c5bff5cdc424d44400dfb8f50ec18cf4376605ed47a99893ebe661030c52b82";
const RESOLUTION_STATEMENT_ID: &str =
    "97665d1abeb5c33e517d2be2cc4e5ca3d54d39f9700dcc0e80adeb7a268b1410";
const RESOLUTION_ID: &str = "0f42d0373321e061ba3dfb286bc391fbc6fb66726a0afd7fc44fe93b80f01187";
const CONSISTENCY_KEY_DIGEST: &str =
    "9921b7e572be77d3e100eb3d3093fb0d8ff4b3b5965f75110c18bfd34479b5ec";
const POSITIVE_CASES_DIGEST: &str =
    "77e02c9c9565ac6b25c1dc1084a58ae1e8c8b07b62180a8d23bafa9310d8eedb";
const NEGATIVE_CASES_DIGEST: &str =
    "04b82a8819842356925ca00ff032bb86ffecf9708207058ced8fb48fd1a45614";
const VECTOR_SUITE_RAW_SHA256: &str =
    "52de3abd84b961c6c654bfe6d06d39b967533f747420c716a1337a45c1c886f7";
const VECTOR_SUITE_DIGEST: &str =
    "101342044d9080270267c58b7790dc264d8f67d6d8e2d144d03e3afcbbc88519";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CaseOutcomeV1 {
    Accept,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseManifestV1 {
    schema_version: u32,
    suite_id: ContractId,
    expected_outcome: CaseOutcomeV1,
    cases: Vec<ContractId>,
}

impl CaseManifestV1 {
    fn validate(&self, expected_outcome: CaseOutcomeV1) {
        assert_eq!(self.schema_version, SUCCESSOR_GENERIC_SCHEMA_VERSION);
        assert_eq!(self.suite_id.as_str(), SUITE_ID);
        assert_eq!(self.expected_outcome, expected_outcome);
        assert!(!self.cases.is_empty());
        assert!(strictly_sorted(&self.cases));
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactPinV1 {
    path: String,
    raw_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorSuiteV1 {
    schema_version: u32,
    suite_id: ContractId,
    fixture_authority: String,
    predecessor_head: RegistryHeadBindingV1,
    current_activation_policy: RegistryReferenceV1,
    generation_two_package_digest: Sha256Digest,
    generation_two_statement_id: GenericSuccessorActivationStatementId,
    generation_two_approval_ids: Vec<GenericSuccessorActivationApprovalId>,
    generation_two_activation_id: GenericSuccessorActivationId,
    generation_two_accepted_event_id: AcceptedEventId,
    generation_two_head: RegistryHeadBindingV1,
    rollback_target_package_digest: Sha256Digest,
    rollback_statement_id: GenericSuccessorActivationStatementId,
    rollback_activation_id: GenericSuccessorActivationId,
    rollback_accepted_event_id: AcceptedEventId,
    rollback_head: RegistryHeadBindingV1,
    rival_statement_id: GenericSuccessorActivationStatementId,
    rival_activation_id: GenericSuccessorActivationId,
    contested_set_id: RegistryContestedSetId,
    contested_activation_ids: Vec<GenericSuccessorActivationId>,
    resolution_statement_id: ContestedSetResolutionStatementId,
    resolution_id: ContestedSetResolutionId,
    consistency_key_family: ContractId,
    consistency_key_digest: Sha256Digest,
    positive_cases_digest: Sha256Digest,
    negative_cases_digest: Sha256Digest,
    external_artifact_pins: Vec<ArtifactPinV1>,
    artifact_pins: Vec<ArtifactPinV1>,
}

fn expected_digest(value: &str) -> Sha256Digest {
    value.parse().unwrap()
}

fn timestamp(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).unwrap()
}

fn case_id(value: &str) -> ContractId {
    ContractId::new(value).unwrap()
}

/// Assert-friendly rejection: the verified typestates are deliberately not
/// comparable, so a negative case compares the exact error instead.
fn rejection<T: fmt::Debug>(result: ContractResult<T>) -> ContractError {
    result.expect_err("the contract must reject this input")
}

fn record(artifact: &'static [u8]) -> &'static [u8] {
    let record = artifact
        .strip_suffix(b"\n")
        .expect("fixture must have exactly one repository-framing LF");
    assert!(!record.ends_with(b"\n"));
    assert!(!record.contains(&b'\r'));
    record
}

fn framed_record(canonical: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(canonical.len() + 1);
    framed.extend_from_slice(canonical);
    framed.push(b'\n');
    framed
}

fn raw_sha256(bytes: &[u8]) -> Sha256Digest {
    let mut hash = Sha256::new();
    hash.update(bytes);
    Sha256Digest::from_bytes(hash.finalize().into())
}

fn manifest_digest(manifest: &CaseManifestV1) -> Sha256Digest {
    domain_separated_digest(
        DigestDomain::TestVectorManifest,
        &encode_canonical(manifest).unwrap(),
    )
}

fn scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        case_id("tenant.fixture"),
        case_id("project.fixture"),
    )
}

fn generation_one_package() -> ManifestVerifiedRegistryPackage {
    ManifestVerifiedRegistryPackage::decode(
        record(GENERATION_ONE_PACKAGE_FIXTURE),
        &frozen_profile_reference_v1(),
    )
    .unwrap()
}

fn generation_one_target() -> StructurallyClosedSuccessorTargetV2 {
    StructurallyClosedSuccessorTargetV2::from_manifest_verified(&generation_one_package()).unwrap()
}

fn generation_one_head() -> RegistryHeadBindingV1 {
    let head: RegistryHeadBindingV1 = decode_strict(record(GENERATION_ONE_HEAD_FIXTURE)).unwrap();
    head.validate_shape().unwrap();
    head
}

/// A minimal but real generation-2 package: one activation-policy v2 entry
/// whose suite roots are that entry's own frozen vector roots.
fn generation_two_package() -> ManifestVerifiedRegistryPackage {
    let entry: RegistryEntryV1 = decode_strict(record(ACTIVATION_POLICY_ENTRY_FIXTURE)).unwrap();
    let package = RegistryPackageV1 {
        schema_version: 1,
        profile: frozen_profile_reference_v1(),
        manifest: vec![RegistryManifestEntryV1 {
            kind: entry.kind,
            entry_id: entry.entry_id.clone(),
            version: entry.version,
            entry_digest: entry.digest().unwrap(),
        }],
        positive_vector_suite_digest: entry.positive_vector_digest,
        negative_vector_suite_digest: entry.negative_vector_digest,
        entries: vec![entry],
    };
    ManifestVerifiedRegistryPackage::new(package, &frozen_profile_reference_v1()).unwrap()
}

fn generation_two_target() -> StructurallyClosedSuccessorTargetV2 {
    StructurallyClosedSuccessorTargetV2::from_manifest_verified(&generation_two_package()).unwrap()
}

fn installed_policy(
    generation: u32,
    head: &RegistryHeadBindingV1,
    installed_package: &StructurallyClosedSuccessorTargetV2,
) -> InstalledSuccessorPolicyV2 {
    InstalledSuccessorPolicyV2::from_durable_audit(
        frozen_profile_reference_v1(),
        scope(),
        generation,
        head.clone(),
        installed_package,
    )
    .unwrap()
}

fn conformance_result(
    target: &StructurallyClosedSuccessorTargetV2,
    completed_at: &str,
) -> VerifiedGenericSuccessorTestResult {
    let result = RegistryTestResultV1 {
        schema_version: REGISTRY_TEST_RESULT_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        package_digest: target.package_digest(),
        positive_vector_suite_digest: target.positive_vector_suite_digest,
        negative_vector_suite_digest: target.negative_vector_suite_digest,
        executed_vector_manifest_digest: frozen_profile_reference_v1().vector_manifest_digest,
        runner_artifact_digest: expected_digest(RUNNER_ARTIFACT_DIGEST),
        runner_configuration_digest: expected_digest(RUNNER_CONFIGURATION_DIGEST),
        passed_case_count: target.entry_count(),
        failed_case_count: 0,
        outcome: RegistryTestOutcomeV1::Passed,
        completed_at: timestamp(completed_at),
    };
    let bytes = encode_canonical(&result).unwrap();
    let pin = GenericSuccessorTestRunnerPin::from_trusted_config(
        result.runner_artifact_digest,
        result.runner_configuration_digest,
        generic_test_result_digest(&result).unwrap(),
    );
    verify_generic_successor_test_result(&bytes, pin, target).unwrap()
}

struct StatementSpec<'a> {
    predecessor_head: &'a RegistryHeadBindingV1,
    current_policy: &'a RegistryReferenceV1,
    target: &'a StructurallyClosedSuccessorTargetV2,
    test_result: &'a VerifiedGenericSuccessorTestResult,
    from_generation: u32,
    effective_from: &'a str,
    proposer: &'a str,
    author: &'a str,
}

fn statement(spec: &StatementSpec<'_>) -> GenericSuccessorActivationStatementV2 {
    GenericSuccessorActivationStatementV2 {
        schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        expected_predecessor_head: spec.predecessor_head.clone(),
        current_activation_policy: spec.current_policy.clone(),
        target_package_digest: spec.target.package_digest(),
        target_activation_policy: spec.target.activation_policy().registry_reference().clone(),
        test_vector_result_digest: spec.test_result.result_digest(),
        from_generation: spec.from_generation,
        to_generation: spec.from_generation + 1,
        effective_from: timestamp(spec.effective_from),
        effective_until: None,
        proposer_principal_id: case_id(spec.proposer),
        package_author_principal_id: case_id(spec.author),
    }
}

fn detached_signature(prefix: &[u8], statement_id: Sha256Digest, seed: [u8; 32]) -> FixedHex64 {
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let signature = key_pair.sign(&approval_signature_message(prefix, statement_id));
    FixedHex64::from_bytes(signature.as_ref().try_into().unwrap())
}

fn activation_approval(
    statement_id: GenericSuccessorActivationStatementId,
    principal: &str,
    seed: [u8; 32],
) -> GenericSuccessorActivationApprovalV2 {
    GenericSuccessorActivationApprovalV2 {
        schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
        statement_id,
        signer_principal_id: case_id(principal),
        signature: detached_signature(
            GENERIC_APPROVAL_SIGNATURE_PREFIX,
            statement_id.digest(),
            seed,
        ),
    }
}

fn approval_set_of(
    statement: &GenericSuccessorActivationStatementV2,
    approvals: Vec<GenericSuccessorActivationApprovalV2>,
) -> GenericSuccessorActivationApprovalSetV2 {
    GenericSuccessorActivationApprovalSetV2 {
        schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
        statement_id: statement.statement_id().unwrap(),
        approvals,
    }
}

fn quorum_approval_set(
    statement: &GenericSuccessorActivationStatementV2,
) -> GenericSuccessorActivationApprovalSetV2 {
    let statement_id = statement.statement_id().unwrap();
    approval_set_of(
        statement,
        vec![
            activation_approval(statement_id, "principal.alice", [1; 32]),
            activation_approval(statement_id, "principal.bob", [2; 32]),
        ],
    )
}

fn verify_activation(
    statement: &GenericSuccessorActivationStatementV2,
    approval_set: &GenericSuccessorActivationApprovalSetV2,
    installed: &InstalledSuccessorPolicyV2,
    target: &StructurallyClosedSuccessorTargetV2,
    test_result: &VerifiedGenericSuccessorTestResult,
) -> ContractResult<VerifiedGenericSuccessorActivation> {
    verify_generic_successor_activation(
        &encode_canonical(statement)?,
        &encode_canonical(approval_set)?,
        installed,
        target,
        test_result,
        &GenericSuccessorPrincipalBinding::from_trusted_config(
            statement.proposer_principal_id.clone(),
            statement.package_author_principal_id.clone(),
        ),
    )
}

struct ActivationArtifacts {
    /// The policy that authorized this activation - the same one a
    /// contender audit must present.
    installed: InstalledSuccessorPolicyV2,
    target: StructurallyClosedSuccessorTargetV2,
    test_result: VerifiedGenericSuccessorTestResult,
    activation: VerifiedGenericSuccessorActivation,
    receipt: GenericSuccessorActivationReceiptV2,
    head: RegistryHeadBindingV1,
    event: GenericSuccessorActivatedEventV2,
}

struct ArtifactSpec<'a> {
    activation: VerifiedGenericSuccessorActivation,
    installed: &'a InstalledSuccessorPolicyV2,
    target: &'a StructurallyClosedSuccessorTargetV2,
    test_result: &'a VerifiedGenericSuccessorTestResult,
    predecessor_accepted_at: &'a str,
    accepted_at: &'a str,
}

fn activation_artifacts(spec: ArtifactSpec<'_>) -> ActivationArtifacts {
    let activation = spec.activation;
    let receipt = activation
        .receipt_at(
            spec.installed,
            &timestamp(spec.predecessor_accepted_at),
            timestamp(spec.accepted_at),
        )
        .unwrap();
    let head = activation.resulting_registry_head(&receipt).unwrap();
    let event = GenericSuccessorActivatedEventV2::from_verified(&activation, &receipt).unwrap();
    ActivationArtifacts {
        installed: spec.installed.clone(),
        target: spec.target.clone(),
        test_result: spec.test_result.clone(),
        activation,
        receipt,
        head,
        event,
    }
}

/// The generation `1 -> 2 -> 3` chain plus its contested branch.
struct SuccessorChain {
    generation_two: ActivationArtifacts,
    rollback: ActivationArtifacts,
    rival: ActivationArtifacts,
    contested_set: AuditedContestedSetV1,
    resolution: VerifiedContestedSetResolution,
    resolution_receipt: ContestedSetResolutionReceiptV1,
}

fn successor_of_generation_one(proposer: &str, author: &str) -> ActivationArtifacts {
    let head = generation_one_head();
    let predecessor = generation_one_target();
    let installed = installed_policy(1, &head, &predecessor);
    let target = generation_two_target();
    let test_result = conformance_result(&target, GENERATION_TWO_TEST_COMPLETED_AT);
    let statement = statement(&StatementSpec {
        predecessor_head: &head,
        current_policy: installed.policy_reference(),
        target: &target,
        test_result: &test_result,
        from_generation: 1,
        effective_from: GENERATION_TWO_EFFECTIVE_FROM,
        proposer,
        author,
    });
    let approval_set = quorum_approval_set(&statement);
    let activation =
        verify_activation(&statement, &approval_set, &installed, &target, &test_result).unwrap();
    activation_artifacts(ArtifactSpec {
        activation,
        installed: &installed,
        target: &target,
        test_result: &test_result,
        predecessor_accepted_at: PREDECESSOR_ACCEPTED_AT,
        accepted_at: GENERATION_TWO_EFFECTIVE_FROM,
    })
}

fn generation_two_activation() -> ActivationArtifacts {
    successor_of_generation_one("principal.proposer", "principal.author")
}

/// A second, independently valid successor of the same generation-1 head.
fn rival_activation() -> ActivationArtifacts {
    successor_of_generation_one("principal.rival-proposer", "principal.rival-author")
}

/// Generation `2 -> 3` reverting to the generation-1 package digest.
fn rollback_activation(generation_two: &ActivationArtifacts) -> ActivationArtifacts {
    let installed = installed_policy(2, &generation_two.head, &generation_two_target());
    let target = generation_one_target();
    let test_result = conformance_result(&target, GENERATION_THREE_TEST_COMPLETED_AT);
    let statement = statement(&StatementSpec {
        predecessor_head: &generation_two.head,
        current_policy: installed.policy_reference(),
        target: &target,
        test_result: &test_result,
        from_generation: 2,
        effective_from: GENERATION_THREE_EFFECTIVE_FROM,
        proposer: "principal.proposer",
        author: "principal.author",
    });
    let approval_set = quorum_approval_set(&statement);
    let activation =
        verify_activation(&statement, &approval_set, &installed, &target, &test_result).unwrap();
    activation_artifacts(ArtifactSpec {
        activation,
        installed: &installed,
        target: &target,
        test_result: &test_result,
        predecessor_accepted_at: GENERATION_TWO_EFFECTIVE_FROM,
        accepted_at: GENERATION_THREE_EFFECTIVE_FROM,
    })
}

/// The durable bytes and out-of-band evidence a repository would re-read for
/// one contender under its stream lock.
fn contender_audit(artifacts: &ActivationArtifacts) -> ContenderActivationAuditV2<'_> {
    ContenderActivationAuditV2 {
        canonical_statement: artifacts.activation.canonical_statement(),
        canonical_approval_set: artifacts.activation.canonical_approval_set(),
        target: &artifacts.target,
        test_result: &artifacts.test_result,
        receipt: &artifacts.receipt,
        event: &artifacts.event,
    }
}

fn audited_contender(artifacts: &ActivationArtifacts) -> AuditedContenderActivationV2 {
    AuditedContenderActivationV2::from_durable_audit(
        &artifacts.installed,
        &contender_audit(artifacts),
    )
    .unwrap()
}

fn generation_one_policy() -> InstalledSuccessorPolicyV2 {
    installed_policy(1, &generation_one_head(), &generation_one_target())
}

fn audited_contested_set(contenders: &[&ActivationArtifacts]) -> AuditedContestedSetV1 {
    let audited = contenders
        .iter()
        .map(|artifacts| audited_contender(artifacts))
        .collect::<Vec<_>>();
    AuditedContestedSetV1::from_durable_audit(&generation_one_policy(), &audited).unwrap()
}

fn contested_set(
    generation_two: &ActivationArtifacts,
    rival: &ActivationArtifacts,
) -> AuditedContestedSetV1 {
    audited_contested_set(&[generation_two, rival])
}

fn resolution_statement(
    set: &AuditedContestedSetV1,
    selected: GenericSuccessorActivationId,
    proposer: &str,
) -> ContestedSetResolutionStatementV1 {
    ContestedSetResolutionStatementV1 {
        schema_version: CONTESTED_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        contested_set_id: set.contested_set_id().unwrap(),
        contested_activation_ids: set.contested_activation_ids().unwrap(),
        selected_activation_id: selected,
        authorizing_activation_policy: set.set().last_unambiguous_activation_policy.clone(),
        effective_from: timestamp(RESOLUTION_EFFECTIVE_FROM),
        proposer_principal_id: case_id(proposer),
    }
}

fn resolution_approval_set(
    statement: &ContestedSetResolutionStatementV1,
) -> ContestedSetResolutionApprovalSetV1 {
    let statement_id = statement.statement_id().unwrap();
    let approval = |principal: &str, seed: [u8; 32]| ContestedSetResolutionApprovalV1 {
        schema_version: CONTESTED_SCHEMA_VERSION,
        statement_id,
        signer_principal_id: case_id(principal),
        signature: detached_signature(
            CONTESTED_RESOLUTION_SIGNATURE_PREFIX,
            statement_id.digest(),
            seed,
        ),
    };
    ContestedSetResolutionApprovalSetV1 {
        schema_version: CONTESTED_SCHEMA_VERSION,
        statement_id,
        approvals: vec![
            approval("principal.alice", [1; 32]),
            approval("principal.bob", [2; 32]),
        ],
    }
}

/// The honest ceremony: the authenticated driver is exactly the principal
/// the statement names. Attacks that disagree with the trusted binding call
/// `verify_contested_set_resolution` directly.
fn verify_resolution(
    statement: &ContestedSetResolutionStatementV1,
    approval_set: &ContestedSetResolutionApprovalSetV1,
    set: &AuditedContestedSetV1,
) -> ContractResult<VerifiedContestedSetResolution> {
    verify_contested_set_resolution(
        &encode_canonical(statement)?,
        &encode_canonical(approval_set)?,
        set,
        &generation_one_policy(),
        &ContestedResolutionPrincipalBinding::from_trusted_config(
            statement.proposer_principal_id.clone(),
        ),
    )
}

fn successor_chain() -> SuccessorChain {
    let generation_two = generation_two_activation();
    let rollback = rollback_activation(&generation_two);
    let rival = rival_activation();
    let set = contested_set(&generation_two, &rival);
    let statement = resolution_statement(
        &set,
        generation_two.receipt.activation_id().unwrap(),
        "principal.arbiter",
    );
    let approval_set = resolution_approval_set(&statement);
    let resolution = verify_resolution(&statement, &approval_set, &set).unwrap();
    let resolution_receipt = resolution
        .receipt_at(
            &generation_one_policy(),
            &set,
            timestamp(RESOLUTION_EFFECTIVE_FROM),
        )
        .unwrap();
    SuccessorChain {
        generation_two,
        rollback,
        rival,
        contested_set: set,
        resolution,
        resolution_receipt,
    }
}

fn positive_cases() -> CaseManifestV1 {
    CaseManifestV1 {
        schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
        suite_id: case_id(SUITE_ID),
        expected_outcome: CaseOutcomeV1::Accept,
        cases: [
            "contested-resolution-under-last-unambiguous-policy",
            "contested-set-records-two-valid-successors",
            "exact-replay-is-a-no-op",
            "generation-one-to-two-activation",
            "installed-policy-is-the-only-authority",
            "rollback-to-an-earlier-package-at-generation-three",
            "stable-registry-activation-stream",
        ]
        .into_iter()
        .map(case_id)
        .collect(),
    }
}

fn negative_cases() -> CaseManifestV1 {
    CaseManifestV1 {
        schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
        suite_id: case_id(SUITE_ID),
        expected_outcome: CaseOutcomeV1::Reject,
        cases: [
            "aba-stale-after-package-digest-returns",
            "approval-below-threshold",
            "approval-under-key-bridge-prefix",
            "approval-under-uninstalled-principal",
            "author-counted-as-approver",
            "contested-contender-approvals-not-derived-from-the-verified-request",
            "contested-contender-head-does-not-reproduce-from-its-activation",
            "contested-contender-of-another-predecessor-head",
            "contested-contender-package-never-passed-conformance",
            "contested-generation-does-not-follow-the-authorizing-policy",
            "contested-resolution-before-its-contenders",
            "contested-resolution-by-a-contestant",
            "contested-resolution-proposer-disagrees-with-trusted-binding",
            "contested-resolution-set-drift",
            "fabricated-contested-contender",
            "genesis-generation-statement",
            "key-bridge-field-in-statement",
            "proposer-counted-as-approver",
            "reactivating-the-current-package",
            "revoked-signer-key",
            "stale-contested-authority-at-receipt-mint",
            "stale-expected-head",
            "stale-head-at-receipt-mint",
            "wrong-generation-step",
            "wrong-scope",
        ]
        .into_iter()
        .map(case_id)
        .collect(),
    }
}

#[allow(clippy::too_many_lines)] // one exhaustive list of every checked-in artifact
fn canonical_artifact_records(
    chain: &SuccessorChain,
    positive_bytes: &[u8],
    negative_bytes: &[u8],
) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "activated-head.jsonl",
            encode_canonical(&chain.generation_two.head).unwrap(),
        ),
        (
            "activation-approval-set.jsonl",
            chain
                .generation_two
                .activation
                .canonical_approval_set()
                .to_vec(),
        ),
        (
            "activation-event.jsonl",
            encode_canonical(&chain.generation_two.event).unwrap(),
        ),
        (
            "activation-receipt.jsonl",
            encode_canonical(&chain.generation_two.receipt).unwrap(),
        ),
        (
            "activation-statement.jsonl",
            chain
                .generation_two
                .activation
                .canonical_statement()
                .to_vec(),
        ),
        (
            "activation-test-result.jsonl",
            chain
                .generation_two
                .activation
                .test_result()
                .canonical_bytes()
                .to_vec(),
        ),
        (
            "contested-resolution-approval-set.jsonl",
            chain.resolution.canonical_approval_set().to_vec(),
        ),
        (
            "contested-resolution-receipt.jsonl",
            encode_canonical(&chain.resolution_receipt).unwrap(),
        ),
        (
            "contested-resolution-statement.jsonl",
            chain.resolution.canonical_statement().to_vec(),
        ),
        (
            "contested-rival-approval-set.jsonl",
            chain.rival.activation.canonical_approval_set().to_vec(),
        ),
        (
            "contested-rival-receipt.jsonl",
            encode_canonical(&chain.rival.receipt).unwrap(),
        ),
        (
            "contested-rival-statement.jsonl",
            chain.rival.activation.canonical_statement().to_vec(),
        ),
        (
            "contested-set.jsonl",
            encode_canonical(chain.contested_set.set()).unwrap(),
        ),
        (
            "generation-2-package.jsonl",
            generation_two_package().canonical_bytes().to_vec(),
        ),
        ("negative-vectors.jsonl", negative_bytes.to_vec()),
        ("positive-vectors.jsonl", positive_bytes.to_vec()),
        (
            "rollback-activated-head.jsonl",
            encode_canonical(&chain.rollback.head).unwrap(),
        ),
        (
            "rollback-approval-set.jsonl",
            chain.rollback.activation.canonical_approval_set().to_vec(),
        ),
        (
            "rollback-event.jsonl",
            encode_canonical(&chain.rollback.event).unwrap(),
        ),
        (
            "rollback-receipt.jsonl",
            encode_canonical(&chain.rollback.receipt).unwrap(),
        ),
        (
            "rollback-statement.jsonl",
            chain.rollback.activation.canonical_statement().to_vec(),
        ),
        (
            "rollback-test-result.jsonl",
            chain
                .rollback
                .activation
                .test_result()
                .canonical_bytes()
                .to_vec(),
        ),
    ]
}

fn vector_suite(
    chain: &SuccessorChain,
    positive: &CaseManifestV1,
    negative: &CaseManifestV1,
    records: &[(&'static str, Vec<u8>)],
) -> VectorSuiteV1 {
    let statement = chain.generation_two.activation.statement();
    let consistency_key = chain
        .generation_two
        .event
        .consistency_partition_key()
        .unwrap();
    VectorSuiteV1 {
        schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
        suite_id: case_id(SUITE_ID),
        fixture_authority: FIXTURE_AUTHORITY.into(),
        predecessor_head: statement.expected_predecessor_head.clone(),
        current_activation_policy: statement.current_activation_policy.clone(),
        generation_two_package_digest: statement.target_package_digest,
        generation_two_statement_id: statement.statement_id().unwrap(),
        generation_two_approval_ids: chain
            .generation_two
            .activation
            .approval_set()
            .approvals
            .iter()
            .map(|approval| approval.approval_id().unwrap())
            .collect(),
        generation_two_activation_id: chain.generation_two.receipt.activation_id().unwrap(),
        generation_two_accepted_event_id: chain.generation_two.event.accepted_event_id().unwrap(),
        generation_two_head: chain.generation_two.head.clone(),
        rollback_target_package_digest: chain.rollback.activation.statement().target_package_digest,
        rollback_statement_id: chain.rollback.activation.statement_id().unwrap(),
        rollback_activation_id: chain.rollback.receipt.activation_id().unwrap(),
        rollback_accepted_event_id: chain.rollback.event.accepted_event_id().unwrap(),
        rollback_head: chain.rollback.head.clone(),
        rival_statement_id: chain.rival.activation.statement_id().unwrap(),
        rival_activation_id: chain.rival.receipt.activation_id().unwrap(),
        contested_set_id: chain.contested_set.contested_set_id().unwrap(),
        contested_activation_ids: chain.contested_set.contested_activation_ids().unwrap(),
        resolution_statement_id: chain.resolution.statement().statement_id().unwrap(),
        resolution_id: chain.resolution_receipt.resolution_id().unwrap(),
        consistency_key_family: consistency_key.family,
        consistency_key_digest: consistency_key.key_digest,
        positive_cases_digest: manifest_digest(positive),
        negative_cases_digest: manifest_digest(negative),
        external_artifact_pins: vec![
            ArtifactPinV1 {
                path: "../../v2/stage4-successor/registry-package.jsonl".into(),
                raw_sha256: raw_sha256(GENERATION_ONE_PACKAGE_FIXTURE),
            },
            ArtifactPinV1 {
                path: "../../v2/successor-activation/activated-head.jsonl".into(),
                raw_sha256: raw_sha256(GENERATION_ONE_HEAD_FIXTURE),
            },
            ArtifactPinV1 {
                path: "../../v2/successor-policy/activation-policy-v2.jsonl".into(),
                raw_sha256: raw_sha256(ACTIVATION_POLICY_ENTRY_FIXTURE),
            },
        ],
        artifact_pins: records
            .iter()
            .map(|(path, bytes)| ArtifactPinV1 {
                path: (*path).into(),
                raw_sha256: raw_sha256(&framed_record(bytes)),
            })
            .collect(),
    }
}

fn write_artifact(output: &Path, name: &str, canonical: &[u8]) {
    require_canonical(canonical).unwrap();
    fs::write(output.join(name), framed_record(canonical)).unwrap();
}

#[test]
#[allow(clippy::too_many_lines)] // one exhaustive freeze of every checked-in artifact
fn canonical_artifacts_and_all_literal_pins_are_frozen() {
    let positive = positive_cases();
    let negative = negative_cases();
    positive.validate(CaseOutcomeV1::Accept);
    negative.validate(CaseOutcomeV1::Reject);
    assert_eq!(
        encode_canonical(&positive).unwrap(),
        record(POSITIVE_VECTORS_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&negative).unwrap(),
        record(NEGATIVE_VECTORS_FIXTURE)
    );

    let chain = successor_chain();
    let records = canonical_artifact_records(
        &chain,
        record(POSITIVE_VECTORS_FIXTURE),
        record(NEGATIVE_VECTORS_FIXTURE),
    );
    let suite = vector_suite(&chain, &positive, &negative, &records);
    assert_eq!(
        encode_canonical(&suite).unwrap(),
        record(VECTOR_SUITE_FIXTURE)
    );
    assert!(
        suite
            .artifact_pins
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
    );
    assert!(
        suite
            .external_artifact_pins
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
    );

    // Every checked-in record equals its regenerated canonical bytes, and
    // the suite's own pin for that path equals the literal file hash.
    let frozen: Vec<(&'static str, &'static [u8])> = vec![
        ("activated-head.jsonl", ACTIVATED_HEAD_FIXTURE),
        (
            "activation-approval-set.jsonl",
            ACTIVATION_APPROVAL_SET_FIXTURE,
        ),
        ("activation-event.jsonl", ACTIVATION_EVENT_FIXTURE),
        ("activation-receipt.jsonl", ACTIVATION_RECEIPT_FIXTURE),
        ("activation-statement.jsonl", ACTIVATION_STATEMENT_FIXTURE),
        (
            "activation-test-result.jsonl",
            ACTIVATION_TEST_RESULT_FIXTURE,
        ),
        (
            "contested-resolution-approval-set.jsonl",
            RESOLUTION_APPROVAL_SET_FIXTURE,
        ),
        (
            "contested-resolution-receipt.jsonl",
            RESOLUTION_RECEIPT_FIXTURE,
        ),
        (
            "contested-resolution-statement.jsonl",
            RESOLUTION_STATEMENT_FIXTURE,
        ),
        (
            "contested-rival-approval-set.jsonl",
            RIVAL_APPROVAL_SET_FIXTURE,
        ),
        ("contested-rival-receipt.jsonl", RIVAL_RECEIPT_FIXTURE),
        ("contested-rival-statement.jsonl", RIVAL_STATEMENT_FIXTURE),
        ("contested-set.jsonl", CONTESTED_SET_FIXTURE),
        ("generation-2-package.jsonl", GENERATION_TWO_PACKAGE_FIXTURE),
        ("negative-vectors.jsonl", NEGATIVE_VECTORS_FIXTURE),
        ("positive-vectors.jsonl", POSITIVE_VECTORS_FIXTURE),
        ("rollback-activated-head.jsonl", ROLLBACK_HEAD_FIXTURE),
        ("rollback-approval-set.jsonl", ROLLBACK_APPROVAL_SET_FIXTURE),
        ("rollback-event.jsonl", ROLLBACK_EVENT_FIXTURE),
        ("rollback-receipt.jsonl", ROLLBACK_RECEIPT_FIXTURE),
        ("rollback-statement.jsonl", ROLLBACK_STATEMENT_FIXTURE),
        ("rollback-test-result.jsonl", ROLLBACK_TEST_RESULT_FIXTURE),
    ];
    assert_eq!(frozen.len(), records.len());
    for (&(expected_path, bytes), (path, canonical)) in frozen.iter().zip(&records) {
        assert_eq!(expected_path, *path);
        require_canonical(record(bytes)).unwrap();
        assert_eq!(record(bytes), canonical.as_slice(), "{path} drifted");
        let pin = suite
            .artifact_pins
            .iter()
            .find(|pin| pin.path == *path)
            .expect("every artifact is pinned by the suite");
        assert_eq!(raw_sha256(bytes), pin.raw_sha256);
    }
    for (path, fixture) in [
        (
            "../../v2/stage4-successor/registry-package.jsonl",
            GENERATION_ONE_PACKAGE_FIXTURE,
        ),
        (
            "../../v2/successor-activation/activated-head.jsonl",
            GENERATION_ONE_HEAD_FIXTURE,
        ),
        (
            "../../v2/successor-policy/activation-policy-v2.jsonl",
            ACTIVATION_POLICY_ENTRY_FIXTURE,
        ),
    ] {
        let pin = suite
            .external_artifact_pins
            .iter()
            .find(|pin| pin.path == path)
            .expect("every external input is pinned by the suite");
        assert_eq!(raw_sha256(fixture), pin.raw_sha256);
    }

    // Inputs owned by the frozen `0 -> 1` contract are unchanged.
    assert_eq!(
        generation_one_package().package_digest().to_string(),
        GENERATION_ONE_PACKAGE_DIGEST
    );
    assert_eq!(
        generation_one_head().head.activation_id.to_string(),
        GENERATION_ONE_ACTIVATION_ID
    );
    assert_eq!(
        generation_one_target()
            .activation_policy()
            .registry_reference()
            .entry_digest
            .to_string(),
        ACTIVATION_POLICY_ENTRY_DIGEST
    );

    assert_eq!(
        suite.generation_two_package_digest.to_string(),
        GENERATION_TWO_PACKAGE_DIGEST
    );
    assert_eq!(
        suite.generation_two_statement_id.to_string(),
        GENERATION_TWO_STATEMENT_ID
    );
    assert_eq!(
        suite.generation_two_activation_id.to_string(),
        GENERATION_TWO_ACTIVATION_ID
    );
    assert_eq!(
        suite.generation_two_accepted_event_id.to_string(),
        GENERATION_TWO_ACCEPTED_EVENT_ID
    );
    assert_eq!(
        suite.rollback_statement_id.to_string(),
        ROLLBACK_STATEMENT_ID
    );
    assert_eq!(
        suite.rollback_activation_id.to_string(),
        ROLLBACK_ACTIVATION_ID
    );
    assert_eq!(
        suite.rollback_accepted_event_id.to_string(),
        ROLLBACK_ACCEPTED_EVENT_ID
    );
    assert_eq!(suite.rival_statement_id.to_string(), RIVAL_STATEMENT_ID);
    assert_eq!(suite.rival_activation_id.to_string(), RIVAL_ACTIVATION_ID);
    assert_eq!(suite.contested_set_id.to_string(), CONTESTED_SET_ID);
    assert_eq!(
        suite.resolution_statement_id.to_string(),
        RESOLUTION_STATEMENT_ID
    );
    assert_eq!(suite.resolution_id.to_string(), RESOLUTION_ID);
    assert_eq!(
        suite.consistency_key_digest.to_string(),
        CONSISTENCY_KEY_DIGEST
    );
    assert_eq!(
        suite.consistency_key_family.as_str(),
        "registry.activation",
        "genesis, first-successor, and generic activations share one stream"
    );
    assert_eq!(
        suite.positive_cases_digest.to_string(),
        POSITIVE_CASES_DIGEST
    );
    assert_eq!(
        suite.negative_cases_digest.to_string(),
        NEGATIVE_CASES_DIGEST
    );
    assert_eq!(
        raw_sha256(VECTOR_SUITE_FIXTURE).to_string(),
        VECTOR_SUITE_RAW_SHA256
    );
    assert_eq!(
        domain_separated_digest(
            DigestDomain::TestVectorManifest,
            record(VECTOR_SUITE_FIXTURE)
        )
        .to_string(),
        VECTOR_SUITE_DIGEST
    );
}

#[test]
fn frozen_artifacts_reverify_without_granting_durable_authority() {
    let head = generation_one_head();
    let installed = installed_policy(1, &head, &generation_one_target());
    let target = generation_two_target();
    let pin = GenericSuccessorTestRunnerPin::from_trusted_config(
        expected_digest(RUNNER_ARTIFACT_DIGEST),
        expected_digest(RUNNER_CONFIGURATION_DIGEST),
        RegistryTestResultDigest::from_digest(domain_separated_digest(
            DigestDomain::RegistryTestResult,
            record(ACTIVATION_TEST_RESULT_FIXTURE),
        )),
    );
    let test_result =
        verify_generic_successor_test_result(record(ACTIVATION_TEST_RESULT_FIXTURE), pin, &target)
            .unwrap();
    let activation = verify_generic_successor_activation(
        record(ACTIVATION_STATEMENT_FIXTURE),
        record(ACTIVATION_APPROVAL_SET_FIXTURE),
        &installed,
        &target,
        &test_result,
        &GenericSuccessorPrincipalBinding::from_trusted_config(
            case_id("principal.proposer"),
            case_id("principal.author"),
        ),
    )
    .unwrap();
    // Verification proves bytes and approvals, never freshness: the head
    // check is a separate, explicit obligation.
    activation.require_expected_head(&head).unwrap();
    assert_eq!(
        activation.required_threshold(),
        2,
        "the installed predecessor policy fixes the threshold"
    );
    assert_eq!(
        activation.applied_separation_of_duty(),
        ActivationSeparationOfDutyV2::AuthorAndProposerDistinctNeitherMayApprove
    );

    // A receipt decoded from public bytes is inert until it revalidates
    // against the exact verified request it belongs to.
    let receipt: GenericSuccessorActivationReceiptV2 =
        decode_strict(record(ACTIVATION_RECEIPT_FIXTURE)).unwrap();
    receipt.validate_against(&activation).unwrap();
    let event: GenericSuccessorActivatedEventV2 =
        decode_strict(record(ACTIVATION_EVENT_FIXTURE)).unwrap();
    event.validate_against(&activation, &receipt).unwrap();
    let stored_head: RegistryHeadBindingV1 =
        decode_strict(record(ACTIVATED_HEAD_FIXTURE)).expect("the activated head is canonical");
    assert_eq!(
        activation.resulting_registry_head(&receipt).unwrap(),
        stored_head
    );

    let rollback_receipt: GenericSuccessorActivationReceiptV2 =
        decode_strict(record(ROLLBACK_RECEIPT_FIXTURE)).unwrap();
    // The checked-in contested-set record is a projection of the audited
    // value, never an input to it.
    let wire_set: RegistryContestedSetV1 =
        decode_strict(record(CONTESTED_SET_FIXTURE)).expect("the contested set is canonical");
    let chain = successor_chain();
    chain.contested_set.require_wire_form(&wire_set).unwrap();
    let mut forged = wire_set;
    forged.contenders[0].activated_head.head.package_digest = Sha256Digest::from_bytes([0xde; 32]);
    assert_eq!(
        chain.contested_set.require_wire_form(&forged),
        Err(ContractError::ManifestMismatch)
    );

    assert_eq!(
        rollback_receipt.validate_against(&activation),
        Err(ContractError::ManifestMismatch),
        "a receipt cannot be transplanted onto another request"
    );
    assert_eq!(
        event.validate_against(&activation, &rollback_receipt),
        Err(ContractError::ManifestMismatch)
    );
}

#[test]
fn rollback_activates_an_earlier_package_under_a_new_activation_id() {
    let chain = successor_chain();
    let rollback_statement = chain.rollback.activation.statement();
    assert_eq!(rollback_statement.from_generation, 2);
    assert_eq!(rollback_statement.to_generation, 3);
    // The revert targets exactly the generation-1 package digest.
    assert_eq!(
        rollback_statement.target_package_digest,
        generation_one_package().package_digest()
    );
    assert_eq!(
        chain.rollback.head.head.package_digest,
        generation_one_head().head.package_digest
    );
    // No prior activation identity is rewritten: the revert mints a new one.
    assert_ne!(
        chain.rollback.head.head.activation_id,
        generation_one_head().head.activation_id
    );
    assert_ne!(
        chain.rollback.head.head.activation_id,
        chain.generation_two.head.head.activation_id
    );
    assert!(chain.rollback.head.effective_from > chain.generation_two.head.effective_from);
    assert_eq!(
        record(ROLLBACK_HEAD_FIXTURE),
        encode_canonical(&chain.rollback.head).unwrap()
    );
}

#[test]
fn stale_and_aba_expected_heads_fail_closed() {
    let chain = successor_chain();
    let head = generation_one_head();
    let installed = installed_policy(1, &head, &generation_one_target());
    let target = generation_two_target();
    let test_result = conformance_result(&target, GENERATION_TWO_TEST_COMPLETED_AT);

    // A -> B -> A: the rollback head names package A again, so package
    // equality alone would revive the stale generation-1 proposal.
    assert_eq!(
        chain.rollback.head.head.package_digest,
        head.head.package_digest
    );
    assert_eq!(
        chain
            .generation_two
            .activation
            .require_expected_head(&chain.rollback.head),
        Err(ContractError::StaleRegistryHead)
    );
    assert_eq!(
        chain
            .generation_two
            .activation
            .require_expected_head(&chain.generation_two.head),
        Err(ContractError::StaleRegistryHead)
    );

    // Verification happened while generation 1 was current; by mint time
    // the head has moved to generation 3. The receipt seam re-presents the
    // audited head, so the accepted form cannot be minted at all.
    let moved_on = installed_policy(3, &chain.rollback.head, &generation_one_target());
    assert_eq!(
        rejection(chain.generation_two.activation.receipt_at(
            &moved_on,
            &timestamp(PREDECESSOR_ACCEPTED_AT),
            timestamp(GENERATION_TWO_EFFECTIVE_FROM),
        )),
        ContractError::StaleRegistryHead
    );

    // A statement written against a head that is not the audited current
    // head is rejected during verification, not merely at CAS time.
    let mut drifted = statement(&StatementSpec {
        predecessor_head: &head,
        current_policy: installed.policy_reference(),
        target: &target,
        test_result: &test_result,
        from_generation: 1,
        effective_from: GENERATION_TWO_EFFECTIVE_FROM,
        proposer: "principal.proposer",
        author: "principal.author",
    });
    drifted.expected_predecessor_head.head.activation_id = Sha256Digest::from_bytes([0x5a; 32]);
    let approval_set = quorum_approval_set(&drifted);
    assert_eq!(
        rejection(verify_activation(
            &drifted,
            &approval_set,
            &installed,
            &target,
            &test_result
        )),
        ContractError::StaleRegistryHead
    );
}

#[test]
fn installed_policy_governs_eligibility_threshold_and_separation_of_duty() {
    let head = generation_one_head();
    let installed = installed_policy(1, &head, &generation_one_target());
    let target = generation_two_target();
    let test_result = conformance_result(&target, GENERATION_TWO_TEST_COMPLETED_AT);
    let spec = |proposer: &'static str, author: &'static str| StatementSpec {
        predecessor_head: &head,
        current_policy: installed.policy_reference(),
        target: &target,
        test_result: &test_result,
        from_generation: 1,
        effective_from: GENERATION_TWO_EFFECTIVE_FROM,
        proposer,
        author,
    };

    // Below the installed threshold of two.
    let proposal = statement(&spec("principal.proposer", "principal.author"));
    let statement_id = proposal.statement_id().unwrap();
    let single = approval_set_of(
        &proposal,
        vec![activation_approval(
            statement_id,
            "principal.alice",
            [1; 32],
        )],
    );
    assert_eq!(
        rejection(verify_activation(
            &proposal,
            &single,
            &installed,
            &target,
            &test_result
        )),
        ContractError::ApprovalThresholdNotMet
    );

    // A principal the installed policy does not list has no key here, and a
    // listed principal signing with a rotated key verifies against nothing.
    let uninstalled = approval_set_of(
        &proposal,
        vec![
            activation_approval(statement_id, "principal.alice", [1; 32]),
            activation_approval(statement_id, "principal.carol", [3; 32]),
        ],
    );
    assert_eq!(
        rejection(verify_activation(
            &proposal,
            &uninstalled,
            &installed,
            &target,
            &test_result
        )),
        ContractError::SignatureVerification
    );
    let revoked = approval_set_of(
        &proposal,
        vec![
            activation_approval(statement_id, "principal.alice", [9; 32]),
            activation_approval(statement_id, "principal.bob", [2; 32]),
        ],
    );
    assert_eq!(
        rejection(verify_activation(
            &proposal,
            &revoked,
            &installed,
            &target,
            &test_result
        )),
        ContractError::SignatureVerification
    );

    // The package author may not be counted as an approver, and the author
    // and proposer may not be the same principal. Both are the installed
    // v2 rule in `ActivationPolicyEntryV2::validate_approval_principal_set`.
    let author_approves = statement(&spec("principal.proposer", "principal.alice"));
    let author_set = quorum_approval_set(&author_approves);
    assert!(matches!(
        verify_activation(
            &author_approves,
            &author_set,
            &installed,
            &target,
            &test_result
        ),
        Err(ContractError::Schema(_))
    ));
    let proposer_approves = statement(&spec("principal.alice", "principal.author"));
    let proposer_set = quorum_approval_set(&proposer_approves);
    assert!(matches!(
        verify_activation(
            &proposer_approves,
            &proposer_set,
            &installed,
            &target,
            &test_result
        ),
        Err(ContractError::Schema(_))
    ));
    let mut collapsed = proposal;
    collapsed.package_author_principal_id = collapsed.proposer_principal_id.clone();
    assert!(collapsed.validate_shape().is_err());
}

#[test]
fn no_key_bridge_participates_in_generic_transitions() {
    let head = generation_one_head();
    let installed = installed_policy(1, &head, &generation_one_target());
    let target = generation_two_target();
    let test_result = conformance_result(&target, GENERATION_TWO_TEST_COMPLETED_AT);
    let statement = statement(&StatementSpec {
        predecessor_head: &head,
        current_policy: installed.policy_reference(),
        target: &target,
        test_result: &test_result,
        from_generation: 1,
        effective_from: GENERATION_TWO_EFFECTIVE_FROM,
        proposer: "principal.proposer",
        author: "principal.author",
    });
    let statement_id = statement.statement_id().unwrap();

    // Approvals minted under the one-shot `0 -> 1` bridge prefix do not
    // verify under the generic v2 approval domain.
    let bridge_signed = |principal: &str, seed: [u8; 32]| GenericSuccessorActivationApprovalV2 {
        schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
        statement_id,
        signer_principal_id: case_id(principal),
        signature: detached_signature(
            BRIDGE_APPROVAL_SIGNATURE_PREFIX,
            statement_id.digest(),
            seed,
        ),
    };
    let bridged = approval_set_of(
        &statement,
        vec![
            bridge_signed("principal.alice", [1; 32]),
            bridge_signed("principal.bob", [2; 32]),
        ],
    );
    assert_eq!(
        rejection(verify_activation(
            &statement,
            &bridged,
            &installed,
            &target,
            &test_result
        )),
        ContractError::SignatureVerification
    );

    // A statement carrying a bridge digest is not a generic statement.
    let canonical = encode_canonical(&statement).unwrap();
    let marker: &[u8] = br#","package_author_principal_id""#;
    let position = canonical
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("canonical key order places the author after the generation fields");
    let mut with_bridge = canonical[..position].to_vec();
    with_bridge.extend_from_slice(
        br#","genesis_successor_key_bridge_digest":"e15309eba5118e21996a7cee6b3780c1a237982bdf4f22460bca4da189ef6592""#,
    );
    with_bridge.extend_from_slice(&canonical[position..]);
    require_canonical(&with_bridge).expect("only the unknown key differs");
    assert!(decode_strict::<GenericSuccessorActivationStatementV2>(&with_bridge).is_err());
}

#[test]
fn wrong_scope_and_generation_steps_fail_closed() {
    let head = generation_one_head();
    let installed = installed_policy(1, &head, &generation_one_target());
    let target = generation_two_target();
    let test_result = conformance_result(&target, GENERATION_TWO_TEST_COMPLETED_AT);
    let base = statement(&StatementSpec {
        predecessor_head: &head,
        current_policy: installed.policy_reference(),
        target: &target,
        test_result: &test_result,
        from_generation: 1,
        effective_from: GENERATION_TWO_EFFECTIVE_FROM,
        proposer: "principal.proposer",
        author: "principal.author",
    });

    let mut wrong_scope = base.clone();
    wrong_scope.scope = AuthenticatedProjectScopeV1::from_trusted_context(
        case_id("tenant.other"),
        case_id("project.fixture"),
    );
    let approvals = quorum_approval_set(&wrong_scope);
    assert_eq!(
        rejection(verify_activation(
            &wrong_scope,
            &approvals,
            &installed,
            &target,
            &test_result
        )),
        ContractError::ManifestMismatch
    );

    // Generation zero belongs to the frozen bridge contract, a two-step
    // jump is not a transition, and re-activating the current package is a
    // no-op rather than a successor.
    let mut genesis_step = base.clone();
    genesis_step.from_generation = 0;
    genesis_step.to_generation = 1;
    assert!(genesis_step.validate_shape().is_err());
    let mut double_step = base.clone();
    double_step.to_generation = 3;
    assert!(double_step.validate_shape().is_err());
    let mut same_package = base;
    same_package.target_package_digest = head.head.package_digest;
    assert!(same_package.validate_shape().is_err());
}

#[test]
fn replay_classification_mirrors_the_frozen_first_successor_semantics() {
    let chain = successor_chain();
    let activation = &chain.generation_two.activation;
    let statement_id = activation.statement_id().unwrap();

    assert_eq!(
        classify_generic_successor_replay(
            activation,
            statement_id,
            activation.canonical_statement(),
            activation.canonical_approval_set(),
        )
        .unwrap(),
        GenericSuccessorReplayClassV2::ExactReplay
    );
    assert_eq!(
        classify_generic_successor_replay(
            activation,
            statement_id,
            record(ROLLBACK_STATEMENT_FIXTURE),
            activation.canonical_approval_set(),
        )
        .unwrap(),
        GenericSuccessorReplayClassV2::IntegrityCollision
    );
    assert_eq!(
        classify_generic_successor_replay(
            activation,
            statement_id,
            activation.canonical_statement(),
            chain.rival.activation.canonical_approval_set(),
        )
        .unwrap(),
        GenericSuccessorReplayClassV2::ApprovalSetConflict
    );
    assert_eq!(
        classify_generic_successor_replay(
            activation,
            chain.rival.activation.statement_id().unwrap(),
            chain.rival.activation.canonical_statement(),
            chain.rival.activation.canonical_approval_set(),
        )
        .unwrap(),
        GenericSuccessorReplayClassV2::StaleStatement
    );
}

#[test]
fn contested_set_records_two_valid_successors_of_one_head() {
    let chain = successor_chain();
    // Both contenders verified on their own merits against the same head.
    assert_eq!(
        chain
            .generation_two
            .activation
            .statement()
            .expected_predecessor_head,
        chain.rival.activation.statement().expected_predecessor_head
    );
    assert_ne!(
        chain.generation_two.receipt.activation_id().unwrap(),
        chain.rival.receipt.activation_id().unwrap()
    );
    assert_eq!(
        chain.generation_two.activation.statement().effective_from,
        chain.rival.activation.statement().effective_from,
        "the contest is over the same scope and effective interval"
    );
    assert_eq!(chain.contested_set.set().contenders.len(), 2);
    assert_eq!(chain.contested_set.set().contested_generation, 2);
    let ids = chain.contested_set.contested_activation_ids().unwrap();
    assert!(strictly_sorted(&ids));
    assert!(ids.contains(&chain.generation_two.receipt.activation_id().unwrap()));
    assert!(ids.contains(&chain.rival.receipt.activation_id().unwrap()));

    // Every field of the record is derived from the audited activations,
    // and the contested generation follows the authorizing policy.
    assert_eq!(
        chain.contested_set.set().contested_generation,
        generation_one_policy().generation() + 1
    );
    assert_eq!(
        chain.contested_set.set().last_unambiguous_head,
        *generation_one_policy().head()
    );

    // A single-contender record is not a contest.
    let mut lone = chain.contested_set.set().clone();
    lone.contenders.truncate(1);
    assert!(lone.validate_shape().is_err());
    assert_eq!(
        rejection(AuditedContestedSetV1::from_durable_audit(
            &generation_one_policy(),
            &[audited_contender(&chain.generation_two)],
        )),
        ContractError::Schema("invalid registry contested set v1".into())
    );
}

/// A wholly synthetic contender: three artifacts that agree with each other
/// perfectly and correspond to no activation that ever happened.
struct GhostContender {
    statement: GenericSuccessorActivationStatementV2,
    approval_set: GenericSuccessorActivationApprovalSetV2,
    receipt: GenericSuccessorActivationReceiptV2,
    event: GenericSuccessorActivatedEventV2,
}

/// Build the coherent forgery the mutual-consistency audit used to accept:
/// a package digest that never passed conformance, an activation policy that
/// was never installed, and a receipt whose own digest anchors the head the
/// event announces.
fn ghost_contender(approvals: Vec<GenericSuccessorActivationApprovalV2>) -> GhostContender {
    let head = generation_one_head();
    let installed = generation_one_policy();
    let ghost_package = Sha256Digest::from_bytes([0xbe; 32]);
    let ghost_policy = RegistryReferenceV1 {
        entry_id: case_id("activation.ghost"),
        version: 7,
        entry_digest: Sha256Digest::from_bytes([0xca; 32]),
    };
    let statement = GenericSuccessorActivationStatementV2 {
        schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        expected_predecessor_head: head.clone(),
        current_activation_policy: installed.policy_reference().clone(),
        target_package_digest: ghost_package,
        target_activation_policy: ghost_policy.clone(),
        test_vector_result_digest: RegistryTestResultDigest::from_digest(Sha256Digest::from_bytes(
            [0x77; 32],
        )),
        from_generation: 1,
        to_generation: 2,
        effective_from: timestamp(GENERATION_TWO_EFFECTIVE_FROM),
        effective_until: None,
        proposer_principal_id: case_id("principal.mallory"),
        package_author_principal_id: case_id("principal.mallory-author"),
    };
    let statement_id = statement.statement_id().unwrap();
    let approval_set = GenericSuccessorActivationApprovalSetV2 {
        schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
        statement_id,
        approvals,
    };
    let receipt = GenericSuccessorActivationReceiptV2 {
        schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
        statement_id,
        predecessor_head: head.clone(),
        current_activation_policy: installed.policy_reference().clone(),
        target_package_digest: ghost_package,
        target_activation_policy: ghost_policy.clone(),
        test_vector_result_digest: statement.test_vector_result_digest,
        from_generation: 1,
        to_generation: 2,
        eligible_approvals: vec![EligibleApprovalV1 {
            attestation_id: Sha256Digest::from_bytes([0x99; 32]),
            principal_id: case_id("principal.mallory-approver"),
            signer_key_id: case_id("key.mallory"),
        }],
        required_threshold: 1,
        applied_separation_of_duty:
            ActivationSeparationOfDutyV2::AuthorAndProposerDistinctNeitherMayApprove,
        separation_of_duty_satisfied: true,
        accepted_at: timestamp(GENERATION_TWO_EFFECTIVE_FROM),
    };
    let activation_id = receipt.activation_id().unwrap();
    let event = GenericSuccessorActivatedEventV2 {
        schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
        event_kind: case_id(SUCCESSOR_GENERIC_EVENT_KIND),
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        activation_id,
        statement_id,
        predecessor_head: head,
        activated_head: RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id: activation_id.digest(),
                package_digest: ghost_package,
                activation_policy_digest: ghost_policy.entry_digest,
            },
            effective_from: timestamp(GENERATION_TWO_EFFECTIVE_FROM),
            effective_until: None,
        },
        current_activation_policy: installed.policy_reference().clone(),
        target_activation_policy: ghost_policy,
        test_vector_result_digest: statement.test_vector_result_digest,
        from_generation: 1,
        to_generation: 2,
    };
    GhostContender {
        statement,
        approval_set,
        receipt,
        event,
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one adversary, many coherent forgeries
fn contested_contenders_must_reproduce_from_their_own_activations() {
    let generation_two = generation_two_activation();
    let rival = rival_activation();
    let policy = generation_one_policy();
    let target = generation_two_target();
    let test_result = conformance_result(&target, GENERATION_TWO_TEST_COMPLETED_AT);

    // ATTACK: three artifacts forged *coherently*, not one at a time. The
    // statement names a package digest that never passed conformance and an
    // activation policy that was never installed; the receipt agrees with
    // the statement field for field; the event's activated head is derived
    // from the receipt's own digest exactly as `resulting_registry_head`
    // would derive it, and it is signed for by the two really installed
    // keys. Mutual consistency is therefore complete - and worthless.
    let ghost_statement_id = ghost_contender(Vec::new())
        .statement
        .statement_id()
        .unwrap();
    let ghost = ghost_contender(vec![
        activation_approval(ghost_statement_id, "principal.alice", [1; 32]),
        activation_approval(ghost_statement_id, "principal.bob", [2; 32]),
    ]);
    assert_eq!(
        ghost.event.activated_head.head.activation_id,
        ghost.receipt.activation_id().unwrap().digest(),
        "the forgery is internally consistent: the head reproduces from the receipt"
    );
    let ghost_statement_bytes = encode_canonical(&ghost.statement).unwrap();
    let ghost_approval_bytes = encode_canonical(&ghost.approval_set).unwrap();
    assert_eq!(
        rejection(AuditedContenderActivationV2::from_durable_audit(
            &policy,
            &ContenderActivationAuditV2 {
                canonical_statement: &ghost_statement_bytes,
                canonical_approval_set: &ghost_approval_bytes,
                target: &target,
                test_result: &test_result,
                receipt: &ghost.receipt,
                event: &ghost.event,
            },
        )),
        ContractError::ManifestMismatch,
        "a contender must bind real package bytes and a runner-pinned conformance result"
    );

    // ATTACK: the real generation-2 statement, approved by a principal the
    // installed policy does not list. There is no key to verify against, so
    // an approver set nobody eligible signed cannot enter a contender.
    let statement_bytes = generation_two.activation.canonical_statement().to_vec();
    let approval_bytes = generation_two.activation.canonical_approval_set().to_vec();
    let real_statement_id = generation_two.activation.statement_id().unwrap();
    let mallory_approvals = encode_canonical(&GenericSuccessorActivationApprovalSetV2 {
        schema_version: SUCCESSOR_GENERIC_SCHEMA_VERSION,
        statement_id: real_statement_id,
        approvals: vec![activation_approval(
            real_statement_id,
            "principal.mallory-approver",
            [9; 32],
        )],
    })
    .unwrap();
    assert_eq!(
        rejection(AuditedContenderActivationV2::from_durable_audit(
            &policy,
            &ContenderActivationAuditV2 {
                canonical_statement: &statement_bytes,
                canonical_approval_set: &mallory_approvals,
                target: &target,
                test_result: &test_result,
                receipt: &generation_two.receipt,
                event: &generation_two.event,
            },
        )),
        ContractError::SignatureVerification
    );

    // ATTACK: a real statement and real approvals, with the receipt
    // rewritten to a threshold of one and an approver who never signed. The
    // receipt is admitted only if it is the one the verifier derives.
    let mut downgraded = generation_two.receipt.clone();
    downgraded.required_threshold = 1;
    downgraded.eligible_approvals = vec![EligibleApprovalV1 {
        attestation_id: Sha256Digest::from_bytes([0x99; 32]),
        principal_id: case_id("principal.mallory-approver"),
        signer_key_id: case_id("key.mallory"),
    }];
    assert_eq!(
        rejection(AuditedContenderActivationV2::from_durable_audit(
            &policy,
            &ContenderActivationAuditV2 {
                canonical_statement: &statement_bytes,
                canonical_approval_set: &approval_bytes,
                target: &target,
                test_result: &test_result,
                receipt: &downgraded,
                event: &generation_two.event,
            },
        )),
        ContractError::ManifestMismatch,
        "the receipt's threshold and approver set are server-derived, not claimed"
    );

    // A head naming a package digest that never passed conformance cannot be
    // slipped into the event either: the event must equal the one the
    // verified request and its receipt produce.
    let mut forged_head = generation_two.event.clone();
    forged_head.activated_head.head.package_digest = Sha256Digest::from_bytes([0xde; 32]);
    assert_eq!(
        rejection(AuditedContenderActivationV2::from_durable_audit(
            &policy,
            &ContenderActivationAuditV2 {
                canonical_statement: &statement_bytes,
                canonical_approval_set: &approval_bytes,
                target: &target,
                test_result: &test_result,
                receipt: &generation_two.receipt,
                event: &forged_head,
            },
        )),
        ContractError::ManifestMismatch
    );
    for mutate in [
        (|event: &mut GenericSuccessorActivatedEventV2| {
            event.activated_head.head.activation_policy_digest =
                Sha256Digest::from_bytes([0xad; 32]);
        }) as fn(&mut GenericSuccessorActivatedEventV2),
        |event: &mut GenericSuccessorActivatedEventV2| {
            event.activated_head.head.activation_id = Sha256Digest::from_bytes([0x11; 32]);
        },
    ] {
        let mut forged = generation_two.event.clone();
        mutate(&mut forged);
        assert!(
            AuditedContenderActivationV2::from_durable_audit(
                &policy,
                &ContenderActivationAuditV2 {
                    canonical_statement: &statement_bytes,
                    canonical_approval_set: &approval_bytes,
                    target: &target,
                    test_result: &test_result,
                    receipt: &generation_two.receipt,
                    event: &forged,
                },
            )
            .is_err()
        );
    }

    // Rewriting the receipt instead moves the activation ID, so the event
    // no longer reproduces from it either.
    let mut rewritten = generation_two.receipt.clone();
    rewritten.target_package_digest = Sha256Digest::from_bytes([0xde; 32]);
    assert_eq!(
        rejection(AuditedContenderActivationV2::from_durable_audit(
            &policy,
            &ContenderActivationAuditV2 {
                canonical_statement: &statement_bytes,
                canonical_approval_set: &approval_bytes,
                target: &target,
                test_result: &test_result,
                receipt: &rewritten,
                event: &generation_two.event,
            },
        )),
        ContractError::ManifestMismatch
    );

    // The proposer and author are bound by the statement digest, so another
    // genuine activation's receipt cannot be transplanted onto this request
    // to rename who proposed the contender - and therefore cannot bar a
    // legitimate arbiter from resolving the contest.
    assert_eq!(
        rejection(AuditedContenderActivationV2::from_durable_audit(
            &policy,
            &ContenderActivationAuditV2 {
                canonical_statement: rival.activation.canonical_statement(),
                canonical_approval_set: rival.activation.canonical_approval_set(),
                target: &target,
                test_result: &test_result,
                receipt: &generation_two.receipt,
                event: &generation_two.event,
            },
        )),
        ContractError::ManifestMismatch
    );

    // A genuine activation of a different predecessor head is not a
    // contender of this contest, and the authorizing policy says so before
    // the contested set is ever assembled.
    let rollback = rollback_activation(&generation_two);
    assert_eq!(
        rejection(AuditedContenderActivationV2::from_durable_audit(
            &policy,
            &contender_audit(&rollback),
        )),
        ContractError::ManifestMismatch,
        "generation 2 -> 3 is not a step the generation-1 policy governs"
    );
    assert_eq!(
        rejection(AuditedContestedSetV1::from_durable_audit(
            &policy,
            &[
                audited_contender(&generation_two),
                audited_contender(&rollback),
            ],
        )),
        ContractError::ManifestMismatch
    );
}

#[test]
fn contested_generation_must_follow_the_authorizing_policy_generation() {
    let chain = successor_chain();
    let selected = chain.generation_two.receipt.activation_id().unwrap();
    let statement = resolution_statement(&chain.contested_set, selected, "principal.arbiter");
    let approvals = resolution_approval_set(&statement);

    // The generation an `InstalledSuccessorPolicyV2` claims is not derivable
    // from its head bytes, so head equality alone cannot pin it. A policy
    // audited at generation 9 governs a generation-10 contest and nothing
    // else, even when it presents the frozen generation-1 head.
    let mismatched = InstalledSuccessorPolicyV2::from_durable_audit(
        frozen_profile_reference_v1(),
        scope(),
        9,
        generation_one_head(),
        &generation_one_target(),
    )
    .unwrap();
    assert_eq!(
        rejection(verify_contested_set_resolution(
            &encode_canonical(&statement).unwrap(),
            &encode_canonical(&approvals).unwrap(),
            &chain.contested_set,
            &mismatched,
            &ContestedResolutionPrincipalBinding::from_trusted_config(
                case_id("principal.arbiter",)
            ),
        )),
        ContractError::ManifestMismatch
    );
    assert_eq!(
        rejection(chain.resolution.receipt_at(
            &mismatched,
            &chain.contested_set,
            timestamp(RESOLUTION_EFFECTIVE_FROM),
        )),
        ContractError::ManifestMismatch
    );

    // And a contest cannot be audited into existence at a generation its
    // own contenders did not step to.
    assert_eq!(
        rejection(AuditedContestedSetV1::from_durable_audit(
            &mismatched,
            &[
                audited_contender(&chain.generation_two),
                audited_contender(&chain.rival),
            ],
        )),
        ContractError::ManifestMismatch
    );
}

#[test]
fn contested_resolution_requires_the_last_unambiguous_policy_and_bars_self_selection() {
    let chain = successor_chain();
    let selected = chain.generation_two.receipt.activation_id().unwrap();
    assert_eq!(
        *chain.resolution.selected_head(),
        chain.generation_two.head,
        "resolution installs the selected contender's own head"
    );
    assert_eq!(
        chain.resolution_receipt.contested_activation_ids,
        chain.contested_set.contested_activation_ids().unwrap()
    );
    assert!(chain.resolution_receipt.self_selection_excluded);

    // Neither contested successor may authorize its own selection.
    for contestant in [
        "principal.proposer",
        "principal.author",
        "principal.rival-proposer",
        "principal.rival-author",
        "principal.alice",
    ] {
        let statement = resolution_statement(&chain.contested_set, selected, contestant);
        let approvals = resolution_approval_set(&statement);
        assert!(
            matches!(
                verify_resolution(&statement, &approvals, &chain.contested_set),
                Err(ContractError::Schema(_))
            ),
            "{contestant} must not be able to resolve the contest"
        );
    }

    // The contested activation-ID set is a compare-and-swap precondition:
    // a third successor of the same head appearing after the statement was
    // written cannot be silently excluded from the contest it belongs to.
    let late = successor_of_generation_one("principal.late-proposer", "principal.late-author");
    let drifted = audited_contested_set(&[&chain.generation_two, &chain.rival, &late]);
    let stale = resolution_statement(&chain.contested_set, selected, "principal.arbiter");
    let approvals = resolution_approval_set(&stale);
    assert_eq!(
        rejection(verify_resolution(&stale, &approvals, &drifted)),
        ContractError::StaleRegistryHead,
        "a resolution cannot silently exclude a contender that appeared later"
    );
    assert_eq!(
        rejection(chain.resolution.receipt_at(
            &generation_one_policy(),
            &drifted,
            timestamp(RESOLUTION_EFFECTIVE_FROM),
        )),
        ContractError::StaleRegistryHead,
        "the receipt seam re-audits the contested set, not only the verifier"
    );

    // The re-audited authority is a compare-and-swap precondition at mint
    // time: a head that has since moved cannot mint the accepted form.
    let moved_on = installed_policy(2, &chain.generation_two.head, &generation_two_target());
    assert!(
        chain
            .resolution
            .receipt_at(
                &moved_on,
                &chain.contested_set,
                timestamp(RESOLUTION_EFFECTIVE_FROM)
            )
            .is_err()
    );

    // A resolution cannot claim to take effect before the contest existed.
    let mut early = resolution_statement(&chain.contested_set, selected, "principal.arbiter");
    early.effective_from = timestamp(GENERATION_TWO_EFFECTIVE_FROM);
    let early_approvals = resolution_approval_set(&early);
    assert!(matches!(
        verify_resolution(&early, &early_approvals, &chain.contested_set),
        Err(ContractError::Schema(_))
    ));

    // Selecting an activation outside the recorded set is impossible.
    let mut foreign = stale;
    foreign.selected_activation_id = chain.rollback.receipt.activation_id().unwrap();
    assert!(foreign.validate_shape().is_err());
}

#[test]
fn the_contested_resolution_proposer_is_authenticated_not_labelled() {
    let chain = successor_chain();
    let selected = chain.generation_two.receipt.activation_id().unwrap();
    // The party actually driving the ceremony, from authenticated
    // configuration rather than from the request payload.
    let driver =
        ContestedResolutionPrincipalBinding::from_trusted_config(case_id("principal.proposer"));

    // Truthfully named, contender A's own proposer is barred.
    let honest = resolution_statement(&chain.contested_set, selected, "principal.proposer");
    let honest_approvals = resolution_approval_set(&honest);
    assert!(matches!(
        verify_contested_set_resolution(
            &encode_canonical(&honest).unwrap(),
            &encode_canonical(&honest_approvals).unwrap(),
            &chain.contested_set,
            &generation_one_policy(),
            &driver,
        ),
        Err(ContractError::Schema(_))
    ));

    // The same party writing a different name in the payload no longer
    // escapes the bar. The proposer is compared against trusted
    // configuration before the barred sets are consulted at all, so the
    // rule tests an authenticated identity rather than a chosen string.
    for alias in [
        "principal.proposer-but-spelled-differently",
        "principal.zzz",
        "principal.arbiter",
    ] {
        let aliased = resolution_statement(&chain.contested_set, selected, alias);
        let approvals = resolution_approval_set(&aliased);
        assert_eq!(
            rejection(verify_contested_set_resolution(
                &encode_canonical(&aliased).unwrap(),
                &encode_canonical(&approvals).unwrap(),
                &chain.contested_set,
                &generation_one_policy(),
                &driver,
            )),
            ContractError::ManifestMismatch,
            "{alias} disagrees with the authenticated driver"
        );
    }
}

#[test]
#[ignore = "maintainer-only canonical generic-successor fixture regeneration"]
fn regenerate_generic_successor_artifacts() {
    let output = env::var("SUCCESSOR_GENERIC_VECTOR_OUTPUT")
        .expect("set SUCCESSOR_GENERIC_VECTOR_OUTPUT to an explicit output directory");
    let output = Path::new(&output);
    fs::create_dir_all(output).unwrap();

    let positive = positive_cases();
    let negative = negative_cases();
    positive.validate(CaseOutcomeV1::Accept);
    negative.validate(CaseOutcomeV1::Reject);
    let positive_bytes = encode_canonical(&positive).unwrap();
    let negative_bytes = encode_canonical(&negative).unwrap();

    let chain = successor_chain();
    let records = canonical_artifact_records(&chain, &positive_bytes, &negative_bytes);
    let suite = vector_suite(&chain, &positive, &negative, &records);
    let suite_bytes = encode_canonical(&suite).unwrap();

    for (name, bytes) in &records {
        write_artifact(output, name, bytes);
    }
    write_artifact(output, "vector-suite.jsonl", &suite_bytes);

    println!(
        "generation_two_package_digest={}",
        suite.generation_two_package_digest
    );
    println!(
        "generation_two_statement_id={}",
        suite.generation_two_statement_id
    );
    println!(
        "generation_two_activation_id={}",
        suite.generation_two_activation_id
    );
    println!(
        "generation_two_accepted_event_id={}",
        suite.generation_two_accepted_event_id
    );
    println!("rollback_statement_id={}", suite.rollback_statement_id);
    println!("rollback_activation_id={}", suite.rollback_activation_id);
    println!(
        "rollback_accepted_event_id={}",
        suite.rollback_accepted_event_id
    );
    println!("rival_statement_id={}", suite.rival_statement_id);
    println!("rival_activation_id={}", suite.rival_activation_id);
    println!("contested_set_id={}", suite.contested_set_id);
    println!("resolution_statement_id={}", suite.resolution_statement_id);
    println!("resolution_id={}", suite.resolution_id);
    println!("consistency_key_digest={}", suite.consistency_key_digest);
    println!("positive_cases_digest={}", suite.positive_cases_digest);
    println!("negative_cases_digest={}", suite.negative_cases_digest);
    println!(
        "vector_suite_raw_sha256={}",
        raw_sha256(&framed_record(&suite_bytes))
    );
    println!(
        "vector_suite_digest={}",
        domain_separated_digest(DigestDomain::TestVectorManifest, &suite_bytes)
    );
}
