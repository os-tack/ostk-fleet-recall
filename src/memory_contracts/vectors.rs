//! Authoritative Stage-1 byte-contract fixtures.
//!
//! This module is test-only. Runtime authority must come from trusted pins and
//! activated registry state, never from these public deterministic fixtures.

use std::str::FromStr;

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Deserialize;

use super::{
    ContractError,
    bootstrap::{
        BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1,
        BootstrapSignatureAlgorithm, BootstrapSignerPolicyV1, BootstrapSignerV1,
        BootstrapStatementV1, ConsistencyPartitionKeyV1, GenesisLogEpochV1, PartitionAlgorithm,
        PartitionRecipeV1, verify_pinned_bootstrap,
    },
    canonical::{decode_strict, encode_canonical, parse_strict, require_canonical},
    common::{
        AuthenticatedProjectScopeV1, CanonicalDecimal, CanonicalTimestamp, ContractId, FixedHex32,
        FixedHex64, ProfileReferenceV1, RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, body_digest, domain_separated_digest, framed_digest},
    evidence::{
        EvidenceStatementV1, ReplayDisposition, RepresentationIdentityV1, SourceFactId,
        SourceFactIdentityV1, derive_representation_key, derive_source_fact_id, replay_disposition,
    },
    genesis::{SemanticallyClosedGenesisPackage, fixture_closed_package},
    identity::{
        CanonicalLocatorV1, IdentityDerivationContextV1, IdentityForm, ResourceUri,
        ValidatedIdentityRecipe, derive_resource_uri,
    },
    registry::{ManifestVerifiedRegistryPackage, RegistryEntryKind, RegistryPackageV1},
};

const PROFILE_ARTIFACT: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/canonical-profile.jsonl");
const CONFORMANCE_MANIFEST: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/conformance-manifest.jsonl");
const RESOURCE_LOCATOR: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/resource-locator.jsonl");
const SOURCE_FACT: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/evidence-source-fact.jsonl");
const REPRESENTATION: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/evidence-representation.jsonl");
const EVIDENCE_STATEMENT: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/evidence-statement.jsonl");
const GENESIS_PACKAGE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");
const BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");
const STAGE1_SUITE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/stage1-vector-suite.jsonl");

const PROFILE_DIGEST: &str = "cf22991a86bfc560556c7d04efa4ee6b7b1ee0f49c919b257ea7b4f30f8e4a29";
const VECTOR_MANIFEST_DIGEST: &str =
    "f984f62866fc769df3a5617a2247e3ade694827c1de69e615a7bda68858b4174";
const RESOURCE_DIGEST: &str = "da6e6a2cfdf45740b0b7c3247d4879cfb879344fc303370258292e6695c748a8";
const RESOURCE_URI: &str = "urn:ostk:entity:v1:repository:sha256:da6e6a2cfdf45740b0b7c3247d4879cfb879344fc303370258292e6695c748a8";
const SOURCE_FACT_ID: &str = "afca668a2e62b532b24ff41f852729ff9a1a2797afb0c28fc3ed747aff3eaa7b";
const REPRESENTATION_KEY: &str = "8420741a01af862ea095ae44106dc76a9892fda9498243f4d3983c594eaef879";
const EVIDENCE_EVENT_ID: &str = "93a262e3554a4dec653197c12a0dfd79c651a8de66e5c2e998a311992319115e";
const GENESIS_PACKAGE_DIGEST: &str =
    "5a931fd5551bec47f83adb019f3e794d1b6a759f4501e7ea26a83076d9518177";
const BOOTSTRAP_RECEIPT_DIGEST: &str =
    "084ee06ea7ebf3b1d592d6e5843584485144c0ee5720fcc2124a61a7fcde48f0";
const BOOTSTRAP_STATEMENT_ID: &str =
    "373cd66d2f2f0166d292294779bcee41ff4285dcbdb8307bc48ef8866c5d8285";
const GENESIS_EPOCH_ID: &str = "d35655f3297e1c5eb4503443befb956f93dc5210b46cdc1a4d7d9f2746b8fab2";
const SOURCE_FACT_SHARD: u16 = 14;
const SOURCE_FACT_GENESIS_CHAIN: &str =
    "38391af6b37814235649bd6e2fc0f7afa45b5408718003c41779b33a79f5f70c";
const STAGE1_SUITE_DIGEST: &str =
    "d1168eb31c08d4213d5bf6a481efeea4c26bcad6973ab00ac474ddc7cf9d87d1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConformanceManifest {
    canonical_negative: Vec<CanonicalNegative>,
    canonical_positive: Vec<CanonicalPositive>,
    digest_vectors: Vec<DigestVector>,
    profile_digest: String,
    profile_id: String,
    scalar_vectors: ScalarVectors,
    schema_version: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPositive {
    expected_canonical_utf8_hex: String,
    id: String,
    input_utf8_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalNegative {
    expected: String,
    id: String,
    input_utf8_hex: String,
    operation: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestVector {
    domain: String,
    expected_sha256: String,
    formula: String,
    id: String,
    #[serde(default)]
    input_utf8_hex: Option<String>,
    #[serde(default)]
    parts_utf8_hex: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScalarVectors {
    decimal_invalid: Vec<String>,
    decimal_valid: Vec<String>,
    timestamp_invalid: Vec<String>,
    timestamp_valid: Vec<String>,
}

fn record(artifact: &'static [u8]) -> &'static [u8] {
    let body = artifact
        .strip_suffix(b"\n")
        .expect("contract artifact must have one repository-framing LF");
    assert!(
        !body.ends_with(b"\n"),
        "contract artifact has more than one repository-framing LF"
    );
    assert!(
        !body.contains(&b'\r'),
        "contract artifact must not use CRLF framing"
    );
    body
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::from_str(value).expect("hard-coded digest must be lowercase SHA-256")
}

fn fixture_profile() -> ProfileReferenceV1 {
    ProfileReferenceV1 {
        profile_id: ContractId::new("ostk-canonical-json-v1").unwrap(),
        profile_digest: digest(PROFILE_DIGEST),
        vector_manifest_digest: digest(VECTOR_MANIFEST_DIGEST),
    }
}

fn fixture_scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.fixture").unwrap(),
        ContractId::new("project.fixture").unwrap(),
    )
}

fn complete_genesis_fixture() -> SemanticallyClosedGenesisPackage {
    let base = fixture_closed_package();
    let mut package: RegistryPackageV1 = decode_strict(base.canonical_bytes()).unwrap();
    package.profile = fixture_profile();
    let manifest_verified =
        ManifestVerifiedRegistryPackage::new(package, &fixture_profile()).unwrap();
    SemanticallyClosedGenesisPackage::from_manifest_verified(manifest_verified).unwrap()
}

fn assert_registry_reference(
    package: &SemanticallyClosedGenesisPackage,
    kind: RegistryEntryKind,
    reference: &RegistryReferenceV1,
) {
    let entry = package
        .manifest_verified_package()
        .package()
        .entries
        .iter()
        .find(|entry| {
            entry.kind == kind
                && entry.entry_id == reference.entry_id
                && entry.version == reference.version
        })
        .expect("fixture reference must resolve to one genesis entry");
    assert_eq!(entry.digest().unwrap(), reference.entry_digest);
    assert!(
        package
            .entry(kind, &reference.entry_id, reference.version)
            .is_some()
    );
}

fn key_pair(seed_byte: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed_byte; 32]).unwrap()
}

fn signed_bootstrap_fixture(package: &SemanticallyClosedGenesisPackage) -> BootstrapReceiptV1 {
    let pairs = [key_pair(1), key_pair(2), key_pair(3)];
    let signer_policy = BootstrapSignerPolicyV1 {
        schema_version: 1,
        signers: pairs
            .iter()
            .enumerate()
            .map(|(index, pair)| BootstrapSignerV1 {
                principal_id: ContractId::new(format!("principal.{}", index + 1)).unwrap(),
                algorithm: BootstrapSignatureAlgorithm::Ed25519,
                public_key: FixedHex32::from_bytes(pair.public_key().as_ref().try_into().unwrap()),
            })
            .collect(),
        threshold: 2,
    };
    let statement = BootstrapStatementV1 {
        schema_version: 1,
        profile: fixture_profile(),
        scope: fixture_scope(),
        genesis_registry_package_digest: package.package_digest(),
        genesis_epoch: GenesisLogEpochV1 {
            schema_version: 1,
            profile: fixture_profile(),
            scope: fixture_scope(),
            partition_recipe: PartitionRecipeV1 {
                schema_version: 1,
                recipe_id: ContractId::new("ostk.partition.sha256_prefix64_modulo").unwrap(),
                recipe_version: 1,
                algorithm: PartitionAlgorithm::Sha256Prefix64Modulo,
                seed: FixedHex32::from_bytes([7; 32]),
                shard_count: 16,
            },
        },
        signer_policy_digest: signer_policy.digest().unwrap(),
        signer_policy,
    };
    let statement_id = statement.statement_id().unwrap();
    let mut message = b"ostk-bootstrap-approval-v1\0".to_vec();
    message.extend_from_slice(statement_id.digest().as_bytes());
    let attestations = [1_u8, 2]
        .into_iter()
        .enumerate()
        .map(|(index, seed)| BootstrapAttestationV1 {
            schema_version: 1,
            statement_id,
            signer_principal_id: ContractId::new(format!("principal.{}", index + 1)).unwrap(),
            signature: FixedHex64::from_bytes(
                key_pair(seed).sign(&message).as_ref().try_into().unwrap(),
            ),
        })
        .collect();
    BootstrapReceiptV1 {
        schema_version: 1,
        statement,
        attestations,
    }
}

#[test]
fn profile_descriptor_and_manifest_have_frozen_bytes() {
    let profile = record(PROFILE_ARTIFACT);
    require_canonical(profile).unwrap();
    assert_eq!(
        domain_separated_digest(DigestDomain::CanonicalProfile, profile),
        digest(PROFILE_DIGEST)
    );

    let descriptor: serde_json::Value = serde_json::from_slice(profile).unwrap();
    assert_eq!(
        descriptor["unicode_profile"]["normalization_data_version"],
        "17.0.0"
    );
    assert_eq!(descriptor["unicode_profile"]["normalization"], "NFC");
    assert_eq!(
        descriptor["typed_timestamp_profile"]["syntax"],
        "YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ"
    );
    assert_eq!(
        descriptor["document_limits"]["input_bytes"],
        super::canonical::MAX_INPUT_BYTES
    );
    assert_eq!(
        descriptor["document_limits"]["output_bytes"],
        super::canonical::MAX_OUTPUT_BYTES
    );
    assert_eq!(
        descriptor["document_limits"]["nodes"],
        super::canonical::MAX_NODES
    );
    assert_eq!(
        descriptor["document_limits"]["recursive_container_depth"],
        super::canonical::MAX_DEPTH
    );
    assert_eq!(
        descriptor["collection_limits"]["array_elements"],
        super::canonical::MAX_COLLECTION_ELEMENTS
    );
    assert_eq!(
        descriptor["document_limits"]["string_utf8_bytes"],
        super::canonical::MAX_STRING_BYTES
    );
    assert_eq!(
        descriptor["integer_profile"]["maximum"],
        super::canonical::MAX_SAFE_INTEGER
    );
    assert_eq!(unicode_normalization::UNICODE_VERSION, (17, 0, 0));

    let manifest_bytes = record(CONFORMANCE_MANIFEST);
    require_canonical(manifest_bytes).unwrap();
    assert_eq!(
        domain_separated_digest(DigestDomain::TestVectorManifest, manifest_bytes),
        digest(VECTOR_MANIFEST_DIGEST)
    );
    let manifest: ConformanceManifest = decode_strict(manifest_bytes).unwrap();
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.profile_id, "ostk-canonical-json-v1");
    assert_eq!(manifest.profile_digest, PROFILE_DIGEST);
}

#[test]
fn canonical_positive_and_negative_vectors_are_authoritative() {
    let manifest: ConformanceManifest = decode_strict(record(CONFORMANCE_MANIFEST)).unwrap();
    for vector in manifest.canonical_positive {
        let input = hex::decode(&vector.input_utf8_hex).unwrap();
        let expected = hex::decode(&vector.expected_canonical_utf8_hex).unwrap();
        assert_eq!(
            parse_strict(&input).unwrap().bytes(),
            expected,
            "positive vector {}",
            vector.id
        );
    }
    for vector in manifest.canonical_negative {
        assert_eq!(vector.expected, "reject");
        let input = hex::decode(&vector.input_utf8_hex).unwrap();
        let rejected = match vector.operation.as_str() {
            "parse" => parse_strict(&input).is_err(),
            "require" => require_canonical(&input).is_err(),
            operation => panic!("unknown operation {operation} in {}", vector.id),
        };
        assert!(rejected, "negative vector {} was accepted", vector.id);
    }
}

#[test]
fn digest_and_scalar_vectors_are_authoritative() {
    let manifest: ConformanceManifest = decode_strict(record(CONFORMANCE_MANIFEST)).unwrap();
    for vector in manifest.digest_vectors {
        let actual = match vector.formula.as_str() {
            "domain_separated" => {
                let domain = match vector.domain.as_str() {
                    "ostk-registry-package-v1" => DigestDomain::RegistryPackage,
                    "ostk-registry-entry-v1" => DigestDomain::RegistryEntry,
                    domain => panic!("unknown domain {domain} in {}", vector.id),
                };
                let input = hex::decode(vector.input_utf8_hex.as_deref().unwrap()).unwrap();
                domain_separated_digest(domain, &input)
            }
            "u64_be_length_framed" => {
                assert_eq!(vector.domain, DigestDomain::Partition.prefix());
                let parts = vector
                    .parts_utf8_hex
                    .iter()
                    .map(|part| hex::decode(part).unwrap())
                    .collect::<Vec<_>>();
                let borrowed = parts.iter().map(Vec::as_slice).collect::<Vec<_>>();
                framed_digest(DigestDomain::Partition, &borrowed)
            }
            "body_exact_length" => {
                assert_eq!(vector.domain, DigestDomain::Body.prefix());
                let input = hex::decode(vector.input_utf8_hex.as_deref().unwrap()).unwrap();
                body_digest(&input)
            }
            formula => panic!("unknown digest formula {formula} in {}", vector.id),
        };
        assert_eq!(actual, digest(&vector.expected_sha256), "{}", vector.id);
    }

    for value in manifest.scalar_vectors.timestamp_valid {
        CanonicalTimestamp::parse(value).unwrap();
    }
    for value in manifest.scalar_vectors.timestamp_invalid {
        assert!(
            CanonicalTimestamp::parse(&value).is_err(),
            "accepted {value}"
        );
    }
    for value in manifest.scalar_vectors.decimal_valid {
        CanonicalDecimal::parse(value).unwrap();
    }
    for value in manifest.scalar_vectors.decimal_invalid {
        assert!(CanonicalDecimal::parse(&value).is_err(), "accepted {value}");
    }
}

#[test]
fn resource_locator_bytes_and_uri_are_frozen() {
    let bytes = record(RESOURCE_LOCATOR);
    require_canonical(bytes).unwrap();
    let locator: CanonicalLocatorV1 = decode_strict(bytes).unwrap();
    assert_eq!(encode_canonical(&locator).unwrap(), bytes);
    let locator_digest = domain_separated_digest(DigestDomain::ResourceLocator, bytes);
    assert_eq!(locator_digest, digest(RESOURCE_DIGEST));

    let uri: ResourceUri = RESOURCE_URI.parse().unwrap();
    assert_eq!(uri.identity_form(), IdentityForm::Entity);
    assert_eq!(uri.resource_kind().as_str(), "repository");
    assert_eq!(uri.digest(), locator_digest);
    assert_eq!(uri.to_string(), RESOURCE_URI);

    let package = complete_genesis_fixture();
    let recipe = ValidatedIdentityRecipe::from_package(
        package.manifest_verified_package(),
        &locator.recipe.entry_id,
        locator.recipe.version,
    )
    .unwrap();
    assert_registry_reference(&package, RegistryEntryKind::IdentityRecipe, &locator.recipe);
    let context = IdentityDerivationContextV1::from_trusted_context(
        locator.profile.clone(),
        locator.scope.clone(),
        locator.provider_instance_namespace.clone(),
    );
    assert_eq!(
        derive_resource_uri(&context, &locator, &recipe, None)
            .unwrap()
            .uri(),
        &uri
    );

    assert!(RESOURCE_URI.to_uppercase().parse::<ResourceUri>().is_err());
    assert!(
        format!("urn:ostk:entity:v2:repository:sha256:{RESOURCE_DIGEST}")
            .parse::<ResourceUri>()
            .is_err()
    );
    let mut noncanonical_decimal = locator;
    noncanonical_decimal.components[0].value = "01".into();
    assert!(derive_resource_uri(&context, &noncanonical_decimal, &recipe, None).is_err());
}

#[test]
fn evidence_preimages_and_semantic_ids_are_frozen() {
    let source_bytes = record(SOURCE_FACT);
    require_canonical(source_bytes).unwrap();
    let source: SourceFactIdentityV1 = decode_strict(source_bytes).unwrap();
    assert_eq!(encode_canonical(&source).unwrap(), source_bytes);
    assert_eq!(
        derive_source_fact_id(&source).unwrap().digest(),
        digest(SOURCE_FACT_ID)
    );

    let representation_bytes = record(REPRESENTATION);
    require_canonical(representation_bytes).unwrap();
    let representation: RepresentationIdentityV1 = decode_strict(representation_bytes).unwrap();
    assert_eq!(
        encode_canonical(&representation).unwrap(),
        representation_bytes
    );
    assert_eq!(
        derive_representation_key(&representation).unwrap().digest(),
        digest(REPRESENTATION_KEY)
    );

    let statement_bytes = record(EVIDENCE_STATEMENT);
    require_canonical(statement_bytes).unwrap();
    let statement: EvidenceStatementV1 = decode_strict(statement_bytes).unwrap();
    assert_eq!(encode_canonical(&statement).unwrap(), statement_bytes);
    assert_eq!(
        statement.event_id().unwrap().digest(),
        digest(EVIDENCE_EVENT_ID)
    );
    assert_eq!(statement.source_fact, source);
    assert_eq!(statement.representation, representation);
    assert_eq!(
        statement.canonical_content.content_digest,
        body_digest(b"pub fn main() {}\n")
    );

    let package = complete_genesis_fixture();
    assert_registry_reference(
        &package,
        RegistryEntryKind::ConnectorSchema,
        &source.connector_schema,
    );
    for (kind, reference) in [
        (
            RegistryEntryKind::EvidenceSchema,
            &representation.evidence_schema,
        ),
        (
            RegistryEntryKind::IdentityRecipe,
            &representation.identity_recipe,
        ),
        (
            RegistryEntryKind::RedactionPolicy,
            &representation.redaction_policy,
        ),
        (
            RegistryEntryKind::ClassifierPolicy,
            &representation.classifier_policy,
        ),
        (
            RegistryEntryKind::RetentionPolicy,
            &representation.retention_policy,
        ),
        (
            RegistryEntryKind::PublicationRule,
            &representation.publication_policy,
        ),
    ] {
        assert_registry_reference(&package, kind, reference);
    }

    let encoded = std::str::from_utf8(statement_bytes).unwrap();
    for excluded in [
        "authenticated_ingress_principal_id",
        "connector_instance_id",
        "provider_delivery_id",
        "received_at",
        "storage_identity",
        "committed_offset",
    ] {
        assert!(
            !encoded.contains(excluded),
            "physical field {excluded} entered the semantic preimage"
        );
    }
}

#[test]
fn evidence_negative_vectors_fail_closed() {
    let statement: EvidenceStatementV1 = decode_strict(record(EVIDENCE_STATEMENT)).unwrap();

    let mut mismatched_source = statement.clone();
    mismatched_source.source_fact_id = SourceFactId::from_digest(digest(PROFILE_DIGEST));
    assert!(mismatched_source.event_id().is_err());

    let mut same_representation_different_statement = statement.clone();
    same_representation_different_statement.observed_at =
        CanonicalTimestamp::parse("2026-08-14T12:00:02.000000000Z").unwrap();
    assert_eq!(
        replay_disposition(&statement, &same_representation_different_statement),
        Err(ContractError::RepresentationCollision)
    );

    assert_eq!(
        replay_disposition(&statement, &statement).unwrap(),
        ReplayDisposition::ExactReplay
    );
}

#[test]
fn complete_genesis_and_bootstrap_artifacts_are_frozen() {
    let package_bytes = record(GENESIS_PACKAGE);
    require_canonical(package_bytes).unwrap();
    let manifest_verified =
        ManifestVerifiedRegistryPackage::decode(package_bytes, &fixture_profile()).unwrap();
    let package =
        SemanticallyClosedGenesisPackage::from_manifest_verified(manifest_verified).unwrap();
    assert_eq!(package.canonical_bytes(), package_bytes);
    assert_eq!(
        package.canonical_bytes(),
        complete_genesis_fixture().canonical_bytes()
    );
    assert_eq!(package.package_digest(), digest(GENESIS_PACKAGE_DIGEST));
    assert_eq!(package.entries().len(), 20);

    let receipt_bytes = record(BOOTSTRAP_RECEIPT);
    require_canonical(receipt_bytes).unwrap();
    assert_eq!(
        receipt_bytes,
        encode_canonical(&signed_bootstrap_fixture(&package)).unwrap()
    );
    let receipt_digest = BootstrapReceiptDigest::from_digest(digest(BOOTSTRAP_RECEIPT_DIGEST));
    let verified = verify_pinned_bootstrap(
        receipt_bytes,
        BootstrapPin::from_trusted_config(receipt_digest),
        &fixture_profile(),
        &fixture_scope(),
        &package,
    )
    .unwrap();
    assert_eq!(verified.canonical_bytes(), receipt_bytes);
    assert_eq!(
        verified.receipt_digest().digest(),
        digest(BOOTSTRAP_RECEIPT_DIGEST)
    );
    assert_eq!(
        verified.statement_id().digest(),
        digest(BOOTSTRAP_STATEMENT_ID)
    );
    assert_eq!(verified.epoch_id().digest(), digest(GENESIS_EPOCH_ID));

    let partition_key = ConsistencyPartitionKeyV1 {
        family: ContractId::new("source_fact").unwrap(),
        key_digest: digest(SOURCE_FACT_ID),
    };
    let shard = verified.partition_for(&partition_key).unwrap();
    assert_eq!(shard, SOURCE_FACT_SHARD);
    assert_eq!(
        verified.genesis_chain_digest(shard).unwrap(),
        digest(SOURCE_FACT_GENESIS_CHAIN)
    );
    assert!(verified.genesis_chain_digest(16).is_err());
}

#[test]
fn bootstrap_negative_vectors_fail_closed() {
    let package_manifest =
        ManifestVerifiedRegistryPackage::decode(record(GENESIS_PACKAGE), &fixture_profile())
            .unwrap();
    let package =
        SemanticallyClosedGenesisPackage::from_manifest_verified(package_manifest).unwrap();
    let receipt_bytes = record(BOOTSTRAP_RECEIPT);

    let wrong_pin = BootstrapReceiptDigest::from_digest(digest(PROFILE_DIGEST));
    assert!(matches!(
        verify_pinned_bootstrap(
            receipt_bytes,
            BootstrapPin::from_trusted_config(wrong_pin),
            &fixture_profile(),
            &fixture_scope(),
            &package,
        ),
        Err(ContractError::BootstrapPinMismatch)
    ));

    let mut bad_signature: BootstrapReceiptV1 = decode_strict(receipt_bytes).unwrap();
    let mut signature = *bad_signature.attestations[0].signature.as_bytes();
    signature[0] ^= 0x80;
    bad_signature.attestations[0].signature = FixedHex64::from_bytes(signature);
    let bad_signature_bytes = encode_canonical(&bad_signature).unwrap();
    let bad_signature_pin = BootstrapReceiptDigest::from_digest(domain_separated_digest(
        DigestDomain::BootstrapReceipt,
        &bad_signature_bytes,
    ));
    assert!(matches!(
        verify_pinned_bootstrap(
            &bad_signature_bytes,
            BootstrapPin::from_trusted_config(bad_signature_pin),
            &fixture_profile(),
            &fixture_scope(),
            &package,
        ),
        Err(ContractError::SignatureVerification)
    ));

    let mut below_threshold: BootstrapReceiptV1 = decode_strict(receipt_bytes).unwrap();
    below_threshold.attestations.truncate(1);
    let below_threshold_bytes = encode_canonical(&below_threshold).unwrap();
    let below_threshold_pin = BootstrapReceiptDigest::from_digest(domain_separated_digest(
        DigestDomain::BootstrapReceipt,
        &below_threshold_bytes,
    ));
    assert!(matches!(
        verify_pinned_bootstrap(
            &below_threshold_bytes,
            BootstrapPin::from_trusted_config(below_threshold_pin),
            &fixture_profile(),
            &fixture_scope(),
            &package,
        ),
        Err(ContractError::ApprovalThresholdNotMet)
    ));

    let mut noncanonical = Vec::with_capacity(receipt_bytes.len() + 1);
    noncanonical.push(b' ');
    noncanonical.extend_from_slice(receipt_bytes);
    let noncanonical_pin = BootstrapReceiptDigest::from_digest(domain_separated_digest(
        DigestDomain::BootstrapReceipt,
        &noncanonical,
    ));
    assert!(matches!(
        verify_pinned_bootstrap(
            &noncanonical,
            BootstrapPin::from_trusted_config(noncanonical_pin),
            &fixture_profile(),
            &fixture_scope(),
            &package,
        ),
        Err(ContractError::NotCanonical)
    ));

    let mut incomplete: RegistryPackageV1 = decode_strict(record(GENESIS_PACKAGE)).unwrap();
    let index = incomplete
        .entries
        .iter()
        .position(|entry| entry.kind == RegistryEntryKind::PublicationRule)
        .unwrap();
    incomplete.entries.remove(index);
    incomplete.manifest.remove(index);
    let manifest_only =
        ManifestVerifiedRegistryPackage::new(incomplete, &fixture_profile()).unwrap();
    assert!(
        SemanticallyClosedGenesisPackage::from_manifest_verified(manifest_only).is_err(),
        "manifest closure must not imply semantic genesis closure"
    );
}

#[test]
fn stage1_suite_index_is_canonical_and_fixture_only() {
    let bytes = record(STAGE1_SUITE);
    require_canonical(bytes).unwrap();
    assert_eq!(
        domain_separated_digest(DigestDomain::TestVectorManifest, bytes),
        digest(STAGE1_SUITE_DIGEST)
    );
    let suite: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(suite["schema_version"], 1);
    assert!(
        suite["fixture_authority"]
            .as_str()
            .unwrap()
            .contains("MUST NOT authorize any runtime")
    );
}
