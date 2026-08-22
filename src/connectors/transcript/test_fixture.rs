//! Shared unit-test fixture: the frozen Stage-4 package bound to a synthetic
//! active head, plus a transcript builder.
//!
//! The head here is synthetic on purpose. These are unit tests of the connector,
//! not of activation: `tests/transcript_connector_live.rs` runs the real
//! bootstrap → genesis → successor ceremony against a live database, so the same
//! code paths are exercised once against a synthesized head (fast, exhaustive on
//! the rejection paths) and once against a genuinely activated one.

use std::collections::BTreeMap;

use crate::evidence_ledger::{
    ActiveStage4Package, WriterAuthoritySnapshot, WriterAuthorityWitness, partition_algorithm_label,
};
use crate::memory_contracts::bootstrap::BootstrapReceiptV1;
use crate::memory_contracts::canonical::decode_strict;
use crate::memory_contracts::common::{
    CanonicalTimestamp, ContractId, frozen_profile_reference_v1,
};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, domain_separated_digest};
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::registry::{ManifestVerifiedRegistryPackage, RegistryHeadV1};
use crate::memory_contracts::stage4_target_package::SemanticallyClosedStage4Package;
use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;

use super::canonicalizer::TranscriptConnectorBindingV1;
use super::collector::TranscriptIngressClocksV1;

const BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../../../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");
const TARGET_PACKAGE: &[u8] =
    include_bytes!("../../../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");

/// The single installation coordinate the frozen gen-1 provider-instance recipe
/// requires. A gen-2 transcript connector will require its own; the point of
/// this map is that the recipe decides, not the connector.
pub const INSTALLATION_COORDINATE: &str = "provider_installation_id";

fn record(artifact: &'static [u8]) -> &'static [u8] {
    artifact
        .strip_suffix(b"\n")
        .expect("contract JSONL must have exactly one framing LF")
}

/// The frozen Stage-4 package bound to a synthetic head that activated it.
pub fn active_package() -> ActiveStage4Package {
    let manifest = ManifestVerifiedRegistryPackage::decode(
        record(TARGET_PACKAGE),
        &frozen_profile_reference_v1(),
    )
    .expect("frozen Stage-4 package must decode");
    let package = SemanticallyClosedStage4Package::from_successor_package(
        SemanticallyClosedSuccessorPackage::from_manifest_verified(manifest)
            .expect("frozen Stage-4 package must close"),
    )
    .expect("frozen Stage-4 package must narrow to the Stage-4 target");

    let head = RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: domain_separated_digest(
                DigestDomain::RegistryActivationReceipt,
                b"w2-trans-activation",
            ),
            package_digest: package.package_digest(),
            activation_policy_digest: domain_separated_digest(
                DigestDomain::RegistryActivationStatement,
                b"w2-trans-activation-policy",
            ),
        },
        effective_from: CanonicalTimestamp::parse("2026-08-15T12:00:00.000000000Z").unwrap(),
        effective_until: None,
    };
    let receipt: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
    let genesis_epoch = receipt.statement.genesis_epoch.clone();
    let scope = receipt.statement.scope;
    let recipe = genesis_epoch.partition_recipe.clone();
    let witness = WriterAuthorityWitness::from_authority_snapshot(WriterAuthoritySnapshot {
        head_state: "active".to_owned(),
        generation: 1,
        activation_id: head.head.activation_id,
        package_digest: head.head.package_digest,
        activation_policy_digest: head.head.activation_policy_digest,
        log_epoch_id: genesis_epoch.epoch_id().unwrap(),
        partition_recipe_id: recipe.recipe_id.as_str().to_owned(),
        partition_recipe_version: recipe.recipe_version,
        partition_algorithm: partition_algorithm_label(recipe.algorithm).to_owned(),
        partition_seed: recipe.seed,
        log_shard_count: recipe.shard_count,
        head_scope: scope.clone(),
        bootstrap_scope: scope,
        genesis_epoch,
    })
    .expect("the frozen bootstrap receipt must yield a consistent witness");

    ActiveStage4Package::bind(&package, head, &witness)
        .expect("the frozen package must bind to a head that activated it")
}

/// A binding that supplies exactly the coordinates the frozen recipes demand.
pub fn binding() -> TranscriptConnectorBindingV1 {
    let mut instance_coordinates = BTreeMap::new();
    instance_coordinates.insert(
        ContractId::new(INSTALLATION_COORDINATE).unwrap(),
        "4242".to_owned(),
    );
    TranscriptConnectorBindingV1 {
        ingress_principal_id: ContractId::new("connector.transcript").unwrap(),
        connector_instance_id: ContractId::new("connector.transcript.instance-1").unwrap(),
        instance_coordinates,
    }
}

/// A binding that supplies no coordinates at all.
pub fn binding_without_coordinates() -> TranscriptConnectorBindingV1 {
    TranscriptConnectorBindingV1 {
        instance_coordinates: BTreeMap::new(),
        ..binding()
    }
}

/// Ingress clocks that are ordered and microsecond-aligned.
pub fn clocks() -> TranscriptIngressClocksV1 {
    TranscriptIngressClocksV1 {
        observed_at: CanonicalTimestamp::parse("2026-08-15T13:00:00.000000000Z").unwrap(),
        received_at: CanonicalTimestamp::parse("2026-08-15T13:00:01.000000000Z").unwrap(),
    }
}

/// One transcript line.
pub fn line(kind: &str, session: &str, uid: &str, timestamp: &str, text: &str) -> String {
    format!(
        r#"{{"type":"{kind}","sessionId":"{session}","uuid":"{uid}","timestamp":"{timestamp}","message":{{"role":"{kind}","content":[{{"type":"text","text":{}}}]}}}}"#,
        serde_json::to_string(text).unwrap()
    )
}

/// A two-turn clean transcript.
pub fn clean_transcript(session: &str) -> String {
    format!(
        "{}\n{}\n",
        line(
            "user",
            session,
            "turn-1",
            "2026-08-15T12:30:00.000Z",
            "please check the failing auth test"
        ),
        line(
            "assistant",
            session,
            "turn-2",
            "2026-08-15T12:30:01.000Z",
            "the failure is a missing scope binding"
        )
    )
}

/// The literal redactable secret planted in [`secret_transcript`]. Its turn is
/// staged with the secret replaced; these exact bytes must appear nowhere
/// durable.
pub const PLANTED_REDACTABLE_SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

/// The literal unredactable key material planted in [`secret_transcript`]. Its
/// whole turn is withheld; these exact bytes must appear nowhere durable.
pub const PLANTED_KEY_MATERIAL: &str = "MIIEowIBAAKCAQEAxWITNESSxKEY";

/// A four-turn transcript: two clean turns, one carrying a redactable secret,
/// and one carrying unredactable key material.
pub fn secret_transcript(session: &str) -> String {
    format!(
        "{}\n{}\n{}\n{}\n",
        line(
            "user",
            session,
            "turn-1",
            "2026-08-15T12:30:00.000Z",
            "here is the config"
        ),
        line(
            "assistant",
            session,
            "turn-2",
            "2026-08-15T12:30:01.000Z",
            &format!(
                "-----BEGIN RSA PRIVATE KEY-----\n{PLANTED_KEY_MATERIAL}\n-----END RSA PRIVATE KEY-----"
            )
        ),
        line(
            "user",
            session,
            "turn-3",
            "2026-08-15T12:30:02.000Z",
            &format!("the access key is {PLANTED_REDACTABLE_SECRET} in the env")
        ),
        line(
            "assistant",
            session,
            "turn-4",
            "2026-08-15T12:30:03.000Z",
            "understood, moving on"
        )
    )
}

/// A digest helper used by assertions.
pub fn sha256(bytes: &[u8]) -> Sha256Digest {
    use sha2::Digest as _;
    Sha256Digest::from_bytes(sha2::Sha256::digest(bytes).into())
}
