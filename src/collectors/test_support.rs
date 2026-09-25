//! Shared unit-test fixtures: a generation-3 head bound to one collected
//! connector, and fake credentials built at runtime.

use crate::evidence_ledger::{
    ActiveStage4Package, WriterAuthoritySnapshot, WriterAuthorityWitness, partition_algorithm_label,
};
use crate::memory_contracts::bootstrap::BootstrapReceiptV1;
use crate::memory_contracts::canonical::decode_strict;
use crate::memory_contracts::collected_item::CollectionModeV1;
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, domain_separated_digest};
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::registry::RegistryHeadV1;
use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;

use super::redaction::CollectorRedactorV1;

const BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");

fn record(artifact: &'static [u8]) -> &'static [u8] {
    artifact
        .strip_suffix(b"\n")
        .expect("contract JSONL must have exactly one framing LF")
}

fn synthetic_head(package_digest: Sha256Digest) -> RegistryHeadBindingV1 {
    RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: domain_separated_digest(
                DigestDomain::RegistryActivationReceipt,
                b"collected-items-activation",
            ),
            package_digest,
            activation_policy_digest: domain_separated_digest(
                DigestDomain::RegistryActivationStatement,
                b"collected-items-activation-policy",
            ),
        },
        effective_from: CanonicalTimestamp::parse("2026-09-25T00:00:00.000000000Z").unwrap(),
        effective_until: None,
    }
}

fn witness_for(head: &RegistryHeadBindingV1) -> WriterAuthorityWitness {
    let receipt: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
    let genesis_epoch = receipt.statement.genesis_epoch.clone();
    let scope = receipt.statement.scope;
    let recipe = genesis_epoch.partition_recipe.clone();
    WriterAuthorityWitness::from_authority_snapshot(WriterAuthoritySnapshot {
        head_state: "active".to_owned(),
        generation: 3,
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
    .expect("the frozen bootstrap receipt must yield a consistent witness")
}

fn bind(package: SemanticallyClosedSuccessorPackage, connector: &str) -> ActiveStage4Package {
    let head = synthetic_head(package.package_digest());
    let witness = witness_for(&head);
    ActiveStage4Package::bind_connector(
        package,
        &ContractId::new(connector).unwrap(),
        head,
        &witness,
    )
    .expect("the package must bind to the head that activated it")
}

/// A generation-3 head bound to the connector `mode` admits under.
pub fn generation_three_active(mode: CollectionModeV1) -> ActiveStage4Package {
    let package = crate::registry_witness::compiled_generation_three_package()
        .expect("the compiled generation-3 package closes");
    bind((*package).clone(), mode.connector_schema_id())
}

/// A generation-2 head bound to its git connector: it carries no collected
/// connector at all.
pub fn generation_two_git_active() -> ActiveStage4Package {
    let package = crate::registry_witness::compiled_generation_two_package()
        .expect("the compiled generation-2 package closes");
    bind(
        (*package).clone(),
        crate::memory_contracts::generation2_registry::GIT_CONNECTOR.connector_schema,
    )
}

/// The redactor under the generation-3 head's own redaction guarantee.
pub fn redactor() -> CollectorRedactorV1 {
    CollectorRedactorV1::from_active_package(&generation_three_active(CollectionModeV1::Pull))
        .expect("generation 3 carries generation 1's redaction guarantee")
}

/// A fake credential: `prefix` followed by `body_len` mixed alphanumerics.
///
/// Built at runtime so no credential-shaped literal sits in the source, where
/// a repository secret scanner would rightly flag it.
pub fn fake_credential(prefix: &str, body_len: usize) -> String {
    const ALPHABET: &[u8] = b"A1b2C3d4E5f6G7h8J9k0";
    let body: String = (0..body_len)
        .map(|index| char::from(ALPHABET[index % ALPHABET.len()]))
        .collect();
    format!("{prefix}{body}")
}

/// Join fragments, so a credential prefix never appears whole in a literal.
pub fn joined(parts: &[&str]) -> String {
    parts.concat()
}
