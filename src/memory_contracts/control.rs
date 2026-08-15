//! Pure bootstrap control-event identity and append-chain contracts.
//!
//! This module binds the first accepted control event to already-verified
//! bootstrap authority. Physical placement authenticates the append, but never
//! enters the accepted-event identity.

use serde::{Deserialize, Serialize};

use super::{
    ContractError, ContractResult,
    bootstrap::{
        AppendPositionV1, BootstrapReceiptDigest, BootstrapStatementId, CommittedOffsetV1,
        ConsistencyPartitionKeyV1, EpochId, VerifiedBootstrapReceipt,
    },
    canonical::encode_canonical,
    common::{AuthenticatedProjectScopeV1, ContractId, ProfileReferenceV1},
    digest::{DigestDomain, Sha256Digest, domain_separated_digest, framed_digest},
    evidence::AcceptedEventId,
    genesis::SemanticallyClosedGenesisPackage,
};

const CONTROL_SCHEMA_VERSION: u32 = 1;
const GENESIS_BOOTSTRAP_EVENT_KIND: &str = "control.bootstrap.accepted";
const GENESIS_BOOTSTRAP_CONSISTENCY_FAMILY: &str = "control.bootstrap";

/// Semantic bootstrap acceptance event.
///
/// Receipt, package, profile, scope, and epoch identities are authority-bound.
/// Epoch shard, committed offset, arrival time, and storage coordinates are
/// deliberately absent from this preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisBootstrapEventV1 {
    pub schema_version: u32,
    pub event_kind: ContractId,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub genesis_registry_package_digest: Sha256Digest,
    pub bootstrap_statement_id: BootstrapStatementId,
    pub bootstrap_receipt_digest: BootstrapReceiptDigest,
    pub signer_policy_digest: Sha256Digest,
    pub genesis_epoch_id: EpochId,
}

impl GenesisBootstrapEventV1 {
    /// Materialize the only v1 bootstrap event from verified authority.
    pub fn from_verified(
        bootstrap: &VerifiedBootstrapReceipt,
        package: &SemanticallyClosedGenesisPackage,
    ) -> ContractResult<Self> {
        let statement = &bootstrap.receipt().statement;
        let event = Self {
            schema_version: CONTROL_SCHEMA_VERSION,
            event_kind: ContractId::new(GENESIS_BOOTSTRAP_EVENT_KIND)?,
            profile: statement.profile.clone(),
            scope: statement.scope.clone(),
            genesis_registry_package_digest: package.package_digest(),
            bootstrap_statement_id: bootstrap.statement_id(),
            bootstrap_receipt_digest: bootstrap.receipt_digest(),
            signer_policy_digest: statement.signer_policy_digest,
            genesis_epoch_id: bootstrap.epoch_id(),
        };
        event.validate_against(bootstrap, package)?;
        Ok(event)
    }

    /// Validate both schema shape and every authority-derived binding.
    pub fn validate_against(
        &self,
        bootstrap: &VerifiedBootstrapReceipt,
        package: &SemanticallyClosedGenesisPackage,
    ) -> ContractResult<()> {
        self.validate_shape()?;
        let statement = &bootstrap.receipt().statement;
        if package.package_digest() != statement.genesis_registry_package_digest
            || package.manifest_verified_package().package().profile != statement.profile
            || self.profile != statement.profile
            || self.scope != statement.scope
            || self.genesis_registry_package_digest != package.package_digest()
            || self.bootstrap_statement_id != bootstrap.statement_id()
            || self.bootstrap_receipt_digest != bootstrap.receipt_digest()
            || self.signer_policy_digest != statement.signer_policy_digest
            || self.genesis_epoch_id != bootstrap.epoch_id()
        {
            return Err(ContractError::BootstrapBindingMismatch);
        }
        Ok(())
    }

    /// Derive semantic identity from the canonical event alone.
    pub fn accepted_event_id(&self) -> ContractResult<AcceptedEventId> {
        self.validate_shape()?;
        Ok(AcceptedEventId::from_digest(domain_separated_digest(
            DigestDomain::AcceptedEvent,
            &encode_canonical(self)?,
        )))
    }

    /// The frozen bootstrap serialization key is the verified statement ID.
    pub fn consistency_partition_key(&self) -> ContractResult<ConsistencyPartitionKeyV1> {
        self.validate_shape()?;
        Ok(ConsistencyPartitionKeyV1 {
            family: ContractId::new(GENESIS_BOOTSTRAP_CONSISTENCY_FAMILY)?,
            key_digest: self.bootstrap_statement_id.digest(),
        })
    }

    fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        if self.schema_version != CONTROL_SCHEMA_VERSION
            || self.event_kind.as_str() != GENESIS_BOOTSTRAP_EVENT_KIND
        {
            return Err(ContractError::Schema(
                "invalid genesis bootstrap control event".into(),
            ));
        }
        Ok(())
    }
}

/// Complete, byte-verifiable first append for the bootstrap control event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisBootstrapAppendV1 {
    pub schema_version: u32,
    pub event: GenesisBootstrapEventV1,
    pub accepted_event_id: AcceptedEventId,
    pub consistency_partition_key: ConsistencyPartitionKeyV1,
    pub append_position: AppendPositionV1,
    pub previous_chain_digest: Sha256Digest,
    pub append_chain_digest: Sha256Digest,
}

impl GenesisBootstrapAppendV1 {
    /// Build the first physical append from the verified receipt's partition and
    /// genesis-chain methods. Bootstrap is always committed offset one.
    pub fn from_verified(
        bootstrap: &VerifiedBootstrapReceipt,
        package: &SemanticallyClosedGenesisPackage,
    ) -> ContractResult<Self> {
        let event = GenesisBootstrapEventV1::from_verified(bootstrap, package)?;
        let accepted_event_id = event.accepted_event_id()?;
        let consistency_partition_key = event.consistency_partition_key()?;
        let shard = bootstrap.partition_for(&consistency_partition_key)?;
        let append_position = AppendPositionV1 {
            epoch_id: bootstrap.epoch_id(),
            shard,
            committed_offset: CommittedOffsetV1::new(1)?,
        };
        append_position.validate_for(bootstrap)?;
        let previous_chain_digest = bootstrap.genesis_chain_digest(shard)?;
        let append_chain_digest =
            derive_append_chain_digest(previous_chain_digest, accepted_event_id, &append_position)?;
        let append = Self {
            schema_version: CONTROL_SCHEMA_VERSION,
            event,
            accepted_event_id,
            consistency_partition_key,
            append_position,
            previous_chain_digest,
            append_chain_digest,
        };
        append.validate_against(bootstrap, package)?;
        Ok(append)
    }

    /// Recompute every redundant receipt, package, partition, position, and
    /// chain binding. Deserialized or stored material grants no authority until
    /// this succeeds with the verified bootstrap token.
    pub fn validate_against(
        &self,
        bootstrap: &VerifiedBootstrapReceipt,
        package: &SemanticallyClosedGenesisPackage,
    ) -> ContractResult<()> {
        if self.schema_version != CONTROL_SCHEMA_VERSION {
            return Err(ContractError::Schema(
                "invalid genesis bootstrap append".into(),
            ));
        }
        self.event.validate_against(bootstrap, package)?;
        let expected_event_id = self.event.accepted_event_id()?;
        let expected_key = self.event.consistency_partition_key()?;
        if self.accepted_event_id != expected_event_id
            || self.consistency_partition_key != expected_key
        {
            return Err(ContractError::BootstrapBindingMismatch);
        }

        let expected_shard = bootstrap.partition_for(&expected_key)?;
        self.append_position.validate_for(bootstrap)?;
        if self.append_position.shard != expected_shard
            || self.append_position.committed_offset != CommittedOffsetV1::new(1)?
        {
            return Err(ContractError::BootstrapBindingMismatch);
        }

        let expected_previous = bootstrap.genesis_chain_digest(expected_shard)?;
        let expected_chain = derive_append_chain_digest(
            expected_previous,
            expected_event_id,
            &self.append_position,
        )?;
        if self.previous_chain_digest != expected_previous
            || self.append_chain_digest != expected_chain
        {
            return Err(ContractError::BootstrapBindingMismatch);
        }
        Ok(())
    }
}

/// H1 = framed AppendChain(H0, canonical append position, accepted-event ID).
pub(crate) fn derive_append_chain_digest(
    previous_chain_digest: Sha256Digest,
    accepted_event_id: AcceptedEventId,
    append_position: &AppendPositionV1,
) -> ContractResult<Sha256Digest> {
    let position_bytes = encode_canonical(append_position)?;
    Ok(framed_digest(
        DigestDomain::AppendChain,
        &[
            previous_chain_digest.as_bytes(),
            &position_bytes,
            accepted_event_id.digest().as_bytes(),
        ],
    ))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::memory_contracts::{
        bootstrap::{BootstrapPin, verify_pinned_bootstrap},
        canonical::{decode_strict, require_canonical},
        registry::ManifestVerifiedRegistryPackage,
    };

    const PROFILE_DIGEST: &str = "cf22991a86bfc560556c7d04efa4ee6b7b1ee0f49c919b257ea7b4f30f8e4a29";
    const VECTOR_MANIFEST_DIGEST: &str =
        "f984f62866fc769df3a5617a2247e3ade694827c1de69e615a7bda68858b4174";
    const BOOTSTRAP_RECEIPT_DIGEST: &str =
        "084ee06ea7ebf3b1d592d6e5843584485144c0ee5720fcc2124a61a7fcde48f0";
    const ACCEPTED_EVENT_ID: &str =
        "ca530fad9338a7a35ce7aad78e016f53b88a21846d4a1f53fecdcb1cabbdabe0";
    const CONSISTENCY_KEY_DIGEST: &str =
        "373cd66d2f2f0166d292294779bcee41ff4285dcbdb8307bc48ef8866c5d8285";
    const SELECTED_SHARD: u16 = 5;
    const H0: &str = "a3ca801a63519f957a28d3bae6cd63f8c4edb3e3c851457323b511a8a7a2bce5";
    const H1: &str = "b044f8700a078372645a37ff1329cc0eb4e2e0ffbd374b47fd10935f42920987";
    const APPEND_POSITION_CANONICAL: &[u8] = br#"{"committed_offset":"1","epoch_id":"d35655f3297e1c5eb4503443befb956f93dc5210b46cdc1a4d7d9f2746b8fab2","shard":5}"#;

    const GENESIS_PACKAGE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");
    const BOOTSTRAP_RECEIPT: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");
    const BOOTSTRAP_CONTROL_EVENT: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v1/bootstrap-control-event.jsonl");

    fn record(artifact: &'static [u8]) -> &'static [u8] {
        let body = artifact
            .strip_suffix(b"\n")
            .expect("contract artifact must have one repository-framing LF");
        assert!(!body.ends_with(b"\n"));
        assert!(!body.contains(&b'\r'));
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

    fn fixture_package() -> SemanticallyClosedGenesisPackage {
        let package =
            ManifestVerifiedRegistryPackage::decode(record(GENESIS_PACKAGE), &fixture_profile())
                .unwrap();
        SemanticallyClosedGenesisPackage::from_manifest_verified(package).unwrap()
    }

    fn fixture_bootstrap(package: &SemanticallyClosedGenesisPackage) -> VerifiedBootstrapReceipt {
        verify_pinned_bootstrap(
            record(BOOTSTRAP_RECEIPT),
            BootstrapPin::from_trusted_config(BootstrapReceiptDigest::from_digest(digest(
                BOOTSTRAP_RECEIPT_DIGEST,
            ))),
            &fixture_profile(),
            &fixture_scope(),
            package,
        )
        .unwrap()
    }

    #[test]
    fn bootstrap_control_event_and_chain_match_golden_bytes() {
        let package = fixture_package();
        let bootstrap = fixture_bootstrap(&package);
        let append = GenesisBootstrapAppendV1::from_verified(&bootstrap, &package).unwrap();
        let golden = record(BOOTSTRAP_CONTROL_EVENT);
        require_canonical(golden).unwrap();
        assert_eq!(encode_canonical(&append).unwrap(), golden);

        let decoded: GenesisBootstrapAppendV1 = decode_strict(golden).unwrap();
        assert_eq!(decoded, append);
        decoded.validate_against(&bootstrap, &package).unwrap();
        assert_eq!(
            decoded.event.event_kind.as_str(),
            GENESIS_BOOTSTRAP_EVENT_KIND
        );
        assert_eq!(
            decoded.accepted_event_id.digest(),
            digest(ACCEPTED_EVENT_ID)
        );
        assert_eq!(
            decoded.consistency_partition_key.family.as_str(),
            GENESIS_BOOTSTRAP_CONSISTENCY_FAMILY
        );
        assert_eq!(
            decoded.consistency_partition_key.key_digest,
            digest(CONSISTENCY_KEY_DIGEST)
        );
        assert_eq!(
            decoded.consistency_partition_key.key_digest,
            bootstrap.statement_id().digest()
        );
        assert_eq!(decoded.append_position.shard, SELECTED_SHARD);
        assert_eq!(decoded.previous_chain_digest, digest(H0));
        assert_eq!(
            encode_canonical(&decoded.append_position).unwrap(),
            APPEND_POSITION_CANONICAL
        );
        assert_eq!(decoded.append_chain_digest, digest(H1));

        let semantic_preimage =
            String::from_utf8(encode_canonical(&decoded.event).unwrap()).unwrap();
        for excluded in ["append_position", "committed_offset", "shard"] {
            assert!(
                !semantic_preimage.contains(excluded),
                "physical field {excluded} entered accepted-event identity"
            );
        }
    }

    #[test]
    fn authority_and_derived_field_mutations_fail_closed() {
        let package = fixture_package();
        let bootstrap = fixture_bootstrap(&package);
        let golden: GenesisBootstrapAppendV1 =
            decode_strict(record(BOOTSTRAP_CONTROL_EVENT)).unwrap();

        let mut wrong_kind = golden.clone();
        wrong_kind.event.event_kind = ContractId::new("control.bootstrap.proposed").unwrap();
        assert!(wrong_kind.validate_against(&bootstrap, &package).is_err());

        let mut wrong_signer_policy = golden.clone();
        wrong_signer_policy.event.signer_policy_digest = digest(PROFILE_DIGEST);
        assert!(
            wrong_signer_policy
                .validate_against(&bootstrap, &package)
                .is_err()
        );

        let mut wrong_receipt = golden.clone();
        wrong_receipt.event.bootstrap_receipt_digest =
            BootstrapReceiptDigest::from_digest(digest(PROFILE_DIGEST));
        assert!(
            wrong_receipt
                .validate_against(&bootstrap, &package)
                .is_err()
        );

        let mut wrong_event_id = golden.clone();
        wrong_event_id.accepted_event_id = AcceptedEventId::from_digest(digest(PROFILE_DIGEST));
        assert!(
            wrong_event_id
                .validate_against(&bootstrap, &package)
                .is_err()
        );

        let mut wrong_family = golden.clone();
        wrong_family.consistency_partition_key.family = ContractId::new("source_fact").unwrap();
        assert!(wrong_family.validate_against(&bootstrap, &package).is_err());

        let mut wrong_key = golden.clone();
        wrong_key.consistency_partition_key.key_digest = digest(PROFILE_DIGEST);
        assert!(wrong_key.validate_against(&bootstrap, &package).is_err());

        let mut wrong_shard = golden.clone();
        wrong_shard.append_position.shard = SELECTED_SHARD + 1;
        assert!(wrong_shard.validate_against(&bootstrap, &package).is_err());

        let mut wrong_epoch = golden.clone();
        wrong_epoch.append_position.epoch_id = EpochId::from_digest(digest(PROFILE_DIGEST));
        assert!(wrong_epoch.validate_against(&bootstrap, &package).is_err());

        let mut wrong_h0 = golden.clone();
        wrong_h0.previous_chain_digest = digest(PROFILE_DIGEST);
        assert!(wrong_h0.validate_against(&bootstrap, &package).is_err());

        let mut wrong_h1 = golden;
        wrong_h1.append_chain_digest = digest(PROFILE_DIGEST);
        assert!(wrong_h1.validate_against(&bootstrap, &package).is_err());
    }

    #[test]
    fn physical_position_changes_chain_but_not_event_identity() {
        let package = fixture_package();
        let bootstrap = fixture_bootstrap(&package);
        let golden: GenesisBootstrapAppendV1 =
            decode_strict(record(BOOTSTRAP_CONTROL_EVENT)).unwrap();
        let semantic_id = golden.event.accepted_event_id().unwrap();

        let mut different_position = golden.clone();
        different_position.append_position.committed_offset = CommittedOffsetV1::new(2).unwrap();
        assert_eq!(
            different_position.event.accepted_event_id().unwrap(),
            semantic_id
        );
        assert_ne!(
            derive_append_chain_digest(
                different_position.previous_chain_digest,
                semantic_id,
                &different_position.append_position,
            )
            .unwrap(),
            golden.append_chain_digest
        );
        assert!(
            different_position
                .validate_against(&bootstrap, &package)
                .is_err()
        );

        let noncanonical_offset = String::from_utf8(record(BOOTSTRAP_CONTROL_EVENT).to_vec())
            .unwrap()
            .replace("\"committed_offset\":\"1\"", "\"committed_offset\":\"01\"");
        assert!(decode_strict::<GenesisBootstrapAppendV1>(noncanonical_offset.as_bytes()).is_err());
    }
}
