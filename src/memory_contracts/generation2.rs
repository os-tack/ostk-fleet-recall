//! Generation-2 registry package composition manifest.
//!
//! The manifest is a canonical, profile-bound statement of what a generation-2
//! registry package must contain: the exact Stage-4 carry-forward roots by full
//! reference, the reserved generation-2 body-schema slots whose typed bodies are
//! not wired yet, and the exact generation-1 head the transition must replace.
//!
//! Nothing here activates anything. A [`StructurallyClosedGeneration2Manifest`]
//! proves canonical bytes, closed ordering, exact predecessor-head bytes, and
//! that every listed triple is a member of the closed body-schema slot table. It
//! is not an activation proposal, an approval, a receipt, or a current-head
//! witness, and it cannot make a reserved slot decodable: any package entry that
//! selects a reserved or unknown triple fails closed here exactly as it does in
//! the genesis and successor closures.
//!
//! Invariants: AUTH-04 (only a registry and its activation policy designate
//! normative contracts; a manifest that lists a slot does not admit its body)
//! and REPLAY-01 (the manifest digest is a pure function of canonical bytes, so
//! replaying the same manifest yields the same identity).
//!
//! Widening the closed slot table is a revision, never an edit. The r1
//! artifacts under `contracts/dynamic-memory/v3/registry-gen2/` keep their
//! bytes and their pinned digests forever; the current revision is r2, and the
//! r1 manifest deliberately no longer closes against the widened table. That
//! visible break is the freeze doing its job.

use serde::{Deserialize, Serialize};

use super::{
    ContractError, ContractResult,
    canonical::{decode_strict, encode_canonical, require_canonical},
    common::{ContractId, ProfileReferenceV1, RegistryReferenceV1},
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    genesis::resolve_reference,
    registry::{
        BODY_SCHEMA_SLOTS, BodySchemaSlotClassV1, ManifestVerifiedRegistryPackage,
        RegistryEntryKind, RegistryHeadV1, classify_body_schema_triple,
    },
};

const MANIFEST_SCHEMA_VERSION: u32 = 1;
const SLOT_SCHEMA_VERSION: u32 = 1;
const PREDECESSOR_GENERATION: u32 = 1;
const SUCCESSOR_GENERATION: u32 = 2;
const MAX_CARRY_FORWARD_ROOTS: usize = 64;
const ACTIVATION_POLICY_V2_SCHEMA_VERSION: u32 = 2;
/// Every checked-in vector is public structural material with no authority.
const FIXTURE_AUTHORITY: &str = "test_only_no_runtime_authority";

/// Exact generation-1 activation ID from
/// `contracts/dynamic-memory/v2/successor-activation/activated-head.jsonl`.
const GENERATION1_ACTIVATION_ID_HEX: &str =
    "60fe4eb627dab5e7798a22188218c308063de7eca121ea7f4b267f9ab23db4bb";
/// Exact frozen Stage-4 target package digest carried by that head.
const GENERATION1_PACKAGE_DIGEST_HEX: &str =
    "16f98d5df93b74dab5b2188274cbd1da21d089ff7a64cd8fc29679946e7fe2c9";
/// Exact activation-policy v2 entry digest installed by that head.
const GENERATION1_ACTIVATION_POLICY_DIGEST_HEX: &str =
    "5611a4fea75d0a8132395bf6e3040ce97638a3447e290f5cabc183c1bb9faa6c";

/// The one head a generation-2 transition may replace.
///
/// These bytes are pinned from the checked-in generation-1 activation fixture.
/// Reproducing them is not authority: a repository must still compare-and-swap
/// the durable head inside its own transaction.
pub fn generation1_expected_head() -> ContractResult<RegistryHeadV1> {
    Ok(RegistryHeadV1 {
        activation_id: GENERATION1_ACTIVATION_ID_HEX.parse()?,
        package_digest: GENERATION1_PACKAGE_DIGEST_HEX.parse()?,
        activation_policy_digest: GENERATION1_ACTIVATION_POLICY_DIGEST_HEX.parse()?,
    })
}

/// Canonical projection of one closed body-schema slot.
///
/// The record cannot disagree with the compiled table: `validate` recomputes the
/// class from [`classify_body_schema_triple`] and rejects any other value, so a
/// slot digest always commits to this binary's real dispatch decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodySchemaSlotRecordV1 {
    pub schema_version: u32,
    pub kind: RegistryEntryKind,
    pub entry_schema_id: ContractId,
    pub entry_schema_version: u32,
    pub slot_class: BodySchemaSlotClassV1,
}

impl BodySchemaSlotRecordV1 {
    pub fn validate(&self) -> ContractResult<()> {
        let actual = classify_body_schema_triple(
            self.kind,
            self.entry_schema_id.as_str(),
            self.entry_schema_version,
        );
        if self.schema_version != SLOT_SCHEMA_VERSION
            || self.entry_schema_version == 0
            || actual == BodySchemaSlotClassV1::Unknown
            || actual != self.slot_class
        {
            return Err(ContractError::Schema(format!(
                "body-schema slot ({}, {}, {}) does not match the closed table",
                self.kind.as_str(),
                self.entry_schema_id,
                self.entry_schema_version
            )));
        }
        encode_canonical(self)?;
        Ok(())
    }

    pub fn digest(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::RegistryBodySchemaSlotV1,
            &encode_canonical(self)?,
        ))
    }
}

/// The complete closed slot table as canonical records, in table order.
pub fn body_schema_slot_records() -> ContractResult<Vec<BodySchemaSlotRecordV1>> {
    BODY_SCHEMA_SLOTS
        .iter()
        .map(|slot| {
            let record = BodySchemaSlotRecordV1 {
                schema_version: SLOT_SCHEMA_VERSION,
                kind: slot.kind,
                entry_schema_id: ContractId::new(slot.entry_schema_id)?,
                entry_schema_version: slot.entry_schema_version,
                slot_class: slot.class,
            };
            record.validate()?;
            Ok(record)
        })
        .collect()
}

/// Canonical freeze of the complete closed body-schema slot table.
///
/// Freezing the table as bytes makes any silent widening — a new dispatched
/// triple, a reserved slot quietly promoted — a visible digest change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodySchemaSlotTableV1 {
    pub schema_version: u32,
    pub table_id: ContractId,
    pub fixture_authority: String,
    pub slots: Vec<BodySchemaSlotRecordV1>,
}

impl BodySchemaSlotTableV1 {
    /// Project the compiled table into its canonical record form.
    pub fn from_compiled_table() -> ContractResult<Self> {
        Ok(Self {
            schema_version: SLOT_SCHEMA_VERSION,
            table_id: ContractId::new("registry.body_schema_slots")?,
            fixture_authority: FIXTURE_AUTHORITY.to_owned(),
            slots: body_schema_slot_records()?,
        })
    }

    /// Require the record to equal the compiled table exactly.
    pub fn validate(&self) -> ContractResult<()> {
        if self != &Self::from_compiled_table()? {
            return Err(ContractError::Schema(
                "body-schema slot table differs from the compiled closed table".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }
}

/// One Stage-4 entry a generation-2 package must carry forward unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generation2CarryForwardRootV1 {
    pub kind: RegistryEntryKind,
    pub entry_id: ContractId,
    pub version: u32,
    pub entry_schema_id: ContractId,
    pub entry_schema_version: u32,
    pub entry_digest: Sha256Digest,
}

impl Generation2CarryForwardRootV1 {
    pub fn reference(&self) -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: self.entry_id.clone(),
            version: self.version,
            entry_digest: self.entry_digest,
        }
    }

    fn sort_key(&self) -> (&str, &str, u32) {
        (self.kind.as_str(), self.entry_id.as_str(), self.version)
    }

    fn validate(&self) -> ContractResult<()> {
        let class = classify_body_schema_triple(
            self.kind,
            self.entry_schema_id.as_str(),
            self.entry_schema_version,
        );
        let dispatched = matches!(
            class,
            BodySchemaSlotClassV1::Generation1Dispatched
                | BodySchemaSlotClassV1::Generation2Dispatched
        );
        if self.version == 0 || self.entry_digest == Sha256Digest::ZERO || !dispatched {
            return Err(ContractError::Schema(format!(
                "carry-forward root {}@{} selects the non-dispatched triple ({}, {}, {})",
                self.entry_id,
                self.version,
                self.kind.as_str(),
                self.entry_schema_id,
                self.entry_schema_version
            )));
        }
        Ok(())
    }
}

/// One reserved generation-2 slot a package may name only once a typed body
/// lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generation2ReservedSlotV1 {
    pub kind: RegistryEntryKind,
    pub entry_schema_id: ContractId,
    pub entry_schema_version: u32,
    pub slot_digest: Sha256Digest,
}

impl Generation2ReservedSlotV1 {
    fn sort_key(&self) -> (&str, &str, u32) {
        (
            self.kind.as_str(),
            self.entry_schema_id.as_str(),
            self.entry_schema_version,
        )
    }

    fn validate(&self) -> ContractResult<()> {
        let record = BodySchemaSlotRecordV1 {
            schema_version: SLOT_SCHEMA_VERSION,
            kind: self.kind,
            entry_schema_id: self.entry_schema_id.clone(),
            entry_schema_version: self.entry_schema_version,
            slot_class: BodySchemaSlotClassV1::Generation2Reserved,
        };
        if record.digest()? != self.slot_digest {
            return Err(ContractError::Schema(format!(
                "reserved slot ({}, {}, {}) is not bound to its closed-table digest",
                self.kind.as_str(),
                self.entry_schema_id,
                self.entry_schema_version
            )));
        }
        Ok(())
    }
}

/// Every reserved slot the closed table declares, in canonical order.
pub fn reserved_generation2_slots() -> ContractResult<Vec<Generation2ReservedSlotV1>> {
    body_schema_slot_records()?
        .into_iter()
        .filter(|record| record.slot_class == BodySchemaSlotClassV1::Generation2Reserved)
        .map(|record| {
            Ok(Generation2ReservedSlotV1 {
                kind: record.kind,
                entry_schema_id: record.entry_schema_id.clone(),
                entry_schema_version: record.entry_schema_version,
                slot_digest: record.digest()?,
            })
        })
        .collect()
}

/// Canonical composition rule for the generation `1 -> 2` registry package.
///
/// The record is data. It names the required inventory and the exact head it
/// expects to replace; it grants no approval, threshold, or activation
/// authority, and no field inside it can designate its own normativity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generation2CompositionManifestV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub manifest_id: ContractId,
    pub from_generation: u32,
    pub to_generation: u32,
    pub predecessor_head: RegistryHeadV1,
    pub carry_forward_roots: Vec<Generation2CarryForwardRootV1>,
    pub reserved_slots: Vec<Generation2ReservedSlotV1>,
}

impl Generation2CompositionManifestV1 {
    /// Close the manifest over its own rules without touching any package.
    pub fn validate(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        if self.schema_version != MANIFEST_SCHEMA_VERSION
            || self.from_generation != PREDECESSOR_GENERATION
            || self.to_generation != SUCCESSOR_GENERATION
        {
            return Err(ContractError::Schema(
                "invalid generation-2 composition manifest envelope".into(),
            ));
        }
        if self.predecessor_head != generation1_expected_head()? {
            return Err(ContractError::StaleRegistryHead);
        }
        self.validate_roots()?;
        self.validate_reserved_slots()?;
        encode_canonical(self)?;
        Ok(())
    }

    fn validate_roots(&self) -> ContractResult<()> {
        if self.carry_forward_roots.is_empty()
            || self.carry_forward_roots.len() > MAX_CARRY_FORWARD_ROOTS
        {
            return Err(ContractError::Schema(
                "generation-2 manifest carry-forward root count is invalid".into(),
            ));
        }
        for root in &self.carry_forward_roots {
            root.validate()?;
        }
        if !self
            .carry_forward_roots
            .windows(2)
            .all(|pair| pair[0].sort_key() < pair[1].sort_key())
        {
            return Err(ContractError::NonCanonicalSet {
                field: "carry_forward_roots",
            });
        }
        let mut activation_roots = self
            .carry_forward_roots
            .iter()
            .filter(|root| root.kind == RegistryEntryKind::ActivationPolicy);
        let activation = activation_roots.next().ok_or_else(|| {
            ContractError::Schema(
                "generation-2 manifest lacks its activation-policy v2 root".into(),
            )
        })?;
        if activation_roots.next().is_some()
            || activation.entry_schema_version != ACTIVATION_POLICY_V2_SCHEMA_VERSION
        {
            return Err(ContractError::Schema(
                "generation-2 manifest requires exactly one activation-policy v2 root".into(),
            ));
        }
        Ok(())
    }

    fn validate_reserved_slots(&self) -> ContractResult<()> {
        for slot in &self.reserved_slots {
            slot.validate()?;
        }
        if !self
            .reserved_slots
            .windows(2)
            .all(|pair| pair[0].sort_key() < pair[1].sort_key())
        {
            return Err(ContractError::NonCanonicalSet {
                field: "reserved_slots",
            });
        }
        if self.reserved_slots != reserved_generation2_slots()? {
            return Err(ContractError::Schema(
                "generation-2 manifest reserved slots differ from the closed table".into(),
            ));
        }
        Ok(())
    }

    /// Return the single activation-policy v2 root without assuming validation.
    pub fn activation_policy_root(&self) -> ContractResult<&Generation2CarryForwardRootV1> {
        self.validate()?;
        self.carry_forward_roots
            .iter()
            .find(|root| root.kind == RegistryEntryKind::ActivationPolicy)
            .ok_or_else(|| {
                ContractError::Schema(
                    "generation-2 manifest lacks its activation-policy v2 root".into(),
                )
            })
    }

    pub fn canonical_bytes(&self) -> ContractResult<Vec<u8>> {
        self.validate()?;
        encode_canonical(self)
    }

    pub fn digest(&self) -> ContractResult<Sha256Digest> {
        Ok(domain_separated_digest(
            DigestDomain::Generation2CompositionManifestV1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Manifest that parsed from exact canonical bytes and closed its own rules.
///
/// This typestate is structural on purpose. It proves byte form, ordering,
/// closed-table membership, and the exact predecessor head. It does not prove
/// that any package exists, that the predecessor head is currently durable, or
/// that a generation-2 activation is authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructurallyClosedGeneration2Manifest {
    manifest: Generation2CompositionManifestV1,
    canonical_bytes: Vec<u8>,
    manifest_digest: Sha256Digest,
}

impl StructurallyClosedGeneration2Manifest {
    /// Decode already canonical wire bytes; non-canonical bytes fail closed.
    pub fn decode(input: &[u8]) -> ContractResult<Self> {
        require_canonical(input)?;
        Self::new(decode_strict(input)?)
    }

    pub fn new(manifest: Generation2CompositionManifestV1) -> ContractResult<Self> {
        let canonical_bytes = manifest.canonical_bytes()?;
        let manifest_digest = domain_separated_digest(
            DigestDomain::Generation2CompositionManifestV1,
            &canonical_bytes,
        );
        Ok(Self {
            manifest,
            canonical_bytes,
            manifest_digest,
        })
    }

    pub const fn manifest(&self) -> &Generation2CompositionManifestV1 {
        &self.manifest
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn manifest_digest(&self) -> Sha256Digest {
        self.manifest_digest
    }

    /// Apply the composition closure rule to one manifest-verified package.
    ///
    /// Every listed root must resolve exactly once by full reference, every
    /// package entry must select a dispatched triple, and exactly one
    /// activation-policy v2 entry must be present. Passing this check proves
    /// package composition only; the package is still not an active head.
    pub fn close_against_package(
        &self,
        package: &ManifestVerifiedRegistryPackage,
    ) -> ContractResult<()> {
        for root in &self.manifest.carry_forward_roots {
            let entry = resolve_reference(package.package(), root.kind, &root.reference())?;
            if entry.entry_schema_id != root.entry_schema_id
                || entry.entry_schema_version != root.entry_schema_version
            {
                return Err(ContractError::Schema(format!(
                    "carry-forward root {}@{} resolved to a different body schema",
                    root.entry_id, root.version
                )));
            }
        }

        for entry in &package.package().entries {
            let class = classify_body_schema_triple(
                entry.kind,
                entry.entry_schema_id.as_str(),
                entry.entry_schema_version,
            );
            if !matches!(
                class,
                BodySchemaSlotClassV1::Generation1Dispatched
                    | BodySchemaSlotClassV1::Generation2Dispatched
            ) {
                return Err(ContractError::Schema(format!(
                    "package entry {}@{} selects {} triple ({}, {}, {})",
                    entry.entry_id,
                    entry.version,
                    class.as_str(),
                    entry.kind.as_str(),
                    entry.entry_schema_id,
                    entry.entry_schema_version
                )));
            }
        }

        let activation_entries = package
            .package()
            .entries
            .iter()
            .filter(|entry| {
                entry.kind == RegistryEntryKind::ActivationPolicy
                    && entry.entry_schema_version == ACTIVATION_POLICY_V2_SCHEMA_VERSION
            })
            .count();
        if activation_entries != 1 {
            return Err(ContractError::Schema(
                "package does not contain exactly one activation-policy v2 root".into(),
            ));
        }
        Ok(())
    }
}

impl TryFrom<Generation2CompositionManifestV1> for StructurallyClosedGeneration2Manifest {
    type Error = ContractError;

    fn try_from(value: Generation2CompositionManifestV1) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::Value;
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::memory_contracts::{
        canonical::CanonicalValue,
        common::frozen_profile_reference_v1,
        evidence_v2::RegistryHeadBindingV1,
        genesis::SemanticallyClosedGenesisPackage,
        registry::{RegistryEntryV1, RegistryManifestEntryV1, RegistryPackageV1},
        stage4_target_package::SemanticallyClosedStage4Package,
        successor_package::SemanticallyClosedSuccessorPackage,
    };

    const STAGE4_PACKAGE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");
    const ACTIVATED_HEAD_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-activation/activated-head.jsonl"
    );
    const GENESIS_PACKAGE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");
    const MANIFEST_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/composition-manifest.jsonl"
    );
    const SLOT_TABLE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/registry-gen2/body-schema-slots.jsonl");
    const NEGATIVE_MISSING_REQUIRED_KIND_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-missing-required-kind.jsonl"
    );
    const NEGATIVE_DUPLICATE_ROOT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-duplicate-root.jsonl"
    );
    const NEGATIVE_UNKNOWN_KIND_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-unknown-kind.jsonl"
    );
    const NEGATIVE_WRONG_PREDECESSOR_HEAD_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-wrong-predecessor-head.jsonl"
    );
    const NEGATIVE_V1_KIND_AT_V2_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-v1-kind-at-v2.jsonl"
    );
    const NEGATIVE_RESERVED_WRONG_VERSION_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-reserved-wrong-version.jsonl"
    );
    const NEGATIVE_UNSORTED_ROOTS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-unsorted-roots.jsonl"
    );
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/registry-gen2/vector-suite.jsonl");

    const MANIFEST_R2_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/composition-manifest-r2.jsonl"
    );
    const SLOT_TABLE_R2_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/body-schema-slots-r2.jsonl"
    );
    const NEGATIVE_DUPLICATE_ROOT_R2_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-duplicate-root-r2.jsonl"
    );
    const NEGATIVE_GENERATION2_ONLY_ROOT_R2_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-generation2-only-root-r2.jsonl"
    );
    const NEGATIVE_MISSING_REQUIRED_KIND_R2_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-missing-required-kind-r2.jsonl"
    );
    const NEGATIVE_RESERVED_WRONG_VERSION_R2_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-reserved-wrong-version-r2.jsonl"
    );
    const NEGATIVE_UNKNOWN_KIND_R2_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-unknown-kind-r2.jsonl"
    );
    const NEGATIVE_UNSORTED_ROOTS_R2_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-unsorted-roots-r2.jsonl"
    );
    const NEGATIVE_V1_KIND_AT_V2_R2_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-v1-kind-at-v2-r2.jsonl"
    );
    const NEGATIVE_WRONG_PREDECESSOR_HEAD_R2_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/registry-gen2/negative-wrong-predecessor-head-r2.jsonl"
    );
    const VECTOR_SUITE_R2_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/registry-gen2/vector-suite-r2.jsonl");

    /// The frozen Stage-4 package digest. This constant must never change.
    const STAGE4_PACKAGE_DIGEST_HEX: &str =
        "16f98d5df93b74dab5b2188274cbd1da21d089ff7a64cd8fc29679946e7fe2c9";
    const EXPECTED_MANIFEST_DIGEST: &str =
        "43af63523127e59f1e0128d4ce83aa023987d1eba1ed4de1d754c4d0fd36b337";
    const EXPECTED_SLOT_TABLE_DIGEST: &str =
        "5a4bbcd7e17557cf0215d0932644b5cf3c78028681393249364a959c2c481d43";
    const EXPECTED_VECTOR_SUITE_DIGEST: &str =
        "ec497fd0adb5a850862bbfebdc6f5024422e916919aff59dc02788a9972abefd";
    const EXPECTED_MANIFEST_RAW_SHA256: &str =
        "cad41bb3fdac991cea1d0a56a5dbbd65d259db7373d871bd2468024b26232ee7";
    const EXPECTED_SLOT_TABLE_RAW_SHA256: &str =
        "78f8500aa91ae4f1e3a3213f0dc205c0019c667a7edeec2b0bd88a60352a8dc2";
    const EXPECTED_VECTOR_SUITE_RAW_SHA256: &str =
        "b8503470bf563810d6d6a98b8838d626ad56c76e8bd6b12bc8281c3449c3de88";

    /// r1 froze exactly seven reserved slots and 32 closed-table triples.
    const R1_RESERVED_SLOT_COUNT: usize = 7;
    const R1_SLOT_TABLE_LEN: usize = 32;

    const EXPECTED_MANIFEST_R2_DIGEST: &str =
        "6d6e8ac25bab65b8faa1c9399aec70a319143c6401d6205e918b108ad369a4ed";
    const EXPECTED_SLOT_TABLE_R2_DIGEST: &str =
        "a3db241757b3e5a8f02680557e5568a1e83ac97ff4e934c1ebc36618a00e877d";
    const EXPECTED_VECTOR_SUITE_R2_DIGEST: &str =
        "8d6929de2d3af569b8d7f9d603c3185786948ba7d23d1594b9c89674c9dc7ef8";
    const EXPECTED_MANIFEST_R2_RAW_SHA256: &str =
        "532c58564b8053e8cecb90ea0972639aefe200e393ecf7d32544f0ffec1ca44b";
    const EXPECTED_SLOT_TABLE_R2_RAW_SHA256: &str =
        "90d79dcb6c11691a67e7163f8f0c5eef079df1c41a621e6eb769e6ff3a1a1658";
    const EXPECTED_VECTOR_SUITE_R2_RAW_SHA256: &str =
        "211edfe7c97f0abd25b8a797def76af24b41960d88b196575b87b8169821ceeb";

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NegativeArtifactPinV1 {
        case_id: ContractId,
        path: String,
        raw_sha256: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Generation2VectorSuiteV1 {
        schema_version: u32,
        suite_id: ContractId,
        fixture_authority: String,
        manifest_path: String,
        manifest_digest: Sha256Digest,
        manifest_raw_sha256: String,
        slot_table_path: String,
        slot_table_digest: Sha256Digest,
        slot_table_raw_sha256: String,
        predecessor_head: RegistryHeadV1,
        stage4_package_digest: Sha256Digest,
        negative_artifacts: Vec<NegativeArtifactPinV1>,
    }

    fn record(bytes: &[u8]) -> &[u8] {
        let body = bytes
            .strip_suffix(b"\n")
            .expect("contract artifact must have exactly one framing LF");
        assert!(!body.ends_with(b"\n"));
        assert!(!body.contains(&b'\r'));
        body
    }

    fn digest(value: &str) -> Sha256Digest {
        value.parse().unwrap()
    }

    fn raw_sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn framed_raw_sha256(bytes: &[u8]) -> String {
        let mut framed = bytes.to_vec();
        framed.push(b'\n');
        raw_sha256(&framed)
    }

    fn manifest_domain_digest(bytes: &[u8]) -> Sha256Digest {
        domain_separated_digest(DigestDomain::TestVectorManifest, bytes)
    }

    fn stage4_package() -> RegistryPackageV1 {
        decode_strict(record(STAGE4_PACKAGE_FIXTURE)).unwrap()
    }

    fn genesis_package() -> RegistryPackageV1 {
        decode_strict(record(GENESIS_PACKAGE_FIXTURE)).unwrap()
    }

    fn verified(package: RegistryPackageV1) -> ManifestVerifiedRegistryPackage {
        ManifestVerifiedRegistryPackage::new(package, &frozen_profile_reference_v1()).unwrap()
    }

    fn rebuild(mut package: RegistryPackageV1) -> RegistryPackageV1 {
        package.entries.sort_by(|left, right| {
            (left.kind.as_str(), left.entry_id.as_str(), left.version).cmp(&(
                right.kind.as_str(),
                right.entry_id.as_str(),
                right.version,
            ))
        });
        package.manifest = package
            .entries
            .iter()
            .map(|entry| RegistryManifestEntryV1 {
                kind: entry.kind,
                entry_id: entry.entry_id.clone(),
                version: entry.version,
                entry_digest: entry.digest().unwrap(),
            })
            .collect();
        package
    }

    fn stage4_target() -> SemanticallyClosedStage4Package {
        let successor =
            SemanticallyClosedSuccessorPackage::from_manifest_verified(verified(stage4_package()))
                .unwrap();
        SemanticallyClosedStage4Package::from_successor_package(successor).unwrap()
    }

    /// One entry copied out of the frozen Stage-4 package by exact tuple.
    fn stage4_entry(kind: RegistryEntryKind, entry_id: &str, version: u32) -> RegistryEntryV1 {
        stage4_package()
            .entries
            .into_iter()
            .find(|entry| {
                entry.kind == kind
                    && entry.entry_id.as_str() == entry_id
                    && entry.version == version
            })
            .expect("frozen Stage-4 root must exist")
    }

    fn root(
        kind: RegistryEntryKind,
        entry_id: &str,
        version: u32,
    ) -> Generation2CarryForwardRootV1 {
        let entry = stage4_entry(kind, entry_id, version);
        Generation2CarryForwardRootV1 {
            kind,
            entry_id: entry.entry_id.clone(),
            version: entry.version,
            entry_schema_id: entry.entry_schema_id.clone(),
            entry_schema_version: entry.entry_schema_version,
            entry_digest: entry.digest().unwrap(),
        }
    }

    fn carry_forward_roots() -> Vec<Generation2CarryForwardRootV1> {
        vec![
            root(RegistryEntryKind::ActivationPolicy, "activation.default", 2),
            root(
                RegistryEntryKind::AuthorityRule,
                "remember.actor_assertion",
                3,
            ),
            root(
                RegistryEntryKind::ConnectorSchema,
                "connector.github.push",
                3,
            ),
            root(
                RegistryEntryKind::PredicateSchema,
                "mcp.remember.allowed_actions",
                3,
            ),
            root(
                RegistryEntryKind::RelationProof,
                "relation.repository_parent",
                2,
            ),
        ]
    }

    fn manifest() -> Generation2CompositionManifestV1 {
        Generation2CompositionManifestV1 {
            schema_version: 1,
            profile: frozen_profile_reference_v1(),
            manifest_id: ContractId::new("generation2.composition").unwrap(),
            from_generation: 1,
            to_generation: 2,
            predecessor_head: generation1_expected_head().unwrap(),
            carry_forward_roots: carry_forward_roots(),
            reserved_slots: reserved_generation2_slots().unwrap(),
        }
    }

    /// The required set loses its activation-policy v2 root. Every other rule
    /// still holds, so only the "exactly one activation-policy v2 root" clause
    /// can reject it.
    fn negative_missing_required_kind() -> Generation2CompositionManifestV1 {
        let mut value = manifest();
        value
            .carry_forward_roots
            .retain(|root| root.kind != RegistryEntryKind::ActivationPolicy);
        value
    }

    fn negative_duplicate_root() -> Generation2CompositionManifestV1 {
        let mut value = manifest();
        let duplicate = value.carry_forward_roots[2].clone();
        value.carry_forward_roots.insert(3, duplicate);
        value
    }

    fn negative_wrong_predecessor_head() -> Generation2CompositionManifestV1 {
        let mut value = manifest();
        let mut activation_id = *value.predecessor_head.activation_id.as_bytes();
        activation_id[31] ^= 0x01;
        value.predecessor_head.activation_id = Sha256Digest::from_bytes(activation_id);
        value
    }

    fn negative_v1_kind_at_v2() -> Generation2CompositionManifestV1 {
        let mut value = manifest();
        let mut retention = root(
            RegistryEntryKind::RelationProof,
            "relation.repository_parent",
            2,
        );
        retention.kind = RegistryEntryKind::RetentionPolicy;
        retention.entry_id = ContractId::new("retention.default").unwrap();
        retention.version = 3;
        retention.entry_schema_id = ContractId::new("registry.retention_policy").unwrap();
        retention.entry_schema_version = 2;
        value.carry_forward_roots.push(retention);
        value
    }

    fn negative_reserved_wrong_version() -> Generation2CompositionManifestV1 {
        let mut value = manifest();
        let slot = value
            .reserved_slots
            .iter_mut()
            .find(|slot| slot.kind == RegistryEntryKind::ParserContract)
            .unwrap();
        slot.entry_schema_version = 2;
        value
    }

    /// A carry-forward root must select a dispatched triple. A generation-2-only
    /// kind never can, so naming one as a root is rejected even though the root
    /// is otherwise well formed and in canonical position.
    fn negative_generation2_only_root() -> Generation2CompositionManifestV1 {
        let mut value = manifest();
        value.carry_forward_roots.insert(
            3,
            Generation2CarryForwardRootV1 {
                kind: RegistryEntryKind::ConsolidationPolicy,
                entry_id: ContractId::new("consolidation.default").unwrap(),
                version: 1,
                entry_schema_id: ContractId::new("registry.consolidation_policy").unwrap(),
                entry_schema_version: 1,
                entry_digest: domain_separated_digest(
                    DigestDomain::RegistryEntry,
                    b"consolidation.default@1",
                ),
            },
        );
        value
    }

    fn negative_unsorted_roots() -> Generation2CompositionManifestV1 {
        let mut value = manifest();
        value.carry_forward_roots.swap(0, 1);
        value
    }

    /// A kind name outside the closed enum can only be produced at the byte
    /// level; no typed constructor can express it.
    fn negative_unknown_kind_bytes() -> Vec<u8> {
        let mut value = serde_json::to_value(manifest()).unwrap();
        value
            .get_mut("carry_forward_roots")
            .and_then(Value::as_array_mut)
            .and_then(|roots| roots.get_mut(2))
            .and_then(Value::as_object_mut)
            .unwrap()
            .insert(
                "kind".into(),
                Value::String("transcript_session_connector".into()),
            );
        encode_canonical(&value).unwrap()
    }

    fn negative_artifact_bytes() -> Vec<(&'static str, &'static str, Vec<u8>)> {
        vec![
            (
                "duplicate_root",
                "negative-duplicate-root-r2.jsonl",
                encode_canonical(&negative_duplicate_root()).unwrap(),
            ),
            (
                "generation2_only_root",
                "negative-generation2-only-root-r2.jsonl",
                encode_canonical(&negative_generation2_only_root()).unwrap(),
            ),
            (
                "missing_required_kind",
                "negative-missing-required-kind-r2.jsonl",
                encode_canonical(&negative_missing_required_kind()).unwrap(),
            ),
            (
                "reserved_triple_wrong_version",
                "negative-reserved-wrong-version-r2.jsonl",
                encode_canonical(&negative_reserved_wrong_version()).unwrap(),
            ),
            (
                "unknown_kind",
                "negative-unknown-kind-r2.jsonl",
                negative_unknown_kind_bytes(),
            ),
            (
                "unsorted_roots",
                "negative-unsorted-roots-r2.jsonl",
                encode_canonical(&negative_unsorted_roots()).unwrap(),
            ),
            (
                "v1_kind_claimed_at_v2",
                "negative-v1-kind-at-v2-r2.jsonl",
                encode_canonical(&negative_v1_kind_at_v2()).unwrap(),
            ),
            (
                "wrong_predecessor_head",
                "negative-wrong-predecessor-head-r2.jsonl",
                encode_canonical(&negative_wrong_predecessor_head()).unwrap(),
            ),
        ]
    }

    fn vector_suite_r2() -> Generation2VectorSuiteV1 {
        let manifest_bytes = encode_canonical(&manifest()).unwrap();
        let table = BodySchemaSlotTableV1::from_compiled_table().unwrap();
        let table_bytes = encode_canonical(&table).unwrap();
        Generation2VectorSuiteV1 {
            schema_version: 1,
            suite_id: ContractId::new("registry.generation2.composition.r2").unwrap(),
            fixture_authority: FIXTURE_AUTHORITY.to_owned(),
            manifest_path: "composition-manifest-r2.jsonl".into(),
            manifest_digest: manifest().digest().unwrap(),
            manifest_raw_sha256: framed_raw_sha256(&manifest_bytes),
            slot_table_path: "body-schema-slots-r2.jsonl".into(),
            slot_table_digest: manifest_domain_digest(&table_bytes),
            slot_table_raw_sha256: framed_raw_sha256(&table_bytes),
            predecessor_head: generation1_expected_head().unwrap(),
            stage4_package_digest: digest(STAGE4_PACKAGE_DIGEST_HEX),
            negative_artifacts: negative_artifact_bytes()
                .into_iter()
                .map(|(case_id, path, bytes)| NegativeArtifactPinV1 {
                    case_id: ContractId::new(case_id).unwrap(),
                    path: path.into(),
                    raw_sha256: framed_raw_sha256(&bytes),
                })
                .collect(),
        }
    }

    /// A generation-2-only entry any caller can propose but no closure admits.
    fn generation2_only_entry(kind: RegistryEntryKind, schema_id: &str) -> RegistryEntryV1 {
        let source = stage4_entry(RegistryEntryKind::ActivationPolicy, "activation.default", 2);
        RegistryEntryV1 {
            schema_version: 1,
            kind,
            entry_id: ContractId::new("generation2.reserved").unwrap(),
            version: 1,
            entry_schema_id: ContractId::new(schema_id).unwrap(),
            entry_schema_version: 1,
            body: CanonicalValue::Object(std::collections::BTreeMap::from([(
                "schema_version".to_owned(),
                CanonicalValue::Integer(1),
            )])),
            positive_vector_digest: source.positive_vector_digest,
            negative_vector_digest: source.negative_vector_digest,
        }
    }

    #[test]
    fn frozen_stage4_package_digest_is_unchanged() {
        let target = stage4_target();
        assert_eq!(target.package_digest(), digest(STAGE4_PACKAGE_DIGEST_HEX));
        assert_eq!(
            generation1_expected_head().unwrap().package_digest,
            digest(STAGE4_PACKAGE_DIGEST_HEX)
        );
        assert_eq!(
            target.activation_policy().registry_reference().entry_digest,
            generation1_expected_head()
                .unwrap()
                .activation_policy_digest
        );

        // The hex constants in this module are a copy of the checked-in
        // generation-1 head. Re-freezing that head without re-freezing the
        // manifest must fail here rather than silently retarget a transition.
        let binding: RegistryHeadBindingV1 = decode_strict(record(ACTIVATED_HEAD_FIXTURE)).unwrap();
        assert_eq!(binding.head, generation1_expected_head().unwrap());
    }

    #[test]
    fn every_generation1_closure_rejects_generation2_only_kinds() {
        // Exactly the generation-2-only set: a new such kind that skips this
        // loop fails the count assertion below instead of escaping coverage.
        let generation2_only = [
            (
                RegistryEntryKind::ArrowBatchSchema,
                "registry.arrow_batch_schema",
            ),
            (
                RegistryEntryKind::ComparatorLineage,
                "registry.comparator_lineage",
            ),
            (
                RegistryEntryKind::ConsolidationPolicy,
                "registry.consolidation_policy",
            ),
            (
                RegistryEntryKind::LogEpochRecipe,
                "registry.log_epoch_recipe",
            ),
            (
                RegistryEntryKind::ParserContract,
                "registry.parser_contract",
            ),
        ];
        assert_eq!(
            generation2_only.map(|(kind, _)| kind).to_vec(),
            crate::memory_contracts::registry::ALL_REGISTRY_ENTRY_KINDS
                .into_iter()
                .filter(|kind| kind.is_generation2_only())
                .collect::<Vec<_>>()
        );
        for (kind, schema_id) in generation2_only {
            let mut genesis = genesis_package();
            genesis
                .entries
                .push(generation2_only_entry(kind, schema_id));
            let genesis_error = SemanticallyClosedGenesisPackage::from_manifest_verified(verified(
                rebuild(genesis),
            ))
            .unwrap_err();
            assert!(
                matches!(&genesis_error, ContractError::Schema(message)
                    if message.contains("generation-2-only kind")),
                "{genesis_error:?}"
            );

            let mut stage4 = stage4_package();
            stage4.entries.push(generation2_only_entry(kind, schema_id));
            let successor_error = SemanticallyClosedSuccessorPackage::from_manifest_verified(
                verified(rebuild(stage4)),
            )
            .unwrap_err();
            assert!(
                matches!(&successor_error, ContractError::Schema(message)
                    if message.contains("generation-2-only kind")),
                "{successor_error:?}"
            );
        }

        // The Stage-4 target closure consumes a semantically closed successor
        // package, so it cannot even be offered a generation-2-only entry; the
        // frozen inventory independently contains none.
        let frozen = stage4_package();
        assert_eq!(frozen.entries.len(), 27);
        assert!(
            !frozen
                .entries
                .iter()
                .any(|entry| entry.kind.is_generation2_only())
        );
        assert!(
            stage4_target()
                .successor_package()
                .manifest_verified_package()
                .package()
                .entries
                .iter()
                .all(|entry| {
                    classify_body_schema_triple(
                        entry.kind,
                        entry.entry_schema_id.as_str(),
                        entry.entry_schema_version,
                    ) != BodySchemaSlotClassV1::Unknown
                })
        );
    }

    #[test]
    fn reserved_generation2_triples_fail_closed_in_the_successor_closure() {
        // Every reserved v2 triple the closed table declares for a kind that
        // already exists at v1. Naming one must fail before any body decode,
        // because no typed body is wired for it yet.
        let reserved_v2 = [
            (RegistryEntryKind::CoverageProof, "registry.coverage_proof"),
            (RegistryEntryKind::EpisodePolicy, "registry.episode_policy"),
            (
                RegistryEntryKind::NormativeBindingSchema,
                "registry.normative_binding_schema",
            ),
            (
                RegistryEntryKind::ObserverAdmission,
                "registry.observer_admission",
            ),
        ];
        for (kind, schema_id) in reserved_v2 {
            assert_eq!(
                classify_body_schema_triple(kind, schema_id, 2),
                BodySchemaSlotClassV1::Generation2Reserved
            );
            let mut stage4 = stage4_package();
            let mut reserved = generation2_only_entry(kind, schema_id);
            reserved.entry_schema_version = 2;
            stage4.entries.push(reserved);
            let error = SemanticallyClosedSuccessorPackage::from_manifest_verified(verified(
                rebuild(stage4),
            ))
            .unwrap_err();
            assert!(
                matches!(&error, ContractError::Schema(message)
                    if message.contains("reserved generation-2 body schema")),
                "{error:?}"
            );
        }
        // The reserved set the manifest freezes is exactly the reserved class
        // of the closed table, so this list plus the three generation-2-only
        // kinds is the whole reservation.
        assert_eq!(
            reserved_generation2_slots().unwrap().len(),
            R1_RESERVED_SLOT_COUNT + 2
        );
    }

    #[test]
    fn manifest_closes_against_the_frozen_stage4_package() {
        let closed = StructurallyClosedGeneration2Manifest::new(manifest()).unwrap();
        closed
            .close_against_package(
                stage4_target()
                    .successor_package()
                    .manifest_verified_package(),
            )
            .unwrap();
        let activation = closed.manifest().activation_policy_root().unwrap();
        assert_eq!(
            activation.entry_digest,
            generation1_expected_head()
                .unwrap()
                .activation_policy_digest
        );
        assert_eq!(activation.entry_schema_version, 2);
    }

    #[test]
    fn package_closure_rejects_missing_roots_and_reserved_triples() {
        let closed = StructurallyClosedGeneration2Manifest::new(manifest()).unwrap();

        let mut missing = stage4_package();
        missing
            .entries
            .retain(|entry| entry.kind != RegistryEntryKind::RelationProof);
        let error = closed
            .close_against_package(&verified(rebuild(missing)))
            .unwrap_err();
        assert!(
            matches!(&error, ContractError::Schema(message) if message.contains("missing exact")),
            "{error:?}"
        );

        let mut reserved = stage4_package();
        reserved.entries.push(generation2_only_entry(
            RegistryEntryKind::ParserContract,
            "registry.parser_contract",
        ));
        let error = closed
            .close_against_package(&verified(rebuild(reserved)))
            .unwrap_err();
        assert!(
            matches!(&error, ContractError::Schema(message)
                if message.contains("generation2_reserved")),
            "{error:?}"
        );

        let mut drifted = stage4_package();
        let root = closed.manifest().carry_forward_roots[2].clone();
        for entry in &mut drifted.entries {
            if entry.entry_id == root.entry_id && entry.kind == root.kind {
                entry.version += 1;
            }
        }
        let error = closed
            .close_against_package(&verified(rebuild(drifted)))
            .unwrap_err();
        assert!(
            matches!(&error, ContractError::Schema(message) if message.contains("missing exact")),
            "{error:?}"
        );
    }

    #[test]
    fn manifest_negative_cases_fail_closed_in_memory() {
        for value in [
            negative_missing_required_kind(),
            negative_duplicate_root(),
            negative_wrong_predecessor_head(),
            negative_v1_kind_at_v2(),
            negative_reserved_wrong_version(),
            negative_unsorted_roots(),
            negative_generation2_only_root(),
        ] {
            assert!(StructurallyClosedGeneration2Manifest::new(value).is_err());
        }
        assert!(
            StructurallyClosedGeneration2Manifest::decode(&negative_unknown_kind_bytes()).is_err()
        );

        let mut wrong_generation = manifest();
        wrong_generation.to_generation = 3;
        assert!(StructurallyClosedGeneration2Manifest::new(wrong_generation).is_err());

        // The reserved set is required to equal the compiled table exactly, so
        // dropping one reserved slot is as fatal as renaming it.
        let mut dropped_reserved_slot = manifest();
        dropped_reserved_slot
            .reserved_slots
            .retain(|slot| slot.kind != RegistryEntryKind::CoverageProof);
        assert!(StructurallyClosedGeneration2Manifest::new(dropped_reserved_slot).is_err());

        let mut wrong_profile = manifest();
        wrong_profile.profile.profile_digest = Sha256Digest::ZERO;
        assert_eq!(
            StructurallyClosedGeneration2Manifest::new(wrong_profile),
            Err(ContractError::ProfileMismatch)
        );

        let canonical = encode_canonical(&manifest()).unwrap();
        let mut noncanonical = vec![b' '];
        noncanonical.extend_from_slice(&canonical);
        assert_eq!(
            StructurallyClosedGeneration2Manifest::decode(&noncanonical),
            Err(ContractError::NotCanonical)
        );
    }

    #[test]
    fn r1_artifacts_stay_byte_frozen_and_are_superseded_by_r2() {
        // Raw hashes and domain digests are pure functions of the file bytes,
        // so these hold no matter what the compiled table now says. If any r1
        // file were edited or regenerated, this is what would fail.
        for (fixture, expected) in [
            (MANIFEST_FIXTURE, EXPECTED_MANIFEST_RAW_SHA256),
            (SLOT_TABLE_FIXTURE, EXPECTED_SLOT_TABLE_RAW_SHA256),
            (VECTOR_SUITE_FIXTURE, EXPECTED_VECTOR_SUITE_RAW_SHA256),
        ] {
            assert_eq!(raw_sha256(fixture), expected);
        }
        assert_eq!(
            domain_separated_digest(
                DigestDomain::Generation2CompositionManifestV1,
                record(MANIFEST_FIXTURE),
            ),
            digest(EXPECTED_MANIFEST_DIGEST)
        );
        assert_eq!(
            manifest_domain_digest(record(SLOT_TABLE_FIXTURE)),
            digest(EXPECTED_SLOT_TABLE_DIGEST)
        );
        assert_eq!(
            manifest_domain_digest(record(VECTOR_SUITE_FIXTURE)),
            digest(EXPECTED_VECTOR_SUITE_DIGEST)
        );

        // The r1 suite still parses and still pins its own negatives exactly.
        let suite: Generation2VectorSuiteV1 = decode_strict(record(VECTOR_SUITE_FIXTURE)).unwrap();
        assert_eq!(suite.suite_id.as_str(), "registry.generation2.composition");
        assert_eq!(suite.manifest_digest, digest(EXPECTED_MANIFEST_DIGEST));
        assert_eq!(suite.slot_table_digest, digest(EXPECTED_SLOT_TABLE_DIGEST));
        assert_eq!(suite.predecessor_head, generation1_expected_head().unwrap());
        assert_eq!(
            suite.stage4_package_digest,
            digest(STAGE4_PACKAGE_DIGEST_HEX)
        );
        for (pin, fixture) in suite.negative_artifacts.iter().zip([
            NEGATIVE_DUPLICATE_ROOT_FIXTURE,
            NEGATIVE_MISSING_REQUIRED_KIND_FIXTURE,
            NEGATIVE_RESERVED_WRONG_VERSION_FIXTURE,
            NEGATIVE_UNKNOWN_KIND_FIXTURE,
            NEGATIVE_UNSORTED_ROOTS_FIXTURE,
            NEGATIVE_V1_KIND_AT_V2_FIXTURE,
            NEGATIVE_WRONG_PREDECESSOR_HEAD_FIXTURE,
        ]) {
            assert_eq!(pin.raw_sha256, raw_sha256(fixture), "{}", pin.path);
            require_canonical(record(fixture)).unwrap();
            assert!(StructurallyClosedGeneration2Manifest::decode(record(fixture)).is_err());
        }

        // Widening the closed table supersedes r1 instead of editing it. r1
        // reserved seven slots; the compiled table now reserves nine, so the
        // r1 manifest no longer closes and the r1 slot-table projection no
        // longer equals the compiled table. That visible break is the freeze
        // doing its job: a silently widened table would have kept passing.
        let error =
            StructurallyClosedGeneration2Manifest::decode(record(MANIFEST_FIXTURE)).unwrap_err();
        assert!(
            matches!(&error, ContractError::Schema(message)
                if message.contains("reserved slots differ from the closed table")),
            "{error:?}"
        );
        let r1_table: BodySchemaSlotTableV1 = decode_strict(record(SLOT_TABLE_FIXTURE)).unwrap();
        assert_eq!(r1_table.slots.len(), R1_SLOT_TABLE_LEN);
        assert_eq!(
            r1_table
                .slots
                .iter()
                .filter(|slot| slot.slot_class == BodySchemaSlotClassV1::Generation2Reserved)
                .count(),
            R1_RESERVED_SLOT_COUNT
        );
        assert_ne!(
            r1_table,
            BodySchemaSlotTableV1::from_compiled_table().unwrap()
        );
        assert!(r1_table.validate().is_err());
    }

    #[test]
    fn r2_canonical_artifacts_and_literal_pins_are_frozen() {
        let closed = StructurallyClosedGeneration2Manifest::decode(record(MANIFEST_R2_FIXTURE))
            .expect("frozen r2 manifest must decode");
        assert_eq!(closed.manifest(), &manifest());
        assert_eq!(
            closed.manifest_digest(),
            digest(EXPECTED_MANIFEST_R2_DIGEST)
        );
        assert_eq!(
            closed.manifest().reserved_slots.len(),
            R1_RESERVED_SLOT_COUNT + 2
        );

        let table: BodySchemaSlotTableV1 = decode_strict(record(SLOT_TABLE_R2_FIXTURE)).unwrap();
        table.validate().unwrap();
        assert_eq!(table, BodySchemaSlotTableV1::from_compiled_table().unwrap());
        assert_eq!(table.slots.len(), R1_SLOT_TABLE_LEN + 2);
        assert_eq!(
            manifest_domain_digest(record(SLOT_TABLE_R2_FIXTURE)),
            digest(EXPECTED_SLOT_TABLE_R2_DIGEST)
        );

        for fixture in [
            NEGATIVE_DUPLICATE_ROOT_R2_FIXTURE,
            NEGATIVE_GENERATION2_ONLY_ROOT_R2_FIXTURE,
            NEGATIVE_MISSING_REQUIRED_KIND_R2_FIXTURE,
            NEGATIVE_RESERVED_WRONG_VERSION_R2_FIXTURE,
            NEGATIVE_UNKNOWN_KIND_R2_FIXTURE,
            NEGATIVE_UNSORTED_ROOTS_R2_FIXTURE,
            NEGATIVE_V1_KIND_AT_V2_R2_FIXTURE,
            NEGATIVE_WRONG_PREDECESSOR_HEAD_R2_FIXTURE,
        ] {
            require_canonical(record(fixture)).unwrap();
            assert!(StructurallyClosedGeneration2Manifest::decode(record(fixture)).is_err());
        }

        // The one negative this revision adds: a generation-2-only kind can
        // never be a carry-forward root, because a root must be dispatched.
        let error = StructurallyClosedGeneration2Manifest::decode(record(
            NEGATIVE_GENERATION2_ONLY_ROOT_R2_FIXTURE,
        ))
        .unwrap_err();
        assert!(
            matches!(&error, ContractError::Schema(message)
                if message.contains("selects the non-dispatched triple")),
            "{error:?}"
        );

        let suite: Generation2VectorSuiteV1 =
            decode_strict(record(VECTOR_SUITE_R2_FIXTURE)).unwrap();
        assert_eq!(suite, vector_suite_r2());
        assert_eq!(
            manifest_domain_digest(record(VECTOR_SUITE_R2_FIXTURE)),
            digest(EXPECTED_VECTOR_SUITE_R2_DIGEST)
        );
        // The r2 suite pins the frozen Stage-4 package and the same
        // generation-1 head as r1: this revision widens the slot table and
        // nothing else.
        assert_eq!(
            suite.stage4_package_digest,
            digest(STAGE4_PACKAGE_DIGEST_HEX)
        );
        assert_eq!(suite.predecessor_head, generation1_expected_head().unwrap());

        for (fixture, expected) in [
            (MANIFEST_R2_FIXTURE, EXPECTED_MANIFEST_R2_RAW_SHA256),
            (SLOT_TABLE_R2_FIXTURE, EXPECTED_SLOT_TABLE_R2_RAW_SHA256),
            (VECTOR_SUITE_R2_FIXTURE, EXPECTED_VECTOR_SUITE_R2_RAW_SHA256),
        ] {
            assert_eq!(raw_sha256(fixture), expected);
        }
        for (pin, fixture) in suite.negative_artifacts.iter().zip([
            NEGATIVE_DUPLICATE_ROOT_R2_FIXTURE,
            NEGATIVE_GENERATION2_ONLY_ROOT_R2_FIXTURE,
            NEGATIVE_MISSING_REQUIRED_KIND_R2_FIXTURE,
            NEGATIVE_RESERVED_WRONG_VERSION_R2_FIXTURE,
            NEGATIVE_UNKNOWN_KIND_R2_FIXTURE,
            NEGATIVE_UNSORTED_ROOTS_R2_FIXTURE,
            NEGATIVE_V1_KIND_AT_V2_R2_FIXTURE,
            NEGATIVE_WRONG_PREDECESSOR_HEAD_R2_FIXTURE,
        ]) {
            assert_eq!(pin.raw_sha256, raw_sha256(fixture), "{}", pin.path);
        }
    }

    #[test]
    fn r2_reserves_exactly_two_new_kinds_and_nothing_else() {
        let closed = StructurallyClosedGeneration2Manifest::decode(record(MANIFEST_R2_FIXTURE))
            .expect("frozen r2 manifest must decode");
        let table: BodySchemaSlotTableV1 = decode_strict(record(SLOT_TABLE_R2_FIXTURE)).unwrap();

        // Each new kind holds exactly one slot, reserved, at entry schema v1 —
        // and it is reserved in the frozen manifest too, not only in the table.
        for (kind, schema_id) in [
            (
                RegistryEntryKind::ComparatorLineage,
                "registry.comparator_lineage",
            ),
            (
                RegistryEntryKind::ConsolidationPolicy,
                "registry.consolidation_policy",
            ),
        ] {
            let slots = table
                .slots
                .iter()
                .filter(|slot| slot.kind == kind)
                .collect::<Vec<_>>();
            assert_eq!(slots.len(), 1, "{}", kind.as_str());
            assert_eq!(slots[0].entry_schema_id.as_str(), schema_id);
            assert_eq!(slots[0].entry_schema_version, 1);
            assert_eq!(
                slots[0].slot_class,
                BodySchemaSlotClassV1::Generation2Reserved
            );
            assert!(
                closed
                    .manifest()
                    .reserved_slots
                    .iter()
                    .any(|slot| slot.kind == kind && slot.entry_schema_id.as_str() == schema_id),
                "{}",
                kind.as_str()
            );
        }

        // Nothing else moved: r2 is r1's table plus those two reserved slots.
        let r1_table: BodySchemaSlotTableV1 = decode_strict(record(SLOT_TABLE_FIXTURE)).unwrap();
        let added = table
            .slots
            .iter()
            .filter(|slot| !r1_table.slots.contains(slot))
            .map(|slot| slot.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            added,
            [
                RegistryEntryKind::ComparatorLineage,
                RegistryEntryKind::ConsolidationPolicy
            ]
        );
        assert!(
            r1_table.slots.iter().all(|slot| table.slots.contains(slot)),
            "r2 must be a superset of the r1 table"
        );
    }

    #[test]
    #[ignore = "maintainer-only canonical fixture regeneration"]
    fn regenerate_generation2_artifacts() {
        use std::fs;

        fn write(output: &Path, name: &str, bytes: &[u8]) {
            let mut framed = bytes.to_vec();
            framed.push(b'\n');
            fs::write(output.join(name), framed).unwrap();
        }

        let output = std::env::var_os("GENERATION2_VECTOR_OUTPUT")
            .map(std::path::PathBuf::from)
            .expect("GENERATION2_VECTOR_OUTPUT is required");
        fs::create_dir_all(&output).unwrap();

        // r1 file names are never written here: widening the closed table is a
        // new revision, and the r1 bytes stay exactly as they were frozen.
        let manifest_bytes = encode_canonical(&manifest()).unwrap();
        write(&output, "composition-manifest-r2.jsonl", &manifest_bytes);
        let table_bytes =
            encode_canonical(&BodySchemaSlotTableV1::from_compiled_table().unwrap()).unwrap();
        write(&output, "body-schema-slots-r2.jsonl", &table_bytes);
        for (_, path, bytes) in negative_artifact_bytes() {
            write(&output, path, &bytes);
        }
        let suite_bytes = encode_canonical(&vector_suite_r2()).unwrap();
        write(&output, "vector-suite-r2.jsonl", &suite_bytes);

        println!("manifest_digest={}", manifest().digest().unwrap());
        println!("slot_table_digest={}", manifest_domain_digest(&table_bytes));
        println!(
            "vector_suite_digest={}",
            manifest_domain_digest(&suite_bytes)
        );
        println!("manifest_raw_sha256={}", framed_raw_sha256(&manifest_bytes));
        println!("slot_table_raw_sha256={}", framed_raw_sha256(&table_bytes));
        println!(
            "vector_suite_raw_sha256={}",
            framed_raw_sha256(&suite_bytes)
        );
    }
}
