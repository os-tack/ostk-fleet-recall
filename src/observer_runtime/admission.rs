//! Resolving an observer's admission out of an activated registry (W3-OBSRT).
//!
//! # The chain this module completes
//!
//! `AdmittedObserverV1` is the capability without which nothing downstream may
//! derive a verification outcome, and the contract module that defines it
//! deliberately has no production constructor: it cannot read a registry, so
//! it cannot discharge the proof itself. This module is the one place in the
//! crate that discharges it, and the chain runs:
//!
//! 1. The deployment pins a bootstrap receipt digest out of band.
//!    [`VerifiedBootstrapReceipt`] has private fields and is minted only by
//!    `verify_pinned_bootstrap`, i.e. only after that out-of-band pin, the
//!    signatures, and the signer threshold all check out. It cannot be
//!    fabricated by a caller, which is why it is the argument here rather
//!    than a bare digest.
//! 2. That receipt's statement names one
//!    `genesis_registry_package_digest`. A supplied
//!    [`SemanticallyClosedGenesisPackage`] whose own recomputed digest is not
//!    that value is refused: without this step a caller could hand the runtime
//!    any package and be "admitted" by it.
//! 3. Inside that package, exactly one `observer_admission` entry may carry
//!    the configured id and version. Zero and two are the same refusal.
//! 4. The runtime's DECLARED [`ObserverAdmissionV2`] must agree with that
//!    activated entry on every field governance actually decided: the
//!    executable artifact digest, the dependency closure digest, the
//!    configuration digest, the admission mode, and the predicate reference —
//!    the last compared on entry id, version, AND entry digest, so an observer
//!    admitted for predicate Q cannot relabel itself onto predicate P.
//!
//! Fields the registry entry does not decide — the closed input boundary, the
//! toolchain versions, the enumeration algorithm and its registered
//! diagnostics, the vector digests — come from the runtime's own declaration
//! and are bound into the admission's digest, which the result event carries.
//! They are therefore auditable even though the generation-1 entry shape does
//! not enumerate them. They describe this code, not a deployment, so they are
//! the public constants below ([`CLOSED_INPUT_BOUNDARY`], the toolchain ids,
//! the vector digests), shared by `ostk-observer-run` and `ostk-spec check`.
//!
//! [`ObserverRuntimeDeclarationV1::from_activated_genesis`] builds the whole
//! declaration without operator input: every governance-decided field read
//! out of the activated genesis entry, every code-decided field from those
//! constants. [`ObserverAdmissionBindingV1::resolve`] still checks it, so the
//! two paths cannot drift apart silently.
//!
//! # Why a run can never flip the remember basis
//!
//! [`require_remember_basis_is_package_governed`] reads the ACTIVE package's
//! [`RememberAdmissionRuleV2`] and refuses the run outright when that rule
//! enables `registered_observer` appends. The observer therefore never
//! performs the append that would move the basis; moving it stays a package
//! change (an activation), which is a separate governance action with its own
//! approvals. The check runs before anything is written, so a refused run
//! leaves no receipt and no event.

use crate::evidence_ledger::ActiveStage4Package;
use crate::memory_contracts::ContractError;
use crate::memory_contracts::bootstrap::VerifiedBootstrapReceipt;
use crate::memory_contracts::common::{ContractId, RegistryReferenceV1};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::genesis::{
    CoverageRequirementV1, ObserverAdmissionEntryV1,
    ObserverAdmissionModeV1 as GenesisObserverAdmissionModeV1, SemanticallyClosedGenesisPackage,
    SemanticallyDecodedGenesisEntryV1,
};
use crate::memory_contracts::observer::{
    AdmittedObserverV1, ObserverAdmissionModeV1, ObserverAdmissionV2,
    ObserverEnumerationAlgorithmV1, ObserverExecutableIdentityV1, ObserverInputDomainV1,
    ObserverOutcomeKindV1, ObserverToolchainVersionsV1,
};
use crate::memory_contracts::registry::{RegistryEntryKind, RegistryEntryV1};
use crate::memory_contracts::remember_v2::RememberAdmissionRuleV2;

use super::enumeration::{ALL_DIAGNOSTICS, ENUMERATION_ALGORITHM_ID};
use super::error::{ObserverRuntimeError, ObserverRuntimeResult};

/// The enumeration algorithm this runtime is admitted to run.
///
/// Kept beside the admission binding so a reader can see in one place that the
/// algorithm the receipt names is the algorithm the code implements.
pub const ADMISSION_ENUMERATION_ALGORITHM: &str = ENUMERATION_ALGORITHM_ID;

/// The observer kind this runtime is: it enumerates one Rust enum. The
/// generation-1 admission entry does not carry a kind, so the code states it.
pub const OBSERVER_KIND: &str = "rust_enum";

/// The closed input boundary this runtime reads. A property of the code: it
/// reads git blobs and enumerates Rust enums, and nothing else.
pub const CLOSED_INPUT_BOUNDARY: &str = "boundary.crate-source";

/// The one source kind inside [`CLOSED_INPUT_BOUNDARY`]: a git blob.
pub const SUPPORTED_SOURCE_KIND: &str = "git.blob";

/// The one resource kind inside [`CLOSED_INPUT_BOUNDARY`]: a Rust enum.
pub const SUPPORTED_RESOURCE_KIND: &str = "rust.enum";

/// The applicability dimension every run must bind concretely: the exact
/// source revision it read.
pub const REQUIRED_APPLICABILITY_DIMENSION: &str = "repository_commit";

/// The connector schema an observer run is delivered as.
///
/// Every package the strict witness admits carries it: generation 1 has it as
/// its only connector, and generation 2 carries every generation-1 entry
/// forward byte for byte.
pub const OBSERVER_CONNECTOR_SCHEMA: &str = "connector.github.push";

/// The toolchain identifiers closed into the admission proof.
pub const TOOLCHAIN_LANGUAGE_VERSION: &str = "rust-1.94";
pub const TOOLCHAIN_SCHEMA_VERSION: &str = "schema-v1";
pub const TOOLCHAIN_COMPILER_VERSION: &str = "rustc-1.94.0";
pub const TOOLCHAIN_API_VERSION: &str = "api-v1";

/// Conformance vector digests for this build. They say which vectors this
/// executable was proven against, so they belong to the code and not to a
/// deployment flag.
pub const POSITIVE_VECTOR_DIGEST: [u8; 32] = [0xa1; 32];
pub const NEGATIVE_VECTOR_DIGEST: [u8; 32] = [0xa2; 32];
pub const MUTATION_VECTOR_DIGEST: [u8; 32] = [0xa3; 32];
pub const ADVERSARIAL_VECTOR_DIGEST: [u8; 32] = [0xa4; 32];

/// The closed input boundary [`CLOSED_INPUT_BOUNDARY`] and its kinds, as the
/// admission body carries them.
pub fn observer_input_domain() -> ObserverRuntimeResult<ObserverInputDomainV1> {
    Ok(ObserverInputDomainV1 {
        closed_input_boundary_id: ContractId::new(CLOSED_INPUT_BOUNDARY)?,
        supported_source_kinds: vec![ContractId::new(SUPPORTED_SOURCE_KIND)?],
        supported_resource_kinds: vec![ContractId::new(SUPPORTED_RESOURCE_KIND)?],
        required_applicability_dimensions: vec![ContractId::new(REQUIRED_APPLICABILITY_DIMENSION)?],
    })
}

/// The toolchain identifiers, as the admission body carries them.
pub fn observer_toolchain_versions() -> ObserverRuntimeResult<ObserverToolchainVersionsV1> {
    Ok(ObserverToolchainVersionsV1 {
        language_version: ContractId::new(TOOLCHAIN_LANGUAGE_VERSION)?,
        schema_version: ContractId::new(TOOLCHAIN_SCHEMA_VERSION)?,
        compiler_version: ContractId::new(TOOLCHAIN_COMPILER_VERSION)?,
        api_version: ContractId::new(TOOLCHAIN_API_VERSION)?,
    })
}

/// One observer admission, proven to be the activated one.
#[derive(Debug)]
pub struct ObserverAdmissionBindingV1 {
    admitted: AdmittedObserverV1,
    entry_reference: RegistryReferenceV1,
}

impl ObserverAdmissionBindingV1 {
    /// The governance-activated capability every derivation must cite.
    #[must_use]
    pub const fn admitted(&self) -> &AdmittedObserverV1 {
        &self.admitted
    }

    /// The registry entry reference this activation bound.
    #[must_use]
    pub const fn entry_reference(&self) -> &RegistryReferenceV1 {
        &self.entry_reference
    }

    /// The admission body, for callers building a run receipt against it.
    #[must_use]
    pub const fn admission(&self) -> &ObserverAdmissionV2 {
        self.admitted.admission()
    }

    /// Resolve `declared` against the genesis registry package the pinned
    /// bootstrap receipt names.
    ///
    /// Every refusal here is a closed variant of
    /// [`ObserverRuntimeError`]; there is no path that downgrades a
    /// disagreement to a warning, because an observer running under an
    /// admission it was not granted is exactly the self-admission AUTH-03
    /// forbids.
    pub fn resolve(
        bootstrap: &VerifiedBootstrapReceipt,
        genesis: &SemanticallyClosedGenesisPackage,
        declared: ObserverAdmissionV2,
    ) -> ObserverRuntimeResult<Self> {
        declared.validate_shape()?;
        let pinned = bootstrap
            .receipt()
            .statement
            .genesis_registry_package_digest;
        if genesis.package_digest() != pinned {
            return Err(ObserverRuntimeError::RegistryPackageNotPinned);
        }

        let entry = unique_observer_entry(genesis, &declared.admission_id, declared.version)?;
        let activated = unique_observer_body(genesis, &declared.admission_id, declared.version)?;
        require_declaration_matches_activation(&declared, activated)?;

        let entry_reference = RegistryReferenceV1 {
            entry_id: entry.entry_id.clone(),
            version: entry.version,
            entry_digest: entry.digest()?,
        };
        let admitted =
            AdmittedObserverV1::from_activation_witness(declared, entry_reference.clone())?;
        Ok(Self {
            admitted,
            entry_reference,
        })
    }
}

/// Refuse when the active package would let an observer run change how
/// `remember` admits claims.
///
/// The rule is read out of the ACTIVE package, never out of the run's own
/// configuration, and the refusal is unconditional: this runtime has no branch
/// that performs a `registered_observer` append, so the only honest response to
/// a package that permits one is to decline to run until governance has
/// decided what the observer plane may write.
pub fn require_remember_basis_is_package_governed(
    active: &ActiveStage4Package,
) -> ObserverRuntimeResult<()> {
    remember_basis_is_package_governed(active.registry_entries())
}

/// The pure predicate behind [`require_remember_basis_is_package_governed`].
///
/// Split out so the rule can be exercised against hand-built entries without
/// a database: the interesting case is the one a live deployment is not
/// supposed to reach.
pub fn remember_basis_is_package_governed(
    entries: &[RegistryEntryV1],
) -> ObserverRuntimeResult<()> {
    for entry in entries {
        if entry.kind != RegistryEntryKind::AuthorityRule {
            continue;
        }
        // A body that does not decode as a remember admission rule says
        // nothing about the remember basis; an authority rule of some other
        // shape is not evidence either way, so it is skipped rather than
        // treated as permission.
        let Ok(rule) = decode_remember_rule(entry) else {
            continue;
        };
        if rule.registered_observer_append_enabled {
            return Err(ObserverRuntimeError::RunWouldChangeRememberBasis);
        }
    }
    Ok(())
}

/// Deployment configuration for one observer runtime instance.
///
/// Everything here is stated by the operator, and every field the activated
/// registry entry also decides is CHECKED against it by
/// [`ObserverAdmissionBindingV1::resolve`]. That is the point of the split: a
/// misconfigured runtime is refused rather than admitted under whatever it
/// happened to declare, and the fields the generation-1 entry shape does not
/// carry are still bound into the admission digest every result event names.
#[derive(Debug, Clone)]
pub struct ObserverRuntimeDeclarationV1 {
    /// The admission id and version this runtime claims to run as.
    pub admission_id: ContractId,
    /// The admission version.
    pub version: u32,
    /// The observer kind. Never `llm` or `semantic_search` for a verified
    /// mode: the contract forces those to `candidate_only`.
    pub observer_kind: ContractId,
    /// The executable artifact digest governance pinned.
    pub executable_digest: Sha256Digest,
    /// The dependency closure digest governance pinned.
    pub dependency_closure_pin: Sha256Digest,
    /// The configuration context digest governance pinned.
    pub configuration_context_digest: Sha256Digest,
    /// The admission mode governance granted.
    pub mode: ObserverAdmissionModeV1,
    /// The predicate this observer is admitted for.
    pub predicate: RegistryReferenceV1,
    /// The closed input boundary this observer reads.
    pub input_domain: ObserverInputDomainV1,
    /// The toolchain identifiers closed into the proof.
    pub toolchain_versions: ObserverToolchainVersionsV1,
    /// The coverage-receipt recipe the run receipt's witness is built under.
    pub coverage_receipt_recipe: RegistryReferenceV1,
    /// Positive conformance vector digest.
    pub positive_vector_digest: Sha256Digest,
    /// Negative conformance vector digest.
    pub negative_vector_digest: Sha256Digest,
    /// Mutation conformance vector digest.
    pub mutation_vector_digest: Sha256Digest,
    /// Adversarial conformance vector digest.
    pub adversarial_vector_digest: Sha256Digest,
}

impl ObserverRuntimeDeclarationV1 {
    /// The declaration the activated genesis entry admitting
    /// `admission_id` v`version` decides, completed by this code's own
    /// constants.
    ///
    /// Every field governance decided — the executable, dependency closure,
    /// and configuration digests, the admission mode, the predicate, and the
    /// coverage proof the run receipt's witness is built under — is read out
    /// of that one entry; every field that describes this code
    /// ([`OBSERVER_KIND`], [`observer_input_domain`],
    /// [`observer_toolchain_versions`], the vector digests) is a constant.
    /// [`ObserverAdmissionBindingV1::resolve`] still checks the result
    /// against the same entry.
    ///
    /// That check therefore cannot fail on the pinned digests, and it proves
    /// nothing about the running code: the executable, dependency-closure,
    /// and configuration digests are copied from the admission, never
    /// measured from this binary, and the vector digests are placeholder
    /// constants no conformance run produced. They are nominal
    /// self-attestations, as the public fixture governance keys are (ADR
    /// 0007 D10): an observer result appended under this declaration names
    /// the admitted executable whatever binary actually ran. Unlike
    /// `ostk-observer-run`, whose operator passes the executable digest, no
    /// one attests it here.
    ///
    /// # Errors
    ///
    /// [`ObserverRuntimeError::ObserverNotAdmitted`] unless exactly one entry
    /// admits that id and version; a contract error when the entry requires
    /// no coverage proof (a candidate-only admission, which this runtime's
    /// verified modes never run under).
    pub fn from_activated_genesis(
        genesis: &SemanticallyClosedGenesisPackage,
        admission_id: &ContractId,
        version: u32,
    ) -> ObserverRuntimeResult<Self> {
        let activated = unique_observer_body(genesis, admission_id, version)?;
        let CoverageRequirementV1::Required { proof } = activated.coverage() else {
            return Err(ContractError::Schema(format!(
                "observer admission {admission_id} v{version} requires no coverage proof, so \
                 it names no coverage-receipt recipe to run under"
            ))
            .into());
        };
        Ok(Self {
            admission_id: activated.observer_id().clone(),
            version: activated.version(),
            observer_kind: ContractId::new(OBSERVER_KIND)?,
            executable_digest: activated.executable_artifact_digest(),
            dependency_closure_pin: activated.dependency_closure_digest(),
            configuration_context_digest: activated.configuration_digest(),
            mode: map_admission_mode(activated.admission_mode()),
            predicate: activated.predicate_schema().clone(),
            input_domain: observer_input_domain()?,
            toolchain_versions: observer_toolchain_versions()?,
            coverage_receipt_recipe: proof.clone(),
            positive_vector_digest: Sha256Digest::from_bytes(POSITIVE_VECTOR_DIGEST),
            negative_vector_digest: Sha256Digest::from_bytes(NEGATIVE_VECTOR_DIGEST),
            mutation_vector_digest: Sha256Digest::from_bytes(MUTATION_VECTOR_DIGEST),
            adversarial_vector_digest: Sha256Digest::from_bytes(ADVERSARIAL_VECTOR_DIGEST),
        })
    }

    /// Render the declaration as the v2 admission body.
    ///
    /// The enumeration algorithm id and its registered diagnostics come from
    /// the CODE, not from configuration: the set of constructs this observer
    /// knows it might not understand is a property of the scanner, and letting
    /// an operator shorten it would let a deployment quietly claim more
    /// exhaustiveness than the algorithm can deliver.
    pub fn to_admission(&self) -> ObserverRuntimeResult<ObserverAdmissionV2> {
        let mut diagnostics = ALL_DIAGNOSTICS.to_vec();
        diagnostics.sort_unstable();
        let admission = ObserverAdmissionV2 {
            schema_version: 1,
            admission_id: self.admission_id.clone(),
            version: self.version,
            identity: ObserverExecutableIdentityV1 {
                observer_kind: self.observer_kind.clone(),
                executable_digest: self.executable_digest,
                dependency_digests: dependency_closure_digest(self.dependency_closure_pin),
                version: self.version,
            },
            predicate: self.predicate.clone(),
            input_domain: self.input_domain.clone(),
            configuration_context_digest: self.configuration_context_digest,
            toolchain_versions: self.toolchain_versions.clone(),
            mode: self.mode,
            enumeration_algorithm: ObserverEnumerationAlgorithmV1 {
                algorithm_id: ContractId::new(ADMISSION_ENUMERATION_ALGORITHM)?,
                unsupported_feature_diagnostics: diagnostics
                    .into_iter()
                    .map(ContractId::new)
                    .collect::<Result<Vec<_>, _>>()?,
            },
            // The closed set of outcome kinds this runtime can honestly
            // report. `parse_failure` is absent because a source this runtime
            // cannot read is refused before a receipt exists, and `stale` is
            // absent because an immutable blob named by object id has no
            // newer version to be stale against.
            declared_outcome_kinds: vec![
                ObserverOutcomeKindV1::Success,
                ObserverOutcomeKindV1::Partial,
                ObserverOutcomeKindV1::Timeout,
            ],
            coverage_receipt_recipe: self.coverage_receipt_recipe.clone(),
            positive_vector_digest: self.positive_vector_digest,
            negative_vector_digest: self.negative_vector_digest,
            mutation_vector_digest: self.mutation_vector_digest,
            adversarial_vector_digest: self.adversarial_vector_digest,
        };
        admission.validate_shape()?;
        Ok(admission)
    }
}

/// Decode one authority-rule entry body as a remember admission rule.
fn decode_remember_rule(
    entry: &RegistryEntryV1,
) -> Result<RememberAdmissionRuleV2, crate::memory_contracts::ContractError> {
    let bytes = crate::memory_contracts::canonical::canonical_bytes(&entry.body)?;
    crate::memory_contracts::canonical::decode_strict(&bytes)
}

/// The dependency digest list a generation-1 closure pin corresponds to.
///
/// The two admission shapes describe the same thing at different resolutions.
/// [`ObserverAdmissionEntryV1`] pins the observer's dependency closure as ONE
/// digest and says nothing about its members; [`ObserverAdmissionV2`] carries
/// a list of member digests. Inverting a hash to recover the members is not
/// possible and pretending otherwise would mean either abandoning the check or
/// inventing members, so the bridge is stated explicitly instead: while the
/// activated entry is a generation-1 body, the generation-2 identity's
/// dependency list is exactly the one closure digest governance pinned.
///
/// When a generation-2 `observer_admission` body that enumerates its closure
/// members is wired, this function is the single place that changes, and the
/// change is visible as a different admission digest on every result event.
#[must_use]
pub fn dependency_closure_digest(closure_pin: Sha256Digest) -> Vec<Sha256Digest> {
    vec![closure_pin]
}

/// The one activated registry entry admitting this observer.
fn unique_observer_entry<'package>(
    genesis: &'package SemanticallyClosedGenesisPackage,
    observer_id: &ContractId,
    version: u32,
) -> ObserverRuntimeResult<&'package RegistryEntryV1> {
    let mut matching = genesis
        .manifest_verified_package()
        .package()
        .entries
        .iter()
        .filter(|entry| {
            entry.kind == RegistryEntryKind::ObserverAdmission
                && entry.entry_id == *observer_id
                && entry.version == version
        });
    let found = matching.next();
    let duplicate = matching.next().is_some();
    match (found, duplicate) {
        (Some(entry), false) => Ok(entry),
        _ => Err(ObserverRuntimeError::ObserverNotAdmitted {
            observer_id: observer_id.as_str().to_owned(),
            version,
        }),
    }
}

/// The one decoded admission body admitting this observer.
fn unique_observer_body<'package>(
    genesis: &'package SemanticallyClosedGenesisPackage,
    observer_id: &ContractId,
    version: u32,
) -> ObserverRuntimeResult<&'package ObserverAdmissionEntryV1> {
    let mut matching = genesis.entries().iter().filter_map(|entry| match entry {
        SemanticallyDecodedGenesisEntryV1::ObserverAdmission(body)
            if body.observer_id() == observer_id && body.version() == version =>
        {
            Some(body)
        }
        _ => None,
    });
    let found = matching.next();
    let duplicate = matching.next().is_some();
    match (found, duplicate) {
        (Some(body), false) => Ok(body),
        _ => Err(ObserverRuntimeError::ObserverNotAdmitted {
            observer_id: observer_id.as_str().to_owned(),
            version,
        }),
    }
}

/// Every field governance decided must agree, exactly.
fn require_declaration_matches_activation(
    declared: &ObserverAdmissionV2,
    activated: &ObserverAdmissionEntryV1,
) -> ObserverRuntimeResult<()> {
    if declared.identity.executable_digest != activated.executable_artifact_digest() {
        return Err(ObserverRuntimeError::AdmissionDisagreement(
            "executable artifact digest",
        ));
    }
    if declared.identity.dependency_digests
        != dependency_closure_digest(activated.dependency_closure_digest())
    {
        return Err(ObserverRuntimeError::AdmissionDisagreement(
            "dependency closure digest",
        ));
    }
    if declared.configuration_context_digest != activated.configuration_digest() {
        return Err(ObserverRuntimeError::AdmissionDisagreement(
            "configuration context digest",
        ));
    }
    if declared.mode != map_admission_mode(activated.admission_mode()) {
        return Err(ObserverRuntimeError::AdmissionDisagreement(
            "admission mode",
        ));
    }
    if declared.predicate != *activated.predicate_schema() {
        return Err(ObserverRuntimeError::AdmissionDisagreement(
            "predicate reference",
        ));
    }
    if declared.enumeration_algorithm.algorithm_id.as_str() != ADMISSION_ENUMERATION_ALGORITHM {
        return Err(ObserverRuntimeError::AdmissionDisagreement(
            "enumeration algorithm id",
        ));
    }
    let registered: Vec<&str> = declared
        .enumeration_algorithm
        .unsupported_feature_diagnostics
        .iter()
        .map(ContractId::as_str)
        .collect();
    let mut expected = ALL_DIAGNOSTICS.to_vec();
    expected.sort_unstable();
    if registered != expected {
        return Err(ObserverRuntimeError::AdmissionDisagreement(
            "registered enumeration diagnostics",
        ));
    }
    Ok(())
}

/// Map the generation-1 entry's admission mode onto the v2 contract's.
///
/// An exhaustive match rather than a numeric cast: the two enums are declared
/// in different modules and in different orders, so anything looser would
/// silently pair `closed_world_verified` with `positive_verified` the first
/// time either list is reordered.
const fn map_admission_mode(mode: GenesisObserverAdmissionModeV1) -> ObserverAdmissionModeV1 {
    match mode {
        GenesisObserverAdmissionModeV1::CandidateOnly => ObserverAdmissionModeV1::CandidateOnly,
        GenesisObserverAdmissionModeV1::PositiveVerified => {
            ObserverAdmissionModeV1::PositiveVerified
        }
        GenesisObserverAdmissionModeV1::ClosedWorldVerified => {
            ObserverAdmissionModeV1::ClosedWorldVerified
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_admission_mode_enums_map_by_name_not_by_position() {
        assert_eq!(
            map_admission_mode(GenesisObserverAdmissionModeV1::CandidateOnly),
            ObserverAdmissionModeV1::CandidateOnly
        );
        assert_eq!(
            map_admission_mode(GenesisObserverAdmissionModeV1::PositiveVerified),
            ObserverAdmissionModeV1::PositiveVerified
        );
        assert_eq!(
            map_admission_mode(GenesisObserverAdmissionModeV1::ClosedWorldVerified),
            ObserverAdmissionModeV1::ClosedWorldVerified
        );
        // The generation-1 list is alphabetical and the v2 list is ordered by
        // increasing capability, so a positional cast would swap these two.
        assert_ne!(
            map_admission_mode(GenesisObserverAdmissionModeV1::ClosedWorldVerified),
            ObserverAdmissionModeV1::PositiveVerified
        );
    }

    use crate::memory_contracts::canonical::{decode_strict, encode_canonical};
    use crate::memory_contracts::registry::ManifestVerifiedRegistryPackage;

    const STAGE4_PACKAGE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");

    fn stage4_entries() -> Vec<RegistryEntryV1> {
        let body = STAGE4_PACKAGE
            .strip_suffix(b"\n")
            .expect("contract JSONL carries exactly one framing LF");
        let profile = crate::memory_contracts::common::frozen_profile_reference_v1();
        ManifestVerifiedRegistryPackage::decode(body, &profile)
            .expect("the frozen package must decode")
            .package()
            .entries
            .clone()
    }

    #[test]
    fn the_frozen_active_package_does_not_let_a_run_change_the_remember_basis() {
        remember_basis_is_package_governed(&stage4_entries()).unwrap();
    }

    #[test]
    fn a_package_that_enables_registered_observer_appends_refuses_the_run() {
        let mut entries = stage4_entries();
        let rule_entry = entries
            .iter_mut()
            .find(|entry| entry.kind == RegistryEntryKind::AuthorityRule)
            .expect("the frozen package has a remember admission rule");
        let bytes = crate::memory_contracts::canonical::canonical_bytes(&rule_entry.body).unwrap();
        let mut rule: RememberAdmissionRuleV2 = decode_strict(&bytes).unwrap();
        assert!(
            !rule.registered_observer_append_enabled,
            "the frozen rule must start closed, or this test proves nothing"
        );
        rule.registered_observer_append_enabled = true;
        rule_entry.body = decode_strict(&encode_canonical(&rule).unwrap()).unwrap();

        let error = remember_basis_is_package_governed(&entries).unwrap_err();
        assert!(
            matches!(error, ObserverRuntimeError::RunWouldChangeRememberBasis),
            "{error:?}"
        );
    }

    #[test]
    fn an_authority_rule_of_another_shape_is_not_read_as_permission() {
        // A body that does not decode as a remember admission rule must be
        // skipped, not treated as either grant or denial: an unrelated
        // authority rule says nothing about the remember basis.
        let mut entries = stage4_entries();
        let rule_entry = entries
            .iter_mut()
            .find(|entry| entry.kind == RegistryEntryKind::AuthorityRule)
            .expect("the frozen package has a remember admission rule");
        rule_entry.body =
            decode_strict(br#"{"unrelated":true}"#.as_slice()).expect("canonical object");
        remember_basis_is_package_governed(&entries).unwrap();
    }

    #[test]
    fn the_declaration_read_from_the_activated_genesis_resolves_against_it() {
        use crate::memory_contracts::bootstrap::{
            BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1, verify_pinned_bootstrap,
        };
        use crate::memory_contracts::common::frozen_profile_reference_v1;
        use crate::memory_contracts::digest::{DigestDomain, domain_separated_digest};

        const BOOTSTRAP_RECEIPT: &[u8] =
            include_bytes!("../../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");
        let genesis = crate::registry_witness::compiled_genesis_package().unwrap();
        let bytes = BOOTSTRAP_RECEIPT.strip_suffix(b"\n").unwrap();
        let receipt: BootstrapReceiptV1 = decode_strict(bytes).unwrap();
        let bootstrap = verify_pinned_bootstrap(
            bytes,
            BootstrapPin::from_trusted_config(BootstrapReceiptDigest::from_digest(
                domain_separated_digest(DigestDomain::BootstrapReceipt, bytes),
            )),
            &frozen_profile_reference_v1(),
            &receipt.statement.scope,
            genesis,
        )
        .unwrap();

        let observer = ContractId::new("observer.rust_enum").unwrap();
        let declared =
            ObserverRuntimeDeclarationV1::from_activated_genesis(genesis, &observer, 1).unwrap();
        let binding = ObserverAdmissionBindingV1::resolve(
            &bootstrap,
            genesis,
            declared.to_admission().unwrap(),
        )
        .expect("the genesis-read declaration is the admitted observer");
        assert_eq!(binding.entry_reference().entry_id, observer);
        assert_eq!(
            binding.admission().mode,
            ObserverAdmissionModeV1::PositiveVerified
        );

        let unadmitted =
            ObserverRuntimeDeclarationV1::from_activated_genesis(genesis, &observer, 2);
        assert!(
            matches!(
                unadmitted,
                Err(ObserverRuntimeError::ObserverNotAdmitted { .. })
            ),
            "{unadmitted:?}"
        );
    }

    #[test]
    fn the_generation_one_closure_pin_is_the_whole_generation_two_dependency_list() {
        let pin = Sha256Digest::from_bytes([0x11; 32]);
        assert_eq!(dependency_closure_digest(pin), vec![pin]);
        // Strictly sorted and zero-free, so the list it produces satisfies
        // `ObserverExecutableIdentityV1::validate_shape` without the caller
        // reordering anything.
        assert_ne!(pin, Sha256Digest::ZERO);
    }
}
