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
//! not enumerate them.
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
use crate::memory_contracts::bootstrap::VerifiedBootstrapReceipt;
use crate::memory_contracts::common::{ContractId, RegistryReferenceV1};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::genesis::{
    ObserverAdmissionEntryV1, ObserverAdmissionModeV1 as GenesisObserverAdmissionModeV1,
    SemanticallyClosedGenesisPackage, SemanticallyDecodedGenesisEntryV1,
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
    fn the_generation_one_closure_pin_is_the_whole_generation_two_dependency_list() {
        let pin = Sha256Digest::from_bytes([0x11; 32]);
        assert_eq!(dependency_closure_digest(pin), vec![pin]);
        // Strictly sorted and zero-free, so the list it produces satisfies
        // `ObserverExecutableIdentityV1::validate_shape` without the caller
        // reordering anything.
        assert_ne!(pin, Sha256Digest::ZERO);
    }
}
