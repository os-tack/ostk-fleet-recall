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
//! 1. The deployment pins a bootstrap receipt digest out of band. The head
//!    witness ([`crate::registry_witness::WriterAuthorityWitness`]) exists only
//!    after that pin, the durable log epoch, and the active head all agree.
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
use crate::memory_contracts::common::{ContractId, RegistryReferenceV1};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::genesis::{
    ObserverAdmissionEntryV1, ObserverAdmissionModeV1 as GenesisObserverAdmissionModeV1,
    SemanticallyClosedGenesisPackage, SemanticallyDecodedGenesisEntryV1,
};
use crate::memory_contracts::observer::{
    AdmittedObserverV1, ObserverAdmissionModeV1, ObserverAdmissionV2,
};
use crate::memory_contracts::registry::{RegistryEntryKind, RegistryEntryV1};
use crate::memory_contracts::remember_v2::RememberAdmissionRuleV2;
use crate::registry_witness::WriterAuthorityWitness;

use super::enumeration::{ALL_DIAGNOSTICS, ENUMERATION_ALGORITHM_ID};
use super::error::{ObserverRuntimeError, ObserverRuntimeResult};

/// The enumeration algorithm this runtime is admitted to run, as a contract
/// id. Kept beside the admission binding so a reader can see in one place that
/// the algorithm the receipt names is the algorithm the code implements.
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
        witness: &WriterAuthorityWitness,
        genesis: &SemanticallyClosedGenesisPackage,
        declared: ObserverAdmissionV2,
    ) -> ObserverRuntimeResult<Self> {
        declared.validate_shape()?;
        let pinned = witness
            .bootstrap()
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
    for entry in active.registry_entries() {
        if entry.kind != RegistryEntryKind::AuthorityRule {
            continue;
        }
        let Ok(rule) = decode_remember_rule(entry) else {
            continue;
        };
        if rule.registered_observer_append_enabled {
            return Err(ObserverRuntimeError::RunWouldChangeRememberBasis);
        }
    }
    Ok(())
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
        return Err(ObserverRuntimeError::AdmissionDisagreement("admission mode"));
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
