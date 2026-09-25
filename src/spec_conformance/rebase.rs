//! Rebasing normative binding families onto a new registry head (ADR 0008
//! D3).
//!
//! A binding family's head records the registry package and activation
//! policy it was last advanced under, and every activation into the family
//! compare-and-sets against them. A registry transition therefore strands the
//! family (ADR 0007 D11) unless it is rebased: its head moved onto the new
//! registry head, with a `rebase` row in its own log, and only when every
//! registry entry its live statements depend on is byte-identical under the
//! new head.
//!
//! The normative log holds each statement's interval, not its proposal, so
//! this module resolves the dependencies from what `ostk-spec activate`
//! recorded ([`spec_statement_dependencies`]) and hands them to
//! [`CockroachNormativeActivationRepository::rebase_family`], which checks
//! them against the durable live set under the head lock. A family it cannot
//! resolve — a live statement `ostk-spec` did not record, or one drafted
//! under a package this build does not recognize — is left where it is and
//! reported [`NormativeFamilyRebaseOutcomeV1::Stranded`] with the reason,
//! never rebased on trust.
//!
//! [`rebase_spec_families`] is the step `ostk-authority-install apply --target
//! generation-3` runs after the `2 -> 3` transition, as the migrator login. It
//! is idempotent: a family already at the head is
//! [`NormativeFamilyRebaseOutcomeV1::AlreadyCurrent`] and writes nothing.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sqlx::PgPool;

use crate::Result;
use crate::control_log::TrustedControlScope;
use crate::error::FleetError;
use crate::memory_contracts::ContractResult;
use crate::memory_contracts::common::{ContractId, RegistryReferenceV1};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::normative_v2::NormativeBindingProposalV2;
use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;
use crate::normative_runtime::{
    CockroachNormativeActivationRepository, NormativeActivationRepository as _, NormativeHeadRowV1,
    NormativeRebaseOutcomeV1, NormativeRebaseRequestV1, NormativeRebaseTargetV1,
    NormativeRegistryBindingV1,
};
use crate::registry_witness::{WriterAuthorityWitness, materialize_active_package};
use crate::store::cockroach::RetryPolicy;

use super::cockroach::CockroachSpecRepository;
use super::draft::repository_recipe;

/// How many times one family is re-resolved when its head moves between the
/// read and the rebase transaction, before it is reported stranded.
const MAX_REBASE_ATTEMPTS: usize = 3;

/// What rebasing one binding family did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NormativeFamilyRebaseV1 {
    pub binding_family_id: ContractId,
    #[serde(flatten)]
    pub outcome: NormativeFamilyRebaseOutcomeV1,
}

/// The outcome for one binding family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum NormativeFamilyRebaseOutcomeV1 {
    /// This run appended the rebase row and moved the family's head.
    Rebased {
        /// The `rebase` record's identity in the family's normative log.
        record_id: Sha256Digest,
        /// The registry package the head named before.
        from_registry_package_digest: Sha256Digest,
        head_revision: u64,
        log_seq: u64,
        /// How many registry entries the live statements depend on, each
        /// found byte-identical under the new head.
        carried_entries: usize,
    },
    /// The family's head already names the active head. Nothing was written.
    AlreadyCurrent,
    /// The family was not rebased and still names its old head, so nothing
    /// more can be activated into it (ADR 0007 D11). Nothing was written.
    Stranded { reason: String },
}

/// The registry entries one spec statement depends on.
///
/// They are its applicability evaluator and every proposition's predicate
/// schema, which resolve in the genesis package, and the
/// `identity.github.repository` recipe its subject was derived under in
/// `package`, the package it was drafted under.
///
/// # Errors
///
/// A contract error when `package` does not carry exactly one repository
/// recipe.
pub fn spec_statement_dependencies(
    package: &SemanticallyClosedSuccessorPackage,
    proposal: &NormativeBindingProposalV2,
) -> ContractResult<BTreeSet<RegistryReferenceV1>> {
    let mut dependencies = BTreeSet::from([
        proposal.applicability_evaluator.clone(),
        repository_recipe(package)?,
    ]);
    dependencies.extend(
        proposal
            .propositions
            .iter()
            .map(|proposition| proposition.predicate_schema.clone()),
    );
    Ok(dependencies)
}

/// Rebase every binding family of `control`'s scope onto the head `witness`
/// certifies, family by family, each in its own serializable transaction.
///
/// `pool` must be able to read the spec statement table and write the
/// normative tables: the migrator login the installer runs as, or a login
/// holding the runtime grants.
///
/// # Errors
///
/// A database error, a scope holding more families than
/// [`crate::normative_runtime::MAX_LISTED_FAMILY_HEADS`], or a stored row that
/// does not decode. A family that cannot be rebased is not an error: it is
/// reported [`NormativeFamilyRebaseOutcomeV1::Stranded`].
pub async fn rebase_spec_families(
    pool: &PgPool,
    control: &TrustedControlScope,
    witness: &WriterAuthorityWitness,
    retry: RetryPolicy,
) -> Result<Vec<NormativeFamilyRebaseV1>> {
    let target = NormativeRebaseTargetV1::from_witness(witness)?;
    let normative = CockroachNormativeActivationRepository::new(
        pool.clone(),
        control.clone(),
        NormativeRegistryBindingV1::from_witness(witness),
        retry,
    )?;
    let specs = CockroachSpecRepository::new(pool.clone(), control.clone(), retry);
    let mut families = Vec::new();
    for head in normative.list_heads().await? {
        let outcome = rebase_family(&normative, &specs, &target, head.clone()).await?;
        families.push(NormativeFamilyRebaseV1 {
            binding_family_id: head.binding_family_id,
            outcome,
        });
    }
    Ok(families)
}

async fn rebase_family(
    normative: &CockroachNormativeActivationRepository,
    specs: &CockroachSpecRepository,
    target: &NormativeRebaseTargetV1,
    mut head: NormativeHeadRowV1,
) -> Result<NormativeFamilyRebaseOutcomeV1> {
    let family = head.binding_family_id.clone();
    for _ in 0..MAX_REBASE_ATTEMPTS {
        if head.registry_package_digest == target.binding().registry_package_digest
            && head.activation_policy_digest == target.binding().activation_policy_digest
        {
            return Ok(NormativeFamilyRebaseOutcomeV1::AlreadyCurrent);
        }
        let live = normative
            .read_projection(&family)
            .await?
            .map(|projection| projection.live_statement_ids())
            .unwrap_or_default();
        let live_statement_dependencies = match resolve_dependencies(specs, &live).await? {
            Ok(dependencies) => dependencies,
            Err(reason) => return Ok(NormativeFamilyRebaseOutcomeV1::Stranded { reason }),
        };
        let request = NormativeRebaseRequestV1 {
            binding_family_id: family.clone(),
            expected_head_revision: head.head_revision,
            live_statement_dependencies,
        };
        match normative.rebase_family(target, &request).await {
            Ok(NormativeRebaseOutcomeV1::Rebased { transition, rebase }) => {
                return Ok(NormativeFamilyRebaseOutcomeV1::Rebased {
                    record_id: transition.event_id,
                    from_registry_package_digest: rebase.from_registry_package_digest,
                    head_revision: transition.head_revision,
                    log_seq: transition.log_seq,
                    carried_entries: rebase.carried_entry_digests.len(),
                });
            }
            Ok(NormativeRebaseOutcomeV1::AlreadyCurrent { .. }) => {
                return Ok(NormativeFamilyRebaseOutcomeV1::AlreadyCurrent);
            }
            Ok(NormativeRebaseOutcomeV1::Stale { .. }) => {
                let Some(current) = normative.read_head(&family).await? else {
                    return Err(FleetError::Memory(format!(
                        "binding family {family} lost its normative head during a rebase"
                    )));
                };
                head = current;
            }
            Err(FleetError::ControlContract(refusal)) => {
                return Ok(NormativeFamilyRebaseOutcomeV1::Stranded {
                    reason: refusal.to_string(),
                });
            }
            Err(error) => return Err(error),
        }
    }
    Ok(NormativeFamilyRebaseOutcomeV1::Stranded {
        reason: format!(
            "the family's head moved during each of {MAX_REBASE_ATTEMPTS} attempts; re-run the \
             rebase"
        ),
    })
}

/// Each live statement's dependencies, resolved from the proposal `ostk-spec`
/// recorded for it under the package it was drafted under, or why they cannot
/// be.
async fn resolve_dependencies(
    specs: &CockroachSpecRepository,
    live: &[Sha256Digest],
) -> Result<std::result::Result<BTreeMap<Sha256Digest, BTreeSet<RegistryReferenceV1>>, String>> {
    let mut resolved = BTreeMap::new();
    for statement_id in live {
        let Some(statement) = specs.read_statement(*statement_id).await? else {
            return Ok(Err(format!(
                "live statement {statement_id} has no recorded spec proposal, so the registry \
                 entries it depends on cannot be verified"
            )));
        };
        let drafted_under = statement.proposal.registry_head.head.package_digest;
        let Ok(package) = materialize_active_package(drafted_under) else {
            return Ok(Err(format!(
                "live statement {statement_id} was drafted under registry package \
                 {drafted_under}, which this build does not recognize"
            )));
        };
        match spec_statement_dependencies(package.successor(), &statement.proposal) {
            Ok(dependencies) => {
                resolved.insert(*statement_id, dependencies);
            }
            Err(error) => {
                return Ok(Err(format!(
                    "live statement {statement_id}'s dependencies do not resolve: {error}"
                )));
            }
        }
    }
    Ok(Ok(resolved))
}

#[cfg(test)]
#[path = "rebase_tests.rs"]
mod tests;
