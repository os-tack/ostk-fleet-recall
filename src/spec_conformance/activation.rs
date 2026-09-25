//! Activating one spec statement under the strict writer-authority witness
//! (Stage 6).
//!
//! [`activate_spec_statement`] is the only path from a drafted spec statement
//! to a normative one. It re-reads the strict witness for the call (D4, never
//! cached) and then, in order, fails closed on:
//!
//! 1. a proposal that does not name exactly the witnessed registry head
//!    ([`require_witnessed_head`]: the exact `activation_id` and effective
//!    interval, not only the package and policy digests);
//! 2. an expectation the proposal does not carry, or a proposal that is not
//!    a spec statement: its predicate must be the one the genesis package
//!    admits the observer for, and its applicability evaluator the genesis
//!    package's own ([`require_spec_statement`]);
//! 3. approvals that do not verify under the ACTIVE package's activation
//!    policy ([`verify_normative_approvals`]), which also mints the receipt
//!    with `accepted_at` = the caller's server time.
//!
//! Only then does it write: the canonical proposal and expectation go to
//! `memory_normative_statements_v1` first, so an activation that then loses
//! leaves a harmless, content-addressed orphan row, and the normative runtime
//! compare-and-sets the activation into migration 0024's head, log, and
//! projection in one serializable transaction. A statement that is already
//! live reports [`SpecActivationOutcomeV1::AlreadyActive`] and appends
//! nothing, whether that is seen before the attempt or after losing the
//! compare-and-set to it.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

use crate::Result;
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use crate::memory_contracts::normative_v2::{ApprovalAttestationV1, NormativeBindingProposalV2};
use crate::memory_contracts::{ContractError, ContractResult};
use crate::normative_runtime::{
    CockroachNormativeActivationRepository, NormativeActivationCandidateV1,
    NormativeActivationOutcomeV1, NormativeActivationRepository as _, NormativeRegistryBindingV1,
    require_witnessed_head, verify_normative_approvals,
};
use crate::registry_witness::{WriterAuthorityRuntime, WriterAuthorityWitness};

use super::cockroach::{CockroachSpecRepository, SpecRowWriteV1};
use super::draft::{spec_applicability_evaluator, spec_predicate};
use super::expectation::RememberActionExpectationV1;

/// What one activation attempt did to the binding family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SpecActivationOutcomeV1 {
    /// The activation compare-and-set won: the log row, the head advance, and
    /// the projection advance committed together.
    Installed {
        /// The lifecycle event appended to the normative log.
        event_id: Sha256Digest,
        head_revision: u64,
        log_seq: u64,
        /// The family's binding-set digest now current.
        active_binding_set_digest: Option<Sha256Digest>,
    },
    /// The statement was already live. Nothing was appended.
    AlreadyActive,
    /// A concurrent transition moved the family's head and this statement is
    /// not live. Nothing was appended; re-draft against the current head.
    Lost {
        observed_binding_set_digest: Option<Sha256Digest>,
        observed_head_revision: u64,
    },
}

/// The report of one [`activate_spec_statement`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecActivationV1 {
    pub statement_id: Sha256Digest,
    pub binding_family_id: ContractId,
    /// The server time the receipt records as the activation's acceptance.
    pub accepted_at: CanonicalTimestamp,
    /// Whether this call stored the statement row or found it already there.
    pub statement_row: SpecRowWriteV1,
    #[serde(flatten)]
    pub outcome: SpecActivationOutcomeV1,
}

impl SpecActivationV1 {
    /// Whether the statement is live after this call.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(
            self.outcome,
            SpecActivationOutcomeV1::Installed { .. } | SpecActivationOutcomeV1::AlreadyActive
        )
    }
}

/// Activate one spec statement: verify it against a fresh witness, verify
/// its approvals under the active policy, record it, and compare-and-set it
/// into its binding family.
///
/// `accepted_at` must be the database's clock ([`database_now`]), never the
/// approver's or the proposal's. The proposal's `effective_from` must not
/// precede it.
///
/// # Errors
///
/// [`ContractError::StaleRegistryHead`] (as [`crate::FleetError::ControlContract`])
/// for a proposal drafted under another head; a contract error for an
/// unbound expectation, a proposal that is not a spec statement, or approvals
/// that do not verify; whatever the strict witness, the statement store, or
/// the normative runtime refuses. Every refusal before the statement row is
/// written leaves the database untouched.
pub async fn activate_spec_statement(
    runtime: &WriterAuthorityRuntime,
    proposal: &NormativeBindingProposalV2,
    expectation: &RememberActionExpectationV1,
    approvals: &[ApprovalAttestationV1],
    accepted_at: &CanonicalTimestamp,
) -> Result<SpecActivationV1> {
    let verified = runtime.verify().await?;
    let witness = verified.witness();
    require_witnessed_head(proposal, witness.head_binding())?;
    require_spec_statement(witness.genesis_package(), proposal, expectation)?;
    let receipt = verify_normative_approvals(
        proposal,
        approvals,
        witness.package().activation_policy(),
        accepted_at,
    )?;

    let statement = spec_repository(runtime)
        .record_statement(proposal, expectation)
        .await?;
    let normative = normative_repository(runtime, witness)?;
    let family = &proposal.binding_family_id;
    let outcome = if is_live(&normative, family, statement.statement_id).await? {
        SpecActivationOutcomeV1::AlreadyActive
    } else {
        let candidate = NormativeActivationCandidateV1 {
            proposal: proposal.clone(),
            receipt,
            retroactive_correction: None,
        };
        match normative.activate(&candidate).await? {
            NormativeActivationOutcomeV1::Installed(transition) => {
                SpecActivationOutcomeV1::Installed {
                    event_id: transition.event_id,
                    head_revision: transition.head_revision,
                    log_seq: transition.log_seq,
                    active_binding_set_digest: transition.active_binding_set_digest,
                }
            }
            NormativeActivationOutcomeV1::Lost {
                observed_binding_set_digest,
                observed_head_revision,
            } => {
                if is_live(&normative, family, statement.statement_id).await? {
                    SpecActivationOutcomeV1::AlreadyActive
                } else {
                    SpecActivationOutcomeV1::Lost {
                        observed_binding_set_digest,
                        observed_head_revision,
                    }
                }
            }
        }
    };
    Ok(SpecActivationV1 {
        statement_id: statement.statement_id,
        binding_family_id: family.clone(),
        accepted_at: accepted_at.clone(),
        statement_row: statement.write,
        outcome,
    })
}

/// Refuse a proposal/expectation pair the genesis-admitted observer cannot
/// check.
///
/// The expectation must be bound to the proposal and name the predicate the
/// genesis package admits `observer.rust_enum` for, and the proposal must use
/// the genesis package's applicability evaluator.
///
/// # Errors
///
/// [`ContractError::Schema`] naming the first rule that does not hold.
pub fn require_spec_statement(
    genesis: &SemanticallyClosedGenesisPackage,
    proposal: &NormativeBindingProposalV2,
    expectation: &RememberActionExpectationV1,
) -> ContractResult<()> {
    expectation.require_bound_to(proposal)?;
    if expectation.predicate != spec_predicate(genesis)? {
        return Err(ContractError::Schema(
            "the expectation names a predicate the genesis observer is not admitted for".into(),
        ));
    }
    if proposal.applicability_evaluator != spec_applicability_evaluator(genesis)? {
        return Err(ContractError::Schema(
            "the proposal names an applicability evaluator other than the genesis package's".into(),
        ));
    }
    Ok(())
}

/// The database's clock: the only source of an activation's `accepted_at`
/// and of a draft's "now".
///
/// # Errors
///
/// A database error.
pub async fn database_now(pool: &PgPool) -> Result<DateTime<Utc>> {
    Ok(
        sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
            .fetch_one(pool)
            .await?,
    )
}

/// The spec statement and check store bound to `runtime`'s scope.
#[must_use]
pub fn spec_repository(runtime: &WriterAuthorityRuntime) -> CockroachSpecRepository {
    CockroachSpecRepository::new(
        runtime.pool().clone(),
        runtime.control_scope().clone(),
        runtime.retry_policy(),
    )
}

/// The normative runtime bound to `runtime`'s scope and to the registry
/// binding `witness` certifies. Build it from a fresh witness for each
/// invocation; the binding is a snapshot of one read.
///
/// # Errors
///
/// A contract error for a zero registry binding, which a verified witness
/// never has.
pub fn normative_repository(
    runtime: &WriterAuthorityRuntime,
    witness: &WriterAuthorityWitness,
) -> Result<CockroachNormativeActivationRepository> {
    CockroachNormativeActivationRepository::new(
        runtime.pool().clone(),
        runtime.control_scope().clone(),
        NormativeRegistryBindingV1::from_witness(witness),
        runtime.retry_policy(),
    )
}

/// Whether `statement_id` is live in `family`'s stored projection.
async fn is_live(
    normative: &CockroachNormativeActivationRepository,
    family: &ContractId,
    statement_id: Sha256Digest,
) -> Result<bool> {
    Ok(normative
        .read_projection(family)
        .await?
        .is_some_and(|projection| {
            projection
                .live
                .iter()
                .any(|interval| interval.statement_id == statement_id)
        }))
}

#[cfg(test)]
#[path = "activation_tests.rs"]
mod tests;
