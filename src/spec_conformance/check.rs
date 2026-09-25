//! Checking one commit against the spec statement in force (Stage 6): the
//! spec-nonconformance deriver behind `ostk-spec check`.
//!
//! [`run_spec_check`] runs the whole normative -> observer -> discrepancy
//! chain for one binding family and one commit, under a strict witness read
//! for the call (D4, never cached):
//!
//! 1. It selects the statement in force at the selection instant (the
//!    server's clock, or [`SpecCheckRequestV1::evaluated_through`]). A family
//!    with no statement in force, or a contested one, yields `unknown` and
//!    writes nothing: there is no statement to record a check against.
//! 2. It reads the statement's recorded proposal and expectation back,
//!    verified, and refuses a statement about another repository than the
//!    worker git source it was asked to read.
//! 3. It reads the source file the expectation names at the commit and runs
//!    the observer the genesis package admitted
//!    ([`ObserverRuntimeDeclarationV1::from_activated_genesis`]) over the enum
//!    and member the expectation names. Nothing is appended before both
//!    succeed, so a source that cannot be read or enumerated writes nothing.
//!    The observer's coverage witness binds the git source's latest coverage
//!    receipt; a source the worker has never covered is refused.
//! 4. It appends the file's git blob fact under the worker's own git source
//!    identity (principal, instance, installation, repository), so the blob
//!    event is an exact replay of what that source would mint and never a
//!    second copy, and then the observer result, citing it, under the sources
//!    file's observer identity. A quarantined append is an error.
//! 5. It compares the two sides at `t = max(statement effective_from, commit
//!    instant)` ([`super::providers`]).
//! 6. Only a discrepant comparison touches the discrepancy ledger, under the
//!    opening rule ([`spec_opening_decision`]), which is keyed on the
//!    statement and the commit: a commit already judged nonconforming under
//!    this statement joins the episode it was judged into, even after a
//!    registry head change mints new blob and observer events for it;
//!    otherwise a family that already has an episode that is not closed
//!    (open, acknowledged, or waived) keeps it; otherwise the check opens a
//!    new episode ([`super::envelope::build_spec_envelope`]).
//! 7. Every comparison, whatever its verdict, records one
//!    [`SpecCheckRecordV1`]. A replay of the same check writes nothing new.
//!
//! Under the genesis `positive_verified` admission only presence is ever
//! verified. So "must be absent" is the only expectation a commit can be
//! verified to violate, an absent member is `unknown` rather than
//! `conforming`, and a commit that fixes a violation never verifies the fix:
//! no check closes an episode. An operator does.
//!
//! The discrepancy write is fenced by the witnessed registry binding, not by
//! the append transaction's head read, and the opening rule is read before
//! the write rather than inside it: two concurrent checks of different
//! commits can each open an episode in one family.

use serde::Serialize;

use crate::Result;
use crate::connectors::git::{
    GitConnectorBindingV1, GitDrainContextV1, GitIngressClocksV1, GitObjectId, GitRepositoryReader,
    drain_git_facts,
};
use crate::coverage_runtime::CockroachCoverageRuntimeRepository;
use crate::discrepancy_runtime::{
    CockroachDiscrepancyLedgerRepository, ComparisonIndeterminacyV1, ComparisonVerdictV1,
    DiscrepancyAppendOutcomeV1, DiscrepancyLedgerRepository as _, DiscrepancyRegistryBindingV1,
};
use crate::error::FleetError;
use crate::evidence_ledger::ContentKeyEncryptionKey;
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::discrepancy::{DiscrepancyEpisodeFingerprintV1, LifecycleState};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::generation2_registry::GIT_CONNECTOR;
use crate::memory_contracts::observer::{
    EvaluatedConditionV1, ObserverCoverageContinuityV1, VerificationOutcomeV1,
};
use crate::memory_contracts::relation::ConcreteApplicabilityDimensionV1;
use crate::normative_runtime::{
    NormativeActivationRepository as _, NormativeFamilyProjectionV1, NormativePointResolutionV1,
};
use crate::observer_runtime::{
    OBSERVER_CONNECTOR_SCHEMA, ObserverAdmissionBindingV1, ObserverConnectorBindingV1,
    ObserverDrainContextV1, ObserverIngressClocksV1, ObserverQuestionV1, ObserverRunPlanV1,
    ObserverRuntimeDeclarationV1, REQUIRED_APPLICABILITY_DIMENSION, build_observer_run,
    drain_observer_run, enumerate_rust_enum,
};
use crate::registry_witness::WriterAuthorityRuntime;
use crate::worker::{GitSourceV1, ObserverSourceV1, WorkerSourcesV1};

use super::activation::{
    database_now, normative_repository, require_spec_statement, spec_repository,
};
use super::cockroach::SpecRowWriteV1;
use super::draft::{SPEC_OBSERVER_ID, SPEC_OBSERVER_VERSION, bind_blob_at, repository_subject};
use super::envelope::{
    SpecDetectionV1, build_spec_envelope, observer_source_fact_id, spec_family_fingerprint,
};
use super::providers::{
    NormativeStatementSide, ObservedMembershipSide, compare_spec_sides, spec_verdict,
};
use super::record::{SPEC_CHECK_RECORD_SCHEMA_VERSION, SpecCheckRecordV1, SpecVerdictV1};

/// The member bound a check enumerates under unless told otherwise.
pub const DEFAULT_SPEC_MEMBER_BOUND: usize = 64;

/// What `ostk-spec check` asks.
#[derive(Debug, Clone)]
pub struct SpecCheckRequestV1 {
    /// The binding family whose statement in force the commit is judged
    /// against.
    pub binding_family_id: ContractId,
    /// The worker's sources file: the git source to read, and the observer
    /// identity to append under.
    pub sources: WorkerSourcesV1,
    /// The connector instance of the git source in [`Self::sources`] that
    /// reads the statement's repository.
    pub git_source: ContractId,
    /// The exact commit to check.
    pub commit: GitObjectId,
    /// Hard cap on enumerated members; reaching it makes the read
    /// non-exhaustive.
    pub member_bound: usize,
    /// The instant the statement in force is selected at, and through which
    /// the normative side is known. `None` is the server's clock, which is
    /// what an operator wants; a caller passing a later instant asserts the
    /// family will not change before then.
    pub evaluated_through: Option<CanonicalTimestamp>,
}

impl SpecCheckRequestV1 {
    /// The git source named [`Self::git_source`].
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] when the sources file has no such git
    /// source, or it names no `provider_repository_id`.
    pub fn git(&self) -> Result<(&GitSourceV1, u64)> {
        let source = self
            .sources
            .git
            .iter()
            .find(|source| source.connector_instance == self.git_source)
            .ok_or_else(|| {
                FleetError::Configuration(format!(
                    "the sources file has no git source {}",
                    self.git_source
                ))
            })?;
        let provider_repository_id = source.provider_repository_id.ok_or_else(|| {
            FleetError::Configuration(format!(
                "git source {} names no provider_repository_id, so no spec statement's \
                 repository can be matched to it",
                self.git_source
            ))
        })?;
        Ok((source, provider_repository_id))
    }

    /// The observer identity observer runs are appended under.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] when the sources file names none.
    pub fn observer(&self) -> Result<&ObserverSourceV1> {
        self.sources.observer.as_ref().ok_or_else(|| {
            FleetError::Configuration(
                "the sources file names no observer identity to append observer runs under".into(),
            )
        })
    }
}

/// How the binding family resolved at the selection instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecSelectionV1 {
    /// Exactly one statement was in force; the commit was checked against it.
    Bound,
    /// No statement was in force.
    NoBinding,
    /// The family is contested: which statement is in force is unknown.
    Contested,
}

/// What one check did to the discrepancy ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum SpecDiscrepancyActionV1 {
    /// A new episode was opened for this detection.
    Opened {
        episode: DiscrepancyEpisodeFingerprintV1,
    },
    /// The family already has an episode that is not closed; the check joined
    /// it.
    AlreadyOpen {
        episode: DiscrepancyEpisodeFingerprintV1,
    },
    /// This commit was already judged nonconforming under this statement,
    /// into this episode.
    AlreadyJudged {
        episode: DiscrepancyEpisodeFingerprintV1,
    },
    /// The comparison was not discrepant; the ledger was not touched.
    NotOpened,
}

impl SpecDiscrepancyActionV1 {
    /// The episode the check opened or joined, if any.
    #[must_use]
    pub const fn episode(self) -> Option<DiscrepancyEpisodeFingerprintV1> {
        match self {
            Self::Opened { episode }
            | Self::AlreadyOpen { episode }
            | Self::AlreadyJudged { episode } => Some(episode),
            Self::NotOpened => None,
        }
    }
}

/// What [`spec_opening_decision`] decided for a discrepant comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecOpeningDecisionV1 {
    /// The commit was already judged nonconforming into this episode.
    AlreadyJudged(DiscrepancyEpisodeFingerprintV1),
    /// The family already has this episode that is not closed.
    AlreadyOpen(DiscrepancyEpisodeFingerprintV1),
    /// Open a new episode.
    Open,
}

/// The opening rule, keyed on (statement, commit) first.
///
/// `prior_nonconforming` is the episode a previous nonconforming check of the
/// same statement at the same commit named; `family_episodes` are the
/// family's episodes with their lifecycle states. A prior judgement wins, so
/// a registry head change, which mints new events for the same commit, can
/// never re-open an episode an operator closed. Otherwise the lowest-keyed
/// episode that is still open, acknowledged, or waived is joined, and only a
/// family with none opens a new one.
#[must_use]
pub fn spec_opening_decision(
    prior_nonconforming: Option<DiscrepancyEpisodeFingerprintV1>,
    family_episodes: &[(DiscrepancyEpisodeFingerprintV1, LifecycleState)],
) -> SpecOpeningDecisionV1 {
    if let Some(episode) = prior_nonconforming {
        return SpecOpeningDecisionV1::AlreadyJudged(episode);
    }
    family_episodes
        .iter()
        .filter(|(_, state)| is_not_closed(*state))
        .map(|(episode, _)| *episode)
        .min()
        .map_or(
            SpecOpeningDecisionV1::Open,
            SpecOpeningDecisionV1::AlreadyOpen,
        )
}

/// Whether an episode in `state` still stands: open, acknowledged, or waived
/// (a waiver expires back to open). Resolved, dismissed, and superseded
/// episodes are closed.
#[must_use]
pub const fn is_not_closed(state: LifecycleState) -> bool {
    matches!(
        state,
        LifecycleState::Open | LifecycleState::Acknowledged | LifecycleState::Waived
    )
}

/// The report of one [`run_spec_check`] call; what `ostk-spec check` prints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecCheckOutcomeV1 {
    pub binding_family_id: ContractId,
    pub commit: GitObjectId,
    /// The instant the statement in force was selected at.
    pub selected_at: CanonicalTimestamp,
    pub selection: SpecSelectionV1,
    /// The statement the commit was judged against; absent when none was in
    /// force.
    pub statement_id: Option<Sha256Digest>,
    pub verdict: SpecVerdictV1,
    /// Why an `unknown` check could not conclude.
    pub reasons: Vec<ComparisonIndeterminacyV1>,
    /// The instant the two sides were compared at.
    pub compared_at: Option<CanonicalTimestamp>,
    pub observed_condition: Option<EvaluatedConditionV1>,
    pub verification_outcome: Option<VerificationOutcomeV1>,
    /// The observer result event that measured the commit.
    pub observer_event: Option<AcceptedEventId>,
    /// The git blob event naming the exact source object the observer read.
    pub blob_event: Option<AcceptedEventId>,
    pub discrepancy: SpecDiscrepancyActionV1,
    /// The recorded check; absent when nothing was checked.
    pub check_id: Option<Sha256Digest>,
    pub check_row: Option<SpecRowWriteV1>,
}

impl SpecCheckOutcomeV1 {
    /// The report of a check that found no single statement in force: an
    /// unknown verdict, and nothing written. The normative side is
    /// unmeasured with unknown coverage, exactly as a comparison would have
    /// reported it.
    fn unselected(
        request: &SpecCheckRequestV1,
        selected_at: CanonicalTimestamp,
        selection: SpecSelectionV1,
    ) -> Self {
        Self {
            binding_family_id: request.binding_family_id.clone(),
            commit: request.commit.clone(),
            selected_at,
            selection,
            statement_id: None,
            verdict: SpecVerdictV1::Unknown,
            reasons: vec![
                ComparisonIndeterminacyV1::NormativeUnmeasured,
                ComparisonIndeterminacyV1::NormativeUnknownCoverage,
            ],
            compared_at: None,
            observed_condition: None,
            verification_outcome: None,
            observer_event: None,
            blob_event: None,
            discrepancy: SpecDiscrepancyActionV1::NotOpened,
            check_id: None,
            check_row: None,
        }
    }
}

/// Check one commit against the statement in force in one binding family.
///
/// `kek` seals the blob fact and the observer run record, which are governed
/// content. See the module documentation for every step.
///
/// # Errors
///
/// [`FleetError::Configuration`] for a sources file without the named git
/// source, its provider repository id, or an observer identity;
/// [`FleetError::Memory`] for a live statement with no recorded expectation,
/// a statement about another repository, a git source the worker never
/// covered, a source that cannot be read or enumerated, or an append the
/// ledger quarantined; whatever the strict witness, the admission seam, or a
/// repository refuses.
#[allow(clippy::too_many_lines)] // one linear select -> observe -> compare -> record pipeline
pub async fn run_spec_check(
    runtime: &WriterAuthorityRuntime,
    kek: &ContentKeyEncryptionKey,
    request: &SpecCheckRequestV1,
) -> Result<SpecCheckOutcomeV1> {
    let (git, provider_repository_id) = request.git()?;
    let observer = request.observer()?;
    let reader =
        GitRepositoryReader::new(&git.git_dir, git.repository()?, None).map_err(|error| {
            FleetError::Configuration(format!(
                "git source {} cannot be read: {error}",
                git.connector_instance
            ))
        })?;

    let verified = runtime.verify().await?;
    let witness = verified.witness();

    // The statement in force at the selection instant.
    let selected_at = match &request.evaluated_through {
        Some(at) => at.clone(),
        None => CanonicalTimestamp::from_datetime(&database_now(runtime.pool()).await?)?,
    };
    let family = &request.binding_family_id;
    let projection = normative_repository(runtime, witness)?
        .read_projection(family)
        .await?
        .unwrap_or_else(|| NormativeFamilyProjectionV1::empty(family.clone()));
    let statement_id = match projection.resolve_at(&selected_at) {
        NormativePointResolutionV1::Bound(statement_id) => statement_id,
        NormativePointResolutionV1::NoBinding => {
            return Ok(SpecCheckOutcomeV1::unselected(
                request,
                selected_at,
                SpecSelectionV1::NoBinding,
            ));
        }
        NormativePointResolutionV1::Unknown => {
            return Ok(SpecCheckOutcomeV1::unselected(
                request,
                selected_at,
                SpecSelectionV1::Contested,
            ));
        }
    };

    // What it expects, about which repository.
    let specs = spec_repository(runtime);
    let statement = specs.read_statement(statement_id).await?.ok_or_else(|| {
        FleetError::Memory(format!(
            "statement {statement_id} is in force in {family}, but no spec expectation was \
             recorded for it; only statements activated through ostk-spec can be checked"
        ))
    })?;
    let (proposal, expectation) = (&statement.proposal, &statement.expectation);
    require_spec_statement(witness.genesis_package(), proposal, expectation)?;
    if &proposal.binding_family_id != family {
        return Err(FleetError::Memory(format!(
            "statement {statement_id} belongs to another binding family than {family}"
        )));
    }
    let subject = repository_subject(
        witness.package(),
        runtime.semantic_scope(),
        provider_repository_id,
    )?;
    if subject != proposal.repository_entity_id {
        return Err(FleetError::Memory(format!(
            "statement {statement_id} is about another repository than git source {}",
            git.connector_instance
        )));
    }

    // The source the worker covered.
    let coverage = CockroachCoverageRuntimeRepository::new(
        runtime.pool().clone(),
        runtime.control_scope().clone(),
        runtime.retry_policy(),
    );
    let receipt = coverage
        .latest_receipt_for_instance(&git.connector_instance)
        .await?
        .ok_or_else(|| {
            FleetError::Memory(format!(
                "git source {} has no coverage receipt; run the worker's git step \
                 (`ostk-fleet-recall worker --once --steps ingest`) for it first",
                git.connector_instance
            ))
        })?;
    let coverage_receipt_digest = receipt.receipt_id()?.digest();

    // The exact source object, as the worker's git source would render it.
    let source = bind_blob_at(
        &reader,
        &request.commit,
        &expectation.source_path,
        "spec source",
    )?;

    // The observer the genesis package admitted, run over that object before
    // anything is appended, so a source it cannot enumerate writes nothing.
    let genesis = witness.genesis_package();
    let declaration = ObserverRuntimeDeclarationV1::from_activated_genesis(
        genesis,
        &ContractId::new(SPEC_OBSERVER_ID)?,
        SPEC_OBSERVER_VERSION,
    )
    .map_err(|error| refused("the genesis observer admission does not resolve", &error))?;
    let admission = declaration
        .to_admission()
        .and_then(|admission| {
            ObserverAdmissionBindingV1::resolve(witness.bootstrap(), genesis, admission)
        })
        .map_err(|error| refused("the genesis observer admission does not resolve", &error))?;
    let text = source
        .source_text()
        .map_err(|error| refused("the spec source is not text", &error))?;
    let enumeration = enumerate_rust_enum(text, &expectation.enum_name, request.member_bound)
        .map_err(|error| refused("the spec source's enum cannot be enumerated", &error))?;
    let revision = source
        .observed_revision_uri()
        .map_err(|error| refused("the spec source has no version identity", &error))?;
    let now = CanonicalTimestamp::from_datetime(&database_now(runtime.pool()).await?)?;
    let git_active = verified
        .bind_connector(&ContractId::new(GIT_CONNECTOR.connector_schema)?)
        .map_err(|error| {
            refused(
                "the active package does not admit the git connector",
                &error,
            )
        })?;
    let git_binding = GitConnectorBindingV1::resolve(
        &git_active,
        git.connector_principal.clone(),
        git.connector_instance.clone(),
        git.installation_id,
    )
    .map_err(|error| refused("the git source does not bind", &error))?;
    let drained = drain_git_facts(
        &GitDrainContextV1 {
            binding: &git_binding,
            active: &git_active,
            witness: verified.append_witness(),
            ledger: runtime.ledger().as_ref(),
            control_scope: runtime.control_scope(),
            kek,
            clocks: &GitIngressClocksV1 {
                received_at: now.clone(),
            },
        },
        &[source.git_fact()],
    )
    .await
    .map_err(|error| refused("the spec source's blob fact was not appended", &error))?;
    let blob_event = match (drained.quarantined, drained.events.as_slice()) {
        (0, [event]) => *event,
        _ => {
            return Err(FleetError::Memory(
                "the ledger quarantined the spec source's blob fact".into(),
            ));
        }
    };

    let push_active = verified
        .bind_connector(&ContractId::new(OBSERVER_CONNECTOR_SCHEMA)?)
        .map_err(|error| {
            refused(
                "the active package does not admit the observer connector",
                &error,
            )
        })?;
    let plan = ObserverRunPlanV1 {
        enum_name: expectation.enum_name.clone(),
        question: ObserverQuestionV1::Membership {
            member: expectation.member.clone(),
        },
        member_bound: request.member_bound,
        applicability: vec![ConcreteApplicabilityDimensionV1 {
            dimension_id: ContractId::new(REQUIRED_APPLICABILITY_DIMENSION)?,
            resource: revision.clone(),
        }],
        evidence_event_ids: vec![blob_event],
        coverage_receipt_digest,
        // One immutable blob has no sequencing dimension to be contiguous in.
        coverage_continuity: ObserverCoverageContinuityV1::NotApplicable,
        profile: push_active.profile().clone(),
        scope: push_active.scope().clone(),
    };
    let record = build_observer_run(&admission, &source, &enumeration, &plan, revision.clone())
        .map_err(|error| refused("the observer run was refused", &error))?;
    let observer_binding = ObserverConnectorBindingV1::resolve(
        &push_active,
        observer.connector_principal.clone(),
        observer.connector_instance.clone(),
        git.installation_id,
    )
    .map_err(|error| refused("the observer identity does not bind", &error))?;
    let clocks = ObserverIngressClocksV1 {
        received_at: now.clone(),
    };
    let run = drain_observer_run(
        &ObserverDrainContextV1 {
            binding: &observer_binding,
            active: &push_active,
            witness: verified.append_witness(),
            ledger: runtime.ledger().as_ref(),
            control_scope: runtime.control_scope(),
            kek,
            clocks: &clocks,
        },
        &record,
    )
    .await
    .map_err(|error| refused("the observer result was not appended", &error))?;
    let observer_event = run
        .accepted_event
        .ok_or_else(|| FleetError::Memory("the ledger quarantined the observer result".into()))?;

    // Compare both sides at the compared instant.
    let normative_side = NormativeStatementSide::new(
        projection,
        statement_id,
        proposal,
        expectation.clone(),
        selected_at.clone(),
    );
    let observed_side = ObservedMembershipSide::from_run(&record, expectation);
    let (compared, comparison) = compare_spec_sides(&normative_side, &observed_side)?;
    let (verdict, reasons) = spec_verdict(&comparison);
    let compared_at = compared.window_start;
    let family_fingerprint = spec_family_fingerprint(
        runtime.semantic_scope(),
        statement_id,
        proposal,
        expectation,
    )?;

    // Only a verified nonconformance touches the discrepancy ledger.
    let discrepancy = if comparison == ComparisonVerdictV1::Discrepant {
        let prior = specs
            .nonconforming_check_for(statement_id, &request.commit)
            .await?
            .and_then(|check| check.record.episode);
        let ledger = CockroachDiscrepancyLedgerRepository::new(
            runtime.pool().clone(),
            runtime.control_scope().clone(),
            DiscrepancyRegistryBindingV1::from_witness(witness),
            runtime.retry_policy(),
        )?;
        let family_episodes = if prior.is_some() {
            Vec::new()
        } else {
            ledger
                .read_family_episodes(family_fingerprint)
                .await?
                .into_iter()
                .map(|(stored, _)| (stored.episode_fingerprint, stored.lifecycle_state))
                .collect()
        };
        match spec_opening_decision(prior, &family_episodes) {
            SpecOpeningDecisionV1::AlreadyJudged(episode) => {
                SpecDiscrepancyActionV1::AlreadyJudged { episode }
            }
            SpecOpeningDecisionV1::AlreadyOpen(episode) => {
                SpecDiscrepancyActionV1::AlreadyOpen { episode }
            }
            SpecOpeningDecisionV1::Open => {
                let ingress = observer_binding
                    .build_ingress(&record, &clocks, 1)
                    .map_err(|error| refused("the observer result has no source fact", &error))?;
                let source_fact_id = observer_source_fact_id(&ingress.candidate)?;
                let candidate = build_spec_envelope(&SpecDetectionV1 {
                    registry: witness.head_binding(),
                    statement_id,
                    proposal,
                    expectation,
                    extractor: admission.entry_reference(),
                    observer_event,
                    blob_event,
                    source_fact_id,
                    compared_at: &compared_at,
                    verdict: &comparison,
                })?;
                let episode = candidate.envelope.episode_fingerprint;
                match ledger.admit_envelope(&candidate).await? {
                    DiscrepancyAppendOutcomeV1::Appended(_) => {
                        SpecDiscrepancyActionV1::Opened { episode }
                    }
                    // This very detection is already durable (a check that
                    // died before recording itself): the commit was judged.
                    DiscrepancyAppendOutcomeV1::AlreadyRecorded { .. } => {
                        SpecDiscrepancyActionV1::AlreadyJudged { episode }
                    }
                }
            }
        }
    } else {
        SpecDiscrepancyActionV1::NotOpened
    };

    let check = SpecCheckRecordV1 {
        schema_version: SPEC_CHECK_RECORD_SCHEMA_VERSION,
        statement_id,
        binding_family_id: family.clone(),
        family_fingerprint,
        commit_oid: request.commit.clone(),
        observed_revision_uri: revision,
        observer_event_id: observer_event,
        blob_event_id: blob_event,
        member: expectation.member.clone(),
        expected: expectation.expected,
        observed_condition: record.result.evaluated_condition,
        verification_outcome: record.result.verification_outcome,
        verdict,
        reasons: reasons.clone(),
        episode: discrepancy.episode(),
        compared_at: compared_at.clone(),
    };
    let written = specs.record_check(&check).await?;

    Ok(SpecCheckOutcomeV1 {
        binding_family_id: family.clone(),
        commit: request.commit.clone(),
        selected_at,
        selection: SpecSelectionV1::Bound,
        statement_id: Some(statement_id),
        verdict,
        reasons,
        compared_at: Some(compared_at),
        observed_condition: Some(check.observed_condition),
        verification_outcome: Some(check.verification_outcome),
        observer_event: Some(observer_event),
        blob_event: Some(blob_event),
        discrepancy,
        check_id: Some(written.check_id),
        check_row: Some(written.write),
    })
}

fn refused(what: &str, error: &dyn std::fmt::Display) -> FleetError {
    FleetError::Memory(format!("{what}: {error}"))
}

#[cfg(test)]
#[path = "check_tests.rs"]
mod tests;
