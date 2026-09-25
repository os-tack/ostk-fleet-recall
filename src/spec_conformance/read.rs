//! The agent-facing read of spec conformance (Stage 6, ADR 0007):
//! `recall(action="discrepancies")` and the `spec_conformance` block of
//! `recall(status)`.
//!
//! [`CockroachSpecConformanceReader`] reads, in one serializable transaction,
//! what the chain has recorded for its physical scope:
//!
//! * every binding family's normative projection (at most
//!   [`MAX_LISTED_SPECS`] families), and for each statement still live in one
//!   the spec statement `ostk-spec activate` recorded and its latest check. A
//!   live statement without a recorded spec is not a spec (only `ostk-spec`
//!   records one) and is left out. The projection's live set is not
//!   filtered by time, so each spec is classified against the database's
//!   time inside the read ([`SpecEffectV1`]): in force, scheduled (not yet in
//!   effect), or expired (past its `effective_until`). Only specs in force
//!   count as active, as `ostk-spec check` selects at that clock;
//! * the discrepancy episodes, most recently changed first: by default only
//!   the ones that still stand (open, acknowledged, or waived) in the family
//!   of a live spec that has not expired, so an episode of a retired,
//!   superseded, or expired spec is hidden; with `include_resolved`, every
//!   episode in the scope. An episode of a scheduled spec (a check evaluated
//!   through an instant after the server's clock) is listed, because the
//!   nonconformance it records was verified;
//! * for each spec episode, its statement and the check that opened it.
//!
//! Episodes record verified nonconformance only, so an answer always carries
//! every live spec's latest check as well: "no episode" must never read as
//! "conforms". A row that fails re-verification is skipped with a warning; it
//! never fails the read.
//!
//! The reader is bound to the physical `(tenant_id, project)` pair every
//! statement here binds as `$1` and `$2`, and needs only SELECT
//! ([`probe_spec_conformance`]). `serve` may run without the writer-authority
//! pins, so the reader has no semantic scope to hold rows to; instead each
//! spec episode is cross-checked against the statement it names (semantic
//! scope, binding family, and family fingerprint), and its spec is withheld
//! with a warning when they disagree.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::Result;
use crate::connectors::git::GitObjectId;
use crate::context::FleetScope;
use crate::discrepancy_runtime::{
    ComparisonIndeterminacyV1, DiscrepancyLogRecordV1, lifecycle_state_from_str,
    verification_state_from_str,
};
use crate::error::FleetError;
use crate::memory_contracts::canonical::decode_strict;
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId, RegistryReferenceV1};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::discrepancy::{
    DiscrepancyEnvelopeV1, DiscrepancyEpisodeFingerprintV1, DiscrepancyFamilyFingerprintV1,
    DiscrepancySeverityV1, FindingType, LifecycleState, LifecycleTransitionV1, VerificationState,
    VerificationUpdateV1,
};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::identity::ResourceUri;
use crate::memory_contracts::normative::SourceByteSpanV1;
use crate::memory_contracts::observer::{EvaluatedConditionV1, VerificationOutcomeV1};
use crate::normative_runtime::{
    NormativeFamilyProjectionV1, NormativeResolutionV1, NormativeStatementIntervalV1,
};
use crate::store::cockroach::{
    DatabaseCapabilities, RetryPolicy, SpecConformanceReadCapability, probe_spec_conformance,
    with_serializable_retry,
};

use super::cockroach::{
    LATEST_CHECKS_SQL, RecordedSpecStatementV1, StoredSpecCheckV1, check_columns,
    decode_any_statement_row, decode_check_row, statement_row_columns,
};
use super::envelope::spec_family_fingerprint;
use super::expectation::{ExpectedMembershipV1, RememberActionExpectationV1};
use super::record::SpecVerdictV1;

/// Upper bound on the episodes one listing returns.
pub const MAX_DISCREPANCY_RESULTS: usize = 100;

/// Upper bound on the binding families, and on the live specs, one read
/// considers. Past it the answer says `specs_truncated`.
pub const MAX_LISTED_SPECS: usize = 100;

/// Upper bound on the lifecycle events one episode lookup returns.
pub const MAX_EPISODE_HISTORY: usize = 50;

/// Upper bound on the check rows read to find the checks that opened the
/// listed episodes. Each episode has one opening check; the bound only keeps
/// a corrupt scope from making the read unbounded.
const MAX_OPENING_CHECK_ROWS: usize = 1024;

/// What every answer says about reading it.
pub const SPEC_CONFORMANCE_NOTE: &str = "Episodes record verified nonconformance only. No episode does not mean the code conforms: read specs[].last_check. 'unknown' means the observer could not verify either way; absence cannot be verified under the activated positive_verified admission, so a fixed commit never auto-resolves an episode.";

/// The lifecycle states of an episode that still stands,
/// [`crate::discrepancy_runtime::STANDING_LIFECYCLE_STATES`].
macro_rules! standing_states {
    () => {
        "('open', 'acknowledged', 'waived')"
    };
}

/// One episode: its stored states and the envelope that seeded it.
macro_rules! episode_select {
    () => {
        "SELECT p.episode_fingerprint, h.family_fingerprint, p.lifecycle_state, \
         p.verification_state, l.canonical_record \
         FROM public.memory_discrepancy_projections_v1 AS p \
         JOIN public.memory_discrepancy_heads_v1 AS h \
           ON h.tenant_id = p.tenant_id AND h.project = p.project \
          AND h.episode_fingerprint = p.episode_fingerprint \
         JOIN public.memory_discrepancy_log_v1 AS l \
           ON l.tenant_id = p.tenant_id AND l.project = p.project \
          AND l.episode_fingerprint = p.episode_fingerprint AND l.seq = 1"
    };
}

const NORMATIVE_PROJECTIONS_SQL: &str = "SELECT binding_family_id, resolution, \
     canonical_projection FROM public.memory_normative_projections_v1 \
     WHERE tenant_id = $1 AND project = $2 ORDER BY binding_family_id LIMIT $3";

const STATEMENTS_SQL: &str = concat!(
    "SELECT ",
    statement_row_columns!(),
    " FROM public.memory_normative_statements_v1 \
     WHERE tenant_id = $1 AND project = $2 AND statement_id = ANY($3::BYTES[])"
);

/// The checks that opened the listed episodes: those naming one of them and
/// measured by one of their member observer events, earliest first. The
/// episode prefix is `memory_spec_checks_episode_idx`.
const OPENING_CHECKS_SQL: &str = concat!(
    "SELECT ",
    check_columns!(),
    " FROM public.memory_spec_checks_v1 \
     WHERE tenant_id = $1 AND project = $2 AND episode_fingerprint = ANY($3::BYTES[]) \
       AND observer_event_id = ANY($4::BYTES[]) \
     ORDER BY episode_fingerprint, created_at, check_id LIMIT $5"
);

/// `$3` is `include_resolved`; without it only standing episodes of the
/// families in `$4` (the live specs' that have not expired) are listed.
const LIST_EPISODES_SQL: &str = concat!(
    episode_select!(),
    " WHERE p.tenant_id = $1 AND p.project = $2 \
       AND ($3::BOOL OR (p.lifecycle_state IN ",
    standing_states!(),
    " AND h.family_fingerprint = ANY($4::BYTES[]))) \
     ORDER BY p.evaluated_at DESC, p.episode_fingerprint LIMIT $5"
);

const GET_EPISODE_SQL: &str = concat!(
    episode_select!(),
    " WHERE p.tenant_id = $1 AND p.project = $2 AND p.episode_fingerprint = $3"
);

const EPISODE_HISTORY_SQL: &str = "SELECT seq, canonical_record \
     FROM public.memory_discrepancy_log_v1 \
     WHERE tenant_id = $1 AND project = $2 AND episode_fingerprint = $3 AND seq > 1 \
     ORDER BY seq LIMIT $4";

const COUNT_STANDING_SQL: &str = concat!(
    "SELECT count(*) FROM public.memory_discrepancy_projections_v1 AS p \
     JOIN public.memory_discrepancy_heads_v1 AS h \
       ON h.tenant_id = p.tenant_id AND h.project = p.project \
      AND h.episode_fingerprint = p.episode_fingerprint \
     WHERE p.tenant_id = $1 AND p.project = $2 AND p.lifecycle_state IN ",
    standing_states!(),
    " AND h.family_fingerprint = ANY($3::BYTES[])"
);

/// Where a live spec stands at the read's database time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecEffectV1 {
    /// Its effective interval contains the read's time: `ostk-spec check`
    /// selects it now.
    InForce,
    /// It takes effect after the read's time.
    Scheduled,
    /// Its `effective_until` is at or before the read's time.
    Expired,
}

impl SpecEffectV1 {
    /// Where `interval` stands at `now`.
    #[must_use]
    pub fn at(interval: &NormativeStatementIntervalV1, now: &CanonicalTimestamp) -> Self {
        if interval
            .effective_until
            .as_ref()
            .is_some_and(|until| until <= now)
        {
            Self::Expired
        } else if &interval.effective_from > now {
            Self::Scheduled
        } else {
            Self::InForce
        }
    }
}

/// Something a read skipped or could not settle, reported beside its answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecConformanceWarningV1 {
    /// `spec_row_unreadable`, `spec_statement_missing`,
    /// `spec_family_contested`, or `specs_truncated`.
    pub code: &'static str,
    pub message: String,
}

/// What a spec statement expects, as an agent reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecExpectationViewV1 {
    #[serde(rename = "enum")]
    pub enum_name: String,
    pub member: String,
    pub expected: ExpectedMembershipV1,
    pub source_path: String,
    /// The severity an episode of this spec carries.
    pub severity: DiscrepancySeverityV1,
}

impl SpecExpectationViewV1 {
    fn of(expectation: &RememberActionExpectationV1) -> Self {
        Self {
            enum_name: expectation.enum_name.clone(),
            member: expectation.member.clone(),
            expected: expectation.expected,
            source_path: expectation.source_path.clone(),
            severity: expectation.severity,
        }
    }
}

/// The spec statement an episode violates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecStatementViewV1 {
    pub statement_id: Sha256Digest,
    pub binding_family_id: ContractId,
    /// The spec document's repository path, as git names it.
    pub spec_path: String,
    /// The exact version of the spec document the statement cites.
    pub spec_version: ResourceUri,
    /// The cited byte spans of that version.
    pub spans: Vec<SourceByteSpanV1>,
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
    pub expectation: SpecExpectationViewV1,
}

impl SpecStatementViewV1 {
    fn of(statement: &RecordedSpecStatementV1) -> Self {
        let proposal = &statement.proposal;
        Self {
            statement_id: statement.statement_id,
            binding_family_id: proposal.binding_family_id.clone(),
            spec_path: String::from_utf8_lossy(proposal.exact_path_bytes.as_bytes()).into_owned(),
            spec_version: proposal.repository_version_id.clone(),
            spans: proposal.source_spans.clone(),
            effective_from: proposal.effective_from.clone(),
            effective_until: proposal.effective_until.clone(),
            expectation: SpecExpectationViewV1::of(&statement.expectation),
        }
    }
}

/// What the check that opened an episode observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecObservationV1 {
    pub commit: GitObjectId,
    pub condition: EvaluatedConditionV1,
    pub verification_outcome: VerificationOutcomeV1,
    pub observer_event_id: AcceptedEventId,
    pub compared_at: CanonicalTimestamp,
}

/// The evidence an episode cites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecEvidenceV1 {
    pub member: Vec<AcceptedEventId>,
    pub supporting: Vec<AcceptedEventId>,
}

/// One lifecycle event of an episode, in log order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecEpisodeEventV1 {
    pub seq: u64,
    pub effective_at: CanonicalTimestamp,
    pub lifecycle_transition: Option<LifecycleTransitionV1>,
    pub verification_update: Option<VerificationUpdateV1>,
    pub evidence_event_ids: Vec<AcceptedEventId>,
}

/// One discrepancy episode, as `recall(discrepancies)` returns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecDiscrepancyV1 {
    pub episode_id: DiscrepancyEpisodeFingerprintV1,
    pub family_id: DiscrepancyFamilyFingerprintV1,
    pub finding_type: &'static str,
    pub severity: DiscrepancySeverityV1,
    pub lifecycle_state: LifecycleState,
    pub verification_state: VerificationState,
    /// Whether the statement it violates still stands: live in its binding
    /// family and not expired (in force, or scheduled). Always false for an
    /// episode with no readable spec.
    pub spec_live: bool,
    pub detected_at: CanonicalTimestamp,
    pub subject: ResourceUri,
    pub predicate: RegistryReferenceV1,
    /// The statement it violates; `None` when it is not a spec
    /// nonconformance or its statement could not be read.
    pub spec: Option<SpecStatementViewV1>,
    /// What the opening check observed; `None` when that check is not
    /// recorded.
    pub observed: Option<SpecObservationV1>,
    pub evidence: SpecEvidenceV1,
    /// The lifecycle log after the detection, only when one episode is
    /// looked up by id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<SpecEpisodeEventV1>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_truncated: Option<bool>,
}

/// A live spec's latest check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecLastCheckV1 {
    pub commit: GitObjectId,
    pub verdict: SpecVerdictV1,
    /// Why an `unknown` check could not conclude.
    pub reasons: Vec<ComparisonIndeterminacyV1>,
    pub compared_at: CanonicalTimestamp,
    pub observer_event_id: AcceptedEventId,
    /// The episode a nonconforming check opened or joined.
    pub episode_id: Option<DiscrepancyEpisodeFingerprintV1>,
}

impl SpecLastCheckV1 {
    fn of(check: &StoredSpecCheckV1) -> Self {
        let record = &check.record;
        Self {
            commit: record.commit_oid.clone(),
            verdict: record.verdict,
            reasons: record.reasons.clone(),
            compared_at: record.compared_at.clone(),
            observer_event_id: record.observer_event_id,
            episode_id: record.episode,
        }
    }
}

/// One live spec statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecSummaryV1 {
    pub binding_family_id: ContractId,
    /// The binding family's normative resolution, which is not about time:
    /// `active` (one live statement), `scheduled` (several with disjoint
    /// windows), or `unknown` (contested: a check of it reports unknown and
    /// records nothing).
    pub resolution: &'static str,
    /// Whether this statement is in force at the read's database time,
    /// scheduled, or expired.
    pub effect: SpecEffectV1,
    pub statement_id: Sha256Digest,
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
    pub expectation: SpecExpectationViewV1,
    /// `None` when the statement was never checked.
    pub last_check: Option<SpecLastCheckV1>,
}

/// How much of the scope an answer covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecCoverageV1 {
    pub episodes_returned: usize,
    /// More episodes matched than the limit returned.
    pub episodes_truncated: bool,
    /// Specs in force at the read's database time.
    pub active_specs: usize,
    /// Live specs that take effect later.
    pub scheduled_specs: usize,
    /// Live specs past their `effective_until`.
    pub expired_specs: usize,
    /// Specs in force that were never checked.
    pub never_checked_specs: usize,
    /// Specs in force whose latest check is `unknown`.
    pub unknown_specs: usize,
    /// More binding families or live statements exist than one read
    /// considers; the specs, their counts, and the default episode filter
    /// cover only the first [`MAX_LISTED_SPECS`].
    pub specs_truncated: bool,
    pub note: &'static str,
}

/// One `recall(discrepancies)` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecConformanceAnswerV1 {
    pub discrepancies: Vec<SpecDiscrepancyV1>,
    pub specs: Vec<SpecSummaryV1>,
    pub coverage: SpecCoverageV1,
    pub warnings: Vec<SpecConformanceWarningV1>,
}

/// The counts `recall(status)` reports, at the read's database time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecConformanceStatusV1 {
    /// Specs in force.
    pub active_specs: usize,
    /// Live specs that take effect later.
    pub scheduled_specs: usize,
    /// Live specs past their `effective_until`.
    pub expired_specs: usize,
    /// Standing (open, acknowledged, or waived) episodes of specs in force
    /// or scheduled: what the default listing lists.
    pub open_discrepancies: u64,
    /// Specs in force whose latest check is `unknown`.
    pub unknown_specs: usize,
    /// Specs in force that were never checked.
    pub never_checked_specs: usize,
    pub warnings: Vec<SpecConformanceWarningV1>,
}

/// The spec conformance read over one scope.
#[async_trait]
pub trait SpecConformanceRead: Send + Sync {
    /// The episodes, newest first, at most `limit` (1 to
    /// [`MAX_DISCREPANCY_RESULTS`]) of them: only standing episodes of live
    /// specs that have not expired, or every episode with
    /// `include_resolved`; and every live spec.
    async fn list(&self, include_resolved: bool, limit: usize) -> Result<SpecConformanceAnswerV1>;

    /// One episode by id, in any state, with its lifecycle history; and
    /// every live spec. No episode with that id answers an empty list.
    async fn get(
        &self,
        episode: DiscrepancyEpisodeFingerprintV1,
    ) -> Result<SpecConformanceAnswerV1>;

    /// The counts, without listing.
    async fn status(&self) -> Result<SpecConformanceStatusV1>;
}

/// [`SpecConformanceRead`] over one physical scope's private plane.
#[derive(Clone)]
pub struct CockroachSpecConformanceReader {
    pool: PgPool,
    scope: ReadScope,
    retry_policy: RetryPolicy,
}

impl std::fmt::Debug for CockroachSpecConformanceReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachSpecConformanceReader")
            .field("tenant_id", &self.scope.tenant_id)
            .field("project", &self.scope.project)
            .finish_non_exhaustive()
    }
}

impl CockroachSpecConformanceReader {
    /// The reader for `scope`'s physical pair, once
    /// [`probe_spec_conformance`] found its tables readable.
    ///
    /// # Errors
    ///
    /// An invalid scope.
    pub fn new(
        pool: PgPool,
        scope: &FleetScope,
        _capability: SpecConformanceReadCapability,
    ) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            pool,
            scope: ReadScope {
                tenant_id: scope.tenant_id,
                project: scope.project.clone(),
            },
            retry_policy: RetryPolicy::default(),
        })
    }
}

#[async_trait]
impl SpecConformanceRead for CockroachSpecConformanceReader {
    async fn list(&self, include_resolved: bool, limit: usize) -> Result<SpecConformanceAnswerV1> {
        if !(1..=MAX_DISCREPANCY_RESULTS).contains(&limit) {
            return Err(FleetError::Memory(format!(
                "a discrepancy listing returns 1 to {MAX_DISCREPANCY_RESULTS} episodes"
            )));
        }
        let scope = self.scope.clone();
        with_serializable_retry(&self.pool, self.retry_policy, move |transaction| {
            let scope = scope.clone();
            Box::pin(
                async move { read_listing(transaction, &scope, include_resolved, limit).await },
            )
        })
        .await
    }

    async fn get(
        &self,
        episode: DiscrepancyEpisodeFingerprintV1,
    ) -> Result<SpecConformanceAnswerV1> {
        let scope = self.scope.clone();
        with_serializable_retry(&self.pool, self.retry_policy, move |transaction| {
            let scope = scope.clone();
            Box::pin(async move { read_episode(transaction, &scope, episode).await })
        })
        .await
    }

    async fn status(&self) -> Result<SpecConformanceStatusV1> {
        let scope = self.scope.clone();
        with_serializable_retry(&self.pool, self.retry_policy, move |transaction| {
            let scope = scope.clone();
            Box::pin(async move { read_status(transaction, &scope).await })
        })
        .await
    }
}

/// The spec conformance read for `scope`, or `None` when this deployment
/// does not serve `recall(discrepancies)`.
///
/// It is served wherever the schema has reached migration 31 and the login
/// may read every table the reader reads ([`probe_spec_conformance`]). Like
/// evidence recall it is additive: a missing migration or grant is logged at
/// info level, a failed probe at error level, and either way `serve` goes on
/// with every tool schema as it was. The probe runs once, so a later grant
/// change needs a restart.
pub async fn start_spec_conformance(
    pool: &PgPool,
    capabilities: &DatabaseCapabilities,
    scope: &FleetScope,
) -> Option<Arc<dyn SpecConformanceRead>> {
    let probed = match probe_spec_conformance(pool, capabilities).await {
        Ok(probed) => probed,
        Err(error) => {
            tracing::error!(
                error = %error,
                "recall(discrepancies) is off: its startup probe failed; serving recall and remember without it"
            );
            return None;
        }
    };
    let Some(capability) = probed else {
        tracing::info!(
            "recall(discrepancies) not served: migration 31 or its runtime read grants are absent"
        );
        return None;
    };
    match CockroachSpecConformanceReader::new(pool.clone(), scope, capability) {
        Ok(reader) => {
            tracing::info!("serving recall(action=discrepancies)");
            Some(Arc::new(reader))
        }
        Err(error) => {
            tracing::error!(error = %error, "recall(discrepancies) is off: its scope is invalid");
            None
        }
    }
}

/// The physical pair every statement binds as `$1` and `$2`.
#[derive(Debug, Clone)]
struct ReadScope {
    tenant_id: Uuid,
    project: String,
}

/// One live spec: a statement live in its binding family, with a recorded
/// spec.
struct LiveSpec {
    resolution: &'static str,
    effect: SpecEffectV1,
    interval: NormativeStatementIntervalV1,
    binding_family_id: ContractId,
    family_fingerprint: DiscrepancyFamilyFingerprintV1,
    expectation: SpecExpectationViewV1,
    last_check: Option<StoredSpecCheckV1>,
}

/// Everything one read learned about the scope's specs.
struct SpecSnapshot {
    specs: Vec<LiveSpec>,
    /// Every statement live in a family read and not expired, spec or not.
    standing_statements: BTreeSet<Sha256Digest>,
    /// Every statement read and verified, by id.
    statements: BTreeMap<Sha256Digest, RecordedSpecStatementV1>,
    truncated: bool,
    warnings: Vec<SpecConformanceWarningV1>,
}

impl SpecSnapshot {
    /// The discrepancy families of the live specs that have not expired, as
    /// the heads table stores them: the families whose standing episodes the
    /// default listing and the status count.
    fn family_bytes(&self) -> Vec<Vec<u8>> {
        self.specs
            .iter()
            .filter(|spec| spec.effect != SpecEffectV1::Expired)
            .map(|spec| spec.family_fingerprint.digest())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|digest| digest.as_bytes().to_vec())
            .collect()
    }

    fn with_effect(&self, effect: SpecEffectV1) -> impl Iterator<Item = &LiveSpec> {
        self.specs.iter().filter(move |spec| spec.effect == effect)
    }

    fn count(&self, effect: SpecEffectV1) -> usize {
        self.with_effect(effect).count()
    }

    /// Specs in force that were never checked.
    fn never_checked(&self) -> usize {
        self.with_effect(SpecEffectV1::InForce)
            .filter(|spec| spec.last_check.is_none())
            .count()
    }

    /// Specs in force whose latest check is `unknown`.
    fn unknown(&self) -> usize {
        self.with_effect(SpecEffectV1::InForce)
            .filter(|spec| {
                spec.last_check
                    .as_ref()
                    .is_some_and(|check| check.record.verdict == SpecVerdictV1::Unknown)
            })
            .count()
    }

    fn answer(
        self,
        discrepancies: Vec<SpecDiscrepancyV1>,
        episodes_truncated: bool,
    ) -> SpecConformanceAnswerV1 {
        let coverage = SpecCoverageV1 {
            episodes_returned: discrepancies.len(),
            episodes_truncated,
            active_specs: self.count(SpecEffectV1::InForce),
            scheduled_specs: self.count(SpecEffectV1::Scheduled),
            expired_specs: self.count(SpecEffectV1::Expired),
            never_checked_specs: self.never_checked(),
            unknown_specs: self.unknown(),
            specs_truncated: self.truncated,
            note: SPEC_CONFORMANCE_NOTE,
        };
        let specs = self
            .specs
            .into_iter()
            .map(|spec| SpecSummaryV1 {
                binding_family_id: spec.binding_family_id,
                resolution: spec.resolution,
                effect: spec.effect,
                statement_id: spec.interval.statement_id,
                effective_from: spec.interval.effective_from,
                effective_until: spec.interval.effective_until,
                expectation: spec.expectation,
                last_check: spec.last_check.as_ref().map(SpecLastCheckV1::of),
            })
            .collect();
        SpecConformanceAnswerV1 {
            discrepancies,
            specs,
            coverage,
            warnings: self.warnings,
        }
    }
}

/// One stored episode that decoded: its states and its seeding envelope.
struct StoredEpisode {
    episode: DiscrepancyEpisodeFingerprintV1,
    lifecycle_state: LifecycleState,
    verification_state: VerificationState,
    envelope: DiscrepancyEnvelopeV1,
}

impl StoredEpisode {
    /// The statement a spec nonconformance names as its expectation policy.
    fn statement_id(&self) -> Option<Sha256Digest> {
        (self.envelope.finding_type == FindingType::SpecNonconformance)
            .then_some(self.envelope.expectation_policy.entry_digest)
    }
}

async fn read_listing(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ReadScope,
    include_resolved: bool,
    limit: usize,
) -> Result<SpecConformanceAnswerV1> {
    let mut snapshot = read_snapshot(transaction, scope).await?;
    let rows: Vec<PgRow> = sqlx::query(LIST_EPISODES_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(include_resolved)
        .bind(snapshot.family_bytes())
        .bind(sql_limit(limit + 1)?)
        .fetch_all(&mut **transaction)
        .await?;
    let truncated = rows.len() > limit;
    let episodes = rows
        .iter()
        .take(limit)
        .filter_map(|row| decode_episode_row(row, &mut snapshot.warnings))
        .collect();
    let discrepancies = describe_episodes(transaction, scope, &mut snapshot, episodes).await?;
    Ok(snapshot.answer(discrepancies, truncated))
}

async fn read_episode(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ReadScope,
    episode: DiscrepancyEpisodeFingerprintV1,
) -> Result<SpecConformanceAnswerV1> {
    let mut snapshot = read_snapshot(transaction, scope).await?;
    let row: Option<PgRow> = sqlx::query(GET_EPISODE_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(episode.digest().as_bytes().to_vec())
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(stored) = row
        .as_ref()
        .and_then(|row| decode_episode_row(row, &mut snapshot.warnings))
    else {
        return Ok(snapshot.answer(Vec::new(), false));
    };
    let (history, truncated) =
        read_history(transaction, scope, episode, &mut snapshot.warnings).await?;
    let mut discrepancies =
        describe_episodes(transaction, scope, &mut snapshot, vec![stored]).await?;
    for discrepancy in &mut discrepancies {
        discrepancy.history = Some(history.clone());
        discrepancy.history_truncated = Some(truncated);
    }
    Ok(snapshot.answer(discrepancies, false))
}

async fn read_status(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ReadScope,
) -> Result<SpecConformanceStatusV1> {
    let snapshot = read_snapshot(transaction, scope).await?;
    let families = snapshot.family_bytes();
    let standing: i64 = if families.is_empty() {
        0
    } else {
        sqlx::query_scalar(COUNT_STANDING_SQL)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(families)
            .fetch_one(&mut **transaction)
            .await?
    };
    Ok(SpecConformanceStatusV1 {
        active_specs: snapshot.count(SpecEffectV1::InForce),
        scheduled_specs: snapshot.count(SpecEffectV1::Scheduled),
        expired_specs: snapshot.count(SpecEffectV1::Expired),
        open_discrepancies: u64::try_from(standing)
            .map_err(|_| FleetError::Memory("a negative episode count".into()))?,
        unknown_specs: snapshot.unknown(),
        never_checked_specs: snapshot.never_checked(),
        warnings: snapshot.warnings,
    })
}

/// One statement live in a binding family: the family's resolution, the
/// statement's interval, and the family.
type LiveInterval = (&'static str, NormativeStatementIntervalV1, ContractId);

/// Every live spec of the first [`MAX_LISTED_SPECS`] binding families, with
/// its latest check and where it stands at the database's time.
async fn read_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ReadScope,
) -> Result<SpecSnapshot> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(&mut **transaction)
        .await?;
    let now = CanonicalTimestamp::from_datetime(&now)?;
    let mut warnings = Vec::new();
    let (live, truncated) = read_live_intervals(transaction, scope, &mut warnings).await?;
    let standing_statements: BTreeSet<Sha256Digest> = live
        .iter()
        .filter(|(_, interval, _)| SpecEffectV1::at(interval, &now) != SpecEffectV1::Expired)
        .map(|(_, interval, _)| interval.statement_id)
        .collect();
    let wanted: Vec<Sha256Digest> = live
        .iter()
        .map(|(_, interval, _)| interval.statement_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let statements = read_statements(transaction, scope, &wanted, &mut warnings).await?;
    let mut checks = read_latest_checks(transaction, scope, &wanted, &mut warnings).await?;

    let mut specs = Vec::new();
    for (resolution, interval, binding_family_id) in live {
        // A live statement no spec was recorded for is not a spec.
        let Some(statement) = statements.get(&interval.statement_id) else {
            continue;
        };
        let family_fingerprint = match live_spec_family(statement, &binding_family_id) {
            Ok(family) => family,
            Err(error) => {
                skip(
                    &mut warnings,
                    "spec_row_unreadable",
                    format!(
                        "spec statement {} was skipped: {error}",
                        interval.statement_id
                    ),
                );
                continue;
            }
        };
        specs.push(LiveSpec {
            resolution,
            effect: SpecEffectV1::at(&interval, &now),
            last_check: checks.remove(&interval.statement_id),
            expectation: SpecExpectationViewV1::of(&statement.expectation),
            interval,
            binding_family_id,
            family_fingerprint,
        });
    }
    Ok(SpecSnapshot {
        specs,
        standing_statements,
        statements,
        truncated,
        warnings,
    })
}

/// The statements live in the first [`MAX_LISTED_SPECS`] binding families,
/// at most [`MAX_LISTED_SPECS`] of them, and whether either bound cut the
/// read. A contested family and a cut read are warned about.
async fn read_live_intervals(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ReadScope,
    warnings: &mut Vec<SpecConformanceWarningV1>,
) -> Result<(Vec<LiveInterval>, bool)> {
    let rows: Vec<PgRow> = sqlx::query(NORMATIVE_PROJECTIONS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(sql_limit(MAX_LISTED_SPECS + 1)?)
        .fetch_all(&mut **transaction)
        .await?;
    let mut truncated = rows.len() > MAX_LISTED_SPECS;
    let mut live = Vec::new();
    for row in rows.iter().take(MAX_LISTED_SPECS) {
        let projection = match decode_normative_projection(row) {
            Ok(projection) => projection,
            Err(error) => {
                skip(
                    warnings,
                    "spec_row_unreadable",
                    format!("a normative projection was skipped: {error}"),
                );
                continue;
            }
        };
        if matches!(projection.resolution, NormativeResolutionV1::Unknown { .. }) {
            skip(
                warnings,
                "spec_family_contested",
                format!(
                    "binding family {} is contested: which of its statements is in force is \
                     unknown, so checking it reports unknown and records nothing",
                    projection.binding_family_id
                ),
            );
        }
        let resolution = projection.resolution.as_str();
        for interval in projection.live {
            live.push((resolution, interval, projection.binding_family_id.clone()));
        }
    }
    if live.len() > MAX_LISTED_SPECS {
        live.truncate(MAX_LISTED_SPECS);
        truncated = true;
    }
    if truncated {
        skip(
            warnings,
            "specs_truncated",
            format!(
                "only the first {MAX_LISTED_SPECS} binding families or live statements are \
                 read; the specs, their counts, and the default episode listing cover only those"
            ),
        );
    }
    Ok((live, truncated))
}

/// The discrepancy family of a statement live in `binding_family_id`.
fn live_spec_family(
    statement: &RecordedSpecStatementV1,
    binding_family_id: &ContractId,
) -> Result<DiscrepancyFamilyFingerprintV1> {
    let proposal = &statement.proposal;
    if &proposal.binding_family_id != binding_family_id {
        return Err(FleetError::Memory(format!(
            "it is live in {binding_family_id} but was recorded for {}",
            proposal.binding_family_id
        )));
    }
    Ok(spec_family_fingerprint(
        &proposal.scope,
        statement.statement_id,
        proposal,
        &statement.expectation,
    )?)
}

fn decode_normative_projection(row: &PgRow) -> Result<NormativeFamilyProjectionV1> {
    let binding_family_id: String = row.try_get("binding_family_id")?;
    let resolution: String = row.try_get("resolution")?;
    let canonical: Vec<u8> = row.try_get("canonical_projection")?;
    let projection: NormativeFamilyProjectionV1 = decode_strict(&canonical)?;
    if projection.binding_family_id.as_str() != binding_family_id
        || projection.resolution.as_str() != resolution
    {
        return Err(FleetError::Memory(format!(
            "the stored projection of {binding_family_id} disagrees with its columns"
        )));
    }
    Ok(projection)
}

/// The verified statements among `statement_ids`; an unrecorded one is
/// absent, an unreadable one is skipped with a warning.
async fn read_statements(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ReadScope,
    statement_ids: &[Sha256Digest],
    warnings: &mut Vec<SpecConformanceWarningV1>,
) -> Result<BTreeMap<Sha256Digest, RecordedSpecStatementV1>> {
    if statement_ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let rows: Vec<PgRow> = sqlx::query(STATEMENTS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(digest_bytes(statement_ids.iter().copied()))
        .fetch_all(&mut **transaction)
        .await?;
    let mut statements = BTreeMap::new();
    for row in &rows {
        match decode_any_statement_row(row) {
            Ok(statement) => {
                statements.insert(statement.statement_id, statement);
            }
            Err(error) => skip(
                warnings,
                "spec_row_unreadable",
                format!("a spec statement was skipped: {error}"),
            ),
        }
    }
    Ok(statements)
}

/// The latest readable check of each statement that has one.
async fn read_latest_checks(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ReadScope,
    statement_ids: &[Sha256Digest],
    warnings: &mut Vec<SpecConformanceWarningV1>,
) -> Result<BTreeMap<Sha256Digest, StoredSpecCheckV1>> {
    if statement_ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let rows: Vec<PgRow> = sqlx::query(LATEST_CHECKS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(digest_bytes(statement_ids.iter().copied()))
        .fetch_all(&mut **transaction)
        .await?;
    let mut checks = BTreeMap::new();
    for row in &rows {
        match decode_check_row(row) {
            Ok(check) => {
                checks.insert(check.record.statement_id, check);
            }
            Err(error) => skip(
                warnings,
                "spec_row_unreadable",
                format!(
                    "a spec check was skipped, so its statement reads as never checked: {error}"
                ),
            ),
        }
    }
    Ok(checks)
}

fn decode_episode_row(
    row: &PgRow,
    warnings: &mut Vec<SpecConformanceWarningV1>,
) -> Option<StoredEpisode> {
    match try_decode_episode_row(row) {
        Ok(episode) => Some(episode),
        Err(error) => {
            skip(
                warnings,
                "spec_row_unreadable",
                format!("a discrepancy episode was skipped: {error}"),
            );
            None
        }
    }
}

fn try_decode_episode_row(row: &PgRow) -> Result<StoredEpisode> {
    let episode =
        DiscrepancyEpisodeFingerprintV1::from_digest(digest_column(row, "episode_fingerprint")?);
    let family =
        DiscrepancyFamilyFingerprintV1::from_digest(digest_column(row, "family_fingerprint")?);
    let lifecycle_state = lifecycle_state_from_str(&row.try_get::<String, _>("lifecycle_state")?)?;
    let verification_state =
        verification_state_from_str(&row.try_get::<String, _>("verification_state")?)?;
    let record: DiscrepancyLogRecordV1 =
        decode_strict(&row.try_get::<Vec<u8>, _>("canonical_record")?)?;
    record.validate()?;
    let DiscrepancyLogRecordV1::Envelope { envelope } = record else {
        return Err(FleetError::Memory(format!(
            "episode {episode}'s log sequence 1 is not an envelope"
        )));
    };
    if envelope.episode_fingerprint != episode || envelope.family_fingerprint != family {
        return Err(FleetError::Memory(format!(
            "episode {episode}'s envelope names another episode or family"
        )));
    }
    Ok(StoredEpisode {
        episode,
        lifecycle_state,
        verification_state,
        envelope,
    })
}

/// The lifecycle events after the detection, at most
/// [`MAX_EPISODE_HISTORY`], and whether more exist.
async fn read_history(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ReadScope,
    episode: DiscrepancyEpisodeFingerprintV1,
    warnings: &mut Vec<SpecConformanceWarningV1>,
) -> Result<(Vec<SpecEpisodeEventV1>, bool)> {
    let rows: Vec<PgRow> = sqlx::query(EPISODE_HISTORY_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(episode.digest().as_bytes().to_vec())
        .bind(sql_limit(MAX_EPISODE_HISTORY + 1)?)
        .fetch_all(&mut **transaction)
        .await?;
    let truncated = rows.len() > MAX_EPISODE_HISTORY;
    let mut events = Vec::with_capacity(rows.len().min(MAX_EPISODE_HISTORY));
    for row in rows.iter().take(MAX_EPISODE_HISTORY) {
        match decode_history_row(row, episode) {
            Ok(event) => events.push(event),
            Err(error) => skip(
                warnings,
                "spec_row_unreadable",
                format!("a lifecycle event of episode {episode} was skipped: {error}"),
            ),
        }
    }
    Ok((events, truncated))
}

fn decode_history_row(
    row: &PgRow,
    episode: DiscrepancyEpisodeFingerprintV1,
) -> Result<SpecEpisodeEventV1> {
    let seq = u64::try_from(row.try_get::<i64, _>("seq")?)
        .map_err(|_| FleetError::Memory("a negative log sequence".into()))?;
    let record: DiscrepancyLogRecordV1 =
        decode_strict(&row.try_get::<Vec<u8>, _>("canonical_record")?)?;
    record.validate()?;
    let DiscrepancyLogRecordV1::Lifecycle { event } = record else {
        return Err(FleetError::Memory(format!(
            "log sequence {seq} is a second envelope"
        )));
    };
    if event.episode_fingerprint != episode {
        return Err(FleetError::Memory(format!(
            "log sequence {seq} targets another episode"
        )));
    }
    Ok(SpecEpisodeEventV1 {
        seq,
        effective_at: event.effective_at,
        lifecycle_transition: event.lifecycle_transition,
        verification_update: event.verification_update,
        evidence_event_ids: event.evidence_event_ids,
    })
}

/// Each episode as agents read it: its spec, whether that spec is live, and
/// what its opening check observed.
async fn describe_episodes(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ReadScope,
    snapshot: &mut SpecSnapshot,
    episodes: Vec<StoredEpisode>,
) -> Result<Vec<SpecDiscrepancyV1>> {
    let unread: Vec<Sha256Digest> = episodes
        .iter()
        .filter_map(StoredEpisode::statement_id)
        .filter(|statement_id| !snapshot.statements.contains_key(statement_id))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let more = read_statements(transaction, scope, &unread, &mut snapshot.warnings).await?;
    snapshot.statements.extend(more);
    let opening =
        read_opening_checks(transaction, scope, &episodes, &mut snapshot.warnings).await?;
    Ok(episodes
        .into_iter()
        .map(|episode| {
            let observed = opening
                .get(&episode.episode)
                .map(|check| SpecObservationV1 {
                    commit: check.record.commit_oid.clone(),
                    condition: check.record.observed_condition,
                    verification_outcome: check.record.verification_outcome,
                    observer_event_id: check.record.observer_event_id,
                    compared_at: check.record.compared_at.clone(),
                });
            describe_episode(episode, snapshot, observed)
        })
        .collect())
}

fn describe_episode(
    stored: StoredEpisode,
    snapshot: &mut SpecSnapshot,
    observed: Option<SpecObservationV1>,
) -> SpecDiscrepancyV1 {
    let spec = stored.statement_id().and_then(|statement_id| {
        let Some(statement) = snapshot.statements.get(&statement_id) else {
            skip(
                &mut snapshot.warnings,
                "spec_statement_missing",
                format!(
                    "episode {} names spec statement {statement_id}, which this scope has not \
                     recorded",
                    stored.episode
                ),
            );
            return None;
        };
        match require_episode_of(&stored.envelope, statement) {
            Ok(()) => Some(SpecStatementViewV1::of(statement)),
            Err(error) => {
                skip(
                    &mut snapshot.warnings,
                    "spec_row_unreadable",
                    format!("episode {}'s spec is withheld: {error}", stored.episode),
                );
                None
            }
        }
    });
    let spec_live = spec
        .as_ref()
        .is_some_and(|spec| snapshot.standing_statements.contains(&spec.statement_id));
    let envelope = stored.envelope;
    SpecDiscrepancyV1 {
        episode_id: stored.episode,
        family_id: envelope.family_fingerprint,
        finding_type: finding_type_name(envelope.finding_type),
        severity: envelope.severity,
        lifecycle_state: stored.lifecycle_state,
        verification_state: stored.verification_state,
        spec_live,
        detected_at: envelope.detected_at,
        subject: envelope.canonical_subject,
        predicate: envelope.predicate,
        spec,
        observed,
        evidence: SpecEvidenceV1 {
            member: envelope.member_evidence_ids,
            supporting: envelope.supporting_evidence_ids,
        },
        history: None,
        history_truncated: None,
    }
}

/// A spec episode's envelope is exactly what its statement would open: the
/// same semantic scope, binding family, and discrepancy family.
fn require_episode_of(
    envelope: &DiscrepancyEnvelopeV1,
    statement: &RecordedSpecStatementV1,
) -> Result<()> {
    let proposal = &statement.proposal;
    if proposal.scope != envelope.scope
        || proposal.binding_family_id != envelope.expectation_policy.entry_id
    {
        return Err(FleetError::Memory(
            "its statement belongs to another scope or binding family".into(),
        ));
    }
    let family = spec_family_fingerprint(
        &proposal.scope,
        statement.statement_id,
        proposal,
        &statement.expectation,
    )?;
    if family != envelope.family_fingerprint {
        return Err(FleetError::Memory(
            "its statement derives another discrepancy family".into(),
        ));
    }
    Ok(())
}

/// The earliest readable check that opened each episode: a check naming it
/// and measured by one of its member observer events.
async fn read_opening_checks(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ReadScope,
    episodes: &[StoredEpisode],
    warnings: &mut Vec<SpecConformanceWarningV1>,
) -> Result<BTreeMap<DiscrepancyEpisodeFingerprintV1, StoredSpecCheckV1>> {
    let members: BTreeMap<DiscrepancyEpisodeFingerprintV1, &[AcceptedEventId]> = episodes
        .iter()
        .filter(|episode| episode.statement_id().is_some())
        .map(|episode| {
            (
                episode.episode,
                episode.envelope.member_evidence_ids.as_slice(),
            )
        })
        .collect();
    if members.is_empty() {
        return Ok(BTreeMap::new());
    }
    let events = digest_bytes(
        members
            .values()
            .flat_map(|events| events.iter().map(|event| event.digest())),
    );
    let rows: Vec<PgRow> = sqlx::query(OPENING_CHECKS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(digest_bytes(members.keys().map(|episode| episode.digest())))
        .bind(events)
        .bind(sql_limit(MAX_OPENING_CHECK_ROWS)?)
        .fetch_all(&mut **transaction)
        .await?;
    let mut opening = BTreeMap::new();
    for row in &rows {
        let check = match decode_check_row(row) {
            Ok(check) => check,
            Err(error) => {
                skip(
                    warnings,
                    "spec_row_unreadable",
                    format!("a spec check was skipped: {error}"),
                );
                continue;
            }
        };
        let Some(episode) = check.record.episode else {
            continue;
        };
        let opened = members
            .get(&episode)
            .is_some_and(|events| events.contains(&check.record.observer_event_id));
        if opened {
            opening.entry(episode).or_insert(check);
        }
    }
    Ok(opening)
}

/// The agent-facing name of a finding type.
const fn finding_type_name(finding: FindingType) -> &'static str {
    match finding {
        FindingType::ClaimConflict => "claim_conflict",
        FindingType::ClaimEvidenceContradiction => "claim_evidence_contradiction",
        FindingType::SpecNonconformance => "spec_nonconformance",
        FindingType::DocumentationDrift => "documentation_drift",
        FindingType::ProvenanceGap => "provenance_gap",
        FindingType::LifecycleGap { .. } => "lifecycle_gap",
        FindingType::RuntimeNonconformance { .. } => "runtime_nonconformance",
        FindingType::ConfigurationDrift => "configuration_drift",
        FindingType::ReleaseIntegrityConflict => "release_integrity_conflict",
        FindingType::RegressionCandidate => "regression_candidate",
        FindingType::TelemetryDisagreement => "telemetry_disagreement",
    }
}

/// Record a skipped row or an unsettled question, and log it.
fn skip(warnings: &mut Vec<SpecConformanceWarningV1>, code: &'static str, message: String) {
    tracing::warn!(code, %message, "spec conformance read");
    warnings.push(SpecConformanceWarningV1 { code, message });
}

fn digest_bytes(digests: impl Iterator<Item = Sha256Digest>) -> Vec<Vec<u8>> {
    digests.map(|digest| digest.as_bytes().to_vec()).collect()
}

fn digest_column(row: &PgRow, column: &str) -> Result<Sha256Digest> {
    let bytes: Vec<u8> = row.try_get(column)?;
    let exact: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| FleetError::Memory(format!("stored {column} is not 32 bytes")))?;
    Ok(Sha256Digest::from_bytes(exact))
}

fn sql_limit(limit: usize) -> Result<i64> {
    i64::try_from(limit).map_err(|_| FleetError::Memory("a read bound exceeds INT8".into()))
}

#[cfg(test)]
#[path = "read_tests.rs"]
mod tests;
