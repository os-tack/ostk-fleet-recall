//! `CockroachDB` store for spec statements and spec checks (migration 0031).
//!
//! Two insert-only, private-plane tables, both keyed by the trusted
//! `(tenant_id, project)` pair bound at construction, which every statement
//! here binds as `$1` and `$2`:
//!
//! * `memory_normative_statements_v1` holds the canonical proposal and the
//!   canonical expectation each spec statement was activated with. A row is
//!   addressed by its `statement_id`, which is the digest of its own
//!   `canonical_proposal`, and is never trusted on read: [`read_statement`]
//!   recomputes the id, re-decodes both documents as strictly canonical, and
//!   re-runs [`RememberActionExpectationV1::require_bound_to`], so a row edited
//!   in place is refused rather than re-interpreted.
//! * `memory_spec_checks_v1` holds one [`SpecCheckRecordV1`] per comparison,
//!   addressed by its [`SpecCheckRecordV1::check_id`]. A check is recorded only
//!   against a statement this scope holds, and only when its member, expected
//!   membership, and binding family are that statement's.
//!
//! Writes are `INSERT ... ON CONFLICT DO NOTHING` inside
//! [`with_serializable_retry`] (which retries only on 40001). A replay of the
//! same bytes writes nothing and reports [`SpecRowWriteV1::AlreadyRecorded`];
//! a stored row whose bytes differ from the ones being written under the same
//! id is refused. There is no `UPDATE` or `DELETE` in this file, and the
//! runtime role holds only `SELECT` and `INSERT` on both tables.
//!
//! [`read_statement`]: CockroachSpecRepository::read_statement

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row as _, Transaction};

use crate::Result;
use crate::connectors::git::GitObjectId;
use crate::control_log::TrustedControlScope;
use crate::error::FleetError;
use crate::memory_contracts::canonical::{decode_typed_canonical, encode_canonical};
use crate::memory_contracts::common::{AuthenticatedProjectScopeV1, ContractId};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::discrepancy::DiscrepancyEpisodeFingerprintV1;
use crate::memory_contracts::normative_v2::NormativeBindingProposalV2;
use crate::memory_contracts::{ContractError, ContractResult};
use crate::store::cockroach::{RetryPolicy, with_serializable_retry};

use super::expectation::RememberActionExpectationV1;
use super::record::SpecCheckRecordV1;

/// Upper bound on `canonical_proposal`, as migration 0031 constrains it.
pub const MAX_CANONICAL_PROPOSAL_BYTES: usize = 1_048_576;

/// Upper bound on `canonical_expectation` and `canonical_check`, as migration
/// 0031 constrains them.
pub const MAX_CANONICAL_SPEC_RECORD_BYTES: usize = 65_536;

/// Upper bound on the statement ids one [`CockroachSpecRepository::latest_checks`]
/// call reads.
pub const MAX_LATEST_CHECK_STATEMENTS: usize = 256;

const INSERT_STATEMENT_SQL: &str = "INSERT INTO public.memory_normative_statements_v1 (\
     tenant_id, project, statement_id, binding_family_id, expectation_digest, \
     canonical_proposal, canonical_expectation, created_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, pg_catalog.statement_timestamp()) \
     ON CONFLICT (tenant_id, project, statement_id) DO NOTHING \
     RETURNING statement_id";

const INSERT_CHECK_SQL: &str = "INSERT INTO public.memory_spec_checks_v1 (\
     tenant_id, project, check_id, statement_id, family_fingerprint, observer_event_id, \
     commit_oid, verdict, episode_fingerprint, canonical_check, created_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, pg_catalog.statement_timestamp()) \
     ON CONFLICT (tenant_id, project, check_id) DO NOTHING \
     RETURNING check_id";

/// The columns [`decode_check_row`] reads.
macro_rules! check_columns {
    () => {
        "check_id, statement_id, family_fingerprint, observer_event_id, commit_oid, \
         verdict, episode_fingerprint, canonical_check, created_at"
    };
}
pub(super) use check_columns;

/// The columns [`decode_any_statement_row`] reads.
macro_rules! statement_row_columns {
    () => {
        "statement_id, binding_family_id, expectation_digest, canonical_proposal, \
         canonical_expectation, created_at"
    };
}
pub(super) use statement_row_columns;

const SELECT_STATEMENT_SQL: &str = concat!(
    "SELECT ",
    statement_row_columns!(),
    " FROM public.memory_normative_statements_v1 \
     WHERE tenant_id = $1 AND project = $2 AND statement_id = $3"
);

const SELECT_CHECK_SQL: &str = concat!(
    "SELECT ",
    check_columns!(),
    " FROM public.memory_spec_checks_v1 \
     WHERE tenant_id = $1 AND project = $2 AND check_id = $3"
);

/// The newest recorded check per statement. A replay inserts nothing, so it
/// does not make an older check the newest again.
pub(super) const LATEST_CHECKS_SQL: &str = concat!(
    "SELECT DISTINCT ON (statement_id) ",
    check_columns!(),
    " FROM public.memory_spec_checks_v1 \
     WHERE tenant_id = $1 AND project = $2 AND statement_id = ANY($3::BYTES[]) \
     ORDER BY statement_id, created_at DESC, check_id"
);

/// The newest nonconforming check of one statement at one commit, through
/// `memory_spec_checks_statement_commit_idx`.
const NONCONFORMING_CHECK_SQL: &str = concat!(
    "SELECT ",
    check_columns!(),
    " FROM public.memory_spec_checks_v1 \
     WHERE tenant_id = $1 AND project = $2 AND statement_id = $3 AND commit_oid = $4 \
       AND verdict = 'nonconforming' \
     ORDER BY created_at DESC, check_id LIMIT 1"
);

/// Whether a write stored a new row or found the identical row already there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecRowWriteV1 {
    Inserted,
    AlreadyRecorded,
}

/// What [`CockroachSpecRepository::record_statement`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SpecStatementWriteV1 {
    pub statement_id: Sha256Digest,
    pub write: SpecRowWriteV1,
}

/// What [`CockroachSpecRepository::record_check`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SpecCheckWriteV1 {
    pub check_id: Sha256Digest,
    pub write: SpecRowWriteV1,
}

/// A stored spec statement that passed every re-read check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedSpecStatementV1 {
    pub statement_id: Sha256Digest,
    pub proposal: NormativeBindingProposalV2,
    pub expectation: RememberActionExpectationV1,
    /// When the row was first written.
    pub recorded_at: DateTime<Utc>,
}

/// A stored spec check whose bytes still derive its id and its indexed
/// columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSpecCheckV1 {
    pub check_id: Sha256Digest,
    pub record: SpecCheckRecordV1,
    /// When the row was first written. A replay does not move it.
    pub recorded_at: DateTime<Utc>,
}

/// Spec statement and spec check store bound once to physical and semantic
/// scope.
#[derive(Clone)]
pub struct CockroachSpecRepository {
    pool: PgPool,
    trusted_scope: TrustedControlScope,
    retry_policy: RetryPolicy,
}

impl std::fmt::Debug for CockroachSpecRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachSpecRepository")
            .field("trusted_scope", &self.trusted_scope)
            .finish_non_exhaustive()
    }
}

impl CockroachSpecRepository {
    /// Bind one pool, one physical/semantic scope, and one retry policy.
    #[must_use]
    pub const fn new(
        pool: PgPool,
        trusted_scope: TrustedControlScope,
        retry_policy: RetryPolicy,
    ) -> Self {
        Self {
            pool,
            trusted_scope,
            retry_policy,
        }
    }

    /// The scope every statement here binds.
    #[must_use]
    pub const fn trusted_scope(&self) -> &TrustedControlScope {
        &self.trusted_scope
    }

    /// Record the canonical proposal and expectation of one spec statement.
    ///
    /// The expectation must be bound to the proposal, and the proposal must be
    /// minted for this repository's semantic scope. Recording is idempotent: the
    /// same pair again is [`SpecRowWriteV1::AlreadyRecorded`]. A stored row under
    /// the same `statement_id` whose bytes differ is refused.
    ///
    /// # Errors
    ///
    /// A contract error for an unbound, out-of-scope, or oversized statement;
    /// [`FleetError::Memory`] for a divergent stored row; a database error.
    pub async fn record_statement(
        &self,
        proposal: &NormativeBindingProposalV2,
        expectation: &RememberActionExpectationV1,
    ) -> Result<SpecStatementWriteV1> {
        require_scope(proposal, self.trusted_scope.semantic_scope())?;
        expectation.require_bound_to(proposal)?;
        let statement_id = proposal.statement_id()?;
        let row = StatementColumns {
            statement_id,
            binding_family_id: proposal.binding_family_id.as_str().to_owned(),
            expectation_digest: expectation.fingerprint()?,
            canonical_proposal: bounded(
                encode_canonical(proposal)?,
                MAX_CANONICAL_PROPOSAL_BYTES,
                "canonical proposal",
            )?,
            canonical_expectation: bounded(
                expectation.canonical_bytes()?,
                MAX_CANONICAL_SPEC_RECORD_BYTES,
                "canonical expectation",
            )?,
        };
        let scope = self.trusted_scope.clone();
        let write = with_serializable_retry(&self.pool, self.retry_policy, move |transaction| {
            let scope = scope.clone();
            let row = row.clone();
            Box::pin(async move { insert_statement(transaction, &scope, &row).await })
        })
        .await?;
        Ok(SpecStatementWriteV1 {
            statement_id,
            write,
        })
    }

    /// Read one spec statement back, verified.
    ///
    /// Returns `None` when this scope holds no such statement. A stored row is
    /// refused unless its proposal re-derives `statement_id`, belongs to this
    /// scope, and names the row's binding family, and its expectation hashes
    /// to the row's `expectation_digest` and is still bound to the proposal.
    ///
    /// # Errors
    ///
    /// [`FleetError::Memory`] for a row that fails verification; a database
    /// error.
    pub async fn read_statement(
        &self,
        statement_id: Sha256Digest,
    ) -> Result<Option<RecordedSpecStatementV1>> {
        let row: Option<PgRow> = sqlx::query(SELECT_STATEMENT_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(statement_id.as_bytes().to_vec())
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            decode_statement_row(
                Some(self.trusted_scope.semantic_scope()),
                statement_id,
                &row,
            )
        })
        .transpose()
    }

    /// Record one spec check.
    ///
    /// The check must cite a statement this scope holds, with that
    /// statement's binding family, member, and expected membership. Recording
    /// is idempotent: the same record again is
    /// [`SpecRowWriteV1::AlreadyRecorded`]. A stored row under the same
    /// `check_id` whose bytes or indexed columns differ is refused.
    ///
    /// # Errors
    ///
    /// A contract error for an invalid or oversized record;
    /// [`FleetError::Memory`] for a check that does not match its statement,
    /// cites an unrecorded statement, or collides with a divergent row; a
    /// database error.
    pub async fn record_check(&self, check: &SpecCheckRecordV1) -> Result<SpecCheckWriteV1> {
        let check_id = check.check_id()?;
        let row = CheckColumns::from_record(
            check_id,
            check,
            bounded(
                check.canonical_bytes()?,
                MAX_CANONICAL_SPEC_RECORD_BYTES,
                "canonical check",
            )?,
        );
        let scope = self.trusted_scope.clone();
        let check = check.clone();
        let write = with_serializable_retry(&self.pool, self.retry_policy, move |transaction| {
            let scope = scope.clone();
            let row = row.clone();
            let check = check.clone();
            Box::pin(async move { insert_check(transaction, &scope, &check, &row).await })
        })
        .await?;
        Ok(SpecCheckWriteV1 { check_id, write })
    }

    /// The newest recorded check of each listed statement that has one,
    /// ordered by statement id. A statement never checked is simply absent.
    ///
    /// # Errors
    ///
    /// [`FleetError::Memory`] for more than [`MAX_LATEST_CHECK_STATEMENTS`]
    /// distinct statements or a stored check that fails verification; a
    /// database error.
    pub async fn latest_checks(
        &self,
        statement_ids: &[Sha256Digest],
    ) -> Result<Vec<StoredSpecCheckV1>> {
        let distinct: BTreeSet<Sha256Digest> = statement_ids.iter().copied().collect();
        if distinct.is_empty() {
            return Ok(Vec::new());
        }
        if distinct.len() > MAX_LATEST_CHECK_STATEMENTS {
            return Err(FleetError::Memory(format!(
                "latest spec checks read at most {MAX_LATEST_CHECK_STATEMENTS} statements"
            )));
        }
        let ids: Vec<Vec<u8>> = distinct
            .iter()
            .map(|statement_id| statement_id.as_bytes().to_vec())
            .collect();
        let rows: Vec<PgRow> = sqlx::query(LATEST_CHECKS_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(ids)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(decode_check_row).collect()
    }

    /// The newest nonconforming check of `statement_id` at `commit_oid`, if
    /// any: whether that commit was already judged nonconforming under that
    /// statement.
    ///
    /// # Errors
    ///
    /// [`FleetError::Memory`] for a stored check that fails verification; a
    /// database error.
    pub async fn nonconforming_check_for(
        &self,
        statement_id: Sha256Digest,
        commit_oid: &GitObjectId,
    ) -> Result<Option<StoredSpecCheckV1>> {
        let row: Option<PgRow> = sqlx::query(NONCONFORMING_CHECK_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(statement_id.as_bytes().to_vec())
            .bind(commit_oid.to_hex())
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(decode_check_row).transpose()
    }
}

/// The stored columns of one statement row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StatementColumns {
    statement_id: Sha256Digest,
    binding_family_id: String,
    expectation_digest: Sha256Digest,
    canonical_proposal: Vec<u8>,
    canonical_expectation: Vec<u8>,
}

/// The stored columns of one check row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckColumns {
    check_id: Sha256Digest,
    statement_id: Sha256Digest,
    family_fingerprint: Sha256Digest,
    observer_event_id: Sha256Digest,
    commit_oid: String,
    verdict: String,
    episode_fingerprint: Option<Sha256Digest>,
    canonical_check: Vec<u8>,
}

impl CheckColumns {
    fn from_record(check_id: Sha256Digest, record: &SpecCheckRecordV1, canonical: Vec<u8>) -> Self {
        Self {
            check_id,
            statement_id: record.statement_id,
            family_fingerprint: record.family_fingerprint.digest(),
            observer_event_id: record.observer_event_id.digest(),
            commit_oid: record.commit_oid.to_hex(),
            verdict: record.verdict.as_str().to_owned(),
            episode_fingerprint: record.episode.map(DiscrepancyEpisodeFingerprintV1::digest),
            canonical_check: canonical,
        }
    }

    fn from_row(row: &PgRow) -> Result<Self> {
        let episode: Option<Vec<u8>> = row.try_get("episode_fingerprint")?;
        Ok(Self {
            check_id: digest_column(row, "check_id")?,
            statement_id: digest_column(row, "statement_id")?,
            family_fingerprint: digest_column(row, "family_fingerprint")?,
            observer_event_id: digest_column(row, "observer_event_id")?,
            commit_oid: row.try_get("commit_oid")?,
            verdict: row.try_get("verdict")?,
            episode_fingerprint: episode.as_deref().map(digest_from).transpose()?,
            canonical_check: row.try_get("canonical_check")?,
        })
    }
}

async fn insert_statement(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    row: &StatementColumns,
) -> Result<SpecRowWriteV1> {
    let inserted: Option<Vec<u8>> = sqlx::query_scalar(INSERT_STATEMENT_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(row.statement_id.as_bytes().to_vec())
        .bind(&row.binding_family_id)
        .bind(row.expectation_digest.as_bytes().to_vec())
        .bind(&row.canonical_proposal)
        .bind(&row.canonical_expectation)
        .fetch_optional(&mut **transaction)
        .await?;
    if inserted.is_some() {
        return Ok(SpecRowWriteV1::Inserted);
    }
    let stored: PgRow = sqlx::query(SELECT_STATEMENT_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(row.statement_id.as_bytes().to_vec())
        .fetch_one(&mut **transaction)
        .await?;
    if &statement_columns(&stored)? != row {
        return Err(FleetError::Memory(format!(
            "stored normative statement {} diverges from the statement being recorded",
            row.statement_id
        )));
    }
    Ok(SpecRowWriteV1::AlreadyRecorded)
}

async fn insert_check(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    check: &SpecCheckRecordV1,
    row: &CheckColumns,
) -> Result<SpecRowWriteV1> {
    let statement: Option<PgRow> = sqlx::query(SELECT_STATEMENT_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(check.statement_id.as_bytes().to_vec())
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(statement) = statement else {
        return Err(FleetError::Memory(format!(
            "spec check cites statement {} that this scope has not recorded",
            check.statement_id
        )));
    };
    let statement =
        decode_statement_row(Some(scope.semantic_scope()), check.statement_id, &statement)?;
    require_check_matches_statement(check, &statement).map_err(|error| {
        FleetError::Memory(format!(
            "spec check does not match statement {}: {error}",
            check.statement_id
        ))
    })?;

    let inserted: Option<Vec<u8>> = sqlx::query_scalar(INSERT_CHECK_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(row.check_id.as_bytes().to_vec())
        .bind(row.statement_id.as_bytes().to_vec())
        .bind(row.family_fingerprint.as_bytes().to_vec())
        .bind(row.observer_event_id.as_bytes().to_vec())
        .bind(&row.commit_oid)
        .bind(&row.verdict)
        .bind(
            row.episode_fingerprint
                .map(|episode| episode.as_bytes().to_vec()),
        )
        .bind(&row.canonical_check)
        .fetch_optional(&mut **transaction)
        .await?;
    if inserted.is_some() {
        return Ok(SpecRowWriteV1::Inserted);
    }
    let stored: PgRow = sqlx::query(SELECT_CHECK_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(row.check_id.as_bytes().to_vec())
        .fetch_one(&mut **transaction)
        .await?;
    if &CheckColumns::from_row(&stored)? != row {
        return Err(FleetError::Memory(format!(
            "stored spec check {} diverges from the check being recorded",
            row.check_id
        )));
    }
    Ok(SpecRowWriteV1::AlreadyRecorded)
}

/// A check judges its statement's own expectation, under its statement's
/// binding family.
fn require_check_matches_statement(
    check: &SpecCheckRecordV1,
    statement: &RecordedSpecStatementV1,
) -> ContractResult<()> {
    if check.binding_family_id != statement.proposal.binding_family_id {
        return Err(ContractError::Schema(
            "the check names another binding family".into(),
        ));
    }
    if check.member != statement.expectation.member
        || check.expected != statement.expectation.expected
    {
        return Err(ContractError::Schema(
            "the check's member or expected membership is not the statement's expectation".into(),
        ));
    }
    Ok(())
}

fn statement_columns(row: &PgRow) -> Result<StatementColumns> {
    Ok(StatementColumns {
        statement_id: digest_column(row, "statement_id")?,
        binding_family_id: row.try_get("binding_family_id")?,
        expectation_digest: digest_column(row, "expectation_digest")?,
        canonical_proposal: row.try_get("canonical_proposal")?,
        canonical_expectation: row.try_get("canonical_expectation")?,
    })
}

/// One statement row of whatever id it holds, verified like
/// [`CockroachSpecRepository::read_statement`] verifies one, except that its
/// proposal's semantic scope is not compared with a bound one: a reader bound
/// only to the physical `(tenant_id, project)` pair, as `serve` is, has none to
/// compare it with.
pub(super) fn decode_any_statement_row(row: &PgRow) -> Result<RecordedSpecStatementV1> {
    decode_statement_row(None, digest_column(row, "statement_id")?, row)
}

fn decode_statement_row(
    semantic_scope: Option<&AuthenticatedProjectScopeV1>,
    requested: Sha256Digest,
    row: &PgRow,
) -> Result<RecordedSpecStatementV1> {
    let columns = statement_columns(row)?;
    let recorded_at: DateTime<Utc> = row.try_get("created_at")?;
    let (proposal, expectation) = verify_statement_columns(semantic_scope, requested, &columns)
        .map_err(|error| {
            FleetError::Memory(format!(
                "stored normative statement {requested} fails verification: {error}"
            ))
        })?;
    Ok(RecordedSpecStatementV1 {
        statement_id: requested,
        proposal,
        expectation,
        recorded_at,
    })
}

/// Every re-read check on one stored statement row, free of I/O. The
/// proposal's scope is compared with `semantic_scope` when one is given.
fn verify_statement_columns(
    semantic_scope: Option<&AuthenticatedProjectScopeV1>,
    requested: Sha256Digest,
    columns: &StatementColumns,
) -> ContractResult<(NormativeBindingProposalV2, RememberActionExpectationV1)> {
    let proposal: NormativeBindingProposalV2 = decode_typed_canonical(&columns.canonical_proposal)?;
    let expectation: RememberActionExpectationV1 =
        decode_typed_canonical(&columns.canonical_expectation)?;
    if columns.statement_id != requested || proposal.statement_id()? != requested {
        return Err(ContractError::Schema(
            "the stored proposal does not derive its statement id".into(),
        ));
    }
    if semantic_scope.is_some_and(|scope| &proposal.scope != scope) {
        return Err(ContractError::Schema(
            "the stored proposal belongs to another project scope".into(),
        ));
    }
    if ContractId::new(columns.binding_family_id.clone())? != proposal.binding_family_id {
        return Err(ContractError::Schema(
            "the stored binding family is not the proposal's".into(),
        ));
    }
    if expectation.fingerprint()? != columns.expectation_digest {
        return Err(ContractError::Schema(
            "the stored expectation does not derive its expectation digest".into(),
        ));
    }
    expectation.require_bound_to(&proposal)?;
    Ok((proposal, expectation))
}

pub(super) fn decode_check_row(row: &PgRow) -> Result<StoredSpecCheckV1> {
    let columns = CheckColumns::from_row(row)?;
    let recorded_at: DateTime<Utc> = row.try_get("created_at")?;
    let record = verify_check_columns(&columns).map_err(|error| {
        FleetError::Memory(format!(
            "stored spec check {} fails verification: {error}",
            columns.check_id
        ))
    })?;
    Ok(StoredSpecCheckV1 {
        check_id: columns.check_id,
        record,
        recorded_at,
    })
}

/// Every re-read check on one stored check row, free of I/O: the canonical
/// record derives the row's id, and each indexed column is a copy of the
/// record's own field.
fn verify_check_columns(columns: &CheckColumns) -> ContractResult<SpecCheckRecordV1> {
    let record: SpecCheckRecordV1 = decode_typed_canonical(&columns.canonical_check)?;
    let check_id = record.check_id()?;
    if CheckColumns::from_record(check_id, &record, columns.canonical_check.clone()) != *columns {
        return Err(ContractError::Schema(
            "the stored check's columns are not its canonical record's".into(),
        ));
    }
    Ok(record)
}

fn require_scope(
    proposal: &NormativeBindingProposalV2,
    semantic_scope: &AuthenticatedProjectScopeV1,
) -> ContractResult<()> {
    if &proposal.scope != semantic_scope {
        return Err(ContractError::Schema(
            "spec statement proposal scope is not the repository's bound project scope".into(),
        ));
    }
    Ok(())
}

fn bounded(bytes: Vec<u8>, limit: usize, what: &str) -> ContractResult<Vec<u8>> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(ContractError::Schema(format!(
            "{what} must be 1 to {limit} bytes"
        )));
    }
    Ok(bytes)
}

fn digest_column(row: &PgRow, column: &str) -> Result<Sha256Digest> {
    let bytes: Vec<u8> = row.try_get(column)?;
    digest_from(&bytes)
}

fn digest_from(bytes: &[u8]) -> Result<Sha256Digest> {
    let exact: [u8; 32] = bytes
        .try_into()
        .map_err(|_| FleetError::Memory("stored spec digest is not 32 bytes".into()))?;
    Ok(Sha256Digest::from_bytes(exact))
}

#[cfg(test)]
#[path = "cockroach_tests.rs"]
mod tests;
