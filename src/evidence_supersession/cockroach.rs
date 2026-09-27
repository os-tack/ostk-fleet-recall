//! `CockroachDB` side of the at-rest supersession pass.
//!
//! Two passes over the scope's `evidence.accepted` events, paged in
//! `(epoch_id, shard, committed_offset)` order:
//!
//! 1. **Worklist.** Every event is decoded once. Git facts are queued; for
//!    every event the storage identity of its governed content is counted,
//!    so the second pass knows which content objects are shared; a
//!    transcript turn whose stored text the active profile would change is
//!    counted as raw at rest.
//! 2. **Action.** Each queued git fact is probed for a successor (one seek on
//!    migration 0037's index), then, when none exists, opened with the key,
//!    redacted, re-rendered under the binding of the source it was admitted
//!    from, admitted with a `supersedes` lineage, and appended through the
//!    ledger with a projection that stores the successor's content and
//!    erases the raw representation in the same transaction.
//!
//! # Erase cost
//!
//! `memory_chunk_occurrences_v1` is keyed by `occurrence_id` and carries no
//! secondary index on `accepted_event_id` or `body_content_id`, so both the
//! "this event's occurrences" selection and the per-body `NOT EXISTS`
//! reference check are range scans over the scope's occurrence rows. One
//! superseded fact therefore costs `1 + bodies` scope scans of that table.
//! The pass is a one-shot over the pre-profile-3 backlog and runs under the
//! ledger's serializable retry, so the cost is accepted rather than paid for
//! with a permanent index the steady state never needs; a deployment whose
//! backlog makes it untenable adds the index in a forward migration first.
//!
//! # What runs under which grant
//!
//! Every statement here is one `fleet_supersession` holds
//! (`deploy/cockroach/supersession-role-grants.sql`): SELECT on the migration
//! history, the authority view, the ledger, the quarantine, the content
//! store, and the body plane; INSERT/UPDATE on what the ledger append seam
//! needs; DELETE on the content store and the body plane only. Nothing here
//! touches `memory_control_*` or `memory_registry_*`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::connectors::git::{
    GitConnectorBindingV1, GitFactV1, GitIngressClocksV1, redact_git_fact,
};
use crate::connectors::transcript::TranscriptTurnBodyV1;
use crate::evidence_ledger::{
    AcceptedEventRepository as _, ActiveStage4Package, AppendOutcome, AppendProjection,
    ContentKeyEncryptionKey, EvidenceAdmissionRequestV1, EvidenceAppendResult,
    GovernedContentProjection, ProjectionContext, admit_evidence, fetch_governed_content,
};
use crate::memory_contracts::canonical::decode_strict;
use crate::memory_contracts::chunk_identity::StorageIdentityPreimageV1;
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::evidence_v2::{EvidenceStatementV2, RepresentationLineageV2};
use crate::memory_contracts::generation2_registry::GIT_CONNECTOR;
use crate::memory_contracts::identity::ResourceUri;
use crate::redaction::RedactionGuaranteeV1;
use crate::registry_witness::WriterAuthorityRuntime;
use crate::store::cockroach::{
    EVIDENCE_PREDECESSOR_KEY_SCHEMA_VERSION, read_schema_version, with_serializable_retry,
};
use crate::{FleetError, Result};

use super::{
    ContentReferencesV1, EventKindV1, GitFactDecisionV1, SupersessionReportV1,
    SupersessionRequestV1, classify_media_type, decide_git_fact, transcript_text_is_raw_at_rest,
};

const EVIDENCE_ACCEPTED_EVENT_KIND: &str = "evidence.accepted";
const STORAGE_IDENTITY_SCHEMA_VERSION: u32 = 1;
const WORKLIST_PAGE_ROWS: usize = 256;

/// The body table, named once so the report can count its rows separately.
pub const BODY_TABLE: &str = "memory_body_objects_v1";

const SELECT_FIRST_PAGE_SQL: &str = "SELECT epoch_id, shard, committed_offset, event_id, \
     canonical_event FROM public.memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND event_kind = $3 \
     ORDER BY epoch_id, shard, committed_offset LIMIT 256";

const SELECT_NEXT_PAGE_SQL: &str = "SELECT epoch_id, shard, committed_offset, event_id, \
     canonical_event FROM public.memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND event_kind = $3 \
       AND (epoch_id, shard, committed_offset) > ($4, $5, $6) \
     ORDER BY epoch_id, shard, committed_offset LIMIT 256";

const SELECT_EVENT_BY_ID_SQL: &str = "SELECT canonical_event FROM public.memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND event_id = $3";

/// One seek on migration 0037's predecessor-key index.
const SELECT_SUCCESSOR_EXISTS_SQL: &str = "SELECT EXISTS (\
     SELECT 1 FROM public.memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND predecessor_representation_key_digest = $3 \
       AND event_kind = $4)";

// The erase, in statement order. $1 tenant, $2 project, $3 the raw accepted
// event id; $4 the raw source representation URI; $5 the raw storage
// identity; the per-body statements bind the body id as $3.
const SELECT_RAW_BODIES_SQL: &str = "SELECT DISTINCT body_content_id \
     FROM public.memory_chunk_occurrences_v1 \
     WHERE tenant_id = $1 AND project = $2 AND accepted_event_id = $3";

const DELETE_RAW_SPANS_SQL: &str = "DELETE FROM public.memory_chunk_occurrence_spans_v1 \
     WHERE tenant_id = $1 AND project = $2 AND occurrence_id IN (\
       SELECT occurrence_id FROM public.memory_chunk_occurrences_v1 \
       WHERE tenant_id = $1 AND project = $2 AND accepted_event_id = $3)";

const DELETE_RAW_OCCURRENCES_SQL: &str = "DELETE FROM public.memory_chunk_occurrences_v1 \
     WHERE tenant_id = $1 AND project = $2 AND accepted_event_id = $3";

// Each per-body delete carries the same orphan predicate verbatim (a
// `NOT EXISTS` over the scope's occurrences for that body); the test module
// pins it.
const DELETE_ORPHAN_DENSE_SQL: &str = "DELETE FROM public.memory_body_dense_projection_v1 \
     WHERE tenant_id = $1 AND project = $2 AND body_content_id = $3 \
       AND NOT EXISTS (\
       SELECT 1 FROM public.memory_chunk_occurrences_v1 AS occurrence \
       WHERE occurrence.tenant_id = $1 AND occurrence.project = $2 \
         AND occurrence.body_content_id = $3)";

const DELETE_ORPHAN_LEXICAL_SQL: &str = "DELETE FROM public.memory_body_lexical_projection_v1 \
     WHERE tenant_id = $1 AND project = $2 AND body_content_id = $3 \
       AND NOT EXISTS (\
       SELECT 1 FROM public.memory_chunk_occurrences_v1 AS occurrence \
       WHERE occurrence.tenant_id = $1 AND occurrence.project = $2 \
         AND occurrence.body_content_id = $3)";

const DELETE_ORPHAN_VISIBILITY_SQL: &str = "DELETE FROM public.memory_body_visibility_v1 \
     WHERE tenant_id = $1 AND project = $2 AND body_content_id = $3 \
       AND NOT EXISTS (\
       SELECT 1 FROM public.memory_chunk_occurrences_v1 AS occurrence \
       WHERE occurrence.tenant_id = $1 AND occurrence.project = $2 \
         AND occurrence.body_content_id = $3)";

const DELETE_ORPHAN_BODY_SQL: &str = "DELETE FROM public.memory_body_objects_v1 \
     WHERE tenant_id = $1 AND project = $2 AND content_sha256 = $3 \
       AND NOT EXISTS (\
       SELECT 1 FROM public.memory_chunk_occurrences_v1 AS occurrence \
       WHERE occurrence.tenant_id = $1 AND occurrence.project = $2 \
         AND occurrence.body_content_id = $3)";

/// The pointer goes only when it names one of the raw event's manifests
/// (the raw event may hold one per parser generation); a pointer the
/// successor has since installed for the same source is left alone.
const DELETE_RAW_POINTER_SQL: &str = "DELETE FROM public.memory_generation_pointers_v1 \
     WHERE tenant_id = $1 AND project = $2 AND source_representation_uri = $4 \
       AND active_manifest_id IN (\
       SELECT manifest_id FROM public.memory_parse_run_manifests_v1 \
       WHERE tenant_id = $1 AND project = $2 AND accepted_event_id = $3)";

const DELETE_RAW_MANIFESTS_SQL: &str = "DELETE FROM public.memory_parse_run_manifests_v1 \
     WHERE tenant_id = $1 AND project = $2 AND accepted_event_id = $3";

const DELETE_CONTENT_OBJECT_SQL: &str = "DELETE FROM public.memory_content_objects \
     WHERE tenant_id = $1 AND project = $2 AND storage_identity = $3";

/// The raw representation one erase removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EraseTargetV1 {
    /// The raw accepted event: what the body plane keyed its rows on.
    pub raw_event_id: AcceptedEventId,
    /// The raw event's canonical resource, the generation pointer's key.
    pub source_representation_uri: String,
    /// The raw governed content object.
    pub storage_identity: Sha256Digest,
    /// Whether this erase may delete the content object: the worklist proved
    /// this event is its only reference.
    pub delete_content: bool,
}

/// Run the pass over `runtime`'s scope.
///
/// # Errors
///
/// A schema below migration 0037; a head that does not verify; a content
/// object missing for a git fact that has no successor; a re-rendered fact
/// whose source-fact identity is not the raw one; any storage failure. Every
/// error is returned before the next event is touched, so a partial run
/// leaves each superseded fact complete (append and erase are one
/// transaction) and the rest untouched.
pub async fn run_supersession(
    pool: &PgPool,
    runtime: &WriterAuthorityRuntime,
    kek: &ContentKeyEncryptionKey,
    request: SupersessionRequestV1<'_>,
) -> Result<SupersessionReportV1> {
    let schema = read_schema_version(pool).await?;
    if schema < EVIDENCE_PREDECESSOR_KEY_SCHEMA_VERSION {
        return Err(FleetError::Configuration(format!(
            "the at-rest supersession pass needs the schema through migration \
             {EVIDENCE_PREDECESSOR_KEY_SCHEMA_VERSION}, but the database is at {schema}"
        )));
    }
    let verified = runtime.verify().await?;
    let active = verified
        .bind_connector(&ContractId::new(GIT_CONNECTOR.connector_schema)?)
        .map_err(|error| {
            describe(
                "the active package does not admit the git connector",
                &error,
            )
        })?;
    let guarantee = RedactionGuaranteeV1::from_active_package(&active)
        .map_err(|error| describe("the active package promises no redaction", &error))?;
    let bindings = resolve_bindings(&active, request.sources)?;
    let scope = Scope {
        tenant_id: runtime.physical_scope().tenant_id,
        project: runtime.physical_scope().project.clone(),
    };

    let mut report = SupersessionReportV1::new(request.dry_run);
    let worklist = build_worklist(pool, runtime, kek, &scope, &guarantee, &mut report).await?;

    let pass = Pass {
        pool,
        runtime,
        kek,
        verified: &verified,
        active: &active,
        guarantee: &guarantee,
        bindings: &bindings,
        scope: &scope,
        dry_run: request.dry_run,
    };
    let mut references = worklist.references;
    for raw_event_id in worklist.git_facts {
        pass.supersede_one(raw_event_id, &mut references, &mut report)
            .await?;
    }
    pass.release_shared_content(&references, &mut report)
        .await?;
    Ok(report)
}

/// Everything one run holds constant across its git facts.
struct Pass<'run> {
    pool: &'run PgPool,
    runtime: &'run WriterAuthorityRuntime,
    kek: &'run ContentKeyEncryptionKey,
    verified: &'run crate::registry_witness::VerifiedWriterAuthority,
    active: &'run ActiveStage4Package,
    guarantee: &'run RedactionGuaranteeV1,
    bindings: &'run [(ResourceUri, GitConnectorBindingV1)],
    scope: &'run Scope,
    dry_run: bool,
}

impl Pass<'_> {
    /// One git fact: probe, open, redact, decide, and act.
    async fn supersede_one(
        &self,
        raw_event_id: AcceptedEventId,
        references: &mut BTreeMap<Sha256Digest, ContentReferencesV1>,
        report: &mut SupersessionReportV1,
    ) -> Result<()> {
        let Some(canonical) = fetch_canonical_event(self.pool, self.scope, raw_event_id).await?
        else {
            return Err(FleetError::Memory(format!(
                "accepted event {raw_event_id} vanished between the worklist and the pass"
            )));
        };
        let raw: EvidenceStatementV2 = decode_strict(&canonical)?;
        let storage_identity = storage_identity_of(&raw)?;
        let successor_exists =
            successor_exists(self.pool, self.scope, raw.representation_key.digest()).await?;
        let references_here = references.entry(storage_identity).or_default();
        let target = EraseTargetV1 {
            raw_event_id,
            source_representation_uri: raw.source_fact.canonical_resource_id.to_string(),
            storage_identity,
            delete_content: references_here.sole_reference(),
        };

        if successor_exists {
            report.skipped_with_successor += 1;
            references_here.resolved += 1;
            if !self.dry_run {
                let removed =
                    erase_in_own_transaction(self.pool, self.runtime, self.scope, &target).await?;
                report.absorb(&removed);
            }
            return Ok(());
        }

        let sealed = fetch_governed_content(
            self.pool,
            self.scope.tenant_id,
            &self.scope.project,
            self.runtime.semantic_scope(),
            storage_identity,
        )
        .await?
        .ok_or_else(|| {
            FleetError::Memory(format!(
                "accepted event {raw_event_id} has no governed content object and no successor"
            ))
        })?;
        let raw_bytes = sealed.open(self.kek)?;
        let raw_fact: GitFactV1 = decode_strict(&raw_bytes)?;
        let (redacted, redaction) = redact_git_fact(self.guarantee, &raw_fact)
            .map_err(|error| describe("redacting the raw git fact", &error))?;
        match decide_git_fact(false, redaction.redacted()) {
            GitFactDecisionV1::UnchangedUnderProfile => {
                report.unchanged_under_profile += 1;
                return Ok(());
            }
            GitFactDecisionV1::SkipWithSuccessor => unreachable!("no successor was found"),
            GitFactDecisionV1::Supersede => {}
        }
        let Some(binding) = self
            .bindings
            .iter()
            .find(|(instance, _)| *instance == raw.source_fact.provider_instance_id)
            .map(|(_, binding)| binding)
        else {
            report.source_unbound += 1;
            return Ok(());
        };
        if self.dry_run {
            report.superseded += 1;
            references_here.resolved += 1;
            return Ok(());
        }

        match self
            .append_successor(binding, &raw, &redacted, target.clone())
            .await?
        {
            AppendedSuccessor::Appended(removed) => {
                report.superseded += 1;
                references_here.resolved += 1;
                report.absorb(&removed);
            }
            AppendedSuccessor::Replayed => {
                report.skipped_with_successor += 1;
                references_here.resolved += 1;
                let removed =
                    erase_in_own_transaction(self.pool, self.runtime, self.scope, &target).await?;
                report.absorb(&removed);
            }
            AppendedSuccessor::Quarantined => {
                report.quarantined += 1;
            }
        }
        Ok(())
    }

    /// Render the redacted successor under `binding`, admit it with a
    /// `supersedes` lineage, and append it with the erase in one
    /// transaction.
    async fn append_successor(
        &self,
        binding: &GitConnectorBindingV1,
        raw: &EvidenceStatementV2,
        redacted: &GitFactV1,
        target: EraseTargetV1,
    ) -> Result<AppendedSuccessor> {
        let now = server_instant(self.pool).await?;
        let ingress = binding
            .build_ingress(redacted, &GitIngressClocksV1 { received_at: now }, 1)
            .map_err(|error| describe("building the successor ingress", &error))?;
        if ingress.candidate.source_fact != raw.source_fact {
            return Err(FleetError::Memory(format!(
                "the redacted rendering of accepted event {} names a different source fact \
                 than the raw one; refusing to supersede",
                target.raw_event_id
            )));
        }
        let admitted = admit_evidence(
            self.active,
            EvidenceAdmissionRequestV1 {
                candidate: &ingress.candidate,
                locators: &ingress.locators,
                canonical_payload: &ingress.canonical_payload,
                delivery: ingress.delivery.clone(),
                lineage: RepresentationLineageV2::Supersedes {
                    predecessor_representation_key: raw.representation_key,
                },
            },
        )
        .map_err(|error| describe("admitting the successor", &error))?;
        let appendable = admitted.appendable(self.verified.append_witness())?;
        let removed = Arc::new(Mutex::new(BTreeMap::new()));
        let projection = Arc::new(ProjectionHandle {
            inner: SupersessionProjection {
                content: GovernedContentProjection::new(
                    self.runtime.control_scope(),
                    admitted.content(),
                    self.kek,
                )?,
                scope: self.scope.clone(),
                target,
            },
            removed: Arc::clone(&removed),
        });
        let outcome = self
            .runtime
            .ledger()
            .append(self.verified.append_witness(), &appendable, projection)
            .await?;
        Ok(match outcome {
            AppendOutcome::Appended { .. } => AppendedSuccessor::Appended(
                removed
                    .lock()
                    .map_or_else(|_| BTreeMap::new(), |map| map.clone()),
            ),
            AppendOutcome::Replayed { .. } => AppendedSuccessor::Replayed,
            AppendOutcome::Quarantined { .. } => AppendedSuccessor::Quarantined,
        })
    }

    /// Shared content objects: released only once every event referencing
    /// them has a successor, otherwise counted and left in place.
    async fn release_shared_content(
        &self,
        references: &BTreeMap<Sha256Digest, ContentReferencesV1>,
        report: &mut SupersessionReportV1,
    ) -> Result<()> {
        for (storage_identity, counts) in references {
            if !counts.shared() || counts.resolved == 0 {
                continue;
            }
            if counts.releasable() {
                if !self.dry_run {
                    let removed = delete_content_in_own_transaction(
                        self.pool,
                        self.runtime,
                        self.scope,
                        *storage_identity,
                    )
                    .await?;
                    report.absorb(&removed);
                }
            } else {
                report.content_shared_skipped += counts.resolved;
            }
        }
        Ok(())
    }
}

/// What appending one successor did, with the erase counts of the attempt
/// that committed.
enum AppendedSuccessor {
    Appended(BTreeMap<&'static str, u64>),
    Replayed,
    Quarantined,
}

#[derive(Debug, Clone)]
struct Scope {
    tenant_id: Uuid,
    project: String,
}

struct Worklist {
    git_facts: Vec<AcceptedEventId>,
    references: BTreeMap<Sha256Digest, ContentReferencesV1>,
}

/// Bind every git source of the sources file to the active package, keyed
/// by the provider-instance URI its facts were admitted under.
fn resolve_bindings(
    active: &ActiveStage4Package,
    sources: &crate::worker::WorkerSourcesV1,
) -> Result<Vec<(ResourceUri, GitConnectorBindingV1)>> {
    sources
        .git
        .iter()
        .map(|source| {
            let binding = GitConnectorBindingV1::resolve(
                active,
                source.connector_principal.clone(),
                source.connector_instance.clone(),
                source.installation_id,
            )
            .map_err(|error| describe("binding a git source", &error))?;
            let instance = binding
                .provider_instance_uri()
                .map_err(|error| describe("deriving a git source's provider instance", &error))?;
            Ok((instance, binding))
        })
        .collect()
}

async fn build_worklist(
    pool: &PgPool,
    runtime: &WriterAuthorityRuntime,
    kek: &ContentKeyEncryptionKey,
    scope: &Scope,
    guarantee: &RedactionGuaranteeV1,
    report: &mut SupersessionReportV1,
) -> Result<Worklist> {
    let mut worklist = Worklist {
        git_facts: Vec::new(),
        references: BTreeMap::new(),
    };
    let mut cursor: Option<(Vec<u8>, i32, i64)> = None;
    loop {
        let rows = fetch_page(pool, scope, cursor.as_ref()).await?;
        let page_len = rows.len();
        for row in rows {
            let epoch_id: Vec<u8> = row.try_get("epoch_id")?;
            let shard: i32 = row.try_get("shard")?;
            let committed_offset: i64 = row.try_get("committed_offset")?;
            cursor = Some((epoch_id, shard, committed_offset));
            let event_id = AcceptedEventId::from_digest(digest32(row.try_get("event_id")?)?);
            let canonical: Vec<u8> = row.try_get("canonical_event")?;
            let statement: EvidenceStatementV2 = decode_strict(&canonical)?;
            report.events_scanned += 1;
            let storage_identity = storage_identity_of(&statement)?;
            worklist
                .references
                .entry(storage_identity)
                .or_default()
                .total += 1;
            match classify_media_type(statement.canonical_content.media_type.as_str()) {
                EventKindV1::GitFact => {
                    report.git_facts_scanned += 1;
                    worklist.git_facts.push(event_id);
                }
                EventKindV1::TranscriptTurn => {
                    if transcript_turn_raw_at_rest(
                        pool,
                        runtime,
                        kek,
                        scope,
                        guarantee,
                        storage_identity,
                    )
                    .await?
                    {
                        report.transcript_turns_raw_at_rest += 1;
                    }
                }
                EventKindV1::Other => {}
            }
        }
        if page_len < WORKLIST_PAGE_ROWS {
            break;
        }
    }
    Ok(worklist)
}

async fn fetch_page(
    pool: &PgPool,
    scope: &Scope,
    cursor: Option<&(Vec<u8>, i32, i64)>,
) -> Result<Vec<PgRow>> {
    let rows = match cursor {
        None => {
            sqlx::query(SELECT_FIRST_PAGE_SQL)
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(EVIDENCE_ACCEPTED_EVENT_KIND)
                .fetch_all(pool)
                .await?
        }
        Some((epoch_id, shard, committed_offset)) => {
            sqlx::query(SELECT_NEXT_PAGE_SQL)
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(EVIDENCE_ACCEPTED_EVENT_KIND)
                .bind(epoch_id)
                .bind(*shard)
                .bind(*committed_offset)
                .fetch_all(pool)
                .await?
        }
    };
    Ok(rows)
}

/// Whether a transcript turn's stored text would change under the active
/// profile. A turn whose content object is gone, or whose content is not a
/// transcript turn body, is not counted: this pass judges only what it can
/// read.
async fn transcript_turn_raw_at_rest(
    pool: &PgPool,
    runtime: &WriterAuthorityRuntime,
    kek: &ContentKeyEncryptionKey,
    scope: &Scope,
    guarantee: &RedactionGuaranteeV1,
    storage_identity: Sha256Digest,
) -> Result<bool> {
    let Some(sealed) = fetch_governed_content(
        pool,
        scope.tenant_id,
        &scope.project,
        runtime.semantic_scope(),
        storage_identity,
    )
    .await?
    else {
        return Ok(false);
    };
    let bytes = sealed.open(kek)?;
    let Ok(body) = decode_strict::<TranscriptTurnBodyV1>(&bytes) else {
        return Ok(false);
    };
    Ok(transcript_text_is_raw_at_rest(
        &body.text,
        &guarantee.apply(&body.text),
    ))
}

async fn fetch_canonical_event(
    pool: &PgPool,
    scope: &Scope,
    event_id: AcceptedEventId,
) -> Result<Option<Vec<u8>>> {
    let row: Option<PgRow> = sqlx::query(SELECT_EVENT_BY_ID_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(bytes(event_id.digest()))
        .fetch_optional(pool)
        .await?;
    row.map(|row| Ok(row.try_get("canonical_event")?))
        .transpose()
}

async fn successor_exists(
    pool: &PgPool,
    scope: &Scope,
    representation_key: Sha256Digest,
) -> Result<bool> {
    Ok(sqlx::query_scalar(SELECT_SUCCESSOR_EXISTS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(bytes(representation_key))
        .bind(EVIDENCE_ACCEPTED_EVENT_KIND)
        .fetch_one(pool)
        .await?)
}

/// The storage identity an accepted statement's content is stored under,
/// derived exactly as the writer and the body projector derive it.
fn storage_identity_of(statement: &EvidenceStatementV2) -> Result<Sha256Digest> {
    Ok(StorageIdentityPreimageV1 {
        schema_version: STORAGE_IDENTITY_SCHEMA_VERSION,
        protection_domain_id: statement.canonical_content.protection_domain_id.clone(),
        body_content_id: statement.canonical_content.content_digest,
    }
    .storage_identity()?
    .digest())
}

async fn server_instant(pool: &PgPool) -> Result<CanonicalTimestamp> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(pool)
        .await?;
    Ok(CanonicalTimestamp::from_datetime(&now)?)
}

/// The projection the ledger runs inside the successor's append transaction:
/// the successor's governed content, then the erase of the raw
/// representation. Idempotent within one logical append, as the seam
/// requires: a retried attempt runs against a rolled-back transaction.
struct SupersessionProjection {
    content: GovernedContentProjection,
    scope: Scope,
    target: EraseTargetV1,
}

impl SupersessionProjection {
    async fn run(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: ProjectionContext,
    ) -> EvidenceAppendResult<BTreeMap<&'static str, u64>> {
        self.content.project(transaction, context).await?;
        erase_raw_representation(transaction, &self.scope, &self.target)
            .await
            .map_err(crate::evidence_ledger::EvidenceAppendError::Storage)
    }
}

/// Hands the erase counts of the attempt that committed back to the caller.
struct ProjectionHandle {
    inner: SupersessionProjection,
    removed: Arc<Mutex<BTreeMap<&'static str, u64>>>,
}

#[async_trait]
impl AppendProjection for ProjectionHandle {
    async fn project(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: ProjectionContext,
    ) -> EvidenceAppendResult<()> {
        let removed = self.inner.run(transaction, context).await?;
        if let Ok(mut latest) = self.removed.lock() {
            *latest = removed;
        }
        Ok(())
    }
}

/// Remove the raw representation's body plane and, when permitted, its
/// content object, inside `transaction`. Returns rows removed per table.
///
/// Every statement is scoped to `(tenant_id, project)` and keyed on the raw
/// accepted event, its source URI, or its storage identity; nothing here
/// names a row by a value read from the content. The order matters: spans
/// before their occurrences, occurrences before the per-body orphan checks,
/// the pointer (which needs the manifest rows to recognise itself) before
/// the manifests.
async fn erase_raw_representation(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &Scope,
    target: &EraseTargetV1,
) -> Result<BTreeMap<&'static str, u64>> {
    let mut removed: BTreeMap<&'static str, u64> = BTreeMap::new();
    let raw_event = bytes(target.raw_event_id.digest());

    let body_rows: Vec<PgRow> = sqlx::query(SELECT_RAW_BODIES_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&raw_event)
        .fetch_all(&mut **transaction)
        .await?;
    let bodies: Vec<Vec<u8>> = body_rows
        .iter()
        .map(|row| Ok(row.try_get("body_content_id")?))
        .collect::<Result<_>>()?;

    for (table, sql) in [
        ("memory_chunk_occurrence_spans_v1", DELETE_RAW_SPANS_SQL),
        ("memory_chunk_occurrences_v1", DELETE_RAW_OCCURRENCES_SQL),
    ] {
        let affected = sqlx::query(sql)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(&raw_event)
            .execute(&mut **transaction)
            .await?
            .rows_affected();
        *removed.entry(table).or_default() += affected;
    }

    for body in &bodies {
        for (table, sql) in [
            ("memory_body_dense_projection_v1", DELETE_ORPHAN_DENSE_SQL),
            (
                "memory_body_lexical_projection_v1",
                DELETE_ORPHAN_LEXICAL_SQL,
            ),
            ("memory_body_visibility_v1", DELETE_ORPHAN_VISIBILITY_SQL),
            (BODY_TABLE, DELETE_ORPHAN_BODY_SQL),
        ] {
            let affected = sqlx::query(sql)
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(body)
                .execute(&mut **transaction)
                .await?
                .rows_affected();
            *removed.entry(table).or_default() += affected;
        }
    }

    let affected = sqlx::query(DELETE_RAW_POINTER_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&raw_event)
        .bind(&target.source_representation_uri)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
    *removed.entry("memory_generation_pointers_v1").or_default() += affected;
    let affected = sqlx::query(DELETE_RAW_MANIFESTS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&raw_event)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
    *removed.entry("memory_parse_run_manifests_v1").or_default() += affected;

    if target.delete_content {
        let affected = delete_content_object(transaction, scope, target.storage_identity).await?;
        *removed.entry("memory_content_objects").or_default() += affected;
    }
    Ok(removed)
}

async fn delete_content_object(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &Scope,
    storage_identity: Sha256Digest,
) -> Result<u64> {
    Ok(sqlx::query(DELETE_CONTENT_OBJECT_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(bytes(storage_identity))
        .execute(&mut **transaction)
        .await?
        .rows_affected())
}

/// The idempotent erase for a fact whose successor already exists: its own
/// serializable transaction, retried on 40001 like every append.
async fn erase_in_own_transaction(
    pool: &PgPool,
    runtime: &WriterAuthorityRuntime,
    scope: &Scope,
    target: &EraseTargetV1,
) -> Result<BTreeMap<&'static str, u64>> {
    let scope = scope.clone();
    let target = target.clone();
    with_serializable_retry(pool, runtime.retry_policy(), move |transaction| {
        let scope = scope.clone();
        let target = target.clone();
        let future: BoxFuture<'_, Result<BTreeMap<&'static str, u64>>> =
            Box::pin(async move { erase_raw_representation(transaction, &scope, &target).await });
        future
    })
    .await
}

async fn delete_content_in_own_transaction(
    pool: &PgPool,
    runtime: &WriterAuthorityRuntime,
    scope: &Scope,
    storage_identity: Sha256Digest,
) -> Result<BTreeMap<&'static str, u64>> {
    let scope = scope.clone();
    with_serializable_retry(pool, runtime.retry_policy(), move |transaction| {
        let scope = scope.clone();
        let future: BoxFuture<'_, Result<BTreeMap<&'static str, u64>>> = Box::pin(async move {
            let affected = delete_content_object(transaction, &scope, storage_identity).await?;
            Ok(BTreeMap::from([("memory_content_objects", affected)]))
        });
        future
    })
    .await
}

fn describe(what: &str, error: &dyn std::fmt::Display) -> FleetError {
    FleetError::Memory(format!("{what}: {error}"))
}

fn bytes(digest: Sha256Digest) -> Vec<u8> {
    digest.as_bytes().to_vec()
}

fn digest32(value: Vec<u8>) -> Result<Sha256Digest> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| FleetError::Memory("stored digest column is not 32 bytes".into()))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The predicate every per-body delete must carry verbatim.
    const ORPHAN_BODY_PREDICATE: &str = "AND NOT EXISTS (\
       SELECT 1 FROM public.memory_chunk_occurrences_v1 AS occurrence \
       WHERE occurrence.tenant_id = $1 AND occurrence.project = $2 \
         AND occurrence.body_content_id = $3)";

    /// Every statement the pass can execute, by name.
    const ALL_SQL: [(&str, &str); 16] = [
        ("SELECT_FIRST_PAGE_SQL", SELECT_FIRST_PAGE_SQL),
        ("SELECT_NEXT_PAGE_SQL", SELECT_NEXT_PAGE_SQL),
        ("SELECT_EVENT_BY_ID_SQL", SELECT_EVENT_BY_ID_SQL),
        ("SELECT_SUCCESSOR_EXISTS_SQL", SELECT_SUCCESSOR_EXISTS_SQL),
        ("SELECT_RAW_BODIES_SQL", SELECT_RAW_BODIES_SQL),
        ("DELETE_RAW_SPANS_SQL", DELETE_RAW_SPANS_SQL),
        ("DELETE_RAW_OCCURRENCES_SQL", DELETE_RAW_OCCURRENCES_SQL),
        ("DELETE_ORPHAN_DENSE_SQL", DELETE_ORPHAN_DENSE_SQL),
        ("DELETE_ORPHAN_LEXICAL_SQL", DELETE_ORPHAN_LEXICAL_SQL),
        ("DELETE_ORPHAN_VISIBILITY_SQL", DELETE_ORPHAN_VISIBILITY_SQL),
        ("DELETE_ORPHAN_BODY_SQL", DELETE_ORPHAN_BODY_SQL),
        ("DELETE_RAW_POINTER_SQL", DELETE_RAW_POINTER_SQL),
        ("DELETE_RAW_MANIFESTS_SQL", DELETE_RAW_MANIFESTS_SQL),
        ("DELETE_CONTENT_OBJECT_SQL", DELETE_CONTENT_OBJECT_SQL),
        ("ORPHAN_BODY_PREDICATE", ORPHAN_BODY_PREDICATE),
        ("BODY_TABLE", BODY_TABLE),
    ];

    /// The accepted envelope is a tombstone, never a target: no statement
    /// deletes or updates `memory_evidence_events`, and none touches a
    /// governance relation.
    #[test]
    fn the_erase_never_touches_the_ledger_or_a_governance_relation() {
        for (name, statement) in ALL_SQL {
            for forbidden in ["memory_control_", "memory_registry_"] {
                assert!(!statement.contains(forbidden), "{name}: {statement}");
            }
            if statement.starts_with("DELETE") {
                assert!(
                    !statement.contains("memory_evidence_events"),
                    "{name} deletes from the ledger"
                );
                assert!(
                    statement.contains("tenant_id = $1 AND project = $2"),
                    "{name}"
                );
            }
            assert!(!statement.contains("UPDATE "), "{name} updates a row");
            assert!(!statement.contains("DROP"), "{name}");
        }
        assert!(
            !DELETE_RAW_SPANS_SQL.contains("memory_source_commit_membership_v1"),
            "commit membership is deferred, not erased"
        );
    }

    /// Every per-body delete carries the orphan predicate verbatim, so a
    /// body another occurrence still references survives.
    #[test]
    fn every_body_delete_requires_the_body_to_be_orphaned() {
        for sql in [
            DELETE_ORPHAN_DENSE_SQL,
            DELETE_ORPHAN_LEXICAL_SQL,
            DELETE_ORPHAN_VISIBILITY_SQL,
            DELETE_ORPHAN_BODY_SQL,
        ] {
            assert!(
                sql.contains(ORPHAN_BODY_PREDICATE.trim_start_matches("AND ")),
                "{sql}"
            );
        }
        assert!(DELETE_RAW_POINTER_SQL.contains("active_manifest_id IN ("));
        assert!(DELETE_RAW_POINTER_SQL.contains("accepted_event_id = $3"));
        assert!(
            SELECT_NEXT_PAGE_SQL.contains("(epoch_id, shard, committed_offset) > ($4, $5, $6)")
        );
        assert!(SELECT_FIRST_PAGE_SQL.ends_with("LIMIT 256"));
        assert!(SELECT_SUCCESSOR_EXISTS_SQL.contains("predecessor_representation_key_digest = $3"));
    }
}
