//! Reusable projection for the bootstrap-manifest import side table
//! (W1-IMPORT).
//!
//! `memory_bootstrap_import_rows` is a PROPOSED table — see the `requests`
//! this workstream's handoff names for the exact DDL. The SCHEMA lane (0019+)
//! has not migrated it in yet. Every caller of [`BootstrapImportProjection`] —
//! the private import CLI (`ostk-bootstrap-manifest-import`) and its own
//! connected tests (`tests/bootstrap_manifest_live.rs`) — shares this ONE
//! implementation, so the row-collision rule enforced here cannot diverge
//! between the two.
//!
//! # The collision rule
//!
//! A row already recorded with the *same* digest is a no-op: re-projecting
//! the identical manifest content is idempotent, exactly like the append
//! seam's own exact-replay rule. A row already recorded with a *different*
//! digest — a second manifest naming an already-imported row with different
//! bytes — fails the whole append transaction closed: [`project`] returns
//! [`EvidenceAppendError::LedgerIntegrity`], so no event insert survives and
//! no head advance happens, because [`AcceptedEventKindV1::BootstrapManifest`]
//! carries no connector-delivery context to shape a
//! [`crate::memory_contracts::quarantine::QuarantineRecordV1`] (see
//! `AcceptedEventKindV1::semantic_identity_rule`'s documentation for the
//! parallel case in `RelationAttestation`/`MemoryClaim`). That value crosses
//! the generic [`AppendProjection`] trait boundary — `append_in_transaction`
//! converts any projection error through `EvidenceAppendError ->
//! FleetError -> EvidenceAppendError::Storage` — so a caller of
//! [`super::AcceptedEventRepository::append`] observes
//! `Err(EvidenceAppendError::Storage(FleetError::Memory(message)))` with this
//! message text, not the `LedgerIntegrity` variant directly; only
//! `FleetError::ControlLogCorrupt`, raised inside the append machinery
//! itself, survives that round trip unchanged.
//!
//! [`project`]: AppendProjection::project
//!
//! [`AcceptedEventKindV1::BootstrapManifest`]: super::AcceptedEventKindV1

use async_trait::async_trait;
use sqlx::{PgPool, Postgres, Row as _, Transaction};

use crate::control_log::TrustedControlScope;
use crate::memory_contracts::bootstrap_manifest::BootstrapManifestRowV1;
use crate::memory_contracts::canonical::encode_canonical;

use super::error::{EvidenceAppendError, EvidenceAppendResult};
use super::repository::{AppendProjection, ProjectionContext};

/// Exact table name this projection reads and writes.
pub const IMPORT_ROWS_TABLE: &str = "public.memory_bootstrap_import_rows";

/// Whether `memory_bootstrap_import_rows` currently exists.
///
/// Connected tests and the private import CLI use this to skip or fail with a
/// clear message rather than an opaque "relation does not exist" error when
/// the SCHEMA lane's migration has not landed yet.
pub async fn import_rows_table_exists(pool: &PgPool) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name = 'memory_bootstrap_import_rows')",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(false)
}

/// Records one row per imported legacy identity.
#[derive(Debug, Clone)]
pub struct BootstrapImportProjection {
    pub scope: TrustedControlScope,
    pub rows: Vec<BootstrapManifestRowV1>,
}

#[async_trait]
impl AppendProjection for BootstrapImportProjection {
    async fn project(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: ProjectionContext,
    ) -> EvidenceAppendResult<()> {
        let accepted_event_id_bytes = context.accepted_event_id.digest().as_bytes().to_vec();
        for row in &self.rows {
            let row_key = row_key_text(row)?;
            let existing_row = sqlx::query(&format!(
                "SELECT row_digest FROM {IMPORT_ROWS_TABLE} \
                 WHERE tenant_id = $1 AND project = $2 AND table_name = $3 AND row_key = $4"
            ))
            .bind(self.scope.tenant_id())
            .bind(self.scope.project())
            .bind(row.table.as_str())
            .bind(&row_key)
            .fetch_optional(&mut **transaction)
            .await?;
            match existing_row {
                Some(existing) => {
                    let existing_digest: Vec<u8> = existing.try_get("row_digest")?;
                    if existing_digest != row.row_digest.as_bytes().as_slice() {
                        return Err(EvidenceAppendError::LedgerIntegrity(format!(
                            "bootstrap import row collision: {} row {row_key} was already \
                             imported with different bytes",
                            row.table.as_str()
                        )));
                    }
                    // Same digest: this row was already imported by an
                    // earlier accepted manifest. Idempotent no-op.
                }
                None => {
                    sqlx::query(&format!(
                        "INSERT INTO {IMPORT_ROWS_TABLE} \
                         (tenant_id, project, table_name, row_key, row_digest, accepted_event_id) \
                         VALUES ($1, $2, $3, $4, $5, $6)"
                    ))
                    .bind(self.scope.tenant_id())
                    .bind(self.scope.project())
                    .bind(row.table.as_str())
                    .bind(&row_key)
                    .bind(row.row_digest.as_bytes().as_slice())
                    .bind(accepted_event_id_bytes.as_slice())
                    .execute(&mut **transaction)
                    .await?;
                }
            }
        }
        Ok(())
    }
}

fn row_key_text(row: &BootstrapManifestRowV1) -> EvidenceAppendResult<String> {
    let bytes = encode_canonical(&row.primary_key)?;
    String::from_utf8(bytes)
        .map_err(|error| EvidenceAppendError::LedgerIntegrity(error.to_string()))
}
