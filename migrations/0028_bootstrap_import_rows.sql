-- no-transaction
-- Bootstrap-manifest import side table (W1-IMPORT). One additive private-plane
-- table recording which legacy row each accepted `bootstrap.manifest.accepted`
-- event imported, so a second manifest naming the same legacy row with
-- different bytes fails closed and an identical re-import is a no-op. The
-- projection that writes it is `evidence_ledger::BootstrapImportProjection`,
-- and it runs inside the same serializable transaction as the event append.
--
-- Like migrations 0018 onward, this DDL runs outside SQLx's transaction
-- wrapper, so every object is created with IF NOT EXISTS and a process death
-- between the schema change and SQLx's history row is resumable. The table is
-- not one of the publication reader's tables and carries no foreign key to
-- any memory_control_* / memory_registry_* table.

-- Ownership: fleet_migrator. row_key is the canonical-JSON encoding of the
-- legacy row's primary key; row_digest is the manifest's per-row digest;
-- accepted_event_id is the bootstrap-manifest event that imported the row.
CREATE TABLE IF NOT EXISTS memory_bootstrap_import_rows (
    tenant_id          UUID NOT NULL,
    project            STRING NOT NULL,
    table_name         STRING NOT NULL,
    row_key            STRING NOT NULL,
    row_digest         BYTES NOT NULL,
    accepted_event_id  BYTES NOT NULL,
    PRIMARY KEY (tenant_id, project, table_name, row_key),
    CONSTRAINT memory_bootstrap_import_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_bootstrap_import_table_name
        CHECK (table_name IN (
            'memory_chunks',
            'memory_claims',
            'memory_conflicts',
            'memory_conflict_members',
            'memory_mutation_receipts'
        )),
    CONSTRAINT memory_bootstrap_import_row_key_bound
        CHECK (octet_length(row_key) BETWEEN 1 AND 4096),
    CONSTRAINT memory_bootstrap_import_row_digest_shape
        CHECK (octet_length(row_digest) = 32),
    CONSTRAINT memory_bootstrap_import_event_shape
        CHECK (octet_length(accepted_event_id) = 32)
);

-- Every row one accepted manifest imported, for audit and replay.
CREATE INDEX IF NOT EXISTS memory_bootstrap_import_rows_event_idx
    ON memory_bootstrap_import_rows (tenant_id, project, accepted_event_id);
