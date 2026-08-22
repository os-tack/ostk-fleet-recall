-- no-transaction
-- Coverage runtime foundations (W2-COVER-RT, COVER-01..03). Two additive
-- private-plane projection tables: a per-connector-instance coverage cursor and
-- the coverage receipts minted as that cursor advances. Nothing here rewrites an
-- existing row, drops an object, or narrows an existing constraint; migrations
-- 0001 through 0018 remain byte-identical. This migration owns version 20 (the
-- co-launched W2-BODY owns the additive 0019); a version gap is expected on this
-- branch and closed at integration.
--
-- CockroachDB 26.2 cannot run this DDL inside SQLx's PostgreSQL-oriented
-- transaction wrapper, so this migration is registered no_tx and every object is
-- created with IF NOT EXISTS: a process death between a committed schema change
-- and SQLx's history row is resumable. Every name is part of the schema
-- contract.
--
-- Neither table is one of the publication reader's eight tables; both are
-- private-plane projections (PUBLIC-03/04). Like migration 0018's projection
-- tables, they carry NO foreign key to any memory_control_* / memory_registry_*
-- table, so fleet_runtime needs no control-plane grant to write them.

-- Ownership: fleet_migrator. The durable coverage cursor for one connector
-- instance over one coverage domain. coverage_key_digest binds the connector
-- instance, the scope URI, the immutable revision, the covered window, and the
-- target sequence range (derived in src/coverage_runtime/cockroach.rs), so a
-- different domain is a different cursor row and can never regress another's
-- observed range. observed_ranges is the canonical JSON of the merged
-- ObservedRangeV1; target_start/target_end are the u64 target bounds stored
-- big-endian so the full unsigned range survives a signed INT8 column.
CREATE TABLE IF NOT EXISTS memory_coverage_cursors_v1 (
    tenant_id                 UUID NOT NULL,
    project                   STRING NOT NULL,
    coverage_key_digest       BYTES NOT NULL,
    connector_instance_id     STRING NOT NULL,
    observed_ranges           BYTES NOT NULL,
    target_start              BYTES NOT NULL,
    target_end                BYTES NOT NULL,
    observation_seq           INT8 NOT NULL,
    last_completeness         STRING NOT NULL,
    last_receipt_id           BYTES NULL,
    updated_at                TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, coverage_key_digest),
    CONSTRAINT memory_coverage_cursor_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_coverage_cursor_key_shape
        CHECK (octet_length(coverage_key_digest) = 32),
    CONSTRAINT memory_coverage_cursor_instance_bound
        CHECK (octet_length(connector_instance_id) BETWEEN 1 AND 128),
    CONSTRAINT memory_coverage_cursor_observed_bound
        CHECK (octet_length(observed_ranges) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_coverage_cursor_target_start_shape
        CHECK (octet_length(target_start) = 8),
    CONSTRAINT memory_coverage_cursor_target_end_shape
        CHECK (octet_length(target_end) = 8),
    CONSTRAINT memory_coverage_cursor_seq_bound
        CHECK (observation_seq >= 0),
    CONSTRAINT memory_coverage_cursor_completeness
        CHECK (last_completeness IN ('complete', 'partial', 'unknown')),
    CONSTRAINT memory_coverage_cursor_last_receipt_shape
        CHECK (last_receipt_id IS NULL OR octet_length(last_receipt_id) = 32)
);

-- Ownership: fleet_migrator. One coverage receipt row per cursor advance,
-- keyed by the coverage contract's receipt_id (the domain-separated digest of
-- the full canonical receipt). canonical_receipt is that exact preimage, so the
-- row is rebuildable and self-checking. INSERT ON CONFLICT DO NOTHING on the
-- primary key makes a replayed advance idempotent (no duplicate receipt).
CREATE TABLE IF NOT EXISTS memory_coverage_receipts_v1 (
    tenant_id                 UUID NOT NULL,
    project                   STRING NOT NULL,
    receipt_id                BYTES NOT NULL,
    connector_instance_id     STRING NOT NULL,
    coverage_key_digest       BYTES NOT NULL,
    completeness              STRING NOT NULL,
    evidence_id               BYTES NOT NULL,
    source_digest             BYTES NOT NULL,
    source_count              INT8 NOT NULL,
    observation_seq           INT8 NOT NULL,
    canonical_receipt         BYTES NOT NULL,
    created_at                TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, receipt_id),
    CONSTRAINT memory_coverage_receipt_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_coverage_receipt_id_shape
        CHECK (octet_length(receipt_id) = 32),
    CONSTRAINT memory_coverage_receipt_instance_bound
        CHECK (octet_length(connector_instance_id) BETWEEN 1 AND 128),
    CONSTRAINT memory_coverage_receipt_key_shape
        CHECK (octet_length(coverage_key_digest) = 32),
    CONSTRAINT memory_coverage_receipt_completeness
        CHECK (completeness IN ('complete', 'partial', 'unknown')),
    CONSTRAINT memory_coverage_receipt_evidence_shape
        CHECK (octet_length(evidence_id) = 32),
    CONSTRAINT memory_coverage_receipt_source_digest_shape
        CHECK (octet_length(source_digest) = 32),
    CONSTRAINT memory_coverage_receipt_source_count_bound
        CHECK (source_count >= 0),
    CONSTRAINT memory_coverage_receipt_seq_bound
        CHECK (observation_seq >= 1),
    CONSTRAINT memory_coverage_receipt_canonical_bound
        CHECK (octet_length(canonical_receipt) BETWEEN 1 AND 1048576)
);

CREATE INDEX IF NOT EXISTS memory_coverage_receipts_instance_idx
    ON memory_coverage_receipts_v1 (
        tenant_id,
        project,
        connector_instance_id,
        observation_seq
    );

-- SQLx sends a multi-statement migration as one implicit transaction, and this
-- migration is registered no_tx, so there is no enclosing application
-- transaction. Commit the schema changes before inspecting the public catalog.
COMMIT;

-- Fail closed on same-name relation drift, exactly as migration 0018 does:
-- IF NOT EXISTS would otherwise ADOPT an unrelated object that merely shares the
-- name. Pin the exact committed column shape of both coverage tables. Stop on
-- 55000 if the named object is not the object this migration defines.
DO $$
DECLARE
    drifted STRING;
BEGIN
    SELECT string_agg(expected.relation_name, ', ' ORDER BY expected.relation_name)
    INTO drifted
    FROM (VALUES
        ('memory_coverage_cursors_v1',
            'tenant_id:uuid:NO,project:text:NO,coverage_key_digest:bytea:NO,connector_instance_id:text:NO,observed_ranges:bytea:NO,target_start:bytea:NO,target_end:bytea:NO,observation_seq:bigint:NO,last_completeness:text:NO,last_receipt_id:bytea:YES,updated_at:timestamp with time zone:NO'),
        ('memory_coverage_receipts_v1',
            'tenant_id:uuid:NO,project:text:NO,receipt_id:bytea:NO,connector_instance_id:text:NO,coverage_key_digest:bytea:NO,completeness:text:NO,evidence_id:bytea:NO,source_digest:bytea:NO,source_count:bigint:NO,observation_seq:bigint:NO,canonical_receipt:bytea:NO,created_at:timestamp with time zone:NO')
    ) AS expected (relation_name, column_shape)
    WHERE expected.column_shape IS DISTINCT FROM (
        SELECT string_agg(
            column_object.column_name || ':' || column_object.data_type
                || ':' || column_object.is_nullable,
            ','
            ORDER BY column_object.ordinal_position
        )
        FROM information_schema.columns AS column_object
        WHERE column_object.table_schema = 'public'
          AND column_object.table_name = expected.relation_name
    );

    IF drifted IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'migration 0020 same-name relation drift: ' || drifted;
    END IF;
END
$$;
