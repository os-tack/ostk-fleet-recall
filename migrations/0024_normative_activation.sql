-- no-transaction
-- Normative activation runtime (W3-NORM, Stage 6). Three additive private-plane
-- tables: the per-binding-family composite compare-and-set head, the
-- append-only normative log (lifecycle events and contest records), and the
-- active-normative projection advanced atomically with its cursor. Nothing here
-- rewrites an existing row, drops an object, or narrows an existing constraint;
-- migrations 0001 through 0023 remain byte-identical.
--
-- This migration owns version 24. The co-launched W3-OBSRT owns the next free
-- number; if both land on the same version the merge gate catches it and one
-- file is renumbered (no object name changes).
--
-- CockroachDB 26.2 cannot run this DDL inside SQLx's PostgreSQL-oriented
-- transaction wrapper, so this migration is registered no_tx and every object is
-- created with IF NOT EXISTS: a process death between a committed schema change
-- and SQLx's history row is resumable. Every name is part of the schema
-- contract.
--
-- None of these tables is one of the publication reader's eight tables; all
-- three are private-plane projections (PUBLIC-03/04). Like migrations 0018 and
-- 0020, they carry NO foreign key to any memory_control_* / memory_registry_*
-- table, so no control-plane grant is needed to write them.

-- Ownership: fleet_migrator. The compare-and-set head for one binding family.
-- The CAS tuple is exactly the doc's composite: (active binding-set digest,
-- active registry package digest, active activation-policy digest). A NULL
-- active_binding_set_digest means "no statement is live for this family", which
-- is the head an inaugural activation must expect. head_revision is a strictly
-- monotone counter over accepted transitions; log_seq mirrors the family's
-- newest normative-log sequence so the projection cursor and the head advance
-- together or not at all.
CREATE TABLE IF NOT EXISTS memory_normative_heads_v1 (
    tenant_id                  UUID NOT NULL,
    project                    STRING NOT NULL,
    binding_family_id          STRING NOT NULL,
    active_binding_set_digest  BYTES NULL,
    registry_package_digest    BYTES NOT NULL,
    activation_policy_digest   BYTES NOT NULL,
    head_revision              INT8 NOT NULL,
    log_seq                    INT8 NOT NULL,
    updated_at                 TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, binding_family_id),
    CONSTRAINT memory_normative_head_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_normative_head_family_bound
        CHECK (octet_length(binding_family_id) BETWEEN 1 AND 256),
    CONSTRAINT memory_normative_head_binding_set_shape
        CHECK (active_binding_set_digest IS NULL
               OR octet_length(active_binding_set_digest) = 32),
    CONSTRAINT memory_normative_head_package_shape
        CHECK (octet_length(registry_package_digest) = 32),
    CONSTRAINT memory_normative_head_policy_shape
        CHECK (octet_length(activation_policy_digest) = 32),
    CONSTRAINT memory_normative_head_revision_bound
        CHECK (head_revision >= 0),
    CONSTRAINT memory_normative_head_log_seq_bound
        CHECK (log_seq >= 0)
);

-- Ownership: fleet_migrator. The append-only normative log for one binding
-- family: lifecycle events (activation, retirement, retraction, expiry,
-- supersession) and contest records, in one stream so the active-normative
-- projection rebuilds from a single ordered source. canonical_record is the
-- exact canonical-JSON preimage the projection folds, so every row is
-- self-checking and a rebuild is byte-reproducible. Nothing ever updates or
-- deletes a row here: a retirement or supersession APPENDS, it never erases the
-- prior activation. record_id is the contract's own event_id / contested_id.
CREATE TABLE IF NOT EXISTS memory_normative_log_v1 (
    tenant_id                  UUID NOT NULL,
    project                    STRING NOT NULL,
    binding_family_id          STRING NOT NULL,
    seq                        INT8 NOT NULL,
    record_kind                STRING NOT NULL,
    record_id                  BYTES NOT NULL,
    statement_id               BYTES NULL,
    supersedes_statement_id    BYTES NULL,
    canonical_record           BYTES NOT NULL,
    created_at                 TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, binding_family_id, seq),
    CONSTRAINT memory_normative_log_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_normative_log_family_bound
        CHECK (octet_length(binding_family_id) BETWEEN 1 AND 256),
    CONSTRAINT memory_normative_log_seq_bound
        CHECK (seq >= 1),
    CONSTRAINT memory_normative_log_kind
        CHECK (record_kind IN ('lifecycle', 'contest')),
    CONSTRAINT memory_normative_log_record_id_shape
        CHECK (octet_length(record_id) = 32),
    CONSTRAINT memory_normative_log_statement_shape
        CHECK (statement_id IS NULL OR octet_length(statement_id) = 32),
    CONSTRAINT memory_normative_log_supersedes_shape
        CHECK (supersedes_statement_id IS NULL
               OR octet_length(supersedes_statement_id) = 32),
    CONSTRAINT memory_normative_log_canonical_bound
        CHECK (octet_length(canonical_record) BETWEEN 1 AND 1048576)
);

-- One record identity may appear at most once per scope: a replayed lifecycle
-- event or contest record cannot be double-applied under a new sequence.
CREATE UNIQUE INDEX IF NOT EXISTS memory_normative_log_record_id_idx
    ON memory_normative_log_v1 (tenant_id, project, record_id);

-- Ownership: fleet_migrator. The active-normative projection for one binding
-- family, advanced in the SAME transaction as the log append that produced it.
-- cursor_seq is the newest normative-log sequence folded into
-- canonical_projection, so a projection row can never be ahead of, or behind,
-- its log. resolution is the derived verdict, denormalised for reads: 'active'
-- names exactly one live statement, 'scheduled' names several with
-- pairwise-disjoint effective intervals, 'unknown' is the fail-closed contested
-- verdict (never a winner picked by recency or insertion order), and 'retired'
-- means nothing is live.
CREATE TABLE IF NOT EXISTS memory_normative_projections_v1 (
    tenant_id                  UUID NOT NULL,
    project                    STRING NOT NULL,
    binding_family_id          STRING NOT NULL,
    cursor_seq                 INT8 NOT NULL,
    resolution                 STRING NOT NULL,
    active_statement_id        BYTES NULL,
    canonical_projection       BYTES NOT NULL,
    updated_at                 TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, binding_family_id),
    CONSTRAINT memory_normative_projection_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_normative_projection_family_bound
        CHECK (octet_length(binding_family_id) BETWEEN 1 AND 256),
    CONSTRAINT memory_normative_projection_cursor_bound
        CHECK (cursor_seq >= 1),
    CONSTRAINT memory_normative_projection_resolution
        CHECK (resolution IN ('active', 'scheduled', 'unknown', 'retired')),
    CONSTRAINT memory_normative_projection_active_shape
        CHECK (active_statement_id IS NULL OR octet_length(active_statement_id) = 32),
    CONSTRAINT memory_normative_projection_active_presence
        CHECK ((resolution = 'active') = (active_statement_id IS NOT NULL)),
    CONSTRAINT memory_normative_projection_canonical_bound
        CHECK (octet_length(canonical_projection) BETWEEN 1 AND 1048576)
);

-- SQLx sends a multi-statement migration as one implicit transaction, and this
-- migration is registered no_tx, so there is no enclosing application
-- transaction. Commit the schema changes before inspecting the public catalog.
COMMIT;

-- Fail closed on same-name relation drift, exactly as migrations 0018 and 0020
-- do: IF NOT EXISTS would otherwise ADOPT an unrelated object that merely shares
-- the name. Pin the exact committed column shape of all three tables. Stop on
-- 55000 if a named object is not the object this migration defines.
DO $$
DECLARE
    drifted STRING;
BEGIN
    SELECT string_agg(expected.relation_name, ', ' ORDER BY expected.relation_name)
    INTO drifted
    FROM (VALUES
        ('memory_normative_heads_v1',
            'tenant_id:uuid:NO,project:text:NO,binding_family_id:text:NO,active_binding_set_digest:bytea:YES,registry_package_digest:bytea:NO,activation_policy_digest:bytea:NO,head_revision:bigint:NO,log_seq:bigint:NO,updated_at:timestamp with time zone:NO'),
        ('memory_normative_log_v1',
            'tenant_id:uuid:NO,project:text:NO,binding_family_id:text:NO,seq:bigint:NO,record_kind:text:NO,record_id:bytea:NO,statement_id:bytea:YES,supersedes_statement_id:bytea:YES,canonical_record:bytea:NO,created_at:timestamp with time zone:NO'),
        ('memory_normative_projections_v1',
            'tenant_id:uuid:NO,project:text:NO,binding_family_id:text:NO,cursor_seq:bigint:NO,resolution:text:NO,active_statement_id:bytea:YES,canonical_projection:bytea:NO,updated_at:timestamp with time zone:NO')
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
            MESSAGE = 'migration 0024 same-name relation drift: ' || drifted;
    END IF;
END
$$;
