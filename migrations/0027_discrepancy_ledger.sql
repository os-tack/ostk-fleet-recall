-- no-transaction
-- Discrepancy ledger runtime (W3-DISC, Stage 6). Four additive private-plane
-- tables: the per-episode head, the append-only episode log (one immutable
-- detection envelope at sequence 1 plus lifecycle transitions), the
-- family-keyed episode relation store, and the deterministic episode
-- projection advanced atomically with its log. Nothing here rewrites an
-- existing row, drops an object, or narrows an existing constraint;
-- migrations 0001 through 0026 remain byte-identical. Version 25 is a
-- permanent, deliberate gap (reserved for an item that added no migration);
-- nothing is renumbered to close it.
--
-- This migration owns version 27, assigned centrally by the wave plan.
--
-- CockroachDB 26.2 cannot run this DDL inside SQLx's PostgreSQL-oriented
-- transaction wrapper, so this migration is registered no_tx and every object
-- is created with IF NOT EXISTS: a process death between a committed schema
-- change and SQLx's history row is resumable. Every name is part of the
-- schema contract.
--
-- None of these tables is one of the publication reader's tables; all four
-- are private-plane projections (PUBLIC-03/04). Like migrations 0018, 0020,
-- and 0024, they carry NO foreign key to any memory_control_* /
-- memory_registry_* table, so no control-plane grant is needed to write them.

-- Ownership: fleet_migrator. One row per admitted discrepancy episode: the
-- episode fingerprint, its family fingerprint, the envelope identity that
-- seeded it (per-detection identity is immutable — a DIFFERENT envelope may
-- never re-seed an episode), and the newest episode-log sequence so the log
-- append and the projection refresh advance together or not at all.
CREATE TABLE IF NOT EXISTS memory_discrepancy_heads_v1 (
    tenant_id            UUID NOT NULL,
    project              STRING NOT NULL,
    episode_fingerprint  BYTES NOT NULL,
    family_fingerprint   BYTES NOT NULL,
    envelope_id          BYTES NOT NULL,
    log_seq              INT8 NOT NULL,
    updated_at           TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, episode_fingerprint),
    CONSTRAINT memory_discrepancy_head_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_discrepancy_head_episode_shape
        CHECK (octet_length(episode_fingerprint) = 32),
    CONSTRAINT memory_discrepancy_head_family_shape
        CHECK (octet_length(family_fingerprint) = 32),
    CONSTRAINT memory_discrepancy_head_envelope_shape
        CHECK (octet_length(envelope_id) = 32),
    CONSTRAINT memory_discrepancy_head_log_seq_bound
        CHECK (log_seq >= 1)
);

-- Ownership: fleet_migrator. The append-only ledger log for one episode:
-- sequence 1 is always the immutable detection envelope, every later
-- sequence a lifecycle transition. canonical_record is the exact
-- canonical-JSON preimage the projection folds, so every row is
-- self-checking and a rebuild is byte-reproducible. Nothing ever updates or
-- deletes a row here: an acknowledge, waiver, resolution, or dismissal
-- APPENDS, it never erases the detection or an earlier transition.
-- record_id is the contract's own envelope_id / lifecycle_event_id.
CREATE TABLE IF NOT EXISTS memory_discrepancy_log_v1 (
    tenant_id            UUID NOT NULL,
    project              STRING NOT NULL,
    episode_fingerprint  BYTES NOT NULL,
    seq                  INT8 NOT NULL,
    record_kind          STRING NOT NULL,
    record_id            BYTES NOT NULL,
    canonical_record     BYTES NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, episode_fingerprint, seq),
    CONSTRAINT memory_discrepancy_log_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_discrepancy_log_episode_shape
        CHECK (octet_length(episode_fingerprint) = 32),
    CONSTRAINT memory_discrepancy_log_seq_bound
        CHECK (seq >= 1),
    CONSTRAINT memory_discrepancy_log_kind
        CHECK (record_kind IN ('envelope', 'lifecycle')),
    CONSTRAINT memory_discrepancy_log_envelope_seed
        CHECK ((record_kind = 'envelope') = (seq = 1)),
    CONSTRAINT memory_discrepancy_log_record_id_shape
        CHECK (octet_length(record_id) = 32),
    CONSTRAINT memory_discrepancy_log_canonical_bound
        CHECK (octet_length(canonical_record) BETWEEN 1 AND 1048576)
);

-- One record identity may appear at most once per scope: a replayed envelope
-- or lifecycle event cannot be double-applied under a new sequence.
CREATE UNIQUE INDEX IF NOT EXISTS memory_discrepancy_log_record_id_idx
    ON memory_discrepancy_log_v1 (tenant_id, project, record_id);

-- Ownership: fleet_migrator. The append-only episode relation store for one
-- discrepancy family (superseded / combined_from / continues /
-- possibly_continues). One relation names several episodes, so relations are
-- keyed by family rather than folded into a single episode's log;
-- relation_id is the domain-separated digest of the canonical relation, so a
-- replayed relation append is idempotent rather than double-applied.
CREATE TABLE IF NOT EXISTS memory_discrepancy_relations_v1 (
    tenant_id            UUID NOT NULL,
    project              STRING NOT NULL,
    family_fingerprint   BYTES NOT NULL,
    relation_id          BYTES NOT NULL,
    canonical_relation   BYTES NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, family_fingerprint, relation_id),
    CONSTRAINT memory_discrepancy_relation_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_discrepancy_relation_family_shape
        CHECK (octet_length(family_fingerprint) = 32),
    CONSTRAINT memory_discrepancy_relation_id_shape
        CHECK (octet_length(relation_id) = 32),
    CONSTRAINT memory_discrepancy_relation_canonical_bound
        CHECK (octet_length(canonical_relation) BETWEEN 1 AND 1048576)
);

-- Ownership: fleet_migrator. The deterministic episode projection, refreshed
-- in the SAME transaction as the append that changed it. cursor_seq is the
-- newest episode-log sequence folded into canonical_projection (a relation
-- refresh recomputes the bytes at the same cursor). evaluated_at is the
-- deterministic evaluation instant derived from the log itself — never a
-- wall clock — so a rebuild from the log and relation store reproduces
-- canonical_projection byte for byte. lifecycle_state and verification_state
-- are the derived states, denormalised for reads.
CREATE TABLE IF NOT EXISTS memory_discrepancy_projections_v1 (
    tenant_id            UUID NOT NULL,
    project              STRING NOT NULL,
    episode_fingerprint  BYTES NOT NULL,
    cursor_seq           INT8 NOT NULL,
    lifecycle_state      STRING NOT NULL,
    verification_state   STRING NOT NULL,
    evaluated_at         STRING NOT NULL,
    canonical_projection BYTES NOT NULL,
    updated_at           TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, episode_fingerprint),
    CONSTRAINT memory_discrepancy_projection_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_discrepancy_projection_episode_shape
        CHECK (octet_length(episode_fingerprint) = 32),
    CONSTRAINT memory_discrepancy_projection_cursor_bound
        CHECK (cursor_seq >= 1),
    CONSTRAINT memory_discrepancy_projection_lifecycle
        CHECK (lifecycle_state IN
               ('open', 'acknowledged', 'resolved', 'waived', 'dismissed', 'superseded')),
    CONSTRAINT memory_discrepancy_projection_verification
        CHECK (verification_state IN ('candidate', 'verified', 'refuted', 'indeterminate')),
    CONSTRAINT memory_discrepancy_projection_evaluated_bound
        CHECK (octet_length(evaluated_at) BETWEEN 1 AND 64),
    CONSTRAINT memory_discrepancy_projection_canonical_bound
        CHECK (octet_length(canonical_projection) BETWEEN 1 AND 1048576)
);

-- SQLx sends a multi-statement migration as one implicit transaction, and
-- this migration is registered no_tx, so there is no enclosing application
-- transaction. Commit the schema changes before inspecting the public catalog.
COMMIT;

-- Fail closed on same-name relation drift, exactly as migrations 0018, 0020,
-- and 0024 do: IF NOT EXISTS would otherwise ADOPT an unrelated object that
-- merely shares the name. Pin the exact committed column shape of all four
-- tables. Stop on 55000 if a named object is not the object this migration
-- defines.
DO $$
DECLARE
    drifted STRING;
BEGIN
    SELECT string_agg(expected.relation_name, ', ' ORDER BY expected.relation_name)
    INTO drifted
    FROM (VALUES
        ('memory_discrepancy_heads_v1',
            'tenant_id:uuid:NO,project:text:NO,episode_fingerprint:bytea:NO,family_fingerprint:bytea:NO,envelope_id:bytea:NO,log_seq:bigint:NO,updated_at:timestamp with time zone:NO'),
        ('memory_discrepancy_log_v1',
            'tenant_id:uuid:NO,project:text:NO,episode_fingerprint:bytea:NO,seq:bigint:NO,record_kind:text:NO,record_id:bytea:NO,canonical_record:bytea:NO,created_at:timestamp with time zone:NO'),
        ('memory_discrepancy_relations_v1',
            'tenant_id:uuid:NO,project:text:NO,family_fingerprint:bytea:NO,relation_id:bytea:NO,canonical_relation:bytea:NO,created_at:timestamp with time zone:NO'),
        ('memory_discrepancy_projections_v1',
            'tenant_id:uuid:NO,project:text:NO,episode_fingerprint:bytea:NO,cursor_seq:bigint:NO,lifecycle_state:text:NO,verification_state:text:NO,evaluated_at:text:NO,canonical_projection:bytea:NO,updated_at:timestamp with time zone:NO')
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
            MESSAGE = 'migration 0027 same-name relation drift: ' || drifted;
    END IF;
END
$$;
