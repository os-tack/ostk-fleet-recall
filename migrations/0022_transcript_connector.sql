-- no-transaction
-- Transcript connector outbox and per-source cursor (W2-TRANS). Two additive
-- private-plane tables: the durable outbox of redacted, canonicalized evidence
-- ingress candidates, and the per-source collection cursor advanced atomically
-- with each batch. Nothing here rewrites an existing row, drops an object, or
-- narrows an existing constraint; migrations 0001 through 0020 remain
-- byte-identical. This migration owns version 21, after the co-launched W2-BODY
-- (0019) and W2-COVER-RT (0020); a version gap is expected on this branch and
-- closed at integration.
--
-- CockroachDB 26.2 cannot run this DDL inside SQLx's PostgreSQL-oriented
-- transaction wrapper, so this migration is registered no_tx and every object is
-- created with IF NOT EXISTS: a process death between a committed schema change
-- and SQLx's history row is resumable. Every name is part of the schema
-- contract.
--
-- Neither table is one of the publication reader's eight tables; both are
-- private-plane staging rows (PUBLIC-03/04). Like migrations 0018-0020, they
-- carry NO foreign key to any memory_control_* / memory_registry_* table, so
-- fleet_runtime needs no control-plane grant to write them.
--
-- SECURITY (EVID-05): canonical_payload holds ONLY redacted bodies. The
-- collector has no code path from raw transcript text to a row here: a turn
-- whose post-redaction re-scan still matches a secret shape is withheld and no
-- row is built for it at all. This table is therefore not an encrypted store —
-- it is a store that never receives secret-shaped material in the first place.
-- The governed content object (migration 0018) is where the same bytes become
-- encrypted at rest once the drain admits them.

-- Ownership: fleet_migrator. One row per staged transcript turn. outbox_id is
-- the SHA-256 of the exact canonical EvidenceIngressCandidateV2 bytes, so
-- re-staging the same turn under the same parser and the same active package is
-- an idempotent primary-key conflict rather than a duplicate row.
CREATE TABLE IF NOT EXISTS memory_transcript_outbox_v1 (
    tenant_id                 UUID NOT NULL,
    project                   STRING NOT NULL,
    outbox_id                 BYTES NOT NULL,
    source_id                 STRING NOT NULL,
    session_id                STRING NOT NULL,
    turn_ordinal              INT8 NOT NULL,
    batch_seq                 INT8 NOT NULL,
    canonical_candidate       BYTES NOT NULL,
    canonical_locators        BYTES NOT NULL,
    canonical_payload         BYTES NOT NULL,
    state                     STRING NOT NULL,
    created_at                TIMESTAMPTZ NOT NULL,
    drained_at                TIMESTAMPTZ NULL,
    PRIMARY KEY (tenant_id, project, outbox_id),
    CONSTRAINT memory_transcript_outbox_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_transcript_outbox_id_shape
        CHECK (octet_length(outbox_id) = 32),
    CONSTRAINT memory_transcript_outbox_source_bound
        CHECK (octet_length(source_id) BETWEEN 1 AND 1024),
    CONSTRAINT memory_transcript_outbox_session_bound
        CHECK (octet_length(session_id) BETWEEN 1 AND 256),
    CONSTRAINT memory_transcript_outbox_ordinal_bound
        CHECK (turn_ordinal >= 0),
    CONSTRAINT memory_transcript_outbox_batch_bound
        CHECK (batch_seq >= 1),
    CONSTRAINT memory_transcript_outbox_candidate_bound
        CHECK (octet_length(canonical_candidate) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_transcript_outbox_locators_bound
        CHECK (octet_length(canonical_locators) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_transcript_outbox_payload_bound
        CHECK (octet_length(canonical_payload) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_transcript_outbox_state
        CHECK (state IN ('pending', 'drained')),
    -- A drained row must carry its drain clock and a pending row must not:
    -- the state column can never disagree with the timestamp column.
    CONSTRAINT memory_transcript_outbox_drained_clock
        CHECK ((state = 'drained') = (drained_at IS NOT NULL))
);

-- Ownership: fleet_migrator. The durable per-source collection cursor. It is
-- advanced in the SAME transaction that inserts a batch's outbox rows, so a
-- crash leaves both unadvanced and the batch is simply re-collected.
-- next_ordinal is the turn number the next collected turn of this source takes,
-- which is what keeps turn ordinals stable across a resumed collection.
CREATE TABLE IF NOT EXISTS memory_transcript_cursors_v1 (
    tenant_id                 UUID NOT NULL,
    project                   STRING NOT NULL,
    source_id                 STRING NOT NULL,
    byte_offset               INT8 NOT NULL,
    line_ordinal              INT8 NOT NULL,
    next_ordinal              INT8 NOT NULL,
    batch_seq                 INT8 NOT NULL,
    source_digest             BYTES NOT NULL,
    updated_at                TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, source_id),
    CONSTRAINT memory_transcript_cursor_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_transcript_cursor_source_bound
        CHECK (octet_length(source_id) BETWEEN 1 AND 1024),
    CONSTRAINT memory_transcript_cursor_offset_bound
        CHECK (byte_offset >= 0),
    CONSTRAINT memory_transcript_cursor_line_bound
        CHECK (line_ordinal >= 0),
    CONSTRAINT memory_transcript_cursor_next_ordinal_bound
        CHECK (next_ordinal >= 0),
    CONSTRAINT memory_transcript_cursor_batch_bound
        CHECK (batch_seq >= 0),
    CONSTRAINT memory_transcript_cursor_digest_shape
        CHECK (octet_length(source_digest) = 32)
);

CREATE INDEX IF NOT EXISTS memory_transcript_outbox_drain_idx
    ON memory_transcript_outbox_v1 (
        tenant_id,
        project,
        state,
        batch_seq,
        turn_ordinal,
        outbox_id
    );

CREATE INDEX IF NOT EXISTS memory_transcript_outbox_source_idx
    ON memory_transcript_outbox_v1 (
        tenant_id,
        project,
        source_id,
        turn_ordinal
    );

-- SQLx sends a multi-statement migration as one implicit transaction, and this
-- migration is registered no_tx, so there is no enclosing application
-- transaction. Commit the schema changes before inspecting the public catalog.
COMMIT;

-- Fail closed on same-name relation drift, exactly as migrations 0018-0020 do:
-- IF NOT EXISTS would otherwise ADOPT an unrelated object that merely shares the
-- name. Pin the exact committed column shape of both tables. Stop on 55000 if
-- the named object is not the object this migration defines.
DO $$
DECLARE
    drifted STRING;
BEGIN
    SELECT string_agg(expected.relation_name, ', ' ORDER BY expected.relation_name)
    INTO drifted
    FROM (VALUES
        ('memory_transcript_outbox_v1',
            'tenant_id:uuid:NO,project:text:NO,outbox_id:bytea:NO,source_id:text:NO,session_id:text:NO,turn_ordinal:bigint:NO,batch_seq:bigint:NO,canonical_candidate:bytea:NO,canonical_locators:bytea:NO,canonical_payload:bytea:NO,state:text:NO,created_at:timestamp with time zone:NO,drained_at:timestamp with time zone:YES'),
        ('memory_transcript_cursors_v1',
            'tenant_id:uuid:NO,project:text:NO,source_id:text:NO,byte_offset:bigint:NO,line_ordinal:bigint:NO,next_ordinal:bigint:NO,batch_seq:bigint:NO,source_digest:bytea:NO,updated_at:timestamp with time zone:NO')
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
            MESSAGE = 'migration 0021 same-name relation drift: ' || drifted;
    END IF;
END
$$;
