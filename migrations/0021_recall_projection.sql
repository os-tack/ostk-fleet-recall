-- no-transaction
-- W2-PROJ. Lexical-first / dense-later recall projection over W2-BODY's
-- content-addressed bodies.
--
-- This migration is ADDITIVE and creates NEW tables only. It does not extend
-- memory_body_objects_v1 (W2-BODY owns that shape) and it does not extend
-- memory_chunks (whose publication grant list is frozen).
--
-- PRIVATE DATA PLANE ONLY. None of the three tables below is added to
-- PUBLICATION_READ_TABLES and none is granted to fleet_publication, so neither
-- the lexical text projected from a governed body nor the dense vector derived
-- from it is ever reachable through the read-only public plane. The dense
-- worker is likewise a private-plane background process: no public route
-- triggers it and no public route reads its output.
--
-- Ownership mirrors migrations 0018-0020: created and owned by fleet_migrator.
-- fleet_runtime needs SELECT on memory_body_objects_v1 (W2-BODY's grant) plus
-- SELECT/INSERT/UPDATE on the three tables below; that runtime grant is added by
-- the deployment role-grant job and is flagged in the W2-PROJ handoff (this
-- migration only creates the objects). Live tests run as the schema owner and
-- therefore need no grant.
--
-- CockroachDB 26.2 online DDL: every object is created with IF NOT EXISTS so a
-- process death between a committed schema change and SQLx's history row is
-- resumable, and this migration is registered no_tx and runs in the third
-- (online) execution phase with autocommit_before_ddl enabled, exactly like
-- migrations 0015 through 0020. Every name is part of the schema contract.
--
-- SPLIT, NOT NULLABLE, EMBEDDING STORAGE. Migration 0001 records why the active
-- dense query must reach rows whose vector-index prefix columns are all
-- equality-bound: CockroachDB 26.2's C-SPANN index can serve the ANN portion of
-- a scan only when every prefix column ahead of the vector column is an
-- equality predicate, and a vector index cannot be built over a nullable
-- column. Rows still waiting for an embedding therefore live in the LEXICAL
-- table alone and simply have no row yet in the dense table, instead of a
-- lexical row carrying a NULL vector. That is what makes "lexical is available
-- immediately, dense arrives later" a physical property of the schema rather
-- than a filter every query has to remember to apply, and it is why a dense
-- failure cannot remove lexical availability: the two tiers share no row.

-- Lexical tier. One row per content-addressed body, written by the lexical
-- projector as soon as the body row lands. lexical_text is the deterministic
-- normalization of the body bytes (src/projectors/lexical.rs) and
-- lexical_text_digest is its domain-separated digest, so a replay from the body
-- tables is verifiable as byte-identical.
-- A body whose bytes carry no derivable lexical text (not UTF-8, or empty after
-- normalization) is still RECORDED here, with lexical_state = 'unindexable' and
-- an empty lexical_text: the projector never silently skips a body, and the
-- cursor can advance past it without losing the fact that it was seen.
CREATE TABLE IF NOT EXISTS memory_body_lexical_projection_v1 (
    tenant_id              UUID NOT NULL,
    project                STRING NOT NULL,
    body_content_id        BYTES NOT NULL,
    body_created_at        TIMESTAMPTZ NOT NULL,
    lexical_state          STRING NOT NULL,
    unindexable_reason     STRING NOT NULL,
    normalization_version  INT8 NOT NULL,
    lexical_text           STRING NOT NULL,
    lexical_text_digest    BYTES NOT NULL,
    search_document        TSVECTOR AS (to_tsvector('english', lexical_text)) STORED,
    PRIMARY KEY (tenant_id, project, body_content_id),
    CONSTRAINT memory_lexical_projection_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_lexical_projection_body_shape
        CHECK (octet_length(body_content_id) = 32),
    CONSTRAINT memory_lexical_projection_state
        CHECK (lexical_state IN ('indexed', 'unindexable')),
    -- An indexed row carries no reason; an unindexable row must name exactly
    -- one of the closed reasons and must carry empty text.
    CONSTRAINT memory_lexical_projection_reason_matches_state
        CHECK ((lexical_state = 'indexed' AND unindexable_reason = '')
               OR (lexical_state = 'unindexable'
                   AND unindexable_reason IN ('non_utf8', 'empty_after_normalization')
                   AND lexical_text = '')),
    CONSTRAINT memory_lexical_projection_normalization_bound
        CHECK (normalization_version > 0),
    CONSTRAINT memory_lexical_projection_text_bound
        CHECK (octet_length(lexical_text) BETWEEN 0 AND 262144),
    CONSTRAINT memory_lexical_projection_text_digest_shape
        CHECK (octet_length(lexical_text_digest) = 32)
);

-- Scope-led inverted index, mirroring memory_chunks_lexical_idx: tenant_id and
-- project lead so a lexical probe stays selective inside one project.
CREATE INVERTED INDEX IF NOT EXISTS memory_body_lexical_projection_idx
    ON memory_body_lexical_projection_v1 (tenant_id, project, search_document);

-- Dense tier. One row per body that has actually been embedded. Absence of a
-- row is the "not embedded yet" state; there is no nullable vector column and
-- therefore no way for an un-embedded body to enter the ANN index.
CREATE TABLE IF NOT EXISTS memory_body_dense_projection_v1 (
    tenant_id              UUID NOT NULL,
    project                STRING NOT NULL,
    body_content_id        BYTES NOT NULL,
    body_created_at        TIMESTAMPTZ NOT NULL,
    embedding_identity_id  BYTES NOT NULL,
    model_digest           BYTES NOT NULL,
    tokenization_version   INT8 NOT NULL,
    preprocessing_version  INT8 NOT NULL,
    distance_metric        STRING NOT NULL,
    dimensions             INT8 NOT NULL,
    embedding              VECTOR(512) NOT NULL,
    PRIMARY KEY (tenant_id, project, body_content_id),
    CONSTRAINT memory_dense_projection_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_dense_projection_body_shape
        CHECK (octet_length(body_content_id) = 32),
    CONSTRAINT memory_dense_projection_identity_shape
        CHECK (octet_length(embedding_identity_id) = 32),
    CONSTRAINT memory_dense_projection_model_shape
        CHECK (octet_length(model_digest) = 32),
    CONSTRAINT memory_dense_projection_policy_versions_bound
        CHECK (tokenization_version > 0 AND preprocessing_version > 0),
    CONSTRAINT memory_dense_projection_metric
        CHECK (distance_metric IN ('cosine', 'dot_product', 'euclidean_l2')),
    CONSTRAINT memory_dense_projection_dimensions
        CHECK (dimensions = 512)
);

-- C-SPANN equality prefix, per migration 0001: tenant_id and project are the
-- only columns ahead of the vector column, and the dense recall query binds
-- both with equality, so CockroachDB can serve the ANN portion of the scan.
CREATE VECTOR INDEX IF NOT EXISTS memory_body_dense_projection_semantic_idx
    ON memory_body_dense_projection_v1 (tenant_id, project, embedding vector_cosine_ops);

-- Per-projector cursors. The lexical and dense projectors are INDEPENDENT: one
-- row per projector, each advanced in the SAME transaction as the outputs it
-- describes (REPLAY-02). Killing the dense worker mid-batch therefore leaves
-- both the dense rows and the dense cursor at the last committed batch, and
-- touches neither the lexical rows nor the lexical cursor.
--
-- The cursor is the (body_created_at, body_content_id) pair of the last body a
-- committed batch consumed: that pair is the total order both projectors scan
-- memory_body_objects_v1 in.
CREATE TABLE IF NOT EXISTS memory_recall_projection_cursors_v1 (
    tenant_id             UUID NOT NULL,
    project               STRING NOT NULL,
    projector             STRING NOT NULL,
    last_body_created_at  TIMESTAMPTZ NOT NULL,
    last_body_content_id  BYTES NOT NULL,
    bodies_projected      INT8 NOT NULL,
    updated_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, projector),
    CONSTRAINT memory_recall_cursor_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_recall_cursor_projector
        CHECK (projector IN ('lexical', 'dense')),
    CONSTRAINT memory_recall_cursor_body_shape
        CHECK (octet_length(last_body_content_id) = 32),
    CONSTRAINT memory_recall_cursor_count_bound
        CHECK (bodies_projected >= 0)
);

-- SQLx sends a multi-statement migration as one implicit transaction, and this
-- migration is registered no_tx, so there is no enclosing application
-- transaction. Commit every object above before inspecting the public catalog.
COMMIT;

-- Fail closed on same-name drift, mirroring migrations 0018 and 0019: IF NOT
-- EXISTS alone would ADOPT an unrelated object that merely shares a name.
-- Assert the exact column shape of every relation this migration claims to
-- create; stop on 55000 if the named object is not the object this migration
-- defines.
DO $$
DECLARE
    drifted STRING;
BEGIN
    SELECT string_agg(expected.relation_name, ', ' ORDER BY expected.relation_name)
    INTO drifted
    FROM (VALUES
        ('memory_body_lexical_projection_v1',
            'tenant_id:uuid:NO,project:text:NO,body_content_id:bytea:NO,body_created_at:timestamp with time zone:NO,lexical_state:text:NO,unindexable_reason:text:NO,normalization_version:bigint:NO,lexical_text:text:NO,lexical_text_digest:bytea:NO,search_document:tsvector:YES'),
        ('memory_body_dense_projection_v1',
            'tenant_id:uuid:NO,project:text:NO,body_content_id:bytea:NO,body_created_at:timestamp with time zone:NO,embedding_identity_id:bytea:NO,model_digest:bytea:NO,tokenization_version:bigint:NO,preprocessing_version:bigint:NO,distance_metric:text:NO,dimensions:bigint:NO,embedding:vector:NO'),
        ('memory_recall_projection_cursors_v1',
            'tenant_id:uuid:NO,project:text:NO,projector:text:NO,last_body_created_at:timestamp with time zone:NO,last_body_content_id:bytea:NO,bodies_projected:bigint:NO,updated_at:timestamp with time zone:NO')
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
