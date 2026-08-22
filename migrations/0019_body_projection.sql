-- no-transaction
-- W2-BODY. Content-addressed body/occurrence/parse-manifest projection plane.
--
-- This migration is ADDITIVE and creates NEW tables only. It deliberately does
-- NOT extend memory_chunks (that table's publication grant list is frozen and
-- an ALTER there would reopen the private-vs-public plane boundary). Every
-- object here lives in the PRIVATE data plane: none is added to
-- PUBLICATION_READ_TABLES and none is granted to fleet_publication, so a body
-- extracted from provider evidence is never reachable through the read-only
-- public plane.
--
-- Ownership: created and owned by fleet_migrator (the single-migrator
-- deployment job), exactly like migration 0018. fleet_runtime needs SELECT on
-- memory_evidence_events (already granted) plus SELECT/INSERT/UPDATE on the
-- seven tables below; that runtime grant is added by the deployment role-grant
-- job and is flagged in the W2-BODY handoff (this migration only creates the
-- objects). Live tests run as the schema owner and therefore need no grant.
--
-- CockroachDB 26.2 online DDL: every object is created with IF NOT EXISTS so a
-- process death between a committed schema change and SQLx's history row is
-- resumable, and this migration is registered no_tx and runs in the third
-- (online) execution phase with autocommit_before_ddl enabled, exactly like
-- migrations 0015 through 0018. Every name is part of the schema contract.
--
-- Identity discipline: every *_id / *_sha256 / *_digest column is a value
-- DERIVED by the projector from the frozen preimages in
-- src/memory_contracts/chunk_identity.rs (ParserKeyV1, SourceSpanV1,
-- ChunkOccurrencePreimageV1, ParseRunManifestPreimageV1, GenerationPointerV1)
-- and src/memory_contracts/digest.rs (body_digest). The database stores those
-- values and their canonical preimage bytes; it never mints an identity.

-- Content-addressed bodies. content_sha256 = body_digest(body_bytes) and is the
-- primary key: a body is stored at most once per (tenant, project) and the
-- projector fails closed if the same digest is ever presented over different
-- bytes (ChunkIntegrityCollisionV1::BodyDigestBytesCollision).
CREATE TABLE IF NOT EXISTS memory_body_objects_v1 (
    tenant_id                  UUID NOT NULL,
    project                    STRING NOT NULL,
    content_sha256             BYTES NOT NULL,
    byte_length                INT8 NOT NULL,
    body_bytes                 BYTES NOT NULL,
    media_type                 STRING NOT NULL,
    protection_domain_id       STRING NOT NULL,
    first_accepted_event_id    BYTES NOT NULL,
    created_at                 TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, content_sha256),
    CONSTRAINT memory_body_object_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_body_object_content_sha256_shape
        CHECK (octet_length(content_sha256) = 32),
    CONSTRAINT memory_body_object_byte_length_bound
        CHECK (byte_length BETWEEN 1 AND 1048576),
    CONSTRAINT memory_body_object_bytes_match_length
        CHECK (octet_length(body_bytes) = byte_length),
    CONSTRAINT memory_body_object_identity_bounds
        CHECK (octet_length(media_type) BETWEEN 1 AND 128
               AND octet_length(protection_domain_id) BETWEEN 1 AND 128),
    CONSTRAINT memory_body_object_accepted_event_shape
        CHECK (octet_length(first_accepted_event_id) = 32)
);

-- One chunk occurrence: occurrence_id = ChunkOccurrencePreimageV1::occurrence_id
-- over the source-object version URI, parser key, ordered spans, ordinal,
-- body-content id, and policy versions. canonical_preimage stores the exact
-- encode_canonical bytes of that preimage, so a replay from the same event log
-- reproduces a byte-identical row and a same-id/different-preimage reissue is
-- detectable as an integrity collision.
CREATE TABLE IF NOT EXISTS memory_chunk_occurrences_v1 (
    tenant_id                       UUID NOT NULL,
    project                         STRING NOT NULL,
    occurrence_id                   BYTES NOT NULL,
    source_object_version_uri       STRING NOT NULL,
    parser_key_id                   BYTES NOT NULL,
    body_content_id                 BYTES NOT NULL,
    occurrence_ordinal              INT8 NOT NULL,
    redaction_policy_version        INT8 NOT NULL,
    publication_classifier_version  INT8 NOT NULL,
    generation_sequence            INT8 NOT NULL,
    canonical_preimage              BYTES NOT NULL,
    accepted_event_id               BYTES NOT NULL,
    created_at                      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, occurrence_id),
    CONSTRAINT memory_chunk_occurrence_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_chunk_occurrence_id_shape
        CHECK (octet_length(occurrence_id) = 32),
    CONSTRAINT memory_chunk_occurrence_uri_bound
        CHECK (octet_length(source_object_version_uri) BETWEEN 1 AND 256),
    CONSTRAINT memory_chunk_occurrence_parser_key_shape
        CHECK (octet_length(parser_key_id) = 32),
    CONSTRAINT memory_chunk_occurrence_body_content_shape
        CHECK (octet_length(body_content_id) = 32),
    CONSTRAINT memory_chunk_occurrence_ordinal_bound
        CHECK (occurrence_ordinal >= 0),
    CONSTRAINT memory_chunk_occurrence_policy_versions_bound
        CHECK (redaction_policy_version > 0 AND publication_classifier_version > 0),
    CONSTRAINT memory_chunk_occurrence_generation_bound
        CHECK (generation_sequence > 0),
    CONSTRAINT memory_chunk_occurrence_preimage_bound
        CHECK (octet_length(canonical_preimage) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_chunk_occurrence_accepted_event_shape
        CHECK (octet_length(accepted_event_id) = 32)
);

-- Ordered raw-source byte spans of one occurrence (SourceSpanV1). Kept as an
-- explicit child table so a query can read an occurrence's exact byte-range
-- coordinates without decoding the canonical preimage. Line numbers are
-- deliberately absent (display metadata only).
CREATE TABLE IF NOT EXISTS memory_chunk_occurrence_spans_v1 (
    tenant_id       UUID NOT NULL,
    project         STRING NOT NULL,
    occurrence_id   BYTES NOT NULL,
    span_ordinal    INT8 NOT NULL,
    byte_start      INT8 NOT NULL,
    byte_end        INT8 NOT NULL,
    span_digest     BYTES NOT NULL,
    PRIMARY KEY (tenant_id, project, occurrence_id, span_ordinal),
    CONSTRAINT memory_occurrence_span_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_occurrence_span_occurrence_shape
        CHECK (octet_length(occurrence_id) = 32),
    CONSTRAINT memory_occurrence_span_ordinal_bound
        CHECK (span_ordinal >= 0),
    CONSTRAINT memory_occurrence_span_range_bound
        CHECK (byte_start >= 0 AND byte_end > byte_start),
    CONSTRAINT memory_occurrence_span_digest_shape
        CHECK (octet_length(span_digest) = 32)
);

-- One parse-run manifest: manifest_id = ParseRunManifestPreimageV1::manifest_id
-- over the source representation URI, parser key, ordered occurrence ids, sorted
-- body digests, and the coverage receipt. canonical_preimage stores the exact
-- encode_canonical bytes (which include the ordered occurrence ids), so the
-- manifest->occurrence graph is recoverable and replay-stable without a
-- separate membership table.
CREATE TABLE IF NOT EXISTS memory_parse_run_manifests_v1 (
    tenant_id                   UUID NOT NULL,
    project                     STRING NOT NULL,
    manifest_id                 BYTES NOT NULL,
    source_representation_uri   STRING NOT NULL,
    parser_key_id               BYTES NOT NULL,
    coverage_receipt_digest     BYTES NOT NULL,
    generation_sequence         INT8 NOT NULL,
    canonical_preimage          BYTES NOT NULL,
    accepted_event_id           BYTES NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, manifest_id),
    CONSTRAINT memory_parse_manifest_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_parse_manifest_id_shape
        CHECK (octet_length(manifest_id) = 32),
    CONSTRAINT memory_parse_manifest_uri_bound
        CHECK (octet_length(source_representation_uri) BETWEEN 1 AND 256),
    CONSTRAINT memory_parse_manifest_parser_key_shape
        CHECK (octet_length(parser_key_id) = 32),
    CONSTRAINT memory_parse_manifest_coverage_shape
        CHECK (octet_length(coverage_receipt_digest) = 32),
    CONSTRAINT memory_parse_manifest_generation_bound
        CHECK (generation_sequence > 0),
    CONSTRAINT memory_parse_manifest_preimage_bound
        CHECK (octet_length(canonical_preimage) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_parse_manifest_accepted_event_shape
        CHECK (octet_length(accepted_event_id) = 32)
);

-- Commit/ref membership: which immutable source-object version was observed
-- under which provider revision ("commit") and logical event key ("ref"),
-- taken verbatim from the accepted evidence event's source-fact identity.
CREATE TABLE IF NOT EXISTS memory_source_commit_membership_v1 (
    tenant_id                   UUID NOT NULL,
    project                     STRING NOT NULL,
    source_object_version_uri   STRING NOT NULL,
    commit_revision             BYTES NOT NULL,
    ref_key                     BYTES NOT NULL,
    accepted_event_id           BYTES NOT NULL,
    observed_at                 TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, source_object_version_uri, commit_revision),
    CONSTRAINT memory_commit_membership_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_commit_membership_uri_bound
        CHECK (octet_length(source_object_version_uri) BETWEEN 1 AND 256),
    CONSTRAINT memory_commit_membership_revision_bound
        CHECK (octet_length(commit_revision) BETWEEN 1 AND 256),
    CONSTRAINT memory_commit_membership_ref_bound
        CHECK (octet_length(ref_key) BETWEEN 1 AND 256),
    CONSTRAINT memory_commit_membership_accepted_event_shape
        CHECK (octet_length(accepted_event_id) = 32)
);

-- Current active parser generation per source representation. pointer_id =
-- GenerationPointerV1::pointer_id. A parser-key upgrade advances
-- generation_sequence by exactly one through a compare-and-swap
-- (GenerationPointerSwitchProposalV1::checked_against) and opens a SHADOW
-- generation; it never rewrites the prior generation's occurrence/manifest
-- rows.
CREATE TABLE IF NOT EXISTS memory_generation_pointers_v1 (
    tenant_id                   UUID NOT NULL,
    project                     STRING NOT NULL,
    source_representation_uri   STRING NOT NULL,
    pointer_id                  BYTES NOT NULL,
    active_parser_key_id        BYTES NOT NULL,
    active_manifest_id          BYTES NOT NULL,
    generation_sequence         INT8 NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, source_representation_uri),
    CONSTRAINT memory_generation_pointer_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_generation_pointer_uri_bound
        CHECK (octet_length(source_representation_uri) BETWEEN 1 AND 256),
    CONSTRAINT memory_generation_pointer_id_shape
        CHECK (octet_length(pointer_id) = 32),
    CONSTRAINT memory_generation_pointer_parser_key_shape
        CHECK (octet_length(active_parser_key_id) = 32),
    CONSTRAINT memory_generation_pointer_manifest_shape
        CHECK (octet_length(active_manifest_id) = 32),
    CONSTRAINT memory_generation_pointer_generation_bound
        CHECK (generation_sequence > 0)
);

-- Projector cursor. Keyed by (ledger_family, shard) exactly like
-- memory_relation_projection_watermarks_v1 (REPLAY-02): a body-projection
-- transaction advances this row in the SAME transaction as the body/occurrence/
-- manifest rows it produced, so the cursor never advances past a row it did not
-- durably write.
CREATE TABLE IF NOT EXISTS memory_body_projection_watermarks_v1 (
    tenant_id                UUID NOT NULL,
    project                  STRING NOT NULL,
    ledger_family            STRING NOT NULL,
    shard                    INT4 NOT NULL,
    last_committed_offset    INT8 NOT NULL,
    updated_at               TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, ledger_family, shard),
    CONSTRAINT memory_body_watermark_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_body_watermark_ledger_family
        CHECK (ledger_family IN ('control', 'evidence')),
    CONSTRAINT memory_body_watermark_shard_bound
        CHECK (shard BETWEEN 0 AND 4095),
    CONSTRAINT memory_body_watermark_offset_bound
        CHECK (last_committed_offset >= 0)
);

-- SQLx sends a multi-statement migration as one implicit transaction, and this
-- migration is registered no_tx, so there is no enclosing application
-- transaction. Commit every object above before inspecting the public catalog.
COMMIT;

-- Fail closed on same-name drift, mirroring migration 0018: IF NOT EXISTS alone
-- would ADOPT an unrelated object that merely shares a name. Assert the exact
-- column shape of every relation this migration claims to create; stop on 55000
-- if the named object is not the object this migration defines.
DO $$
DECLARE
    drifted STRING;
BEGIN
    SELECT string_agg(expected.relation_name, ', ' ORDER BY expected.relation_name)
    INTO drifted
    FROM (VALUES
        ('memory_body_objects_v1',
            'tenant_id:uuid:NO,project:text:NO,content_sha256:bytea:NO,byte_length:bigint:NO,body_bytes:bytea:NO,media_type:text:NO,protection_domain_id:text:NO,first_accepted_event_id:bytea:NO,created_at:timestamp with time zone:NO'),
        ('memory_chunk_occurrences_v1',
            'tenant_id:uuid:NO,project:text:NO,occurrence_id:bytea:NO,source_object_version_uri:text:NO,parser_key_id:bytea:NO,body_content_id:bytea:NO,occurrence_ordinal:bigint:NO,redaction_policy_version:bigint:NO,publication_classifier_version:bigint:NO,generation_sequence:bigint:NO,canonical_preimage:bytea:NO,accepted_event_id:bytea:NO,created_at:timestamp with time zone:NO'),
        ('memory_chunk_occurrence_spans_v1',
            'tenant_id:uuid:NO,project:text:NO,occurrence_id:bytea:NO,span_ordinal:bigint:NO,byte_start:bigint:NO,byte_end:bigint:NO,span_digest:bytea:NO'),
        ('memory_parse_run_manifests_v1',
            'tenant_id:uuid:NO,project:text:NO,manifest_id:bytea:NO,source_representation_uri:text:NO,parser_key_id:bytea:NO,coverage_receipt_digest:bytea:NO,generation_sequence:bigint:NO,canonical_preimage:bytea:NO,accepted_event_id:bytea:NO,created_at:timestamp with time zone:NO'),
        ('memory_source_commit_membership_v1',
            'tenant_id:uuid:NO,project:text:NO,source_object_version_uri:text:NO,commit_revision:bytea:NO,ref_key:bytea:NO,accepted_event_id:bytea:NO,observed_at:timestamp with time zone:NO'),
        ('memory_generation_pointers_v1',
            'tenant_id:uuid:NO,project:text:NO,source_representation_uri:text:NO,pointer_id:bytea:NO,active_parser_key_id:bytea:NO,active_manifest_id:bytea:NO,generation_sequence:bigint:NO,updated_at:timestamp with time zone:NO'),
        ('memory_body_projection_watermarks_v1',
            'tenant_id:uuid:NO,project:text:NO,ledger_family:text:NO,shard:integer:NO,last_committed_offset:bigint:NO,updated_at:timestamp with time zone:NO')
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
            MESSAGE = 'migration 0019 same-name relation drift: ' || drifted;
    END IF;
END
$$;
