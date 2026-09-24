-- no-transaction
-- Spec conformance (ADR 0007). Two additive, insert-only private-plane tables:
-- the canonical normative proposal and typed expectation each statement was
-- activated with, and one content-addressed record per spec check
-- (nonconforming, conforming, or unknown). Migrations 0001 through 0030 remain
-- byte-identical (0024's normative activation tables and 0027's discrepancy
-- ledger are not altered); version 25 remains the permanent gap.
--
-- Like migrations 0018 onward, this DDL runs outside SQLx's transaction
-- wrapper, so every object is created with IF NOT EXISTS and a process death
-- between the schema change and SQLx's history row is resumable.
--
-- Neither table carries a foreign key, and neither is one of the publication
-- reader's tables (PUBLIC-02/03). Rows are content-addressed and written with
-- ON CONFLICT DO NOTHING, so a replay writes nothing new and no row is ever
-- updated or deleted by the runtime.

-- Ownership: fleet_migrator. statement_id is the normative statement's 32-byte
-- identity; a re-read recomputes it from canonical_proposal and refuses a row
-- whose bytes no longer derive it. expectation_digest is the fingerprint of
-- canonical_expectation, which the proposal's proposition must carry.
CREATE TABLE IF NOT EXISTS memory_normative_statements_v1 (
    tenant_id             UUID NOT NULL,
    project               STRING NOT NULL,
    statement_id          BYTES NOT NULL,
    binding_family_id     STRING NOT NULL,
    expectation_digest    BYTES NOT NULL,
    canonical_proposal    BYTES NOT NULL,
    canonical_expectation BYTES NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, statement_id),
    CONSTRAINT memory_normative_statement_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_normative_statement_id_shape
        CHECK (octet_length(statement_id) = 32),
    CONSTRAINT memory_normative_statement_family_bound
        CHECK (octet_length(binding_family_id) BETWEEN 1 AND 256),
    CONSTRAINT memory_normative_statement_expectation_shape
        CHECK (octet_length(expectation_digest) = 32),
    CONSTRAINT memory_normative_statement_proposal_bound
        CHECK (octet_length(canonical_proposal) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_normative_statement_expectation_bound
        CHECK (octet_length(canonical_expectation) BETWEEN 1 AND 65536)
);

-- Ownership: fleet_migrator. check_id is the content address of
-- canonical_check, so the same comparison replays to the same row. The other
-- columns are indexed copies of fields inside canonical_check: the statement
-- and discrepancy family it judged, the observer event that measured the
-- commit, the commit, the verdict, and the discrepancy episode it opened or
-- joined (NULL unless the check found a discrepancy).
CREATE TABLE IF NOT EXISTS memory_spec_checks_v1 (
    tenant_id           UUID NOT NULL,
    project             STRING NOT NULL,
    check_id            BYTES NOT NULL,
    statement_id        BYTES NOT NULL,
    family_fingerprint  BYTES NOT NULL,
    observer_event_id   BYTES NOT NULL,
    commit_oid          STRING NOT NULL,
    verdict             STRING NOT NULL,
    episode_fingerprint BYTES NULL,
    canonical_check     BYTES NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, check_id),
    CONSTRAINT memory_spec_check_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_spec_check_id_shape
        CHECK (octet_length(check_id) = 32),
    CONSTRAINT memory_spec_check_statement_shape
        CHECK (octet_length(statement_id) = 32),
    CONSTRAINT memory_spec_check_family_shape
        CHECK (octet_length(family_fingerprint) = 32),
    CONSTRAINT memory_spec_check_event_shape
        CHECK (octet_length(observer_event_id) = 32),
    CONSTRAINT memory_spec_check_episode_shape
        CHECK (episode_fingerprint IS NULL OR octet_length(episode_fingerprint) = 32),
    CONSTRAINT memory_spec_check_commit_shape
        CHECK (commit_oid ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    CONSTRAINT memory_spec_check_verdict
        CHECK (verdict IN ('nonconforming', 'conforming', 'unknown')),
    CONSTRAINT memory_spec_check_canonical_bound
        CHECK (octet_length(canonical_check) BETWEEN 1 AND 65536)
);

-- The latest check per statement, and the prior verdict for one
-- (statement, commit), which keeps a registry head change from re-opening an
-- already-judged commit.
CREATE INDEX IF NOT EXISTS memory_spec_checks_statement_commit_idx
    ON memory_spec_checks_v1 (tenant_id, project, statement_id, commit_oid, created_at DESC);
-- The checks behind one discrepancy episode.
CREATE INDEX IF NOT EXISTS memory_spec_checks_episode_idx
    ON memory_spec_checks_v1 (tenant_id, project, episode_fingerprint);

-- SQLx sends a multi-statement migration as one implicit transaction, and
-- this migration is registered no_tx, so there is no enclosing application
-- transaction. Commit the schema changes before inspecting the public catalog.
COMMIT;

-- Fail closed on same-name relation drift, as migrations 0018, 0020, 0024,
-- 0027, 0029 and 0030 do: IF NOT EXISTS would otherwise adopt an unrelated
-- object that merely shares the name. Pin the exact committed column shape of
-- both tables and the two named indexes, and stop on 55000 if either is not
-- what this migration defines.
DO $$
DECLARE
    drifted STRING;
    index_count INT8;
BEGIN
    SELECT string_agg(expected.relation_name, ', ' ORDER BY expected.relation_name)
    INTO drifted
    FROM (VALUES
        ('memory_normative_statements_v1',
            'tenant_id:uuid:NO,project:text:NO,statement_id:bytea:NO,binding_family_id:text:NO,expectation_digest:bytea:NO,canonical_proposal:bytea:NO,canonical_expectation:bytea:NO,created_at:timestamp with time zone:NO'),
        ('memory_spec_checks_v1',
            'tenant_id:uuid:NO,project:text:NO,check_id:bytea:NO,statement_id:bytea:NO,family_fingerprint:bytea:NO,observer_event_id:bytea:NO,commit_oid:text:NO,verdict:text:NO,episode_fingerprint:bytea:YES,canonical_check:bytea:NO,created_at:timestamp with time zone:NO')
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

    SELECT count(DISTINCT indexname) INTO index_count
    FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'memory_spec_checks_v1'
      AND indexname IN ('memory_spec_checks_statement_commit_idx',
                        'memory_spec_checks_episode_idx');

    IF drifted IS NOT NULL OR index_count <> 2 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'migration 0031 same-name relation drift: '
                || COALESCE(drifted, 'spec check index set');
    END IF;
END
$$;
