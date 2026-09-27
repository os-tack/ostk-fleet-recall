-- no-transaction
-- The predecessor representation key of an accepted evidence event, as a
-- column the ledger can seek on (ADR 0006 D9, amendment of 2026-09-27).
--
-- An evidence statement whose representation lineage is `supersedes` names
-- the exact representation key it reinterprets, but until now that key lived
-- only inside `canonical_event`. Two readers need it as a seek: the append
-- classifier, which must recognise a re-presented pre-profile-3 fact as a
-- replay of its redacted successor rather than quarantine it, and the body
-- projector, which must let an erased raw representation pass rather than
-- park its watermark on missing content. Both look the successor up by the
-- predecessor's digest, which is the presented event's own semantic object
-- digest.
--
-- The column is nullable and unindexed on NULL: every event already stored
-- keeps NULL, because none of them was appended with a `supersedes` lineage
-- (every connector rendered `origin`), and no backfill rewrites a row. It is
-- written by INSERT only; the accepted envelope is still never updated. The
-- index mirrors the shape of migration 0023's projection indexes: a
-- scope-prefixed seek that stores the columns the successor walk reads, so
-- the walk never touches the primary index.
--
-- Migrations 0001-0036 stay byte-identical. Like migrations 0018 onward this
-- DDL runs outside SQLx's transaction wrapper: each change commits on its own
-- (ADD COLUMN, ADD CONSTRAINT, CREATE INDEX are IF NOT EXISTS), so an
-- interrupted run resumes and a rerun over a hand-edited catalog fails the
-- drift check below rather than recording success.

ALTER TABLE memory_evidence_events
    ADD COLUMN IF NOT EXISTS predecessor_representation_key_digest BYTES NULL;

COMMIT;

ALTER TABLE memory_evidence_events
    ADD CONSTRAINT IF NOT EXISTS memory_evidence_event_predecessor_key_shape
        CHECK (
            predecessor_representation_key_digest IS NULL
            OR octet_length(predecessor_representation_key_digest) = 32
        );

COMMIT;

-- The primary-key columns (epoch_id, shard, committed_offset) are implicit in
-- every secondary index, so the walk's position columns need no STORING
-- clause of their own; the catalog renders only the two explicit ones.
CREATE INDEX IF NOT EXISTS memory_evidence_events_predecessor_key_idx
    ON memory_evidence_events (tenant_id, project, predecessor_representation_key_digest)
    STORING (event_id, event_kind);

COMMIT;

-- Fail closed on drift, as migrations 0032 through 0034 do: IF NOT EXISTS
-- would otherwise adopt a same-name column, constraint, or index of another
-- definition. Require the exact committed column shape of the events table,
-- the exact CHECK, and the exact public index definition; stop on 55000
-- otherwise.
DO $$
DECLARE
    drifted STRING;
    shaped STRING;
    indexed STRING;
    expected_index STRING;
BEGIN
    SELECT string_agg(expected.relation_name, ', ' ORDER BY expected.relation_name)
    INTO drifted
    FROM (VALUES
        ('memory_evidence_events',
            'tenant_id:uuid:NO,project:text:NO,epoch_id:bytea:NO,shard:integer:NO,committed_offset:bigint:NO,event_id:bytea:NO,event_schema_version:integer:NO,event_kind:text:NO,semantic_object_digest:bytea:NO,consistency_family:text:NO,consistency_key_digest:bytea:NO,canonical_event:bytea:NO,previous_chain_digest:bytea:NO,chain_digest:bytea:NO,accepted_at:timestamp with time zone:NO,predecessor_representation_key_digest:bytea:YES')
    ) AS expected (relation_name, column_shape)
    WHERE expected.column_shape IS DISTINCT FROM (
        SELECT string_agg(column_object.column_name || ':' || column_object.data_type
                          || ':' || column_object.is_nullable, ',' ORDER BY column_object.ordinal_position)
        FROM information_schema.columns AS column_object
        WHERE column_object.table_schema = 'public' AND column_object.table_name = expected.relation_name
    );

    SELECT pg_catalog.pg_get_constraintdef(constraint_object.oid)
    INTO shaped
    FROM pg_catalog.pg_constraint AS constraint_object
    JOIN pg_catalog.pg_class AS relation_object
        ON relation_object.oid = constraint_object.conrelid
    JOIN pg_catalog.pg_namespace AS schema_object
        ON schema_object.oid = relation_object.relnamespace
    WHERE schema_object.nspname = 'public'
      AND relation_object.relname = 'memory_evidence_events'
      AND constraint_object.conname = 'memory_evidence_event_predecessor_key_shape';

    SELECT index_object.indexdef
    INTO indexed
    FROM pg_catalog.pg_indexes AS index_object
    WHERE index_object.schemaname = 'public'
      AND index_object.tablename = 'memory_evidence_events'
      AND index_object.indexname = 'memory_evidence_events_predecessor_key_idx';
    -- The public catalog renders the index with the current database name,
    -- exactly as migrations 0016 and 0017 assert their own indexes.
    expected_index := format(
        'CREATE INDEX memory_evidence_events_predecessor_key_idx ON %I.public.memory_evidence_events USING btree (tenant_id ASC, project ASC, predecessor_representation_key_digest ASC) STORING (event_id, event_kind)',
        pg_catalog.current_database()
    );

    IF drifted IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'migration 0037 same-name relation drift: ' || drifted;
    END IF;
    IF shaped IS DISTINCT FROM
           'CHECK (((predecessor_representation_key_digest IS NULL) OR (octet_length(predecessor_representation_key_digest) = 32)))'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'migration 0037 predecessor key constraint drift';
    END IF;
    IF indexed IS DISTINCT FROM expected_index THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'migration 0037 predecessor key index drift';
    END IF;
END
$$;
