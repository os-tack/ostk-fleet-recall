-- no-transaction
-- Normative head rebase (ADR 0008 D3). Adds 'rebase' to the record kinds of
-- migration 0024's normative log, so a binding family's head can move to a new
-- registry head with a row in its own log instead of stranding (ADR 0007 D11).
-- No table, column, or row changes, and nothing else is granted: the runtime
-- role already holds INSERT on the log.
--
-- Migration 0024 stays byte-identical. The widened constraint is added under a
-- new name first and the old one dropped after, each committed on its own, so
-- every interruption point leaves a kind constraint in force and a rerun
-- resumes: ADD CONSTRAINT IF NOT EXISTS keeps a committed new constraint, and
-- DROP CONSTRAINT IF EXISTS skips an already dropped old one. Until the old
-- constraint is dropped, both are in force and a 'rebase' row is still
-- refused, so no rebase can land on a half-applied migration.
--
-- Like migrations 0018 onward, this DDL runs outside SQLx's transaction
-- wrapper. SQLx sends the file as one implicit transaction, so each COMMIT
-- below ends one schema change before the next statement starts.

ALTER TABLE memory_normative_log_v1
    ADD CONSTRAINT IF NOT EXISTS memory_normative_log_kind_v2
        CHECK (record_kind IN ('lifecycle', 'contest', 'rebase'));

COMMIT;

ALTER TABLE memory_normative_log_v1 DROP CONSTRAINT IF EXISTS memory_normative_log_kind;

COMMIT;

-- Fail closed on drift, as migrations 0018 and 0023 do: IF NOT EXISTS would
-- otherwise ADOPT a same-name constraint of another definition, and a rerun
-- over a hand-edited catalog must not record success. Require the exact
-- committed definition of the widened constraint and the absence of the old
-- one; stop on 55000 otherwise.
DO $$
DECLARE
    widened STRING;
    retired INT8;
BEGIN
    SELECT pg_catalog.pg_get_constraintdef(constraint_object.oid)
    INTO widened
    FROM pg_catalog.pg_constraint AS constraint_object
    JOIN pg_catalog.pg_class AS relation_object
        ON relation_object.oid = constraint_object.conrelid
    JOIN pg_catalog.pg_namespace AS schema_object
        ON schema_object.oid = relation_object.relnamespace
    WHERE schema_object.nspname = 'public'
      AND relation_object.relname = 'memory_normative_log_v1'
      AND constraint_object.conname = 'memory_normative_log_kind_v2';

    SELECT count(*)
    INTO retired
    FROM pg_catalog.pg_constraint AS constraint_object
    JOIN pg_catalog.pg_class AS relation_object
        ON relation_object.oid = constraint_object.conrelid
    JOIN pg_catalog.pg_namespace AS schema_object
        ON schema_object.oid = relation_object.relnamespace
    WHERE schema_object.nspname = 'public'
      AND relation_object.relname = 'memory_normative_log_v1'
      AND constraint_object.conname = 'memory_normative_log_kind';

    IF widened IS DISTINCT FROM
           'CHECK ((record_kind IN (''lifecycle''::STRING, ''contest''::STRING, ''rebase''::STRING)))'
       OR retired <> 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'migration 0032 normative log kind constraint drift';
    END IF;
END
$$;
