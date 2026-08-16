-- no-transaction
-- Version conflict identity by detector so a corrected detector can preserve
-- legacy durable rows while opening its own lineage for the same claim key.
-- This is a resumable catalog-only transition: the only accepted entry states
-- are old-only, both, and new-only, and every present index must have the exact
-- expected CockroachDB 26.2 public-catalog shape. No conflict data is rewritten.

DO $$
DECLARE
    old_present BOOL;
    old_exact   BOOL;
    new_present BOOL;
    new_exact   BOOL;
BEGIN
    SELECT
        count(*) > 0,
        count(*) = 1 AND COALESCE(bool_and(indexdef = format(
            'CREATE UNIQUE INDEX memory_conflicts_tenant_id_project_claim_key_key ON %I.public.memory_conflicts USING btree (tenant_id ASC, project ASC, claim_key ASC)',
            current_database()
        )), false)
    INTO old_present, old_exact
    FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'memory_conflicts'
      AND indexname = 'memory_conflicts_tenant_id_project_claim_key_key';

    SELECT
        count(*) > 0,
        count(*) = 1 AND COALESCE(bool_and(indexdef = format(
            'CREATE UNIQUE INDEX memory_conflicts_scope_key_detector_unique_idx ON %I.public.memory_conflicts USING btree (tenant_id ASC, project ASC, claim_key ASC, detector ASC)',
            current_database()
        )), false)
    INTO new_present, new_exact
    FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'memory_conflicts'
      AND indexname = 'memory_conflicts_scope_key_detector_unique_idx';

    IF old_present AND NOT old_exact THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'memory_conflicts legacy unique index catalog shape mismatch';
    END IF;
    IF new_present AND NOT new_exact THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'memory_conflicts detector unique index catalog shape mismatch';
    END IF;
    IF NOT (
        (old_present AND old_exact AND NOT new_present)
        OR (old_present AND old_exact AND new_present AND new_exact)
        OR (NOT old_present AND new_present AND new_exact)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'memory_conflicts unique index transition state is invalid';
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS memory_conflicts_scope_key_detector_unique_idx
    ON memory_conflicts (tenant_id, project, claim_key, detector);

-- CockroachDB 26.2 schema-locks existing tables. Commit the online backfill
-- before proving its public-catalog shape and touching the legacy constraint.
COMMIT;

DO $$
DECLARE
    old_present BOOL;
    old_exact   BOOL;
    new_exact   BOOL;
BEGIN
    SELECT
        count(*) > 0,
        count(*) = 1 AND COALESCE(bool_and(indexdef = format(
            'CREATE UNIQUE INDEX memory_conflicts_tenant_id_project_claim_key_key ON %I.public.memory_conflicts USING btree (tenant_id ASC, project ASC, claim_key ASC)',
            current_database()
        )), false)
    INTO old_present, old_exact
    FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'memory_conflicts'
      AND indexname = 'memory_conflicts_tenant_id_project_claim_key_key';

    SELECT count(*) = 1 AND COALESCE(bool_and(indexdef = format(
        'CREATE UNIQUE INDEX memory_conflicts_scope_key_detector_unique_idx ON %I.public.memory_conflicts USING btree (tenant_id ASC, project ASC, claim_key ASC, detector ASC)',
        current_database()
    )), false)
    INTO new_exact
    FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'memory_conflicts'
      AND indexname = 'memory_conflicts_scope_key_detector_unique_idx';

    IF new_exact IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'memory_conflicts detector unique index catalog shape mismatch before legacy drop';
    END IF;
    IF old_present AND NOT old_exact THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'memory_conflicts legacy unique index catalog shape mismatch before legacy drop';
    END IF;
END
$$;

DROP INDEX IF EXISTS memory_conflicts@memory_conflicts_tenant_id_project_claim_key_key CASCADE;

-- The legacy UNIQUE constraint is backed by the dropped index, so CASCADE is
-- intentional. Commit that one destructive schema change before final proof.
COMMIT;

DO $$
DECLARE
    old_absent BOOL;
    new_exact  BOOL;
BEGIN
    SELECT count(*) = 0
    INTO old_absent
    FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'memory_conflicts'
      AND indexname = 'memory_conflicts_tenant_id_project_claim_key_key';

    SELECT count(*) = 1 AND COALESCE(bool_and(indexdef = format(
        'CREATE UNIQUE INDEX memory_conflicts_scope_key_detector_unique_idx ON %I.public.memory_conflicts USING btree (tenant_id ASC, project ASC, claim_key ASC, detector ASC)',
        current_database()
    )), false)
    INTO new_exact
    FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'memory_conflicts'
      AND indexname = 'memory_conflicts_scope_key_detector_unique_idx';

    IF old_absent IS DISTINCT FROM true OR new_exact IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'memory_conflicts detector unique index final catalog state mismatch';
    END IF;
END
$$;
