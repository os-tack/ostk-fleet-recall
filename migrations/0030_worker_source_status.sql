-- no-transaction
-- Worker source status (ADR 0006). One additive private-plane table. The
-- `ostk-fleet-recall worker` upserts one row per configured connector instance
-- per tick, so evidence recall can tell a source that failed, went stale, or
-- never reported from one that is current. Migrations 0001 through 0029 remain
-- byte-identical; version 25 remains the permanent gap.
--
-- Like migrations 0018 onward, this DDL runs outside SQLx's transaction
-- wrapper, so every object is created with IF NOT EXISTS and a process death
-- between the schema change and SQLx's history row is resumable.
--
-- The table carries no foreign key and is not one of the publication reader's
-- tables (PUBLIC-02/03). It is operational status, not evidence: a row says
-- when the worker last tried a source and what happened, never what the
-- source contains.

-- Ownership: fleet_migrator. One row per (tenant_id, project,
-- connector_instance_id). state is 'retired' for an instance the worker no
-- longer configures. last_attempt_at is the latest tick that tried the
-- source; last_checked_at is the latest tick that completed it ('ok' or
-- 'unchanged'), so a source that has never completed a check has NULL.
-- stale_after_seconds is how long a completed check stays current.
CREATE TABLE IF NOT EXISTS memory_worker_sources_v1 (
    tenant_id             UUID NOT NULL,
    project               STRING NOT NULL,
    connector_instance_id STRING NOT NULL,
    source_kind           STRING NOT NULL,
    state                 STRING NOT NULL,
    stale_after_seconds   INT8 NOT NULL,
    last_outcome          STRING NOT NULL,
    last_attempt_at       TIMESTAMPTZ NOT NULL,
    last_checked_at       TIMESTAMPTZ NULL,
    last_error            STRING NULL,
    updated_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, connector_instance_id),
    CONSTRAINT memory_worker_source_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_worker_source_instance_bound
        CHECK (octet_length(connector_instance_id) BETWEEN 1 AND 128),
    CONSTRAINT memory_worker_source_kind
        CHECK (source_kind IN ('git', 'transcript', 'ci')),
    CONSTRAINT memory_worker_source_state
        CHECK (state IN ('active', 'retired')),
    CONSTRAINT memory_worker_source_outcome
        CHECK (last_outcome IN ('ok', 'unchanged', 'failed')),
    CONSTRAINT memory_worker_source_stale_bound
        CHECK (stale_after_seconds BETWEEN 60 AND 31536000),
    CONSTRAINT memory_worker_source_error_bound
        CHECK (last_error IS NULL OR octet_length(last_error) <= 2048)
);

-- SQLx sends a multi-statement migration as one implicit transaction, and
-- this migration is registered no_tx, so there is no enclosing application
-- transaction. Commit the schema change before inspecting the public catalog.
COMMIT;

-- Fail closed on same-name relation drift, as migrations 0018, 0020, 0024,
-- 0027 and 0029 do: IF NOT EXISTS would otherwise adopt an unrelated object
-- that merely shares the name. Pin the exact committed column shape and stop
-- on 55000 if it is not what this migration defines.
DO $$
DECLARE
    drifted STRING;
BEGIN
    SELECT string_agg(expected.relation_name, ', ' ORDER BY expected.relation_name)
    INTO drifted
    FROM (VALUES
        ('memory_worker_sources_v1',
            'tenant_id:uuid:NO,project:text:NO,connector_instance_id:text:NO,source_kind:text:NO,state:text:NO,stale_after_seconds:bigint:NO,last_outcome:text:NO,last_attempt_at:timestamp with time zone:NO,last_checked_at:timestamp with time zone:YES,last_error:text:YES,updated_at:timestamp with time zone:NO')
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
            MESSAGE = 'migration 0030 same-name relation drift: ' || drifted;
    END IF;
END
$$;
