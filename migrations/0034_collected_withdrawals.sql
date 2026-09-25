-- no-transaction
-- Collected withdrawals (ADR 0008 D5, D6). An audience that narrows hides what
-- the memory already admitted, and only a channel at least as trusted as the
-- one that narrowed it lifts that:
--
-- * memory_collector_containers_v1 gains observed_tier, the trust tier of the
--   observation that last set the row's access. An operator import (reported)
--   never re-opens or relabels a container a pull or a push (verified)
--   recorded or withdrew. NULL is a row written before this migration, and is
--   read as verified.
-- * Its audience check is widened so a container a collector found
--   inadmissible before anything was admitted through it (a Slack Connect
--   channel that agent captures reached under a capture scope) is recorded
--   withdrawn, with audience basis 'none': captures into it are then refused,
--   and what they admitted is withheld.
-- * memory_collected_item_withdrawals_v1 records an item whose own audience
--   narrowed (a Linear issue moved into a private team that is not listed):
--   per trust tier, whether it is withdrawn and the provider order of the
--   observation that last decided it. Evidence recall withholds every body of
--   a withdrawn item until an admissible observation at an order at least as
--   great, through a channel at least as trusted, lifts it.
--
-- Migrations 0001-0033 stay byte-identical. Each change commits on its own, so
-- every interruption point leaves an audience check in force and a rerun
-- resumes: ADD COLUMN, ADD CONSTRAINT, and CREATE TABLE are IF NOT EXISTS, and
-- the old audience check is dropped (IF EXISTS) only after the widened one is
-- committed. Until then both are in force and a 'none' row is refused. No
-- table has a foreign key, none is granted to the publication reader, and no
-- runtime deletes a row: a lifted withdrawal is updated, never removed.
--
-- Like migrations 0018 onward, this DDL runs outside SQLx's transaction
-- wrapper. SQLx sends the file as one implicit transaction, so each COMMIT
-- below ends one schema change before the next statement starts.

ALTER TABLE memory_collector_containers_v1 ADD COLUMN IF NOT EXISTS observed_tier STRING NULL;

COMMIT;

ALTER TABLE memory_collector_containers_v1
    ADD CONSTRAINT IF NOT EXISTS memory_collector_container_tier
        CHECK (observed_tier IS NULL OR observed_tier IN ('verified', 'reported'));

COMMIT;

ALTER TABLE memory_collector_containers_v1
    ADD CONSTRAINT IF NOT EXISTS memory_collector_container_audience_v2
        CHECK (audience_basis IN ('provider_public', 'team_public', 'operator_declared')
               OR (audience_basis = 'none' AND access = 'withdrawn'));

COMMIT;

ALTER TABLE memory_collector_containers_v1
    DROP CONSTRAINT IF EXISTS memory_collector_container_audience;

COMMIT;

CREATE TABLE IF NOT EXISTS memory_collected_item_withdrawals_v1 (
    tenant_id              UUID NOT NULL,
    project                STRING NOT NULL,
    item_key_digest        BYTES NOT NULL,
    observed_tier          STRING NOT NULL,
    withdrawn              BOOL NOT NULL,
    observed_order         INT8 NOT NULL,
    reason                 STRING NOT NULL,
    collection_mode        STRING NOT NULL,
    observed_by_instance   STRING NOT NULL,
    observed_at            TIMESTAMPTZ NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, item_key_digest, observed_tier),
    CONSTRAINT memory_collected_item_withdrawal_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_collected_item_withdrawal_shape
        CHECK (octet_length(item_key_digest) = 32 AND observed_order >= 0
               AND octet_length(observed_by_instance) BETWEEN 1 AND 128),
    CONSTRAINT memory_collected_item_withdrawal_tier
        CHECK (observed_tier IN ('verified', 'reported')),
    CONSTRAINT memory_collected_item_withdrawal_mode
        CHECK (collection_mode IN ('pull', 'push', 'import')),
    CONSTRAINT memory_collected_item_withdrawal_reason
        CHECK (reason IN ('direct_message', 'externally_shared', 'restricted_unlisted',
                          'audience_refused'))
);

COMMIT;

-- Fail closed on drift, as migrations 0032 and 0033 do: IF NOT EXISTS would
-- otherwise adopt a same-name column, constraint, or table of another
-- definition, and a rerun over a hand-edited catalog must not record success.
-- Require the exact committed column shapes, the exact widened and tier
-- constraints, and the absence of the old audience constraint; stop on 55000
-- otherwise.
DO $$
DECLARE
    drifted STRING;
    widened STRING;
    tiered STRING;
    retired INT8;
BEGIN
    SELECT string_agg(expected.relation_name, ', ' ORDER BY expected.relation_name)
    INTO drifted
    FROM (VALUES
        ('memory_collector_containers_v1',
            'tenant_id:uuid:NO,project:text:NO,container_key:bytea:NO,provider:text:NO,provider_scope_id:text:NO,container_kind:text:NO,container_id:text:NO,label:text:YES,audience_basis:text:NO,access:text:NO,observed_by_instance:text:NO,observed_at:timestamp with time zone:NO,updated_at:timestamp with time zone:NO,observed_tier:text:YES'),
        ('memory_collected_item_withdrawals_v1',
            'tenant_id:uuid:NO,project:text:NO,item_key_digest:bytea:NO,observed_tier:text:NO,withdrawn:boolean:NO,observed_order:bigint:NO,reason:text:NO,collection_mode:text:NO,observed_by_instance:text:NO,observed_at:timestamp with time zone:NO,updated_at:timestamp with time zone:NO')
    ) AS expected (relation_name, column_shape)
    WHERE expected.column_shape IS DISTINCT FROM (
        SELECT string_agg(column_object.column_name || ':' || column_object.data_type
                          || ':' || column_object.is_nullable, ',' ORDER BY column_object.ordinal_position)
        FROM information_schema.columns AS column_object
        WHERE column_object.table_schema = 'public' AND column_object.table_name = expected.relation_name
    );

    SELECT pg_catalog.pg_get_constraintdef(constraint_object.oid)
    INTO widened
    FROM pg_catalog.pg_constraint AS constraint_object
    JOIN pg_catalog.pg_class AS relation_object
        ON relation_object.oid = constraint_object.conrelid
    JOIN pg_catalog.pg_namespace AS schema_object
        ON schema_object.oid = relation_object.relnamespace
    WHERE schema_object.nspname = 'public'
      AND relation_object.relname = 'memory_collector_containers_v1'
      AND constraint_object.conname = 'memory_collector_container_audience_v2';

    SELECT pg_catalog.pg_get_constraintdef(constraint_object.oid)
    INTO tiered
    FROM pg_catalog.pg_constraint AS constraint_object
    JOIN pg_catalog.pg_class AS relation_object
        ON relation_object.oid = constraint_object.conrelid
    JOIN pg_catalog.pg_namespace AS schema_object
        ON schema_object.oid = relation_object.relnamespace
    WHERE schema_object.nspname = 'public'
      AND relation_object.relname = 'memory_collector_containers_v1'
      AND constraint_object.conname = 'memory_collector_container_tier';

    SELECT count(*)
    INTO retired
    FROM pg_catalog.pg_constraint AS constraint_object
    JOIN pg_catalog.pg_class AS relation_object
        ON relation_object.oid = constraint_object.conrelid
    JOIN pg_catalog.pg_namespace AS schema_object
        ON schema_object.oid = relation_object.relnamespace
    WHERE schema_object.nspname = 'public'
      AND relation_object.relname = 'memory_collector_containers_v1'
      AND constraint_object.conname = 'memory_collector_container_audience';

    IF drifted IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'migration 0034 same-name relation drift: ' || drifted;
    END IF;
    IF widened IS DISTINCT FROM
           'CHECK (((audience_basis IN (''provider_public''::STRING, ''team_public''::STRING, ''operator_declared''::STRING)) OR ((audience_basis = ''none''::STRING) AND (access = ''withdrawn''::STRING))))'
       OR tiered IS DISTINCT FROM
           'CHECK (((observed_tier IS NULL) OR (observed_tier IN (''verified''::STRING, ''reported''::STRING))))'
       OR retired <> 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'migration 0034 container constraint drift';
    END IF;
END
$$;
