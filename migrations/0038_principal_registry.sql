-- no-transaction
-- ADR 0009: enrollment is the sole writer of identity authorization bindings.
-- Runtime may SELECT; publication and provider ingress receive no privileges.
-- No uniqueness constraint hides ambiguity: the resolver denies tied matches.
CREATE TABLE IF NOT EXISTS memory_principals_v1 (
    principal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    anchor_id STRING NOT NULL,
    subject_pattern STRING NOT NULL,
    role STRING NOT NULL,
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    ceiling STRING NOT NULL,
    agent_pattern STRING NOT NULL,
    enrolled_at TIMESTAMPTZ NOT NULL,
    revised_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    source_digest BYTES NOT NULL,
    revision INT8 NOT NULL,
    CONSTRAINT memory_principal_role CHECK (role IN ('operator', 'launcher', 'shipper')),
    CONSTRAINT memory_principal_ceiling CHECK (ceiling IN ('private', 'project', 'trusted', 'public')),
    CONSTRAINT memory_principal_shape CHECK (
        octet_length(anchor_id) BETWEEN 1 AND 128
        AND octet_length(subject_pattern) BETWEEN 1 AND 1024
        AND octet_length(project) BETWEEN 1 AND 256
        AND octet_length(agent_pattern) BETWEEN 1 AND 256
        AND octet_length(source_digest) = 32
        AND revision > 0
    )
);
CREATE INDEX IF NOT EXISTS memory_principals_anchor_idx ON memory_principals_v1 (anchor_id, subject_pattern);
COMMIT;

DO $$
DECLARE drifted BOOL;
BEGIN
    SELECT 'principal_id:uuid:NO,anchor_id:text:NO,subject_pattern:text:NO,role:text:NO,tenant_id:uuid:NO,project:text:NO,ceiling:text:NO,agent_pattern:text:NO,enrolled_at:timestamp with time zone:NO,revised_at:timestamp with time zone:NO,revoked_at:timestamp with time zone:YES,source_digest:bytea:NO,revision:bigint:NO'
        IS DISTINCT FROM string_agg(column_name || ':' || data_type || ':' || is_nullable, ',' ORDER BY ordinal_position)
    INTO drifted FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'memory_principals_v1';
    IF drifted THEN RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'migration 0038 principal registry column drift'; END IF;
END
$$;

-- Require the exact CHECK and primary-key definitions, not just their names.
DO $$
DECLARE drifted BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM (VALUES
            ('memory_principal_ceiling', 'CHECK ((ceiling IN (''private''::STRING, ''project''::STRING, ''trusted''::STRING, ''public''::STRING)))'),
            ('memory_principal_role', 'CHECK (("role" IN (''operator''::STRING, ''launcher''::STRING, ''shipper''::STRING)))'),
            ('memory_principal_shape', 'CHECK (((((((octet_length(anchor_id) BETWEEN 1 AND 128) AND (octet_length(subject_pattern) BETWEEN 1 AND 1024)) AND (octet_length(project) BETWEEN 1 AND 256)) AND (octet_length(agent_pattern) BETWEEN 1 AND 256)) AND (octet_length(source_digest) = 32)) AND (revision > 0)))'),
            ('memory_principals_v1_pkey', 'PRIMARY KEY (principal_id ASC)')
        ) AS expected(name, definition)
        FULL JOIN (
            SELECT c.conname, pg_catalog.pg_get_constraintdef(c.oid) AS definition
            FROM pg_catalog.pg_constraint AS c
            JOIN pg_catalog.pg_class AS r ON r.oid = c.conrelid
            JOIN pg_catalog.pg_namespace AS n ON n.oid = r.relnamespace
            WHERE n.nspname = 'public' AND r.relname = 'memory_principals_v1'
        ) AS actual ON actual.conname = expected.name
        WHERE actual.definition IS DISTINCT FROM expected.definition
    ) INTO drifted;
    IF drifted THEN RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'migration 0038 constraint drift'; END IF;
END
$$;

DO $$
DECLARE actual STRING;
BEGIN
    SELECT indexdef INTO actual FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public' AND tablename = 'memory_principals_v1' AND indexname = 'memory_principals_anchor_idx';
    IF actual IS DISTINCT FROM format('CREATE INDEX memory_principals_anchor_idx ON %I.public.memory_principals_v1 USING btree (anchor_id ASC, subject_pattern ASC)', pg_catalog.current_database()) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'migration 0038 lookup index drift';
    END IF;
END
$$;
