-- no-transaction
-- ADR 0009: durable delegation rows precede signed tokens. The grant binds the
-- enrollment revision so a changed policy cannot retain previous authority.
-- No FK: runtime can reference the enrollment table without extra privileges.
CREATE TABLE IF NOT EXISTS memory_session_grants_v1 (
    jti UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind STRING NOT NULL,
    principal_id UUID NOT NULL,
    principal_revision INT8 NOT NULL,
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    agent STRING NOT NULL,
    ceiling STRING NOT NULL,
    sandbox_id STRING NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    revoked_by UUID NULL,
    CONSTRAINT memory_session_grant_kind CHECK (kind IN ('agent', 'shipper')),
    CONSTRAINT memory_session_grant_ceiling CHECK (ceiling IN ('private', 'project', 'trusted', 'public')),
    CONSTRAINT memory_session_grant_shape CHECK (
        principal_revision > 0
        AND octet_length(project) BETWEEN 1 AND 256
        AND octet_length(agent) BETWEEN 1 AND 256
        AND (sandbox_id IS NULL OR octet_length(sandbox_id) BETWEEN 1 AND 256)
        AND expires_at > issued_at
        AND expires_at <= issued_at + INTERVAL '24 hours'
        AND ((revoked_at IS NULL) = (revoked_by IS NULL))
    )
);
CREATE INDEX IF NOT EXISTS memory_session_grants_principal_idx ON memory_session_grants_v1 (principal_id, expires_at);
COMMIT;

DO $$
DECLARE drifted BOOL;
BEGIN
    SELECT 'jti:uuid:NO,kind:text:NO,principal_id:uuid:NO,principal_revision:bigint:NO,tenant_id:uuid:NO,project:text:NO,agent:text:NO,ceiling:text:NO,sandbox_id:text:YES,issued_at:timestamp with time zone:NO,expires_at:timestamp with time zone:NO,revoked_at:timestamp with time zone:YES,revoked_by:uuid:YES'
        IS DISTINCT FROM string_agg(column_name || ':' || data_type || ':' || is_nullable, ',' ORDER BY ordinal_position)
    INTO drifted FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'memory_session_grants_v1';
    IF drifted THEN RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'migration 0039 session grants column drift'; END IF;
END
$$;

-- Require the exact CHECK and primary-key definitions, not just their names.
DO $$
DECLARE drifted BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM (VALUES
            ('memory_session_grant_ceiling', 'CHECK ((ceiling IN (''private''::STRING, ''project''::STRING, ''trusted''::STRING, ''public''::STRING)))'),
            ('memory_session_grant_kind', 'CHECK ((kind IN (''agent''::STRING, ''shipper''::STRING)))'),
            ('memory_session_grant_shape', 'CHECK ((((((((principal_revision > 0) AND (octet_length(project) BETWEEN 1 AND 256)) AND (octet_length(agent) BETWEEN 1 AND 256)) AND ((sandbox_id IS NULL) OR (octet_length(sandbox_id) BETWEEN 1 AND 256))) AND (expires_at > issued_at)) AND (expires_at <= (issued_at + ''24:00:00''::INTERVAL))) AND ((revoked_at IS NULL) = (revoked_by IS NULL))))'),
            ('memory_session_grants_v1_pkey', 'PRIMARY KEY (jti ASC)')
        ) AS expected(name, definition)
        FULL JOIN (
            SELECT c.conname, pg_catalog.pg_get_constraintdef(c.oid) AS definition
            FROM pg_catalog.pg_constraint AS c
            JOIN pg_catalog.pg_class AS r ON r.oid = c.conrelid
            JOIN pg_catalog.pg_namespace AS n ON n.oid = r.relnamespace
            WHERE n.nspname = 'public' AND r.relname = 'memory_session_grants_v1'
        ) AS actual ON actual.conname = expected.name
        WHERE actual.definition IS DISTINCT FROM expected.definition
    ) INTO drifted;
    IF drifted THEN RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'migration 0039 constraint drift'; END IF;
END
$$;

DO $$
DECLARE actual STRING;
BEGIN
    SELECT indexdef INTO actual FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public' AND tablename = 'memory_session_grants_v1' AND indexname = 'memory_session_grants_principal_idx';
    IF actual IS DISTINCT FROM format('CREATE INDEX memory_session_grants_principal_idx ON %I.public.memory_session_grants_v1 USING btree (principal_id ASC, expires_at ASC)', pg_catalog.current_database()) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'migration 0039 lookup index drift';
    END IF;
END
$$;
