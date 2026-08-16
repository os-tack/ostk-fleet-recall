-- Long-lived runtime-writer role boundary for the dedicated fleet_recall
-- database.
--
-- Run only after the complete successful migration prefix 1 through 17. Later
-- successful migrations are compatible and cannot mask a missing or failed row
-- in that bounded prefix. Run only as a cluster admin; database ownership alone
-- is insufficient. This policy is independent of the private control,
-- activation, successor, and reconciliation ceremonies and neither requires nor
-- creates their roles.
--
-- The exact application principal fleet_writer, including its password or
-- identity-provider binding, is provisioned outside this file. Before every
-- apply or reapply, drain its existing sessions and set its role options to the
-- exact quiesced state {NOLOGIN}. This policy never changes that principal's
-- authentication material or options. It requires the principal to have no
-- direct/system/default/ownership authority and no role edge except the one
-- exact non-admin membership installed below.
-- Before applying, the cluster admin must also establish the PUBLIC
-- future-default baseline by revoking routine EXECUTE from every non-target
-- existing role. A clean v26.2.3 descriptor synthesizes one exact non-grantable
-- FOR ALL ROLES routine-EXECUTE row after an attempted revoke; that narrow
-- engine baseline is admitted below.
--
-- Object-grant and ownership enforcement in this file is intentionally local
-- to fleet_recall. Before every apply and use, the cluster admin must enumerate
-- every other database and application schema, reject and revoke every direct
-- grant, ownership, or future default held there by fleet_runtime or
-- fleet_writer, and separately inventory current and future inherited
-- PUBLIC authority. Other databases may intentionally retain PUBLIC CONNECT,
-- TEMPORARY, and schema USAGE; exclusive database confinement requires a
-- separate cluster-wide PUBLIC policy. CockroachDB v26.2 cannot construct the
-- required cross-database revocations dynamically inside this static SQL file.
-- The external audit and this policy are multi-statement snapshots, not locks:
-- freeze role/grant/default/ownership and schema-DDL changes from audit start
-- through policy completion and member re-enable, or repeat the full external
-- audit immediately before re-enable under that same change freeze.
--
-- CockroachDB v26.2 does not support delegated SHOW statements inside a
-- PL/pgSQL function body (including DO). Gates that consume SHOW therefore
-- remain top-level statements and use a short-circuited, runtime-derived cast
-- failure. Their stable message substrings are contractual; Cockroach reports
-- SQLSTATE 22P02 for the deliberately invalid cast. Catalog-only DO gates keep
-- their explicit SQLSTATE 55000.

-- Pin built-in resolution and keep the temporary schema last. Naming pg_temp
-- explicitly disables its usual implicit-first search behavior in v26.2.3;
-- every application relation below is also fully qualified.
SET search_path = pg_catalog, public, pg_temp;

-- Bind every later current-database catalog, SHOW, default-privilege, and
-- object-reset statement to fleet_recall before the prefix block is compiled.
-- This must remain a separate block: CockroachDB compiles relation references
-- elsewhere in a PL/pgSQL block before executing an earlier IF branch.
DO $$
BEGIN
    IF pg_catalog.current_database() <> 'fleet_recall' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime writer policy must run in fleet_recall';
    END IF;
END
$$;

-- Fail closed before role creation, option changes, revocations, or grants. A
-- missing or failed prerequisite cannot be masked by a later successful row.
DO $$
DECLARE
    runtime_schema_ready BOOL;
BEGIN
    SELECT count(*) = 17
       AND min(version) = 1
       AND max(version) = 17
       AND COALESCE(bool_and(success), false)
    INTO runtime_schema_ready
    FROM public._sqlx_migrations
    WHERE version BETWEEN 1 AND 17;

    IF runtime_schema_ready IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime writer role requires the complete successful migration prefix through 17';
    END IF;
END
$$;

-- The deployment principal is fixed rather than discovered from an arbitrary
-- inbound edge. It must already exist and be quiesced before any target-role
-- creation or privilege mutation. Password hashes are not exposed by SHOW
-- USERS and identity-provider material is intentionally outside this policy;
-- exact NOLOGIN is the policy's portable authentication deny.
SELECT IF(
    count(*) = 1
        AND COALESCE(bool_and(options::STRING = '{NOLOGIN}'), false),
    1:::INT8,
    CAST(
        concat(
            'runtime writer policy requires exact quiesced principal fleet_writer with options {NOLOGIN}: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_principal_gate
FROM [SHOW USERS]
WHERE username = 'fleet_writer';

-- A current-object reset cannot repair future-object grants for arbitrary
-- grantors. This dedicated database admits no application schema besides
-- public, which lets the policy cover schema-scoped defaults with supported
-- SHOW statements. Temporary session schemas are harmless and may be present.
DO $$
DECLARE
    forbidden_application_schema BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace
        WHERE nspname NOT IN (
            'public',
            'pg_catalog',
            'information_schema',
            'crdb_internal',
            'pg_extension'
        )
          AND nspname NOT LIKE 'pg_temp_%'
    ) INTO forbidden_application_schema;

    IF forbidden_application_schema THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime writer policy requires public to be the only application schema';
    END IF;
END
$$;

-- Inspect PUBLIC explicitly across every grantor before target-role creation,
-- at both database and public-schema scope. CockroachDB release-26.2
-- synthesizes non-grantable PUBLIC EXECUTE-on-routines and USAGE-on-types rows
-- for each role, plus their FOR ALL ROLES baselines. Admit only intrinsic type
-- USAGE, the exact clean-engine all-roles routine row, and this target role's
-- exact creator-scoped routine row. Every other future PUBLIC grant fails
-- closed. The admitted routine rows remain inert only while member credentials
-- are quiesced and no current PUBLIC function grant survives the object-grant
-- boundary below.
WITH public_default AS (
    SELECT role, for_all_roles, object_type, grantee, privilege_type,
           is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type,
           is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
), forbidden_public_default AS (
    SELECT 1
    FROM public_default
    WHERE public_default.object_type IN (
            'schemas', 'routines', 'tables', 'sequences', 'types'
    )
      AND (
          public_default.grantee = 'public'
          AND NOT public_default.is_grantable
          AND public_default.object_type = 'types'
          AND public_default.privilege_type = 'USAGE'
      ) IS NOT TRUE
      AND (
          public_default.role IS NULL
          AND public_default.for_all_roles
          AND public_default.grantee = 'public'
          AND public_default.object_type = 'routines'
          AND public_default.privilege_type = 'EXECUTE'
          AND NOT public_default.is_grantable
      ) IS NOT TRUE
      AND (
          public_default.role = 'fleet_runtime'
          AND NOT public_default.for_all_roles
          AND public_default.grantee = 'public'
          AND public_default.object_type = 'routines'
          AND public_default.privilege_type = 'EXECUTE'
          AND NOT public_default.is_grantable
      ) IS NOT TRUE
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime writer policy permits only intrinsic PUBLIC type USAGE, all-roles routine EXECUTE, and target PUBLIC routine EXECUTE defaults: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_public_default_gate
FROM forbidden_public_default;

-- A current-object reset cannot repair future authority granted to the fixed
-- principal. Admit only CockroachDB's exact self-owner default rows; because
-- the principal has no CREATE or ownership authority, those intrinsic rows are
-- inert. Every grantor-to-principal future grant must be removed externally.
WITH principal_default AS (
    SELECT role, for_all_roles, object_type, grantee, privilege_type,
           is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_writer]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type,
           is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_writer
          IN SCHEMA public]
), forbidden_principal_default AS (
    SELECT 1
    FROM principal_default
    WHERE principal_default.object_type IN (
            'schemas', 'routines', 'tables', 'sequences', 'types'
    )
      AND (
          principal_default.role = 'fleet_writer'
          AND NOT principal_default.for_all_roles
          AND principal_default.grantee = 'fleet_writer'
          AND principal_default.privilege_type = 'ALL'
          AND principal_default.is_grantable
      ) IS NOT TRUE
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime writer principal has non-intrinsic future-default authority: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_principal_default_gate
FROM forbidden_principal_default;

-- Every role implicitly inherits PUBLIC. Neither PUBLIC nor the fixed
-- principal may carry a cluster-global system grant before target creation.
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime writer policy requires PUBLIC to have no system privileges: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_public_system_gate
FROM [SHOW SYSTEM GRANTS]
WHERE grantee = 'public';

SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime writer principal must have no system privileges: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_principal_system_gate
FROM [SHOW SYSTEM GRANTS]
WHERE grantee = 'fleet_writer';

-- The fixed principal must not own any supported current-database object.
-- Ownership in other databases is part of the mandatory external preflight.
DO $$
DECLARE
    runtime_writer_owns_object BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_database AS database_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = database_object.datdba
        WHERE database_object.datname = 'fleet_recall'
          AND owner_role.rolname = 'fleet_writer'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_namespace AS schema_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = schema_object.nspowner
        WHERE owner_role.rolname = 'fleet_writer'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_class AS relation_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = relation_object.relowner
        WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
          AND owner_role.rolname = 'fleet_writer'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_proc AS function_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = function_object.proowner
        WHERE owner_role.rolname = 'fleet_writer'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_type AS type_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = type_object.typowner
        WHERE owner_role.rolname = 'fleet_writer'
    ) INTO runtime_writer_owns_object;

    IF runtime_writer_owns_object THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime writer principal must not own database, schema, relation, function, or type objects';
    END IF;
END
$$;

-- Reject every PUBLIC grant that the later local reset cannot repair before
-- target creation. This includes current function/type authority, non-public
-- objects, and cluster-global external connections. Exact built-in
-- virtual/temporary fallback shapes are admitted narrowly.
WITH forbidden_public_grant AS (
    SELECT 1
    FROM [SHOW GRANTS FOR public]
    WHERE grantee = 'public'
      AND (
          object_type = 'external_connection'
          OR (
              database_name = 'fleet_recall'
              AND NOT (
                  object_type = 'database'
                  OR (object_type = 'schema'
                      AND schema_name = 'public')
                  OR (object_type IN ('table', 'sequence')
                      AND schema_name = 'public')
                  OR (
                      object_type = 'schema'
                      AND schema_name LIKE 'pg_temp_%'
                      AND object_name IS NULL
                      AND privilege_type IN ('CREATE', 'USAGE')
                      AND NOT is_grantable
                  )
                  OR (
                      schema_name IN (
                          'crdb_internal',
                          'information_schema',
                          'pg_catalog',
                          'pg_extension'
                      )
                      AND NOT is_grantable
                      AND (
                          (object_type = 'schema'
                              AND object_name IS NULL
                              AND privilege_type = 'USAGE')
                          OR (object_type = 'table'
                              AND object_name IS NOT NULL
                              AND privilege_type = 'SELECT')
                          OR (object_type = 'type'
                              AND schema_name = 'pg_catalog'
                              AND object_name IS NOT NULL
                              AND privilege_type = 'USAGE')
                      )
                  )
              )
          )
      )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime writer policy found an unsafe PUBLIC grant before target creation: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_public_grant_gate
FROM forbidden_public_grant;

-- The fixed principal receives authority only through the logical runtime role.
-- Any direct current-database or cluster-global external-connection grant must
-- be removed externally rather than silently normalized.
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime writer principal must have no direct object grants: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_principal_grant_gate
FROM [SHOW GRANTS FOR fleet_writer]
WHERE grantee = 'fleet_writer';

-- Before creation or reapplication, neither role may participate in any role
-- graph except the already-installed exact non-admin runtime-to-writer edge.
-- Checking every incident edge makes the principal a leaf and blocks mixed or
-- transitive authority in either direction.
WITH forbidden_incident_edge AS (
    SELECT 1
    FROM [SHOW GRANTS ON ROLE] AS edge
    WHERE (
        edge.role_name IN ('fleet_runtime', 'fleet_writer')
        OR edge.member IN ('fleet_runtime', 'fleet_writer')
    )
      AND NOT (
          edge.role_name = 'fleet_runtime'
          AND edge.member = 'fleet_writer'
          AND NOT edge.is_admin
      )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime writer/principal role graph is not an exact leaf edge: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_principal_edge_gate
FROM forbidden_incident_edge;

CREATE ROLE IF NOT EXISTS fleet_runtime;

-- A named FOR GRANTEE lookup requires the target role to exist. Reject its
-- future-object defaults before changing any role option, membership, system
-- privilege, or object grant. Exact role=self/grantee=self grantable ALL rows
-- merely restate owner authority; ownership is rejected separately below.
WITH runtime_default AS (
    SELECT role, for_all_roles, object_type, grantee, privilege_type,
           is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_runtime]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type,
           is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_runtime
          IN SCHEMA public]
), forbidden_runtime_default AS (
    SELECT 1
    FROM runtime_default
    WHERE runtime_default.object_type IN (
            'schemas', 'routines', 'tables', 'sequences', 'types'
    )
      AND (
          runtime_default.role = 'fleet_runtime'
          AND NOT runtime_default.for_all_roles
          AND runtime_default.grantee = 'fleet_runtime'
          AND runtime_default.privilege_type = 'ALL'
          AND runtime_default.is_grantable
      ) IS NOT TRUE
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime role has non-intrinsic future-default authority: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_target_default_gate
FROM forbidden_runtime_default;

-- Ownership is implicit authority that REVOKE cannot remove. Refuse to
-- normalize a role that owns fleet_recall, any schema/relation visible in the
-- current database, or any supported function/type in the current database.
-- Ownership in every other database is part of the external admin preflight.
DO $$
DECLARE
    runtime_writer_owns_object BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_database AS database_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = database_object.datdba
        WHERE database_object.datname = 'fleet_recall'
          AND owner_role.rolname = 'fleet_runtime'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_namespace AS schema_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = schema_object.nspowner
        WHERE owner_role.rolname = 'fleet_runtime'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_class AS relation_object
        JOIN pg_catalog.pg_namespace AS relation_schema
          ON relation_schema.oid = relation_object.relnamespace
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = relation_object.relowner
        WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
          AND owner_role.rolname = 'fleet_runtime'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_proc AS function_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = function_object.proowner
        WHERE owner_role.rolname = 'fleet_runtime'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_type AS type_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = type_object.typowner
        WHERE owner_role.rolname = 'fleet_runtime'
    ) INTO runtime_writer_owns_object;

    IF runtime_writer_owns_object THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'runtime writer role must not own database, schema, relation, function, or type objects';
    END IF;
END
$$;

-- The reset below can repair arbitrary direct fleet_recall database,
-- public-schema, public-table, and public-sequence grants on the logical role.
-- Fail closed before changing it if any other direct grant is visible,
-- including a function, type, non-public object, or external connection. PUBLIC
-- and fixed-principal boundary checks already ran before target creation.
WITH forbidden_target_grant AS (
    SELECT 1
    FROM [SHOW GRANTS FOR fleet_runtime]
    WHERE grantee = 'fleet_runtime'
      AND NOT (
        (object_type = 'database'
            AND database_name = 'fleet_recall')
        OR (object_type = 'schema'
            AND database_name = 'fleet_recall'
            AND schema_name = 'public')
        OR (object_type IN ('table', 'sequence')
            AND database_name = 'fleet_recall'
            AND schema_name = 'public')
    )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime writer policy found a grant outside the repairable fleet_recall.public boundary: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_out_of_boundary_grant_gate
FROM forbidden_target_grant;

-- Reassert the exact incident-edge graph now that the target exists. A missing
-- expected edge is repairable below; every different inbound, outbound, mixed,
-- or transitive shape fails before role-option normalization.
WITH unexpected_role_edge AS (
    SELECT 1
    FROM [SHOW GRANTS ON ROLE] AS edge
    WHERE (
        edge.role_name IN ('fleet_runtime', 'fleet_writer')
        OR edge.member IN ('fleet_runtime', 'fleet_writer')
    )
      AND NOT (
          edge.role_name = 'fleet_runtime'
          AND edge.member = 'fleet_writer'
          AND NOT edge.is_admin
      )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime writer/principal role graph is not an exact leaf edge: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_unexpected_role_edge_gate
FROM unexpected_role_edge;

-- VALID UNTIL and identity-provider SUBJECT/PROVISIONSRC options are not part
-- of this logical role contract. PROVISIONSRC cannot be removed by SQL; refuse
-- all three before mutation so the operator can replace an incorrectly
-- provisioned identity. Password hashes are not exposed by SHOW USERS. Exact
-- NOLOGIN below is the portable all-authentication-method deny.
WITH forbidden_identity_option AS (
    SELECT 1
    FROM [SHOW USERS] AS target_role
    CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
    WHERE target_role.username = 'fleet_runtime'
      AND (
          role_option.option_name LIKE 'VALID UNTIL=%'
          OR role_option.option_name LIKE 'PROVISIONSRC=%'
          OR role_option.option_name LIKE 'SUBJECT=%'
      )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime writer role has a forbidden validity or provisioned-identity option: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_identity_option_gate
FROM forbidden_identity_option;

-- This is a logical privilege bundle, never a login identity. Clear the full
-- CockroachDB v26.2 direct option and system-privilege surface. Every incident
-- role edge except the exact fixed membership was rejected above.
ALTER ROLE fleet_runtime WITH
    NOBYPASSRLS
    NOCANCELQUERY
    NOCONTROLCHANGEFEED
    NOCONTROLJOB
    NOCREATEDB
    NOCREATELOGIN
    NOCREATEROLE
    NOLOGIN
    NOMODIFYCLUSTERSETTING
    NOREPLICATION
    SQLLOGIN
    NOVIEWACTIVITY
    NOVIEWACTIVITYREDACTED
    NOVIEWCLUSTERSETTING;
REVOKE SYSTEM ALL FROM fleet_runtime;

SELECT IF(
    count(*) = 1
        AND COALESCE(bool_and(options::STRING = '{NOLOGIN}'), false),
    1:::INT8,
    CAST(
        concat(
            'runtime writer role options differ from exact NOLOGIN: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_exact_role_option_postcondition
FROM [SHOW USERS]
WHERE username = 'fleet_runtime';

-- Reassert the exact leaf graph after logical-role option normalization.
WITH forbidden_role_edge AS (
    SELECT 1
    FROM [SHOW GRANTS ON ROLE] AS edge
    WHERE (
        edge.role_name IN ('fleet_runtime', 'fleet_writer')
        OR edge.member IN ('fleet_runtime', 'fleet_writer')
    )
      AND NOT (
          edge.role_name = 'fleet_runtime'
          AND edge.member = 'fleet_writer'
          AND NOT edge.is_admin
      )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime writer role inheritance postcondition failed: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_role_edge_postcondition
FROM forbidden_role_edge;

-- Reassert the dedicated-database PUBLIC boundary, remove DDL authority, and
-- reset every direct current-object privilege and grant option on the runtime
-- role.
-- Future migrations must reapply this policy after creating new objects; no
-- default or future-object grant is installed.
REVOKE ALL ON DATABASE fleet_recall
    FROM public, fleet_runtime;
REVOKE ALL ON SCHEMA public
    FROM public, fleet_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM public;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM public;
REVOKE ALL ON ALL TABLES IN SCHEMA public
    FROM fleet_runtime;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public
    FROM fleet_runtime;

GRANT CONNECT ON DATABASE fleet_recall TO fleet_runtime;
GRANT USAGE ON SCHEMA public TO fleet_runtime;

-- Exact production health + ingest + writer serve/reference/MCP surface. This
-- is intentionally narrower than every method compiled into the reusable Rust
-- libraries: current production commands cannot emit stale chunks, so history
-- receives only the DELETE needed by the active upsert branch plus the SELECT
-- that CockroachDB requires to evaluate that DELETE's keyed WHERE clause;
-- memory_chunks itself receives no DELETE. Migration, reconciliation-private,
-- activation, and successor CLIs are separate ceremonies. The three
-- parent-table SELECT grants also make the nullable receipt foreign keys
-- enforceable on CockroachDB v26.2.3.
GRANT SELECT ON TABLE
    public._sqlx_migrations,
    public.memory_corpus_models,
    public.memory_chunks,
    public.memory_chunk_history,
    public.memory_claims,
    public.memory_claim_embeddings,
    public.memory_claim_support,
    public.memory_conflict_members,
    public.memory_conflicts,
    public.memory_claim_links,
    public.memory_mutation_receipts
TO fleet_runtime;

GRANT INSERT ON TABLE
    public.memory_corpus_models,
    public.memory_chunks,
    public.memory_claims,
    public.memory_claim_embeddings,
    public.memory_claim_support,
    public.memory_claim_events,
    public.memory_conflict_members,
    public.memory_conflicts,
    public.memory_mutation_receipts,
    public.memory_events
TO fleet_runtime;

GRANT UPDATE ON TABLE
    public.memory_chunks,
    public.memory_claims,
    public.memory_conflicts,
    public.memory_mutation_receipts
TO fleet_runtime;

GRANT DELETE ON TABLE public.memory_chunk_history TO fleet_runtime;

GRANT USAGE ON SEQUENCE
    public.memory_claim_id_seq,
    public.memory_claim_support_id_seq,
    public.memory_conflict_id_seq
TO fleet_runtime;

-- Install the sole permitted role edge only after every fail-closed gate and
-- exact logical-role grant have succeeded. The fixed principal remains
-- NOLOGIN; enabling its externally managed authentication is a separate,
-- post-audit deployment action.
GRANT fleet_runtime TO fleet_writer;

-- Exact direct logical-role surface: database CONNECT, public-schema USAGE,
-- twenty-six table-privilege rows, and three sequence-USAGE rows. Because
-- SHOW GRANTS FOR also exposes cluster-global external connections, the exact
-- count rejects those and every function/type/differently privileged row.
SELECT IF(
    count(*) = 31
        AND COALESCE(bool_and(
            NOT is_grantable
            AND (
                (object_type = 'database'
                    AND database_name = 'fleet_recall'
                    AND privilege_type = 'CONNECT')
                OR (object_type = 'schema'
                    AND database_name = 'fleet_recall'
                    AND schema_name = 'public'
                    AND privilege_type = 'USAGE')
                OR (object_type = 'table'
                    AND database_name = 'fleet_recall'
                    AND schema_name = 'public'
                    AND (
                        (privilege_type = 'SELECT'
                            AND object_name IN (
                                '_sqlx_migrations',
                                'memory_corpus_models',
                                'memory_chunks',
                                'memory_chunk_history',
                                'memory_claims',
                                'memory_claim_support',
                                'memory_claim_embeddings',
                                'memory_conflicts',
                                'memory_conflict_members',
                                'memory_claim_links',
                                'memory_mutation_receipts'
                            ))
                        OR (privilege_type = 'INSERT'
                            AND object_name IN (
                                'memory_corpus_models',
                                'memory_chunks',
                                'memory_claims',
                                'memory_claim_support',
                                'memory_claim_embeddings',
                                'memory_claim_events',
                                'memory_conflicts',
                                'memory_conflict_members',
                                'memory_mutation_receipts',
                                'memory_events'
                            ))
                        OR (privilege_type = 'UPDATE'
                            AND object_name IN (
                                'memory_chunks',
                                'memory_claims',
                                'memory_conflicts',
                                'memory_mutation_receipts'
                            ))
                        OR (privilege_type = 'DELETE'
                            AND object_name = 'memory_chunk_history')
                    ))
                OR (object_type = 'sequence'
                    AND database_name = 'fleet_recall'
                    AND schema_name = 'public'
                    AND object_name IN (
                        'memory_claim_id_seq',
                        'memory_claim_support_id_seq',
                        'memory_conflict_id_seq'
                    )
                    AND privilege_type = 'USAGE')
            )
        ), false),
    1:::INT8,
    CAST(
        concat(
            'runtime writer direct-grant postcondition differs from exact thirty-one-row matrix: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_exact_grant_postcondition
FROM [SHOW GRANTS FOR fleet_runtime]
WHERE grantee = 'fleet_runtime';

SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime writer principal direct-grant postcondition is nonzero: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_principal_grant_postcondition
FROM [SHOW GRANTS FOR fleet_writer]
WHERE grantee = 'fleet_writer';

SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime writer/PUBLIC/principal system-grant postcondition is nonzero: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_system_postcondition
FROM [SHOW SYSTEM GRANTS]
WHERE grantee IN (
    'public', 'fleet_runtime', 'fleet_writer'
);

SELECT IF(
    count(*) = 2
        AND COALESCE(bool_and(
            (username = 'fleet_runtime'
                AND options::STRING = '{NOLOGIN}')
            OR (username = 'fleet_writer'
                AND options::STRING = '{NOLOGIN}')
        ), false),
    1:::INT8,
    CAST(
        concat(
            'runtime writer/principal option postcondition differs from exact NOLOGIN: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_principal_option_postcondition
FROM [SHOW USERS]
WHERE username IN ('fleet_runtime', 'fleet_writer');

SELECT IF(
    count(*) = 1
        AND COALESCE(bool_and(
            role_name = 'fleet_runtime'
            AND member = 'fleet_writer'
            AND NOT is_admin
        ), false),
    1:::INT8,
    CAST(
        concat(
            'runtime writer/principal edge postcondition differs from exact non-admin leaf edge: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_principal_edge_postcondition
FROM [SHOW GRANTS ON ROLE]
WHERE role_name IN ('fleet_runtime', 'fleet_writer')
   OR member IN ('fleet_runtime', 'fleet_writer');

-- PUBLIC must retain no current application or external-connection authority.
-- Only exact built-in virtual/temporary fallback rows remain admissible.
WITH forbidden_final_public_grant AS (
    SELECT 1
    FROM [SHOW GRANTS FOR public]
    WHERE grantee = 'public'
      AND (
          object_type = 'external_connection'
          OR (
              database_name = 'fleet_recall'
              AND NOT (
                  (
                      object_type = 'schema'
                      AND schema_name LIKE 'pg_temp_%'
                      AND object_name IS NULL
                      AND privilege_type IN ('CREATE', 'USAGE')
                      AND NOT is_grantable
                  )
                  OR (
                      schema_name IN (
                          'crdb_internal',
                          'information_schema',
                          'pg_catalog',
                          'pg_extension'
                      )
                      AND NOT is_grantable
                      AND (
                          (object_type = 'schema'
                              AND object_name IS NULL
                              AND privilege_type = 'USAGE')
                          OR (object_type = 'table'
                              AND object_name IS NOT NULL
                              AND privilege_type = 'SELECT')
                          OR (object_type = 'type'
                              AND schema_name = 'pg_catalog'
                              AND object_name IS NOT NULL
                              AND privilege_type = 'USAGE')
                      )
                  )
              )
          )
      )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'runtime writer final PUBLIC application boundary is nonzero: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS runtime_writer_public_grant_postcondition
FROM forbidden_final_public_grant;
