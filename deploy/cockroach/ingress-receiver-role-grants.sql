-- Ingress-receiver role boundary for the dedicated fleet_recall database (ADR
-- 0008 D12).
--
-- `ostk-fleet-recall ingress` receives signed provider webhooks and keeps each
-- as a hint: provider ids and digests, never content. This role may do exactly
-- that and nothing else: read the migration history (to check the schema at
-- startup), and read and insert rows of the hint queue
-- (memory_ingress_deliveries_v1) and of the collector dead letters, where a
-- refused delivery is recorded. It holds no grant on evidence, governed
-- content, collected items, the collector outbox, claims, or any control or
-- registry table, and it may never update or delete anything: settling a hint
-- is the runtime writer's (runtime-role-grants.sql grants it SELECT and UPDATE
-- on the queue).
--
-- Run only after the complete successful migration prefix 1 through 36
-- (version 25 is permanently unused). Other later successful migrations are
-- compatible and cannot mask a missing or failed row in that bounded prefix.
-- Run only as a cluster admin; database ownership alone is insufficient. This
-- policy is independent of the runtime, publication, control, activation,
-- successor, and reconciliation policies and neither requires nor creates
-- their roles.
--
-- The exact application principal fleet_ingress, including its password or
-- identity-provider binding, is provisioned outside this file, and created
-- NOLOGIN until it is audited: CREATE USER fleet_ingress WITH NOLOGIN. Before
-- every apply or reapply, drain its existing sessions and set its role options
-- to the exact quiesced state {NOLOGIN}. This policy never changes that
-- principal's authentication material or options. It requires the principal
-- to have no direct/system/default/ownership authority and no role edge except
-- the one exact non-admin membership installed below. Enabling LOGIN is a
-- separate, post-audit deployment action.
-- Before applying, the cluster admin must also establish the PUBLIC
-- future-default baseline by revoking routine EXECUTE from every non-target
-- existing role. A clean v26.2.3 descriptor synthesizes one exact non-grantable
-- FOR ALL ROLES routine-EXECUTE row after an attempted revoke; that narrow
-- engine baseline is admitted below.
--
-- Object-grant and ownership enforcement in this file is intentionally local
-- to fleet_recall. Before every apply and use, the cluster admin must enumerate
-- every other database and application schema, reject and revoke every direct
-- grant, ownership, or future default held there by fleet_ingress_receiver or
-- fleet_ingress, and separately inventory current and future inherited PUBLIC
-- authority. Other databases may intentionally retain PUBLIC CONNECT,
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
            MESSAGE = 'ingress receiver policy must run in fleet_recall';
    END IF;
END
$$;

-- Fail closed before role creation, option changes, revocations, or grants. A
-- missing or failed prerequisite cannot be masked by a later successful row.
DO $$
DECLARE
    ingress_schema_ready BOOL;
BEGIN
    SELECT count(*) = 35
       AND min(version) = 1
       AND max(version) = 36
       AND COALESCE(bool_and(success), false)
    INTO ingress_schema_ready
    FROM public._sqlx_migrations
    WHERE version BETWEEN 1 AND 36;

    IF ingress_schema_ready IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'ingress receiver role requires successful migrations 1 through 36 (25 is permanently unused)';
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
            'ingress receiver policy requires exact quiesced principal fleet_ingress with options {NOLOGIN}: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_principal_gate
FROM [SHOW USERS]
WHERE username = 'fleet_ingress';

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
            MESSAGE = 'ingress receiver policy requires public to be the only application schema';
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
          public_default.role = 'fleet_ingress_receiver'
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
            'ingress receiver policy permits only intrinsic PUBLIC type USAGE/all-roles routine EXECUTE, target PUBLIC routine EXECUTE, and target self-owner ALL future defaults: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_public_default_gate
FROM forbidden_public_default;

-- A current-object reset cannot repair future authority granted to the fixed
-- principal. Admit only CockroachDB's exact self-owner default rows; because
-- the principal has no CREATE or ownership authority, those intrinsic rows are
-- inert. Every grantor-to-principal future grant must be removed externally.
WITH principal_default AS (
    SELECT role, for_all_roles, object_type, grantee, privilege_type,
           is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_ingress]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type,
           is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_ingress
          IN SCHEMA public]
), forbidden_principal_default AS (
    SELECT 1
    FROM principal_default
    WHERE principal_default.object_type IN (
            'schemas', 'routines', 'tables', 'sequences', 'types'
    )
      AND (
          principal_default.role = 'fleet_ingress'
          AND NOT principal_default.for_all_roles
          AND principal_default.grantee = 'fleet_ingress'
          AND principal_default.privilege_type = 'ALL'
          AND principal_default.is_grantable
      ) IS NOT TRUE
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'ingress principal has non-intrinsic future-default authority: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_principal_default_gate
FROM forbidden_principal_default;

-- Every role implicitly inherits PUBLIC. Neither PUBLIC nor the fixed
-- principal may carry a cluster-global system grant before target creation.
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'ingress receiver policy requires PUBLIC to have no system privileges: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_public_system_gate
FROM [SHOW SYSTEM GRANTS]
WHERE grantee = 'public';

SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'ingress principal must have no system privileges: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_principal_system_gate
FROM [SHOW SYSTEM GRANTS]
WHERE grantee = 'fleet_ingress';

-- The fixed principal must not own any supported current-database object.
-- Ownership in other databases is part of the mandatory external preflight.
DO $$
DECLARE
    ingress_principal_owns_object BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_database AS database_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = database_object.datdba
        WHERE database_object.datname = 'fleet_recall'
          AND owner_role.rolname = 'fleet_ingress'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_namespace AS schema_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = schema_object.nspowner
        WHERE owner_role.rolname = 'fleet_ingress'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_class AS relation_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = relation_object.relowner
        WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
          AND owner_role.rolname = 'fleet_ingress'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_proc AS function_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = function_object.proowner
        WHERE owner_role.rolname = 'fleet_ingress'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_type AS type_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = type_object.typowner
        WHERE owner_role.rolname = 'fleet_ingress'
    ) INTO ingress_principal_owns_object;

    IF ingress_principal_owns_object THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'ingress principal must not own database, schema, relation, function, or type objects';
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
            'ingress receiver policy found an unsafe PUBLIC grant before target creation: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_public_grant_gate
FROM forbidden_public_grant;

-- The fixed principal receives authority only through the logical receiver role.
-- Any direct current-database or cluster-global external-connection grant must
-- be removed externally rather than silently normalized.
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'ingress principal must have no direct object grants: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_principal_grant_gate
FROM [SHOW GRANTS FOR fleet_ingress]
WHERE grantee = 'fleet_ingress';

-- Before creation or reapplication, neither role may participate in any role
-- graph except the already-installed exact non-admin receiver-to-principal edge.
-- Checking every incident edge makes the principal a leaf and blocks mixed or
-- transitive authority in either direction.
WITH forbidden_incident_edge AS (
    SELECT 1
    FROM [SHOW GRANTS ON ROLE] AS edge
    WHERE (
        edge.role_name IN ('fleet_ingress_receiver', 'fleet_ingress')
        OR edge.member IN ('fleet_ingress_receiver', 'fleet_ingress')
    )
      AND NOT (
          edge.role_name = 'fleet_ingress_receiver'
          AND edge.member = 'fleet_ingress'
          AND NOT edge.is_admin
      )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'ingress receiver/principal role graph is not an exact leaf edge: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_principal_edge_gate
FROM forbidden_incident_edge;

CREATE ROLE IF NOT EXISTS fleet_ingress_receiver;

-- A named FOR GRANTEE lookup requires the target role to exist. Reject its
-- future-object defaults before changing any role option, membership, system
-- privilege, or object grant. Exact role=self/grantee=self grantable ALL rows
-- merely restate owner authority; ownership is rejected separately below.
WITH receiver_default AS (
    SELECT role, for_all_roles, object_type, grantee, privilege_type,
           is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_ingress_receiver]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type,
           is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_ingress_receiver
          IN SCHEMA public]
), forbidden_receiver_default AS (
    SELECT 1
    FROM receiver_default
    WHERE receiver_default.object_type IN (
            'schemas', 'routines', 'tables', 'sequences', 'types'
    )
      AND (
          receiver_default.role = 'fleet_ingress_receiver'
          AND NOT receiver_default.for_all_roles
          AND receiver_default.grantee = 'fleet_ingress_receiver'
          AND receiver_default.privilege_type = 'ALL'
          AND receiver_default.is_grantable
      ) IS NOT TRUE
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'ingress receiver policy permits only intrinsic PUBLIC type USAGE/all-roles routine EXECUTE, target PUBLIC routine EXECUTE, and target self-owner ALL future defaults: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_target_default_gate
FROM forbidden_receiver_default;

-- Ownership is implicit authority that REVOKE cannot remove. Refuse to
-- normalize a role that owns fleet_recall, any schema/relation visible in the
-- current database, or any supported function/type in the current database.
-- Ownership in every other database is part of the external admin preflight.
DO $$
DECLARE
    ingress_receiver_owns_object BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_database AS database_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = database_object.datdba
        WHERE database_object.datname = 'fleet_recall'
          AND owner_role.rolname = 'fleet_ingress_receiver'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_namespace AS schema_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = schema_object.nspowner
        WHERE owner_role.rolname = 'fleet_ingress_receiver'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_class AS relation_object
        JOIN pg_catalog.pg_namespace AS relation_schema
          ON relation_schema.oid = relation_object.relnamespace
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = relation_object.relowner
        WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
          AND owner_role.rolname = 'fleet_ingress_receiver'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_proc AS function_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = function_object.proowner
        WHERE owner_role.rolname = 'fleet_ingress_receiver'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_type AS type_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = type_object.typowner
        WHERE owner_role.rolname = 'fleet_ingress_receiver'
    ) INTO ingress_receiver_owns_object;

    IF ingress_receiver_owns_object THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'ingress receiver role must not own database, schema, relation, function, or type objects';
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
    FROM [SHOW GRANTS FOR fleet_ingress_receiver]
    WHERE grantee = 'fleet_ingress_receiver'
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
            'ingress receiver policy found a grant outside the repairable fleet_recall.public boundary: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_out_of_boundary_grant_gate
FROM forbidden_target_grant;

-- Reassert the exact incident-edge graph now that the target exists. A missing
-- expected edge is repairable below; every different inbound, outbound, mixed,
-- or transitive shape fails before role-option normalization.
WITH unexpected_role_edge AS (
    SELECT 1
    FROM [SHOW GRANTS ON ROLE] AS edge
    WHERE (
        edge.role_name IN ('fleet_ingress_receiver', 'fleet_ingress')
        OR edge.member IN ('fleet_ingress_receiver', 'fleet_ingress')
    )
      AND NOT (
          edge.role_name = 'fleet_ingress_receiver'
          AND edge.member = 'fleet_ingress'
          AND NOT edge.is_admin
      )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'ingress receiver/principal role graph is not an exact leaf edge: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_unexpected_role_edge_gate
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
    WHERE target_role.username = 'fleet_ingress_receiver'
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
            'ingress receiver role has a forbidden validity or provisioned-identity option: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_identity_option_gate
FROM forbidden_identity_option;

-- This is a logical privilege bundle, never a login identity. Clear the full
-- CockroachDB v26.2 direct option and system-privilege surface. Every incident
-- role edge except the exact fixed membership was rejected above.
ALTER ROLE fleet_ingress_receiver WITH
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
REVOKE SYSTEM ALL FROM fleet_ingress_receiver;

SELECT IF(
    count(*) = 1
        AND COALESCE(bool_and(options::STRING = '{NOLOGIN}'), false),
    1:::INT8,
    CAST(
        concat(
            'ingress receiver role options differ from exact NOLOGIN: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_exact_role_option_postcondition
FROM [SHOW USERS]
WHERE username = 'fleet_ingress_receiver';

-- Reassert the exact leaf graph after logical-role option normalization.
WITH forbidden_role_edge AS (
    SELECT 1
    FROM [SHOW GRANTS ON ROLE] AS edge
    WHERE (
        edge.role_name IN ('fleet_ingress_receiver', 'fleet_ingress')
        OR edge.member IN ('fleet_ingress_receiver', 'fleet_ingress')
    )
      AND NOT (
          edge.role_name = 'fleet_ingress_receiver'
          AND edge.member = 'fleet_ingress'
          AND NOT edge.is_admin
      )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'ingress receiver role inheritance postcondition failed: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_role_edge_postcondition
FROM forbidden_role_edge;

-- Reassert the dedicated-database PUBLIC boundary, remove DDL authority, and
-- reset every direct current-object privilege and grant option on the receiver.
-- Future migrations must reapply this policy after creating new objects; no
-- default or future-object grant is installed.
REVOKE ALL ON DATABASE fleet_recall
    FROM public, fleet_ingress_receiver;
REVOKE ALL ON SCHEMA public
    FROM public, fleet_ingress_receiver;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM public;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM public;
REVOKE ALL ON ALL TABLES IN SCHEMA public
    FROM fleet_ingress_receiver;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public
    FROM fleet_ingress_receiver;

GRANT CONNECT ON DATABASE fleet_recall TO fleet_ingress_receiver;
GRANT USAGE ON SCHEMA public TO fleet_ingress_receiver;

-- Exact direct receiver surface: the migration history, read at startup, and
-- the hint queue and the collector dead letters, read and appended. INSERT ...
-- ON CONFLICT DO NOTHING needs SELECT beside INSERT. The receiver receives no
-- sequence, UPDATE, DELETE, DDL, evidence, content, item, outbox, claim,
-- control, registry, or reconciliation authority.
GRANT SELECT ON TABLE public._sqlx_migrations TO fleet_ingress_receiver;
GRANT SELECT, INSERT ON TABLE
    public.memory_ingress_deliveries_v1,
    public.memory_collector_dead_letters_v1
TO fleet_ingress_receiver;

-- Install the sole permitted role edge only after every fail-closed gate and
-- exact logical-role grant have succeeded. The fixed principal remains
-- NOLOGIN; enabling its externally managed authentication is a separate,
-- post-audit deployment action.
GRANT fleet_ingress_receiver TO fleet_ingress;

-- Exact direct logical-role surface: database CONNECT, public-schema USAGE,
-- one table SELECT on the migration history, and SELECT and INSERT on the two
-- receiver tables, all non-grantable: seven rows. Because SHOW GRANTS FOR also
-- exposes cluster-global external connections, the exact count rejects those
-- and every function/type/sequence or differently privileged row.
SELECT IF(
    count(*) = 7
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
                    AND object_name = '_sqlx_migrations'
                    AND privilege_type = 'SELECT')
                OR (object_type = 'table'
                    AND database_name = 'fleet_recall'
                    AND schema_name = 'public'
                    AND object_name IN (
                        'memory_ingress_deliveries_v1',
                        'memory_collector_dead_letters_v1'
                    )
                    AND privilege_type IN ('SELECT', 'INSERT'))
            )
        ), false),
    1:::INT8,
    CAST(
        concat(
            'ingress receiver direct-grant postcondition differs from exact seven-row matrix: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_exact_grant_postcondition
FROM [SHOW GRANTS FOR fleet_ingress_receiver]
WHERE grantee = 'fleet_ingress_receiver';

SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'ingress principal direct-grant postcondition is nonzero: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_principal_grant_postcondition
FROM [SHOW GRANTS FOR fleet_ingress]
WHERE grantee = 'fleet_ingress';

SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'ingress receiver/PUBLIC/principal system-grant postcondition is nonzero: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_system_postcondition
FROM [SHOW SYSTEM GRANTS]
WHERE grantee IN (
    'public', 'fleet_ingress_receiver', 'fleet_ingress'
);

SELECT IF(
    count(*) = 2
        AND COALESCE(bool_and(
            (username = 'fleet_ingress_receiver'
                AND options::STRING = '{NOLOGIN}')
            OR (username = 'fleet_ingress'
                AND options::STRING = '{NOLOGIN}')
        ), false),
    1:::INT8,
    CAST(
        concat(
            'ingress receiver/principal option postcondition differs from exact NOLOGIN: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_principal_option_postcondition
FROM [SHOW USERS]
WHERE username IN ('fleet_ingress_receiver', 'fleet_ingress');

SELECT IF(
    count(*) = 1
        AND COALESCE(bool_and(
            role_name = 'fleet_ingress_receiver'
            AND member = 'fleet_ingress'
            AND NOT is_admin
        ), false),
    1:::INT8,
    CAST(
        concat(
            'ingress receiver/principal edge postcondition differs from exact non-admin leaf edge: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_principal_edge_postcondition
FROM [SHOW GRANTS ON ROLE]
WHERE role_name IN ('fleet_ingress_receiver', 'fleet_ingress')
   OR member IN ('fleet_ingress_receiver', 'fleet_ingress');

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
            'ingress receiver final PUBLIC application boundary is nonzero: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS ingress_receiver_public_grant_postcondition
FROM forbidden_final_public_grant;
