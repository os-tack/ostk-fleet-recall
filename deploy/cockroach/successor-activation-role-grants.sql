-- One-shot successor registry-activation role boundary for the dedicated
-- fleet_recall database.
--
-- Run only after the complete successful migration prefix 1 through 14. Later
-- successful migrations are compatible and cannot mask a missing or failed row
-- in that bounded prefix. Run only as a cluster admin; database ownership alone
-- is insufficient. Apply the control and genesis registry-activation policies
-- first: their three hardened logical roles are explicit prerequisites. The
-- later fleet_conflict_reconciliation role is optional. This policy never
-- creates it; if it exists, it may coexist only without an inheritance edge to
-- or from fleet_registry_successor_activation.
--
-- Login users and passwords/identity-provider bindings are intentionally
-- provisioned outside this file. Before applying, the cluster admin must
-- establish the PUBLIC future-default baseline by revoking routine EXECUTE from
-- every non-target existing role, including fleet_conflict_reconciliation when
-- it exists. A clean v26.2.3 descriptor synthesizes one
-- exact non-grantable FOR ALL ROLES routine-EXECUTE row after an attempted
-- revoke; that narrow engine baseline is admitted below. Apply and reapply only
-- while every member credential is quiesced (disabled or otherwise prevented
-- from opening a session, with existing sessions drained). After the policy
-- succeeds, give a short-lived, exclusive workstation login membership only in
-- this logical role, run the reviewed successor repository, and immediately
-- remove that membership or disable the login.
--
-- Object-grant and ownership enforcement in this file is intentionally local
-- to fleet_recall. Before every apply and use, the cluster admin must enumerate
-- every other database, reject and revoke all direct grants or ownership held
-- there by fleet_registry_successor_activation, and separately inventory
-- inherited PUBLIC authority. Other databases may intentionally retain PUBLIC
-- CONNECT, TEMPORARY, and schema USAGE; exclusive database confinement requires
-- a separate cluster-wide PUBLIC policy. CockroachDB v26.2 cannot construct the
-- required cross-database revocations dynamically inside this static SQL file.
-- The external audit and this policy are multi-statement snapshots, not locks:
-- freeze role/grant/default/ownership and schema-DDL changes from audit start
-- through policy completion and the one-shot member's enable/use/disable, or
-- repeat the full external audit immediately before enable/use under that same
-- change freeze.
--
-- CockroachDB v26.2 does not support delegated SHOW statements inside a
-- PL/pgSQL function body (including DO). Gates that consume SHOW therefore
-- remain top-level statements and use a short-circuited, runtime-derived cast
-- failure. Their stable message substrings are contractual; Cockroach reports
-- SQLSTATE 22P02 for the deliberately invalid cast. Catalog-only DO gates keep
-- their explicit SQLSTATE 55000.

-- Pin built-in resolution and keep the temporary schema last. Naming pg_temp
-- explicitly disables its usual implicit-first search behavior in v26.2.3;
-- application relations below remain fully qualified as defense in depth.
SET search_path = pg_catalog, public, pg_temp;

-- Bind every later current-database catalog, SHOW, default-privilege, and
-- object-reset statement to fleet_recall before the prefix block is compiled.
DO $$
BEGIN
    IF pg_catalog.current_database() <> 'fleet_recall' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'successor activation policy must run in fleet_recall';
    END IF;
END
$$;

-- Fail closed before role creation, option changes, revocations, or grants. A
-- missing or failed prerequisite cannot be masked by any later successful row.
DO $$
DECLARE
    successor_schema_ready BOOL;
BEGIN
    SELECT count(*) = 14
       AND min(version) = 1
       AND max(version) = 14
       AND COALESCE(bool_and(success), false)
    INTO successor_schema_ready
    FROM public._sqlx_migrations
    WHERE version BETWEEN 1 AND 14;

    IF successor_schema_ready IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'successor activation role requires the complete successful migration prefix through 14';
    END IF;
END
$$;

-- Freeze policy ordering before creating or changing the successor role.
-- Missing roles or any option set other than exact {NOLOGIN} indicate that the
-- older role policies have not established their reviewed boundary. The
-- optional later reconciliation role is deliberately not a prerequisite.
SELECT IF(
    count(*) = 3
        AND COALESCE(bool_and(options::STRING = '{NOLOGIN}'), false),
    1:::INT8,
    CAST(
        concat(
            'successor activation role requires the three hardened prior application roles: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS successor_activation_prerequisite_role_gate
FROM [SHOW USERS]
WHERE username IN (
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation'
);

-- A current-object reset cannot repair future-object grants for arbitrary
-- grantors. This dedicated database admits no application schema besides
-- public, which lets the policy cover schema-scoped defaults entirely with
-- supported SHOW statements. Temporary session schemas are harmless and may be
-- present while the policy runs.
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
            MESSAGE = 'successor activation policy requires public to be the only application schema';
    END IF;
END
$$;

-- Inspect PUBLIC explicitly across every grantor before target-role creation,
-- for both database-wide and public-schema defaults. CockroachDB release-26.2
-- synthesizes non-grantable PUBLIC EXECUTE-on-routines and USAGE-on-types rows
-- for each role, plus their FOR ALL ROLES baselines. Admit only intrinsic type
-- USAGE, the exact clean-engine all-roles routine row, and this target role's
-- exact creator-scoped routine row. Every other future PUBLIC grant fails
-- closed. If the optional reconciliation role exists, its creator-scoped PUBLIC
-- routine row is an explicit cluster-admin cleanup prerequisite; v26.2 cannot
-- conditionally run its grantee-targeted cross-grantor default audit here.
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
      AND NOT (
          public_default.grantee = 'public'
          AND NOT public_default.is_grantable
          AND public_default.object_type = 'types'
          AND public_default.privilege_type = 'USAGE'
      )
      AND NOT (
          public_default.role IS NULL
          AND public_default.for_all_roles
          AND public_default.grantee = 'public'
          AND public_default.object_type = 'routines'
          AND public_default.privilege_type = 'EXECUTE'
          AND NOT public_default.is_grantable
      )
      AND NOT (
          public_default.role = 'fleet_registry_successor_activation'
          AND NOT public_default.for_all_roles
          AND public_default.grantee = 'public'
          AND public_default.object_type = 'routines'
          AND public_default.privilege_type = 'EXECUTE'
          AND NOT public_default.is_grantable
      )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'successor activation policy permits only intrinsic PUBLIC type USAGE/all-roles routine EXECUTE, target PUBLIC routine EXECUTE, and target self-owner ALL future defaults: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS successor_activation_public_default_gate
FROM forbidden_public_default;

-- Every role implicitly inherits PUBLIC. Refuse every cluster-wide PUBLIC
-- system grant before target-role creation; an operator must revoke it.
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'successor activation policy requires PUBLIC to have no system privileges: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS successor_activation_public_system_gate
FROM [SHOW SYSTEM GRANTS]
WHERE grantee = 'public';

CREATE ROLE IF NOT EXISTS fleet_registry_successor_activation;

-- A named FOR GRANTEE lookup requires the target role to exist. Reject its
-- future-object defaults before changing any role option, membership, system
-- privilege, or object grant. Exact role=self/grantee=self grantable ALL rows
-- merely restate owner authority; ownership is rejected separately below.
WITH successor_default AS (
    SELECT role, for_all_roles, object_type, grantee, privilege_type,
           is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_registry_successor_activation]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type,
           is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_registry_successor_activation
          IN SCHEMA public]
), forbidden_successor_default AS (
    SELECT 1
    FROM successor_default
    WHERE successor_default.object_type IN (
            'schemas', 'routines', 'tables', 'sequences', 'types'
    )
      AND NOT (
          successor_default.role = 'fleet_registry_successor_activation'
          AND NOT successor_default.for_all_roles
          AND successor_default.grantee = 'fleet_registry_successor_activation'
          AND successor_default.privilege_type = 'ALL'
          AND successor_default.is_grantable
      )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'successor activation policy permits only intrinsic PUBLIC type USAGE/all-roles routine EXECUTE, target PUBLIC routine EXECUTE, and target self-owner ALL future defaults: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS successor_activation_target_default_gate
FROM forbidden_successor_default;

-- Ownership is implicit authority that REVOKE cannot remove. Refuse to
-- normalize a role that owns fleet_recall, any schema/relation visible in the
-- current database, or any supported function/type in the current database.
DO $$
DECLARE
    successor_owns_object BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_database AS database_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = database_object.datdba
        WHERE database_object.datname = 'fleet_recall'
          AND owner_role.rolname = 'fleet_registry_successor_activation'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_namespace AS schema_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = schema_object.nspowner
        WHERE owner_role.rolname = 'fleet_registry_successor_activation'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_class AS relation_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = relation_object.relowner
        WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
          AND owner_role.rolname = 'fleet_registry_successor_activation'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_proc AS function_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = function_object.proowner
        WHERE owner_role.rolname = 'fleet_registry_successor_activation'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_type AS type_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = type_object.typowner
        WHERE owner_role.rolname = 'fleet_registry_successor_activation'
    ) INTO successor_owns_object;

    IF successor_owns_object THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'successor activation role must not own database, schema, relation, function, or type objects';
    END IF;
END
$$;

-- The reset below is intentionally bounded to fleet_recall.public. Fail closed
-- before changing the target role if it has any other visible direct object
-- grant, including a function or type grant. Also reject PUBLIC grants that the
-- reset cannot repair and every PUBLIC external-connection grant. Admit only
-- v26.2.3's exact non-grantable virtual-schema fallback and a session's exact
-- non-grantable temporary-schema CREATE/USAGE rows.
WITH forbidden_out_of_boundary_grant AS (
    SELECT 1
    FROM [SHOW GRANTS FOR fleet_registry_successor_activation]
    WHERE grantee = 'fleet_registry_successor_activation'
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
    UNION ALL
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
            'successor activation policy found a grant outside the repairable fleet_recall.public boundary: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS successor_activation_out_of_boundary_grant_gate
FROM forbidden_out_of_boundary_grant;

-- Admit only repairable drift edges with the three mandatory older application
-- roles. LOGIN members of the successor role without ADMIN OPTION are external
-- identity-plane state and intentionally survive. Any other NOLOGIN edge or any
-- ADMIN OPTION fails closed. The optional reconciliation role is explicit here:
-- because v26.2 cannot conditionally issue role-membership DDL and this policy
-- must not create that optional role, an edge in either direction requires
-- cluster-admin cleanup before reapplication.
WITH unexpected_role_edge AS (
    SELECT 1
    FROM [SHOW GRANTS ON ROLE] AS edge
    JOIN [SHOW USERS] AS member_role
      ON member_role.username = edge.member
    WHERE (
        edge.member = 'fleet_registry_successor_activation'
        AND edge.role_name NOT IN (
            'admin',
            'fleet_runtime',
            'fleet_control_bootstrap',
            'fleet_registry_activation'
        )
    ) OR (
        edge.role_name = 'fleet_registry_successor_activation'
        AND (
            'NOLOGIN' = ANY(member_role.options)
            OR edge.is_admin
        )
        AND edge.member NOT IN (
            'fleet_runtime',
            'fleet_control_bootstrap',
            'fleet_registry_activation'
        )
    ) OR (
        edge.role_name = 'fleet_conflict_reconciliation'
        AND edge.member = 'fleet_registry_successor_activation'
    ) OR (
        edge.role_name = 'fleet_registry_successor_activation'
        AND edge.member = 'fleet_conflict_reconciliation'
    )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'successor activation role has an unexpected NOLOGIN, reconciliation, or admin-option inheritance edge: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS successor_activation_unexpected_role_edge_gate
FROM unexpected_role_edge;

-- VALID UNTIL and identity-provider SUBJECT/PROVISIONSRC options are not part
-- of this logical role contract. PROVISIONSRC cannot be removed by SQL; refuse
-- all three before mutation. Password hashes are not exposed by SHOW USERS; the
-- exact NOLOGIN postcondition is the portable all-authentication-method deny.
WITH forbidden_identity_option AS (
    SELECT 1
    FROM [SHOW USERS] AS target_role
    CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
    WHERE target_role.username = 'fleet_registry_successor_activation'
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
            'successor activation role has a forbidden validity or provisioned-identity option: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS successor_activation_identity_option_gate
FROM forbidden_identity_option;

-- This is a logical one-shot privilege bundle, never a login identity. Remove
-- every v26.2 direct role option, system grant, and both directions of inherited
-- authority with the three mandatory older roles. The optional reconciliation
-- role has already been required to have no edge and is never created here.
ALTER ROLE fleet_registry_successor_activation WITH
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
REVOKE admin, fleet_runtime, fleet_control_bootstrap, fleet_registry_activation
    FROM fleet_registry_successor_activation;
REVOKE fleet_registry_successor_activation
    FROM fleet_runtime, fleet_control_bootstrap, fleet_registry_activation;
REVOKE SYSTEM ALL FROM fleet_registry_successor_activation;

SELECT IF(
    count(*) = 1
        AND COALESCE(bool_and(options::STRING = '{NOLOGIN}'), false),
    1:::INT8,
    CAST(
        concat(
            'successor activation role options differ from exact NOLOGIN: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS successor_activation_exact_role_option_postcondition
FROM [SHOW USERS]
WHERE username = 'fleet_registry_successor_activation';

-- Postcondition: successor inherits no role, and no NOLOGIN role inherits
-- successor. Externally provisioned LOGIN members without ADMIN OPTION remain
-- intentionally visible for the deployment identity audit.
WITH forbidden_role_edge AS (
    SELECT 1
    FROM [SHOW GRANTS ON ROLE] AS edge
    JOIN [SHOW USERS] AS member_role
      ON member_role.username = edge.member
    WHERE edge.member = 'fleet_registry_successor_activation'
       OR (
           edge.role_name = 'fleet_registry_successor_activation'
           AND (
               'NOLOGIN' = ANY(member_role.options)
               OR edge.is_admin
           )
       )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'successor activation role inheritance postcondition failed: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS successor_activation_role_edge_postcondition
FROM forbidden_role_edge;

-- Reassert the dedicated-database PUBLIC boundary, remove DDL authority, and
-- reset every direct current-object privilege and grant option on the one-shot
-- role. Future migrations must reapply this policy after creating new objects.
REVOKE ALL ON DATABASE fleet_recall
    FROM public, fleet_registry_successor_activation;
REVOKE ALL ON SCHEMA public
    FROM public, fleet_registry_successor_activation;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM public;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM public;
REVOKE ALL ON ALL TABLES IN SCHEMA public
    FROM fleet_registry_successor_activation;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public
    FROM fleet_registry_successor_activation;

GRANT CONNECT ON DATABASE fleet_recall
    TO fleet_registry_successor_activation;
GRANT USAGE ON SCHEMA public
    TO fleet_registry_successor_activation;

-- The repository repeats the exact successful-prefix-1-through-14 preflight
-- inside its serializable operation. It can inspect, but never mutate, SQLx
-- history.
GRANT SELECT ON TABLE public._sqlx_migrations
    TO fleet_registry_successor_activation;

-- Exact reviewed repository surface. CockroachDB v26.2 requires table-level
-- UPDATE for SELECT ... FOR UPDATE on the control head, even though the same
-- table is also advanced by the repository. INSERT on the three successor
-- authority tables is table-wide, and UPDATE on the current-head projection is
-- likewise not column-scoped. Those raw operations are residual credential
-- capabilities, not an engine-enforced repository boundary. Keep the member
-- credential short-lived, exclusive to the reviewed successor repository, and
-- quiesced outside the one-shot transaction.
GRANT SELECT ON TABLE public.memory_control_bootstraps
    TO fleet_registry_successor_activation;
GRANT SELECT, INSERT ON TABLE public.memory_control_events
    TO fleet_registry_successor_activation;
GRANT SELECT ON TABLE public.memory_control_log_epochs
    TO fleet_registry_successor_activation;
GRANT SELECT, UPDATE ON TABLE public.memory_control_shard_heads
    TO fleet_registry_successor_activation;
GRANT SELECT ON TABLE public.memory_registry_activations
    TO fleet_registry_successor_activation;
GRANT SELECT, INSERT, UPDATE ON TABLE public.memory_registry_current_heads_v2
    TO fleet_registry_successor_activation;
GRANT SELECT, INSERT ON TABLE
    public.memory_registry_genesis_bridge_consumptions
    TO fleet_registry_successor_activation;
GRANT SELECT ON TABLE public.memory_registry_heads
    TO fleet_registry_successor_activation;
GRANT SELECT, INSERT ON TABLE public.memory_registry_transitions
    TO fleet_registry_successor_activation;

-- Successor storage remains invisible to PUBLIC and every older long-lived or
-- one-shot application role. This reasserts the post-0014 quarantine even when
-- grant or grant-option drift was injected after its original application.
REVOKE ALL ON TABLE
    public.memory_registry_transitions,
    public.memory_registry_genesis_bridge_consumptions,
    public.memory_registry_current_heads_v2
FROM
    public,
    fleet_runtime,
    fleet_control_bootstrap,
    fleet_registry_activation;
