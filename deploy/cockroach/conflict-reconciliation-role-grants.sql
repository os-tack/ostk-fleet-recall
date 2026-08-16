-- One-shot conflict-detector reconciliation role boundary for the dedicated
-- fleet_recall database.
--
-- Run only after the complete successful migration prefix 1 through 16. A
-- later successful migration 17 is compatible: reconciliation consumes the
-- detector-versioned uniqueness contract from migration 15 and the exact
-- transition-provenance index from migration 16, but not the serving-only
-- projection index from migration 17. Run as a cluster admin, or as a
-- dedicated security operator that has CREATEROLE, SYSTEM CREATELOGIN, the
-- required role admin options and SYSTEM grant options, plus grant authority
-- on every object below. Database ownership alone is insufficient. Apply the
-- control and registry-activation policies first: their three hardened logical
-- roles are explicit prerequisites. Login users and their
-- passwords/identity-provider bindings are intentionally provisioned outside
-- this file. Before the delegated security-operator path is usable, a cluster
-- admin must establish the PUBLIC future-default baseline by revoking routine
-- EXECUTE from every non-target existing role and FOR ALL ROLES. Apply and
-- reapply only while every member credential is quiesced
-- (disabled or otherwise prevented from opening a session, with existing
-- sessions drained). After the policy succeeds, give the one-shot login
-- membership only in this logical role, run the reviewed reconciliation
-- repository, and then remove that membership or disable the login.

-- Fail closed before role creation, option changes, revocations, or grants. A
-- missing or failed prerequisite cannot be masked by a successful row 17.
DO $$
DECLARE
    reconciliation_schema_ready BOOL;
BEGIN
    SELECT count(*) = 16
       AND min(version) = 1
       AND max(version) = 16
       AND COALESCE(bool_and(success), false)
    INTO reconciliation_schema_ready
    FROM _sqlx_migrations
    WHERE version BETWEEN 1 AND 16;

    IF reconciliation_schema_ready IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'conflict reconciliation role requires the complete successful migration prefix through 16';
    END IF;
END
$$;

-- Freeze policy ordering before creating or changing the reconciliation role.
-- Missing roles or any option set other than exact {NOLOGIN} indicate that the
-- older role policies have not established their reviewed boundary.
DO $$
DECLARE
    prerequisite_roles_ready BOOL;
BEGIN
    SELECT count(*) = 3
       AND COALESCE(bool_and(options::STRING = '{NOLOGIN}'), false)
    INTO prerequisite_roles_ready
    FROM [SHOW USERS]
    WHERE username IN (
        'fleet_runtime',
        'fleet_control_bootstrap',
        'fleet_registry_activation'
    );

    IF prerequisite_roles_ready IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'conflict reconciliation role requires the three hardened prior application roles';
    END IF;
END
$$;

-- A current-object reset cannot repair future-object grants for arbitrary
-- grantors. SHOW DEFAULT PRIVILEGES without a target is scoped to the current
-- grantor. This dedicated database admits no application schema besides
-- public, which lets the policy cover schema-scoped defaults entirely with
-- supported SHOW statements rather than unsafe internal catalogs. Temporary
-- session schemas are harmless and may be present while the policy runs.
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
          AND nspname NOT LIKE 'pg_toast_temp_%'
    ) INTO forbidden_application_schema;

    IF forbidden_application_schema THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'conflict reconciliation policy requires public to be the only application schema';
    END IF;
END
$$;

-- Inspect PUBLIC explicitly across every grantor before target-role creation,
-- for both database-wide and public-schema defaults. CockroachDB release-26.2
-- synthesizes non-grantable PUBLIC EXECUTE-on-routines and USAGE-on-types rows
-- for each role, plus their FOR ALL ROLES baselines:
-- https://github.com/cockroachdb/cockroach/blob/v26.2.3/pkg/sql/logictest/testdata/logic_test/show_default_privileges
-- This stronger policy admits type USAGE plus only the target role's exact
-- creator-scoped routine row. Before apply, a cluster admin must revoke
-- PUBLIC routine EXECUTE for every other existing role and FOR ALL ROLES;
-- v26.2 cannot dynamically revoke arbitrary role identifiers here. Any other
-- PUBLIC routine default is forbidden because a future SECURITY DEFINER
-- routine would become an escape.
DO $$
DECLARE
    forbidden_public_default_privilege BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM (
            SELECT role, for_all_roles, object_type, grantee, privilege_type,
                   is_grantable
            FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
            UNION
            SELECT role, for_all_roles, object_type, grantee, privilege_type,
                   is_grantable
            FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
        ) AS forbidden_default
        WHERE forbidden_default.object_type IN (
            'schemas', 'routines', 'tables', 'sequences', 'types'
        )
          AND NOT (
              forbidden_default.grantee = 'public'
              AND NOT forbidden_default.is_grantable
              AND forbidden_default.object_type = 'types'
              AND forbidden_default.privilege_type = 'USAGE'
          )
          AND NOT (
              forbidden_default.role = 'fleet_conflict_reconciliation'
              AND NOT forbidden_default.for_all_roles
              AND forbidden_default.grantee = 'public'
              AND forbidden_default.object_type = 'routines'
              AND forbidden_default.privilege_type = 'EXECUTE'
              AND NOT forbidden_default.is_grantable
          )
    ) INTO forbidden_public_default_privilege;

    IF forbidden_public_default_privilege THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'conflict reconciliation policy permits only PUBLIC type USAGE, target PUBLIC routine EXECUTE, and target self-owner ALL future defaults';
    END IF;
END
$$;

-- Every role implicitly inherits PUBLIC. A cluster-wide PUBLIC system grant
-- therefore bypasses an otherwise exact direct-role boundary and cannot be
-- repaired by mutating this one-shot role. Refuse all such grants before
-- target-role creation; the security operator must revoke them explicitly.
DO $$
DECLARE
    forbidden_public_system_privilege BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM [SHOW SYSTEM GRANTS]
        WHERE grantee = 'public'
    ) INTO forbidden_public_system_privilege;

    IF forbidden_public_system_privilege THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'conflict reconciliation policy requires PUBLIC to have no system privileges';
    END IF;
END
$$;

CREATE ROLE IF NOT EXISTS fleet_conflict_reconciliation;

-- A named FOR GRANTEE lookup requires the target role to exist. After the
-- prefix/PUBLIC gates create it if absent, reject its future-object defaults
-- before changing any role option, membership, system privilege, or object
-- grant. CockroachDB's intrinsic role=self/grantee=self ALL rows merely restate
-- owner authority; ownership is rejected separately below, so exclude only
-- those exact grantable baseline rows.
DO $$
DECLARE
    forbidden_reconciliation_default_privilege BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM (
            SELECT role, for_all_roles, object_type, grantee, privilege_type,
                   is_grantable
            FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_conflict_reconciliation]
            UNION
            SELECT role, for_all_roles, object_type, grantee, privilege_type,
                   is_grantable
            FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_conflict_reconciliation
                  IN SCHEMA public]
        ) AS forbidden_default
        WHERE forbidden_default.object_type IN (
            'schemas', 'routines', 'tables', 'sequences', 'types'
        )
          AND NOT (
              forbidden_default.role = 'fleet_conflict_reconciliation'
              AND NOT forbidden_default.for_all_roles
              AND forbidden_default.grantee = 'fleet_conflict_reconciliation'
              AND forbidden_default.privilege_type = 'ALL'
              AND forbidden_default.is_grantable
          )
    ) INTO forbidden_reconciliation_default_privilege;

    IF forbidden_reconciliation_default_privilege THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'conflict reconciliation policy permits only PUBLIC type USAGE, target PUBLIC routine EXECUTE, and target self-owner ALL future defaults';
    END IF;
END
$$;

-- Ownership is implicit authority that REVOKE cannot remove. Refuse to
-- normalize a role that owns any database, any schema/relation visible in the
-- current database, or any supported function/type in the current database.
-- An operator must first transfer that ownership to the migrator/security
-- owner. This includes objects outside the migration-owned public schema.
DO $$
DECLARE
    reconciliation_owns_object BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_database AS database_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = database_object.datdba
        WHERE owner_role.rolname = 'fleet_conflict_reconciliation'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_namespace AS schema_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = schema_object.nspowner
        WHERE owner_role.rolname = 'fleet_conflict_reconciliation'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_class AS relation_object
        JOIN pg_catalog.pg_namespace AS relation_schema
          ON relation_schema.oid = relation_object.relnamespace
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = relation_object.relowner
        WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
          AND owner_role.rolname = 'fleet_conflict_reconciliation'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_proc AS function_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = function_object.proowner
        WHERE owner_role.rolname = 'fleet_conflict_reconciliation'
        UNION ALL
        SELECT 1
        FROM pg_catalog.pg_type AS type_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = type_object.typowner
        WHERE owner_role.rolname = 'fleet_conflict_reconciliation'
    ) INTO reconciliation_owns_object;

    IF reconciliation_owns_object THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'conflict reconciliation role must not own database, schema, relation, function, or type objects';
    END IF;
END
$$;

-- The reset below is intentionally bounded to the fleet_recall database and
-- its migration-owned public schema. It can repair arbitrary direct database,
-- public-schema, public-table, and public-sequence grants, but it cannot safely
-- enumerate and revoke identifiers elsewhere. Fail closed before changing the
-- target role if it has any other direct object grant, including a function or
-- type grant. Role inheritance is checked separately below. Also reject every
-- PUBLIC grant in this dedicated database that the reset cannot repair,
-- including function/type grants even in public and every non-public object.
-- SHOW GRANTS also unions cluster-global external connections with NULL
-- database_name; reject every PUBLIC external-connection grant explicitly.
-- https://github.com/cockroachdb/cockroach/blob/v26.2.3/pkg/sql/delegate/show_grants.go#L444-L477
-- These rows must be cleaned up by an operator.
DO $$
DECLARE
    forbidden_out_of_boundary_grant BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM [SHOW GRANTS FOR fleet_conflict_reconciliation]
        WHERE grantee = 'fleet_conflict_reconciliation'
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
                  )
              )
          )
    ) INTO forbidden_out_of_boundary_grant;

    IF forbidden_out_of_boundary_grant THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'conflict reconciliation policy found a grant outside the repairable fleet_recall.public boundary';
    END IF;
END
$$;

-- Role DDL cannot safely enumerate and revoke arbitrary identifiers in
-- CockroachDB v26.2. Admit the three explicit legacy-role drift edges below so
-- reapplication can repair them, but fail closed on every other inheritance
-- edge involving a NOLOGIN role, or on an ADMIN OPTION attached to an external
-- member. LOGIN members of the reconciliation role without ADMIN OPTION are
-- intentionally external identity-plane state and are allowed; deployments
-- must separately audit that member list against the one-shot runbook.
DO $$
DECLARE
    unexpected_role_edge BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM [SHOW GRANTS ON ROLE] AS edge
        JOIN [SHOW USERS] AS member_role
          ON member_role.username = edge.member
        WHERE (
            edge.member = 'fleet_conflict_reconciliation'
            AND edge.role_name NOT IN (
                'admin',
                'fleet_runtime',
                'fleet_control_bootstrap',
                'fleet_registry_activation'
            )
        ) OR (
            edge.role_name = 'fleet_conflict_reconciliation'
            AND (
                'NOLOGIN' = ANY(member_role.options)
                OR edge.is_admin
            )
            AND edge.member NOT IN (
                'fleet_runtime',
                'fleet_control_bootstrap',
                'fleet_registry_activation'
            )
        )
    ) INTO unexpected_role_edge;

    IF unexpected_role_edge THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'conflict reconciliation role has an unexpected NOLOGIN or admin-option inheritance edge';
    END IF;
END
$$;

-- VALID UNTIL and identity-provider SUBJECT/PROVISIONSRC options are not part
-- of this logical role contract. PROVISIONSRC cannot be removed by SQL; refuse
-- all three before mutation so the operator can replace an incorrectly
-- provisioned identity. Password hashes are intentionally not inspected here:
-- SHOW USERS does not expose them, and PASSWORD NULL is unsupported on the
-- insecure Docker parity substrate. The exact NOLOGIN postcondition below is
-- the portable engine control that prevents every authentication method even
-- if a stale password hash exists; secure-cluster operators may additionally
-- clear a non-provisioned role's password with PASSWORD NULL.
DO $$
DECLARE
    forbidden_identity_option BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM [SHOW USERS] AS target_role
        CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
        WHERE target_role.username = 'fleet_conflict_reconciliation'
          AND (
              role_option.option_name LIKE 'VALID UNTIL=%'
              OR role_option.option_name LIKE 'PROVISIONSRC=%'
              OR role_option.option_name LIKE 'SUBJECT=%'
          )
    ) INTO forbidden_identity_option;

    IF forbidden_identity_option THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'conflict reconciliation role has a forbidden validity or provisioned-identity option';
    END IF;
END
$$;

-- This is a logical one-shot privilege bundle, never a login identity. Remove
-- ambient role options, direct system privileges, inherited admin/application
-- authority, and both directions of inheritance with every admitted older
-- application role. The serving runtime retains its separately documented
-- direct ledger DML for remember/recall; this policy prevents additional
-- inherited authority and does not claim to make raw table DML exclusive.
-- CREATE ROLE also synthesizes the one narrowly admitted target-grantor PUBLIC
-- routine default. Changing it can require target membership, so the policy
-- retains that creator-scoped row under quiescence; the ownership, CREATE, and
-- role-edge postconditions below make it inert. Every other PUBLIC routine
-- default remains a fail-closed operator-cleanup prerequisite.
ALTER ROLE fleet_conflict_reconciliation WITH
    NOBYPASSRLS
    NOCANCELQUERY
    NOCONTROLCHANGEFEED
    NOCONTROLJOB
    NOCREATEDB
    NOCREATELOGIN
    NOCREATEROLE
    NOLOGIN
    NOMODIFYCLUSTERSETTING
    SQLLOGIN
    NOVIEWACTIVITY
    NOVIEWACTIVITYREDACTED
    NOVIEWCLUSTERSETTING;
REVOKE admin, fleet_runtime, fleet_control_bootstrap, fleet_registry_activation
    FROM fleet_conflict_reconciliation;
REVOKE fleet_conflict_reconciliation
    FROM fleet_runtime, fleet_control_bootstrap, fleet_registry_activation;
REVOKE SYSTEM ALL FROM fleet_conflict_reconciliation;

DO $$
DECLARE
    exact_role_options BOOL;
BEGIN
    SELECT count(*) = 1
       AND COALESCE(bool_and(options::STRING = '{NOLOGIN}'), false)
    INTO exact_role_options
    FROM [SHOW USERS]
    WHERE username = 'fleet_conflict_reconciliation';

    IF exact_role_options IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'conflict reconciliation role options differ from exact NOLOGIN';
    END IF;
END
$$;

-- Postcondition: reconciliation inherits no role, and no NOLOGIN role inherits
-- reconciliation. Externally provisioned LOGIN members without ADMIN OPTION
-- remain intentionally visible for the deployment identity audit.
DO $$
DECLARE
    forbidden_role_edge BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM [SHOW GRANTS ON ROLE] AS edge
        JOIN [SHOW USERS] AS member_role
          ON member_role.username = edge.member
        WHERE edge.member = 'fleet_conflict_reconciliation'
           OR (
               edge.role_name = 'fleet_conflict_reconciliation'
               AND (
                   'NOLOGIN' = ANY(member_role.options)
                   OR edge.is_admin
               )
           )
    ) INTO forbidden_role_edge;

    IF forbidden_role_edge THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'conflict reconciliation role inheritance postcondition failed';
    END IF;
END
$$;

-- Reassert the dedicated-database PUBLIC boundary, remove DDL authority, and
-- reset every direct current-object privilege and grant option on the one-shot
-- role. CockroachDB's REVOKE ALL removes both a privilege and its grant option.
-- Future migrations must reapply this policy after creating new objects.
REVOKE ALL ON DATABASE fleet_recall
    FROM public, fleet_conflict_reconciliation;
REVOKE ALL ON SCHEMA public
    FROM public, fleet_conflict_reconciliation;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM public;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM public;
REVOKE ALL ON ALL TABLES IN SCHEMA public
    FROM fleet_conflict_reconciliation;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public
    FROM fleet_conflict_reconciliation;

GRANT CONNECT ON DATABASE fleet_recall TO fleet_conflict_reconciliation;
GRANT USAGE ON SCHEMA public TO fleet_conflict_reconciliation;

-- The repository repeats the exact successful-prefix-1-through-16 preflight
-- inside its serializable operation. It can inspect, but never mutate, SQLx
-- history.
GRANT SELECT ON TABLE _sqlx_migrations TO fleet_conflict_reconciliation;

-- Exact reviewed repository surface. Legacy conflict rows and memberships are
-- immutable; reconciliation appends a separate v2 lineage and its exact member
-- set. CockroachDB v26.2 requires table-level UPDATE privilege for the
-- repository's SELECT ... FOR UPDATE locks on both tables. That is a residual
-- credential capability: the frozen repository has no UPDATE statement for
-- either table, and the one-shot login must remain exclusive to that code path.
-- Claims may change lifecycle state, with every change appended to the claim
-- event ledger in the same serializable transaction.
GRANT SELECT, INSERT, UPDATE ON TABLE memory_conflicts
    TO fleet_conflict_reconciliation;
GRANT SELECT, INSERT, UPDATE ON TABLE memory_conflict_members
    TO fleet_conflict_reconciliation;
GRANT SELECT, UPDATE ON TABLE memory_claims
    TO fleet_conflict_reconciliation;
GRANT SELECT, INSERT ON TABLE memory_claim_events
    TO fleet_conflict_reconciliation;

-- A tenant-wide idempotency receipt is reserved and completed around the
-- mutation. The aggregate audit row is append-only and intentionally has no
-- read grant under this credential.
GRANT SELECT, INSERT, UPDATE ON TABLE memory_mutation_receipts
    TO fleet_conflict_reconciliation;
GRANT INSERT ON TABLE memory_events
    TO fleet_conflict_reconciliation;

-- INSERT on memory_conflicts consumes its default sequence through USAGE.
-- USAGE also permits session-local currval/lastval after nextval, but not
-- persistent/global sequence inspection or setval. No other legacy corpus
-- sequence is admitted.
GRANT USAGE ON SEQUENCE memory_conflict_id_seq
    TO fleet_conflict_reconciliation;
