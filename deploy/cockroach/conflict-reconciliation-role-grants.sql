-- One-shot conflict-detector reconciliation role boundary for the dedicated
-- fleet_recall database.
--
-- Run only after the complete successful migration prefix 1 through 16. A
-- later successful migration 17 is compatible: reconciliation consumes the
-- detector-versioned uniqueness contract from migration 15 and the exact
-- transition-provenance index from migration 16, but not the serving-only
-- projection index from migration 17. Run only as a cluster admin; database
-- ownership alone is insufficient. Apply the
-- control and registry-activation policies first: their three hardened logical
-- roles are explicit prerequisites. Login users and their
-- passwords/identity-provider bindings are intentionally provisioned outside
-- this file. Before applying, the cluster admin must establish the PUBLIC
-- future-default baseline by revoking routine
-- EXECUTE from every non-target existing role. A clean v26.2.3 descriptor
-- synthesizes one exact non-grantable FOR ALL ROLES routine-EXECUTE row after
-- an attempted revoke; that narrow engine baseline is admitted below. Apply and
-- reapply only while every member credential is quiesced
-- (disabled or otherwise prevented from opening a session, with existing
-- sessions drained). After the policy succeeds, give the one-shot login
-- membership only in this logical role, run the reviewed reconciliation
-- repository, and then remove that membership or disable the login.
--
-- Object-grant and ownership enforcement in this file is intentionally local
-- to fleet_recall. Before every apply and use, the cluster admin must enumerate
-- every other database, reject and revoke all direct grants or ownership held
-- there by fleet_conflict_reconciliation, and separately inventory inherited
-- PUBLIC authority. Other databases may intentionally retain PUBLIC CONNECT,
-- TEMPORARY, and schema USAGE; exclusive database confinement requires a
-- separate cluster-wide PUBLIC policy. CockroachDB v26.2 cannot construct the
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
-- Keeping this assertion in its own block is required: CockroachDB compiles
-- relation references elsewhere in a PL/pgSQL block before executing an
-- earlier IF branch, so a wrong database without public._sqlx_migrations would
-- otherwise report 42P01 instead of this fail-closed boundary.
DO $$
BEGIN
    IF pg_catalog.current_database() <> 'fleet_recall' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'conflict reconciliation policy must run in fleet_recall';
    END IF;
END
$$;

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
    FROM public._sqlx_migrations
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
SELECT IF(
    count(*) = 3
        AND COALESCE(bool_and(options::STRING = '{NOLOGIN}'), false),
    1:::INT8,
    CAST(
        concat(
            'conflict reconciliation role requires the three hardened prior application roles: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS conflict_reconciliation_prerequisite_role_gate
FROM [SHOW USERS]
WHERE username IN (
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation'
);

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
-- This stronger policy admits type USAGE, the exact clean-engine non-grantable
-- FOR ALL ROLES routine row, and only the target role's exact creator-scoped
-- routine row. Before apply, a cluster admin must revoke PUBLIC routine EXECUTE
-- for every other existing role; v26.2 cannot dynamically revoke arbitrary
-- role identifiers here. Any other PUBLIC routine default is forbidden because
-- a future SECURITY DEFINER routine would become an escape. The admitted rows
-- are inert only while member credentials are quiesced and no current PUBLIC
-- function grant survives the object-grant boundary below. Reapply and clean
-- current grants before re-enabling a member after future schema work.
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
          public_default.role = 'fleet_conflict_reconciliation'
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
            'conflict reconciliation policy permits only intrinsic PUBLIC type USAGE/all-roles routine EXECUTE, target PUBLIC routine EXECUTE, and target self-owner ALL future defaults: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS conflict_reconciliation_public_default_gate
FROM forbidden_public_default;

-- Every role implicitly inherits PUBLIC. A cluster-wide PUBLIC system grant
-- therefore bypasses an otherwise exact direct-role boundary and cannot be
-- repaired by mutating this one-shot role. Refuse all such grants before
-- target-role creation; the cluster admin must revoke them explicitly.
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'conflict reconciliation policy requires PUBLIC to have no system privileges: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS conflict_reconciliation_public_system_gate
FROM [SHOW SYSTEM GRANTS]
WHERE grantee = 'public';

CREATE ROLE IF NOT EXISTS fleet_conflict_reconciliation;

-- A named FOR GRANTEE lookup requires the target role to exist. After the
-- prefix/PUBLIC gates create it if absent, reject its future-object defaults
-- before changing any role option, membership, system privilege, or object
-- grant. CockroachDB's intrinsic role=self/grantee=self ALL rows merely restate
-- owner authority; ownership is rejected separately below, so exclude only
-- those exact grantable baseline rows.
WITH reconciliation_default AS (
    SELECT role, for_all_roles, object_type, grantee, privilege_type,
           is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_conflict_reconciliation]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type,
           is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_conflict_reconciliation
          IN SCHEMA public]
), forbidden_reconciliation_default AS (
    SELECT 1
    FROM reconciliation_default
    WHERE reconciliation_default.object_type IN (
            'schemas', 'routines', 'tables', 'sequences', 'types'
    )
      AND NOT (
          reconciliation_default.role = 'fleet_conflict_reconciliation'
          AND NOT reconciliation_default.for_all_roles
          AND reconciliation_default.grantee = 'fleet_conflict_reconciliation'
          AND reconciliation_default.privilege_type = 'ALL'
          AND reconciliation_default.is_grantable
      )
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'conflict reconciliation policy permits only intrinsic PUBLIC type USAGE/all-roles routine EXECUTE, target PUBLIC routine EXECUTE, and target self-owner ALL future defaults: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS conflict_reconciliation_target_default_gate
FROM forbidden_reconciliation_default;

-- Ownership is implicit authority that REVOKE cannot remove. Refuse to
-- normalize a role that owns fleet_recall, any schema/relation visible in the
-- current database, or any supported function/type in the current database.
-- An operator must first transfer that ownership to the migrator/security
-- owner. This includes current-database objects outside the migration-owned
-- public schema; ownership in other databases is an external admin preflight.
DO $$
DECLARE
    reconciliation_owns_object BOOL;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_database AS database_object
        JOIN pg_catalog.pg_roles AS owner_role
          ON owner_role.oid = database_object.datdba
        WHERE database_object.datname = 'fleet_recall'
          AND owner_role.rolname = 'fleet_conflict_reconciliation'
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
-- enumerate and revoke identifiers elsewhere in the current database, and a
-- current-database SHOW cannot enforce the required other-database audit. Fail
-- closed before changing the target role if it has any other visible direct
-- object grant, including a function or type grant. Role inheritance is
-- checked separately below. Also reject every
-- PUBLIC grant in this dedicated database that the reset cannot repair,
-- including function/type grants even in public and every non-public object.
-- SHOW GRANTS also unions cluster-global external connections with NULL
-- database_name; reject every PUBLIC external-connection grant explicitly.
-- https://github.com/cockroachdb/cockroach/blob/v26.2.3/pkg/sql/delegate/show_grants.go#L444-L477
-- SHOW GRANTS also synthesizes PUBLIC's baseline visibility into the four
-- unmodifiable v26.2.3 virtual schemas. Admit only the exact non-grantable
-- fallback shapes: schema USAGE and table SELECT in all four, plus type USAGE
-- in pg_catalog. Cockroach rejects user object creation/shadowing in these
-- reserved schemas, and every routine or differently shaped row still fails.
-- A session with temporary tables also synthesizes non-grantable PUBLIC CREATE
-- and USAGE on its session-unique pg_temp schema. Admit only
-- those exact schema rows; direct target grants on a temporary object still
-- fail through the first branch.
-- Every other out-of-boundary row must be cleaned up by an operator.
WITH forbidden_out_of_boundary_grant AS (
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
            'conflict reconciliation policy found a grant outside the repairable fleet_recall.public boundary: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS conflict_reconciliation_out_of_boundary_grant_gate
FROM forbidden_out_of_boundary_grant;

-- Role DDL cannot safely enumerate and revoke arbitrary identifiers in
-- CockroachDB v26.2. Admit the three explicit legacy-role drift edges below so
-- reapplication can repair them, but fail closed on every other inheritance
-- edge involving a NOLOGIN role, or on an ADMIN OPTION attached to an external
-- member. LOGIN members of the reconciliation role without ADMIN OPTION are
-- intentionally external identity-plane state and are allowed; deployments
-- must separately audit that member list against the one-shot runbook.
WITH unexpected_role_edge AS (
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
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'conflict reconciliation role has an unexpected NOLOGIN or admin-option inheritance edge: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS conflict_reconciliation_unexpected_role_edge_gate
FROM unexpected_role_edge;

-- VALID UNTIL and identity-provider SUBJECT/PROVISIONSRC options are not part
-- of this logical role contract. PROVISIONSRC cannot be removed by SQL; refuse
-- all three before mutation so the operator can replace an incorrectly
-- provisioned identity. Password hashes are intentionally not inspected here:
-- SHOW USERS does not expose them, and PASSWORD NULL is unsupported on the
-- insecure Docker parity substrate. The exact NOLOGIN postcondition below is
-- the portable engine control that prevents every authentication method even
-- if a stale password hash exists; secure-cluster operators may additionally
-- clear a non-provisioned role's password with PASSWORD NULL.
WITH forbidden_identity_option AS (
    SELECT 1
    FROM [SHOW USERS] AS target_role
    CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
    WHERE target_role.username = 'fleet_conflict_reconciliation'
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
            'conflict reconciliation role has a forbidden validity or provisioned-identity option: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS conflict_reconciliation_identity_option_gate
FROM forbidden_identity_option;

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
    NOREPLICATION
    SQLLOGIN
    NOVIEWACTIVITY
    NOVIEWACTIVITYREDACTED
    NOVIEWCLUSTERSETTING;
REVOKE admin, fleet_runtime, fleet_control_bootstrap, fleet_registry_activation
    FROM fleet_conflict_reconciliation;
REVOKE fleet_conflict_reconciliation
    FROM fleet_runtime, fleet_control_bootstrap, fleet_registry_activation;
REVOKE SYSTEM ALL FROM fleet_conflict_reconciliation;

SELECT IF(
    count(*) = 1
        AND COALESCE(bool_and(options::STRING = '{NOLOGIN}'), false),
    1:::INT8,
    CAST(
        concat(
            'conflict reconciliation role options differ from exact NOLOGIN: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS conflict_reconciliation_exact_role_option_postcondition
FROM [SHOW USERS]
WHERE username = 'fleet_conflict_reconciliation';

-- Postcondition: reconciliation inherits no role, and no NOLOGIN role inherits
-- reconciliation. Externally provisioned LOGIN members without ADMIN OPTION
-- remain intentionally visible for the deployment identity audit.
WITH forbidden_role_edge AS (
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
)
SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            'conflict reconciliation role inheritance postcondition failed: observed=',
            count(*)::STRING
        )
        AS INT8
    )
) AS conflict_reconciliation_role_edge_postcondition
FROM forbidden_role_edge;

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
GRANT SELECT ON TABLE public._sqlx_migrations
    TO fleet_conflict_reconciliation;

-- Exact reviewed repository surface. Legacy conflict rows and memberships are
-- immutable; reconciliation appends a separate v2 lineage and its exact member
-- set. CockroachDB v26.2 requires table-level UPDATE privilege for the
-- repository's SELECT ... FOR UPDATE locks on both tables. That is a residual
-- credential capability: the frozen repository has no UPDATE statement for
-- either table, and the one-shot login must remain exclusive to that code path.
-- Claims may change lifecycle state, with every change appended to the claim
-- event ledger in the same serializable transaction.
GRANT SELECT, INSERT, UPDATE ON TABLE public.memory_conflicts
    TO fleet_conflict_reconciliation;
GRANT SELECT, INSERT, UPDATE ON TABLE public.memory_conflict_members
    TO fleet_conflict_reconciliation;
GRANT SELECT, UPDATE ON TABLE public.memory_claims
    TO fleet_conflict_reconciliation;
GRANT SELECT, INSERT ON TABLE public.memory_claim_events
    TO fleet_conflict_reconciliation;

-- A tenant-wide idempotency receipt is reserved and completed around the
-- mutation. The aggregate audit row is append-only and intentionally has no
-- read grant under this credential.
GRANT SELECT, INSERT, UPDATE ON TABLE public.memory_mutation_receipts
    TO fleet_conflict_reconciliation;
GRANT INSERT ON TABLE public.memory_events
    TO fleet_conflict_reconciliation;

-- INSERT on memory_conflicts consumes its default sequence through USAGE.
-- USAGE also permits session-local currval/lastval after nextval, but not
-- persistent/global sequence inspection or setval. No other legacy corpus
-- sequence is admitted.
GRANT USAGE ON SEQUENCE public.memory_conflict_id_seq
    TO fleet_conflict_reconciliation;
