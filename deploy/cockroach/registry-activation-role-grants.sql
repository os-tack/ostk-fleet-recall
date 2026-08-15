-- Stage-3 registry-activation role boundary for the dedicated fleet_recall
-- database.
--
-- Run only after the complete successful migration prefix 1 through 9 and the
-- Stage-2 control-role policy. This base policy intentionally remains runnable
-- at version 9; after migration 0014, also apply the separately gated
-- successor-schema-quarantine-grants.sql. Run as a cluster admin, or as a
-- dedicated security operator that has CREATEROLE, the required role admin
-- options and SYSTEM grant options, plus grant authority on every object below.
-- Database ownership alone is insufficient. Login users and their
-- passwords/identity-provider bindings are intentionally provisioned outside
-- this file. Give the private activation login membership only in this logical
-- role.

CREATE ROLE IF NOT EXISTS fleet_registry_activation;

-- Keep the logical role non-login and strip legacy role options that are not
-- represented by SHOW SYSTEM GRANTS. Reapplication must also break both known
-- directions of application-role inheritance: activation cannot inherit the
-- older roles, and runtime/bootstrap cannot inherit activation.
ALTER ROLE fleet_registry_activation WITH NOLOGIN NOCREATEROLE NOCREATEDB;
REVOKE admin, fleet_runtime, fleet_control_bootstrap
    FROM fleet_registry_activation;
REVOKE fleet_registry_activation
    FROM fleet_runtime, fleet_control_bootstrap;
REVOKE SYSTEM ALL FROM fleet_registry_activation;

-- Reassert the dedicated-database PUBLIC boundary on every application object
-- that exists now. This closes inherited PUBLIC drift on legacy/private tables
-- and sequences as well as database/schema CREATE and connection privileges.
-- Future migrations must reapply this policy after creating new objects.
REVOKE ALL ON DATABASE fleet_recall
    FROM public, fleet_registry_activation;
REVOKE ALL ON SCHEMA public
    FROM public, fleet_registry_activation;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM public;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM public;

-- Reset all direct current-object drift on the one-shot activation bundle.
-- The exact migration/control/registry surface is added back below.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM fleet_registry_activation;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM fleet_registry_activation;

-- Apply the exact connection surface after the reset.
GRANT CONNECT ON DATABASE fleet_recall TO fleet_registry_activation;
GRANT USAGE ON SCHEMA public TO fleet_registry_activation;

-- The private command requires the complete successful migration prefix 1
-- through 9. A missing or failed prerequisite cannot be masked by a later
-- successful row. It cannot mutate SQLx migration history.
REVOKE ALL ON TABLE _sqlx_migrations FROM fleet_registry_activation;
GRANT SELECT ON TABLE _sqlx_migrations TO fleet_registry_activation;

-- Activation reads every Stage-2 control anchor, appends its accepted control
-- event, and advances only the existing shard head. It cannot bootstrap a new
-- scope, epoch, or head, and cannot rewrite or delete immutable control rows.
-- CockroachDB 26.2 has table-level, not column-level, UPDATE grants. Keep this
-- credential exclusive to the reviewed activation repository, whose frozen
-- compare-and-swap updates only offset, chain digest, and advancement time.
REVOKE ALL ON TABLE
    memory_control_bootstraps,
    memory_control_log_epochs,
    memory_control_shard_heads,
    memory_control_events
FROM fleet_registry_activation;

GRANT SELECT ON TABLE
    memory_control_bootstraps,
    memory_control_log_epochs,
    memory_control_shard_heads,
    memory_control_events
TO fleet_registry_activation;
GRANT INSERT ON TABLE memory_control_events TO fleet_registry_activation;
GRANT UPDATE ON TABLE memory_control_shard_heads TO fleet_registry_activation;

-- Stage-3 rows are append-only. Reset every application role on the complete
-- new-table surface so runtime, bootstrap, and public cannot inherit access.
REVOKE ALL ON TABLE
    memory_registry_activations,
    memory_registry_heads
FROM
    public,
    fleet_runtime,
    fleet_control_bootstrap,
    fleet_registry_activation;

GRANT SELECT, INSERT ON TABLE
    memory_registry_activations,
    memory_registry_heads
TO fleet_registry_activation;
