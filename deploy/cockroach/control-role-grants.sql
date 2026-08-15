-- Stage-2 control-ledger role boundary for the dedicated fleet_recall database.
--
-- This boundary can first be applied after migration 0003. Reapply it after
-- every later migration creates objects. This base policy remains valid from
-- the complete successful prefix through 3 onward; after migration 0014, also
-- apply successor-schema-quarantine-grants.sql. Run as a cluster admin,
-- or as a dedicated security operator that has CREATEROLE, the required role
-- admin options and SYSTEM grant options, plus grant authority on every object
-- below. Database ownership alone is insufficient. Login users and their
-- passwords/identity-provider bindings are intentionally provisioned outside
-- this file. Grant each login membership in exactly one logical role.

CREATE ROLE IF NOT EXISTS fleet_runtime;
CREATE ROLE IF NOT EXISTS fleet_control_bootstrap;

-- These are logical privilege bundles, never login identities. Remove ambient
-- role options, direct system privileges, inherited admin, and either direction
-- of application-role inheritance on every application.
ALTER ROLE fleet_runtime WITH NOLOGIN NOCREATEROLE NOCREATEDB;
ALTER ROLE fleet_control_bootstrap WITH NOLOGIN NOCREATEROLE NOCREATEDB;
REVOKE admin FROM fleet_runtime, fleet_control_bootstrap;
REVOKE fleet_runtime FROM fleet_control_bootstrap;
REVOKE fleet_control_bootstrap FROM fleet_runtime;
REVOKE SYSTEM ALL FROM fleet_runtime, fleet_control_bootstrap;

-- CockroachDB gives `public` CONNECT and public-schema CREATE/USAGE on a new
-- database by default. This application database is dedicated, so replace
-- those ambient grants with explicit role grants.
REVOKE ALL ON DATABASE fleet_recall
    FROM public, fleet_runtime, fleet_control_bootstrap;
REVOKE ALL ON SCHEMA public
    FROM public, fleet_runtime, fleet_control_bootstrap;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM public;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM public;

-- The one-shot bootstrap credential has no legacy table or sequence surface.
-- Reset every current object before adding back only migration metadata and the
-- four control-ledger tables. Runtime's separately reviewed legacy grants are
-- deliberately not reset here.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM fleet_control_bootstrap;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM fleet_control_bootstrap;

GRANT CONNECT ON DATABASE fleet_recall TO fleet_runtime;
GRANT CONNECT ON DATABASE fleet_recall TO fleet_control_bootstrap;
GRANT USAGE ON SCHEMA public TO fleet_runtime;
GRANT USAGE ON SCHEMA public TO fleet_control_bootstrap;

-- Serving health reads the uninterrupted successful migration prefix and
-- accepts the additive serving minimum. The private Stage-2 bootstrap command
-- deliberately remains compatible with the complete successful prefix 1
-- through 3, even when later migrations are present; it neither requires nor
-- authenticates Stage-3 readiness. Neither identity may mutate history.
REVOKE ALL ON TABLE _sqlx_migrations
    FROM public, fleet_runtime, fleet_control_bootstrap;
GRANT SELECT ON TABLE _sqlx_migrations
    TO fleet_runtime, fleet_control_bootstrap;

-- Reset the complete control-table surface before applying the exact grant
-- set. Re-running this file therefore removes accidental privilege expansion.
REVOKE ALL ON TABLE
    memory_control_bootstraps,
    memory_control_log_epochs,
    memory_control_shard_heads,
    memory_control_events
FROM public, fleet_runtime, fleet_control_bootstrap;

GRANT SELECT, INSERT ON TABLE memory_control_bootstraps
    TO fleet_control_bootstrap;
GRANT SELECT, INSERT ON TABLE memory_control_log_epochs
    TO fleet_control_bootstrap;
GRANT SELECT, INSERT, UPDATE ON TABLE memory_control_shard_heads
    TO fleet_control_bootstrap;
GRANT SELECT, INSERT ON TABLE memory_control_events
    TO fleet_control_bootstrap;
