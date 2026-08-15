-- Stage-2 control-ledger role boundary for the dedicated fleet_recall database.
--
-- Run as the database owner or migrator after migration 0003. Login users and
-- their passwords/identity-provider bindings are intentionally provisioned
-- outside this file. Grant each login membership in exactly one logical role.

CREATE ROLE IF NOT EXISTS fleet_runtime;
CREATE ROLE IF NOT EXISTS fleet_control_bootstrap;

-- CockroachDB gives `public` CONNECT and public-schema CREATE/USAGE on a new
-- database by default. This application database is dedicated, so replace
-- those ambient grants with explicit role grants.
REVOKE ALL ON DATABASE fleet_recall FROM public;
REVOKE ALL ON SCHEMA public FROM public;

GRANT CONNECT ON DATABASE fleet_recall TO fleet_runtime;
GRANT CONNECT ON DATABASE fleet_recall TO fleet_control_bootstrap;
GRANT USAGE ON SCHEMA public TO fleet_runtime;
GRANT USAGE ON SCHEMA public TO fleet_control_bootstrap;

-- Both serving health and the private command perform a read-only additive
-- schema-version preflight. Neither identity may mutate migration history.
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
