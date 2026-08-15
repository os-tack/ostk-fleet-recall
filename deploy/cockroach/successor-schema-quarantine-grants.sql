-- Post-migration-0014 quarantine for successor registry storage.
--
-- Migrations 0012 through 0014 create durable authority surfaces before a
-- successor activation principal is deployed. No existing application role
-- may inherit access to those tables during that interval. Run this file as
-- the same cluster security operator required by the Stage-2 and Stage-3 grant
-- policies, after both of those policies have created and hardened their
-- logical roles.
--
-- This file is deliberately separate from the v9-compatible grant policies:
-- CockroachDB v26.2 cannot conditionally execute REVOKE inside PL/pgSQL. The
-- exact successful-prefix gate below therefore fails closed before any static
-- reference to the post-v9 tables is evaluated.

DO $$
DECLARE
    successor_schema_ready BOOL;
BEGIN
    SELECT count(*) = 14 AND COALESCE(bool_and(success), false)
    INTO successor_schema_ready
    FROM _sqlx_migrations
    WHERE version BETWEEN 1 AND 14;

    IF successor_schema_ready IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'successor schema quarantine requires the complete successful migration prefix through 14';
    END IF;
END
$$;

-- In CockroachDB, REVOKE ALL removes both the privilege and its grant option;
-- the engine does not implement PostgreSQL's trailing CASCADE syntax. The
-- successor repository will receive a separate, reviewed role policy; this
-- quarantine never grants access.
REVOKE ALL ON TABLE
    memory_registry_transitions,
    memory_registry_genesis_bridge_consumptions,
    memory_registry_current_heads_v2
FROM
    public,
    fleet_runtime,
    fleet_control_bootstrap,
    fleet_registry_activation;
