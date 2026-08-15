-- no-transaction
-- Exact foreign-key target for the immutable generation-zero activation.
-- The tuple retains the complete root head, frozen canonical profile, contract
-- scope, effective time, physical event coordinate, and database acceptance
-- time. Migration 0004 already requires effective_until IS NULL.
-- CockroachDB 26.2 schema-locks existing tables, so this index cannot share an
-- explicit SQL transaction with SQLx's success-row insert. IF NOT EXISTS makes
-- an interrupted completed backfill resumable; the catalog assertion prevents
-- an object with the right name but any other shape from being accepted.

CREATE UNIQUE INDEX IF NOT EXISTS memory_registry_activations_genesis_root_idx
    ON memory_registry_activations (
        tenant_id,
        project,
        activation_id,
        activated_package_digest,
        activated_policy_digest,
        profile_id,
        profile_digest,
        vector_manifest_digest,
        contract_tenant_namespace,
        contract_project_namespace,
        effective_from,
        accepted_event_id,
        control_epoch_id,
        control_shard,
        control_committed_offset,
        accepted_at
    );

-- SQLx sends a multi-statement migration as one implicit transaction. Commit
-- the schema change before inspecting the public catalog; this migration is
-- registered no_tx, so there is no enclosing application transaction.
COMMIT;

DO $$
DECLARE
    exact_index BOOL;
BEGIN
    SELECT indexdef = format(
        'CREATE UNIQUE INDEX memory_registry_activations_genesis_root_idx ON %I.public.memory_registry_activations USING btree (tenant_id ASC, project ASC, activation_id ASC, activated_package_digest ASC, activated_policy_digest ASC, profile_id ASC, profile_digest ASC, vector_manifest_digest ASC, contract_tenant_namespace ASC, contract_project_namespace ASC, effective_from ASC, accepted_event_id ASC, control_epoch_id ASC, control_shard ASC, control_committed_offset ASC, accepted_at ASC)',
        current_database()
    )
    INTO exact_index
    FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'memory_registry_activations'
      AND indexname = 'memory_registry_activations_genesis_root_idx';

    IF exact_index IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'memory_registry_activations_genesis_root_idx catalog shape mismatch';
    END IF;
END
$$;
