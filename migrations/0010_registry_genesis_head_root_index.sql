-- no-transaction
-- Exact foreign-key target for the immutable generation-zero registry head.
-- This is an online index backfill over the frozen 0004 table. The full source
-- event coordinate and database acceptance time prevent a later transition
-- row from cross-wiring a semantic head to another physical control event.
-- CockroachDB 26.2 schema-locks existing tables, so this index cannot share an
-- explicit SQL transaction with SQLx's success-row insert. IF NOT EXISTS makes
-- an interrupted completed backfill resumable; the catalog assertion prevents
-- an object with the right name but any other shape from being accepted.

CREATE UNIQUE INDEX IF NOT EXISTS memory_registry_heads_genesis_root_idx
    ON memory_registry_heads (
        tenant_id,
        project,
        activation_id,
        package_digest,
        activation_policy_digest,
        source_event_id,
        source_epoch_id,
        source_shard,
        source_committed_offset,
        activated_at
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
        'CREATE UNIQUE INDEX memory_registry_heads_genesis_root_idx ON %I.public.memory_registry_heads USING btree (tenant_id ASC, project ASC, activation_id ASC, package_digest ASC, activation_policy_digest ASC, source_event_id ASC, source_epoch_id ASC, source_shard ASC, source_committed_offset ASC, activated_at ASC)',
        current_database()
    )
    INTO exact_index
    FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'memory_registry_heads'
      AND indexname = 'memory_registry_heads_genesis_root_idx';

    IF exact_index IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'memory_registry_heads_genesis_root_idx catalog shape mismatch';
    END IF;
END
$$;
