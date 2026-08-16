-- no-transaction
-- Exact covering lane for the latest durable lifecycle transition of one claim.
-- The event kind participates in the key so reconciliation can prove the exact
-- transition provenance without scanning unrelated claim events or performing
-- an index join for the immutable reason, state pair, and canonical payload.
-- CockroachDB 26.2 schema-locks existing tables, so this online backfill cannot
-- share an explicit SQL transaction with SQLx's success-row insert.
-- IF NOT EXISTS resumes a completed backfill whose history row was interrupted;
-- the catalog assertion rejects an object with the right name but another shape.

CREATE INDEX IF NOT EXISTS memory_claim_events_transition_provenance_idx
    ON memory_claim_events (
        tenant_id,
        project,
        claim_id,
        event_kind,
        created_at DESC,
        event_id DESC
    ) STORING (
        reason,
        from_state,
        to_state,
        payload
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
        'CREATE INDEX memory_claim_events_transition_provenance_idx ON %I.public.memory_claim_events USING btree (tenant_id ASC, project ASC, claim_id ASC, event_kind ASC, created_at DESC, event_id DESC) STORING (reason, from_state, to_state, payload)',
        current_database()
    )
    INTO exact_index
    FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'memory_claim_events'
      AND indexname = 'memory_claim_events_transition_provenance_idx';

    IF exact_index IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'memory_claim_events_transition_provenance_idx catalog shape mismatch';
    END IF;
END
$$;
