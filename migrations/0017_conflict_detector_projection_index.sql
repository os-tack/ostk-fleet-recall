-- no-transaction
-- Exact covering lane for detector admission, state filtering, and current
-- conflict recency. Detector precedes state so bounded range probes can reject
-- every unknown detector before the admitted detector/state branches read a
-- recency page. The stored projection avoids primary-index lookups.
-- CockroachDB 26.2 schema-locks existing tables, so this online backfill cannot
-- share an explicit SQL transaction with SQLx's success-row insert.
-- IF NOT EXISTS resumes a completed backfill whose history row was interrupted;
-- the catalog assertion rejects an object with the right name but another shape.

CREATE INDEX IF NOT EXISTS memory_conflicts_scope_detector_state_recency_idx
    ON memory_conflicts (
        tenant_id,
        project,
        detector,
        state,
        last_seen_at DESC,
        id
    ) STORING (
        claim_key,
        kind,
        rationale,
        revision,
        detected_at,
        resolved_at,
        resolution_kind,
        resolution_reason
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
        'CREATE INDEX memory_conflicts_scope_detector_state_recency_idx ON %I.public.memory_conflicts USING btree (tenant_id ASC, project ASC, detector ASC, state ASC, last_seen_at DESC, id ASC) STORING (claim_key, kind, rationale, revision, detected_at, resolved_at, resolution_kind, resolution_reason)',
        current_database()
    )
    INTO exact_index
    FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'memory_conflicts'
      AND indexname = 'memory_conflicts_scope_detector_state_recency_idx';

    IF exact_index IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'memory_conflicts_scope_detector_state_recency_idx catalog shape mismatch';
    END IF;
END
$$;
