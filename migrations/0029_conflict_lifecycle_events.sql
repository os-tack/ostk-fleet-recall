-- no-transaction
-- Serving conflict lifecycle events (ADR 0004). One additive, append-only,
-- private-plane table recording every agent- or detector-attributed conflict
-- lifecycle transition the serving writer performs: acknowledgements and
-- waivers (overlay only; memory_conflicts is never touched) and the
-- resolved/dismissed closes the writer applies to memory_conflicts in the same
-- serializable transaction. memory_conflicts, memory_conflict_members, and
-- migrations 0001 through 0028 remain byte-identical (ADR 0003 amendment).
-- Version 25 remains the permanent gap.
--
-- Like migrations 0018 onward, this DDL runs outside SQLx's transaction
-- wrapper, so every object is created with IF NOT EXISTS and a process death
-- between the schema change and SQLx's history row is resumable.
--
-- The table deliberately carries NO foreign key: an inbound key would change
-- the memory_conflicts descriptor and make bulk DELETEs of memory_conflicts
-- fail. The writer inserts rows only while holding the conflict lineage row
-- FOR UPDATE after reserving its idempotency receipt. This is not one of the
-- publication reader's tables (PUBLIC-02/03).

-- Ownership: fleet_migrator. event_seq numbers one conflict's events from 1
-- without gaps. episode_revision is the memory_conflicts revision the event
-- was decided against; result_revision is the revision it left (the same for
-- an overlay event, one more for a close). actor is the trusted agent, or the
-- detector identifier for a detector-verified close.
CREATE TABLE IF NOT EXISTS memory_conflict_lifecycle_events_v1 (
    tenant_id         UUID NOT NULL,
    project           STRING NOT NULL,
    conflict_id       INT8 NOT NULL,
    event_seq         INT8 NOT NULL,
    event_kind        STRING NOT NULL,
    episode_revision  INT8 NOT NULL,
    result_revision   INT8 NOT NULL,
    from_state        STRING NOT NULL,
    to_state          STRING NOT NULL,
    actor_kind        STRING NOT NULL,
    actor             STRING NOT NULL,
    session_id        STRING,
    operation         STRING NOT NULL,
    idempotency_key   STRING NOT NULL,
    member_count      INT8 NOT NULL,
    reason_kind       STRING,
    rationale         STRING,
    expires_at        TIMESTAMPTZ,
    review_by         TIMESTAMPTZ,
    payload           JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, conflict_id, event_seq),
    CONSTRAINT memory_conflict_lifecycle_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_conflict_lifecycle_ids
        CHECK (conflict_id BETWEEN 1 AND 9007199254740991
               AND event_seq BETWEEN 1 AND 4096
               AND episode_revision > 0 AND result_revision > 0),
    CONSTRAINT memory_conflict_lifecycle_kind
        CHECK (event_kind IN ('acknowledged', 'waived', 'resolved', 'dismissed')),
    CONSTRAINT memory_conflict_lifecycle_shape CHECK (
           (event_kind IN ('acknowledged', 'waived') AND from_state = 'open'
                AND to_state = 'open' AND result_revision = episode_revision)
        OR (event_kind = 'resolved' AND from_state = 'open'
                AND to_state = 'resolved' AND result_revision = episode_revision + 1)
        OR (event_kind = 'dismissed' AND from_state = 'open'
                AND to_state = 'dismissed' AND result_revision = episode_revision + 1)),
    CONSTRAINT memory_conflict_lifecycle_actor
        CHECK (actor_kind IN ('agent', 'detector')
               AND octet_length(actor) BETWEEN 1 AND 256
               AND (actor_kind = 'agent' OR event_kind = 'resolved')),
    CONSTRAINT memory_conflict_lifecycle_session_bound
        CHECK (session_id IS NULL OR octet_length(session_id) BETWEEN 1 AND 256),
    CONSTRAINT memory_conflict_lifecycle_operation
        CHECK (operation IN ('supersede', 'retract', 'conflict_acknowledge',
                             'conflict_resolve', 'conflict_dismiss', 'conflict_waive')),
    CONSTRAINT memory_conflict_lifecycle_key_bound
        CHECK (octet_length(idempotency_key) BETWEEN 1 AND 256),
    CONSTRAINT memory_conflict_lifecycle_member_count
        CHECK (member_count BETWEEN 0 AND 4096),
    CONSTRAINT memory_conflict_lifecycle_reason_kind_bound
        CHECK (reason_kind IS NULL OR octet_length(reason_kind) BETWEEN 1 AND 64),
    CONSTRAINT memory_conflict_lifecycle_rationale_bound
        CHECK (rationale IS NULL OR octet_length(rationale) BETWEEN 1 AND 4096),
    CONSTRAINT memory_conflict_lifecycle_payload_bound
        CHECK (octet_length(payload::STRING) <= 262144),
    CONSTRAINT memory_conflict_lifecycle_resolution
        CHECK (event_kind <> 'resolved' OR reason_kind = 'no_current_incompatibility'),
    CONSTRAINT memory_conflict_lifecycle_dismissal
        CHECK (event_kind <> 'dismissed' OR (
            reason_kind IN ('false_positive', 'duplicate_of_other_episode',
                            'out_of_scope', 'not_reproducible')
            AND rationale IS NOT NULL)),
    CONSTRAINT memory_conflict_lifecycle_waiver CHECK (
        ((event_kind = 'waived') = (expires_at IS NOT NULL))
        AND (event_kind <> 'waived' OR (
            reason_kind IN ('capacity_deferred', 'cost_exceeds_risk', 'upstream_blocked',
                            'policy_exception', 'scheduled_remediation')
            AND rationale IS NOT NULL AND expires_at > created_at))
        AND (review_by IS NULL OR (expires_at IS NOT NULL AND review_by <= expires_at)))
);

-- One lifecycle event per mutation per conflict (receipt backstop).
CREATE UNIQUE INDEX IF NOT EXISTS memory_conflict_lifecycle_v1_mutation_idx
    ON memory_conflict_lifecycle_events_v1 (tenant_id, idempotency_key, conflict_id);
-- One acknowledgement per actor per episode (conflict_id, revision).
CREATE UNIQUE INDEX IF NOT EXISTS memory_conflict_lifecycle_v1_ack_once_idx
    ON memory_conflict_lifecycle_events_v1 (tenant_id, project, conflict_id, episode_revision, actor)
    WHERE event_kind = 'acknowledged';
-- Bounded per-episode overlay reads.
CREATE INDEX IF NOT EXISTS memory_conflict_lifecycle_v1_episode_idx
    ON memory_conflict_lifecycle_events_v1
        (tenant_id, project, conflict_id, episode_revision, event_seq DESC)
    STORING (event_kind, result_revision, actor_kind, actor, operation, reason_kind,
             rationale, expires_at, review_by, member_count, created_at);

-- SQLx sends a multi-statement migration as one implicit transaction, and
-- this migration is registered no_tx, so there is no enclosing application
-- transaction. Commit the schema changes before inspecting the public catalog.
COMMIT;

-- Fail closed on same-name relation drift, as migrations 0018, 0020, 0024 and
-- 0027 do: IF NOT EXISTS would otherwise adopt an unrelated object that merely
-- shares the name. Pin the exact committed column shape and the three named
-- indexes, and stop on 55000 if either is not what this migration defines.
DO $$
DECLARE
    drifted STRING;
    index_count INT8;
BEGIN
    SELECT string_agg(expected.relation_name, ', ' ORDER BY expected.relation_name)
    INTO drifted
    FROM (VALUES
        ('memory_conflict_lifecycle_events_v1',
            'tenant_id:uuid:NO,project:text:NO,conflict_id:bigint:NO,event_seq:bigint:NO,event_kind:text:NO,episode_revision:bigint:NO,result_revision:bigint:NO,from_state:text:NO,to_state:text:NO,actor_kind:text:NO,actor:text:NO,session_id:text:YES,operation:text:NO,idempotency_key:text:NO,member_count:bigint:NO,reason_kind:text:YES,rationale:text:YES,expires_at:timestamp with time zone:YES,review_by:timestamp with time zone:YES,payload:jsonb:NO,created_at:timestamp with time zone:NO')
    ) AS expected (relation_name, column_shape)
    WHERE expected.column_shape IS DISTINCT FROM (
        SELECT string_agg(
            column_object.column_name || ':' || column_object.data_type
                || ':' || column_object.is_nullable,
            ','
            ORDER BY column_object.ordinal_position
        )
        FROM information_schema.columns AS column_object
        WHERE column_object.table_schema = 'public'
          AND column_object.table_name = expected.relation_name
    );

    SELECT count(DISTINCT indexname) INTO index_count
    FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'memory_conflict_lifecycle_events_v1'
      AND indexname IN ('memory_conflict_lifecycle_v1_mutation_idx',
                        'memory_conflict_lifecycle_v1_ack_once_idx',
                        'memory_conflict_lifecycle_v1_episode_idx');

    IF drifted IS NOT NULL OR index_count <> 3 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'migration 0029 same-name relation drift: '
                || COALESCE(drifted, 'lifecycle index set');
    END IF;
END
$$;
