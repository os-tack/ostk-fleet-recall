-- no-transaction
-- Authenticated private ingress (ADR 0008 D12): the durable hint queue of
-- signed provider webhooks.
--
-- A row carries provider ids and digests only, never content: the signed id
-- of the delivery, the digest and length of its raw body, what it named (an
-- upsert or a delete of one provider object), and where it stands in the
-- queue. The receiver (`ostk-fleet-recall ingress`, logging in as a member of
-- fleet_ingress_receiver) inserts; the worker's `collect` step settles a hint
-- only in the transaction that stages what it caused, which is the queue's
-- acknowledgement. A delivery the receiver ignores (a direct message, an event
-- the collectors do not read) or answers (Slack's URL verification) is kept
-- with no queue state, so a replay of it is still recognized.
--
-- Migrations 0001-0035 stay byte-identical. The table has no foreign key and
-- is never granted to the publication reader. Like migrations 0018 onward,
-- this DDL runs outside SQLx's transaction wrapper, so every object is
-- created with IF NOT EXISTS and an interrupted run resumes.
CREATE TABLE IF NOT EXISTS memory_ingress_deliveries_v1 (
    tenant_id              UUID NOT NULL,
    project                STRING NOT NULL,
    collector_instance_id  STRING NOT NULL,
    delivery_key           BYTES NOT NULL,
    provider               STRING NOT NULL,
    delivery_id            BYTES NOT NULL,
    raw_body_sha256        BYTES NOT NULL,
    raw_body_bytes         INT8 NOT NULL,
    event_kind             STRING NOT NULL,
    disposition            STRING NOT NULL,
    hint_kind              STRING NULL,
    object_kind            STRING NULL,
    external_id            STRING NULL,
    container_id           STRING NULL,
    provider_event_at      TIMESTAMPTZ NULL,
    state                  STRING NOT NULL,
    attempts               INT8 NOT NULL,
    next_attempt_at        TIMESTAMPTZ NULL,
    settled_at             TIMESTAMPTZ NULL,
    last_error             STRING NULL,
    received_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, collector_instance_id, delivery_key),
    CONSTRAINT memory_ingress_delivery_shape
        CHECK (octet_length(delivery_key) = 32 AND octet_length(raw_body_sha256) = 32
               AND octet_length(delivery_id) BETWEEN 1 AND 64 AND raw_body_bytes >= 0
               AND octet_length(event_kind) BETWEEN 1 AND 64
               AND (external_id IS NULL OR octet_length(external_id) BETWEEN 1 AND 1024)
               AND (container_id IS NULL OR octet_length(container_id) BETWEEN 1 AND 256)
               AND (last_error IS NULL OR octet_length(last_error) <= 512)),
    CONSTRAINT memory_ingress_delivery_disposition CHECK (disposition IN ('hint', 'ignored', 'challenge')),
    CONSTRAINT memory_ingress_delivery_hint
        CHECK ((disposition = 'hint') = (hint_kind IS NOT NULL AND object_kind IS NOT NULL AND external_id IS NOT NULL)),
    CONSTRAINT memory_ingress_delivery_hint_kind CHECK (hint_kind IS NULL OR hint_kind IN ('upsert', 'delete')),
    CONSTRAINT memory_ingress_delivery_state CHECK (state IN ('none', 'pending', 'settled', 'dead')),
    CONSTRAINT memory_ingress_delivery_queue CHECK ((disposition = 'hint') = (state <> 'none')),
    CONSTRAINT memory_ingress_delivery_settled CHECK ((state IN ('settled', 'dead')) = (settled_at IS NOT NULL)),
    CONSTRAINT memory_ingress_delivery_attempts CHECK (attempts BETWEEN 0 AND 8)
);
CREATE INDEX IF NOT EXISTS memory_ingress_deliveries_queue_idx
    ON memory_ingress_deliveries_v1 (tenant_id, project, state, collector_instance_id, next_attempt_at);

COMMIT;

-- Fail closed on drift, as migrations 0032 through 0035 do: IF NOT EXISTS would
-- otherwise adopt a same-name table of another definition, and a rerun over a
-- hand-edited catalog must not record success.
DO $$
DECLARE
    drifted STRING;
BEGIN
    SELECT string_agg(expected.relation_name, ', ')
    INTO drifted
    FROM (VALUES
        ('memory_ingress_deliveries_v1',
            'tenant_id:uuid:NO,project:text:NO,collector_instance_id:text:NO,delivery_key:bytea:NO,provider:text:NO,delivery_id:bytea:NO,raw_body_sha256:bytea:NO,raw_body_bytes:bigint:NO,event_kind:text:NO,disposition:text:NO,hint_kind:text:YES,object_kind:text:YES,external_id:text:YES,container_id:text:YES,provider_event_at:timestamp with time zone:YES,state:text:NO,attempts:bigint:NO,next_attempt_at:timestamp with time zone:YES,settled_at:timestamp with time zone:YES,last_error:text:YES,received_at:timestamp with time zone:NO')
    ) AS expected (relation_name, column_shape)
    WHERE expected.column_shape IS DISTINCT FROM (
        SELECT string_agg(column_object.column_name || ':' || column_object.data_type
                          || ':' || column_object.is_nullable, ',' ORDER BY column_object.ordinal_position)
        FROM information_schema.columns AS column_object
        WHERE column_object.table_schema = 'public' AND column_object.table_name = expected.relation_name
    );

    IF drifted IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'migration 0036 same-name relation drift: ' || drifted;
    END IF;
END
$$;
