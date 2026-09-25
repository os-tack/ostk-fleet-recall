-- no-transaction
-- Collected items (ADR 0008 D4-D6). The generic staging sink, the append-only
-- item history, the current-view heads, item links, container audiences,
-- collector status, per-container cursors, and digest-only dead letters.
-- Migrations 0001 through 0032 remain byte-identical; version 25 remains the
-- permanent gap.
--
-- Like migrations 0018 onward, this DDL runs outside SQLx's transaction
-- wrapper, so every object is created with IF NOT EXISTS and a process death
-- between the schema change and SQLx's history row is resumable.
--
-- No table has a foreign key, and none is ever granted to the publication
-- reader (PUBLIC-02/03). Every row is keyed by the physical (tenant_id,
-- project) scope first.

-- Ownership: fleet_migrator. The staging outbox: one row per staged part of
-- one item version read through one channel. stage_id is the envelope's
-- immutable revision, so re-staging an unchanged part is a primary-key no-op.
-- The canonical envelope (redacted text) is held only while the row is
-- pending; settling a row sets it to NULL, and envelope_sha256 remains.
CREATE TABLE IF NOT EXISTS memory_collector_outbox_v1 (
    tenant_id              UUID NOT NULL,
    project                STRING NOT NULL,
    stage_id               BYTES NOT NULL,
    collector_instance_id  STRING NOT NULL,
    principal_id           STRING NOT NULL,
    collection_mode        STRING NOT NULL,
    attester_principal_id  STRING NULL,
    provider               STRING NOT NULL,
    provider_scope_id      STRING NOT NULL,
    item_key_digest        BYTES NOT NULL,
    version_key_digest     BYTES NOT NULL,
    container_key          BYTES NULL,
    part_ordinal           INT8 NOT NULL,
    part_count             INT8 NOT NULL,
    provider_order         INT8 NOT NULL,
    pass_seq               INT8 NULL,
    canonical_envelope     BYTES NULL,
    envelope_sha256        BYTES NOT NULL,
    delivery_id            BYTES NOT NULL,
    occurred_at            TIMESTAMPTZ NOT NULL,
    observed_at            TIMESTAMPTZ NOT NULL,
    received_at            TIMESTAMPTZ NOT NULL,
    state                  STRING NOT NULL,
    accepted_event_id      BYTES NULL,
    quarantine_id          BYTES NULL,
    attempts               INT8 NOT NULL,
    last_error             STRING NULL,
    created_at             TIMESTAMPTZ NOT NULL,
    settled_at             TIMESTAMPTZ NULL,
    PRIMARY KEY (tenant_id, project, stage_id),
    CONSTRAINT memory_collector_outbox_project_bound CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_collector_outbox_instance_bound
        CHECK (octet_length(collector_instance_id) BETWEEN 1 AND 128 AND octet_length(principal_id) BETWEEN 1 AND 128),
    CONSTRAINT memory_collector_outbox_digest_shape
        CHECK (octet_length(stage_id) = 32 AND octet_length(item_key_digest) = 32
               AND octet_length(version_key_digest) = 32 AND octet_length(envelope_sha256) = 32
               AND (container_key IS NULL OR octet_length(container_key) = 32)),
    CONSTRAINT memory_collector_outbox_mode CHECK (collection_mode IN ('pull', 'push', 'capture', 'import')),
    CONSTRAINT memory_collector_outbox_attester
        CHECK ((collection_mode = 'capture') = (attester_principal_id IS NOT NULL)),
    CONSTRAINT memory_collector_outbox_provider
        CHECK (provider ~ '^[a-z][a-z0-9_-]{0,31}$' AND octet_length(provider_scope_id) BETWEEN 1 AND 256),
    CONSTRAINT memory_collector_outbox_part
        CHECK (part_count BETWEEN 1 AND 64 AND part_ordinal >= 0 AND part_ordinal < part_count),
    CONSTRAINT memory_collector_outbox_order CHECK (provider_order >= 0),
    CONSTRAINT memory_collector_outbox_envelope_bound
        CHECK (canonical_envelope IS NULL OR octet_length(canonical_envelope) BETWEEN 1 AND 1048548),
    CONSTRAINT memory_collector_outbox_delivery_bound CHECK (octet_length(delivery_id) BETWEEN 1 AND 64),
    CONSTRAINT memory_collector_outbox_clock_order CHECK (occurred_at <= observed_at AND observed_at <= received_at),
    CONSTRAINT memory_collector_outbox_state CHECK (state IN ('pending', 'admitted', 'quarantined', 'dead_lettered')),
    CONSTRAINT memory_collector_outbox_envelope_iff_pending CHECK ((state = 'pending') = (canonical_envelope IS NOT NULL)),
    CONSTRAINT memory_collector_outbox_settled CHECK ((state = 'pending') = (settled_at IS NULL)),
    CONSTRAINT memory_collector_outbox_admitted CHECK ((state = 'admitted') = (accepted_event_id IS NOT NULL)),
    CONSTRAINT memory_collector_outbox_quarantined CHECK ((state = 'quarantined') = (quarantine_id IS NOT NULL)),
    CONSTRAINT memory_collector_outbox_attempts CHECK (attempts BETWEEN 0 AND 8),
    CONSTRAINT memory_collector_outbox_error_bound CHECK (last_error IS NULL OR octet_length(last_error) <= 512)
);
CREATE INDEX IF NOT EXISTS memory_collector_outbox_state_idx
    ON memory_collector_outbox_v1 (tenant_id, project, state, created_at, stage_id);
CREATE INDEX IF NOT EXISTS memory_collector_outbox_item_idx
    ON memory_collector_outbox_v1 (tenant_id, project, item_key_digest, state);

-- Append-only item history: one row per admitted part, keyed by the accepted
-- evidence event that admitted it. Older versions stay here after an edit or
-- a delete; the heads below decide what is current.
CREATE TABLE IF NOT EXISTS memory_collected_items_v1 (
    tenant_id                UUID NOT NULL,
    project                  STRING NOT NULL,
    accepted_event_id        BYTES NOT NULL,
    stage_id                 BYTES NOT NULL,
    item_key_digest          BYTES NOT NULL,
    version_key_digest       BYTES NOT NULL,
    part_ordinal             INT8 NOT NULL,
    part_count               INT8 NOT NULL,
    provider                 STRING NOT NULL,
    provider_scope_id        STRING NOT NULL,
    object_kind              STRING NOT NULL,
    external_id              STRING NOT NULL,
    collection_mode          STRING NOT NULL,
    trust_tier               STRING NOT NULL,
    collector_instance_id    STRING NOT NULL,
    attester_principal_id    STRING NULL,
    lifecycle                STRING NOT NULL,
    version_marker           STRING NOT NULL,
    provider_order           INT8 NOT NULL,
    redaction_profile        INT8 NOT NULL,
    container_key            BYTES NULL,
    thread_root_external_id  STRING NULL,
    author_id                STRING NULL,
    author_kind              STRING NULL,
    provider_created_at      TIMESTAMPTZ NULL,
    provider_updated_at      TIMESTAMPTZ NULL,
    provider_url             STRING NULL,
    canonical_resource_id    STRING NOT NULL,
    body_content_id          BYTES NOT NULL,
    content_digest           BYTES NOT NULL,
    audience_basis           STRING NOT NULL,
    admitted_at              TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, accepted_event_id),
    CONSTRAINT memory_collected_item_project_bound CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_collected_item_digest_shape
        CHECK (octet_length(accepted_event_id) = 32 AND octet_length(stage_id) = 32
               AND octet_length(item_key_digest) = 32 AND octet_length(version_key_digest) = 32
               AND octet_length(body_content_id) = 32 AND octet_length(content_digest) = 32
               AND (container_key IS NULL OR octet_length(container_key) = 32)),
    CONSTRAINT memory_collected_item_part CHECK (part_count BETWEEN 1 AND 64 AND part_ordinal BETWEEN 0 AND part_count - 1),
    CONSTRAINT memory_collected_item_identity_bound
        CHECK (octet_length(provider_scope_id) BETWEEN 1 AND 256 AND octet_length(object_kind) BETWEEN 1 AND 64
               AND octet_length(external_id) BETWEEN 1 AND 1024 AND octet_length(version_marker) BETWEEN 1 AND 256
               AND octet_length(canonical_resource_id) BETWEEN 1 AND 256
               AND (provider_url IS NULL OR octet_length(provider_url) <= 2048)),
    CONSTRAINT memory_collected_item_mode CHECK (collection_mode IN ('pull', 'push', 'capture', 'import')),
    CONSTRAINT memory_collected_item_tier
        CHECK (trust_tier = CASE WHEN collection_mode IN ('pull', 'push') THEN 'verified' ELSE 'reported' END),
    CONSTRAINT memory_collected_item_lifecycle
        CHECK (lifecycle IN ('live', 'edited', 'archived', 'deleted', 'trashed', 'revoked')),
    CONSTRAINT memory_collected_item_audience
        CHECK (audience_basis IN ('provider_public', 'team_public', 'operator_declared',
                                  'verified_container', 'operator_capture_scope'))
);
CREATE INDEX IF NOT EXISTS memory_collected_items_version_idx
    ON memory_collected_items_v1 (tenant_id, project, item_key_digest, version_key_digest, part_ordinal);
CREATE INDEX IF NOT EXISTS memory_collected_items_body_idx
    ON memory_collected_items_v1 (tenant_id, project, body_content_id) STORING (item_key_digest, container_key);
CREATE INDEX IF NOT EXISTS memory_collected_items_url_idx
    ON memory_collected_items_v1 (tenant_id, project, provider_url);

-- The current view: one head per (item, trust tier). A version becomes a head
-- only once every part is admitted, and a head moves only to a greater
-- (provider_order, redaction_profile). Exactly one row per item is presented:
-- the verified head when one exists, else the reported head.
CREATE TABLE IF NOT EXISTS memory_collected_item_heads_v1 (
    tenant_id              UUID NOT NULL,
    project                STRING NOT NULL,
    item_key_digest        BYTES NOT NULL,
    trust_tier             STRING NOT NULL,
    presented              BOOL NOT NULL,
    provider               STRING NOT NULL,
    provider_scope_id      STRING NOT NULL,
    object_kind            STRING NOT NULL,
    external_id            STRING NOT NULL,
    container_key          BYTES NULL,
    version_key_digest     BYTES NOT NULL,
    content_digest         BYTES NOT NULL,
    provider_order         INT8 NOT NULL,
    redaction_profile      INT8 NOT NULL,
    lifecycle              STRING NOT NULL,
    part_count             INT8 NOT NULL,
    version_count          INT8 NOT NULL,
    order_ties             INT8 NOT NULL,
    disagreement           BOOL NOT NULL,
    last_accepted_event_id BYTES NOT NULL,
    revision               INT8 NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, item_key_digest, trust_tier),
    CONSTRAINT memory_collected_head_tier CHECK (trust_tier IN ('verified', 'reported')),
    CONSTRAINT memory_collected_head_lifecycle
        CHECK (lifecycle IN ('live', 'edited', 'archived', 'deleted', 'trashed', 'revoked')),
    CONSTRAINT memory_collected_head_shape
        CHECK (octet_length(item_key_digest) = 32 AND octet_length(version_key_digest) = 32
               AND octet_length(content_digest) = 32 AND octet_length(last_accepted_event_id) = 32
               AND (container_key IS NULL OR octet_length(container_key) = 32)),
    CONSTRAINT memory_collected_head_counts
        CHECK (part_count BETWEEN 1 AND 64 AND version_count >= 1 AND order_ties >= 0 AND revision >= 1),
    CONSTRAINT memory_collected_head_disagreement CHECK (NOT disagreement OR presented)
);
CREATE UNIQUE INDEX IF NOT EXISTS memory_collected_item_heads_presented_idx
    ON memory_collected_item_heads_v1 (tenant_id, project, item_key_digest) WHERE presented;
CREATE INDEX IF NOT EXISTS memory_collected_item_heads_scope_idx
    ON memory_collected_item_heads_v1 (tenant_id, project, provider, provider_scope_id, object_kind, lifecycle);

-- Outbound links of each admitted part, in the envelope's order.
CREATE TABLE IF NOT EXISTS memory_collected_item_links_v1 (
    tenant_id          UUID NOT NULL,
    project            STRING NOT NULL,
    accepted_event_id  BYTES NOT NULL,
    link_ordinal       INT8 NOT NULL,
    rel                STRING NOT NULL,
    target             STRING NOT NULL,
    PRIMARY KEY (tenant_id, project, accepted_event_id, link_ordinal),
    CONSTRAINT memory_collected_item_link_shape
        CHECK (octet_length(accepted_event_id) = 32 AND link_ordinal BETWEEN 0 AND 63
               AND octet_length(rel) BETWEEN 1 AND 64 AND octet_length(target) BETWEEN 1 AND 2048)
);
CREATE INDEX IF NOT EXISTS memory_collected_item_links_target_idx
    ON memory_collected_item_links_v1 (tenant_id, project, target);

-- What a verified collector or an operator import recorded about a container:
-- the audience it was admitted on, and whether that audience still holds.
-- 'withdrawn' hides every item in the container at read time.
CREATE TABLE IF NOT EXISTS memory_collector_containers_v1 (
    tenant_id              UUID NOT NULL,
    project                STRING NOT NULL,
    container_key          BYTES NOT NULL,
    provider               STRING NOT NULL,
    provider_scope_id      STRING NOT NULL,
    container_kind         STRING NOT NULL,
    container_id           STRING NOT NULL,
    label                  STRING NULL,
    audience_basis         STRING NOT NULL,
    access                 STRING NOT NULL,
    observed_by_instance   STRING NOT NULL,
    observed_at            TIMESTAMPTZ NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, container_key),
    CONSTRAINT memory_collector_container_shape
        CHECK (octet_length(container_key) = 32 AND octet_length(container_id) BETWEEN 1 AND 256
               AND (label IS NULL OR octet_length(label) <= 256)),
    CONSTRAINT memory_collector_container_audience
        CHECK (audience_basis IN ('provider_public', 'team_public', 'operator_declared')),
    CONSTRAINT memory_collector_container_access CHECK (access IN ('ok', 'withdrawn'))
);

-- Collector status, kept apart from memory_worker_sources_v1 so the worker's
-- retirement and older binaries never see it. owner names the process that
-- maintains the row; only a reconciliation pass sets last_checked_at.
CREATE TABLE IF NOT EXISTS memory_collector_sources_v1 (
    tenant_id              UUID NOT NULL,
    project                STRING NOT NULL,
    collector_instance_id  STRING NOT NULL,
    provider               STRING NOT NULL,
    provider_scope_id      STRING NOT NULL,
    collection_mode        STRING NOT NULL,
    coverage_role          STRING NOT NULL,
    owner                  STRING NOT NULL,
    state                  STRING NOT NULL,
    stale_after_seconds    INT8 NOT NULL,
    last_outcome           STRING NOT NULL,
    last_attempt_at        TIMESTAMPTZ NOT NULL,
    last_checked_at        TIMESTAMPTZ NULL,
    last_error             STRING NULL,
    updated_at             TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, collector_instance_id),
    CONSTRAINT memory_collector_source_instance_bound CHECK (octet_length(collector_instance_id) BETWEEN 1 AND 128),
    CONSTRAINT memory_collector_source_mode CHECK (collection_mode IN ('pull', 'capture', 'import')),
    CONSTRAINT memory_collector_source_role CHECK (coverage_role IN ('live', 'snapshot', 'none')),
    CONSTRAINT memory_collector_source_owner CHECK (owner IN ('worker', 'import', 'capture')),
    CONSTRAINT memory_collector_source_state CHECK (state IN ('active', 'retired')),
    CONSTRAINT memory_collector_source_outcome CHECK (last_outcome IN ('ok', 'unchanged', 'failed')),
    CONSTRAINT memory_collector_source_stale_bound CHECK (stale_after_seconds BETWEEN 60 AND 31536000),
    CONSTRAINT memory_collector_source_error_bound CHECK (last_error IS NULL OR octet_length(last_error) <= 2048)
);

-- Resumable per-domain cursors. cursor_state is the collector's own opaque
-- bytes; it advances in the same transaction that stages what it read.
CREATE TABLE IF NOT EXISTS memory_collector_cursors_v1 (
    tenant_id              UUID NOT NULL,
    project                STRING NOT NULL,
    collector_instance_id  STRING NOT NULL,
    domain_key             STRING NOT NULL,
    cursor_state           BYTES NOT NULL,
    high_water_order       INT8 NULL,
    pass_seq               INT8 NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, collector_instance_id, domain_key),
    CONSTRAINT memory_collector_cursor_shape
        CHECK (octet_length(domain_key) BETWEEN 1 AND 256 AND octet_length(cursor_state) BETWEEN 1 AND 16384
               AND pass_seq >= 0 AND (high_water_order IS NULL OR high_water_order >= 0))
);

-- Dead letters hold digests, a closed reason, and a static diagnostic, never
-- content. dead_letter_id is a digest of (instance, reason, payload digest,
-- stage id), so recording the same refusal twice is a no-op.
CREATE TABLE IF NOT EXISTS memory_collector_dead_letters_v1 (
    tenant_id              UUID NOT NULL,
    project                STRING NOT NULL,
    dead_letter_id         BYTES NOT NULL,
    collector_instance_id  STRING NOT NULL,
    collection_mode        STRING NOT NULL,
    provider               STRING NOT NULL,
    reason                 STRING NOT NULL,
    stage_id               BYTES NULL,
    delivery_id            BYTES NULL,
    payload_digest         BYTES NOT NULL,
    diagnostic             STRING NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, dead_letter_id),
    CONSTRAINT memory_collector_dead_letter_shape
        CHECK (octet_length(dead_letter_id) = 32 AND octet_length(payload_digest) = 32
               AND (stage_id IS NULL OR octet_length(stage_id) = 32)
               AND (delivery_id IS NULL OR octet_length(delivery_id) BETWEEN 1 AND 64)
               AND octet_length(diagnostic) <= 512),
    CONSTRAINT memory_collector_dead_letter_mode CHECK (collection_mode IN ('pull', 'push', 'capture', 'import')),
    CONSTRAINT memory_collector_dead_letter_reason
        CHECK (reason IN ('parse_failed', 'validation_failed', 'redaction_withheld', 'audience_refused',
                          'oversize', 'clock_ahead', 'admission_refused', 'invalid_signature',
                          'stale_signature', 'unauthorized_scope', 'retry_exhausted', 'fetch_failed'))
);
CREATE INDEX IF NOT EXISTS memory_collector_dead_letters_time_idx
    ON memory_collector_dead_letters_v1 (tenant_id, project, created_at);

-- SQLx sends a multi-statement migration as one implicit transaction, and
-- this migration is registered no_tx, so there is no enclosing application
-- transaction. Commit the schema changes before inspecting the public catalog.
COMMIT;

-- Fail closed on same-name relation drift, as migrations 0018 through 0031
-- do: IF NOT EXISTS would otherwise adopt an unrelated object that merely
-- shares the name. Pin the exact committed column shape of every table and
-- the partial unique index that keeps one presented head per item, and stop
-- on 55000 if either is not what this migration defines.
DO $$
DECLARE
    drifted STRING;
    presented_index_count INT8;
BEGIN
    SELECT string_agg(expected.relation_name, ', ' ORDER BY expected.relation_name)
    INTO drifted
    FROM (VALUES
        ('memory_collector_outbox_v1',
            'tenant_id:uuid:NO,project:text:NO,stage_id:bytea:NO,collector_instance_id:text:NO,principal_id:text:NO,collection_mode:text:NO,attester_principal_id:text:YES,provider:text:NO,provider_scope_id:text:NO,item_key_digest:bytea:NO,version_key_digest:bytea:NO,container_key:bytea:YES,part_ordinal:bigint:NO,part_count:bigint:NO,provider_order:bigint:NO,pass_seq:bigint:YES,canonical_envelope:bytea:YES,envelope_sha256:bytea:NO,delivery_id:bytea:NO,occurred_at:timestamp with time zone:NO,observed_at:timestamp with time zone:NO,received_at:timestamp with time zone:NO,state:text:NO,accepted_event_id:bytea:YES,quarantine_id:bytea:YES,attempts:bigint:NO,last_error:text:YES,created_at:timestamp with time zone:NO,settled_at:timestamp with time zone:YES'),
        ('memory_collected_items_v1',
            'tenant_id:uuid:NO,project:text:NO,accepted_event_id:bytea:NO,stage_id:bytea:NO,item_key_digest:bytea:NO,version_key_digest:bytea:NO,part_ordinal:bigint:NO,part_count:bigint:NO,provider:text:NO,provider_scope_id:text:NO,object_kind:text:NO,external_id:text:NO,collection_mode:text:NO,trust_tier:text:NO,collector_instance_id:text:NO,attester_principal_id:text:YES,lifecycle:text:NO,version_marker:text:NO,provider_order:bigint:NO,redaction_profile:bigint:NO,container_key:bytea:YES,thread_root_external_id:text:YES,author_id:text:YES,author_kind:text:YES,provider_created_at:timestamp with time zone:YES,provider_updated_at:timestamp with time zone:YES,provider_url:text:YES,canonical_resource_id:text:NO,body_content_id:bytea:NO,content_digest:bytea:NO,audience_basis:text:NO,admitted_at:timestamp with time zone:NO'),
        ('memory_collected_item_heads_v1',
            'tenant_id:uuid:NO,project:text:NO,item_key_digest:bytea:NO,trust_tier:text:NO,presented:boolean:NO,provider:text:NO,provider_scope_id:text:NO,object_kind:text:NO,external_id:text:NO,container_key:bytea:YES,version_key_digest:bytea:NO,content_digest:bytea:NO,provider_order:bigint:NO,redaction_profile:bigint:NO,lifecycle:text:NO,part_count:bigint:NO,version_count:bigint:NO,order_ties:bigint:NO,disagreement:boolean:NO,last_accepted_event_id:bytea:NO,revision:bigint:NO,updated_at:timestamp with time zone:NO'),
        ('memory_collected_item_links_v1',
            'tenant_id:uuid:NO,project:text:NO,accepted_event_id:bytea:NO,link_ordinal:bigint:NO,rel:text:NO,target:text:NO'),
        ('memory_collector_containers_v1',
            'tenant_id:uuid:NO,project:text:NO,container_key:bytea:NO,provider:text:NO,provider_scope_id:text:NO,container_kind:text:NO,container_id:text:NO,label:text:YES,audience_basis:text:NO,access:text:NO,observed_by_instance:text:NO,observed_at:timestamp with time zone:NO,updated_at:timestamp with time zone:NO'),
        ('memory_collector_sources_v1',
            'tenant_id:uuid:NO,project:text:NO,collector_instance_id:text:NO,provider:text:NO,provider_scope_id:text:NO,collection_mode:text:NO,coverage_role:text:NO,owner:text:NO,state:text:NO,stale_after_seconds:bigint:NO,last_outcome:text:NO,last_attempt_at:timestamp with time zone:NO,last_checked_at:timestamp with time zone:YES,last_error:text:YES,updated_at:timestamp with time zone:NO'),
        ('memory_collector_cursors_v1',
            'tenant_id:uuid:NO,project:text:NO,collector_instance_id:text:NO,domain_key:text:NO,cursor_state:bytea:NO,high_water_order:bigint:YES,pass_seq:bigint:NO,updated_at:timestamp with time zone:NO'),
        ('memory_collector_dead_letters_v1',
            'tenant_id:uuid:NO,project:text:NO,dead_letter_id:bytea:NO,collector_instance_id:text:NO,collection_mode:text:NO,provider:text:NO,reason:text:NO,stage_id:bytea:YES,delivery_id:bytea:YES,payload_digest:bytea:NO,diagnostic:text:NO,created_at:timestamp with time zone:NO')
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

    SELECT count(*) INTO presented_index_count
    FROM pg_catalog.pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'memory_collected_item_heads_v1'
      AND indexname = 'memory_collected_item_heads_presented_idx'
      AND indexdef LIKE 'CREATE UNIQUE INDEX %(tenant_id ASC, project ASC, item_key_digest ASC) WHERE (presented)';

    IF drifted IS NOT NULL OR presented_index_count <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'migration 0033 same-name relation drift: '
                || COALESCE(drifted, 'presented head index');
    END IF;
END
$$;
