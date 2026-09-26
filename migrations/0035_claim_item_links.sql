-- no-transaction
-- Claim-to-item links (ADR 0008 D11). Private plane only; never a publication
-- table.
--
-- A claim cites a collected item through `remember(assert)`'s
-- `assertion.support_items` or a `record` support entry `{item: ...}`. Each
-- cited part's accepted evidence event gets one row here, keyed by the claim
-- and that event: `via = 'assert'` rows name the claim's own accepted event
-- (`claim_event_id`), `via = 'record'` rows share the random `link_id` that
-- the claim's opaque `memory_claim_support` row (`fleet.item`, `item-link`,
-- the link id in hex) names. The item, version, and part the event admitted
-- are copied so `recall(get, kind=item)` lists the claims that cite an item
-- and `recall(get, kind=claim)` expands the links, without the publication
-- reader ever seeing which item a claim cites.
--
-- Migrations 0001-0034 stay byte-identical. The table has no foreign key, is
-- append-only by privilege (SELECT and INSERT), and is never granted to the
-- publication reader. Like migrations 0018 onward, this DDL runs outside
-- SQLx's transaction wrapper, so every object is created with IF NOT EXISTS
-- and an interrupted run resumes.
CREATE TABLE IF NOT EXISTS memory_claim_item_links_v1 (
    tenant_id           UUID NOT NULL,
    project             STRING NOT NULL,
    claim_id            INT8 NOT NULL,
    support_event_id    BYTES NOT NULL,
    link_id             BYTES NOT NULL,
    via                 STRING NOT NULL,
    claim_event_id      BYTES NULL,
    item_key_digest     BYTES NOT NULL,
    version_key_digest  BYTES NOT NULL,
    part_ordinal        INT8 NOT NULL,
    relation            STRING NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, claim_id, support_event_id),
    CONSTRAINT memory_claim_item_link_shape
        CHECK (octet_length(support_event_id) = 32 AND octet_length(link_id) = 16
               AND octet_length(item_key_digest) = 32 AND octet_length(version_key_digest) = 32
               AND (claim_event_id IS NULL OR octet_length(claim_event_id) = 32)
               AND part_ordinal BETWEEN 0 AND 63 AND octet_length(relation) BETWEEN 1 AND 64),
    CONSTRAINT memory_claim_item_link_via CHECK (via IN ('assert', 'record')),
    CONSTRAINT memory_claim_item_link_event CHECK ((via = 'assert') = (claim_event_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS memory_claim_item_links_item_idx
    ON memory_claim_item_links_v1 (tenant_id, project, item_key_digest, created_at);
CREATE INDEX IF NOT EXISTS memory_claim_item_links_link_idx
    ON memory_claim_item_links_v1 (tenant_id, project, link_id);

COMMIT;

-- Fail closed on drift, as migrations 0032 through 0034 do: IF NOT EXISTS would
-- otherwise adopt a same-name table of another definition, and a rerun over a
-- hand-edited catalog must not record success.
DO $$
DECLARE
    drifted STRING;
BEGIN
    SELECT string_agg(expected.relation_name, ', ')
    INTO drifted
    FROM (VALUES
        ('memory_claim_item_links_v1',
            'tenant_id:uuid:NO,project:text:NO,claim_id:bigint:NO,support_event_id:bytea:NO,link_id:bytea:NO,via:text:NO,claim_event_id:bytea:YES,item_key_digest:bytea:NO,version_key_digest:bytea:NO,part_ordinal:bigint:NO,relation:text:NO,created_at:timestamp with time zone:NO')
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
            MESSAGE = 'migration 0035 same-name relation drift: ' || drifted;
    END IF;
END
$$;
