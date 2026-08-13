-- no-transaction
-- ostk-fleet-recall's durable CockroachDB substrate.
-- CockroachDB 26.2 vector-index builds require the declarative schema changer
-- and fail inside an explicit multi-statement transaction (SQLSTATE 0A000).
--
-- Scope columns lead every corpus access path. In particular, both vector
-- indexes require tenant_id and project equality predicates before CockroachDB
-- can use the ANN portion of the index.

-- A project has exactly one searchable embedding generation. Historical rows
-- may retain older models, but an active row cannot be inserted with a model
-- different from the registered generation. Changing models is therefore an
-- explicit evacuate/re-embed operation instead of a period of mixed vectors.
CREATE TABLE memory_corpus_models (
    tenant_id        UUID NOT NULL,
    project          STRING NOT NULL,
    embedding_model  STRING NOT NULL,
    dimension        INT4 NOT NULL DEFAULT 512 CHECK (dimension = 512),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project),
    UNIQUE (tenant_id, project, embedding_model)
);

CREATE TABLE memory_chunks (
    tenant_id                 UUID NOT NULL,
    project                   STRING NOT NULL,
    chunk_id                  STRING NOT NULL,
    source                    STRING NOT NULL,
    source_id                 STRING NOT NULL,
    source_config_id          STRING NOT NULL DEFAULT '',
    chunk_index               INT8 NOT NULL CHECK (chunk_index >= 0),
    source_timestamp          TIMESTAMPTZ,
    role                      STRING,
    text                      STRING NOT NULL,
    search_document           TSVECTOR AS (to_tsvector('english', text)) STORED,
    content_sha256            STRING NOT NULL,
    embedding_input_sha256    STRING NOT NULL,
    embedding_model           STRING NOT NULL,
    embedding                 VECTOR(512) NOT NULL,
    facets                    JSONB NOT NULL DEFAULT '{}'::JSONB,
    links                     JSONB NOT NULL DEFAULT '{}'::JSONB,
    extra                     JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, chunk_id),
    CONSTRAINT memory_chunks_model_fk
        FOREIGN KEY (tenant_id, project, embedding_model)
        REFERENCES memory_corpus_models (tenant_id, project, embedding_model)
);

CREATE VECTOR INDEX memory_chunks_semantic_idx
    ON memory_chunks (tenant_id, project, embedding vector_cosine_ops);

-- Recall's hybrid engine performs a source-stratified dense top-up for code.
-- Source is therefore an equality prefix in a second ANN index, avoiding an
-- approximate post-filter for that canonical path.
CREATE VECTOR INDEX memory_chunks_source_semantic_idx
    ON memory_chunks (tenant_id, project, source, embedding vector_cosine_ops);

CREATE INVERTED INDEX memory_chunks_lexical_idx
    ON memory_chunks (tenant_id, project, search_document);

CREATE INDEX memory_chunks_source_idx
    ON memory_chunks (tenant_id, project, source, source_timestamp DESC);

-- Retained rows that are ineligible for recall (stale source projections and
-- lossless transcript archive parents) live outside the ANN hot table. This
-- physical invariant lets the active dense query contain only equality-bound
-- vector-index prefix columns, which CockroachDB 26.2 requires for C-SPANN.
CREATE TABLE memory_chunk_history (
    tenant_id                 UUID NOT NULL,
    project                   STRING NOT NULL,
    chunk_id                  STRING NOT NULL,
    source                    STRING NOT NULL,
    source_id                 STRING NOT NULL,
    source_config_id          STRING NOT NULL DEFAULT '',
    chunk_index               INT8 NOT NULL CHECK (chunk_index >= 0),
    source_timestamp          TIMESTAMPTZ,
    role                      STRING,
    text                      STRING NOT NULL,
    content_sha256            STRING NOT NULL,
    embedding_input_sha256    STRING NOT NULL,
    embedding_model           STRING NOT NULL,
    embedding                 VECTOR(512) NOT NULL,
    facets                    JSONB NOT NULL DEFAULT '{}'::JSONB,
    links                     JSONB NOT NULL DEFAULT '{}'::JSONB,
    extra                     JSONB NOT NULL DEFAULT '{}'::JSONB,
    history_reason            STRING NOT NULL CHECK (history_reason IN ('stale', 'archive_parent')),
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, chunk_id)
);

CREATE INDEX memory_chunk_history_source_idx
    ON memory_chunk_history (tenant_id, project, source, source_timestamp DESC);

CREATE SEQUENCE memory_claim_id_seq START 1 MINVALUE 1 MAXVALUE 9007199254740991;
CREATE SEQUENCE memory_claim_support_id_seq START 1 MINVALUE 1 MAXVALUE 9007199254740991;
CREATE SEQUENCE memory_conflict_id_seq START 1 MINVALUE 1 MAXVALUE 9007199254740991;
CREATE SEQUENCE memory_claim_link_id_seq START 1 MINVALUE 1 MAXVALUE 9007199254740991;

-- Durable, correctable assertions. The vocabulary intentionally mirrors
-- ostk-recall's MemoryClaim so its numeric public IDs remain compatible.
CREATE TABLE memory_claims (
    tenant_id          UUID NOT NULL,
    project            STRING NOT NULL,
    id                 INT8 NOT NULL DEFAULT nextval('memory_claim_id_seq')
                       CHECK (id BETWEEN 1 AND 9007199254740991),
    kind               STRING NOT NULL CHECK (kind IN (
                           'observation', 'note', 'fact', 'decision',
                           'constraint', 'preference', 'procedure', 'open_question'
                       )),
    claim_key          STRING,
    subject            STRING,
    predicate          STRING,
    value              JSONB,
    text               STRING NOT NULL,
    polarity           INT2 NOT NULL DEFAULT 1 CHECK (polarity IN (-1, 1)),
    state              STRING NOT NULL DEFAULT 'active' CHECK (state IN (
                           'active', 'disputed', 'unsupported', 'superseded',
                           'retracted', 'suppressed', 'expired'
                       )),
    origin             STRING NOT NULL DEFAULT 'operator_asserted'
                       CHECK (origin IN (
                           'operator_asserted', 'source_derived', 'legacy_unverified'
                       )),
    actor              STRING,
    confidence         FLOAT8 NOT NULL DEFAULT 1.0
                       CHECK (confidence >= 0.0 AND confidence <= 1.0),
    valid_from         TIMESTAMPTZ,
    valid_to           TIMESTAMPTZ,
    superseded_by      INT8,
    revision           INT8 NOT NULL DEFAULT 1 CHECK (revision > 0),
    conflict_eligible  BOOL NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, id),
    CONSTRAINT memory_claim_validity CHECK (
        valid_from IS NULL OR valid_to IS NULL OR valid_to > valid_from
    ),
    CONSTRAINT memory_claim_conflict_eligibility CHECK (
        NOT conflict_eligible OR (
            claim_key IS NOT NULL
            AND value IS NOT NULL
            AND kind IN ('fact', 'decision', 'constraint', 'preference', 'procedure')
        )
    ),
    CONSTRAINT memory_claim_superseded_by_fk
        FOREIGN KEY (tenant_id, project, superseded_by)
        REFERENCES memory_claims (tenant_id, project, id)
);

CREATE INDEX memory_claims_scope_key_idx
    ON memory_claims (tenant_id, project, claim_key, state);

CREATE INDEX memory_claims_scope_state_idx
    ON memory_claims (tenant_id, project, state, updated_at DESC);

CREATE TABLE memory_claim_support (
    tenant_id          UUID NOT NULL,
    project            STRING NOT NULL,
    id                 INT8 NOT NULL DEFAULT nextval('memory_claim_support_id_seq')
                       CHECK (id BETWEEN 1 AND 9007199254740991),
    claim_id           INT8 NOT NULL,
    source_config_id   STRING NOT NULL DEFAULT '',
    source             STRING NOT NULL,
    source_id          STRING NOT NULL,
    chunk_id           STRING,
    content_sha256     STRING,
    excerpt            STRING,
    relation           STRING NOT NULL DEFAULT 'supports',
    state              STRING NOT NULL DEFAULT 'current',
    observed_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    invalidated_at     TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, project, id),
    CONSTRAINT memory_claim_support_claim_fk
        FOREIGN KEY (tenant_id, project, claim_id)
        REFERENCES memory_claims (tenant_id, project, id) ON DELETE CASCADE,
    UNIQUE (tenant_id, project, claim_id, source_config_id, source, source_id, chunk_id, relation)
);

CREATE INDEX memory_claim_support_coordinate_idx
    ON memory_claim_support (tenant_id, project, source_config_id, source, source_id, state);

-- Passage-level vectors prevent long claims from being represented by one
-- diluted embedding while preserving the claim as the lifecycle unit.
CREATE TABLE memory_claim_embeddings (
    tenant_id       UUID NOT NULL,
    project         STRING NOT NULL,
    claim_id        INT8 NOT NULL,
    passage_index   INT4 NOT NULL CHECK (passage_index >= 0),
    passage_text    STRING NOT NULL,
    model           STRING NOT NULL,
    dim             INT4 NOT NULL DEFAULT 512 CHECK (dim = 512),
    vector          VECTOR(512) NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, claim_id, passage_index),
    CONSTRAINT memory_claim_embeddings_claim_fk
        FOREIGN KEY (tenant_id, project, claim_id)
        REFERENCES memory_claims (tenant_id, project, id) ON DELETE CASCADE
);

CREATE VECTOR INDEX memory_claim_embeddings_semantic_idx
    ON memory_claim_embeddings (tenant_id, project, model, vector vector_cosine_ops);

CREATE TABLE memory_claim_events (
    tenant_id       UUID NOT NULL,
    project         STRING NOT NULL,
    event_id        UUID NOT NULL DEFAULT gen_random_uuid(),
    claim_id        INT8 NOT NULL,
    event_kind      STRING NOT NULL,
    actor           STRING,
    reason          STRING,
    from_state      STRING,
    to_state        STRING,
    payload         JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, event_id),
    CONSTRAINT memory_claim_events_claim_fk
        FOREIGN KEY (tenant_id, project, claim_id)
        REFERENCES memory_claims (tenant_id, project, id) ON DELETE CASCADE
);

CREATE INDEX memory_claim_events_claim_idx
    ON memory_claim_events (tenant_id, project, claim_id, created_at DESC);

CREATE TABLE memory_conflicts (
    tenant_id          UUID NOT NULL,
    project            STRING NOT NULL,
    id                 INT8 NOT NULL DEFAULT nextval('memory_conflict_id_seq')
                       CHECK (id BETWEEN 1 AND 9007199254740991),
    claim_key          STRING NOT NULL,
    kind               STRING NOT NULL DEFAULT 'contradiction',
    state              STRING NOT NULL DEFAULT 'open'
                       CHECK (state IN ('open', 'resolved', 'dismissed')),
    detector           STRING NOT NULL DEFAULT 'same_key_typed_value',
    rationale          STRING NOT NULL,
    revision           INT8 NOT NULL DEFAULT 1 CHECK (revision > 0),
    detected_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at        TIMESTAMPTZ,
    resolution_kind    STRING,
    resolution_reason  STRING,
    PRIMARY KEY (tenant_id, project, id),
    UNIQUE (tenant_id, project, claim_key)
);

CREATE INDEX memory_conflicts_scope_state_idx
    ON memory_conflicts (tenant_id, project, state, last_seen_at DESC);

CREATE TABLE memory_conflict_members (
    tenant_id    UUID NOT NULL,
    project      STRING NOT NULL,
    conflict_id  INT8 NOT NULL,
    claim_id     INT8 NOT NULL,
    role         STRING NOT NULL DEFAULT 'claim',
    PRIMARY KEY (tenant_id, project, conflict_id, claim_id),
    CONSTRAINT memory_conflict_members_conflict_fk
        FOREIGN KEY (tenant_id, project, conflict_id)
        REFERENCES memory_conflicts (tenant_id, project, id) ON DELETE CASCADE,
    CONSTRAINT memory_conflict_members_claim_fk
        FOREIGN KEY (tenant_id, project, claim_id)
        REFERENCES memory_claims (tenant_id, project, id) ON DELETE CASCADE
);

-- Conflict summaries read by conflict_id through the primary key. Claim reads
-- need the inverse direction and must not scan every membership in a project.
CREATE INDEX memory_conflict_members_claim_idx
    ON memory_conflict_members (tenant_id, project, claim_id, conflict_id);

CREATE TABLE memory_claim_links (
    tenant_id       UUID NOT NULL,
    project         STRING NOT NULL,
    id              INT8 NOT NULL DEFAULT nextval('memory_claim_link_id_seq')
                    CHECK (id BETWEEN 1 AND 9007199254740991),
    from_claim_id   INT8 NOT NULL,
    to_claim_id     INT8 NOT NULL,
    relation        STRING NOT NULL CHECK (relation IN (
                        'part_of', 'continues', 'summarizes', 'derived_from',
                        'supports', 'elaborates'
                    )),
    state           STRING NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'removed')),
    actor           STRING,
    reason          STRING,
    evidence        JSONB,
    revision        INT8 NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    removed_at      TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, project, id),
    UNIQUE (tenant_id, project, from_claim_id, to_claim_id, relation),
    CHECK (from_claim_id <> to_claim_id),
    CONSTRAINT memory_claim_links_from_fk
        FOREIGN KEY (tenant_id, project, from_claim_id)
        REFERENCES memory_claims (tenant_id, project, id),
    CONSTRAINT memory_claim_links_to_fk
        FOREIGN KEY (tenant_id, project, to_claim_id)
        REFERENCES memory_claims (tenant_id, project, id)
);

CREATE INDEX memory_claim_links_from_idx
    ON memory_claim_links (tenant_id, project, from_claim_id, state, relation);

CREATE INDEX memory_claim_links_to_idx
    ON memory_claim_links (tenant_id, project, to_claim_id, state, relation);

CREATE TABLE memory_claim_link_events (
    tenant_id       UUID NOT NULL,
    project         STRING NOT NULL,
    event_id        UUID NOT NULL DEFAULT gen_random_uuid(),
    link_id         INT8 NOT NULL,
    event_kind      STRING NOT NULL,
    actor           STRING,
    reason          STRING,
    payload         JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, event_id),
    CONSTRAINT memory_claim_link_events_link_fk
        FOREIGN KEY (tenant_id, project, link_id)
        REFERENCES memory_claim_links (tenant_id, project, id) ON DELETE CASCADE
);

-- Idempotency keys are unique across an entire tenant, rather than only one
-- project, so retries cannot accidentally replay a mutation in another scope.
CREATE TABLE memory_mutation_receipts (
    tenant_id        UUID NOT NULL,
    idempotency_key  STRING NOT NULL,
    project          STRING NOT NULL,
    request          JSONB NOT NULL,
    operation        STRING NOT NULL,
    claim_id         INT8,
    conflict_id      INT8,
    link_id          INT8,
    response         JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, idempotency_key),
    CONSTRAINT memory_mutation_receipts_claim_fk
        FOREIGN KEY (tenant_id, project, claim_id)
        REFERENCES memory_claims (tenant_id, project, id),
    CONSTRAINT memory_mutation_receipts_conflict_fk
        FOREIGN KEY (tenant_id, project, conflict_id)
        REFERENCES memory_conflicts (tenant_id, project, id),
    CONSTRAINT memory_mutation_receipts_link_fk
        FOREIGN KEY (tenant_id, project, link_id)
        REFERENCES memory_claim_links (tenant_id, project, id)
);

-- Generic append-only events support fleet-wide audit, projection catch-up,
-- and later CDC without making changefeeds part of correctness.
CREATE TABLE memory_events (
    tenant_id       UUID NOT NULL,
    project         STRING NOT NULL,
    event_id        UUID NOT NULL DEFAULT gen_random_uuid(),
    agent            STRING NOT NULL,
    session_id       STRING,
    event_kind       STRING NOT NULL,
    entity_kind      STRING NOT NULL,
    entity_id        STRING NOT NULL,
    idempotency_key  STRING,
    payload           JSONB NOT NULL DEFAULT '{}'::JSONB,
    occurred_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, event_id)
);

CREATE INDEX memory_events_timeline_idx
    ON memory_events (tenant_id, project, occurred_at DESC, event_id);

CREATE UNIQUE INDEX memory_events_idempotency_idx
    ON memory_events (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- session_id uses an empty-string sentinel because primary-key columns are
-- non-nullable; it represents agent-wide attention outside a named session.
CREATE TABLE memory_attention (
    tenant_id        UUID NOT NULL,
    project          STRING NOT NULL,
    agent            STRING NOT NULL,
    session_id       STRING NOT NULL DEFAULT '',
    privacy_tier     STRING NOT NULL,
    focus_embedding  VECTOR(512),
    pins             JSONB NOT NULL DEFAULT '[]'::JSONB,
    state            JSONB NOT NULL DEFAULT '{}'::JSONB,
    revision         INT8 NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, agent, session_id)
);
