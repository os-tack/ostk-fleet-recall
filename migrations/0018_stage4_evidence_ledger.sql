-- no-transaction
-- Stage-4 runtime foundations. This migration implements exactly the
-- "Migration 0018 shape" section of docs/adr/0002-stage4-runtime-foundations.md
-- and adds no semantics that record does not fix.
--
-- CockroachDB 26.2 schema-locks existing tables, so the ALTER TABLE ADD COLUMN
-- steps below cannot share an explicit SQL transaction with SQLx's success-row
-- insert. This migration is therefore registered no_tx and runs in the third
-- (online) execution phase with autocommit_before_ddl enabled, exactly like
-- migrations 0015 through 0017.
--
-- Every object is created with IF NOT EXISTS so a process death between a
-- committed schema change and SQLx's history row is resumable. Every name is
-- part of the schema contract; do not rename an object to work around drift.
--
-- Migrations 0001 through 0017 remain byte-identical. Nothing here rewrites an
-- existing row, drops an object, or narrows an existing constraint.

-- Ownership: created and owned by fleet_migrator (the single-migrator
-- deployment job). ADR 0002 D1. Physical companion of
-- memory_control_shard_heads (0003) for the general accepted-event ledger.
-- The composite FK targets memory_control_log_epochs (tenant_id, project,
-- epoch_id, shard_count), so both physical ledgers share ONE genesis log epoch,
-- one partition recipe, one seed, and one shard count. UNIQUE (tenant_id,
-- project) on memory_control_log_epochs is untouched: the single-epoch
-- invariant stays literal. advanced_at carries no DEFAULT, mirroring migration
-- 0008: every audited head advance binds its acceptance clock explicitly.
CREATE TABLE IF NOT EXISTS memory_evidence_shard_heads (
    tenant_id                   UUID NOT NULL,
    project                     STRING NOT NULL,
    epoch_id                    BYTES NOT NULL,
    shard                       INT4 NOT NULL,
    shard_count                 INT4 NOT NULL,
    last_committed_offset       INT8 NOT NULL,
    chain_digest                BYTES NOT NULL,
    advanced_at                 TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, epoch_id, shard),
    CONSTRAINT memory_evidence_head_epoch_fk
        FOREIGN KEY (tenant_id, project, epoch_id, shard_count)
        REFERENCES memory_control_log_epochs (tenant_id, project, epoch_id, shard_count),
    CONSTRAINT memory_evidence_head_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_evidence_head_epoch_id_shape
        CHECK (octet_length(epoch_id) = 32),
    CONSTRAINT memory_evidence_head_shard_count_bound
        CHECK (shard_count BETWEEN 1 AND 4096),
    CONSTRAINT memory_evidence_head_shard_bound
        CHECK (shard >= 0 AND shard < shard_count),
    CONSTRAINT memory_evidence_head_offset_bound
        CHECK (last_committed_offset >= 0),
    CONSTRAINT memory_evidence_head_chain_digest_shape
        CHECK (octet_length(chain_digest) = 32)
);

-- Ownership: fleet_migrator. ADR 0002 D1. Structural mirror of
-- memory_control_events (0003) with the identical AppendPositionV1 algebra,
-- the identical append-chain recipe, and one shared event_kind /
-- consistency_family namespace.
--
-- The governance-exclusion CHECK is the D1 boundary made non-negotiable in the
-- engine: no bootstrap or registry-activation event can ever land in the
-- evidence ledger, whatever a compromised appender asks for. General kinds
-- symmetrically never enter memory_control_events, which is enforced by the
-- control ledger's separate role boundary.
--
-- As in migration 0005, the predecessor-unique index prevents two events in one
-- scoped shard from claiming the same chain predecessor. It does not make raw
-- INSERT a supported append API: a holder of direct event INSERT can still
-- plant an otherwise unique future offset and wedge that shard. The residual is
-- documented in ADR 0002 D2 (a compromised runtime can wedge its own evidence
-- shards, never the governance ledger); detection is the chain audit and the
-- remedy is a successor log epoch.
CREATE TABLE IF NOT EXISTS memory_evidence_events (
    tenant_id                    UUID NOT NULL,
    project                      STRING NOT NULL,
    epoch_id                     BYTES NOT NULL,
    shard                        INT4 NOT NULL,
    committed_offset             INT8 NOT NULL,
    event_id                     BYTES NOT NULL,
    event_schema_version         INT4 NOT NULL,
    event_kind                   STRING NOT NULL,
    semantic_object_digest       BYTES NOT NULL,
    consistency_family           STRING NOT NULL,
    consistency_key_digest       BYTES NOT NULL,
    canonical_event              BYTES NOT NULL,
    previous_chain_digest        BYTES NOT NULL,
    chain_digest                 BYTES NOT NULL,
    accepted_at                  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, epoch_id, shard, committed_offset),
    UNIQUE (tenant_id, project, event_id),
    CONSTRAINT memory_evidence_event_head_fk
        FOREIGN KEY (tenant_id, project, epoch_id, shard)
        REFERENCES memory_evidence_shard_heads (tenant_id, project, epoch_id, shard),
    CONSTRAINT memory_evidence_event_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_evidence_event_epoch_id_shape
        CHECK (octet_length(epoch_id) = 32),
    CONSTRAINT memory_evidence_event_shard_bound
        CHECK (shard BETWEEN 0 AND 4095),
    CONSTRAINT memory_evidence_event_offset_bound
        CHECK (committed_offset > 0),
    CONSTRAINT memory_evidence_event_id_shape
        CHECK (octet_length(event_id) = 32),
    CONSTRAINT memory_evidence_event_schema_version_bound
        CHECK (event_schema_version > 0),
    CONSTRAINT memory_evidence_event_kind_bound
        CHECK (octet_length(event_kind) BETWEEN 1 AND 128),
    CONSTRAINT memory_evidence_event_semantic_digest_shape
        CHECK (octet_length(semantic_object_digest) = 32),
    CONSTRAINT memory_evidence_event_consistency_family_bound
        CHECK (octet_length(consistency_family) BETWEEN 1 AND 128),
    CONSTRAINT memory_evidence_event_consistency_key_shape
        CHECK (octet_length(consistency_key_digest) = 32),
    CONSTRAINT memory_evidence_event_canonical_bound
        CHECK (octet_length(canonical_event) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_evidence_event_previous_chain_shape
        CHECK (octet_length(previous_chain_digest) = 32),
    CONSTRAINT memory_evidence_event_chain_shape
        CHECK (octet_length(chain_digest) = 32),
    CONSTRAINT memory_evidence_event_governance_exclusion
        CHECK (
            event_kind NOT IN (
                'control.bootstrap.accepted',
                'registry.genesis.activated',
                'registry.successor.activated'
            )
            AND consistency_family <> 'registry.activation'
        )
);

CREATE UNIQUE INDEX IF NOT EXISTS memory_evidence_events_predecessor_unique_idx
    ON memory_evidence_events (
        tenant_id,
        project,
        epoch_id,
        shard,
        previous_chain_digest
    );

-- Ownership: fleet_migrator. ADR 0002, migration-0018 shape (W0-QUAR record).
-- A quarantine row is a bounded integrity receipt, never a payload store: it
-- retains the canonical payload DIGEST and a bounded diagnostic excerpt only.
-- There is deliberately no payload column, so an EVENT-01 integrity collision
-- cannot become a second, ungoverned copy of untrusted provider bytes outside
-- the retention, visibility, and erasure machinery (EVID-05, EVID-08).
-- PRIMARY KEY (tenant_id, project, quarantine_id) is the per-scope quarantine
-- identity: exactly one row per quarantine ID within one tenant/project.
CREATE TABLE IF NOT EXISTS memory_evidence_quarantine (
    tenant_id                    UUID NOT NULL,
    project                      STRING NOT NULL,
    quarantine_id                BYTES NOT NULL,
    connector_principal_id       STRING NOT NULL,
    connector_instance_id        STRING NOT NULL,
    delivery_id                  STRING NOT NULL,
    attempt_count                INT4 NOT NULL,
    source_fact_id               BYTES,
    representation_key_digest    BYTES,
    canonical_payload_digest     BYTES NOT NULL,
    diagnostic                   BYTES NOT NULL,
    reason                       STRING NOT NULL,
    received_at                  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, quarantine_id),
    CONSTRAINT memory_evidence_quarantine_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_evidence_quarantine_id_shape
        CHECK (octet_length(quarantine_id) = 32),
    CONSTRAINT memory_evidence_quarantine_connector_bounds
        CHECK (
            octet_length(connector_principal_id) BETWEEN 1 AND 128
            AND octet_length(connector_instance_id) BETWEEN 1 AND 128
        ),
    CONSTRAINT memory_evidence_quarantine_delivery_bound
        CHECK (octet_length(delivery_id) BETWEEN 1 AND 256),
    CONSTRAINT memory_evidence_quarantine_attempt_bound
        CHECK (attempt_count BETWEEN 1 AND 1048576),
    CONSTRAINT memory_evidence_quarantine_source_fact_shape
        CHECK (source_fact_id IS NULL OR octet_length(source_fact_id) = 32),
    CONSTRAINT memory_evidence_quarantine_representation_shape
        CHECK (
            representation_key_digest IS NULL
            OR octet_length(representation_key_digest) = 32
        ),
    CONSTRAINT memory_evidence_quarantine_payload_digest_shape
        CHECK (octet_length(canonical_payload_digest) = 32),
    CONSTRAINT memory_evidence_quarantine_diagnostic_bound
        CHECK (octet_length(diagnostic) BETWEEN 1 AND 4096),
    CONSTRAINT memory_evidence_quarantine_reason_bound
        CHECK (octet_length(reason) BETWEEN 1 AND 512)
);

-- Ownership: fleet_migrator. ADR 0002 D5. Governed content store for the
-- GovernedContentIdentityV1 / ContentReferenceV1 pair: the semantic envelope
-- keeps no inline bytes and no storage locator, so storage_identity is the
-- physical key here.
--
-- Bytes are stored envelope-encrypted under a per-object DEK wrapped by a
-- config-provided KEK; the KEK never enters this table. Dropping wrapped_dek
-- is the cryptographic erasure primitive that EVID-08 requires while the
-- digest and lifecycle metadata survive. The four nullable erasure-index
-- columns are exactly the ErasureScopeKind axes (representation, source fact,
-- resource, privacy subject) so a composite erasure fence can address an object
-- by scope digest. No secondary index is created here: the access shape belongs
-- to W0-ERASE's tombstone/fence contract, and an index added before that
-- contract exists would freeze the wrong lane.
--
-- encrypted_bytes is bounded at 1 MiB, matching every other canonical byte
-- bound in this schema. A larger raw artifact belongs in the separate private
-- object archive with its own key, policy, and retention boundary; it is never
-- inlined here.
--
-- This table is NEVER one of the publication reader's eight tables; the
-- publication proof asserts that exclusion (PUBLIC-03, PUBLIC-04).
CREATE TABLE IF NOT EXISTS memory_content_objects (
    tenant_id                        UUID NOT NULL,
    project                          STRING NOT NULL,
    storage_identity                 BYTES NOT NULL,
    protection_domain_id             STRING NOT NULL,
    media_type                       STRING NOT NULL,
    byte_length                      INT8 NOT NULL,
    content_digest                   BYTES NOT NULL,
    retention_class                  STRING NOT NULL,
    retention_policy_entry_id        STRING NOT NULL,
    retention_policy_entry_version   INT4 NOT NULL,
    retention_policy_digest          BYTES NOT NULL,
    wrapped_dek                      BYTES NOT NULL,
    encrypted_bytes                  BYTES NOT NULL,
    erasure_representation_digest    BYTES,
    erasure_source_fact_digest       BYTES,
    erasure_resource_digest          BYTES,
    erasure_privacy_subject_digest   BYTES,
    created_at                       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, storage_identity),
    CONSTRAINT memory_content_object_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_content_object_storage_identity_shape
        CHECK (octet_length(storage_identity) = 32),
    CONSTRAINT memory_content_object_identity_bounds
        CHECK (
            octet_length(protection_domain_id) BETWEEN 1 AND 128
            AND octet_length(media_type) BETWEEN 1 AND 128
        ),
    CONSTRAINT memory_content_object_byte_length_bound
        CHECK (byte_length > 0),
    CONSTRAINT memory_content_object_content_digest_shape
        CHECK (octet_length(content_digest) = 32),
    CONSTRAINT memory_content_object_retention_class
        CHECK (retention_class IN ('ephemeral', 'governed', 'immutable')),
    CONSTRAINT memory_content_object_retention_policy_bounds
        CHECK (
            octet_length(retention_policy_entry_id) BETWEEN 1 AND 128
            AND retention_policy_entry_version > 0
            AND octet_length(retention_policy_digest) = 32
        ),
    CONSTRAINT memory_content_object_wrapped_dek_bound
        CHECK (octet_length(wrapped_dek) BETWEEN 1 AND 4096),
    CONSTRAINT memory_content_object_encrypted_bytes_bound
        CHECK (octet_length(encrypted_bytes) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_content_object_erasure_index_shapes
        CHECK (
            (
                erasure_representation_digest IS NULL
                OR octet_length(erasure_representation_digest) = 32
            )
            AND (
                erasure_source_fact_digest IS NULL
                OR octet_length(erasure_source_fact_digest) = 32
            )
            AND (
                erasure_resource_digest IS NULL
                OR octet_length(erasure_resource_digest) = 32
            )
            AND (
                erasure_privacy_subject_digest IS NULL
                OR octet_length(erasure_privacy_subject_digest) = 32
            )
        )
);

-- Ownership: fleet_migrator. ADR 0002, migration-0018 shape (W1-REL).
-- Disposable projection of the current state of one relation fingerprint. The
-- four admitted states are exactly RelationProjectionStateV1 in
-- src/memory_contracts/relation.rs; no payload selects them directly (REL-01).
-- The row is rebuildable from memory_evidence_events alone, so it is never a
-- second authority (REPLAY-01).
CREATE TABLE IF NOT EXISTS memory_relation_projection_v1 (
    tenant_id                UUID NOT NULL,
    project                  STRING NOT NULL,
    relation_fingerprint     BYTES NOT NULL,
    projection_state         STRING NOT NULL,
    last_verdict             STRING NOT NULL,
    last_basis               STRING NOT NULL,
    last_event_id            BYTES NOT NULL,
    generation               INT8 NOT NULL,
    updated_at               TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, relation_fingerprint),
    CONSTRAINT memory_relation_projection_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_relation_projection_fingerprint_shape
        CHECK (octet_length(relation_fingerprint) = 32),
    CONSTRAINT memory_relation_projection_state
        CHECK (
            projection_state IN ('declared', 'verified', 'refuted', 'contested')
        ),
    CONSTRAINT memory_relation_projection_verdict
        CHECK (last_verdict IN ('supports', 'refutes')),
    CONSTRAINT memory_relation_projection_basis
        CHECK (
            last_basis IN (
                'declared',
                'inferred',
                'provider_attested',
                'verifier_result'
            )
        ),
    CONSTRAINT memory_relation_projection_last_event_shape
        CHECK (octet_length(last_event_id) = 32),
    CONSTRAINT memory_relation_projection_generation_bound
        CHECK (generation > 0)
);

-- Ownership: fleet_migrator. ADR 0002 D1 + REPLAY-02. The projector cursor is
-- keyed by (ledger_family, shard) because an append position is unique only
-- within (ledger_family, epoch, shard, offset) once the general ledger is a
-- second physical table. Advancing this row in the same transaction as the
-- projection above is what makes REPLAY-02 mechanical rather than aspirational.
CREATE TABLE IF NOT EXISTS memory_relation_projection_watermarks_v1 (
    tenant_id                UUID NOT NULL,
    project                  STRING NOT NULL,
    ledger_family            STRING NOT NULL,
    shard                    INT4 NOT NULL,
    last_committed_offset    INT8 NOT NULL,
    updated_at               TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, ledger_family, shard),
    CONSTRAINT memory_relation_watermark_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_relation_watermark_ledger_family
        CHECK (ledger_family IN ('control', 'evidence')),
    CONSTRAINT memory_relation_watermark_shard_bound
        CHECK (shard BETWEEN 0 AND 4095),
    CONSTRAINT memory_relation_watermark_offset_bound
        CHECK (last_committed_offset >= 0)
);

-- ADR 0002 D3. The accepted-event coordinate of the event that produced this
-- durable row. NULL means the row predates the event-first path and entered
-- history as a legacy `record` projection; it is imported later by the signed
-- bootstrap-manifest event, never backfilled by a synthesized event.
-- ALTER TABLE ADD COLUMN is an online schema change on CockroachDB 26.2. The
-- CHECK is added as a separate named constraint rather than inline: a column
-- added with an inline named CHECK is NOT resumable, because a re-run skips the
-- existing column but still rejects the duplicate constraint name (SQLSTATE
-- 42710, observed on v26.2.3). The IF NOT EXISTS form of ADD CONSTRAINT is
-- idempotent, so the pair below survives a process death anywhere in this file.
ALTER TABLE memory_claims
    ADD COLUMN IF NOT EXISTS accepted_event_id BYTES NULL;

ALTER TABLE memory_claims
    ADD CONSTRAINT IF NOT EXISTS memory_claim_accepted_event_id_shape
    CHECK (accepted_event_id IS NULL OR octet_length(accepted_event_id) = 32);

ALTER TABLE memory_mutation_receipts
    ADD COLUMN IF NOT EXISTS accepted_event_id BYTES NULL;

ALTER TABLE memory_mutation_receipts
    ADD CONSTRAINT IF NOT EXISTS memory_mutation_receipt_accepted_event_id_shape
    CHECK (accepted_event_id IS NULL OR octet_length(accepted_event_id) = 32);

-- Ownership: fleet_migrator, deliberately. ADR 0002 D4.
--
-- This view is the writer's ONLY read path to bootstrap, log-epoch, and
-- registry-head authority. CockroachDB v26.2.3 resolves a view's base-table
-- reads with the view owner's privileges, so granting fleet_runtime SELECT on
-- this view alone lets the per-transaction head witness run with ZERO privilege
-- on any memory_control_* or memory_registry_* base table (verified on
-- v26.2.3: SELECT through the view succeeds while direct base-table SELECT
-- fails with SQLSTATE 42501). Never grant a base table to work around a
-- missing column; extend this view instead.
--
-- The registry-transition join uses the FULL composite key that migration 0014
-- already enforces as a foreign key, so the view cannot mix one generation's
-- head with another transition's package, policy, profile, scope, effective
-- time, event coordinate, or acceptance time.
--
-- Cardinality: exactly one row per (tenant_id, project). The head projection is
-- keyed by (tenant_id, project); memory_control_bootstraps is keyed by
-- (tenant_id, project); memory_control_log_epochs is UNIQUE (tenant_id,
-- project). D4's "exactly one row, LIMIT 2" witness therefore fails closed on 0
-- rows and can only observe 2 if one of those keys is violated.
CREATE VIEW IF NOT EXISTS memory_writer_authority_v1 AS
SELECT
    head.tenant_id                              AS tenant_id,
    head.project                                AS project,
    bootstrap.receipt_digest                    AS bootstrap_receipt_digest,
    bootstrap.canonical_receipt                 AS bootstrap_canonical_receipt,
    bootstrap.epoch_id                          AS bootstrap_epoch_id,
    bootstrap.shard_count                       AS bootstrap_shard_count,
    bootstrap.contract_tenant_namespace         AS bootstrap_contract_tenant_namespace,
    bootstrap.contract_project_namespace        AS bootstrap_contract_project_namespace,
    epoch.epoch_id                              AS log_epoch_id,
    epoch.partition_recipe_id                   AS partition_recipe_id,
    epoch.partition_recipe_version              AS partition_recipe_version,
    epoch.partition_algorithm                   AS partition_algorithm,
    epoch.partition_seed                        AS partition_seed,
    epoch.shard_count                           AS log_shard_count,
    head.head_state                             AS head_state,
    head.generation                             AS generation,
    head.activation_id                          AS activation_id,
    head.package_digest                         AS package_digest,
    head.activation_policy_digest               AS activation_policy_digest,
    head.profile_id                             AS profile_id,
    head.profile_digest                         AS profile_digest,
    head.vector_manifest_digest                 AS vector_manifest_digest,
    head.contract_tenant_namespace              AS contract_tenant_namespace,
    head.contract_project_namespace             AS contract_project_namespace,
    head.effective_from                         AS effective_from,
    head.accepted_at                            AS accepted_at,
    head.canonical_head                         AS canonical_head,
    transition.root_activation_id               AS root_activation_id,
    transition.root_package_digest              AS root_package_digest,
    transition.root_activation_policy_digest    AS root_activation_policy_digest,
    transition.predecessor_generation           AS predecessor_generation,
    transition.predecessor_activation_id        AS predecessor_activation_id,
    transition.predecessor_package_digest       AS predecessor_package_digest,
    transition.predecessor_activation_policy_digest
        AS predecessor_activation_policy_digest
FROM memory_registry_current_heads_v2 AS head
JOIN memory_registry_transitions AS transition
    ON transition.tenant_id = head.tenant_id
    AND transition.project = head.project
    AND transition.generation = head.generation
    AND transition.activation_id = head.activation_id
    AND transition.package_digest = head.package_digest
    AND transition.activation_policy_digest = head.activation_policy_digest
    AND transition.profile_id = head.profile_id
    AND transition.profile_digest = head.profile_digest
    AND transition.vector_manifest_digest = head.vector_manifest_digest
    AND transition.contract_tenant_namespace = head.contract_tenant_namespace
    AND transition.contract_project_namespace = head.contract_project_namespace
    AND transition.effective_from = head.effective_from
    AND transition.accepted_at = head.accepted_at
    AND transition.source_event_id = head.source_event_id
    AND transition.source_epoch_id = head.source_epoch_id
    AND transition.source_shard = head.source_shard
    AND transition.source_committed_offset = head.source_committed_offset
JOIN memory_control_bootstraps AS bootstrap
    ON bootstrap.tenant_id = head.tenant_id
    AND bootstrap.project = head.project
JOIN memory_control_log_epochs AS epoch
    ON epoch.tenant_id = head.tenant_id
    AND epoch.project = head.project
    AND epoch.bootstrap_receipt_digest = bootstrap.receipt_digest;
