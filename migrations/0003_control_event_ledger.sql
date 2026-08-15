-- no-transaction
-- Minimal private control-event ledger. Accepted events, epochs, and the
-- bootstrap guard are immutable; only shard heads advance after bootstrap.
-- Existing recall projections remain deliberately independent of this schema.

CREATE TABLE memory_control_bootstraps (
    tenant_id                         UUID NOT NULL,
    project                           STRING NOT NULL,
    contract_tenant_namespace         STRING NOT NULL,
    contract_project_namespace        STRING NOT NULL,
    receipt_digest                    BYTES NOT NULL,
    statement_id                      BYTES NOT NULL,
    bootstrap_event_id                BYTES NOT NULL,
    profile_id                        STRING NOT NULL,
    profile_digest                    BYTES NOT NULL,
    vector_manifest_digest            BYTES NOT NULL,
    genesis_registry_package_digest   BYTES NOT NULL,
    signer_policy_digest              BYTES NOT NULL,
    signer_count                      INT4 NOT NULL,
    approval_threshold                INT4 NOT NULL,
    epoch_id                          BYTES NOT NULL,
    shard_count                       INT4 NOT NULL,
    bootstrap_shard                   INT4 NOT NULL,
    bootstrap_offset                  INT8 NOT NULL,
    canonical_receipt                 BYTES NOT NULL,
    canonical_genesis_package         BYTES NOT NULL,
    accepted_at                       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project),
    UNIQUE (tenant_id, project, receipt_digest),
    UNIQUE (tenant_id, project, bootstrap_event_id),
    CONSTRAINT memory_control_bootstrap_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_control_bootstrap_tenant_namespace_bound
        CHECK (octet_length(contract_tenant_namespace) BETWEEN 1 AND 128),
    CONSTRAINT memory_control_bootstrap_project_namespace_bound
        CHECK (octet_length(contract_project_namespace) BETWEEN 1 AND 128),
    CONSTRAINT memory_control_bootstrap_receipt_digest_shape
        CHECK (octet_length(receipt_digest) = 32),
    CONSTRAINT memory_control_bootstrap_statement_id_shape
        CHECK (octet_length(statement_id) = 32),
    CONSTRAINT memory_control_bootstrap_event_id_shape
        CHECK (octet_length(bootstrap_event_id) = 32),
    CONSTRAINT memory_control_bootstrap_profile
        CHECK (profile_id = 'ostk-canonical-json-v1'),
    CONSTRAINT memory_control_bootstrap_profile_digest_shape
        CHECK (octet_length(profile_digest) = 32),
    CONSTRAINT memory_control_bootstrap_vector_manifest_digest_shape
        CHECK (octet_length(vector_manifest_digest) = 32),
    CONSTRAINT memory_control_bootstrap_registry_digest_shape
        CHECK (octet_length(genesis_registry_package_digest) = 32),
    CONSTRAINT memory_control_bootstrap_signer_policy_digest_shape
        CHECK (octet_length(signer_policy_digest) = 32),
    CONSTRAINT memory_control_bootstrap_epoch_id_shape
        CHECK (octet_length(epoch_id) = 32),
    CONSTRAINT memory_control_bootstrap_signer_count_bound
        CHECK (signer_count BETWEEN 1 AND 64),
    CONSTRAINT memory_control_bootstrap_threshold_bound
        CHECK (approval_threshold BETWEEN 1 AND signer_count),
    CONSTRAINT memory_control_bootstrap_shard_count_bound
        CHECK (shard_count BETWEEN 1 AND 4096),
    CONSTRAINT memory_control_bootstrap_shard_bound
        CHECK (bootstrap_shard >= 0 AND bootstrap_shard < shard_count),
    CONSTRAINT memory_control_bootstrap_offset
        CHECK (bootstrap_offset = 1),
    CONSTRAINT memory_control_bootstrap_receipt_bound
        CHECK (octet_length(canonical_receipt) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_control_bootstrap_package_bound
        CHECK (octet_length(canonical_genesis_package) BETWEEN 1 AND 1048576)
);

CREATE TABLE memory_control_log_epochs (
    tenant_id                     UUID NOT NULL,
    project                       STRING NOT NULL,
    epoch_id                      BYTES NOT NULL,
    bootstrap_receipt_digest      BYTES NOT NULL,
    canonical_epoch               BYTES NOT NULL,
    partition_recipe_id           STRING NOT NULL,
    partition_recipe_version      INT4 NOT NULL,
    partition_algorithm           STRING NOT NULL,
    partition_seed                BYTES NOT NULL,
    shard_count                   INT4 NOT NULL,
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, epoch_id),
    UNIQUE (tenant_id, project),
    UNIQUE (tenant_id, project, epoch_id, shard_count),
    CONSTRAINT memory_control_epoch_bootstrap_fk
        FOREIGN KEY (tenant_id, project, bootstrap_receipt_digest)
        REFERENCES memory_control_bootstraps (tenant_id, project, receipt_digest),
    CONSTRAINT memory_control_epoch_id_shape
        CHECK (octet_length(epoch_id) = 32),
    CONSTRAINT memory_control_epoch_receipt_digest_shape
        CHECK (octet_length(bootstrap_receipt_digest) = 32),
    CONSTRAINT memory_control_epoch_canonical_bound
        CHECK (octet_length(canonical_epoch) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_control_epoch_partition_recipe
        CHECK (partition_recipe_id = 'ostk.partition.sha256_prefix64_modulo'),
    CONSTRAINT memory_control_epoch_partition_recipe_version
        CHECK (partition_recipe_version = 1),
    CONSTRAINT memory_control_epoch_partition_algorithm
        CHECK (partition_algorithm = 'sha256_prefix64_modulo'),
    CONSTRAINT memory_control_epoch_partition_seed_shape
        CHECK (octet_length(partition_seed) = 32),
    CONSTRAINT memory_control_epoch_shard_count_bound
        CHECK (shard_count BETWEEN 1 AND 4096)
);

CREATE TABLE memory_control_shard_heads (
    tenant_id                   UUID NOT NULL,
    project                     STRING NOT NULL,
    epoch_id                    BYTES NOT NULL,
    shard                       INT4 NOT NULL,
    shard_count                 INT4 NOT NULL,
    last_committed_offset       INT8 NOT NULL,
    chain_digest                BYTES NOT NULL,
    advanced_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, epoch_id, shard),
    CONSTRAINT memory_control_head_epoch_fk
        FOREIGN KEY (tenant_id, project, epoch_id, shard_count)
        REFERENCES memory_control_log_epochs (tenant_id, project, epoch_id, shard_count),
    CONSTRAINT memory_control_head_epoch_id_shape
        CHECK (octet_length(epoch_id) = 32),
    CONSTRAINT memory_control_head_shard_count_bound
        CHECK (shard_count BETWEEN 1 AND 4096),
    CONSTRAINT memory_control_head_shard_bound
        CHECK (shard >= 0 AND shard < shard_count),
    CONSTRAINT memory_control_head_offset_bound
        CHECK (last_committed_offset >= 0),
    CONSTRAINT memory_control_head_chain_digest_shape
        CHECK (octet_length(chain_digest) = 32)
);

CREATE TABLE memory_control_events (
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
    accepted_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, epoch_id, shard, committed_offset),
    UNIQUE (tenant_id, project, event_id),
    CONSTRAINT memory_control_event_head_fk
        FOREIGN KEY (tenant_id, project, epoch_id, shard)
        REFERENCES memory_control_shard_heads (tenant_id, project, epoch_id, shard),
    CONSTRAINT memory_control_event_epoch_id_shape
        CHECK (octet_length(epoch_id) = 32),
    CONSTRAINT memory_control_event_shard_bound
        CHECK (shard BETWEEN 0 AND 4095),
    CONSTRAINT memory_control_event_offset_bound
        CHECK (committed_offset > 0),
    CONSTRAINT memory_control_event_id_shape
        CHECK (octet_length(event_id) = 32),
    CONSTRAINT memory_control_event_schema_version_bound
        CHECK (event_schema_version > 0),
    CONSTRAINT memory_control_event_kind_bound
        CHECK (octet_length(event_kind) BETWEEN 1 AND 128),
    CONSTRAINT memory_control_event_semantic_digest_shape
        CHECK (octet_length(semantic_object_digest) = 32),
    CONSTRAINT memory_control_event_consistency_family_bound
        CHECK (octet_length(consistency_family) BETWEEN 1 AND 128),
    CONSTRAINT memory_control_event_consistency_key_shape
        CHECK (octet_length(consistency_key_digest) = 32),
    CONSTRAINT memory_control_event_canonical_bound
        CHECK (octet_length(canonical_event) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_control_event_previous_chain_shape
        CHECK (octet_length(previous_chain_digest) = 32),
    CONSTRAINT memory_control_event_chain_shape
        CHECK (octet_length(chain_digest) = 32)
);
