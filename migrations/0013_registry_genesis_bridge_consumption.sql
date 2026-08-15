-- One-shot consumption of the deployment-pinned generation 0 -> 1 key bridge.
-- The scope-leading primary key prevents a second bridge from being consumed
-- for the same registry. Both endpoints are complete transition-head FKs; a
-- bridge cannot name a different generation, package, policy, profile, scope,
-- effective time, control event, or database acceptance time.
-- Both endpoint transitions are governed by 0012's OPEN-HEAD-ONLY SCHEMA
-- CONTRACT; the current 0 -> 1 contract rejects effective_until on either.

CREATE TABLE memory_registry_genesis_bridge_consumptions (
    tenant_id                                  UUID NOT NULL,
    project                                    STRING NOT NULL,
    bridge_digest                              BYTES NOT NULL,
    from_generation                            INT8 NOT NULL,
    genesis_activation_id                      BYTES NOT NULL,
    genesis_package_digest                     BYTES NOT NULL,
    genesis_activation_policy_digest           BYTES NOT NULL,
    genesis_profile_id                         STRING NOT NULL,
    genesis_profile_digest                     BYTES NOT NULL,
    genesis_vector_manifest_digest             BYTES NOT NULL,
    genesis_contract_tenant_namespace          STRING NOT NULL,
    genesis_contract_project_namespace         STRING NOT NULL,
    genesis_effective_from                     TIMESTAMPTZ NOT NULL,
    genesis_accepted_at                        TIMESTAMPTZ NOT NULL,
    genesis_source_event_id                    BYTES NOT NULL,
    genesis_source_epoch_id                    BYTES NOT NULL,
    genesis_source_shard                       INT4 NOT NULL,
    genesis_source_committed_offset            INT8 NOT NULL,
    to_generation                              INT8 NOT NULL,
    successor_activation_id                    BYTES NOT NULL,
    successor_package_digest                   BYTES NOT NULL,
    successor_activation_policy_digest         BYTES NOT NULL,
    successor_profile_id                       STRING NOT NULL,
    successor_profile_digest                   BYTES NOT NULL,
    successor_vector_manifest_digest           BYTES NOT NULL,
    successor_contract_tenant_namespace        STRING NOT NULL,
    successor_contract_project_namespace       STRING NOT NULL,
    successor_effective_from                   TIMESTAMPTZ NOT NULL,
    successor_accepted_at                      TIMESTAMPTZ NOT NULL,
    successor_source_event_id                  BYTES NOT NULL,
    successor_source_epoch_id                  BYTES NOT NULL,
    successor_source_shard                     INT4 NOT NULL,
    successor_source_committed_offset          INT8 NOT NULL,
    canonical_bridge                           BYTES NOT NULL,
    consumed_at                                TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project),
    UNIQUE (tenant_id, project, bridge_digest),
    CONSTRAINT memory_registry_bridge_genesis_transition_fk
        FOREIGN KEY (
            tenant_id,
            project,
            from_generation,
            genesis_activation_id,
            genesis_package_digest,
            genesis_activation_policy_digest,
            genesis_profile_id,
            genesis_profile_digest,
            genesis_vector_manifest_digest,
            genesis_contract_tenant_namespace,
            genesis_contract_project_namespace,
            genesis_effective_from,
            genesis_accepted_at,
            genesis_source_event_id,
            genesis_source_epoch_id,
            genesis_source_shard,
            genesis_source_committed_offset
        )
        REFERENCES memory_registry_transitions (
            tenant_id,
            project,
            generation,
            activation_id,
            package_digest,
            activation_policy_digest,
            profile_id,
            profile_digest,
            vector_manifest_digest,
            contract_tenant_namespace,
            contract_project_namespace,
            effective_from,
            accepted_at,
            source_event_id,
            source_epoch_id,
            source_shard,
            source_committed_offset
        ),
    CONSTRAINT memory_registry_bridge_successor_transition_fk
        FOREIGN KEY (
            tenant_id,
            project,
            to_generation,
            successor_activation_id,
            successor_package_digest,
            successor_activation_policy_digest,
            successor_profile_id,
            successor_profile_digest,
            successor_vector_manifest_digest,
            successor_contract_tenant_namespace,
            successor_contract_project_namespace,
            successor_effective_from,
            successor_accepted_at,
            successor_source_event_id,
            successor_source_epoch_id,
            successor_source_shard,
            successor_source_committed_offset
        )
        REFERENCES memory_registry_transitions (
            tenant_id,
            project,
            generation,
            activation_id,
            package_digest,
            activation_policy_digest,
            profile_id,
            profile_digest,
            vector_manifest_digest,
            contract_tenant_namespace,
            contract_project_namespace,
            effective_from,
            accepted_at,
            source_event_id,
            source_epoch_id,
            source_shard,
            source_committed_offset
        ),
    CONSTRAINT memory_registry_bridge_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_registry_bridge_one_shot_generation
        CHECK (from_generation = 0 AND to_generation = 1),
    CONSTRAINT memory_registry_bridge_digest_shapes
        CHECK (
            octet_length(bridge_digest) = 32
            AND octet_length(genesis_activation_id) = 32
            AND octet_length(genesis_package_digest) = 32
            AND octet_length(genesis_activation_policy_digest) = 32
            AND octet_length(genesis_profile_digest) = 32
            AND octet_length(genesis_vector_manifest_digest) = 32
            AND octet_length(genesis_source_event_id) = 32
            AND octet_length(genesis_source_epoch_id) = 32
            AND octet_length(successor_activation_id) = 32
            AND octet_length(successor_package_digest) = 32
            AND octet_length(successor_activation_policy_digest) = 32
            AND octet_length(successor_profile_digest) = 32
            AND octet_length(successor_vector_manifest_digest) = 32
            AND octet_length(successor_source_event_id) = 32
            AND octet_length(successor_source_epoch_id) = 32
        ),
    CONSTRAINT memory_registry_bridge_profiles_and_scope
        CHECK (
            genesis_profile_id = 'ostk-canonical-json-v1'
            AND successor_profile_id = genesis_profile_id
            AND successor_profile_digest = genesis_profile_digest
            AND successor_vector_manifest_digest = genesis_vector_manifest_digest
            AND octet_length(genesis_contract_tenant_namespace) BETWEEN 1 AND 128
            AND octet_length(genesis_contract_project_namespace) BETWEEN 1 AND 128
            AND successor_contract_tenant_namespace = genesis_contract_tenant_namespace
            AND successor_contract_project_namespace = genesis_contract_project_namespace
        ),
    CONSTRAINT memory_registry_bridge_source_bounds
        CHECK (
            genesis_source_shard BETWEEN 0 AND 4095
            AND genesis_source_committed_offset > 0
            AND successor_source_shard BETWEEN 0 AND 4095
            AND successor_source_committed_offset > 0
        ),
    CONSTRAINT memory_registry_bridge_times
        CHECK (
            date_trunc('microsecond', genesis_effective_from) = genesis_effective_from
            AND date_trunc('microsecond', genesis_accepted_at) = genesis_accepted_at
            AND date_trunc('microsecond', successor_effective_from) = successor_effective_from
            AND date_trunc('microsecond', successor_accepted_at) = successor_accepted_at
            AND date_trunc('microsecond', consumed_at) = consumed_at
            AND successor_effective_from >= genesis_effective_from
            AND successor_accepted_at >= genesis_accepted_at
            AND consumed_at = successor_accepted_at
        ),
    CONSTRAINT memory_registry_bridge_canonical_bound
        CHECK (octet_length(canonical_bridge) BETWEEN 1 AND 1048576)
);
