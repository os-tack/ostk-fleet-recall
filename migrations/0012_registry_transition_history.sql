-- Append-only, generation-complete registry transition history. Migration
-- 0012 deliberately performs no generation-zero backfill: the successor
-- repository lazily projects the existing nonempty 0004 genesis row while it
-- holds the stable registry control-shard head lock, then appends a successor
-- in the same short SERIALIZABLE transaction.
--
-- Every row retains the exact immutable genesis root through both 0004 tables.
-- Generation zero equals that root and has no predecessor. Every later row
-- names generation - 1 through a complete self-FK. The table is generic only
-- across open-head successor generations; the one-time 0 -> 1 bridge is
-- isolated in 0013.
--
-- canonical_head is always the canonical RegistryHeadBindingV1 preimage. For
-- the lazy generation-zero mirror, reconstruct it from the fully audited 0004
-- RegistryHeadV1 plus the linked activation's effective_from and null
-- effective_until; never byte-copy the narrower legacy canonical_head.
--
-- OPEN-HEAD-ONLY SCHEMA CONTRACT: the current 0 -> 1 activation contract
-- rejects a finite effective_until on either endpoint. It is therefore absent
-- from this projection rather than being a nullable composite-FK escape hatch.
-- Any future successor contract that admits a finite interval requires an
-- additive interval column plus an audit migration before it may use this
-- history.

CREATE TABLE memory_registry_transitions (
    tenant_id                                  UUID NOT NULL,
    project                                    STRING NOT NULL,
    generation                                 INT8 NOT NULL,
    activation_id                              BYTES NOT NULL,
    statement_id                               BYTES NOT NULL,
    package_digest                             BYTES NOT NULL,
    activation_policy_digest                   BYTES NOT NULL,
    test_result_digest                         BYTES NOT NULL,
    profile_id                                 STRING NOT NULL,
    profile_digest                             BYTES NOT NULL,
    vector_manifest_digest                     BYTES NOT NULL,
    contract_tenant_namespace                  STRING NOT NULL,
    contract_project_namespace                 STRING NOT NULL,
    effective_from                             TIMESTAMPTZ NOT NULL,
    accepted_at                                TIMESTAMPTZ NOT NULL,
    source_event_id                            BYTES NOT NULL,
    source_epoch_id                            BYTES NOT NULL,
    source_shard                               INT4 NOT NULL,
    source_committed_offset                    INT8 NOT NULL,
    proposer_principal_id                      STRING NOT NULL,
    package_author_principal_id                STRING NOT NULL,
    approval_ids_packed                        BYTES NOT NULL,
    approval_count                             INT4 NOT NULL,
    required_threshold                         INT4 NOT NULL,
    separation_of_duty_satisfied               BOOL NOT NULL,
    root_activation_id                         BYTES NOT NULL,
    root_package_digest                        BYTES NOT NULL,
    root_activation_policy_digest              BYTES NOT NULL,
    root_profile_id                            STRING NOT NULL,
    root_profile_digest                        BYTES NOT NULL,
    root_vector_manifest_digest                BYTES NOT NULL,
    root_contract_tenant_namespace             STRING NOT NULL,
    root_contract_project_namespace            STRING NOT NULL,
    root_effective_from                        TIMESTAMPTZ NOT NULL,
    root_accepted_at                           TIMESTAMPTZ NOT NULL,
    root_source_event_id                       BYTES NOT NULL,
    root_source_epoch_id                       BYTES NOT NULL,
    root_source_shard                          INT4 NOT NULL,
    root_source_committed_offset               INT8 NOT NULL,
    predecessor_generation                     INT8,
    predecessor_activation_id                  BYTES,
    predecessor_package_digest                 BYTES,
    predecessor_activation_policy_digest       BYTES,
    predecessor_profile_id                     STRING,
    predecessor_profile_digest                 BYTES,
    predecessor_vector_manifest_digest         BYTES,
    predecessor_contract_tenant_namespace      STRING,
    predecessor_contract_project_namespace     STRING,
    predecessor_effective_from                 TIMESTAMPTZ,
    predecessor_accepted_at                    TIMESTAMPTZ,
    predecessor_source_event_id                BYTES,
    predecessor_source_epoch_id                BYTES,
    predecessor_source_shard                   INT4,
    predecessor_source_committed_offset        INT8,
    canonical_package                          BYTES NOT NULL,
    canonical_statement                        BYTES NOT NULL,
    canonical_approval_set                     BYTES NOT NULL,
    canonical_test_result                      BYTES NOT NULL,
    canonical_receipt                          BYTES NOT NULL,
    canonical_event                            BYTES NOT NULL,
    canonical_head                             BYTES NOT NULL,
    PRIMARY KEY (tenant_id, project, generation),
    UNIQUE (tenant_id, project, activation_id),
    UNIQUE (tenant_id, project, statement_id),
    UNIQUE (tenant_id, project, source_event_id),
    UNIQUE (
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
    CONSTRAINT memory_registry_transition_genesis_head_fk
        FOREIGN KEY (
            tenant_id,
            project,
            root_activation_id,
            root_package_digest,
            root_activation_policy_digest,
            root_source_event_id,
            root_source_epoch_id,
            root_source_shard,
            root_source_committed_offset,
            root_accepted_at
        )
        REFERENCES memory_registry_heads (
            tenant_id,
            project,
            activation_id,
            package_digest,
            activation_policy_digest,
            source_event_id,
            source_epoch_id,
            source_shard,
            source_committed_offset,
            activated_at
        ),
    CONSTRAINT memory_registry_transition_genesis_activation_fk
        FOREIGN KEY (
            tenant_id,
            project,
            root_activation_id,
            root_package_digest,
            root_activation_policy_digest,
            root_profile_id,
            root_profile_digest,
            root_vector_manifest_digest,
            root_contract_tenant_namespace,
            root_contract_project_namespace,
            root_effective_from,
            root_source_event_id,
            root_source_epoch_id,
            root_source_shard,
            root_source_committed_offset,
            root_accepted_at
        )
        REFERENCES memory_registry_activations (
            tenant_id,
            project,
            activation_id,
            activated_package_digest,
            activated_policy_digest,
            profile_id,
            profile_digest,
            vector_manifest_digest,
            contract_tenant_namespace,
            contract_project_namespace,
            effective_from,
            accepted_event_id,
            control_epoch_id,
            control_shard,
            control_committed_offset,
            accepted_at
        ),
    CONSTRAINT memory_registry_transition_control_source_fk
        FOREIGN KEY (
            tenant_id,
            project,
            source_event_id,
            source_epoch_id,
            source_shard,
            source_committed_offset,
            activation_id,
            accepted_at
        )
        REFERENCES memory_control_events (
            tenant_id,
            project,
            event_id,
            epoch_id,
            shard,
            committed_offset,
            semantic_object_digest,
            accepted_at
        ),
    CONSTRAINT memory_registry_transition_predecessor_fk
        FOREIGN KEY (
            tenant_id,
            project,
            predecessor_generation,
            predecessor_activation_id,
            predecessor_package_digest,
            predecessor_activation_policy_digest,
            predecessor_profile_id,
            predecessor_profile_digest,
            predecessor_vector_manifest_digest,
            predecessor_contract_tenant_namespace,
            predecessor_contract_project_namespace,
            predecessor_effective_from,
            predecessor_accepted_at,
            predecessor_source_event_id,
            predecessor_source_epoch_id,
            predecessor_source_shard,
            predecessor_source_committed_offset
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
    CONSTRAINT memory_registry_transition_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_registry_transition_generation_bound
        CHECK (generation BETWEEN 0 AND 4294967295),
    CONSTRAINT memory_registry_transition_digest_shapes
        CHECK (
            octet_length(activation_id) = 32
            AND octet_length(statement_id) = 32
            AND octet_length(package_digest) = 32
            AND octet_length(activation_policy_digest) = 32
            AND octet_length(test_result_digest) = 32
            AND octet_length(profile_digest) = 32
            AND octet_length(vector_manifest_digest) = 32
            AND octet_length(source_event_id) = 32
            AND octet_length(source_epoch_id) = 32
            AND octet_length(root_activation_id) = 32
            AND octet_length(root_package_digest) = 32
            AND octet_length(root_activation_policy_digest) = 32
            AND octet_length(root_profile_digest) = 32
            AND octet_length(root_vector_manifest_digest) = 32
            AND octet_length(root_source_event_id) = 32
            AND octet_length(root_source_epoch_id) = 32
        ),
    CONSTRAINT memory_registry_transition_profile
        CHECK (
            profile_id = 'ostk-canonical-json-v1'
            AND root_profile_id = 'ostk-canonical-json-v1'
            AND profile_id = root_profile_id
            AND profile_digest = root_profile_digest
            AND vector_manifest_digest = root_vector_manifest_digest
        ),
    CONSTRAINT memory_registry_transition_scope_bounds
        CHECK (
            octet_length(contract_tenant_namespace) BETWEEN 1 AND 128
            AND octet_length(contract_project_namespace) BETWEEN 1 AND 128
            AND octet_length(root_contract_tenant_namespace) BETWEEN 1 AND 128
            AND octet_length(root_contract_project_namespace) BETWEEN 1 AND 128
            AND contract_tenant_namespace = root_contract_tenant_namespace
            AND contract_project_namespace = root_contract_project_namespace
        ),
    CONSTRAINT memory_registry_transition_principal_bounds
        CHECK (
            octet_length(proposer_principal_id) BETWEEN 1 AND 128
            AND octet_length(package_author_principal_id) BETWEEN 1 AND 128
        ),
    CONSTRAINT memory_registry_transition_approval_bounds
        CHECK (
            approval_count BETWEEN 1 AND 64
            AND octet_length(approval_ids_packed) = approval_count * 32
            AND required_threshold BETWEEN 1 AND approval_count
            AND separation_of_duty_satisfied
        ),
    CONSTRAINT memory_registry_transition_source_bounds
        CHECK (
            source_shard BETWEEN 0 AND 4095
            AND source_committed_offset > 0
            AND root_source_shard BETWEEN 0 AND 4095
            AND root_source_committed_offset > 0
        ),
    CONSTRAINT memory_registry_transition_times
        CHECK (
            date_trunc('microsecond', effective_from) = effective_from
            AND date_trunc('microsecond', accepted_at) = accepted_at
            AND date_trunc('microsecond', root_effective_from) = root_effective_from
            AND date_trunc('microsecond', root_accepted_at) = root_accepted_at
            AND accepted_at >= effective_from
            AND root_accepted_at >= root_effective_from
        ),
    CONSTRAINT memory_registry_transition_generation_shape
        CHECK (
            (
                generation = 0
                AND activation_id = root_activation_id
                AND package_digest = root_package_digest
                AND activation_policy_digest = root_activation_policy_digest
                AND effective_from = root_effective_from
                AND accepted_at = root_accepted_at
                AND source_event_id = root_source_event_id
                AND source_epoch_id = root_source_epoch_id
                AND source_shard = root_source_shard
                AND source_committed_offset = root_source_committed_offset
                AND predecessor_generation IS NULL
                AND predecessor_activation_id IS NULL
                AND predecessor_package_digest IS NULL
                AND predecessor_activation_policy_digest IS NULL
                AND predecessor_profile_id IS NULL
                AND predecessor_profile_digest IS NULL
                AND predecessor_vector_manifest_digest IS NULL
                AND predecessor_contract_tenant_namespace IS NULL
                AND predecessor_contract_project_namespace IS NULL
                AND predecessor_effective_from IS NULL
                AND predecessor_accepted_at IS NULL
                AND predecessor_source_event_id IS NULL
                AND predecessor_source_epoch_id IS NULL
                AND predecessor_source_shard IS NULL
                AND predecessor_source_committed_offset IS NULL
            )
            OR
            (
                generation > 0
                AND predecessor_generation IS NOT NULL
                AND predecessor_activation_id IS NOT NULL
                AND predecessor_package_digest IS NOT NULL
                AND predecessor_activation_policy_digest IS NOT NULL
                AND predecessor_profile_id IS NOT NULL
                AND predecessor_profile_digest IS NOT NULL
                AND predecessor_vector_manifest_digest IS NOT NULL
                AND predecessor_contract_tenant_namespace IS NOT NULL
                AND predecessor_contract_project_namespace IS NOT NULL
                AND predecessor_effective_from IS NOT NULL
                AND predecessor_accepted_at IS NOT NULL
                AND predecessor_source_event_id IS NOT NULL
                AND predecessor_source_epoch_id IS NOT NULL
                AND predecessor_source_shard IS NOT NULL
                AND predecessor_source_committed_offset IS NOT NULL
                AND predecessor_generation = generation - 1
                AND predecessor_profile_id = root_profile_id
                AND predecessor_profile_digest = root_profile_digest
                AND predecessor_vector_manifest_digest = root_vector_manifest_digest
                AND predecessor_contract_tenant_namespace = root_contract_tenant_namespace
                AND predecessor_contract_project_namespace = root_contract_project_namespace
                AND predecessor_source_shard BETWEEN 0 AND 4095
                AND predecessor_source_committed_offset > 0
                AND date_trunc('microsecond', predecessor_effective_from)
                    = predecessor_effective_from
                AND date_trunc('microsecond', predecessor_accepted_at)
                    = predecessor_accepted_at
                AND effective_from >= predecessor_effective_from
                AND accepted_at >= predecessor_accepted_at
            )
        ),
    CONSTRAINT memory_registry_transition_canonical_bounds
        CHECK (
            octet_length(canonical_package) BETWEEN 1 AND 1048576
            AND octet_length(canonical_statement) BETWEEN 1 AND 1048576
            AND octet_length(canonical_approval_set) BETWEEN 1 AND 1048576
            AND octet_length(canonical_test_result) BETWEEN 1 AND 1048576
            AND octet_length(canonical_receipt) BETWEEN 1 AND 1048576
            AND octet_length(canonical_event) BETWEEN 1 AND 1048576
            AND octet_length(canonical_head) BETWEEN 1 AND 1048576
        )
);
