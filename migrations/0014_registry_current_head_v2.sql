-- Mutable singleton projection of the current successor-capable registry head.
-- Transition history remains append-only authority. The complete FK prevents
-- a projected head from mixing a generation with another transition's package,
-- policy, profile, scope, effective time, event coordinate, or acceptance time.
-- This projection is governed by 0012's OPEN-HEAD-ONLY SCHEMA CONTRACT. A
-- finite-interval successor needs additive interval storage and audit first.
-- canonical_head is the exact canonical RegistryHeadBindingV1 preimage from
-- the referenced transition, including generation zero's reconstructed
-- effective interval; it is never the narrower legacy RegistryHeadV1 bytes.

CREATE TABLE memory_registry_current_heads_v2 (
    tenant_id                          UUID NOT NULL,
    project                            STRING NOT NULL,
    head_state                         STRING NOT NULL,
    generation                         INT8 NOT NULL,
    activation_id                      BYTES NOT NULL,
    package_digest                     BYTES NOT NULL,
    activation_policy_digest           BYTES NOT NULL,
    profile_id                         STRING NOT NULL,
    profile_digest                     BYTES NOT NULL,
    vector_manifest_digest             BYTES NOT NULL,
    contract_tenant_namespace          STRING NOT NULL,
    contract_project_namespace         STRING NOT NULL,
    effective_from                     TIMESTAMPTZ NOT NULL,
    accepted_at                        TIMESTAMPTZ NOT NULL,
    source_event_id                    BYTES NOT NULL,
    source_epoch_id                    BYTES NOT NULL,
    source_shard                       INT4 NOT NULL,
    source_committed_offset            INT8 NOT NULL,
    canonical_head                     BYTES NOT NULL,
    PRIMARY KEY (tenant_id, project),
    CONSTRAINT memory_registry_current_head_transition_fk
        FOREIGN KEY (
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
    CONSTRAINT memory_registry_current_head_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_registry_current_head_state
        CHECK (head_state = 'active'),
    CONSTRAINT memory_registry_current_head_generation_bound
        CHECK (generation BETWEEN 0 AND 4294967295),
    CONSTRAINT memory_registry_current_head_digest_shapes
        CHECK (
            octet_length(activation_id) = 32
            AND octet_length(package_digest) = 32
            AND octet_length(activation_policy_digest) = 32
            AND octet_length(profile_digest) = 32
            AND octet_length(vector_manifest_digest) = 32
            AND octet_length(source_event_id) = 32
            AND octet_length(source_epoch_id) = 32
        ),
    CONSTRAINT memory_registry_current_head_profile_and_scope
        CHECK (
            profile_id = 'ostk-canonical-json-v1'
            AND octet_length(contract_tenant_namespace) BETWEEN 1 AND 128
            AND octet_length(contract_project_namespace) BETWEEN 1 AND 128
        ),
    CONSTRAINT memory_registry_current_head_source_bounds
        CHECK (source_shard BETWEEN 0 AND 4095 AND source_committed_offset > 0),
    CONSTRAINT memory_registry_current_head_times
        CHECK (
            date_trunc('microsecond', effective_from) = effective_from
            AND date_trunc('microsecond', accepted_at) = accepted_at
            AND accepted_at >= effective_from
        ),
    CONSTRAINT memory_registry_current_head_canonical_bound
        CHECK (octet_length(canonical_head) BETWEEN 1 AND 1048576)
);
