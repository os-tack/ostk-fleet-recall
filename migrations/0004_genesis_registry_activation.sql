-- no-transaction
-- Immutable genesis registry activation and its singleton active head.
-- Authority remains in the canonical, application-verified artifacts. These
-- projections add scoped uniqueness, exact Stage-2 anchors, append-position
-- references, and bounded audit reads without rewriting legacy rows or columns.
-- approval_ids_packed concatenates the strictly ordered 32-byte approval IDs;
-- approval_count is its unambiguous framing and is capped at 64.

-- Two scope-leading projections make the complete bootstrap anchor and the
-- event identity, physical append coordinate, semantic object, and acceptance
-- time exact foreign-key targets. Canonical event bytes remain the authority
-- for event kind, consistency metadata, and chain state; activation reads join
-- those fields from the exact source event instead of duplicating them here.
-- These are online index backfills over immutable control rows; deployment
-- must still run exactly one migrator and inspect both schema-change jobs
-- before activation.
CREATE UNIQUE INDEX memory_control_bootstraps_registry_anchor_idx
    ON memory_control_bootstraps (
        tenant_id,
        project,
        statement_id,
        receipt_digest,
        bootstrap_event_id,
        genesis_registry_package_digest,
        signer_policy_digest,
        profile_id,
        profile_digest,
        vector_manifest_digest,
        contract_tenant_namespace,
        contract_project_namespace,
        epoch_id,
        accepted_at
    );

CREATE UNIQUE INDEX memory_control_events_registry_source_idx
    ON memory_control_events (
        tenant_id,
        project,
        event_id,
        epoch_id,
        shard,
        committed_offset,
        semantic_object_digest,
        accepted_at
    );

-- A stable registry stream may share an epoch and shard with unrelated
-- control events. Keep the fail-closed orphan probe index-only and bounded as
-- the control ledger grows; multiple transitions intentionally share this
-- consistency key, so this index is not unique.
CREATE INDEX memory_control_events_consistency_stream_idx
    ON memory_control_events (
        tenant_id,
        project,
        epoch_id,
        consistency_family,
        consistency_key_digest,
        shard,
        committed_offset
    ) STORING (event_id);

CREATE TABLE memory_registry_activations (
    tenant_id                          UUID NOT NULL,
    project                            STRING NOT NULL,
    activation_id                      BYTES NOT NULL,
    statement_id                       BYTES NOT NULL,
    bootstrap_statement_id             BYTES NOT NULL,
    bootstrap_receipt_digest           BYTES NOT NULL,
    bootstrap_event_id                 BYTES NOT NULL,
    genesis_epoch_id                   BYTES NOT NULL,
    genesis_package_digest             BYTES NOT NULL,
    bootstrap_signer_policy_digest     BYTES NOT NULL,
    profile_id                         STRING NOT NULL,
    profile_digest                     BYTES NOT NULL,
    vector_manifest_digest             BYTES NOT NULL,
    contract_tenant_namespace          STRING NOT NULL,
    contract_project_namespace         STRING NOT NULL,
    activated_package_digest           BYTES NOT NULL,
    activated_policy_digest            BYTES NOT NULL,
    test_result_digest                 BYTES NOT NULL,
    proposer_principal_id              STRING NOT NULL,
    package_author_principal_id         STRING NOT NULL,
    approval_ids_packed                BYTES NOT NULL,
    approval_count                     INT4 NOT NULL,
    required_threshold                 INT4 NOT NULL,
    separation_of_duty_satisfied       BOOL NOT NULL,
    bootstrap_accepted_at              TIMESTAMPTZ NOT NULL,
    effective_from                     TIMESTAMPTZ NOT NULL,
    effective_until                    TIMESTAMPTZ,
    accepted_at                        TIMESTAMPTZ NOT NULL,
    accepted_event_id                  BYTES NOT NULL,
    control_epoch_id                   BYTES NOT NULL,
    control_shard                      INT4 NOT NULL,
    control_committed_offset            INT8 NOT NULL,
    canonical_statement                BYTES NOT NULL,
    canonical_approval_set             BYTES NOT NULL,
    canonical_test_result              BYTES NOT NULL,
    canonical_receipt                  BYTES NOT NULL,
    canonical_event                    BYTES NOT NULL,
    PRIMARY KEY (tenant_id, project, activation_id),
    UNIQUE (tenant_id, project, statement_id),
    UNIQUE (tenant_id, project, accepted_event_id),
    UNIQUE (
        tenant_id,
        project,
        activation_id,
        activated_package_digest,
        activated_policy_digest,
        accepted_event_id,
        control_epoch_id,
        control_shard,
        control_committed_offset,
        accepted_at
    ),
    CONSTRAINT memory_registry_activation_bootstrap_anchor_fk
        FOREIGN KEY (
            tenant_id,
            project,
            bootstrap_statement_id,
            bootstrap_receipt_digest,
            bootstrap_event_id,
            genesis_package_digest,
            bootstrap_signer_policy_digest,
            profile_id,
            profile_digest,
            vector_manifest_digest,
            contract_tenant_namespace,
            contract_project_namespace,
            genesis_epoch_id,
            bootstrap_accepted_at
        )
        REFERENCES memory_control_bootstraps (
            tenant_id,
            project,
            statement_id,
            receipt_digest,
            bootstrap_event_id,
            genesis_registry_package_digest,
            signer_policy_digest,
            profile_id,
            profile_digest,
            vector_manifest_digest,
            contract_tenant_namespace,
            contract_project_namespace,
            epoch_id,
            accepted_at
        ),
    CONSTRAINT memory_registry_activation_genesis_epoch_fk
        FOREIGN KEY (tenant_id, project, genesis_epoch_id)
        REFERENCES memory_control_log_epochs (tenant_id, project, epoch_id),
    CONSTRAINT memory_registry_activation_control_source_fk
        FOREIGN KEY (
            tenant_id,
            project,
            accepted_event_id,
            control_epoch_id,
            control_shard,
            control_committed_offset,
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
    CONSTRAINT memory_registry_activation_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_registry_activation_id_shape
        CHECK (octet_length(activation_id) = 32),
    CONSTRAINT memory_registry_activation_statement_id_shape
        CHECK (octet_length(statement_id) = 32),
    CONSTRAINT memory_registry_activation_bootstrap_statement_shape
        CHECK (octet_length(bootstrap_statement_id) = 32),
    CONSTRAINT memory_registry_activation_bootstrap_receipt_shape
        CHECK (octet_length(bootstrap_receipt_digest) = 32),
    CONSTRAINT memory_registry_activation_bootstrap_event_shape
        CHECK (octet_length(bootstrap_event_id) = 32),
    CONSTRAINT memory_registry_activation_genesis_epoch_shape
        CHECK (octet_length(genesis_epoch_id) = 32),
    CONSTRAINT memory_registry_activation_genesis_package_shape
        CHECK (octet_length(genesis_package_digest) = 32),
    CONSTRAINT memory_registry_activation_bootstrap_policy_shape
        CHECK (octet_length(bootstrap_signer_policy_digest) = 32),
    CONSTRAINT memory_registry_activation_profile
        CHECK (profile_id = 'ostk-canonical-json-v1'),
    CONSTRAINT memory_registry_activation_profile_digest_shape
        CHECK (octet_length(profile_digest) = 32),
    CONSTRAINT memory_registry_activation_vector_manifest_shape
        CHECK (octet_length(vector_manifest_digest) = 32),
    CONSTRAINT memory_registry_activation_tenant_namespace_bound
        CHECK (octet_length(contract_tenant_namespace) BETWEEN 1 AND 128),
    CONSTRAINT memory_registry_activation_project_namespace_bound
        CHECK (octet_length(contract_project_namespace) BETWEEN 1 AND 128),
    CONSTRAINT memory_registry_activation_package_shape
        CHECK (octet_length(activated_package_digest) = 32),
    CONSTRAINT memory_registry_activation_policy_shape
        CHECK (octet_length(activated_policy_digest) = 32),
    CONSTRAINT memory_registry_activation_test_result_shape
        CHECK (octet_length(test_result_digest) = 32),
    CONSTRAINT memory_registry_activation_proposer_bound
        CHECK (octet_length(proposer_principal_id) BETWEEN 1 AND 128),
    CONSTRAINT memory_registry_activation_author_bound
        CHECK (octet_length(package_author_principal_id) BETWEEN 1 AND 128),
    CONSTRAINT memory_registry_activation_approval_count_bound
        CHECK (approval_count BETWEEN 1 AND 64),
    CONSTRAINT memory_registry_activation_approval_ids_shape
        CHECK (octet_length(approval_ids_packed) = approval_count * 32),
    CONSTRAINT memory_registry_activation_threshold_bound
        CHECK (required_threshold BETWEEN 1 AND approval_count),
    CONSTRAINT memory_registry_activation_separation_of_duty
        CHECK (separation_of_duty_satisfied),
    CONSTRAINT memory_registry_activation_effective_interval
        CHECK (effective_until IS NULL),
    CONSTRAINT memory_registry_activation_after_bootstrap
        CHECK (effective_from >= bootstrap_accepted_at),
    CONSTRAINT memory_registry_activation_acceptance_time
        CHECK (accepted_at >= effective_from),
    CONSTRAINT memory_registry_activation_event_id_shape
        CHECK (octet_length(accepted_event_id) = 32),
    CONSTRAINT memory_registry_activation_control_epoch_shape
        CHECK (octet_length(control_epoch_id) = 32),
    CONSTRAINT memory_registry_activation_control_epoch_binding
        CHECK (control_epoch_id = genesis_epoch_id),
    CONSTRAINT memory_registry_activation_control_shard_bound
        CHECK (control_shard BETWEEN 0 AND 4095),
    CONSTRAINT memory_registry_activation_control_offset_bound
        CHECK (control_committed_offset > 0),
    CONSTRAINT memory_registry_activation_package_binding
        CHECK (activated_package_digest = genesis_package_digest),
    CONSTRAINT memory_registry_activation_statement_bound
        CHECK (octet_length(canonical_statement) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_registry_activation_approval_set_bound
        CHECK (octet_length(canonical_approval_set) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_registry_activation_test_result_bound
        CHECK (octet_length(canonical_test_result) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_registry_activation_receipt_bound
        CHECK (octet_length(canonical_receipt) BETWEEN 1 AND 1048576),
    CONSTRAINT memory_registry_activation_event_bound
        CHECK (octet_length(canonical_event) BETWEEN 1 AND 1048576)
);

CREATE TABLE memory_registry_heads (
    tenant_id                          UUID NOT NULL,
    project                            STRING NOT NULL,
    head_state                         STRING NOT NULL,
    activation_id                      BYTES NOT NULL,
    package_digest                     BYTES NOT NULL,
    activation_policy_digest           BYTES NOT NULL,
    source_event_id                    BYTES NOT NULL,
    source_epoch_id                    BYTES NOT NULL,
    source_shard                       INT4 NOT NULL,
    source_committed_offset            INT8 NOT NULL,
    activated_at                       TIMESTAMPTZ NOT NULL,
    canonical_head                     BYTES NOT NULL,
    PRIMARY KEY (tenant_id, project),
    CONSTRAINT memory_registry_head_activation_fk
        FOREIGN KEY (
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
        )
        REFERENCES memory_registry_activations (
            tenant_id,
            project,
            activation_id,
            activated_package_digest,
            activated_policy_digest,
            accepted_event_id,
            control_epoch_id,
            control_shard,
            control_committed_offset,
            accepted_at
        ),
    CONSTRAINT memory_registry_head_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_registry_head_state
        CHECK (head_state = 'active'),
    CONSTRAINT memory_registry_head_activation_shape
        CHECK (octet_length(activation_id) = 32),
    CONSTRAINT memory_registry_head_package_shape
        CHECK (octet_length(package_digest) = 32),
    CONSTRAINT memory_registry_head_policy_shape
        CHECK (octet_length(activation_policy_digest) = 32),
    CONSTRAINT memory_registry_head_event_shape
        CHECK (octet_length(source_event_id) = 32),
    CONSTRAINT memory_registry_head_epoch_shape
        CHECK (octet_length(source_epoch_id) = 32),
    CONSTRAINT memory_registry_head_shard_bound
        CHECK (source_shard BETWEEN 0 AND 4095),
    CONSTRAINT memory_registry_head_offset_bound
        CHECK (source_committed_offset > 0),
    CONSTRAINT memory_registry_head_canonical_bound
        CHECK (octet_length(canonical_head) BETWEEN 1 AND 1048576)
);
