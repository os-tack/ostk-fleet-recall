-- no-transaction
-- CI-evidence connector measured windows (W3-CIEV). One additive private-plane
-- table: the durable record of exactly which finite range of workflow runs this
-- connector actually read, per connector instance and coverage domain. Nothing
-- here rewrites an existing row, drops an object, or narrows an existing
-- constraint; migrations 0001 through 0023 remain byte-identical. This
-- migration owns version 26, assigned centrally; 24 and 25 belong to other
-- in-flight items, so a version gap is expected on this branch and closed at
-- integration.
--
-- CockroachDB 26.2 cannot run this DDL inside SQLx's PostgreSQL-oriented
-- transaction wrapper, so this migration is registered no_tx and every object is
-- created with IF NOT EXISTS: a process death between a committed schema change
-- and SQLx's history row is resumable. Every name is part of the schema
-- contract.
--
-- WHY THIS TABLE EXISTS (COVER-01..03). The connector reads a BOUNDED range of
-- run numbers on one workflow and one branch. Without a durable statement of
-- that range, "no CI failure is recorded" is indistinguishable from "no CI
-- failure happened", and the second claim is one this memory is not entitled to
-- make. A row here is the connector's answer to "what did you actually
-- measure?", and it is what lets a reader resolve a question about a run
-- OUTSIDE the range to UNKNOWN instead of to a false negative. The same row's
-- run-number range is the coverage runtime's observed interval, so the
-- epistemic window and the coverage cursor are the same numbers rather than two
-- bookkeeping systems that can drift.
--
-- The row is a POINTER, not evidence. window_id is the content address of the
-- window's own preimage and evidence_id names the accepted event that carries
-- the window observation, both derived in Rust; this table stores no payload
-- and grants no authority. Deleting a row loses an index into the ledger, never
-- a fact.
--
-- This is not one of the publication reader's eight tables; it is a
-- private-plane index row (PUBLIC-03/04). Like migrations 0018-0023 it carries
-- NO foreign key to any memory_control_* / memory_registry_* table, so
-- fleet_runtime needs no control-plane grant to write it.
--
-- SECURITY: every column here is a bound, an identifier, or a count. No
-- provider text, no annotation body, and no credential of any kind is stored
-- in this table; the provider's own authentication stays ambient in the
-- operator's environment and never reaches the database.

-- Ownership: fleet_migrator. One row per (connector instance, coverage domain,
-- measured window). window_id is the SHA-256 framing of the window preimage —
-- repository, workflow, branch, first and last run number, fetch instant — so
-- recording the same window twice is an idempotent primary-key conflict rather
-- than a duplicate claim.
CREATE TABLE IF NOT EXISTS memory_ci_measured_windows_v1 (
    tenant_id              UUID NOT NULL,
    project                STRING NOT NULL,
    connector_instance     STRING NOT NULL,
    repository_id          STRING NOT NULL,
    installation_id        INT8 NOT NULL,
    workflow               STRING NOT NULL,
    branch                 STRING NOT NULL,
    window_id              BYTES NOT NULL,
    first_run_number       INT8 NOT NULL,
    last_run_number        INT8 NOT NULL,
    fetched_at             TIMESTAMPTZ NOT NULL,
    admitted_run_count     INT8 NOT NULL,
    failed_run_count       INT8 NOT NULL,
    source_digest          BYTES NOT NULL,
    evidence_id            BYTES NOT NULL,
    recorded_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project, connector_instance, window_id),
    CONSTRAINT memory_ci_windows_project_bound
        CHECK (octet_length(project) BETWEEN 1 AND 256),
    CONSTRAINT memory_ci_windows_instance_bound
        CHECK (octet_length(connector_instance) BETWEEN 1 AND 256),
    CONSTRAINT memory_ci_windows_repository_bound
        CHECK (octet_length(repository_id) BETWEEN 1 AND 256),
    CONSTRAINT memory_ci_windows_installation_bound
        CHECK (installation_id >= 0),
    CONSTRAINT memory_ci_windows_workflow_bound
        CHECK (octet_length(workflow) BETWEEN 1 AND 4096),
    CONSTRAINT memory_ci_windows_branch_bound
        CHECK (octet_length(branch) BETWEEN 1 AND 4096),
    CONSTRAINT memory_ci_windows_window_id_shape
        CHECK (octet_length(window_id) = 32),
    CONSTRAINT memory_ci_windows_source_digest_shape
        CHECK (octet_length(source_digest) = 32),
    CONSTRAINT memory_ci_windows_evidence_id_shape
        CHECK (octet_length(evidence_id) = 32),
    -- Provider run numbers start at one. Admitting zero would name a run that
    -- cannot exist and would silently widen every containment answer below it.
    CONSTRAINT memory_ci_windows_range_shape
        CHECK (first_run_number >= 1 AND last_run_number >= first_run_number),
    -- A window may legitimately admit fewer runs than its span (a run number
    -- can belong to another workflow, or have been deleted), but it can never
    -- admit more, and it can never report more failures than runs.
    CONSTRAINT memory_ci_windows_counts_shape
        CHECK (
            admitted_run_count >= 0
            AND failed_run_count >= 0
            AND failed_run_count <= admitted_run_count
            AND admitted_run_count <= last_run_number - first_run_number + 1
        )
);

-- Resume and coverage-report lookups both read the newest window of one
-- coverage domain, so the domain columns lead and the range follows.
CREATE INDEX IF NOT EXISTS memory_ci_windows_domain_range_idx
    ON memory_ci_measured_windows_v1 (
        tenant_id, project, connector_instance, repository_id, workflow, branch,
        last_run_number DESC
    );
