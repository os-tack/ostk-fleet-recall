-- no-transaction
-- Forward-only predecessor hardening for control ledgers created by migration
-- 0003. Keep this as one online schema change: SQLx executes CockroachDB DDL
-- outside a PostgreSQL transaction and records this version only after the
-- unique-index backfill succeeds.
--
-- This version precedes the four timestamp-default migrations. A legacy fork
-- therefore fails closed while all four defaults remain unchanged. The exact
-- index name is part of the schema contract; do not mask drift with
-- conditional creation.
--
-- The unique predecessor projection prevents two events in one scoped shard
-- from claiming the same chain predecessor. It does not make raw INSERT a
-- supported append API: a holder of direct event INSERT can still plant an
-- otherwise unique future offset and wedge that shard. Keep control-writer
-- credentials exclusive and append only through the audited CAS path.
--
-- Registry activation remains genesis-only. A successor authority or head
-- rotation requires an additive schema migration and a separately versioned,
-- canonically verified contract; this migration does not grant generic
-- successor semantics.

CREATE UNIQUE INDEX memory_control_events_predecessor_unique_idx
    ON memory_control_events (
        tenant_id,
        project,
        epoch_id,
        shard,
        previous_chain_digest
    );
