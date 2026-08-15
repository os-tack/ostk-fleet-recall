-- no-transaction
-- Require the verified control-bootstrap writer to bind its single database
-- acceptance timestamp explicitly. One schema change per non-transactional
-- migration keeps SQLx success metadata aligned with CockroachDB DDL jobs.

ALTER TABLE memory_control_bootstraps
    ALTER COLUMN accepted_at DROP DEFAULT;
