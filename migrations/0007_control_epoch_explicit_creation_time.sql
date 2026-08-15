-- no-transaction
-- Require the verified control-bootstrap writer to bind the same database
-- timestamp to its epoch projection explicitly.

ALTER TABLE memory_control_log_epochs
    ALTER COLUMN created_at DROP DEFAULT;
