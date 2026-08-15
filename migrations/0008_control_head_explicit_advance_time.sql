-- no-transaction
-- Require every audited control-log head mutation to bind its database
-- acceptance timestamp explicitly.

ALTER TABLE memory_control_shard_heads
    ALTER COLUMN advanced_at DROP DEFAULT;
