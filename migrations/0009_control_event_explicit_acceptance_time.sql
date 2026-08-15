-- no-transaction
-- Require every audited control event append to bind its database acceptance
-- timestamp explicitly. Migrations 0005 through 0009 together close the
-- predecessor and implicit-clock gaps without rewriting historical migration
-- bytes or existing immutable rows.

ALTER TABLE memory_control_events
    ALTER COLUMN accepted_at DROP DEFAULT;
