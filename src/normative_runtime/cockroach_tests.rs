//! Statement-shape tests for the `CockroachDB` normative activation runtime.
//!
//! These need no database: they pin the properties of the SQL itself that the
//! security argument rests on. The behavioural proof lives in
//! `tests/normative_activation_live.rs`.

use super::*;

const ALL_STATEMENTS: &[(&str, &str)] = &[
    ("SEED_HEAD_SQL", SEED_HEAD_SQL),
    ("LOCK_HEAD_SQL", LOCK_HEAD_SQL),
    ("SELECT_HEAD_SQL", SELECT_HEAD_SQL),
    ("SELECT_FAMILY_HEADS_SQL", SELECT_FAMILY_HEADS_SQL),
    ("ADVANCE_HEAD_SQL", ADVANCE_HEAD_SQL),
    ("APPEND_LOG_SQL", APPEND_LOG_SQL),
    ("SELECT_LOG_SQL", SELECT_LOG_SQL),
    ("UPSERT_PROJECTION_SQL", UPSERT_PROJECTION_SQL),
    ("SELECT_PROJECTION_SQL", SELECT_PROJECTION_SQL),
];

#[test]
fn every_statement_is_keyed_by_the_trusted_tenant_and_project() {
    for (name, sql) in ALL_STATEMENTS {
        assert!(
            sql.contains("tenant_id") && sql.contains("project"),
            "{name} must bind the trusted scope pair"
        );
    }
}

#[test]
fn the_head_is_locked_before_it_is_compared() {
    assert!(LOCK_HEAD_SQL.contains("FOR UPDATE"));
}

#[test]
fn the_head_advance_is_itself_a_compare_and_set() {
    // Revision equality is the ABA-safe half: a head that went A -> B -> A
    // carries the same binding-set digest but never the same revision.
    assert!(ADVANCE_HEAD_SQL.contains("head_revision = $10"));
    assert!(ADVANCE_HEAD_SQL.contains("active_binding_set_digest IS NOT DISTINCT FROM $11"));
    assert!(ADVANCE_HEAD_SQL.contains("RETURNING head_revision"));
}

#[test]
fn the_projection_cursor_can_only_move_forward() {
    assert!(UPSERT_PROJECTION_SQL.contains("cursor_seq < excluded.cursor_seq"));
    assert!(UPSERT_PROJECTION_SQL.contains("RETURNING cursor_seq"));
}

#[test]
fn the_normative_log_is_append_only() {
    // A retirement or supersession must never rewrite the prior activation, so
    // no statement in this module may update or delete a log row.
    for (name, sql) in ALL_STATEMENTS {
        let touches_log = sql.contains("memory_normative_log_v1");
        let mutates = sql.contains("UPDATE public.memory_normative_log_v1")
            || sql.contains("DELETE FROM public.memory_normative_log_v1");
        assert!(
            !(touches_log && mutates),
            "{name} must not rewrite the normative log"
        );
    }
    assert!(APPEND_LOG_SQL.starts_with("INSERT INTO public.memory_normative_log_v1"));
    // No ON CONFLICT: a replayed record id must surface as the unique-index
    // violation it is, not be silently swallowed.
    assert!(!APPEND_LOG_SQL.contains("ON CONFLICT"));
}

#[test]
fn the_log_is_read_in_sequence_order_for_a_deterministic_rebuild() {
    assert!(SELECT_LOG_SQL.contains("ORDER BY seq"));
}

#[test]
fn only_migration_0024_tables_are_touched() {
    for (name, sql) in ALL_STATEMENTS {
        let tables = [
            "memory_normative_heads_v1",
            "memory_normative_log_v1",
            "memory_normative_projections_v1",
        ];
        assert!(
            tables.iter().any(|table| sql.contains(table)),
            "{name} must name a migration-0024 table"
        );
        assert!(
            !sql.contains("memory_control_") && !sql.contains("memory_registry_"),
            "{name} must not reach into the control or registry plane"
        );
    }
}

#[test]
fn a_runtime_bound_to_a_zero_registry_digest_cannot_be_constructed() {
    // Constructed without a pool, so this only exercises the validation arm;
    // `new` rejects before it stores anything.
    let unbound = NormativeRegistryBindingV1 {
        registry_package_digest: Sha256Digest::ZERO,
        activation_policy_digest: Sha256Digest::ZERO,
    };
    assert!(unbound.validate().is_err());
}

#[test]
fn sequence_conversions_fail_closed_outside_the_int8_range() {
    assert!(seq_as_i64(u64::MAX).is_err());
    assert!(seq_from_i64(-1).is_err());
    assert_eq!(seq_from_i64(7).unwrap(), 7);
    assert_eq!(seq_as_i64(7).unwrap(), 7);
}

#[test]
fn a_stored_digest_of_the_wrong_length_fails_closed() {
    assert!(digest_from(&[0_u8; 31]).is_err());
    assert!(digest_from(&[0_u8; 33]).is_err());
    assert!(digest_from(&[0_u8; 32]).is_ok());
}
