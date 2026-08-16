use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::{Number, Value};

use crate::ledger::Claim;

/// Immutable identifier for the proposition-aware legacy conflict contract.
///
/// A new identifier is required because durable rows written by the original
/// `same_key_typed_value` detector used polarity as if it were another value
/// dimension. Those rows must be reconciled explicitly rather than silently
/// reinterpreted under this contract.
pub const FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2: &str = "same_key_functional_value_v2";

/// Human-readable summary persisted beside every v2 conflict observation.
pub const FUNCTIONAL_VALUE_CONFLICT_RATIONALE_V2: &str = "overlapping lifecycle-current functional-key claims affirm different values or affirm and negate the same value";

#[must_use]
pub fn normalize_key_part(value: &str) -> String {
    value
        .trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-")
}

#[must_use]
pub fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<_, _> = map
                .iter()
                .map(|(key, value)| (key.clone(), canonical_json(value)))
                .collect();
            serde_json::to_value(sorted).unwrap_or(Value::Null)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_json).collect()),
        other => other.clone(),
    }
}

fn normalized_json_number(number: &Number) -> Option<(bool, String, i64)> {
    let rendered = number.to_string();
    let (negative, unsigned) = rendered
        .strip_prefix('-')
        .map_or((false, rendered.as_str()), |unsigned| (true, unsigned));
    let (mantissa, explicit_exponent) =
        if let Some((mantissa, exponent)) = unsigned.split_once(['e', 'E']) {
            (mantissa, exponent.parse::<i64>().ok()?)
        } else {
            (unsigned, 0_i64)
        };

    let (whole, fraction) = mantissa
        .split_once('.')
        .map_or((mantissa, ""), |(whole, fraction)| (whole, fraction));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let fraction_len = i64::try_from(fraction.len()).ok()?;
    let mut exponent = explicit_exponent.checked_sub(fraction_len)?;
    let mut digits = String::with_capacity(whole.len() + fraction.len());
    digits.push_str(whole);
    digits.push_str(fraction);
    let first_nonzero = digits.bytes().position(|byte| byte != b'0');
    let Some(first_nonzero) = first_nonzero else {
        return Some((false, "0".into(), 0));
    };
    digits.drain(..first_nonzero);
    while digits.ends_with('0') {
        digits.pop();
        exponent = exponent.checked_add(1)?;
    }
    Some((negative, digits, exponent))
}

fn jsonb_values_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => {
            match (normalized_json_number(left), normalized_json_number(right)) {
                (Some(left), Some(right)) => left == right,
                _ => left == right,
            }
        }
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| jsonb_values_equal(left, right))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, left)| {
                    right
                        .get(key)
                        .is_some_and(|right| jsonb_values_equal(left, right))
                })
        }
        _ => left == right,
    }
}

#[must_use]
pub fn intervals_overlap(
    a_from: Option<DateTime<Utc>>,
    a_to: Option<DateTime<Utc>>,
    b_from: Option<DateTime<Utc>>,
    b_to: Option<DateTime<Utc>>,
) -> bool {
    a_to.is_none_or(|to| b_from.is_none_or(|from| from < to))
        && b_to.is_none_or(|to| a_from.is_none_or(|from| from < to))
}

/// Compare two exact typed propositions for one functional claim key.
///
/// `+1` affirms the exact value and `-1` negates that exact value. Two
/// affirmations conflict when their values differ, an affirmation conflicts
/// with a negation only when they name the same value, and two negations do
/// not conflict. Invalid in-memory polarity values fail closed; persisted
/// claims are additionally protected by a database check constraint.
#[must_use]
pub fn functional_values_are_incompatible(
    left_value: &Value,
    left_polarity: i16,
    right_value: &Value,
    right_polarity: i16,
) -> bool {
    let values_equal = jsonb_values_equal(left_value, right_value);
    match (left_polarity, right_polarity) {
        (1, 1) => !values_equal,
        (1, -1) | (-1, 1) => values_equal,
        _ => false,
    }
}

#[must_use]
pub fn claims_are_incompatible(left: &Claim, right: &Claim) -> bool {
    left.conflict_eligible
        && right.conflict_eligible
        && left.state.is_current()
        && right.state.is_current()
        && left.project == right.project
        && left.claim_key.is_some()
        && left.claim_key == right.claim_key
        && intervals_overlap(
            left.valid_from,
            left.valid_to,
            right.valid_from,
            right.valid_to,
        )
        && left
            .value
            .as_ref()
            .zip(right.value.as_ref())
            .is_some_and(|(left_value, right_value)| {
                functional_values_are_incompatible(
                    left_value,
                    left.polarity,
                    right_value,
                    right.polarity,
                )
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{ClaimKind, ClaimState};

    fn claim(id: i64, value: &str, polarity: i16) -> Claim {
        let now = Utc::now();
        Claim {
            id,
            project: "fleet".into(),
            kind: ClaimKind::Decision,
            claim_key: Some("fleet-store::database-choice".into()),
            subject: Some("fleet-store".into()),
            predicate: Some("database-choice".into()),
            value: Some(Value::String(value.into())),
            text: value.into(),
            polarity,
            state: ClaimState::Active,
            origin: "operator_asserted".into(),
            actor: None,
            confidence: 1.0,
            valid_from: None,
            valid_to: None,
            superseded_by: None,
            revision: 1,
            conflict_eligible: true,
            created_at: now,
            updated_at: now,
            support: Vec::new(),
            conflict_ids: Vec::new(),
        }
    }

    #[test]
    fn detects_same_key_incompatible_values() {
        assert!(claims_are_incompatible(
            &claim(1, "cockroachdb", 1),
            &claim(2, "postgresql", 1)
        ));
    }

    #[test]
    fn ignores_equivalent_values() {
        assert!(!claims_are_incompatible(
            &claim(1, "cockroachdb", 1),
            &claim(2, "cockroachdb", 1)
        ));
    }

    #[test]
    fn polarity_vectors_are_proposition_aware_and_symmetric() {
        let vectors = [
            // CE-1: affirming CockroachDB is compatible with negating a
            // different exact value, PostgreSQL.
            (("cockroachdb", 1), ("postgresql", -1), false),
            // CE-2: two exact-value negations are compatible.
            (("postgresql", -1), ("mysql", -1), false),
            // CE-3: affirmation and negation of the same value conflict.
            (("cockroachdb", 1), ("cockroachdb", -1), true),
            // CE-4: legacy subject::predicate keys are functional, so two
            // different affirmed values conflict.
            (("cockroachdb", 1), ("postgresql", 1), true),
        ];

        for ((left_value, left_polarity), (right_value, right_polarity), expected) in vectors {
            let left = claim(1, left_value, left_polarity);
            let right = claim(2, right_value, right_polarity);
            assert_eq!(claims_are_incompatible(&left, &right), expected);
            assert_eq!(claims_are_incompatible(&right, &left), expected);
        }
    }

    #[test]
    fn invalid_or_missing_in_memory_proposition_fails_closed() {
        let valid = claim(1, "cockroachdb", 1);
        let invalid_polarity = claim(2, "postgresql", 0);
        assert!(!claims_are_incompatible(&valid, &invalid_polarity));

        let mut missing_value = claim(3, "postgresql", 1);
        missing_value.value = None;
        assert!(!claims_are_incompatible(&valid, &missing_value));
    }

    #[test]
    fn functional_comparison_matches_jsonb_key_and_number_semantics() {
        assert_eq!(
            canonical_json(&serde_json::json!({"b": 2, "a": 1.0})),
            serde_json::json!({"a": 1.0, "b": 2})
        );
        assert!(!functional_values_are_incompatible(
            &serde_json::json!(1),
            1,
            &serde_json::json!(1.0),
            1,
        ));
        assert!(!functional_values_are_incompatible(
            &serde_json::json!(10_000_000_000_000_000_000_u64),
            1,
            &serde_json::json!(1e19_f64),
            1,
        ));
        assert!(!functional_values_are_incompatible(
            &serde_json::json!(-0.0),
            1,
            &serde_json::json!(0),
            1,
        ));
        assert!(functional_values_are_incompatible(
            &serde_json::json!(1.5),
            1,
            &serde_json::json!(1),
            1,
        ));
    }

    #[test]
    fn half_open_intervals_touch_without_overlap() {
        let at = Utc::now();
        assert!(!intervals_overlap(None, Some(at), Some(at), None));
    }
}
