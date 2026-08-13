use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::ledger::Claim;

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
        && (left.value != right.value || left.polarity != right.polarity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{ClaimKind, ClaimState};

    fn claim(id: i64, value: &str) -> Claim {
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
            polarity: 1,
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
            &claim(1, "cockroachdb"),
            &claim(2, "postgresql")
        ));
    }

    #[test]
    fn ignores_equivalent_values() {
        assert!(!claims_are_incompatible(
            &claim(1, "cockroachdb"),
            &claim(2, "cockroachdb")
        ));
    }

    #[test]
    fn half_open_intervals_touch_without_overlap() {
        let at = Utc::now();
        assert!(!intervals_overlap(None, Some(at), Some(at), None));
    }
}
