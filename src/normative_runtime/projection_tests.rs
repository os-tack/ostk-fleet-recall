//! Unit tests for the pure active-normative projection fold.
//!
//! Every rejection path is an ordinary negative test. The contested-overlap
//! tests are the load-bearing ones: they assert not only that an overlap yields
//! `Unknown`, but that the fold is order-insensitive, so no future edit can
//! quietly reintroduce a recency or insertion-order tiebreak.

use super::*;
use crate::memory_contracts::digest::{DigestDomain, domain_separated_digest};
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::normative_v2::NormativeContestReasonV1;
use crate::memory_contracts::registry::RegistryHeadV1;

fn label(value: &str) -> Sha256Digest {
    domain_separated_digest(DigestDomain::RegistryEntry, value.as_bytes())
}

fn timestamp(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).unwrap()
}

fn family() -> ContractId {
    ContractId::new("slo.home.errors").unwrap()
}

fn registry_head() -> RegistryHeadBindingV1 {
    RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: label("activation"),
            package_digest: label("registry-package"),
            activation_policy_digest: label("activation-policy"),
        },
        effective_from: timestamp("2026-01-01T00:00:00.000000000Z"),
        effective_until: None,
    }
}

fn interval(statement: &str, from: &str, until: Option<&str>) -> NormativeStatementIntervalV1 {
    NormativeStatementIntervalV1 {
        statement_id: label(statement),
        effective_from: timestamp(from),
        effective_until: until.map(timestamp),
    }
}

fn lifecycle(
    kind: NormativeLifecycleKindV1,
    statement: &str,
    supersedes: Option<&str>,
    interval: NormativeStatementIntervalV1,
) -> NormativeLogRecordV1 {
    NormativeLogRecordV1::Lifecycle {
        event: NormativeLifecycleEventV1 {
            schema_version: 1,
            kind,
            binding_family_id: family(),
            statement_id: label(statement),
            registry_head: registry_head(),
            effective_at: timestamp("2026-08-15T09:00:00.000000000Z"),
            supersedes_statement_id: supersedes.map(label),
            waiver_reference_digest: None,
        },
        interval,
    }
}

fn contest(statements: &[&str]) -> NormativeLogRecordV1 {
    let mut ids: Vec<Sha256Digest> = statements.iter().copied().map(label).collect();
    ids.sort_unstable();
    NormativeLogRecordV1::Contest {
        contest: ContestedBindingV1 {
            schema_version: 1,
            binding_family_id: family(),
            contested_statement_ids: ids,
            reason: NormativeContestReasonV1::IndependentlyAcceptedUnestablishableOrdering,
            detected_at: timestamp("2026-08-16T09:00:00.000000000Z"),
            waiver_reference_digest: None,
        },
    }
}

fn entry(seq: u64, record: NormativeLogRecordV1) -> NormativeLogEntryV1 {
    let record_id = record.record_id().unwrap();
    NormativeLogEntryV1 {
        seq,
        record_id,
        record,
    }
}

fn activation(statement: &str, from: &str, until: Option<&str>) -> NormativeLogRecordV1 {
    lifecycle(
        NormativeLifecycleKindV1::Activation,
        statement,
        None,
        interval(statement, from, until),
    )
}

// --- lawful lifecycle ---

#[test]
fn one_activation_resolves_active() {
    let entries = vec![entry(
        1,
        activation("a", "2026-08-20T00:00:00.000000000Z", None),
    )];
    let projection = project_family(&family(), &entries).unwrap();
    assert_eq!(projection.cursor_seq, 1);
    assert_eq!(
        projection.resolution,
        NormativeResolutionV1::Active {
            statement_id: label("a")
        }
    );
    assert_eq!(projection.resolution.as_str(), "active");
    assert_eq!(
        projection.resolve_at(&timestamp("2026-08-21T00:00:00.000000000Z")),
        NormativePointResolutionV1::Bound(label("a"))
    );
    assert_eq!(
        projection.resolve_at(&timestamp("2026-08-19T00:00:00.000000000Z")),
        NormativePointResolutionV1::NoBinding
    );
}

#[test]
fn a_supersession_replaces_the_prior_statement_without_erasing_the_log() {
    let entries = vec![
        entry(1, activation("a", "2026-08-20T00:00:00.000000000Z", None)),
        entry(
            2,
            lifecycle(
                NormativeLifecycleKindV1::Supersession,
                "b",
                Some("a"),
                interval("b", "2026-08-22T00:00:00.000000000Z", None),
            ),
        ),
    ];
    let projection = project_family(&family(), &entries).unwrap();
    assert_eq!(
        projection.resolution,
        NormativeResolutionV1::Active {
            statement_id: label("b")
        }
    );
    // The prior activation is still in the log this projection was folded from.
    assert_eq!(entries.len(), 2);
    assert_eq!(projection.live_statement_ids(), vec![label("b")]);
}

#[test]
fn retirement_leaves_the_family_retired_and_the_log_intact() {
    for kind in [
        NormativeLifecycleKindV1::Retirement,
        NormativeLifecycleKindV1::Retraction,
        NormativeLifecycleKindV1::Expiry,
    ] {
        let entries = vec![
            entry(1, activation("a", "2026-08-20T00:00:00.000000000Z", None)),
            entry(
                2,
                lifecycle(
                    kind,
                    "a",
                    None,
                    interval("a", "2026-08-20T00:00:00.000000000Z", None),
                ),
            ),
        ];
        let projection = project_family(&family(), &entries).unwrap();
        assert_eq!(projection.resolution, NormativeResolutionV1::Retired);
        assert_eq!(projection.resolution.as_str(), "retired");
        assert!(projection.live.is_empty());
    }
}

#[test]
fn disjoint_live_statements_are_scheduled_and_resolve_point_in_time() {
    let entries = vec![
        entry(
            1,
            activation(
                "a",
                "2026-08-20T00:00:00.000000000Z",
                Some("2026-08-25T00:00:00.000000000Z"),
            ),
        ),
        entry(2, activation("b", "2026-08-25T00:00:00.000000000Z", None)),
    ];
    let projection = project_family(&family(), &entries).unwrap();
    assert_eq!(projection.resolution.as_str(), "scheduled");
    assert_eq!(
        projection.resolve_at(&timestamp("2026-08-21T00:00:00.000000000Z")),
        NormativePointResolutionV1::Bound(label("a"))
    );
    assert_eq!(
        projection.resolve_at(&timestamp("2026-08-26T00:00:00.000000000Z")),
        NormativePointResolutionV1::Bound(label("b"))
    );
    assert_eq!(projection.resolution.active_statement_id(), None);
}

// --- contested => unknown, never a winner ---

#[test]
fn a_declared_contest_over_two_live_statements_projects_unknown() {
    let entries = vec![
        entry(
            1,
            activation(
                "a",
                "2026-08-20T00:00:00.000000000Z",
                Some("2026-08-25T00:00:00.000000000Z"),
            ),
        ),
        entry(2, activation("b", "2026-08-25T00:00:00.000000000Z", None)),
        entry(3, contest(&["a", "b"])),
    ];
    let projection = project_family(&family(), &entries).unwrap();
    let mut expected = vec![label("a"), label("b")];
    expected.sort_unstable();
    assert_eq!(
        projection.resolution,
        NormativeResolutionV1::Unknown {
            contested_statement_ids: expected
        }
    );
    // A point-in-time question about a contested family is unknown even at an
    // instant where exactly one statement is nominally effective.
    assert_eq!(
        projection.resolve_at(&timestamp("2026-08-21T00:00:00.000000000Z")),
        NormativePointResolutionV1::Unknown
    );
    assert_eq!(projection.resolution.active_statement_id(), None);
}

#[test]
fn an_overlap_in_the_log_projects_unknown_without_any_contest_record() {
    // Defence in depth: the admission path refuses to create this, but if an
    // overlap ever reaches the log the fold must still refuse to pick a winner.
    let entries = vec![
        entry(1, activation("a", "2026-08-20T00:00:00.000000000Z", None)),
        entry(2, activation("b", "2026-08-22T00:00:00.000000000Z", None)),
    ];
    let projection = project_family(&family(), &entries).unwrap();
    assert!(matches!(
        projection.resolution,
        NormativeResolutionV1::Unknown { .. }
    ));
}

#[test]
fn contested_resolution_does_not_depend_on_the_order_the_records_arrived() {
    // The whole point: swapping the two conflicting activations must produce a
    // byte-identical projection apart from the record identities in the log.
    let forward = project_family(
        &family(),
        &[
            entry(1, activation("a", "2026-08-20T00:00:00.000000000Z", None)),
            entry(2, activation("b", "2026-08-22T00:00:00.000000000Z", None)),
        ],
    )
    .unwrap();
    let reversed = project_family(
        &family(),
        &[
            entry(1, activation("b", "2026-08-22T00:00:00.000000000Z", None)),
            entry(2, activation("a", "2026-08-20T00:00:00.000000000Z", None)),
        ],
    )
    .unwrap();
    assert_eq!(forward.resolution, reversed.resolution);
    assert_eq!(
        forward.canonical_bytes().unwrap(),
        reversed.canonical_bytes().unwrap()
    );
}

#[test]
fn a_contest_clears_only_when_authorized_events_leave_one_statement_live() {
    let mut entries = vec![
        entry(
            1,
            activation(
                "a",
                "2026-08-20T00:00:00.000000000Z",
                Some("2026-08-25T00:00:00.000000000Z"),
            ),
        ),
        entry(2, activation("b", "2026-08-25T00:00:00.000000000Z", None)),
        entry(3, contest(&["a", "b"])),
    ];
    assert!(matches!(
        project_family(&family(), &entries).unwrap().resolution,
        NormativeResolutionV1::Unknown { .. }
    ));
    // Retiring one contested statement is an authorized lifecycle event; only
    // then is the ambiguity genuinely gone.
    entries.push(entry(
        4,
        lifecycle(
            NormativeLifecycleKindV1::Retraction,
            "a",
            None,
            interval(
                "a",
                "2026-08-20T00:00:00.000000000Z",
                Some("2026-08-25T00:00:00.000000000Z"),
            ),
        ),
    ));
    let cleared = project_family(&family(), &entries).unwrap();
    assert_eq!(
        cleared.resolution,
        NormativeResolutionV1::Active {
            statement_id: label("b")
        }
    );
    // The contest record itself is preserved, not erased.
    assert!(cleared.declared_contested.contains(&label("a")));
}

// --- fail-closed rejections ---

#[test]
fn a_non_contiguous_sequence_is_rejected() {
    let entries = vec![entry(
        2,
        activation("a", "2026-08-20T00:00:00.000000000Z", None),
    )];
    assert!(project_family(&family(), &entries).is_err());
}

#[test]
fn a_record_for_another_binding_family_is_rejected() {
    let other = ContractId::new("slo.other.errors").unwrap();
    let entries = vec![entry(
        1,
        activation("a", "2026-08-20T00:00:00.000000000Z", None),
    )];
    assert!(project_family(&other, &entries).is_err());
}

#[test]
fn a_record_id_that_does_not_match_its_record_is_rejected() {
    let record = activation("a", "2026-08-20T00:00:00.000000000Z", None);
    let tampered = NormativeLogEntryV1 {
        seq: 1,
        record_id: label("not-the-record"),
        record,
    };
    assert!(project_family(&family(), &[tampered]).is_err());
}

#[test]
fn an_interval_that_describes_a_different_statement_is_rejected() {
    let record = lifecycle(
        NormativeLifecycleKindV1::Activation,
        "a",
        None,
        interval("b", "2026-08-20T00:00:00.000000000Z", None),
    );
    assert!(record.validate().is_err());
}

#[test]
fn superseding_a_statement_that_is_not_live_is_rejected() {
    let entries = vec![entry(
        1,
        lifecycle(
            NormativeLifecycleKindV1::Supersession,
            "b",
            Some("a"),
            interval("b", "2026-08-20T00:00:00.000000000Z", None),
        ),
    )];
    assert!(project_family(&family(), &entries).is_err());
}

#[test]
fn retiring_a_statement_that_is_not_live_is_rejected() {
    let entries = vec![entry(
        1,
        lifecycle(
            NormativeLifecycleKindV1::Retirement,
            "a",
            None,
            interval("a", "2026-08-20T00:00:00.000000000Z", None),
        ),
    )];
    assert!(project_family(&family(), &entries).is_err());
}

#[test]
fn activating_an_already_live_statement_is_rejected() {
    let entries = vec![
        entry(1, activation("a", "2026-08-20T00:00:00.000000000Z", None)),
        entry(2, activation("a", "2026-08-20T00:00:00.000000000Z", None)),
    ];
    assert!(project_family(&family(), &entries).is_err());
}

#[test]
fn an_inverted_effective_interval_is_rejected() {
    let record = lifecycle(
        NormativeLifecycleKindV1::Activation,
        "a",
        None,
        NormativeStatementIntervalV1 {
            statement_id: label("a"),
            effective_from: timestamp("2026-08-25T00:00:00.000000000Z"),
            effective_until: Some(timestamp("2026-08-20T00:00:00.000000000Z")),
        },
    );
    assert!(record.validate().is_err());
}

#[test]
fn a_log_longer_than_its_bound_is_rejected() {
    let entries: Vec<NormativeLogEntryV1> = (0..=MAX_FAMILY_LOG_ENTRIES)
        .map(|index| {
            entry(
                u64::try_from(index).unwrap() + 1,
                activation(&format!("s{index}"), "2026-08-20T00:00:00.000000000Z", None),
            )
        })
        .collect();
    assert!(project_family(&family(), &entries).is_err());
}

// --- projection identity ---

#[test]
fn the_projection_round_trips_through_its_canonical_bytes() {
    let entries = vec![
        entry(1, activation("a", "2026-08-20T00:00:00.000000000Z", None)),
        entry(
            2,
            lifecycle(
                NormativeLifecycleKindV1::Supersession,
                "b",
                Some("a"),
                interval("b", "2026-08-22T00:00:00.000000000Z", None),
            ),
        ),
    ];
    let projection = project_family(&family(), &entries).unwrap();
    let bytes = projection.canonical_bytes().unwrap();
    let decoded: NormativeFamilyProjectionV1 =
        crate::memory_contracts::canonical::decode_strict(&bytes).unwrap();
    assert_eq!(decoded, projection);
    assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
}

#[test]
fn incremental_folding_equals_a_full_rebuild() {
    let entries = vec![
        entry(1, activation("a", "2026-08-20T00:00:00.000000000Z", None)),
        entry(
            2,
            lifecycle(
                NormativeLifecycleKindV1::Supersession,
                "b",
                Some("a"),
                interval("b", "2026-08-22T00:00:00.000000000Z", None),
            ),
        ),
        entry(
            3,
            lifecycle(
                NormativeLifecycleKindV1::Retirement,
                "b",
                None,
                interval("b", "2026-08-22T00:00:00.000000000Z", None),
            ),
        ),
    ];
    let mut incremental = NormativeFamilyProjectionV1::empty(family());
    for one in &entries {
        incremental = apply_entry(&incremental, one).unwrap();
    }
    let rebuilt = project_family(&family(), &entries).unwrap();
    assert_eq!(
        incremental.canonical_bytes().unwrap(),
        rebuilt.canonical_bytes().unwrap()
    );
}
