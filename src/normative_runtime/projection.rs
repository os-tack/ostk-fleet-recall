//! Pure active-normative projection: fold an ordered normative log into one
//! binding family's resolution (W3-NORM, Stage 6).
//!
//! There is no I/O here. The fold is a total function of the durable log, so
//! [`CockroachNormativeActivationRepository::rebuild_projection`] can replay the
//! stored canonical records and must reproduce the incrementally maintained
//! projection byte for byte.
//!
//! # The one semantic that matters
//!
//! A **contested** overlap resolves to [`NormativeResolutionV1::Unknown`] and
//! never to a winner. There is no arm anywhere in this file that breaks a tie by
//! recency, by insertion order, by sequence number, or by any other implicit
//! ordering: [`resolve`] derives `Unknown` from the *set* of live statements and
//! the *set* of declared contests, both of which are order-insensitive
//! (`BTreeMap`/`BTreeSet`). Reversing the order of two conflicting activations
//! in the log therefore produces the identical projection.
//!
//! [`CockroachNormativeActivationRepository::rebuild_projection`]: super::cockroach::CockroachNormativeActivationRepository::rebuild_projection

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::normative_v2::{
    ContestedBindingV1, NormativeHeadRebaseV1, NormativeLifecycleEventV1, NormativeLifecycleKindV1,
};
use crate::memory_contracts::{ContractError, ContractResult};

/// `schema_version` carried by every projection this runtime writes.
pub const NORMATIVE_PROJECTION_SCHEMA_VERSION: u32 = 1;

/// Upper bound on one binding family's normative log. A rebuild replays every
/// record, so the log is bounded rather than unbounded-and-hoped-for.
pub const MAX_FAMILY_LOG_ENTRIES: usize = 4096;

/// The effective interval a statement claims, carried alongside its lifecycle
/// event so the projection can detect overlap from the log alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormativeStatementIntervalV1 {
    pub statement_id: Sha256Digest,
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
}

impl NormativeStatementIntervalV1 {
    fn validate(&self) -> ContractResult<()> {
        if self.statement_id == Sha256Digest::ZERO
            || self
                .effective_until
                .as_ref()
                .is_some_and(|until| until <= &self.effective_from)
        {
            return Err(ContractError::Schema(
                "invalid normative statement interval".into(),
            ));
        }
        Ok(())
    }

    fn contains(&self, at: &CanonicalTimestamp) -> bool {
        &self.effective_from <= at && self.effective_until.as_ref().is_none_or(|until| at < until)
    }

    fn overlaps(&self, other: &Self) -> bool {
        let self_starts_before_other_ends = other
            .effective_until
            .as_ref()
            .is_none_or(|until| &self.effective_from < until);
        let other_starts_before_self_ends = self
            .effective_until
            .as_ref()
            .is_none_or(|until| &other.effective_from < until);
        self_starts_before_other_ends && other_starts_before_self_ends
    }
}

/// One durable normative-log record. Lifecycle events, contest records, and head
/// rebases share one stream so a rebuild has exactly one ordered source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
// Both variants are canonical contract records handled one at a time and stored
// as their own canonical bytes; boxing either would add an indirection to every
// fold step to save a few hundred bytes in a log bounded at MAX_FAMILY_LOG_ENTRIES.
#[allow(clippy::large_enum_variant)]
pub enum NormativeLogRecordV1 {
    /// An activation, retirement, retraction, expiry, or supersession, with the
    /// effective interval of the statement it names.
    Lifecycle {
        event: NormativeLifecycleEventV1,
        interval: NormativeStatementIntervalV1,
    },
    /// Two or more independently accepted statements whose precedence cannot be
    /// established. Recording one is the only way a family becomes `Unknown`
    /// without an overlap already being visible in the log.
    Contest { contest: ContestedBindingV1 },
    /// The family's head moved to another registry head with its live
    /// statements unchanged (ADR 0008 D3). A no-op for resolution: the fold
    /// only advances its cursor over it.
    Rebase { rebase: NormativeHeadRebaseV1 },
}

impl NormativeLogRecordV1 {
    /// The binding family this record belongs to.
    #[must_use]
    pub const fn binding_family_id(&self) -> &ContractId {
        match self {
            Self::Lifecycle { event, .. } => &event.binding_family_id,
            Self::Contest { contest } => &contest.binding_family_id,
            Self::Rebase { rebase } => &rebase.binding_family_id,
        }
    }

    /// The record's own contract identity (`event_id` or `contested_id`).
    pub fn record_id(&self) -> ContractResult<Sha256Digest> {
        match self {
            Self::Lifecycle { event, .. } => event.event_id(),
            Self::Contest { contest } => contest.contested_id(),
            Self::Rebase { rebase } => rebase.record_id(),
        }
    }

    /// `'lifecycle'`, `'contest'`, or `'rebase'`, matching the log's kind
    /// check (migration 0024, widened by migration 0032).
    #[must_use]
    pub const fn record_kind(&self) -> &'static str {
        match self {
            Self::Lifecycle { .. } => "lifecycle",
            Self::Contest { .. } => "contest",
            Self::Rebase { .. } => "rebase",
        }
    }

    /// Full shape validation, including that a lifecycle record's interval
    /// actually describes the statement the event names.
    pub fn validate(&self) -> ContractResult<()> {
        match self {
            Self::Lifecycle { event, interval } => {
                event.validate()?;
                interval.validate()?;
                if interval.statement_id != event.statement_id {
                    return Err(ContractError::Schema(
                        "normative log record interval does not describe its event's statement"
                            .into(),
                    ));
                }
                Ok(())
            }
            Self::Contest { contest } => contest.validate(),
            Self::Rebase { rebase } => rebase.validate(),
        }
    }
}

/// One sequenced record in a binding family's normative log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormativeLogEntryV1 {
    /// Strictly increasing, starting at 1, per binding family.
    pub seq: u64,
    /// The record's own contract identity as stored.
    pub record_id: Sha256Digest,
    /// The canonical preimage as stored, folded verbatim on rebuild.
    pub record: NormativeLogRecordV1,
}

/// Derived verdict for one binding family.
///
/// `Unknown` is the fail-closed arm: it is produced by a declared contest or by
/// a detected overlap between live statements, and it names the statements that
/// caused it rather than choosing among them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum NormativeResolutionV1 {
    /// Nothing is live for this family.
    Retired,
    /// Exactly one live statement.
    Active { statement_id: Sha256Digest },
    /// Several live statements with pairwise-disjoint effective intervals: a
    /// lawful schedule, resolvable at a point in time, never at "now" implicitly.
    Scheduled { statement_ids: Vec<Sha256Digest> },
    /// Contested. Dependent comparisons naming this family must report unknown.
    Unknown {
        contested_statement_ids: Vec<Sha256Digest>,
    },
}

impl NormativeResolutionV1 {
    /// `'active' | 'scheduled' | 'unknown' | 'retired'`, matching the
    /// migration-0024 column check.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Retired => "retired",
            Self::Active { .. } => "active",
            Self::Scheduled { .. } => "scheduled",
            Self::Unknown { .. } => "unknown",
        }
    }

    /// The single active statement, if the family resolved to exactly one.
    #[must_use]
    pub const fn active_statement_id(&self) -> Option<Sha256Digest> {
        match self {
            Self::Active { statement_id } => Some(*statement_id),
            Self::Retired | Self::Scheduled { .. } | Self::Unknown { .. } => None,
        }
    }
}

/// What a point-in-time question about a binding family answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormativePointResolutionV1 {
    /// No statement is effective at that instant.
    NoBinding,
    /// Exactly one statement is effective at that instant.
    Bound(Sha256Digest),
    /// The family is contested; the answer is unknown, not a winner.
    Unknown,
}

/// The active-normative projection for one binding family.
///
/// `live` and `declared_contested` are the fold state; `resolution` is derived
/// from them by [`resolve`] and stored only so a reader does not have to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormativeFamilyProjectionV1 {
    pub schema_version: u32,
    pub binding_family_id: ContractId,
    pub cursor_seq: u64,
    /// Live statements, strictly sorted by `statement_id`.
    pub live: Vec<NormativeStatementIntervalV1>,
    /// Every statement ever named by a contest record, strictly sorted.
    pub declared_contested: Vec<Sha256Digest>,
    pub resolution: NormativeResolutionV1,
}

impl NormativeFamilyProjectionV1 {
    /// The empty projection for a family whose log has not been folded yet.
    #[must_use]
    pub const fn empty(binding_family_id: ContractId) -> Self {
        Self {
            schema_version: NORMATIVE_PROJECTION_SCHEMA_VERSION,
            binding_family_id,
            cursor_seq: 0,
            live: Vec::new(),
            declared_contested: Vec::new(),
            resolution: NormativeResolutionV1::Retired,
        }
    }

    /// The exact bytes stored in `canonical_projection`.
    pub fn canonical_bytes(&self) -> ContractResult<Vec<u8>> {
        encode_canonical(self)
    }

    /// Answer a point-in-time question. A contested family answers
    /// [`NormativePointResolutionV1::Unknown`] — never a statement.
    #[must_use]
    pub fn resolve_at(&self, at: &CanonicalTimestamp) -> NormativePointResolutionV1 {
        if matches!(self.resolution, NormativeResolutionV1::Unknown { .. }) {
            return NormativePointResolutionV1::Unknown;
        }
        let mut matched = self.live.iter().filter(|interval| interval.contains(at));
        match (matched.next(), matched.next()) {
            (None, _) => NormativePointResolutionV1::NoBinding,
            (Some(only), None) => NormativePointResolutionV1::Bound(only.statement_id),
            // Unreachable while `resolve` maps every overlap to Unknown; kept as
            // a fail-closed arm rather than a silent pick.
            (Some(_), Some(_)) => NormativePointResolutionV1::Unknown,
        }
    }

    /// The live statement identities, strictly sorted.
    #[must_use]
    pub fn live_statement_ids(&self) -> Vec<Sha256Digest> {
        self.live
            .iter()
            .map(|interval| interval.statement_id)
            .collect()
    }

    fn from_state(
        binding_family_id: ContractId,
        cursor_seq: u64,
        live: &BTreeMap<Sha256Digest, NormativeStatementIntervalV1>,
        declared_contested: &BTreeSet<Sha256Digest>,
    ) -> Self {
        let live_vec: Vec<NormativeStatementIntervalV1> = live.values().cloned().collect();
        let contested_vec: Vec<Sha256Digest> = declared_contested.iter().copied().collect();
        let resolution = resolve(&live_vec, declared_contested);
        Self {
            schema_version: NORMATIVE_PROJECTION_SCHEMA_VERSION,
            binding_family_id,
            cursor_seq,
            live: live_vec,
            declared_contested: contested_vec,
            resolution,
        }
    }

    fn into_state(
        self,
    ) -> (
        BTreeMap<Sha256Digest, NormativeStatementIntervalV1>,
        BTreeSet<Sha256Digest>,
    ) {
        let live = self
            .live
            .into_iter()
            .map(|interval| (interval.statement_id, interval))
            .collect();
        let contested = self.declared_contested.into_iter().collect();
        (live, contested)
    }
}

/// Derive the resolution from the live set and the declared contests.
///
/// Order-insensitive by construction: it reads a `Vec` that is always sorted by
/// `statement_id` and a `BTreeSet`, and it never consults a sequence number, a
/// timestamp ranking, or the insertion order of the log.
fn resolve(
    live: &[NormativeStatementIntervalV1],
    declared_contested: &BTreeSet<Sha256Digest>,
) -> NormativeResolutionV1 {
    let mut contested: BTreeSet<Sha256Digest> = BTreeSet::new();

    // A declared contest counts only while at least two of the statements it
    // names are still live: once authorized lifecycle events have retired all
    // but one, the ambiguity is genuinely gone.
    let open_declared: BTreeSet<Sha256Digest> = live
        .iter()
        .map(|interval| interval.statement_id)
        .filter(|statement_id| declared_contested.contains(statement_id))
        .collect();
    if open_declared.len() >= 2 {
        contested.extend(open_declared);
    }

    // Defence in depth: an overlap that reached the log at all is contested,
    // whatever produced it. The admission path already refuses to create one.
    for (index, first) in live.iter().enumerate() {
        for second in live.iter().skip(index + 1) {
            if first.overlaps(second) {
                contested.insert(first.statement_id);
                contested.insert(second.statement_id);
            }
        }
    }

    if !contested.is_empty() {
        return NormativeResolutionV1::Unknown {
            contested_statement_ids: contested.into_iter().collect(),
        };
    }
    match live {
        [] => NormativeResolutionV1::Retired,
        [only] => NormativeResolutionV1::Active {
            statement_id: only.statement_id,
        },
        _ => NormativeResolutionV1::Scheduled {
            statement_ids: live
                .iter()
                .map(|interval| interval.statement_id)
                .collect::<Vec<_>>(),
        },
    }
}

/// Fold one record into a projection, advancing its cursor to `entry.seq`.
///
/// Fails closed on a non-contiguous sequence, on a record naming a different
/// binding family, on a supersession or retirement whose target is not live, and
/// on an activation whose statement is already live. A rebase changes nothing
/// but the cursor.
pub fn apply_entry(
    projection: &NormativeFamilyProjectionV1,
    entry: &NormativeLogEntryV1,
) -> ContractResult<NormativeFamilyProjectionV1> {
    entry.record.validate()?;
    if entry.record.record_id()? != entry.record_id {
        return Err(ContractError::Schema(
            "normative log entry record_id does not match its canonical record".into(),
        ));
    }
    if entry.record.binding_family_id() != &projection.binding_family_id {
        return Err(ContractError::Schema(
            "normative log entry belongs to a different binding family".into(),
        ));
    }
    if entry.seq != projection.cursor_seq.saturating_add(1) {
        return Err(ContractError::Schema(
            "normative log entry is not contiguous with the projection cursor".into(),
        ));
    }

    let family = projection.binding_family_id.clone();
    let (mut live, mut declared_contested) = projection.clone().into_state();

    match &entry.record {
        NormativeLogRecordV1::Lifecycle { event, interval } => match event.kind {
            NormativeLifecycleKindV1::Activation => {
                if live.contains_key(&event.statement_id) {
                    return Err(ContractError::Schema(
                        "normative activation names a statement that is already live".into(),
                    ));
                }
                live.insert(event.statement_id, interval.clone());
            }
            NormativeLifecycleKindV1::Supersession => {
                let Some(target) = event.supersedes_statement_id else {
                    return Err(ContractError::Schema(
                        "normative supersession without a target reached the projection".into(),
                    ));
                };
                if live.remove(&target).is_none() {
                    return Err(ContractError::Schema(
                        "normative supersession names a statement that is not live".into(),
                    ));
                }
                if live.insert(event.statement_id, interval.clone()).is_some() {
                    return Err(ContractError::Schema(
                        "normative supersession names a statement that is already live".into(),
                    ));
                }
            }
            NormativeLifecycleKindV1::Retirement
            | NormativeLifecycleKindV1::Retraction
            | NormativeLifecycleKindV1::Expiry => {
                if live.remove(&event.statement_id).is_none() {
                    return Err(ContractError::Schema(
                        "normative retirement names a statement that is not live".into(),
                    ));
                }
            }
        },
        NormativeLogRecordV1::Contest { contest } => {
            declared_contested.extend(contest.contested_statement_ids.iter().copied());
        }
        // A rebase moves the head's registry digests, which the projection does
        // not hold: the live set, the declared contests, and so the resolution
        // are exactly what they were. Only the cursor advances.
        NormativeLogRecordV1::Rebase { .. } => {}
    }

    Ok(NormativeFamilyProjectionV1::from_state(
        family,
        entry.seq,
        &live,
        &declared_contested,
    ))
}

/// Fold a whole binding-family log from empty. The rebuild path.
pub fn project_family(
    binding_family_id: &ContractId,
    entries: &[NormativeLogEntryV1],
) -> ContractResult<NormativeFamilyProjectionV1> {
    if entries.len() > MAX_FAMILY_LOG_ENTRIES {
        return Err(ContractError::Schema(
            "normative binding family log exceeds its bound".into(),
        ));
    }
    let mut projection = NormativeFamilyProjectionV1::empty(binding_family_id.clone());
    for entry in entries {
        projection = apply_entry(&projection, entry)?;
    }
    Ok(projection)
}

#[cfg(test)]
#[path = "projection_tests.rs"]
mod tests;
