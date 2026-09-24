//! One spec conformance check, as recorded (Stage 6).
//!
//! Every comparison of an active spec statement against one commit leaves a
//! [`SpecCheckRecordV1`], whatever its verdict. Discrepancy episodes record
//! verified nonconformance only, so without these records "no episode" would
//! be indistinguishable from "never checked" and from "the observer could not
//! tell". The record is content-addressed ([`SpecCheckRecordV1::check_id`]):
//! the same comparison replays to the same identity, and a different verdict,
//! reason set, or episode is a different record.
//!
//! [`SpecCheckRecordV1::validate`] makes a record self-consistent before it
//! can be written or trusted on read: a `conforming` or `nonconforming`
//! verdict must follow from a verified observation and the expectation, an
//! `unknown` verdict must say why, and only a nonconforming check names an
//! episode.

use serde::{Deserialize, Serialize};

use crate::connectors::git::GitObjectId;
use crate::discrepancy_runtime::ComparisonIndeterminacyV1;
use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, domain_separated_digest};
use crate::memory_contracts::discrepancy::{
    DiscrepancyEpisodeFingerprintV1, DiscrepancyFamilyFingerprintV1,
};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::identity::{IdentityForm, ResourceUri};
use crate::memory_contracts::observer::{EvaluatedConditionV1, VerificationOutcomeV1};
use crate::memory_contracts::{ContractError, ContractResult};

use super::expectation::{ExpectedMembershipV1, is_plain_rust_identifier};

/// `schema_version` of [`SpecCheckRecordV1`].
pub const SPEC_CHECK_RECORD_SCHEMA_VERSION: u32 = 1;

/// Upper bound on a record's reason set: every indeterminacy reason at most
/// once.
pub const MAX_SPEC_CHECK_REASONS: usize = 10;

/// What one check concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecVerdictV1 {
    /// The observer verified a membership the expectation forbids, or
    /// verified the absence of one it requires.
    Nonconforming,
    /// The observer verified exactly what the expectation requires.
    Conforming,
    /// No verified conclusion either way; the record's reasons say why.
    Unknown,
}

impl SpecVerdictV1 {
    /// Stable wire name, as the `verdict` column stores it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nonconforming => "nonconforming",
            Self::Conforming => "conforming",
            Self::Unknown => "unknown",
        }
    }

    /// Parse a stored wire name.
    ///
    /// # Errors
    ///
    /// [`ContractError::Schema`] for any other string.
    pub fn parse(value: &str) -> ContractResult<Self> {
        match value {
            "nonconforming" => Ok(Self::Nonconforming),
            "conforming" => Ok(Self::Conforming),
            "unknown" => Ok(Self::Unknown),
            _ => Err(ContractError::Schema(format!(
                "unknown spec check verdict {value:?}"
            ))),
        }
    }
}

/// One comparison of one active spec statement against one commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecCheckRecordV1 {
    pub schema_version: u32,
    /// The normative statement the commit was judged against.
    pub statement_id: Sha256Digest,
    pub binding_family_id: ContractId,
    /// The discrepancy family a nonconformance under this statement belongs
    /// to.
    pub family_fingerprint: DiscrepancyFamilyFingerprintV1,
    /// The commit whose source was read.
    pub commit_oid: GitObjectId,
    /// The exact source version the observer read.
    pub observed_revision_uri: ResourceUri,
    /// The observer result event that measured the commit.
    pub observer_event_id: AcceptedEventId,
    /// The git blob event naming the exact source object the observer read.
    pub blob_event_id: AcceptedEventId,
    /// The member asked about; the statement's expectation member.
    pub member: String,
    /// What the statement's expectation requires.
    pub expected: ExpectedMembershipV1,
    pub observed_condition: EvaluatedConditionV1,
    pub verification_outcome: VerificationOutcomeV1,
    pub verdict: SpecVerdictV1,
    /// Why an `unknown` check could not conclude, strictly sorted. Empty for
    /// every other verdict.
    pub reasons: Vec<ComparisonIndeterminacyV1>,
    /// The discrepancy episode a nonconforming check opened or joined. Absent
    /// for every other verdict.
    pub episode: Option<DiscrepancyEpisodeFingerprintV1>,
    /// The instant the two sides were compared at.
    pub compared_at: CanonicalTimestamp,
}

impl SpecCheckRecordV1 {
    /// Structural and verdict consistency.
    ///
    /// # Errors
    ///
    /// [`ContractError::Schema`] naming the first rule that does not hold.
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != SPEC_CHECK_RECORD_SCHEMA_VERSION {
            return Err(schema("unsupported spec check record version"));
        }
        if self.statement_id == Sha256Digest::ZERO
            || self.family_fingerprint.digest() == Sha256Digest::ZERO
            || self.observer_event_id.digest() == Sha256Digest::ZERO
            || self.blob_event_id.digest() == Sha256Digest::ZERO
        {
            return Err(schema("a spec check record names a zero identity"));
        }
        if self.observer_event_id == self.blob_event_id {
            return Err(schema(
                "a spec check's observer event and blob event must be distinct",
            ));
        }
        if self.observed_revision_uri.identity_form() != IdentityForm::Version {
            return Err(schema("a spec check's observed revision is not a version"));
        }
        if !is_plain_rust_identifier(&self.member) {
            return Err(schema(
                "a spec check's member is not a plain ASCII Rust identifier",
            ));
        }
        let verified_presence =
            verified_presence(self.observed_condition, self.verification_outcome)?;
        if self.reasons.len() > MAX_SPEC_CHECK_REASONS
            || !self.reasons.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(ContractError::NonCanonicalSet { field: "reasons" });
        }
        match self.verdict {
            SpecVerdictV1::Nonconforming | SpecVerdictV1::Conforming => {
                let Some(present) = verified_presence else {
                    return Err(schema(
                        "a conforming or nonconforming check requires a verified observation",
                    ));
                };
                let conforms = present == self.expected.is_present();
                if conforms != (self.verdict == SpecVerdictV1::Conforming) {
                    return Err(schema(
                        "a spec check's verdict does not follow from its expectation and observation",
                    ));
                }
                if !self.reasons.is_empty() {
                    return Err(schema("only an unknown spec check carries reasons"));
                }
            }
            SpecVerdictV1::Unknown => {
                if self.reasons.is_empty() {
                    return Err(schema("an unknown spec check must say why"));
                }
            }
        }
        if self.episode.is_some() != (self.verdict == SpecVerdictV1::Nonconforming) {
            return Err(schema(
                "a spec check names an episode exactly when it is nonconforming",
            ));
        }
        if self
            .episode
            .is_some_and(|episode| episode.digest() == Sha256Digest::ZERO)
        {
            return Err(schema("a spec check names a zero episode"));
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// The record's content identity under [`DigestDomain::SpecCheckRecordV1`].
    ///
    /// # Errors
    ///
    /// Whatever [`Self::validate`] refuses.
    pub fn check_id(&self) -> ContractResult<Sha256Digest> {
        Ok(domain_separated_digest(
            DigestDomain::SpecCheckRecordV1,
            &self.canonical_bytes()?,
        ))
    }

    /// The exact canonical bytes [`Self::check_id`] digests.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::validate`] refuses.
    pub fn canonical_bytes(&self) -> ContractResult<Vec<u8>> {
        self.validate()?;
        encode_canonical(self)
    }
}

/// Whether the observation verified the member present (`Some(true)`) or
/// absent (`Some(false)`), or verified nothing (`None`). An outcome the
/// condition does not support, or an exact-set outcome, which no membership
/// question can reach, is refused.
fn verified_presence(
    condition: EvaluatedConditionV1,
    outcome: VerificationOutcomeV1,
) -> ContractResult<Option<bool>> {
    match (outcome, condition) {
        (VerificationOutcomeV1::VerifiedPositive, EvaluatedConditionV1::Present) => Ok(Some(true)),
        (VerificationOutcomeV1::VerifiedNegative, EvaluatedConditionV1::Absent) => Ok(Some(false)),
        (VerificationOutcomeV1::Candidate | VerificationOutcomeV1::Indeterminate, _) => Ok(None),
        (
            VerificationOutcomeV1::VerifiedPositive
            | VerificationOutcomeV1::VerifiedNegative
            | VerificationOutcomeV1::VerifiedExactSet,
            _,
        ) => Err(schema(
            "a spec check's verification outcome does not match its observed membership condition",
        )),
    }
}

fn schema(message: &str) -> ContractError {
    ContractError::Schema(message.to_owned())
}

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;
