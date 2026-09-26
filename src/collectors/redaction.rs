//! The collector redactor: the crate's one redactor ([`crate::redaction`]),
//! held under the active package's redaction guarantee so a collector cannot
//! stage without one (EVID-05).
//!
//! The matchers and the replacement discipline used to live here, and only
//! collected items saw the provider credential shapes; the transcript and git
//! connectors ran the six shared matchers alone, and the trial found Slack,
//! GitHub, Linear, Granola, and Stripe tokens in transcript turns and commit
//! messages stored and served in plaintext. Everything was lifted into
//! [`crate::redaction`] under one profile
//! ([`crate::redaction::REDACTION_PROFILE_VERSION`]), and this module is now
//! the collectors' view of it: re-exports, the type aliases the collector
//! code was written against, and [`CollectorRedactorV1`], which is a
//! [`RedactionGuaranteeV1`] with the collectors' spelling.
//!
//! Residual, recorded rather than hidden: a collected version sealed under an
//! older profile keeps its bytes; a re-read at the same provider order moves
//! the head to the profile-3 rendering (ADR 0008 D5).

use crate::evidence_ledger::ActiveStage4Package;
pub use crate::redaction::{
    CollectedSecretClassV1, CollectedSecretFindingV1, ProviderSecretClassV1, REDACTION_PLACEHOLDER,
    REDACTION_PROFILE_VERSION as COLLECTOR_REDACTION_PROFILE_VERSION, RedactionGuaranteeV1,
    RedactionPolicyError, SecretClassV1, scan_secrets as scan_collected_secrets,
};

/// What the collector redactor decided about one text.
pub type CollectorDispositionV1 = crate::redaction::RedactionDispositionV1;

/// The outcome of redacting one text.
pub type CollectorRedactionV1 = crate::redaction::RedactionOutcomeV1;

/// The redactor every collector stages through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorRedactorV1 {
    guarantee: RedactionGuaranteeV1,
}

impl CollectorRedactorV1 {
    /// A redactor under a proven guarantee.
    #[must_use]
    pub const fn new(guarantee: RedactionGuaranteeV1) -> Self {
        Self { guarantee }
    }

    /// Read the guarantee out of the active package, then build the redactor.
    pub fn from_active_package(active: &ActiveStage4Package) -> Result<Self, RedactionPolicyError> {
        RedactionGuaranteeV1::from_active_package(active).map(Self::new)
    }

    /// The guarantee this redactor runs under.
    #[must_use]
    pub const fn guarantee(&self) -> &RedactionGuaranteeV1 {
        &self.guarantee
    }

    /// The profile this redactor implements.
    #[must_use]
    pub const fn profile_version(&self) -> u32 {
        self.guarantee.profile_version()
    }

    /// Every finding of both sets, sorted and merged.
    #[must_use]
    pub fn scan(&self, text: &str) -> Vec<CollectedSecretFindingV1> {
        scan_collected_secrets(text)
    }

    /// Redact one text, then prove the result clean.
    #[must_use]
    pub fn redact(&self, text: &str) -> CollectorRedactionV1 {
        self.guarantee.apply(text)
    }
}

#[cfg(test)]
#[path = "redaction_tests.rs"]
mod tests;
