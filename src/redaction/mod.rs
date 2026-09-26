//! Redaction and secret classification, applied BEFORE anything durable.
//!
//! This module is the crate's one secret boundary. The transcript connector
//! redacts every turn with it before canonicalizing, the lexical projector
//! redacts every recall text with it before a row is written, and any later
//! collector redacts with it before staging. It was first written beside the
//! transcript connector; nothing in it is transcript-specific, because the
//! shapes it matches are credentials wherever they appear.
//!
//! Two parts:
//!
//! * The `credential_shapes` submodule holds the closed [`SecretClassV1`] set,
//!   [`scan_secrets`], and [`redact`], whose fail-closed discipline (withhold
//!   an unredactable class whole; re-scan the result and withhold on any
//!   residual) is documented there.
//! * [`RedactionGuaranteeV1`] is the proof that the ACTIVE package's redaction
//!   policy promises redaction before the durable outbox and forbids secrets
//!   in recall. [`RedactionGuaranteeV1::from_active_package`] refuses to mint
//!   one unless the activated policy body makes exactly that promise, and a
//!   collector cannot stage without one (EVID-05, PRED-03).

mod credential_shapes;

pub use credential_shapes::{
    REDACTION_PLACEHOLDER, RedactionDispositionV1, RedactionOutcomeV1, SecretClassV1,
    SecretFindingV1, redact, scan_secrets,
};

use crate::evidence_ledger::ActiveStage4Package;
use crate::memory_contracts::ContractError;
use crate::memory_contracts::canonical::{decode_strict, encode_canonical};
use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::registry::{RegistryEntryKind, RegistryEntryV1};

/// Why no [`RedactionGuaranteeV1`] could be read out of the active package.
#[derive(Debug, thiserror::Error)]
pub enum RedactionPolicyError {
    /// The active package's redaction policy does not promise redaction before
    /// the durable outbox, or there is not exactly one such policy, so nothing
    /// may be staged at all (EVID-05).
    #[error("the active package does not guarantee redaction before the durable outbox")]
    NotGuaranteed,
    /// The activated policy body is not a redaction policy body this build
    /// reads.
    #[error("redaction policy contract failure: {0}")]
    Contract(#[from] ContractError),
}

/// Proof that the ACTIVE package's redaction policy promises redaction before
/// the durable outbox and forbids secrets in recall.
///
/// A collector cannot build a batch without one, so "redact before outbox" is
/// enforced by construction rather than by remembering to call the redactor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionGuaranteeV1 {
    policy_id: ContractId,
    policy_version: u32,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivatedRedactionPolicyBodyV1 {
    schema_version: u32,
    policy_id: ContractId,
    version: u32,
    failure_outcome: ActivatedFailureOutcomeV1,
    redact_before_durable_outbox: bool,
    secrets_allowed_in_recall: bool,
}

/// Single-variant on purpose: a policy that says anything but `withhold` fails
/// to deserialize, so "fail open" is not expressible in the wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ActivatedFailureOutcomeV1 {
    Withhold,
}

impl RedactionGuaranteeV1 {
    /// Read the activated redaction policy out of the active package and prove
    /// it makes the guarantee every collector depends on (EVID-05).
    pub fn from_active_package(active: &ActiveStage4Package) -> Result<Self, RedactionPolicyError> {
        let entries = active.registry_entries();
        let mut matching = entries
            .iter()
            .filter(|entry| entry.kind == RegistryEntryKind::RedactionPolicy);
        let entry: &RegistryEntryV1 = matching.next().ok_or(RedactionPolicyError::NotGuaranteed)?;
        if matching.next().is_some() {
            return Err(RedactionPolicyError::NotGuaranteed);
        }
        let body: ActivatedRedactionPolicyBodyV1 = decode_strict(&encode_canonical(&entry.body)?)?;
        if body.schema_version != 1
            || body.policy_id != entry.entry_id
            || body.version != entry.version
            || body.failure_outcome != ActivatedFailureOutcomeV1::Withhold
            || !body.redact_before_durable_outbox
            || body.secrets_allowed_in_recall
        {
            return Err(RedactionPolicyError::NotGuaranteed);
        }
        Ok(Self {
            policy_id: body.policy_id,
            policy_version: body.version,
        })
    }

    /// The activated policy this guarantee was read from.
    #[must_use]
    pub const fn policy_id(&self) -> &ContractId {
        &self.policy_id
    }

    /// The activated policy's version.
    #[must_use]
    pub const fn policy_version(&self) -> u32 {
        self.policy_version
    }

    /// Redact one text under this guarantee.
    ///
    /// Taking `&self` is the point: there is no free function a collector can
    /// call without first having proven the active package makes the promise.
    #[must_use]
    pub fn apply(&self, text: &str) -> RedactionOutcomeV1 {
        redact(text)
    }
}
