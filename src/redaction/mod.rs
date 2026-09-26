//! Redaction and secret classification, applied BEFORE anything durable.
//!
//! This module is the crate's one secret boundary. The transcript connector
//! redacts every turn with it before canonicalizing, the git connector redacts
//! every commit's text fields with it before building an ingress, the lexical
//! projector redacts every recall text with it before a row is written, and
//! every collector redacts with it before staging. One redactor, one profile,
//! one closed class set, wherever text enters the memory.
//!
//! Three parts:
//!
//! * The `credential_shapes` submodule holds the six shared matchers
//!   ([`SecretClassV1`]); `provider_shapes` holds the provider credential
//!   shapes ([`ProviderSecretClassV1`]): Slack, Linear, Granola, GitHub,
//!   Google, Anthropic, `OpenAI`, Stripe, webhook signing secrets, and signed
//!   JSON Web Tokens. [`CollectedSecretClassV1`] is the union, and
//!   [`scan_secrets`] runs both sets and merges their findings.
//! * [`redact`] is the replacement discipline, fail closed twice: an
//!   unredactable finding (a private key block) withholds the text whole; every
//!   other finding is replaced with [`REDACTION_PLACEHOLDER`]; the result is
//!   scanned again by both sets, and any residual withholds the text rather
//!   than staging a partial redaction. There is no path that stages a text the
//!   re-scan still flags. [`REDACTION_PROFILE_VERSION`] names the class set
//!   and the discipline, so a stricter set is a new profile.
//! * [`RedactionGuaranteeV1`] is the proof that the ACTIVE package's redaction
//!   policy promises redaction before the durable outbox and forbids secrets
//!   in recall. [`RedactionGuaranteeV1::from_active_package`] refuses to mint
//!   one unless the activated policy body makes exactly that promise, and no
//!   connector or collector can stage without one (EVID-05, PRED-03).

mod credential_shapes;
mod provider_shapes;

pub use credential_shapes::{REDACTION_PLACEHOLDER, SecretClassV1, SecretFindingV1};
pub use provider_shapes::ProviderSecretClassV1;

use credential_shapes::scan_shared_secrets;
use provider_shapes::scan_provider_secrets;

use crate::evidence_ledger::ActiveStage4Package;
use crate::memory_contracts::ContractError;
use crate::memory_contracts::canonical::{decode_strict, encode_canonical};
use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::registry::{RegistryEntryKind, RegistryEntryV1};

/// The redaction profile every connector report and collected-item envelope
/// records.
///
/// Profile 2 added a Linear webhook signing secret (`lin_wh_`) and Slack's
/// browser-session tokens (`xoxc-`, `xoxd-`) to profile 1's set. Profile 3
/// adds Stripe keys (`sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`) and is
/// the first profile every ingress runs: before it, only collected items saw
/// the provider shapes, while transcript turns and git facts ran the six
/// shared matchers alone. A collected version sealed under an older profile
/// at the same provider order is an older rendering, so a re-read moves the
/// head to the profile-3 one (ADR 0008 D5).
pub const REDACTION_PROFILE_VERSION: u32 = 3;

/// One class the redactor can report: a shared shape or a provider shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CollectedSecretClassV1 {
    /// A shape of the crate's shared set.
    Shared(SecretClassV1),
    /// A provider credential shape.
    Provider(ProviderSecretClassV1),
}

impl CollectedSecretClassV1 {
    /// Stable label, recorded in an envelope's redaction classes and in
    /// connector reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shared(class) => class.as_str(),
            Self::Provider(class) => class.as_str(),
        }
    }

    /// Whether replacing the matched range can salvage the text.
    #[must_use]
    pub const fn is_redactable(self) -> bool {
        match self {
            Self::Shared(class) => class.is_redactable(),
            Self::Provider(_) => true,
        }
    }
}

/// Serializes as its stable label, so a report carries `"stripe_key"` and
/// never a variant path.
impl serde::Serialize for CollectedSecretClassV1 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// One detected secret-shaped byte range of either set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectedSecretFindingV1 {
    /// Which shape matched.
    pub class: CollectedSecretClassV1,
    /// Inclusive start byte offset into the scanned text.
    pub byte_start: usize,
    /// Exclusive end byte offset into the scanned text.
    pub byte_end: usize,
}

/// What the redactor decided about one text (a transcript turn, a commit
/// message, a recall text, a collected item part).
#[derive(Clone, PartialEq, Eq)]
pub enum RedactionDispositionV1 {
    /// The text is clean or was fully redacted; `text` is safe to stage.
    Stage {
        /// The redacted body. Equal to the input when nothing matched.
        text: String,
    },
    /// The text must not be staged at all: an unredactable class matched, or
    /// the post-redaction re-scan still found a secret shape, so no
    /// partially-redacted body is durable.
    Withhold {
        /// The class that forced the refusal.
        class: CollectedSecretClassV1,
    },
}

/// Prints the disposition and never the text: a redaction outcome reaches
/// logs and reports, and the text it carries is exactly what must not.
impl std::fmt::Debug for RedactionDispositionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stage { text } => formatter
                .debug_struct("Stage")
                .field("text_bytes", &text.len())
                .finish(),
            Self::Withhold { class } => formatter
                .debug_struct("Withhold")
                .field("class", &class.as_str())
                .finish(),
        }
    }
}

/// The outcome of running the redactor over one text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionOutcomeV1 {
    /// What to do with the text.
    pub disposition: RedactionDispositionV1,
    /// Classes detected in the ORIGINAL text, sorted and deduplicated. Metadata
    /// only: it never carries matched bytes.
    pub classes: Vec<CollectedSecretClassV1>,
    /// Number of ranges replaced.
    pub redacted_ranges: u32,
}

impl RedactionOutcomeV1 {
    /// The body to stage, or `None` when the text is withheld.
    #[must_use]
    pub fn staged_text(&self) -> Option<&str> {
        match &self.disposition {
            RedactionDispositionV1::Stage { text } => Some(text),
            RedactionDispositionV1::Withhold { .. } => None,
        }
    }
}

/// Every finding of both sets, as each matcher reported it.
fn scan_unmerged(text: &str) -> Vec<CollectedSecretFindingV1> {
    let mut findings: Vec<CollectedSecretFindingV1> = scan_shared_secrets(text)
        .into_iter()
        .map(|finding| CollectedSecretFindingV1 {
            class: CollectedSecretClassV1::Shared(finding.class),
            byte_start: finding.byte_start,
            byte_end: finding.byte_end,
        })
        .collect();
    findings.extend(scan_provider_secrets(text.as_bytes()));
    findings
}

/// Sort and merge overlapping findings into the widest ranges.
fn merge(mut findings: Vec<CollectedSecretFindingV1>) -> Vec<CollectedSecretFindingV1> {
    findings.sort_by_key(|finding| (finding.byte_start, std::cmp::Reverse(finding.byte_end)));
    let mut merged: Vec<CollectedSecretFindingV1> = Vec::with_capacity(findings.len());
    for finding in findings {
        match merged.last_mut() {
            Some(previous) if finding.byte_start < previous.byte_end => {
                previous.byte_end = previous.byte_end.max(finding.byte_end);
                // An unredactable class anywhere in the merged range wins, so
                // merging can never turn a withhold into a replacement.
                if !finding.class.is_redactable() {
                    previous.class = finding.class;
                }
            }
            _ => merged.push(finding),
        }
    }
    merged
}

/// Every secret-shaped range in `text` of the shared set and the provider
/// set, sorted by start and merged so one replacement neutralizes every class
/// that matched there.
#[must_use]
pub fn scan_secrets(text: &str) -> Vec<CollectedSecretFindingV1> {
    merge(scan_unmerged(text))
}

/// Redact every detected range, then prove the result is clean.
///
/// Every class that matched is reported, including one whose range merged
/// into another's; each merged range is replaced once.
#[must_use]
pub fn redact(text: &str) -> RedactionOutcomeV1 {
    let findings = scan_unmerged(text);
    let mut classes: Vec<CollectedSecretClassV1> =
        findings.iter().map(|finding| finding.class).collect();
    classes.sort_unstable();
    classes.dedup();
    replace_and_verify(text, &merge(findings), classes)
}

/// Replace every finding, then re-scan with both sets: a residual withholds.
///
/// Separate from the scan so the re-scan is provably the last word even when
/// the findings it is handed do not cover every credential in the text (the
/// unit tests hand it deliberately incomplete findings).
pub(crate) fn replace_and_verify(
    text: &str,
    findings: &[CollectedSecretFindingV1],
    classes: Vec<CollectedSecretClassV1>,
) -> RedactionOutcomeV1 {
    let redacted_ranges = u32::try_from(findings.len()).unwrap_or(u32::MAX);
    let withhold = |class| RedactionOutcomeV1 {
        disposition: RedactionDispositionV1::Withhold { class },
        classes: classes.clone(),
        redacted_ranges,
    };
    // The first fence: an unredactable class withholds the whole text before a
    // partially-redacted body is even built, so there is no intermediate value
    // a later stage could accidentally stage (EVID-05).
    if let Some(finding) = findings
        .iter()
        .find(|finding| !finding.class.is_redactable())
    {
        return withhold(finding.class);
    }
    let mut redacted = String::with_capacity(text.len());
    let mut cursor = 0_usize;
    for finding in findings {
        // Byte offsets come from this same &str and every matcher only ever
        // stops on ASCII bytes, so the ranges are always char boundaries;
        // get() rather than indexing keeps a violation a refusal, not a panic.
        let Some(prefix) = text.get(cursor..finding.byte_start) else {
            return withhold(finding.class);
        };
        redacted.push_str(prefix);
        redacted.push_str(REDACTION_PLACEHOLDER);
        cursor = finding.byte_end;
    }
    let Some(tail) = text.get(cursor..) else {
        let class = findings.last().map_or(
            CollectedSecretClassV1::Shared(SecretClassV1::ApiKeyAssignment),
            |finding| finding.class,
        );
        return withhold(class);
    };
    redacted.push_str(tail);
    // The second fence: if anything still matches after redaction, refuse the
    // text outright rather than stage a partial redaction (EVID-05, PRED-03).
    if let Some(residual) = scan_secrets(&redacted).first() {
        return withhold(residual.class);
    }
    RedactionOutcomeV1 {
        disposition: RedactionDispositionV1::Stage { text: redacted },
        classes,
        redacted_ranges,
    }
}

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

    /// The profile this guarantee's redactions run under.
    #[must_use]
    pub const fn profile_version(&self) -> u32 {
        REDACTION_PROFILE_VERSION
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
