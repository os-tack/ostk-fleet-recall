//! The typed expectation a spec statement binds (Stage 6).
//!
//! A normative proposal carries only digests: its propositions name a
//! predicate schema and a `proposition_fingerprint`, never the thing the spec
//! actually asks for. [`RememberActionExpectationV1`] is that thing for the one
//! predicate/observer pair the genesis package admits
//! (`mcp.remember.allowed_actions` read by `observer.rust_enum`): which enum,
//! in which Rust source file of the repository, must or must not declare which
//! member.
//!
//! The expectation is bound to its proposal by content, in both directions
//! [`RememberActionExpectationV1::require_bound_to`] checks: the proposal's
//! single proposition fingerprint and its `parser_configuration_digest` are
//! both [`RememberActionExpectationV1::fingerprint`], and its applicability
//! selector names exactly the proposal's own repository. Approving a proposal
//! therefore approves exactly one expectation, and a stored expectation that
//! no longer hashes to what the proposal carries is detectable drift rather
//! than a silent re-interpretation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::connectors::git::MAX_GIT_PATH_BYTES;
use crate::memory_contracts::canonical::{CanonicalValue, encode_canonical};
use crate::memory_contracts::common::RegistryReferenceV1;
use crate::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest, framed_digest,
};
use crate::memory_contracts::discrepancy::DiscrepancySeverityV1;
use crate::memory_contracts::normative_v2::NormativeBindingProposalV2;
use crate::memory_contracts::{ContractError, ContractResult};

/// `schema_version` of [`RememberActionExpectationV1`].
pub const REMEMBER_ACTION_EXPECTATION_SCHEMA_VERSION: u32 = 1;

/// The applicability-selector key naming the repository a statement applies
/// to. Its value is the proposal's own `repository_entity_id`.
pub const REPOSITORY_SELECTOR_KEY: &str = "repository";

/// Upper bound on [`RememberActionExpectationV1::source_path`], in bytes: the
/// longest tree-entry path the git connector renders.
pub const MAX_SOURCE_PATH_BYTES: usize = MAX_GIT_PATH_BYTES;

/// Upper bound on an enum or member name, in bytes. An enum name must also fit
/// a contract identifier once lowercased, which the observer's run record
/// requires, and that bound is 128.
pub const MAX_RUST_IDENTIFIER_BYTES: usize = 128;

/// Whether the spec requires the member to be declared or not declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedMembershipV1 {
    /// The enum must declare the member.
    Present,
    /// The enum must not declare the member.
    Absent,
}

impl ExpectedMembershipV1 {
    /// Stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
        }
    }

    /// Whether the member is required to be declared.
    #[must_use]
    pub const fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }
}

/// What one spec statement expects of the repository's remember actions: the
/// Rust enum `enum_name` in `source_path` must (or must not) declare `member`.
///
/// The fields are the whole meaning of the statement's single proposition;
/// `severity` is carried into any discrepancy episode the statement opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RememberActionExpectationV1 {
    pub schema_version: u32,
    /// The predicate schema the proposal's proposition names.
    pub predicate: RegistryReferenceV1,
    /// Repository-relative path of the Rust source file that declares the
    /// enum, as git names it (`/`-separated, no leading `/`).
    pub source_path: String,
    /// The enum's Rust name.
    pub enum_name: String,
    /// The variant the expectation is about.
    pub member: String,
    pub expected: ExpectedMembershipV1,
    pub severity: DiscrepancySeverityV1,
}

impl RememberActionExpectationV1 {
    /// Shape checks: the schema version, a positive predicate version, a
    /// normalized relative source path, plain ASCII Rust identifiers, and a
    /// value the canonical profile can encode.
    ///
    /// # Errors
    ///
    /// [`ContractError::Schema`] naming the first field that fails.
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != REMEMBER_ACTION_EXPECTATION_SCHEMA_VERSION {
            return Err(schema("unsupported remember-action expectation version"));
        }
        self.predicate.validate()?;
        if !is_normalized_relative_path(&self.source_path) {
            return Err(schema(
                "expectation source_path is not a normalized repository-relative path",
            ));
        }
        if !is_plain_rust_identifier(&self.enum_name) {
            return Err(schema(
                "expectation enum_name is not a plain ASCII Rust identifier",
            ));
        }
        if !is_plain_rust_identifier(&self.member) {
            return Err(schema(
                "expectation member is not a plain ASCII Rust identifier",
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// The expectation's content identity under
    /// [`DigestDomain::NormativeMembershipExpectationV1`]. A proposal binds it
    /// as its single proposition fingerprint and as its parser configuration.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::validate`] refuses.
    pub fn fingerprint(&self) -> ContractResult<Sha256Digest> {
        Ok(domain_separated_digest(
            DigestDomain::NormativeMembershipExpectationV1,
            &self.canonical_bytes()?,
        ))
    }

    /// The exact canonical bytes [`Self::fingerprint`] digests.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::validate`] refuses.
    pub fn canonical_bytes(&self) -> ContractResult<Vec<u8>> {
        self.validate()?;
        encode_canonical(self)
    }

    /// Refuse a proposal that does not carry exactly this expectation.
    ///
    /// The proposal must be valid and have exactly one proposition, whose
    /// `predicate_schema` is [`Self::predicate`] and whose
    /// `proposition_fingerprint` is [`Self::fingerprint`]; its
    /// `parser_configuration_digest` must also be [`Self::fingerprint`]; and
    /// its applicability selector must be exactly
    /// `{"repository": <repository_entity_id>}`, the proposal's own subject.
    ///
    /// # Errors
    ///
    /// [`ContractError::Schema`] naming the binding that does not hold, or
    /// whatever validating either side refuses.
    pub fn require_bound_to(&self, proposal: &NormativeBindingProposalV2) -> ContractResult<()> {
        proposal.validate()?;
        let fingerprint = self.fingerprint()?;
        let [proposition] = proposal.propositions.as_slice() else {
            return Err(schema(
                "a spec statement proposal must carry exactly one proposition",
            ));
        };
        if proposition.predicate_schema != self.predicate {
            return Err(schema(
                "the proposal's proposition names a different predicate than its expectation",
            ));
        }
        if proposition.proposition_fingerprint != fingerprint {
            return Err(schema(
                "the proposal's proposition fingerprint is not its expectation's fingerprint",
            ));
        }
        if proposal.parser_configuration_digest != fingerprint {
            return Err(schema(
                "the proposal's parser configuration digest is not its expectation's fingerprint",
            ));
        }
        if proposal.applicability_selector != repository_selector(proposal) {
            return Err(schema(
                "the proposal's applicability selector must name exactly its own repository",
            ));
        }
        Ok(())
    }
}

/// The applicability selector a spec statement proposal must carry:
/// `{"repository": <repository_entity_id>}`.
#[must_use]
pub fn repository_selector(proposal: &NormativeBindingProposalV2) -> CanonicalValue {
    CanonicalValue::Object(BTreeMap::from([(
        REPOSITORY_SELECTOR_KEY.to_owned(),
        CanonicalValue::String(proposal.repository_entity_id.to_string()),
    )]))
}

/// The value one side of a spec comparison holds: `enum_name` does (or does
/// not) declare `member`, under [`DigestDomain::SpecMembershipValueV1`].
///
/// The normative side digests what its expectation requires and the observed
/// side digests what the observer verified, so the two compare by value. The
/// parts are length-framed, so no pair of names can collide with another by
/// moving a boundary.
#[must_use]
pub fn membership_value_digest(enum_name: &str, member: &str, present: bool) -> Sha256Digest {
    let condition = if present {
        ExpectedMembershipV1::Present
    } else {
        ExpectedMembershipV1::Absent
    };
    framed_digest(
        DigestDomain::SpecMembershipValueV1,
        &[
            enum_name.as_bytes(),
            member.as_bytes(),
            condition.as_str().as_bytes(),
        ],
    )
}

/// A plain ASCII Rust identifier that starts with a letter: what the observer
/// enumerates as a variant name, and what lowercases into a contract
/// identifier for an enum name.
pub(crate) fn is_plain_rust_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_RUST_IDENTIFIER_BYTES
        && bytes[0].is_ascii_alphabetic()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

/// A git tree path: `/`-separated, relative, with no empty, `.` or `..`
/// segment, no control character or backslash, and no leading `-` that a git
/// command line could read as an option.
fn is_normalized_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SOURCE_PATH_BYTES
        && !value.starts_with('-')
        && !value
            .chars()
            .any(|character| character.is_control() || character == '\\')
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn schema(message: &str) -> ContractError {
    ContractError::Schema(message.to_owned())
}

#[cfg(test)]
#[path = "expectation_tests.rs"]
mod tests;
