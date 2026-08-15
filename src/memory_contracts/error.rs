//! Errors returned by the offline memory contract layer.

use thiserror::Error;

/// Result type for pure memory-contract operations.
pub type ContractResult<T> = Result<T, ContractError>;

/// Fail-closed validation errors for canonical and identity-bearing artifacts.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContractError {
    #[error("canonical input exceeds the {limit}-byte limit")]
    InputTooLarge { limit: usize },
    #[error("canonical output exceeds the {limit}-byte limit")]
    OutputTooLarge { limit: usize },
    #[error("canonical JSON exceeds the maximum nesting depth of {limit}")]
    DepthLimit { limit: usize },
    #[error("canonical JSON exceeds the maximum node count of {limit}")]
    NodeLimit { limit: usize },
    #[error("canonical JSON collection exceeds the {limit}-element limit")]
    CollectionLimit { limit: usize },
    #[error("canonical JSON string exceeds the {limit}-byte limit")]
    StringTooLong { limit: usize },
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    #[error("duplicate decoded object key: {0}")]
    DuplicateKey(String),
    #[error("floating-point and exponent JSON numbers are forbidden")]
    FloatingPointForbidden,
    #[error("JSON integer is outside the safe range")]
    IntegerOutOfRange,
    #[error("negative zero is forbidden")]
    NegativeZero,
    #[error("string is not Unicode NFC")]
    NonNfcString,
    #[error("string contains a forbidden Unicode scalar")]
    ForbiddenUnicode,
    #[error("document is valid but is not already in canonical byte form")]
    NotCanonical,
    #[error("typed schema validation failed: {0}")]
    Schema(String),
    #[error("invalid lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("invalid contract identifier: {0}")]
    InvalidIdentifier(String),
    #[error("set field {field} is not strictly sorted and unique")]
    NonCanonicalSet { field: &'static str },
    #[error("registry package manifest does not match its entries")]
    ManifestMismatch,
    #[error("canonicalization profile mismatch")]
    ProfileMismatch,
    #[error("invalid resource identity recipe: {0}")]
    InvalidIdentityRecipe(String),
    #[error("invalid canonical resource locator: {0}")]
    InvalidResourceLocator(String),
    #[error("invalid OSTK resource URI")]
    InvalidResourceUri,
    #[error("registry activation precondition does not match the exact active head")]
    StaleRegistryHead,
    #[error("bootstrap receipt does not match its out-of-band pin")]
    BootstrapPinMismatch,
    #[error("invalid bootstrap signer policy: {0}")]
    InvalidSignerPolicy(String),
    #[error("bootstrap profile, scope, package, or epoch binding mismatch")]
    BootstrapBindingMismatch,
    #[error("bootstrap approval signature verification failed")]
    SignatureVerification,
    #[error("bootstrap approval threshold was not met")]
    ApprovalThresholdNotMet,
    #[error("same source fact and representation key produced a different accepted statement")]
    RepresentationCollision,
}
