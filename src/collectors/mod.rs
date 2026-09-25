//! Collectors: one generic sink for items from anywhere (ADR 0008).
//!
//! A collector turns provider material into a [`draft::CollectedItemDraftV1`]
//! and nothing more. Everything after that is one path, whatever the provider:
//!
//! ```text
//! draft (memory only)
//!   -> audience::classify     server-derived; a refusal is a digest-only dead letter
//!   -> draft::seal            sanitize -> redact -> split <= 32 KiB -> envelope -> stage id
//!   -> (sink) stage           the collector outbox, idempotent on the stage id
//!   -> binding::build         connector.collected.<mode> -> evidence ingress candidate
//!   -> admission -> append -> bodies, lexical, dense
//! ```
//!
//! This module holds the pure half of that path; the durable sink and the
//! provider adapters build on it:
//!
//! * [`text`] strips hidden Unicode and folds controls ([`text::sanitize_text`]);
//! * [`redaction`] is the collector redactor: the shared secret set plus the
//!   provider credential shapes, under the active package's redaction
//!   guarantee;
//! * [`audience`] decides whether an item may be admitted to the project, and
//!   on what basis, from provider facts and operator configuration only;
//! * [`draft`] holds the draft, the splitter, and [`draft::seal`];
//! * [`binding`] binds `connector.collected.<mode>` from the active package and
//!   builds the admission candidate from a staged envelope.
//!
//! The envelope itself, its identity digests, and the plain-text input an
//! import line or a capture carries are contracts, in
//! [`crate::memory_contracts::collected_item`].

pub mod audience;
pub mod binding;
pub mod draft;
pub mod redaction;
pub mod text;

#[cfg(test)]
pub(crate) mod test_support;
