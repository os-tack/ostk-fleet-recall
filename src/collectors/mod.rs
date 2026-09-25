//! Collectors: one generic sink for items from anywhere (ADR 0008).
//!
//! A collector turns provider material into a [`draft::CollectedItemDraftV1`]
//! and nothing more. Everything after that is one path, whatever the provider:
//!
//! ```text
//! draft (memory only)
//!   -> audience::classify     server-derived; a refusal is a digest-only dead letter
//!   -> draft::seal            sanitize -> redact -> split <= 32 KiB -> envelope -> stage id
//!   -> sink::stage            the collector outbox, idempotent on the stage id
//!   -> binding::build         connector.collected.<mode> -> evidence ingress candidate
//!   -> sink::drain            admission -> append (+ history, links, heads)
//!   -> bodies, lexical, dense
//! ```
//!
//! The pure half of that path:
//!
//! * [`text`] strips hidden Unicode and folds controls ([`text::sanitize_text`]);
//! * [`redaction`] is the collector redactor: the shared secret set plus the
//!   provider credential shapes, under the active package's redaction
//!   guarantee;
//! * [`audience`] decides whether an item may be admitted to the project, and
//!   on what basis, from provider facts and operator configuration only;
//! * [`draft`] holds the draft, the splitter, and [`draft::seal`];
//! * [`binding`] binds `connector.collected.<mode>` from the active package and
//!   builds the admission candidate from a staged envelope;
//! * [`heads`] is the current view's move rule and presentation;
//! * [`withdrawal`] decides what a narrowed audience hides and which channel
//!   may lift it: container observations, and items whose own audience
//!   narrowed.
//!
//! The durable half (ADR 0008 D4-D6, migrations 0033 and 0034):
//!
//! * [`sink`] stages drafts into the collector outbox in one serializable
//!   transaction, and drains staged rows through admission and the ledger,
//!   writing the item history, links, and heads in the append's own
//!   transaction;
//! * [`status`] upserts a collector's row in `memory_collector_sources_v1`;
//! * [`cockroach`] holds the statements, every one bound to one
//!   `(tenant_id, project)`.
//!
//! The worker's `collect` step drains the outbox (`src/worker/collect.rs`), and
//! evidence recall withholds a collected body whose item was deleted or
//! withdrawn, or whose container was withdrawn. The envelope itself, its
//! identity digests, and the plain-text input an import line or a capture
//! carries are contracts, in [`crate::memory_contracts::collected_item`].

pub mod audience;
pub mod binding;
pub mod cockroach;
pub mod draft;
pub mod heads;
pub mod redaction;
pub mod sink;
pub mod status;
pub mod text;
pub mod withdrawal;

#[cfg(test)]
pub(crate) mod test_support;
