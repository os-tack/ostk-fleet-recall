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
//!
//! The collectors (ADR 0008 D8):
//!
//! * [`ADAPTERS`] is the static table of provider adapters: one
//!   [`CollectorAdapterV1`] per provider, which validates a configured
//!   source's settings and builds its collectors. A new provider is one module
//!   and one row here: no registry generation, migration, or recall surface.
//! * [`pull`] is the pull framework: a [`pull::PullCollectorV1`] runs one pass
//!   and stages it page by page through a [`pull::PageStager`], stating how
//!   far it read each container ([`pull::ListingBoundV1`], which has no
//!   default);
//! * [`coverage`] turns a settled reconciliation pass into its
//!   `collector_observation` item and its coverage receipt;
//! * [`http`] is the provider HTTP seam every API collector talks through:
//!   bounded, TLS except on loopback, rate limits as answers, the credential
//!   read from the environment and kept in its header, errors scrubbed;
//! * [`docs`] is the documents-directory collector;
//! * [`slack`] is the Slack collector: channels pulled through the Web API
//!   with a bot token;
//! * [`linear`] is the Linear collector: teams' issues and comments pulled
//!   through the GraphQL API with a personal API key or an OAuth token;
//! * [`granola`] is the Granola collector: meeting notes' AI summaries (and,
//!   when the operator asks, their transcripts) pulled through the public API
//!   with an API key, from the folders the operator declares.
//!
//! Operator imports (ADR 0008 D9):
//!
//! * [`import`] stages a file of items (`items-jsonl`, [`import::jsonl`]) or
//!   a Slack export (a directory or a zip, [`import::slack_export`]) under
//!   `connector.collected.import` and records it as a snapshot of one
//!   provider scope, inline or on the worker's next `collect` step;
//! * [`command`] is `ostk-fleet-recall collect`: `import`, `status`,
//!   `dead-letters`, `retire`, and `retry`.
//!
//! Stage-7 ingress (ADR 0008 D12):
//!
//! * [`ingress`] is `ostk-fleet-recall ingress`: signed Slack, Linear, and
//!   Granola webhooks received on the private plane and kept as hints (ids
//!   only), which the worker's `collect` step re-reads through each
//!   provider's pull adapter ([`pull::ObjectFetcherV1`]) or turns into a
//!   push-mode tombstone, settling each hint in the transaction that stages
//!   what it caused.

pub mod audience;
pub mod binding;
pub mod cockroach;
pub mod command;
pub mod coverage;
pub mod docs;
pub mod draft;
pub mod granola;
pub mod heads;
pub mod http;
pub mod import;
pub mod ingress;
pub mod linear;
pub mod pull;
pub mod redaction;
pub mod sink;
pub mod slack;
pub mod status;
pub mod text;
pub mod withdrawal;

use crate::worker::CollectorSourceV1;

/// One provider's adapter: what a configured collector of that provider
/// runs.
pub trait CollectorAdapterV1: Send + Sync {
    /// The provider kind it reads.
    fn provider(&self) -> &'static str;

    /// Refuse a configured source the adapter could not run exactly as
    /// written: its settings (closed, `deny_unknown_fields`), and the audience
    /// policy the provider needs.
    ///
    /// # Errors
    ///
    /// A message naming the first refused value.
    fn validate(&self, source: &CollectorSourceV1) -> Result<(), String>;

    /// The pull collector of one configured source, or `None` when the
    /// provider has no pull mode. `environment` reads the deployment
    /// variables the settings name (a provider token); the process
    /// environment in production.
    ///
    /// # Errors
    ///
    /// As [`Self::validate`], and a credential the environment does not
    /// hold.
    fn pull(
        &self,
        source: &CollectorSourceV1,
        environment: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<Box<dyn pull::PullCollectorV1>>, String>;

    /// How often the source's reconciliation runs, in seconds, when it is
    /// not every pass: the sources file refuses a staleness bound shorter
    /// than it, which would call every source stale between reconciliations.
    fn reconcile_every_seconds(&self, _source: &CollectorSourceV1) -> Option<u64> {
        None
    }

    /// What re-reads the object an ingress hint names, for one configured
    /// source, or `None` when the provider takes no hints (ADR 0008 D12).
    /// `environment` is read as for [`Self::pull`].
    ///
    /// # Errors
    ///
    /// As [`Self::pull`].
    fn fetch_object(
        &self,
        _source: &CollectorSourceV1,
        _environment: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<Box<dyn pull::ObjectFetcherV1>>, String> {
        Ok(None)
    }

    /// The provider's webhook, when it has one the ingress receives: how a
    /// delivery's signature is checked and what it maps to (ADR 0008 D12).
    fn push(&self) -> Option<&'static dyn ingress::PushVerifierV1> {
        None
    }
}

/// Every provider adapter this build carries.
pub static ADAPTERS: [&dyn CollectorAdapterV1; 4] = [
    &docs::DocsAdapterV1,
    &slack::SlackAdapterV1,
    &linear::LinearAdapterV1,
    &granola::GranolaAdapterV1,
];

/// The adapter of `provider`, when this build carries one.
#[must_use]
pub fn adapter(provider: &str) -> Option<&'static dyn CollectorAdapterV1> {
    ADAPTERS
        .iter()
        .copied()
        .find(|adapter| adapter.provider() == provider)
}

#[cfg(test)]
pub(crate) mod test_support;
