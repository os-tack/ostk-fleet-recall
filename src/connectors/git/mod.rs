//! Git history connector (W2-GIT): local object store -> accepted events.
//!
//! # What this connector claims
//!
//! Three families of provider fact, and no more:
//!
//! * **Commit facts.** Author, committer, message, tree, and recorded parents.
//!   The revision *is* the object id, so a commit fact is content-addressed by
//!   git itself.
//! * **Blob-source facts.** One tree entry naming blob content. Content
//!   identity is the blob id; the fact identity additionally names the commit,
//!   tree, path, and mode, so the same blob at two paths is two observations of
//!   one content.
//! * **Ref-observation facts.** Where a ref pointed at an instant. A ref is a
//!   moving pointer, so the durable fact is the *observation*, never the ref.
//!
//! # What it deliberately cannot claim
//!
//! Ancestry only. [`GitAncestryClaimV1`] has exactly one variant, so "deployed",
//! "released", and "merged to production" are unconstructible rather than
//! merely discouraged — those are claims about a system this connector never
//! reads. A turn-to-commit link is likewise a [`GitDeclaredLinkV1`] whose
//! verification state is the single variant `declared`: the connector reads a
//! local object store and has no evidence that any agent turn produced any
//! commit (PROV-01, REL-01).
//!
//! # The default-branch view advances, it never rewrites
//!
//! [`GitRefObservationLogV1`] is append-only, and an observation's immutable
//! revision closes over its sequence number and instant. A force push therefore
//! mints a NEW source fact naming the previous target; every earlier
//! observation keeps its exact bytes, its exact identity, and its place in the
//! ledger. The branch "view" is simply the newest observation, and it advances
//! only when new observation evidence arrives (EVENT-01, REPLAY-01).
//!
//! # Layout
//!
//! * [`fact`] — the provider-truth model and the identity derivations. Pure;
//!   unit-tested including every rejection path.
//! * [`scan`] — the read-only `git` subprocess reader and its byte-level
//!   parsers. The parsers are pure and unit-tested against real object bytes.
//! * [`ingress`] — resolving the active package's git connector and building
//!   [`crate::memory_contracts::evidence_v2::EvidenceIngressCandidateV2`]s
//!   whose scope comes from the witness and whose locator coordinates come from
//!   the activated recipe.
//! * [`drain`] — admitting and appending a batch through the W1-EVID seam, plus
//!   the coverage observation and the repository+ref resume cursor.
//!
//! # Invariants this module enforces
//!
//! * **EVID-04 / AUTH-04** — every candidate's scope is
//!   [`crate::evidence_ledger::ActiveStage4Package::scope`], which is the
//!   writer credential's, and the connector schema and identity recipes are
//!   resolved from the package whose digest equals the active head's. A
//!   cross-tenant candidate is rejected closed by admission before any
//!   derivation or database work.
//! * **PROV-01 / EVID-02** — locator coordinates are filled only from proven
//!   values; a recipe naming a coordinate this connector cannot prove is
//!   refused rather than guessed.
//! * **EVID-03** — the three clocks are ordered before admission is even
//!   called, and a commit clock ahead of the reader's is refused rather than
//!   back-dated.
//! * **EVENT-01 / REPLAY-01** — a re-scan reproduces byte-identical facts, so
//!   the ledger classifies it as an exact replay; a force push produces a new
//!   observation rather than a mutation of the old one.
//! * **EVID-05** — no private raw artifact is ever emitted: the private plane
//!   would need its own key, retention, and publication boundary, which this
//!   connector does not have.
//! * **COVER-03** — a coverage receipt is only built when the drain produced a
//!   ref-observation accepted event to bind, and only from facts the ledger
//!   made durable. A quarantine writes a dead-letter receipt and no event row,
//!   so a quarantined fact never becomes a receipt's anchor, never appears in
//!   the receipt's source manifest or count, and — when it is the ref
//!   observation itself — voids the whole scope's receipt closed rather than
//!   letting an older surviving observation stand in for it.

pub mod drain;
pub mod error;
pub mod fact;
pub mod ingress;
pub mod scan;

pub use drain::{
    GitCoverageBindingV1, GitDrainContextV1, GitDrainReportV1, drain_git_facts,
    git_coverage_observation, git_fact_canonical_bytes, git_fact_manifest_keys,
    git_resume_sequence, git_scan_manifest_digest,
};
pub use error::{
    GitDrainError, GitDrainResult, GitFactError, GitFactResult, GitIngressError, GitIngressResult,
    GitScanError, GitScanResult,
};
pub use fact::{
    GIT_FACT_SCHEMA_VERSION, GitAncestryClaimV1, GitBlobSourceFactV1, GitCommitFactV1,
    GitDeclaredLinkV1, GitDeclaredRelationV1, GitFactKindV1, GitFactV1, GitFileModeV1,
    GitIdentityV1, GitLinkVerificationV1, GitObjectId, GitRefName, GitRefObservationFactV1,
    GitRefObservationLogV1, GitRepositoryIdV1, MAX_GIT_MESSAGE_BYTES, MAX_GIT_PATH_BYTES,
};
pub use ingress::{GIT_FACT_MEDIA_TYPE, GitConnectorBindingV1, GitIngressClocksV1, GitIngressV1};
pub use scan::{GitRepositoryReader, GitScanRequestV1, GitScanV1, GitTreeScanModeV1};
