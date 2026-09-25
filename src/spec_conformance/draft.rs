//! Drafting one spec statement (Stage 6): a normative proposal bound to exact
//! byte spans of a spec document at one commit, carrying one typed
//! [`RememberActionExpectationV1`].
//!
//! [`draft_statement`] is pure given its inputs: a fresh strict witness, the
//! binding family's current binding-set digest, and a local git reader. Every
//! field of the proposal comes from one of them, never from a caller's
//! assertion:
//!
//! * the spec document is bound through
//!   [`bind_observed_source`](crate::observer_runtime::bind_observed_source),
//!   so the blob the path resolves to at the commit, its git object name, and
//!   its content digest must all agree; `repository_version_id` is that
//!   binding's version URI and `blob_id` names the blob's content digest;
//! * each cited span is digested over exactly the bytes it selects, under
//!   [`DigestDomain::NormativeSourceSpanBytesV1`];
//! * the proposal's parser configuration and its single proposition
//!   fingerprint are both [`RememberActionExpectationV1::fingerprint`], so
//!   approving the proposal approves exactly one expectation;
//! * the predicate is the one the genesis package admits `observer.rust_enum`
//!   for ([`spec_predicate`]), and the applicability evaluator is the genesis
//!   package's own ([`spec_applicability_evaluator`]);
//! * the subject is the repository entity the active package's
//!   `identity.github.repository` recipe derives from the provider's numeric
//!   repository id ([`repository_subject`]), in the witness's contract
//!   namespaces;
//! * the registry head is exactly the witnessed one, which activation later
//!   requires byte for byte.
//!
//! A draft grants nothing. It becomes normative only when
//! [`super::activation::activate_spec_statement`] verifies approvals over its
//! statement id under the active policy.

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::PathBuf;
use std::str::FromStr as _;

use crate::Result;
use crate::connectors::git::{GitObjectId, GitRepositoryIdV1, GitRepositoryReader};
use crate::error::FleetError;
use crate::memory_contracts::canonical::CanonicalValue;
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, HexBytes, RegistryReferenceV1,
};
use crate::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest, framed_digest,
};
use crate::memory_contracts::discrepancy::DiscrepancySeverityV1;
use crate::memory_contracts::genesis::{
    SemanticallyClosedGenesisPackage, SemanticallyDecodedGenesisEntryV1,
};
use crate::memory_contracts::identity::{ResourceUri, derive_entity_from_components};
use crate::memory_contracts::normative::{NormativePropositionV1, SourceByteSpanV1};
use crate::memory_contracts::normative_v2::NormativeBindingProposalV2;
use crate::memory_contracts::registry::RegistryEntryKind;
use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;
use crate::memory_contracts::{ContractError, ContractResult};
use crate::normative_runtime::NormativeActivationRepository as _;
use crate::observer_runtime::{
    MAX_OBSERVED_SOURCE_BYTES, ObservedSourceV1, ObserverSourcePinV1, bind_observed_source,
    source_content_digest,
};
use crate::registry_witness::{WriterAuthorityRuntime, WriterAuthorityWitness};

use super::activation::normative_repository;
use super::expectation::{
    ExpectedMembershipV1, REMEMBER_ACTION_EXPECTATION_SCHEMA_VERSION, RememberActionExpectationV1,
    is_normalized_relative_path, repository_selector,
};

/// The observer admission whose predicate every spec statement names.
pub const SPEC_OBSERVER_ID: &str = "observer.rust_enum";

/// The version of [`SPEC_OBSERVER_ID`] the genesis package admits.
pub const SPEC_OBSERVER_VERSION: u32 = 1;

/// The identity recipe a spec statement's repository subject derives under.
pub const REPOSITORY_IDENTITY_RECIPE_ID: &str = "identity.github.repository";

/// The locator component of [`REPOSITORY_IDENTITY_RECIPE_ID`]: the provider's
/// numeric repository id, in decimal.
pub const REPOSITORY_LOCATOR_KEY: &str = "provider_repository_id";

/// Upper bound on a spec document, in bytes: the bound the observer reads any
/// pinned source under. A larger document is refused, never truncated.
pub const MAX_SPEC_DOCUMENT_BYTES: usize = MAX_OBSERVED_SOURCE_BYTES;

/// `schema_version` of every drafted proposal.
const NORMATIVE_PROPOSAL_SCHEMA_VERSION: u32 = 2;

/// What an operator asks `ostk-spec draft` to propose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftStatementRequestV1 {
    /// The repository's git directory (a bare repository or a `.git`).
    pub git_dir: PathBuf,
    /// Operator-declared repository identity, as the worker's git source
    /// names it.
    pub repository_id: ContractId,
    /// Provider-installation coordinate, as the worker's git source names it.
    pub installation_id: u64,
    /// The provider's numeric repository id the subject derives from.
    pub provider_repository_id: u64,
    /// The exact commit the spec document is read at.
    pub commit: GitObjectId,
    /// Repository-relative path of the spec document.
    pub spec_path: String,
    /// Half-open byte ranges of the spec document the statement cites.
    pub spans: Vec<Range<u64>>,
    pub binding_family_id: ContractId,
    /// The expectation: `enum_name` in `source_path` must (or must not)
    /// declare `member`.
    pub source_path: String,
    pub enum_name: String,
    pub member: String,
    pub expected: ExpectedMembershipV1,
    pub severity: DiscrepancySeverityV1,
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
    /// The live statement this one explicitly supersedes, if any.
    pub supersedes: Option<Sha256Digest>,
    pub proposer: ContractId,
    /// The spec document's author. Must differ from the proposer, and neither
    /// may approve (the activation policy's separation of duty).
    pub author: ContractId,
}

impl DraftStatementRequestV1 {
    /// The repository identity every git fact of this repository carries.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] for an invalid identity.
    pub fn repository(&self) -> Result<GitRepositoryIdV1> {
        GitRepositoryIdV1::from_trusted_config(self.repository_id.clone(), self.installation_id)
            .map_err(|error| {
                FleetError::Configuration(format!("invalid spec repository identity: {error}"))
            })
    }

    /// A reader over [`Self::git_dir`] bound to [`Self::repository`], running
    /// `git` from `PATH`.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] for an invalid identity.
    pub fn reader(&self) -> Result<GitRepositoryReader> {
        GitRepositoryReader::new(&self.git_dir, self.repository()?, None).map_err(|error| {
            FleetError::Configuration(format!("the spec repository cannot be read: {error}"))
        })
    }
}

/// Draft the proposal and expectation `request` describes, under `witness`.
///
/// `current_binding_set` is the binding family's active binding-set digest
/// as its durable head records it (`None` for a family nothing is live in):
/// the compare-and-set value activation will require. `reader` must be bound
/// to the repository `request` names.
///
/// # Errors
///
/// A contract error for a request the proposal or expectation contracts
/// refuse (including an empty, reversed, overlapping, or out-of-range span,
/// and an author who is also the proposer); [`FleetError::Memory`] when the
/// spec document cannot be bound at the commit.
pub fn draft_statement(
    witness: &WriterAuthorityWitness,
    current_binding_set: Option<Sha256Digest>,
    reader: &GitRepositoryReader,
    request: &DraftStatementRequestV1,
) -> Result<(NormativeBindingProposalV2, RememberActionExpectationV1)> {
    if reader.repository() != &request.repository()? {
        return Err(FleetError::Configuration(
            "the git reader is bound to another repository than the draft names".into(),
        ));
    }
    if request.author == request.proposer {
        return Err(schema("the spec author and the proposer must be distinct principals").into());
    }
    if !is_normalized_relative_path(&request.spec_path) {
        return Err(schema("the spec path is not a normalized repository-relative path").into());
    }
    let genesis = witness.genesis_package();
    let expectation = RememberActionExpectationV1 {
        schema_version: REMEMBER_ACTION_EXPECTATION_SCHEMA_VERSION,
        predicate: spec_predicate(genesis)?,
        source_path: request.source_path.clone(),
        enum_name: request.enum_name.clone(),
        member: request.member.clone(),
        expected: request.expected,
        severity: request.severity,
    };
    let fingerprint = expectation.fingerprint()?;

    let document = bind_spec_document(reader, &request.commit, &request.spec_path)?;
    let source_spans = select_spans(document.bytes(), &request.spans)?;
    let scope = AuthenticatedProjectScopeV1::from_trusted_context(
        witness.contract_tenant_namespace().clone(),
        witness.contract_project_namespace().clone(),
    );
    let repository_entity_id =
        repository_subject(witness.package(), &scope, request.provider_repository_id)?;
    let repository_version_id = document.observed_revision_uri().map_err(|error| {
        FleetError::Memory(format!(
            "the spec document has no version identity: {error}"
        ))
    })?;

    let mut proposal = NormativeBindingProposalV2 {
        schema_version: NORMATIVE_PROPOSAL_SCHEMA_VERSION,
        profile: witness
            .package()
            .manifest_verified_package()
            .package()
            .profile
            .clone(),
        scope,
        binding_family_id: request.binding_family_id.clone(),
        expected_active_binding_set_digest: current_binding_set,
        repository_entity_id,
        repository_version_id,
        blob_id: spec_blob_uri(document.content_digest())?,
        exact_path_bytes: HexBytes::new(request.spec_path.as_bytes().to_vec())?,
        source_spans,
        parser_artifact_id: spec_parser_artifact_id()?,
        parser_configuration_digest: fingerprint,
        propositions: vec![NormativePropositionV1 {
            predicate_schema: expectation.predicate.clone(),
            proposition_fingerprint: fingerprint,
        }],
        applicability_evaluator: spec_applicability_evaluator(genesis)?,
        applicability_selector: CanonicalValue::Null,
        effective_from: request.effective_from.clone(),
        effective_until: request.effective_until.clone(),
        registry_head: witness.head_binding().clone(),
        explicitly_supersedes_statement_id: request.supersedes,
        proposer_principal_id: request.proposer.clone(),
        source_author_principal_id: request.author.clone(),
    };
    proposal.applicability_selector = repository_selector(&proposal);
    expectation.require_bound_to(&proposal)?;
    Ok((proposal, expectation))
}

/// [`draft_statement`] under a freshly verified head of `runtime`, with the
/// family's current binding set read from its durable normative head.
///
/// # Errors
///
/// Whatever the strict witness or [`draft_statement`] refuses, and
/// [`FleetError::Memory`] for a family whose head was seeded under another
/// registry package or activation policy: normative families do not follow a
/// registry head change, so nothing drafted now could activate there.
pub async fn draft_spec_statement(
    runtime: &WriterAuthorityRuntime,
    request: &DraftStatementRequestV1,
) -> Result<(NormativeBindingProposalV2, RememberActionExpectationV1)> {
    let reader = request.reader()?;
    let verified = runtime.verify().await?;
    let witness = verified.witness();
    let head = normative_repository(runtime, witness)?
        .read_head(&request.binding_family_id)
        .await?;
    if let Some(head) = &head
        && (head.registry_package_digest != witness.package_digest()
            || head.activation_policy_digest != witness.activation_policy_digest())
    {
        return Err(FleetError::Memory(format!(
            "binding family {} is bound to another registry head than the active one",
            request.binding_family_id
        )));
    }
    draft_statement(
        witness,
        head.and_then(|head| head.active_binding_set_digest),
        &reader,
        request,
    )
}

/// The predicate the genesis package admits `observer.rust_enum` v1 for: the
/// only predicate a spec statement can name, because it is the only one an
/// observer can verify.
///
/// # Errors
///
/// [`ContractError::Schema`] when the genesis package does not admit that
/// observer.
pub fn spec_predicate(
    genesis: &SemanticallyClosedGenesisPackage,
) -> ContractResult<RegistryReferenceV1> {
    let observer_id = ContractId::new(SPEC_OBSERVER_ID)?;
    match genesis.entry(
        RegistryEntryKind::ObserverAdmission,
        &observer_id,
        SPEC_OBSERVER_VERSION,
    ) {
        Some(SemanticallyDecodedGenesisEntryV1::ObserverAdmission(admission)) => {
            Ok(admission.predicate_schema().clone())
        }
        _ => Err(schema(
            "the genesis package does not admit the spec observer observer.rust_enum v1",
        )),
    }
}

/// The genesis package's single applicability evaluator: the one its
/// predicates and its normative binding schema name.
///
/// # Errors
///
/// [`ContractError::Schema`] unless the package carries exactly one.
pub fn spec_applicability_evaluator(
    genesis: &SemanticallyClosedGenesisPackage,
) -> ContractResult<RegistryReferenceV1> {
    let mut evaluators = genesis
        .manifest_verified_package()
        .package()
        .entries
        .iter()
        .filter(|entry| entry.kind == RegistryEntryKind::ApplicabilityEvaluator);
    match (evaluators.next(), evaluators.next()) {
        (Some(entry), None) => Ok(RegistryReferenceV1 {
            entry_id: entry.entry_id.clone(),
            version: entry.version,
            entry_digest: entry.digest()?,
        }),
        _ => Err(schema(
            "the genesis package must carry exactly one applicability evaluator",
        )),
    }
}

/// The repository entity a spec statement is about: the active package's
/// [`REPOSITORY_IDENTITY_RECIPE_ID`] recipe over `provider_repository_id`,
/// in `scope`.
///
/// The recipe is resolved out of the package by its exact entry, so the same
/// provider id in the same scope always names the same subject, and a check
/// can re-derive it from a worker source's `provider_repository_id` and refuse
/// a statement about another repository.
///
/// # Errors
///
/// A contract error when the package does not carry exactly one such recipe,
/// or the recipe refuses the component.
pub fn repository_subject(
    package: &SemanticallyClosedSuccessorPackage,
    scope: &AuthenticatedProjectScopeV1,
    provider_repository_id: u64,
) -> ContractResult<ResourceUri> {
    let manifest = package.manifest_verified_package();
    let recipe_id = ContractId::new(REPOSITORY_IDENTITY_RECIPE_ID)?;
    let mut recipes = manifest.package().entries.iter().filter(|entry| {
        entry.kind == RegistryEntryKind::IdentityRecipe && entry.entry_id == recipe_id
    });
    let (Some(entry), None) = (recipes.next(), recipes.next()) else {
        return Err(ContractError::InvalidIdentityRecipe(format!(
            "the active package must carry exactly one {REPOSITORY_IDENTITY_RECIPE_ID} recipe"
        )));
    };
    let recipe = RegistryReferenceV1 {
        entry_id: entry.entry_id.clone(),
        version: entry.version,
        entry_digest: entry.digest()?,
    };
    let components = BTreeMap::from([(
        REPOSITORY_LOCATOR_KEY.to_owned(),
        provider_repository_id.to_string(),
    )]);
    Ok(
        derive_entity_from_components(manifest, &recipe, scope, &components)?
            .uri()
            .clone(),
    )
}

/// The digest one cited span records: exactly the bytes it selects, under
/// [`DigestDomain::NormativeSourceSpanBytesV1`].
#[must_use]
pub fn spec_span_digest(selected: &[u8]) -> Sha256Digest {
    domain_separated_digest(DigestDomain::NormativeSourceSpanBytesV1, selected)
}

/// The cited spans of `document`, sorted, each digested over the bytes it
/// selects.
///
/// # Errors
///
/// [`ContractError::Schema`] for no span, an empty or reversed span, a span
/// past the end of the document, or two spans that overlap.
pub fn select_spans(
    document: &[u8],
    spans: &[Range<u64>],
) -> ContractResult<Vec<SourceByteSpanV1>> {
    if spans.is_empty() {
        return Err(schema(
            "a spec statement must cite at least one span of its spec document",
        ));
    }
    let mut sorted = spans.to_vec();
    sorted.sort_by_key(|span| (span.start, span.end));
    if sorted.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Err(schema("the cited spec spans overlap"));
    }
    sorted
        .iter()
        .map(|span| {
            let start = usize::try_from(span.start).ok();
            let end = usize::try_from(span.end).ok();
            let selected = start
                .zip(end)
                .filter(|(start, end)| start < end)
                .and_then(|(start, end)| document.get(start..end))
                .ok_or_else(|| {
                    schema("a cited spec span is empty, reversed, or past the end of the document")
                })?;
            Ok(SourceByteSpanV1 {
                start: span.start,
                end: span.end,
                selected_bytes_digest: spec_span_digest(selected),
            })
        })
        .collect()
}

/// The occurrence URI naming a spec document's blob by its content digest.
fn spec_blob_uri(content_digest: Sha256Digest) -> ContractResult<ResourceUri> {
    ResourceUri::from_str(&format!(
        "urn:ostk:occurrence:v1:git_blob:sha256:{content_digest}"
    ))
}

/// The parser artifact every drafted statement names.
///
/// It is `ostk-spec draft` at the expectation schema version: tied to the
/// schema, never to a build or a host, so the same request drafts the same
/// statement id anywhere.
///
/// # Errors
///
/// None in practice; the URI is well formed by construction.
pub fn spec_parser_artifact_id() -> ContractResult<ResourceUri> {
    let digest = framed_digest(
        DigestDomain::SpecDraftParserArtifactV1,
        &[
            b"ostk-spec draft",
            REMEMBER_ACTION_EXPECTATION_SCHEMA_VERSION
                .to_string()
                .as_bytes(),
        ],
    );
    ResourceUri::from_str(&format!("urn:ostk:occurrence:v1:artifact:sha256:{digest}"))
}

/// Bind the spec document at `path` in `commit`.
fn bind_spec_document(
    reader: &GitRepositoryReader,
    commit: &GitObjectId,
    path: &str,
) -> Result<ObservedSourceV1> {
    bind_blob_at(reader, commit, path, "spec document")
}

/// Bind the blob `path` resolves to in `commit`: re-read and checked against
/// its git object name and content digest, and refused over
/// [`MAX_OBSERVED_SOURCE_BYTES`]. `what` names the file in a refusal.
pub(crate) fn bind_blob_at(
    reader: &GitRepositoryReader,
    commit: &GitObjectId,
    path: &str,
    what: &str,
) -> Result<ObservedSourceV1> {
    let unreadable = |error: &dyn std::fmt::Display| {
        FleetError::Memory(format!(
            "{what} {path} cannot be bound at commit {}: {error}",
            commit.to_hex()
        ))
    };
    let entry = reader
        .resolve_path_blob(commit, path.as_bytes())
        .map_err(|error| unreadable(&error))?;
    let bytes = reader
        .read_blob(&entry.blob_id)
        .map_err(|error| unreadable(&error))?;
    let pin = ObserverSourcePinV1 {
        commit_id: commit.clone(),
        path: path.as_bytes().to_vec(),
        blob_id: entry.blob_id,
        content_digest: source_content_digest(&bytes),
    };
    bind_observed_source(reader, &pin, MAX_OBSERVED_SOURCE_BYTES)
        .map_err(|error| unreadable(&error))
}

fn schema(message: &str) -> ContractError {
    ContractError::Schema(message.to_owned())
}

#[cfg(test)]
#[path = "draft_tests.rs"]
mod tests;
