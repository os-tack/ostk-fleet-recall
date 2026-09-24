//! Writer-authority installer: one physical `(tenant_id, project)` to an
//! active generation-2 registry head, idempotently (ADR 0002, AUTH-04).
//!
//! Every writer that appends event-first — `remember(assert)`, the Stage-5
//! worker, `ostk-spec`, the observer — needs the strict witness
//! ([`crate::registry_witness::load_and_verify`]) to accept the physical
//! scope's active head, and every connector needs that head to activate the
//! generation-2 connector package. Before this module the only way to get
//! there was a hand-authored, hand-signed ceremony of four workstation CLIs, or
//! a 250-600-line helper copied into each live test. This drives the same
//! four signed repositories in order, under one call:
//!
//! 1. **Control bootstrap** ([`CockroachGenesisRepository::bootstrap_genesis`]):
//!    the frozen `bootstrap-receipt.jsonl` statement with its scope rewritten
//!    to the requested semantic scope and a partition seed derived from the
//!    physical scope, re-signed with [`FixtureGovernanceKeys`]. The receipt is
//!    a pure function of the request, so a re-run is an exact replay.
//! 2. **Genesis activation**: the frozen genesis package and conformance
//!    result, signed at the database's `statement_timestamp()` (the statement
//!    must fall between bootstrap acceptance and server time).
//! 3. **First successor** (`0 -> 1`): the compiled generation-1 Stage-4
//!    package, through a genesis key bridge rebuilt for the requested scope
//!    (the frozen bridge names `tenant.fixture`).
//! 4. **Generation two** (`1 -> 2`): the compiled generation-2 connector
//!    package ([`compiled_generation_two_package`]) with a conformance result
//!    this module mints itself.
//!
//! Steps 2 through 4 sign fresh statements at server time, so they cannot be
//! replayed byte for byte. Before each of them the installer reads the
//! writer-authority view `memory_writer_authority_v1` through the strict
//! witness and skips what is already durable; the genesis step, which the
//! view cannot see until `0 -> 1` has projected a head, resumes from the
//! audited genesis root instead. Authority the installer would not have put
//! there — a package that is not a [`KnownRegistryPackage`], namespaces other
//! than the request's, another bootstrap receipt — is refused, never
//! repaired, and refused the same way whether or not an earlier run got as far
//! as a head: the stored control bootstrap is checked directly, because the
//! view cannot see it until `0 -> 1` has committed. The run finishes with
//! [`load_and_verify`] under exactly the pins it reports.
//!
//! # What the signatures prove (D4)
//!
//! Nothing. The governance keys are the public Ed25519 test fixtures (seeds
//! `0x01`/`0x02`) that the frozen bootstrap receipt and the compiled
//! generation-1 activation policy already name, and the generation-2
//! conformance result is self-attested. Anyone can produce these signatures.
//!
//! Signing by hand would not change that past generation 1. The strict
//! witness admits only the two compiled packages, generation 2 carries the
//! generation-1 activation policy forward, and a successor activation is
//! verified only against the installed policy's eligible signers: the fixture
//! keys. So `1 -> 2`, and every later successor from a head a writer can run
//! under, can be signed by anyone, whoever signed the earlier steps. Only the
//! control bootstrap, the genesis activation, and the `0 -> 1` key bridge can
//! carry deployment keys. Non-nominal successor governance needs a compiled
//! package whose activation policy names deployment keys, and none exists yet.
//!
//! The real gates are database role separation and the out-of-band
//! receipt-digest pin the reported [`WriterAuthorityPinsV1`] hands each writer
//! process. Only the schema owner/migrator login and the provisioned ceremony
//! roles (`fleet_control_bootstrap`, `fleet_registry_activation`,
//! `fleet_registry_successor_activation`) can write the control and registry
//! tables this touches; the runtime and publication roles cannot.

use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;

use super::cockroach::CockroachGenesisActivationRepository;
use super::{
    CockroachGenericSuccessorRepository, CockroachSuccessorActivationRepository,
    GenericSuccessorActivationCandidate, GenericSuccessorActivationOutcome,
    GenericSuccessorRepository as _, GenesisActivationOutcome, GenesisActivationRepository as _,
    SuccessorActivationCandidate, SuccessorActivationOutcome, SuccessorActivationRepository as _,
};
use crate::config::WriterAuthorityConfig;
use crate::control_log::{
    CockroachGenesisRepository, GenesisBootstrapOutcome, GenesisRepository as _,
    TrustedControlScope,
};
use crate::memory_contracts::bootstrap::{
    BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1,
    VerifiedBootstrapReceipt, verify_pinned_bootstrap,
};
use crate::memory_contracts::canonical::{decode_strict, encode_canonical};
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, FixedHex32, FixedHex64,
    ProfileReferenceV1, RegistryReferenceV1, frozen_profile_reference_v1,
};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, domain_separated_digest};
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use crate::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, GenesisRegistryActivationApprovalSetV1,
    GenesisRegistryActivationApprovalV1, GenesisRegistryActivationStatementV1,
    GenesisRegistryAnchorV1, RegistryTestOutcomeV1, RegistryTestResultDigest, RegistryTestResultV1,
    RegistryTestRunnerPin, VerifiedRegistryTestResult, genesis_activation_policy_digest,
    verify_genesis_registry_activation, verify_registry_test_result,
};
use crate::memory_contracts::registry::RegistryEntryKind;
use crate::memory_contracts::stage4_target_package::SemanticallyClosedStage4Package;
use crate::memory_contracts::successor_activation::{
    SuccessorActivationPrincipalBinding, SuccessorRegistryActivationApprovalSetV1,
    SuccessorRegistryActivationApprovalV1, SuccessorRegistryActivationStatementV1,
    SuccessorRegistryTestRunnerPin,
};
use crate::memory_contracts::successor_generic::{
    GenericSuccessorActivationApprovalSetV2, GenericSuccessorActivationApprovalV2,
    GenericSuccessorActivationStatementV2, GenericSuccessorPrincipalBinding,
    GenericSuccessorTestRunnerPin,
};
use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;
use crate::memory_contracts::successor_policy::{
    ActivationSignatureAlgorithmV2, ActivationSignerBindingV2, GenesisSuccessorKeyBridgePin,
    GenesisSuccessorKeyBridgeV1,
};
use crate::registry_witness::{
    KnownRegistryPackage, WriterAuthorityError, WriterAuthorityRejection, WriterAuthorityWitness,
    compiled_generation_two_package, compiled_genesis_package, compiled_stage4_package,
    load_and_verify,
};
use crate::store::cockroach::RetryPolicy;
use crate::{FleetError, FleetScope, Result};

// ---------------------------------------------------------------------------
// Frozen ceremony inputs. The packages themselves are the registry witness's
// compiled-in bytes, so the installer can only ever activate a package the
// witness admits.
// ---------------------------------------------------------------------------

/// The frozen Stage-1 bootstrap receipt the installer re-scopes and re-signs.
const BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");
/// The frozen conformance result the genesis activation names.
const GENESIS_TEST_RESULT: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v1/genesis-activation/registry-test-result.jsonl"
);
/// The frozen conformance result the `0 -> 1` activation names.
const GENERATION_1_TEST_RESULT: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/successor-activation/registry-test-result.jsonl"
);

/// Pins of the frozen genesis conformance result and the runner it names.
const GENESIS_TEST_RESULT_DIGEST: &str =
    "e91e08070250a722446195b76ee685a9697298b9fdce9809027f120c829b679d";
const GENESIS_RUNNER_ARTIFACT: &str =
    "c2e5b0653471d35e54600a8d3fbe5613aff4c04e911787c09a25e2b327d4bbbd";
const GENESIS_RUNNER_CONFIGURATION: &str =
    "1d12aabe349fd0013389f93bf1917b0de6bbd5d2bd7156c85faff0b97360686d";
/// Pin of the frozen generation-1 conformance result.
const GENERATION_1_TEST_RESULT_DIGEST: &str =
    "e6783b2a018957a5861fe4e0670f55613d1ace35e381a6a9f5190ea9d7fbff8d";
/// The successor conformance runner the frozen generation-1 result names. The
/// minted generation-2 result names the same runner.
const SUCCESSOR_RUNNER_ARTIFACT: &str =
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SUCCESSOR_RUNNER_CONFIGURATION: &str =
    "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
/// Completion instant the minted generation-2 conformance result declares.
/// Fixed rather than a wall clock so the result, and so its digest, is the
/// same on every run; the `1 -> 2` statement must be effective no earlier.
const GENERATION_2_TEST_COMPLETED_AT: &str = "2026-08-22T04:00:00.000000000Z";

/// Ceremony principals. Neither holds a governance key, which is what the
/// separation-of-duty rules require of a proposer and a package author.
const PROPOSER: &str = "principal.operator";
const AUTHOR: &str = "principal.author";

/// Detached-signature framings, one per ceremony.
const BOOTSTRAP_APPROVAL_PREFIX: &[u8] = b"ostk-bootstrap-approval-v1\0";
const GENESIS_APPROVAL_PREFIX: &[u8] = b"ostk-registry-activation-approval-signature-v1\0";
const BRIDGE_APPROVAL_PREFIX: &[u8] = b"ostk-registry-successor-activation-approval-signature-v1\0";
const GENERIC_APPROVAL_PREFIX: &[u8] =
    b"ostk-registry-successor-activation-approval-signature-v2\0";

/// Domain of the per-physical-scope partition seed.
const PARTITION_SEED_DOMAIN: &str = "ostk-authority-install-partition-seed-v1";

/// Pause before reading the server clock for a successor statement, so its
/// `effective_from` is strictly after the predecessor's (the contracts require
/// a strictly later instant at microsecond resolution).
const SUCCESSOR_CLOCK_GAP: Duration = Duration::from_millis(2);

// ---------------------------------------------------------------------------
// Request and report.
// ---------------------------------------------------------------------------

/// What to install: one physical scope bound to one semantic scope.
///
/// The target is always the compiled generation-2 connector package
/// ([`KnownRegistryPackage::ConnectorGeneration2`]); there is no other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityInstallRequestV1 {
    /// The physical `(tenant_id, project)` every row is keyed by. The agent and
    /// session fields are not part of the authority.
    pub physical_scope: FleetScope,
    /// The contract tenant/project namespaces the head will carry, which every
    /// writer then pins.
    pub semantic_scope: AuthenticatedProjectScopeV1,
}

/// One installer step, in the order they run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallStepV1 {
    ControlBootstrap,
    GenesisActivation,
    FirstSuccessor,
    GenerationTwo,
}

/// Whether a step wrote anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallStepOutcomeV1 {
    /// This run committed the step.
    Inserted,
    /// The step was already durable, so this run wrote nothing for it.
    AlreadyPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct InstallStepReportV1 {
    pub step: InstallStepV1,
    pub outcome: InstallStepOutcomeV1,
}

/// The writer-authority pin group a writer process for this physical scope
/// needs. Each key is the environment variable [`WriterAuthorityConfig`]
/// reads, so the serialized object can be exported as-is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WriterAuthorityPinsV1 {
    #[serde(rename = "FLEET_RECALL_CONTRACT_TENANT_NAMESPACE")]
    pub contract_tenant_namespace: ContractId,
    #[serde(rename = "FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE")]
    pub contract_project_namespace: ContractId,
    #[serde(rename = "FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST")]
    pub bootstrap_receipt_digest: BootstrapReceiptDigest,
}

impl WriterAuthorityPinsV1 {
    /// The semantic scope these pins name.
    #[must_use]
    pub fn semantic_scope(&self) -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            self.contract_tenant_namespace.clone(),
            self.contract_project_namespace.clone(),
        )
    }

    /// The pin group as the strict witness consumes it, without the optional
    /// break-glass activation ID.
    #[must_use]
    pub fn writer_authority_config(&self) -> WriterAuthorityConfig {
        WriterAuthorityConfig::from_trusted_context(
            self.semantic_scope(),
            self.bootstrap_receipt_digest,
            None,
        )
    }
}

/// What one installer run did and the authority it leaves behind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorityInstallReportV1 {
    pub steps: Vec<InstallStepReportV1>,
    /// Generation of the active head the strict witness accepted.
    pub generation: u64,
    /// Exact activation of that head; the optional
    /// `FLEET_RECALL_EXPECTED_ACTIVATION_ID` break-glass pin takes this value.
    pub activation_id: Sha256Digest,
    pub package: KnownRegistryPackage,
    pub pins: WriterAuthorityPinsV1,
}

/// The governance keys every installer signature is made with.
///
/// These are the **public** Ed25519 test fixtures, seeds `0x01` and `0x02`:
/// the frozen bootstrap receipt's signer policy names them as `principal.1`
/// and `principal.2`, and the compiled generation-1 activation policy (which
/// generation 2 carries forward) names the same two keys as
/// `principal.alice` and `principal.bob`. Their signatures are nominal (D4):
/// the gate is who can write the registry tables, not who can sign.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FixtureGovernanceKeys;

impl FixtureGovernanceKeys {
    /// Ed25519 seed bytes (each repeated 32 times), in signer order.
    pub const SEEDS: [u8; 2] = [0x01, 0x02];
    /// The bootstrap and genesis-activation principals for [`Self::SEEDS`].
    pub const BOOTSTRAP_PRINCIPALS: [&'static str; 2] = ["principal.1", "principal.2"];
    /// The activation-policy v2 principals for [`Self::SEEDS`].
    pub const SUCCESSOR_PRINCIPALS: [&'static str; 2] = ["principal.alice", "principal.bob"];

    fn key_pair(seed: u8) -> Result<Ed25519KeyPair> {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).map_err(|_| {
            FleetError::Configuration("a fixture governance seed is not an Ed25519 key".into())
        })
    }

    fn sign(seed: u8, prefix: &[u8], statement_id: Sha256Digest) -> Result<FixedHex64> {
        let mut message = Vec::with_capacity(prefix.len() + 32);
        message.extend_from_slice(prefix);
        message.extend_from_slice(statement_id.as_bytes());
        let signature: [u8; 64] = Self::key_pair(seed)?
            .sign(&message)
            .as_ref()
            .try_into()
            .map_err(|_| FleetError::Configuration("Ed25519 signature is not 64 bytes".into()))?;
        Ok(FixedHex64::from_bytes(signature))
    }

    /// Successor principal, seed pairs in signer order.
    fn successor_signers() -> Result<Vec<(ContractId, u8)>> {
        Self::SUCCESSOR_PRINCIPALS
            .into_iter()
            .zip(Self::SEEDS)
            .map(|(principal, seed)| Ok((ContractId::new(principal)?, seed)))
            .collect()
    }

    /// The genesis key bridge's key map: each activation-policy v2 principal
    /// bound to its public key.
    fn successor_key_map() -> Result<Vec<ActivationSignerBindingV2>> {
        Self::successor_signers()?
            .into_iter()
            .map(|(principal_id, seed)| {
                Ok(ActivationSignerBindingV2 {
                    principal_id,
                    algorithm: ActivationSignatureAlgorithmV2::Ed25519,
                    public_key: Self::public_key(seed)?,
                })
            })
            .collect()
    }

    fn public_key(seed: u8) -> Result<FixedHex32> {
        let key_pair = Self::key_pair(seed)?;
        let public_key: [u8; 32] =
            key_pair.public_key().as_ref().try_into().map_err(|_| {
                FleetError::Configuration("Ed25519 public key is not 32 bytes".into())
            })?;
        Ok(FixedHex32::from_bytes(public_key))
    }
}

// ---------------------------------------------------------------------------
// The installer.
// ---------------------------------------------------------------------------

/// Give `request.physical_scope` an active generation-2 head bound to
/// `request.semantic_scope`, skipping whatever is already durable.
///
/// Runs as the schema owner/migrator login: it writes the control and
/// registry tables, which no application role may. It is safe to re-run; a
/// second run reports every step [`InstallStepOutcomeV1::AlreadyPresent`] with
/// the same pins and activation. Two concurrent runs against one physical
/// scope are not coordinated beyond the repositories' own serializable
/// compare-and-swaps, so the loser fails closed and a re-run completes it.
///
/// # Errors
///
/// A configuration error when the physical scope already holds authority the
/// request does not describe (another bootstrap receipt, other namespaces, an
/// unknown package, or a generation-1 package re-activated past generation 1),
/// with or without a registry head above that bootstrap, and any repository,
/// contract, or database error from a step.
pub async fn install_writer_authority(
    pool: &PgPool,
    request: &AuthorityInstallRequestV1,
    retry: RetryPolicy,
) -> Result<AuthorityInstallReportV1> {
    let control = TrustedControlScope::from_trusted_context(
        &request.physical_scope,
        request.semantic_scope.clone(),
    )?;
    let artifacts = InstallArtifacts::compile(request)?;
    let config = artifacts.pins.writer_authority_config();
    let mut steps = Vec::with_capacity(4);

    // Read the view before writing anything: it refuses authority this
    // request does not describe, and it fails before step 1 on a schema that
    // lacks migration 18. The view projects a head only once `0 -> 1` has
    // committed, so a visible head means steps 2 and 3 are durable.
    let installed = read_installed_head(pool, &request.physical_scope, &config)
        .await?
        .is_some();

    // 1. The deterministic receipt: an exact replay reports AlreadyPresent.
    steps.push(InstallStepReportV1 {
        step: InstallStepV1::ControlBootstrap,
        outcome: bootstrap_control(pool, &control, retry, &request.physical_scope, &artifacts)
            .await?,
    });

    // 2 and 3.
    if installed {
        for step in [
            InstallStepV1::GenesisActivation,
            InstallStepV1::FirstSuccessor,
        ] {
            steps.push(InstallStepReportV1 {
                step,
                outcome: InstallStepOutcomeV1::AlreadyPresent,
            });
        }
    } else {
        let genesis_repository = CockroachGenesisActivationRepository::new(
            pool.clone(),
            control.clone(),
            retry,
            artifacts.bootstrap.clone(),
            artifacts.genesis.clone(),
            artifacts.genesis_test_result.clone(),
            principal_binding()?,
        )?;
        let (genesis_head, outcome) = match genesis_repository.accepted_genesis_head().await? {
            Some(head) => (head, InstallStepOutcomeV1::AlreadyPresent),
            None => activate_genesis(pool, &genesis_repository, &artifacts).await?,
        };
        steps.push(InstallStepReportV1 {
            step: InstallStepV1::GenesisActivation,
            outcome,
        });
        steps.push(InstallStepReportV1 {
            step: InstallStepV1::FirstSuccessor,
            outcome: activate_first_successor(pool, &control, retry, &artifacts, genesis_head)
                .await?,
        });
    }

    // 4. Read the head again: only a generation-1 Stage-4 head moves forward.
    let head = read_installed_head(pool, &request.physical_scope, &config)
        .await?
        .ok_or_else(|| {
            FleetError::RegistryActivationCorrupt(
                "the first successor committed but the writer-authority view projects no head"
                    .into(),
            )
        })?;
    let outcome = match head.active_package().known() {
        KnownRegistryPackage::ConnectorGeneration2 => InstallStepOutcomeV1::AlreadyPresent,
        KnownRegistryPackage::Stage4Generation1 if head.generation() == 1 => {
            activate_generation_two(pool, &control, retry, &artifacts, &head).await?
        }
        KnownRegistryPackage::Stage4Generation1 => {
            return Err(refused(&format!(
                "generation {} re-activated the generation-1 package; the installer only drives 1 -> 2",
                head.generation()
            )));
        }
    };
    steps.push(InstallStepReportV1 {
        step: InstallStepV1::GenerationTwo,
        outcome,
    });

    // Finish exactly as every writer will start: the strict witness under the
    // pins this report prints.
    let witness = load_and_verify(pool, &request.physical_scope, &config).await?;
    if witness.active_package().known() != KnownRegistryPackage::ConnectorGeneration2 {
        return Err(FleetError::RegistryActivationCorrupt(
            "the installed head does not activate the generation-2 connector package".into(),
        ));
    }
    Ok(AuthorityInstallReportV1 {
        steps,
        generation: witness.generation(),
        activation_id: witness.activation_id(),
        package: witness.active_package().known(),
        pins: artifacts.pins,
    })
}

/// Everything the four steps sign or bind, closed before any database write.
struct InstallArtifacts {
    profile: ProfileReferenceV1,
    semantic_scope: AuthenticatedProjectScopeV1,
    genesis: &'static SemanticallyClosedGenesisPackage,
    bootstrap: VerifiedBootstrapReceipt,
    genesis_test_result: VerifiedRegistryTestResult,
    stage4: Arc<SemanticallyClosedStage4Package>,
    pins: WriterAuthorityPinsV1,
}

impl InstallArtifacts {
    fn compile(request: &AuthorityInstallRequestV1) -> Result<Self> {
        request.physical_scope.validate()?;
        let profile = frozen_profile_reference_v1();
        let genesis = compiled_genesis_package()?;
        let (canonical_receipt, receipt_digest) = bootstrap_receipt(request)?;
        let bootstrap = verify_pinned_bootstrap(
            &canonical_receipt,
            BootstrapPin::from_trusted_config(receipt_digest),
            &profile,
            &request.semantic_scope,
            genesis,
        )?;
        let genesis_test_result = verify_registry_test_result(
            framed(GENESIS_TEST_RESULT)?,
            RegistryTestRunnerPin::from_trusted_config(
                digest(GENESIS_RUNNER_ARTIFACT)?,
                digest(GENESIS_RUNNER_CONFIGURATION)?,
                RegistryTestResultDigest::from_digest(digest(GENESIS_TEST_RESULT_DIGEST)?),
            ),
            &profile,
            genesis,
        )?;
        Ok(Self {
            profile,
            semantic_scope: request.semantic_scope.clone(),
            genesis,
            bootstrap,
            genesis_test_result,
            stage4: compiled_stage4_package()?,
            pins: WriterAuthorityPinsV1 {
                contract_tenant_namespace: request.semantic_scope.tenant_namespace.clone(),
                contract_project_namespace: request.semantic_scope.project_namespace.clone(),
                bootstrap_receipt_digest: receipt_digest,
            },
        })
    }
}

/// The frozen bootstrap statement re-scoped to the request, re-signed with the
/// fixture governance keys, as canonical bytes plus their receipt digest.
///
/// A pure function of the request: the same physical and semantic scope give
/// the same bytes on every run and every host, which is what makes the
/// control-bootstrap step an exact replay.
fn bootstrap_receipt(
    request: &AuthorityInstallRequestV1,
) -> Result<(Vec<u8>, BootstrapReceiptDigest)> {
    let mut receipt: BootstrapReceiptV1 = decode_strict(framed(BOOTSTRAP_RECEIPT)?)?;
    receipt.statement.scope = request.semantic_scope.clone();
    receipt.statement.genesis_epoch.scope = request.semantic_scope.clone();
    receipt.statement.genesis_epoch.partition_recipe.seed = partition_seed(&request.physical_scope);
    let statement_id = receipt.statement.statement_id()?;
    receipt.attestations = FixtureGovernanceKeys::BOOTSTRAP_PRINCIPALS
        .into_iter()
        .zip(FixtureGovernanceKeys::SEEDS)
        .map(|(principal, seed)| {
            Ok(BootstrapAttestationV1 {
                schema_version: 1,
                statement_id,
                signer_principal_id: ContractId::new(principal)?,
                signature: FixtureGovernanceKeys::sign(
                    seed,
                    BOOTSTRAP_APPROVAL_PREFIX,
                    statement_id.digest(),
                )?,
            })
        })
        .collect::<Result<_>>()?;
    let canonical = encode_canonical(&receipt)?;
    let receipt_digest = BootstrapReceiptDigest::from_digest(domain_separated_digest(
        DigestDomain::BootstrapReceipt,
        &canonical,
    ));
    Ok((canonical, receipt_digest))
}

/// Non-secret partition seed: a framed digest of the physical tenant and
/// project, so two physical scopes never share a genesis epoch.
fn partition_seed(physical_scope: &FleetScope) -> FixedHex32 {
    let mut hash = Sha256::new();
    hash.update(PARTITION_SEED_DOMAIN.as_bytes());
    hash.update([0]);
    for part in [
        physical_scope.tenant_id.as_bytes().as_slice(),
        physical_scope.project.as_bytes(),
    ] {
        hash.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(part);
    }
    FixedHex32::from_bytes(hash.finalize().into())
}

/// The strict witness over the physical scope, or `None` while the view has
/// no head yet. A head that exists but is not what this request installs is
/// refused rather than reported.
async fn read_installed_head(
    pool: &PgPool,
    physical_scope: &FleetScope,
    config: &WriterAuthorityConfig,
) -> Result<Option<WriterAuthorityWitness>> {
    match load_and_verify(pool, physical_scope, config).await {
        Ok(witness) => Ok(Some(witness)),
        Err(WriterAuthorityError::Rejected(WriterAuthorityRejection::Absent)) => Ok(None),
        Err(WriterAuthorityError::Rejected(
            rejection @ (WriterAuthorityRejection::BootstrapPin
            | WriterAuthorityRejection::ContractNamespace
            | WriterAuthorityRejection::UnknownActivePackage),
        )) => Err(refused(&rejection.to_string())),
        Err(error) => Err(error.into()),
    }
}

/// Step 1: apply the deterministic bootstrap receipt, refusing a physical
/// scope whose stored bootstrap is another one.
///
/// The view read before this step cannot see a bootstrap with no head above
/// it, so the stored singleton is checked directly first. A concurrent run
/// for another request can still bootstrap the scope between that check and
/// this write; that is reported as the same refusal, and any other failure as
/// the step's own error.
async fn bootstrap_control(
    pool: &PgPool,
    control: &TrustedControlScope,
    retry: RetryPolicy,
    physical_scope: &FleetScope,
    artifacts: &InstallArtifacts,
) -> Result<InstallStepOutcomeV1> {
    if let Some(rejection) = foreign_bootstrap(pool, physical_scope, &artifacts.pins).await? {
        return Err(refused(&rejection.to_string()));
    }
    match CockroachGenesisRepository::new(pool.clone(), control.clone(), retry)
        .bootstrap_genesis(&artifacts.bootstrap, artifacts.genesis)
        .await
    {
        Ok(GenesisBootstrapOutcome::Inserted(_)) => Ok(InstallStepOutcomeV1::Inserted),
        Ok(GenesisBootstrapOutcome::ExactReplay(_)) => Ok(InstallStepOutcomeV1::AlreadyPresent),
        Err(error) => match foreign_bootstrap(pool, physical_scope, &artifacts.pins).await {
            Ok(Some(rejection)) => Err(refused(&rejection.to_string())),
            _ => Err(error),
        },
    }
}

/// Why the physical scope's stored control bootstrap, if any, is not the one
/// this request installs, or `None` when there is none or it is this one.
///
/// The strict witness sees a bootstrap only through a projected head, and
/// there is none until `0 -> 1` commits. Before that, a hand-run control
/// bootstrap or an install for another request that stopped partway leaves
/// only the bootstrap singleton, and the control repository would report it
/// as a bootstrap conflict or, under other namespaces, as a stored receipt
/// that fails this request's audit. Comparing the singleton's pinned columns
/// first makes each of those the installer's own refusal.
async fn foreign_bootstrap(
    pool: &PgPool,
    physical_scope: &FleetScope,
    pins: &WriterAuthorityPinsV1,
) -> Result<Option<WriterAuthorityRejection>> {
    let stored: Option<(String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT contract_tenant_namespace, contract_project_namespace, receipt_digest \
         FROM public.memory_control_bootstraps WHERE tenant_id = $1 AND project = $2",
    )
    .bind(physical_scope.tenant_id)
    .bind(&physical_scope.project)
    .fetch_optional(pool)
    .await?;
    let Some((tenant_namespace, project_namespace, receipt_digest)) = stored else {
        return Ok(None);
    };
    if tenant_namespace != pins.contract_tenant_namespace.as_str()
        || project_namespace != pins.contract_project_namespace.as_str()
    {
        return Ok(Some(WriterAuthorityRejection::ContractNamespace));
    }
    if receipt_digest.as_slice() != pins.bootstrap_receipt_digest.digest().as_bytes() {
        return Ok(Some(WriterAuthorityRejection::BootstrapPin));
    }
    Ok(None)
}

/// Step 2: sign the genesis statement at server time and activate it.
async fn activate_genesis(
    pool: &PgPool,
    repository: &CockroachGenesisActivationRepository,
    artifacts: &InstallArtifacts,
) -> Result<(RegistryHeadBindingV1, InstallStepOutcomeV1)> {
    let statement = GenesisRegistryActivationStatementV1 {
        schema_version: 1,
        profile: artifacts.profile.clone(),
        scope: artifacts.semantic_scope.clone(),
        expected_anchor: GenesisRegistryAnchorV1::from_verified(
            &artifacts.bootstrap,
            artifacts.genesis,
        )?,
        package_digest: artifacts.genesis.package_digest(),
        resulting_activation_policy_digest: genesis_activation_policy_digest(artifacts.genesis)?,
        effective_from: server_time(pool).await?,
        effective_until: None,
        test_vector_result_digest: artifacts.genesis_test_result.result_digest(),
        proposer_principal_id: ContractId::new(PROPOSER)?,
        package_author_principal_id: ContractId::new(AUTHOR)?,
    };
    let statement_id = statement.statement_id()?;
    let mut approvals = FixtureGovernanceKeys::BOOTSTRAP_PRINCIPALS
        .into_iter()
        .zip(FixtureGovernanceKeys::SEEDS)
        .map(|(principal, seed)| {
            Ok(GenesisRegistryActivationApprovalV1 {
                schema_version: 1,
                statement_id,
                signer_principal_id: ContractId::new(principal)?,
                signature: FixtureGovernanceKeys::sign(
                    seed,
                    GENESIS_APPROVAL_PREFIX,
                    statement_id.digest(),
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    approvals.sort_unstable();
    let request = verify_genesis_registry_activation(
        &encode_canonical(&statement)?,
        &encode_canonical(&GenesisRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id,
            approvals,
        })?,
        &artifacts.bootstrap,
        artifacts.genesis,
        &artifacts.genesis_test_result,
        &principal_binding()?,
    )?;
    let (accepted, outcome) = match repository.activate_genesis(&request).await? {
        GenesisActivationOutcome::Inserted(accepted) => (accepted, InstallStepOutcomeV1::Inserted),
        GenesisActivationOutcome::ExactReplay(accepted) => {
            (accepted, InstallStepOutcomeV1::AlreadyPresent)
        }
    };
    let head = RegistryHeadBindingV1 {
        head: accepted.registry_head,
        effective_from: accepted.effective_from,
        effective_until: None,
    };
    head.validate_shape()?;
    Ok((head, outcome))
}

/// Step 3: bridge the genesis policy to the fixture keys for this semantic
/// scope and activate the compiled generation-1 package.
async fn activate_first_successor(
    pool: &PgPool,
    control: &TrustedControlScope,
    retry: RetryPolicy,
    artifacts: &InstallArtifacts,
    genesis_head: RegistryHeadBindingV1,
) -> Result<InstallStepOutcomeV1> {
    let current_v1_activation_policy = genesis_activation_policy(artifacts.genesis)?;
    let bridge = GenesisSuccessorKeyBridgeV1 {
        schema_version: 1,
        profile: artifacts.profile.clone(),
        scope: artifacts.semantic_scope.clone(),
        genesis_registry_head: genesis_head.clone(),
        current_v1_activation_policy: current_v1_activation_policy.clone(),
        from_generation: 0,
        to_generation: 1,
        key_map: FixtureGovernanceKeys::successor_key_map()?,
    };
    let bridge_digest = bridge.bridge_digest()?;
    let stage4 = artifacts.stage4.as_ref();
    let statement = SuccessorRegistryActivationStatementV1 {
        schema_version: 1,
        profile: artifacts.profile.clone(),
        scope: artifacts.semantic_scope.clone(),
        expected_predecessor_head: genesis_head,
        current_v1_activation_policy,
        target_package_digest: stage4.package_digest(),
        target_activation_policy: stage4.activation_policy().registry_reference().clone(),
        test_vector_result_digest: generation_1_test_result_digest()?,
        genesis_successor_key_bridge_digest: bridge_digest,
        from_generation: 0,
        to_generation: 1,
        effective_from: successor_effective_from(pool).await?,
        effective_until: None,
        proposer_principal_id: ContractId::new(PROPOSER)?,
        package_author_principal_id: ContractId::new(AUTHOR)?,
    };
    let statement_id = statement.statement_id()?;
    let approvals = FixtureGovernanceKeys::successor_signers()?
        .into_iter()
        .map(|(signer_principal_id, seed)| {
            Ok(SuccessorRegistryActivationApprovalV1 {
                schema_version: 1,
                statement_id,
                signer_principal_id,
                signature: FixtureGovernanceKeys::sign(
                    seed,
                    BRIDGE_APPROVAL_PREFIX,
                    statement_id.digest(),
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let candidate = SuccessorActivationCandidate::from_bounded_canonical_bytes(
        encode_canonical(&statement)?,
        encode_canonical(&SuccessorRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id,
            approvals,
        })?,
    )?;
    let repository = CockroachSuccessorActivationRepository::new(
        pool.clone(),
        control.clone(),
        retry,
        artifacts.bootstrap.clone(),
        artifacts.genesis.clone(),
        artifacts.genesis_test_result.clone(),
        principal_binding()?,
        stage4.clone(),
        framed(GENERATION_1_TEST_RESULT)?,
        SuccessorRegistryTestRunnerPin::from_trusted_config(
            digest(SUCCESSOR_RUNNER_ARTIFACT)?,
            digest(SUCCESSOR_RUNNER_CONFIGURATION)?,
            generation_1_test_result_digest()?,
        ),
        encode_canonical(&bridge)?,
        GenesisSuccessorKeyBridgePin::from_trusted_config(bridge_digest),
        SuccessorActivationPrincipalBinding::from_trusted_config(
            ContractId::new(PROPOSER)?,
            ContractId::new(AUTHOR)?,
        ),
    )?;
    Ok(
        match repository.activate_first_successor(&candidate).await? {
            SuccessorActivationOutcome::Inserted(_) => InstallStepOutcomeV1::Inserted,
            SuccessorActivationOutcome::ExactReplay(_) => InstallStepOutcomeV1::AlreadyPresent,
        },
    )
}

/// Step 4: move the generation-1 head to the compiled generation-2 connector
/// package under the policy that head installed.
async fn activate_generation_two(
    pool: &PgPool,
    control: &TrustedControlScope,
    retry: RetryPolicy,
    artifacts: &InstallArtifacts,
    current: &WriterAuthorityWitness,
) -> Result<InstallStepOutcomeV1> {
    let target = compiled_generation_two_package()?;
    let test_result = generation_two_test_result(&artifacts.profile, &target)?;
    let test_result_digest = RegistryTestResultDigest::from_digest(domain_separated_digest(
        DigestDomain::RegistryTestResult,
        &test_result,
    ));
    let expected_head = current.head_binding().clone();
    let repository = CockroachGenericSuccessorRepository::new(
        pool.clone(),
        control.clone(),
        retry,
        artifacts.pins.bootstrap_receipt_digest,
        target.canonical_bytes().to_vec(),
        &test_result,
        GenericSuccessorTestRunnerPin::from_trusted_config(
            digest(SUCCESSOR_RUNNER_ARTIFACT)?,
            digest(SUCCESSOR_RUNNER_CONFIGURATION)?,
            test_result_digest,
        ),
        GenericSuccessorPrincipalBinding::from_trusted_config(
            ContractId::new(PROPOSER)?,
            ContractId::new(AUTHOR)?,
        ),
        expected_head.clone(),
    )?;
    let statement = GenericSuccessorActivationStatementV2 {
        schema_version: 2,
        profile: artifacts.profile.clone(),
        scope: artifacts.semantic_scope.clone(),
        expected_predecessor_head: expected_head,
        current_activation_policy: current
            .package()
            .activation_policy()
            .registry_reference()
            .clone(),
        target_package_digest: target.package_digest(),
        target_activation_policy: target.activation_policy().registry_reference().clone(),
        test_vector_result_digest: test_result_digest,
        from_generation: 1,
        to_generation: 2,
        effective_from: successor_effective_from(pool).await?,
        effective_until: None,
        proposer_principal_id: ContractId::new(PROPOSER)?,
        package_author_principal_id: ContractId::new(AUTHOR)?,
    };
    let statement_id = statement.statement_id()?;
    let approvals = FixtureGovernanceKeys::successor_signers()?
        .into_iter()
        .map(|(signer_principal_id, seed)| {
            Ok(GenericSuccessorActivationApprovalV2 {
                schema_version: 2,
                statement_id,
                signer_principal_id,
                signature: FixtureGovernanceKeys::sign(
                    seed,
                    GENERIC_APPROVAL_PREFIX,
                    statement_id.digest(),
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let candidate = GenericSuccessorActivationCandidate::from_bounded_canonical_bytes(
        encode_canonical(&statement)?,
        encode_canonical(&GenericSuccessorActivationApprovalSetV2 {
            schema_version: 2,
            statement_id,
            approvals,
        })?,
    )?;
    Ok(
        match repository.activate_generic_successor(&candidate).await? {
            GenericSuccessorActivationOutcome::Inserted(_) => InstallStepOutcomeV1::Inserted,
            GenericSuccessorActivationOutcome::ExactReplay(_) => {
                InstallStepOutcomeV1::AlreadyPresent
            }
        },
    )
}

/// The self-attested conformance result the `1 -> 2` statement names. It
/// declares the frozen successor runner and a fixed completion instant, so it
/// is the same bytes on every run.
fn generation_two_test_result(
    profile: &ProfileReferenceV1,
    target: &SemanticallyClosedSuccessorPackage,
) -> Result<Vec<u8>> {
    let package = target.manifest_verified_package().package();
    Ok(encode_canonical(&RegistryTestResultV1 {
        schema_version: 1,
        profile: profile.clone(),
        package_digest: target.package_digest(),
        positive_vector_suite_digest: package.positive_vector_suite_digest,
        negative_vector_suite_digest: package.negative_vector_suite_digest,
        executed_vector_manifest_digest: profile.vector_manifest_digest,
        runner_artifact_digest: digest(SUCCESSOR_RUNNER_ARTIFACT)?,
        runner_configuration_digest: digest(SUCCESSOR_RUNNER_CONFIGURATION)?,
        passed_case_count: 1,
        failed_case_count: 0,
        outcome: RegistryTestOutcomeV1::Passed,
        completed_at: CanonicalTimestamp::parse(GENERATION_2_TEST_COMPLETED_AT)?,
    })?)
}

/// The genesis package's one activation policy (v1), which the `0 -> 1`
/// statement and bridge must name as currently installed.
fn genesis_activation_policy(
    genesis: &SemanticallyClosedGenesisPackage,
) -> Result<RegistryReferenceV1> {
    let entry = genesis
        .manifest_verified_package()
        .package()
        .entries
        .iter()
        .find(|entry| entry.kind == RegistryEntryKind::ActivationPolicy)
        .ok_or_else(|| {
            FleetError::RegistryActivationCorrupt(
                "the compiled genesis package has no activation policy".into(),
            )
        })?;
    Ok(RegistryReferenceV1 {
        entry_id: entry.entry_id.clone(),
        version: entry.version,
        entry_digest: entry.digest()?,
    })
}

fn principal_binding() -> Result<GenesisActivationPrincipalBinding> {
    Ok(GenesisActivationPrincipalBinding::from_trusted_config(
        ContractId::new(PROPOSER)?,
        ContractId::new(AUTHOR)?,
    ))
}

fn generation_1_test_result_digest() -> Result<RegistryTestResultDigest> {
    Ok(RegistryTestResultDigest::from_digest(digest(
        GENERATION_1_TEST_RESULT_DIGEST,
    )?))
}

/// The database clock, as a canonical instant for a statement's
/// `effective_from`.
async fn server_time(pool: &PgPool) -> Result<CanonicalTimestamp> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(pool)
        .await?;
    Ok(CanonicalTimestamp::from_datetime(&now)?)
}

async fn successor_effective_from(pool: &PgPool) -> Result<CanonicalTimestamp> {
    tokio::time::sleep(SUCCESSOR_CLOCK_GAP).await;
    server_time(pool).await
}

fn digest(value: &str) -> Result<Sha256Digest> {
    Ok(Sha256Digest::from_str(value)?)
}

/// Frozen contract artifacts carry exactly one trailing LF frame.
fn framed(artifact: &'static [u8]) -> Result<&'static [u8]> {
    artifact.strip_suffix(b"\n").ok_or_else(|| {
        FleetError::Configuration("a frozen contract artifact is not LF framed".into())
    })
}

fn refused(reason: &str) -> FleetError {
    FleetError::Configuration(format!(
        "writer-authority install refused for this physical scope: {reason}"
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ostk_recall_core::PrivacyTier;
    use uuid::Uuid;

    use super::*;

    fn request(tenant: u128, project: &str) -> AuthorityInstallRequestV1 {
        AuthorityInstallRequestV1 {
            physical_scope: FleetScope::new(
                Uuid::from_u128(tenant),
                project,
                "ostk-authority-install",
                None,
                PrivacyTier::T1Project,
            )
            .unwrap(),
            semantic_scope: AuthenticatedProjectScopeV1::from_trusted_context(
                ContractId::new("tenant.acme").unwrap(),
                ContractId::new("project.recall").unwrap(),
            ),
        }
    }

    #[test]
    fn the_receipt_is_deterministic_and_bound_to_the_physical_scope() {
        let (bytes, digest) = bootstrap_receipt(&request(1, "physical-project")).unwrap();
        assert_eq!(
            bootstrap_receipt(&request(1, "physical-project")).unwrap(),
            (bytes, digest),
            "the same request must give the same receipt on every run"
        );

        let mut other_agent = request(1, "physical-project");
        other_agent.physical_scope.agent = "another-operator".into();
        assert_eq!(
            bootstrap_receipt(&other_agent).unwrap().1,
            digest,
            "the agent is not part of the physical authority"
        );

        for other in [request(2, "physical-project"), request(1, "other-project")] {
            assert_ne!(
                bootstrap_receipt(&other).unwrap().1,
                digest,
                "another physical scope must get another receipt"
            );
        }
    }

    #[test]
    fn the_receipt_verifies_under_its_own_pin_for_the_requested_scope_only() {
        let request = request(1, "physical-project");
        let artifacts = InstallArtifacts::compile(&request).unwrap();
        assert_eq!(
            artifacts.bootstrap.receipt().statement.scope,
            request.semantic_scope
        );
        assert_eq!(
            artifacts.bootstrap.receipt_digest(),
            artifacts.pins.bootstrap_receipt_digest
        );

        let (canonical, receipt_digest) = bootstrap_receipt(&request).unwrap();
        let other_scope = AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.acme").unwrap(),
            ContractId::new("project.other").unwrap(),
        );
        assert!(
            verify_pinned_bootstrap(
                &canonical,
                BootstrapPin::from_trusted_config(receipt_digest),
                &frozen_profile_reference_v1(),
                &other_scope,
                compiled_genesis_package().unwrap(),
            )
            .is_err(),
            "the receipt authorizes only the semantic scope it was installed for"
        );
    }

    #[test]
    fn the_printed_pins_load_back_as_the_writer_authority_group() {
        let pins = InstallArtifacts::compile(&request(1, "physical-project"))
            .unwrap()
            .pins;
        let serde_json::Value::Object(printed) = serde_json::to_value(&pins).unwrap() else {
            panic!("the pins must print as one JSON object");
        };
        let environment = printed
            .into_iter()
            .map(|(name, value)| (name, value.as_str().unwrap().to_owned()))
            .collect::<BTreeMap<_, _>>();
        let config = WriterAuthorityConfig::from_lookup(|name| environment.get(name).cloned())
            .unwrap()
            .expect("the printed object must be the complete pin group");
        assert_eq!(config.semantic_scope(), &pins.semantic_scope());
        assert_eq!(
            config.bootstrap_receipt_digest(),
            pins.bootstrap_receipt_digest
        );
        assert_eq!(config.expected_activation_id(), None);
    }

    /// A run that died after the genesis activation and before `0 -> 1`
    /// leaves a durable genesis the view cannot see yet. The next run must
    /// resume from the audited genesis root instead of signing a second,
    /// stale genesis statement.
    #[tokio::test]
    async fn live_an_interrupted_install_resumes_from_the_durable_genesis_when_configured() {
        let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
            return;
        };
        let mut request = request(1, "authority-resume");
        request.physical_scope.tenant_id = Uuid::now_v7();
        let store = crate::store::cockroach::CockroachStore::connect(
            &database_url,
            request.physical_scope.clone(),
            crate::store::cockroach::PoolConfig::default(),
        )
        .await
        .unwrap();
        store.migrate().await.unwrap();
        let pool = store.pool();
        let retry = RetryPolicy {
            max_attempts: 20,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(50),
        };
        let control = TrustedControlScope::from_trusted_context(
            &request.physical_scope,
            request.semantic_scope.clone(),
        )
        .unwrap();
        let artifacts = InstallArtifacts::compile(&request).unwrap();

        CockroachGenesisRepository::new(pool.clone(), control.clone(), retry)
            .bootstrap_genesis(&artifacts.bootstrap, artifacts.genesis)
            .await
            .unwrap();
        let genesis = CockroachGenesisActivationRepository::new(
            pool.clone(),
            control,
            retry,
            artifacts.bootstrap.clone(),
            artifacts.genesis.clone(),
            artifacts.genesis_test_result.clone(),
            principal_binding().unwrap(),
        )
        .unwrap();
        assert_eq!(genesis.accepted_genesis_head().await.unwrap(), None);
        let (activated, outcome) = activate_genesis(pool, &genesis, &artifacts).await.unwrap();
        assert_eq!(outcome, InstallStepOutcomeV1::Inserted);
        assert_eq!(
            genesis.accepted_genesis_head().await.unwrap(),
            Some(activated),
            "the audited genesis root must yield the head the activation accepted"
        );

        let report = install_writer_authority(pool, &request, retry)
            .await
            .expect("an interrupted install must resume");
        assert_eq!(
            report
                .steps
                .iter()
                .map(|step| (step.step, step.outcome))
                .collect::<Vec<_>>(),
            [
                (
                    InstallStepV1::ControlBootstrap,
                    InstallStepOutcomeV1::AlreadyPresent
                ),
                (
                    InstallStepV1::GenesisActivation,
                    InstallStepOutcomeV1::AlreadyPresent
                ),
                (
                    InstallStepV1::FirstSuccessor,
                    InstallStepOutcomeV1::Inserted
                ),
                (InstallStepV1::GenerationTwo, InstallStepOutcomeV1::Inserted),
            ]
        );
        assert_eq!(report.package, KnownRegistryPackage::ConnectorGeneration2);
    }

    #[test]
    fn the_minted_generation_two_result_is_stable_and_names_the_target() {
        let profile = frozen_profile_reference_v1();
        let target = compiled_generation_two_package().unwrap();
        let first = generation_two_test_result(&profile, &target).unwrap();
        assert_eq!(
            first,
            generation_two_test_result(&profile, &target).unwrap()
        );
        let decoded: RegistryTestResultV1 = decode_strict(&first).unwrap();
        assert_eq!(decoded.package_digest, target.package_digest());
        assert_eq!(decoded.outcome, RegistryTestOutcomeV1::Passed);
    }
}
