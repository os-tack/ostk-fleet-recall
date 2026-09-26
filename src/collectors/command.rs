//! `ostk-fleet-recall collect`: operator imports and what the collectors hold
//! (ADR 0008 D9).
//!
//! [`run_collect_command`] is the whole command once the process
//! configuration is loaded; the binary only supplies the writer connection,
//! the environment, and stdout, as `worker` does. Each subcommand prints one
//! JSON document on one line.
//!
//! * `collect import --instance I --principal P --provider X --provider-scope S
//!   --audience operator-declared --format items-jsonl --path F [--no-drain]
//!   [--stale-after SECONDS]` imports one file
//!   ([`crate::collectors::import`]). It needs the writer-authority pins, and
//!   `FLEET_RECALL_CONTENT_KEK_HEX` unless `--no-drain` leaves the rows to the
//!   worker. `--audience operator-declared` is the operator's declaration that
//!   everything the file holds is visible to the whole project; there is no
//!   other audience, and the flag is required so the declaration is never
//!   implicit. The snapshot stays current for `--stale-after` seconds (30
//!   days by default).
//! * `collect status` lists every collector instance of the scope: its status
//!   row, outbox rows by state, cursors (never their bytes), and dead letters
//!   by reason.
//! * `collect dead-letters [--since RFC3339] [--instance I]` lists dead
//!   letters, oldest first: identities, digests, reasons, and the sink's
//!   static diagnostics, never provider text.
//! * `collect retire --instance I` retires an import's status row, so evidence
//!   and item recall stop judging absence by its snapshot. Only an import's
//!   row: the worker retires its own collectors, and capture rows are never
//!   retired here. Its items stay recallable; re-importing re-activates it.
//!
//! Every subcommand runs as the writer login and needs the schema through
//! migration 34. `import` checks, before it stages anything, every privilege
//! the worker's `collect` step would use.

use std::collections::BTreeSet;
use std::future::Future;
use std::io::Write;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::config::WriterAuthorityConfig;
use crate::context::FleetScope;
use crate::coverage_runtime::CockroachCoverageRuntimeRepository;
use crate::error::{FleetError, Result};
use crate::evidence_ledger::content_kek_from_lookup;
use crate::memory_contracts::collected_item::{BoundedTextV1, ProviderKindV1};
use crate::memory_contracts::common::ContractId;
use crate::registry_witness::WriterAuthorityRuntime;
use crate::store::cockroach::{COLLECTED_ITEMS_SCHEMA_VERSION, DatabaseCapabilities, RetryPolicy};
use crate::worker::{WorkerStepV1, probe_worker_privileges};

use super::import::{
    DEFAULT_IMPORT_STALE_AFTER_SECONDS, ImportContextV1, ItemsImportRequestV1, import_items_jsonl,
};
use super::sink::{CollectedDrainContextV1, CollectedItemSink, RetireImportV1};

/// The audience an operator declares for an import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportAudienceV1 {
    /// Everything the file holds is visible to the whole project.
    OperatorDeclared,
}

/// The format of an import file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormatV1 {
    /// One `CollectedItemInputV1` per line.
    ItemsJsonl,
}

/// The arguments of `collect import`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectImportV1 {
    /// `--instance`.
    pub instance: String,
    /// `--principal`.
    pub principal: String,
    /// `--provider`.
    pub provider: String,
    /// `--provider-scope`.
    pub provider_scope: String,
    /// `--audience`.
    pub audience: ImportAudienceV1,
    /// `--format`.
    pub format: ImportFormatV1,
    /// `--path`.
    pub path: PathBuf,
    /// `--no-drain`: stage only, and leave the rows to the worker.
    pub no_drain: bool,
    /// `--stale-after`, in seconds.
    pub stale_after_seconds: Option<u64>,
}

impl CollectImportV1 {
    fn request(&self) -> Result<ItemsImportRequestV1> {
        let ImportAudienceV1::OperatorDeclared = self.audience;
        let ImportFormatV1::ItemsJsonl = self.format;
        let field = |flag: &str, error: &dyn std::fmt::Display| {
            FleetError::Configuration(format!("{flag}: {error}"))
        };
        Ok(ItemsImportRequestV1 {
            instance: ContractId::new(&self.instance)
                .map_err(|error| field("--instance", &error))?,
            principal: ContractId::new(&self.principal)
                .map_err(|error| field("--principal", &error))?,
            provider: ProviderKindV1::new(self.provider.clone())
                .map_err(|error| field("--provider", &error))?,
            provider_scope_id: BoundedTextV1::new(self.provider_scope.clone())
                .map_err(|error| field("--provider-scope", &error))?,
            path: self.path.clone(),
            stale_after_seconds: self
                .stale_after_seconds
                .unwrap_or(DEFAULT_IMPORT_STALE_AFTER_SECONDS),
        })
    }
}

/// One `collect` subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectCommandV1 {
    /// `collect import`.
    Import(CollectImportV1),
    /// `collect status`.
    Status,
    /// `collect dead-letters`.
    DeadLetters {
        /// `--since`, RFC 3339.
        since: Option<String>,
        /// `--instance`.
        instance: Option<String>,
    },
    /// `collect retire`.
    Retire {
        /// `--instance`.
        instance: String,
    },
}

/// What the process gives the command besides its arguments.
pub struct CollectProcessV1<'a> {
    /// The physical `(tenant_id, project)`.
    pub scope: FleetScope,
    /// Reads one deployment variable: the writer-authority pins and the
    /// content key. The process environment in production.
    pub lookup: &'a (dyn Fn(&str) -> Option<String> + Sync),
    /// Retry policy for every serializable write (retried only on 40001).
    pub retry: RetryPolicy,
}

impl std::fmt::Debug for CollectProcessV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CollectProcessV1")
            .field("scope", &self.scope)
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

fn require_schema(capabilities: &DatabaseCapabilities) -> Result<()> {
    if capabilities.supports_schema_version(COLLECTED_ITEMS_SCHEMA_VERSION) {
        return Ok(());
    }
    Err(FleetError::Configuration(format!(
        "collected items need the schema through migration {COLLECTED_ITEMS_SCHEMA_VERSION}, \
         but this database has reached {}; run `ostk-fleet-recall migrate`",
        capabilities.schema_version
    )))
}

fn instance_id(flag: &str, value: &str) -> Result<ContractId> {
    ContractId::new(value).map_err(|error| FleetError::Configuration(format!("{flag}: {error}")))
}

/// Run one `ostk-fleet-recall collect` subcommand and print its JSON
/// document as one line on `out`. See the module documentation.
///
/// `connect` is called once, after every argument and configuration input
/// has been read, and returns a pool authenticated as the writer login with
/// that pool's schema snapshot.
///
/// # Errors
///
/// [`FleetError::Configuration`] for an invalid argument, missing pins, a
/// missing content key for an import that drains, an unreadable file, an
/// older schema, a missing privilege, an instance an import may not use, or
/// a retire of a row no import owns; whatever `connect` returns; a writer
/// authority that does not verify; any database failure; and a failure to
/// write the document.
pub async fn run_collect_command<Connect, Connecting>(
    command: &CollectCommandV1,
    process: CollectProcessV1<'_>,
    connect: Connect,
    out: &mut (impl Write + Send),
) -> Result<Value>
where
    Connect: FnOnce() -> Connecting + Send,
    Connecting: Future<Output = Result<(PgPool, DatabaseCapabilities)>> + Send,
{
    let document = match command {
        CollectCommandV1::Import(arguments) => {
            Box::pin(import(arguments, &process, connect)).await?
        }
        CollectCommandV1::Status => {
            let sink = connect_sink(&process, connect).await?;
            to_value(&sink.collector_status().await?)?
        }
        CollectCommandV1::DeadLetters { since, instance } => {
            let since = since
                .as_deref()
                .map(|since| {
                    DateTime::parse_from_rfc3339(since)
                        .map(|since| since.with_timezone(&Utc))
                        .map_err(|error| {
                            FleetError::Configuration(format!(
                                "--since must be an RFC 3339 timestamp: {error}"
                            ))
                        })
                })
                .transpose()?;
            let instance = instance
                .as_deref()
                .map(|instance| instance_id("--instance", instance))
                .transpose()?;
            let sink = connect_sink(&process, connect).await?;
            to_value(&sink.dead_letters(since, instance.as_ref()).await?)?
        }
        CollectCommandV1::Retire { instance } => {
            let id = instance_id("--instance", instance)?;
            let sink = connect_sink(&process, connect).await?;
            match sink.retire_import(&id).await? {
                RetireImportV1::Retired => json!({"instance": instance, "retired": true}),
                RetireImportV1::AlreadyRetired => {
                    json!({"instance": instance, "retired": true, "already_retired": true})
                }
                RetireImportV1::OwnedBy(owner) => {
                    return Err(FleetError::Configuration(format!(
                        "instance {instance} reports as a {owner} collector; `collect retire` \
                         retires an import's row only"
                    )));
                }
                RetireImportV1::Unknown => {
                    return Err(FleetError::Configuration(format!(
                        "no collector reports under instance {instance}"
                    )));
                }
            }
        }
    };
    let line = serde_json::to_string(&document).map_err(|error| {
        FleetError::Protocol(format!("the collect report does not serialize: {error}"))
    })?;
    writeln!(out, "{line}")
        .and_then(|()| out.flush())
        .map_err(|error| {
            FleetError::Protocol(format!("the collect report could not be written: {error}"))
        })?;
    Ok(document)
}

fn to_value(value: &impl serde::Serialize) -> Result<Value> {
    serde_json::to_value(value).map_err(|error| {
        FleetError::Protocol(format!("the collect report does not serialize: {error}"))
    })
}

async fn connect_sink<Connect, Connecting>(
    process: &CollectProcessV1<'_>,
    connect: Connect,
) -> Result<CollectedItemSink>
where
    Connect: FnOnce() -> Connecting + Send,
    Connecting: Future<Output = Result<(PgPool, DatabaseCapabilities)>> + Send,
{
    let (pool, capabilities) = connect().await?;
    require_schema(&capabilities)?;
    CollectedItemSink::new(pool, &process.scope, process.retry)
}

async fn import<Connect, Connecting>(
    arguments: &CollectImportV1,
    process: &CollectProcessV1<'_>,
    connect: Connect,
) -> Result<Value>
where
    Connect: FnOnce() -> Connecting + Send,
    Connecting: Future<Output = Result<(PgPool, DatabaseCapabilities)>> + Send,
{
    let request = arguments.request()?;
    let pins = WriterAuthorityConfig::from_lookup(process.lookup)?.ok_or_else(|| {
        FleetError::Configuration(
            "collect import needs the writer-authority pins that `ostk-authority-install apply` \
             prints"
                .to_owned(),
        )
    })?;
    let kek = if arguments.no_drain {
        None
    } else {
        Some(content_kek_from_lookup(process.lookup)?.ok_or_else(|| {
            FleetError::Configuration(
                "collect import drains what it stages, which needs FLEET_RECALL_CONTENT_KEK_HEX; \
                 pass --no-drain to leave the rows to the worker"
                    .to_owned(),
            )
        })?)
    };
    std::fs::File::open(&request.path).map_err(|error| {
        FleetError::Configuration(format!("cannot read {}: {error}", request.path.display()))
    })?;

    let (pool, capabilities) = connect().await?;
    require_schema(&capabilities)?;
    probe_worker_privileges(
        &pool,
        &capabilities,
        &BTreeSet::from([WorkerStepV1::Collect]),
    )
    .await?;
    let (runtime, _) =
        WriterAuthorityRuntime::start(pool.clone(), process.scope.clone(), pins, process.retry)
            .await?;
    let verified = runtime.verify().await.map_err(|error| {
        FleetError::Configuration(format!("the writer authority does not verify: {error}"))
    })?;
    let sink = CollectedItemSink::new(pool.clone(), &process.scope, process.retry)?;
    let coverage = CockroachCoverageRuntimeRepository::new(
        pool,
        runtime.control_scope().clone(),
        process.retry,
    );
    let drain = kek.as_ref().map(|kek| CollectedDrainContextV1 {
        verified: &verified,
        ledger: runtime.ledger().as_ref(),
        control_scope: runtime.control_scope(),
        kek,
    });
    let report = Box::pin(import_items_jsonl(
        &request,
        &ImportContextV1 {
            sink: &sink,
            verified: &verified,
            coverage: &coverage,
            drain: drain.as_ref(),
        },
    ))
    .await?;
    to_value(&report)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    use uuid::Uuid;

    use super::*;

    const CONNECTED: &str = "connect was called";

    fn arguments(path: PathBuf) -> CollectImportV1 {
        CollectImportV1 {
            instance: "import.slack".into(),
            principal: "principal.import".into(),
            provider: "slack".into(),
            provider_scope: "T07ACME0001".into(),
            audience: ImportAudienceV1::OperatorDeclared,
            format: ImportFormatV1::ItemsJsonl,
            path,
            no_drain: false,
            stale_after_seconds: None,
        }
    }

    /// Run `command` with a `connect` that records the call and stops the
    /// run; the error and whether it connected.
    async fn run(
        command: &CollectCommandV1,
        variables: &HashMap<&'static str, String>,
    ) -> (String, bool) {
        let connected = AtomicBool::new(false);
        let connected_flag = &connected;
        let lookup = |name: &str| variables.get(name).cloned();
        let mut out = Vec::new();
        let outcome = run_collect_command(
            command,
            CollectProcessV1 {
                scope: FleetScope::new(
                    Uuid::now_v7(),
                    "collect-command",
                    "collector",
                    None,
                    ostk_recall_core::PrivacyTier::T1Project,
                )
                .unwrap(),
                lookup: &lookup,
                retry: RetryPolicy::default(),
            },
            move || async move {
                connected_flag.store(true, Ordering::SeqCst);
                Err(FleetError::Configuration(CONNECTED.into()))
            },
            &mut out,
        )
        .await;
        assert!(out.is_empty(), "a run that stopped prints nothing");
        let Err(FleetError::Configuration(message)) = outcome else {
            panic!("expected a configuration error, got {outcome:?}");
        };
        (message, connected.load(Ordering::SeqCst))
    }

    fn pins() -> HashMap<&'static str, String> {
        HashMap::from([
            (
                "FLEET_RECALL_CONTRACT_TENANT_NAMESPACE",
                "tenant.acme".into(),
            ),
            (
                "FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE",
                "project.recall".into(),
            ),
            ("FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST", "ab".repeat(32)),
        ])
    }

    #[tokio::test]
    async fn an_import_needs_its_inputs_before_it_connects() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("items.jsonl");
        std::fs::write(&file, b"").unwrap();

        let (message, connected) = run(
            &CollectCommandV1::Import(arguments(file.clone())),
            &HashMap::new(),
        )
        .await;
        assert!(message.contains("writer-authority pins"), "{message}");
        assert!(!connected);

        let (message, connected) =
            run(&CollectCommandV1::Import(arguments(file.clone())), &pins()).await;
        assert!(
            message.contains("FLEET_RECALL_CONTENT_KEK_HEX"),
            "{message}"
        );
        assert!(message.contains("--no-drain"), "{message}");
        assert!(!connected);

        // Staging alone needs no content key.
        let staging = CollectImportV1 {
            no_drain: true,
            ..arguments(file.clone())
        };
        let (message, connected) = run(&CollectCommandV1::Import(staging), &pins()).await;
        assert_eq!(message, CONNECTED);
        assert!(connected);

        let missing = arguments(directory.path().join("absent.jsonl"));
        let mut keyed = pins();
        keyed.insert("FLEET_RECALL_CONTENT_KEK_HEX", "cd".repeat(32));
        let (message, connected) = run(&CollectCommandV1::Import(missing), &keyed).await;
        assert!(message.contains("absent.jsonl"), "{message}");
        assert!(!connected);

        let bad = CollectImportV1 {
            instance: "Not An Instance".into(),
            ..arguments(file)
        };
        let (message, connected) = run(&CollectCommandV1::Import(bad), &keyed).await;
        assert!(message.starts_with("--instance"), "{message}");
        assert!(!connected);
    }

    #[tokio::test]
    async fn listing_arguments_are_checked_before_connecting() {
        let (message, connected) = run(
            &CollectCommandV1::DeadLetters {
                since: Some("yesterday".into()),
                instance: None,
            },
            &HashMap::new(),
        )
        .await;
        assert!(message.contains("--since"), "{message}");
        assert!(!connected);
        let (message, connected) = run(
            &CollectCommandV1::Retire {
                instance: "UPPER".into(),
            },
            &HashMap::new(),
        )
        .await;
        assert!(message.starts_with("--instance"), "{message}");
        assert!(!connected);
        let (message, connected) = run(&CollectCommandV1::Status, &HashMap::new()).await;
        assert_eq!(message, CONNECTED);
        assert!(connected);
    }
}
