//! Bounded, single-flight construction of tenant/project services and agent edges.

use super::McpServer;
use crate::application::LifecycleServing;
use crate::evidence_recall::{EvidenceRecall, start_evidence_recall};
use crate::item_recall::{ItemRecall, start_item_recall_citing};
use crate::ledger::CockroachClaimLedger;
use crate::memory_contracts::digest::Sha256Digest;
use crate::projectors::{ChunkEmbedderProvider, EmbeddingProvider};
use crate::remember_runtime::{
    AssertStatusV1, CaptureStatusV1, start_collected_capture, start_event_first_assert,
};
use crate::service::{
    FleetMemoryService, RecallAction, RecallRequest, RecallResult, RecallSurface, Refusal,
    RememberAction, RememberRequest, RememberResult, RememberSurface, ServiceError, ServiceResult,
};
use crate::spec_conformance::{SpecConformanceRead, start_spec_conformance};
use crate::store::cockroach::{
    ClaimItemLinksCapability, CockroachStore, ConflictLifecycleCapability, DatabaseCapabilities,
    RetryPolicy, active_embedding_model, probe_claim_item_links, probe_conflict_lifecycle,
};
use crate::{CockroachMemoryService, FleetConfig, FleetError, FleetScope, Result};
use async_trait::async_trait;
use ostk_recall_core::{ChunkEmbedder, PrivacyTier};
use sqlx::PgPool;
use std::{
    collections::HashMap,
    hash::Hash,
    str::FromStr as _,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OnceCell};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Access {
    Writer,
    Shipper,
    Publication,
}

type Cached<T> = Arc<OnceCell<(Instant, Option<Arc<T>>)>>;
struct Entry<T> {
    used: Instant,
    value: Cached<T>,
}

/// Failed initialization is retried after 30 seconds; successful entries are
/// evicted least-recently-used. Authentication is never cached here.
struct Cache<K, T> {
    limit: usize,
    entries: Mutex<HashMap<K, Entry<T>>>,
}
impl<K: Clone + Eq + Hash + Send, T: Send + Sync> Cache<K, T> {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            entries: Mutex::new(HashMap::new()),
        }
    }
    async fn cell(&self, key: K) -> Cached<T> {
        let mut entries = self.entries.lock().await;
        if entries.get(&key).is_some_and(|entry| {
            entry.value.get().is_some_and(|(at, value)| {
                value.is_none() && at.elapsed() >= Duration::from_secs(30)
            })
        }) {
            entries.remove(&key);
        }
        if let Some(entry) = entries.get_mut(&key) {
            entry.used = Instant::now();
            return entry.value.clone();
        }
        if entries.len() >= self.limit
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(key, _)| key.clone())
        {
            entries.remove(&oldest);
        }
        let value = Arc::new(OnceCell::new());
        entries.insert(
            key,
            Entry {
                used: Instant::now(),
                value: value.clone(),
            },
        );
        value
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ScopeKey {
    tenant: Uuid,
    project: String,
    public: bool,
}
#[derive(Clone, PartialEq, Eq, Hash)]
struct AgentKey {
    scope: ScopeKey,
    agent: String,
    access: Access,
}

struct Prepared {
    store: Arc<CockroachStore>,
    capabilities: DatabaseCapabilities,
    conflict: Option<ConflictLifecycleCapability>,
    item_support: Option<ClaimItemLinksCapability>,
    items: Option<Arc<dyn ItemRecall>>,
    evidence: Option<Arc<dyn EvidenceRecall>>,
    spec: Option<Arc<dyn SpecConformanceRead>>,
}

pub struct ScopeServices {
    config: FleetConfig,
    pool: PgPool,
    embedder: Arc<dyn ChunkEmbedder>,
    embedding_tier: Option<Arc<crate::embed_tier::remote::RemoteClient>>,
    scopes: Cache<ScopeKey, Prepared>,
    agents: Cache<AgentKey, McpServer>,
}

impl ScopeServices {
    pub fn new(
        config: FleetConfig,
        pool: PgPool,
        embedder: Arc<dyn ChunkEmbedder>,
        scope_limit: usize,
        agent_limit: usize,
    ) -> Result<Self> {
        if scope_limit == 0 || agent_limit == 0 {
            return Err(FleetError::Configuration(
                "remote service cache limits must be positive".into(),
            ));
        }
        Ok(Self {
            config,
            pool,
            embedder,
            embedding_tier: None,
            scopes: Cache::new(scope_limit),
            agents: Cache::new(agent_limit),
        })
    }

    #[must_use]
    pub fn with_embedding_tier(
        mut self,
        tier: Option<Arc<crate::embed_tier::remote::RemoteClient>>,
    ) -> Self {
        self.embedding_tier = tier;
        self
    }

    pub async fn server(&self, scope: FleetScope, access: Access) -> Result<Arc<McpServer>> {
        scope.validate()?;
        if scope.session_id.is_some() || scope.privacy_tier != PrivacyTier::T1Project {
            return Err(FleetError::InvalidScope(
                "remote service scopes use project storage and request-local sessions".into(),
            ));
        }
        let key = ScopeKey {
            tenant: scope.tenant_id,
            project: scope.project.clone(),
            public: access == Access::Publication,
        };
        let scope_cell = self.scopes.cell(key.clone()).await;
        let (_, prepared) = scope_cell
            .get_or_init(|| async {
                (
                    Instant::now(),
                    self.prepare(&scope, key.public).await.ok().map(Arc::new),
                )
            })
            .await;
        let prepared = prepared
            .as_ref()
            .ok_or_else(|| FleetError::Configuration("scope_not_bootstrapped".into()))?;
        let cell = self
            .agents
            .cell(AgentKey {
                scope: key,
                agent: scope.agent.clone(),
                access,
            })
            .await;
        let (_, server) = cell
            .get_or_init(|| async {
                (
                    Instant::now(),
                    self.build_agent(scope, access, prepared)
                        .await
                        .ok()
                        .map(Arc::new),
                )
            })
            .await;
        server
            .clone()
            .ok_or_else(|| FleetError::Configuration("scope_service_unavailable".into()))
    }

    async fn prepare(&self, scope: &FleetScope, public: bool) -> Result<Prepared> {
        if active_embedding_model(&self.pool, scope).await?.as_deref()
            != Some(self.config.embedding_model_identity().as_str())
        {
            return Err(FleetError::Configuration("scope_not_bootstrapped".into()));
        }
        let store = Arc::new(CockroachStore::from_pool(self.pool.clone(), scope.clone())?);
        let capabilities = store.capabilities().await?;
        let conflict = if !public && self.config.lifecycle.remember_lifecycle {
            probe_conflict_lifecycle(&self.pool, &capabilities).await?
        } else {
            None
        };
        let links = if public {
            None
        } else {
            probe_claim_item_links(&self.pool, &capabilities).await?
        };
        let items = if public {
            None
        } else {
            start_item_recall_citing(
                &self.pool,
                &capabilities,
                scope,
                &self.config.embedding_model_sha256,
                links,
            )
            .await
        };
        let evidence = if public {
            None
        } else {
            start_evidence_recall(
                &self.pool,
                &capabilities,
                scope,
                &self.config.embedding_model_sha256,
            )
            .await
        };
        let spec = if public {
            None
        } else {
            start_spec_conformance(&self.pool, &capabilities, scope).await
        };
        Ok(Prepared {
            store,
            capabilities,
            conflict,
            item_support: links.filter(|_| items.is_some()),
            items,
            evidence,
            spec,
        })
    }

    #[allow(clippy::too_many_lines)] // Keep the complete capability composition auditable together.
    async fn build_agent(
        &self,
        scope: FleetScope,
        access: Access,
        prepared: &Prepared,
    ) -> Result<McpServer> {
        let mut ledger = CockroachClaimLedger::new(
            self.pool.clone(),
            scope.clone(),
            self.embedder.clone(),
            RetryPolicy::default(),
        )?;
        if access == Access::Publication {
            let service = CockroachMemoryService::publication(
                scope.clone(),
                prepared.store.clone(),
                Arc::new(ledger),
                self.embedder.clone(),
            )?
            .with_embedding_tier(self.embedding_tier.clone());
            return McpServer::new(
                Arc::new(RoleGatedService::new(Arc::new(service), access)),
                scope,
            );
        }
        if let Some(capability) = prepared.conflict {
            ledger = ledger.with_conflict_lifecycle(capability);
            if self.config.lifecycle.conflict_adjudication {
                ledger = ledger.with_conflict_adjudication();
            }
        }
        if let Some(capability) = prepared.item_support {
            ledger = ledger.with_claim_item_links(capability);
        }
        ledger = ledger.with_self_dispute_refusal(self.config.lifecycle.remember_lifecycle);
        let pinned = scope.tenant_id == self.config.default_scope.tenant_id
            && scope.project == self.config.default_scope.project;
        let (ledger, assert_status) = if pinned {
            start_event_first_assert(self.pool.clone(), &scope, RetryPolicy::default())
                .await
                .bind_ledger(ledger)
        } else {
            (
                ledger,
                Some(AssertStatusV1 {
                    served: false,
                    reason: Some("scope has no writer-authority pins".into()),
                    registry: None,
                    route: None,
                }),
            )
        };
        let provider = self.embedding_tier.as_ref().map_or_else(
            || {
                Sha256Digest::from_str(&self.config.embedding_model_sha256)
                    .ok()
                    .and_then(|digest| {
                        ChunkEmbedderProvider::new(self.embedder.clone(), digest).ok()
                    })
                    .map(|provider| Arc::new(provider) as Arc<dyn EmbeddingProvider>)
            },
            |tier| {
                Some(
                    Arc::new(crate::embed_tier::remote::RemoteEmbeddingProvider::new(
                        tier.clone(),
                    )) as Arc<dyn EmbeddingProvider>,
                )
            },
        );
        let (capture, capture_status) = if pinned {
            start_collected_capture(
                self.pool.clone(),
                &prepared.capabilities,
                &scope,
                RetryPolicy::default(),
                provider,
            )
            .await
            .into_parts()
        } else {
            (
                None,
                Some(CaptureStatusV1 {
                    served: false,
                    mode: None,
                    reason: Some("scope has no writer-authority pins".into()),
                    identity: None,
                    capture_scopes: None,
                }),
            )
        };
        let surface = RememberSurface {
            claim_lifecycle: self.config.lifecycle.remember_lifecycle,
            conflict_lifecycle: prepared.conflict.is_some(),
            adjudication: prepared.conflict.is_some()
                && self.config.lifecycle.conflict_adjudication,
            assert: assert_status.as_ref().is_some_and(|status| status.served),
            capture: capture.is_some(),
            item_support: prepared.item_support.is_some(),
        };
        let mut service = CockroachMemoryService::new(
            scope.clone(),
            prepared.store.clone(),
            Arc::new(ledger),
            self.embedder.clone(),
        )?
        .with_embedding_tier(self.embedding_tier.clone())
        .with_assert_status(assert_status)
        .with_capture(capture, capture_status)
        .with_lifecycle(LifecycleServing {
            surface,
            hide_non_current_claim_chunks: self.config.lifecycle.remember_lifecycle,
            lifecycle_overlay: prepared.conflict.is_some(),
        });
        if let Some(value) = &prepared.items {
            service = service.with_item_recall(value.clone());
        }
        if let Some(value) = &prepared.evidence {
            service = service.with_evidence_recall(value.clone());
        }
        if let Some(value) = &prepared.spec {
            service = service.with_spec_conformance(value.clone());
        }
        McpServer::new(
            Arc::new(RoleGatedService::new(Arc::new(service), access)),
            scope,
        )
    }
}

pub struct RoleGatedService {
    inner: Arc<dyn FleetMemoryService>,
    access: Access,
}
impl RoleGatedService {
    pub fn new(inner: Arc<dyn FleetMemoryService>, access: Access) -> Self {
        Self { inner, access }
    }
}
fn forbidden() -> ServiceError {
    ServiceError::Refused(Refusal {
        code: "role_forbids_action",
        message: "the authenticated role does not allow this action".into(),
        details: serde_json::json!({}),
    })
}
#[async_trait]
impl FleetMemoryService for RoleGatedService {
    async fn recall(
        &self,
        scope: FleetScope,
        request: RecallRequest,
    ) -> ServiceResult<RecallResult> {
        if self.access == Access::Shipper
            && !matches!(request.action, RecallAction::Status | RecallAction::Brief)
        {
            return Err(forbidden());
        }
        self.inner.recall(scope, request).await
    }
    async fn remember(
        &self,
        scope: FleetScope,
        request: RememberRequest,
    ) -> ServiceResult<RememberResult> {
        if self.access == Access::Publication
            || (self.access == Access::Shipper && request.action != RememberAction::Capture)
        {
            return Err(forbidden());
        }
        self.inner.remember(scope, request).await
    }
    fn remember_surface(&self) -> RememberSurface {
        match self.access {
            Access::Writer => self.inner.remember_surface(),
            Access::Shipper => RememberSurface {
                capture: self.inner.remember_surface().capture,
                ..RememberSurface::RECORD_ONLY
            },
            Access::Publication => RememberSurface::RECORD_ONLY,
        }
    }
    fn recall_surface(&self) -> RecallSurface {
        if self.access == Access::Shipper {
            RecallSurface::NONE
        } else {
            self.inner.recall_surface()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, json};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Memory {
        calls: AtomicUsize,
    }
    #[async_trait]
    impl FleetMemoryService for Memory {
        async fn recall(&self, _: FleetScope, _: RecallRequest) -> ServiceResult<RecallResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(RecallResult::new(json!({})))
        }
        async fn remember(
            &self,
            _: FleetScope,
            _: RememberRequest,
        ) -> ServiceResult<RememberResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(RememberResult::new(json!({})))
        }
    }

    #[tokio::test]
    async fn restricted_roles_refuse_before_backend_dispatch() {
        let memory = Arc::new(Memory::default());
        let scope = FleetScope::new(
            Uuid::now_v7(),
            "test",
            "agent",
            None,
            PrivacyTier::T1Project,
        )
        .unwrap();
        let shipper = RoleGatedService::new(memory.clone(), Access::Shipper);
        for action in [RecallAction::Search, RecallAction::Get, RecallAction::Audit] {
            assert!(
                shipper
                    .recall(scope.clone(), RecallRequest::new(action, Map::new()))
                    .await
                    .is_err()
            );
        }
        for action in [
            RememberAction::Record,
            RememberAction::Assert,
            RememberAction::Forget,
        ] {
            assert!(
                shipper
                    .remember(
                        scope.clone(),
                        RememberRequest::new(action, None, Map::new())
                    )
                    .await
                    .is_err()
            );
        }
        let public = RoleGatedService::new(memory.clone(), Access::Publication);
        assert!(
            public
                .remember(
                    scope.clone(),
                    RememberRequest::new(RememberAction::Capture, None, Map::new())
                )
                .await
                .is_err()
        );
        assert_eq!(memory.calls.load(Ordering::SeqCst), 0);
        for action in [RecallAction::Status, RecallAction::Brief] {
            shipper
                .recall(scope.clone(), RecallRequest::new(action, Map::new()))
                .await
                .unwrap();
        }
        shipper
            .remember(
                scope,
                RememberRequest::new(RememberAction::Capture, None, Map::new()),
            )
            .await
            .unwrap();
        assert_eq!(memory.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn cache_singleflight_lru_and_negative_retry() {
        let cache = Arc::new(Cache::<String, usize>::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let tasks = (0..20)
            .map(|_| {
                let cache = cache.clone();
                let calls = calls.clone();
                tokio::spawn(async move {
                    let cell = cache.cell("a".into()).await;
                    cell.get_or_init(|| async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        (Instant::now(), Some(Arc::new(42)))
                    })
                    .await
                    .1
                    .clone()
                    .unwrap()
                })
            })
            .collect::<Vec<_>>();
        for task in tasks {
            assert_eq!(*task.await.unwrap(), 42);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let b = cache.cell("b".into()).await;
        cache.cell("a".into()).await;
        cache.cell("c".into()).await;
        assert!(!Arc::ptr_eq(&b, &cache.cell("b".into()).await));
        assert_eq!(cache.entries.lock().await.len(), 2);
        let failed = cache.cell("failed".into()).await;
        failed
            .set((
                Instant::now().checked_sub(Duration::from_secs(31)).unwrap(),
                None,
            ))
            .unwrap();
        assert!(!Arc::ptr_eq(&failed, &cache.cell("failed".into()).await));
        let recent = cache.cell("recent".into()).await;
        recent.set((Instant::now(), None)).unwrap();
        assert!(Arc::ptr_eq(&recent, &cache.cell("recent".into()).await));
    }
}
