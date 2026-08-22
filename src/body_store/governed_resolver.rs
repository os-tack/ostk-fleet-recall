//! The production [`SourceContentResolver`]: the governed content store.
//!
//! [`super::repository::SourceContentResolver`] is the one seam between the
//! body projector and the content plane, and until now the only implementation
//! was an in-memory map inside a test. This is the real one: it reads the
//! per-object ciphertext an accepted evidence event committed to, unwraps its
//! per-object DEK under the deployment's key-encryption key, and hands the
//! plaintext back.
//!
//! # What it does NOT do
//!
//! It does not verify the returned bytes. That is deliberate and load-bearing:
//! [`super::projector::derive_parse_run`] re-hashes whatever a resolver returns
//! against `statement.canonical_content.content_digest` and fails closed on a
//! mismatch, so integrity is enforced at the one place that mints identities,
//! not separately in every resolver. A resolver that verified as well would
//! make that check look optional.
//!
//! It also selects nothing. The storage identity comes from the accepted
//! evidence event, and the scope comes from the binding this resolver was
//! constructed with, so no argument can steer a read at another tenant's
//! object: a storage identity from another scope simply finds no row and
//! becomes [`BodyProjectionError::MissingSourceContent`].

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::evidence_ledger::{ContentKeyEncryptionKey, fetch_governed_content};
use crate::memory_contracts::chunk_identity::StorageIdentityPreimageV1;
use crate::memory_contracts::common::AuthenticatedProjectScopeV1;
use crate::memory_contracts::evidence_v2::EvidenceStatementV2;

use super::error::{BodyProjectionError, BodyProjectionResult};
use super::repository::SourceContentResolver;

/// Reads governed content objects for one physical and semantic scope.
pub struct GovernedContentResolver {
    pool: PgPool,
    tenant_id: Uuid,
    project: String,
    scope: AuthenticatedProjectScopeV1,
    kek: ContentKeyEncryptionKey,
}

impl std::fmt::Debug for GovernedContentResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GovernedContentResolver")
            .field("tenant_id", &self.tenant_id)
            .field("project", &self.project)
            .finish_non_exhaustive()
    }
}

impl GovernedContentResolver {
    /// Bind one pool, one physical scope, one semantic scope, and the KEK.
    #[must_use]
    pub const fn new(
        pool: PgPool,
        tenant_id: Uuid,
        project: String,
        scope: AuthenticatedProjectScopeV1,
        kek: ContentKeyEncryptionKey,
    ) -> Self {
        Self {
            pool,
            tenant_id,
            project,
            scope,
            kek,
        }
    }
}

#[async_trait]
impl SourceContentResolver for GovernedContentResolver {
    async fn resolve(&self, statement: &EvidenceStatementV2) -> BodyProjectionResult<Vec<u8>> {
        // The storage identity is DERIVED from the accepted statement's own
        // protection domain and content digest, exactly as the writer derived
        // it. Nothing about which object is read comes from a caller.
        let storage_identity = StorageIdentityPreimageV1 {
            schema_version: 1,
            protection_domain_id: statement.canonical_content.protection_domain_id.clone(),
            body_content_id: statement.canonical_content.content_digest,
        }
        .storage_identity()?
        .digest();

        let sealed = fetch_governed_content(
            &self.pool,
            self.tenant_id,
            &self.project,
            &self.scope,
            storage_identity,
        )
        .await
        .map_err(|error| BodyProjectionError::Storage(error.into()))?
        // No row for this storage identity in this scope: the content plane has
        // not caught up (or the object belongs to another scope). Either way the
        // projector must leave its cursor unadvanced rather than invent bytes.
        .ok_or(BodyProjectionError::MissingSourceContent)?;

        sealed
            .open(&self.kek)
            .map_err(|error| BodyProjectionError::Storage(error.into()))
    }
}
