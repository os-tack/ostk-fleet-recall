//! Governed content objects: envelope encryption and the `memory_content_objects`
//! write seam (ADR 0002 D5, EVID-01/EVID-08).
//!
//! # Why the bytes are not in the event
//!
//! EVID-01 says canonical or raw governed payload bytes live *behind typed
//! content references* unless their retention class explicitly permits
//! immutable inline retention. [`EvidenceStatementV2`] therefore carries only a
//! [`GovernedContentIdentityV1`] — protection domain, media type, byte length,
//! and content digest — and the bytes themselves are stored here, in a
//! separately addressable, envelope-encrypted row keyed by
//! `(tenant_id, project, storage_identity)`.
//!
//! [`EvidenceStatementV2`]: crate::memory_contracts::evidence_v2::EvidenceStatementV2
//!
//! # Envelope shape
//!
//! Every object gets its OWN 32-byte data-encryption key. That DEK is wrapped
//! under the deployment's key-encryption key ([`ContentKeyEncryptionKey`],
//! `FLEET_RECALL_CONTENT_KEK_HEX`), and the body is sealed under the DEK. Both
//! AEAD operations are AES-256-GCM (`ring`, already pinned) and both use the
//! SAME associated data: the canonical bytes of
//! [`GovernedContentAssociatedDataV1`], which commits to the semantic scope,
//! the storage identity, the content digest, the byte length, the protection
//! domain, the media type, and the retention class/policy. A ciphertext
//! therefore cannot be moved to another row, another scope, another protection
//! domain, or another retention class: the open fails.
//!
//! A per-object DEK is what makes artifact-scoped cryptographic erasure
//! possible at all (EVID-08: *"Each archived artifact has a unique
//! data-encryption key wrapped inside its protection domain; one shared bucket
//! key is not sufficient"*). Destroying one `wrapped_dek` destroys exactly one
//! object.
//!
//! # Idempotence, and what a conflict means
//!
//! The insert is `ON CONFLICT DO NOTHING`. A conflict is expected and lawful:
//! two representations of the same source fact can reference the same governed
//! bytes, and a retried delivery reaches the same storage identity. When the
//! row already exists, every *governed* column is compared field by field and a
//! divergence fails the whole append closed with
//! [`EvidenceAppendError::LedgerIntegrity`]. The ciphertext columns are
//! deliberately NOT compared: each seal draws fresh nonces, so equal plaintext
//! yields different bytes, and comparing them would turn a correct retry into a
//! false integrity alarm.
//!
//! # Why the four erasure-index columns stay NULL here
//!
//! A storage identity is `f(protection domain, content digest)`
//! ([`StorageIdentityPreimageV1`]), so it deduplicates: two representations of
//! one source fact, and two different source facts that happen to carry
//! identical redacted bytes, all land on ONE row. Every `ErasureScopeKind` axis
//! — representation, source fact, resource, privacy subject — is therefore
//! many-to-one onto that row. Writing one representation's key into the row
//! would make an erasure of that representation destroy bytes another
//! representation still lawfully references, which is precisely the
//! reference-count hazard [`BodyReferenceStateV1`] already records as a model
//! gap.
//!
//! So this stage writes NULL into all four columns and says so, rather than
//! writing a key it cannot justify. The representation-to-content binding is
//! not lost: the accepted event carries both the `canonical_content` identity
//! and its own `erasure_scopes`, and the ledger is the authority. Populating
//! the columns needs the reference-counted mapping W0-ERASE owns, together with
//! the tombstone/fence/generation machinery ADR 0002 D5 explicitly defers.
//!
//! [`StorageIdentityPreimageV1`]: crate::memory_contracts::chunk_identity::StorageIdentityPreimageV1
//! [`BodyReferenceStateV1`]: crate::memory_contracts::chunk_identity::BodyReferenceStateV1

use std::fmt;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::{Executor, Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::FleetError;
use crate::control_log::TrustedControlScope;
use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, ContractId, RegistryReferenceV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::{GovernedContentIdentityV1, RetentionClass};

use super::error::{EvidenceAppendError, EvidenceAppendResult, integrity};
use super::repository::{AppendProjection, ProjectionContext};

/// Environment variable holding the hex-encoded 32-byte content KEK.
pub const CONTENT_KEY_ENCRYPTION_KEY_ENV: &str = "FLEET_RECALL_CONTENT_KEK_HEX";

/// Largest plaintext this store admits.
///
/// Migration 0018 bounds `encrypted_bytes` at 1 MiB, and AES-256-GCM adds a
/// 12-byte nonce plus a 16-byte tag, so the plaintext bound is 1 MiB minus 28.
/// Enforcing it in Rust means an oversized payload is a typed rejection before
/// any statement is built, not a `CHECK` violation mid-transaction.
pub const MAX_GOVERNED_CONTENT_BYTES: u64 = 1_048_576 - (NONCE_LEN as u64) - 16;

const AEAD_TAG_LEN: usize = 16;
const DEK_LEN: usize = 32;
const KEK_LEN: usize = 32;
const WRAPPED_DEK_LEN: usize = NONCE_LEN + DEK_LEN + AEAD_TAG_LEN;
const ASSOCIATED_DATA_SCHEMA_VERSION: u32 = 1;

const INSERT_CONTENT_OBJECT_SQL: &str = "INSERT INTO public.memory_content_objects (\
     tenant_id, project, storage_identity, protection_domain_id, media_type, byte_length, \
     content_digest, retention_class, retention_policy_entry_id, \
     retention_policy_entry_version, retention_policy_digest, wrapped_dek, encrypted_bytes, \
     erasure_representation_digest, erasure_source_fact_digest, erasure_resource_digest, \
     erasure_privacy_subject_digest, created_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) \
     ON CONFLICT (tenant_id, project, storage_identity) DO NOTHING";

const SELECT_CONTENT_OBJECT_SQL: &str = "SELECT protection_domain_id, media_type, byte_length, \
     content_digest, retention_class, retention_policy_entry_id, \
     retention_policy_entry_version, retention_policy_digest, wrapped_dek, encrypted_bytes \
     FROM public.memory_content_objects \
     WHERE tenant_id = $1 AND project = $2 AND storage_identity = $3";

/// The deployment key-encryption key that wraps every per-object DEK.
///
/// Deliberately not `Clone`-into-bytes and deliberately opaque in `Debug`: the
/// only things a holder can do with it are wrap and unwrap a DEK.
pub struct ContentKeyEncryptionKey {
    key: [u8; KEK_LEN],
}

impl fmt::Debug for ContentKeyEncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContentKeyEncryptionKey")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Drop for ContentKeyEncryptionKey {
    fn drop(&mut self) {
        // Best-effort hygiene. `write_volatile` is not available without
        // `unsafe`, which this crate forbids, so this is a plain overwrite the
        // optimizer is permitted to elide; it is not a security boundary.
        self.key.fill(0);
    }
}

impl ContentKeyEncryptionKey {
    /// Parse exactly 64 lowercase hex characters into a 32-byte KEK.
    ///
    /// Uppercase and short/long inputs are refused rather than normalized: a
    /// deployment that mis-set the variable must fail closed at startup, not
    /// silently encrypt under a key nobody meant to use.
    pub fn from_hex(value: &str) -> Result<Self, FleetError> {
        let trimmed = value.trim();
        if trimmed.len() != KEK_LEN * 2 || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(FleetError::Configuration(format!(
                "{CONTENT_KEY_ENCRYPTION_KEY_ENV} must be exactly {} hex characters",
                KEK_LEN * 2
            )));
        }
        if trimmed.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(FleetError::Configuration(format!(
                "{CONTENT_KEY_ENCRYPTION_KEY_ENV} must be lowercase hex"
            )));
        }
        let mut key = [0_u8; KEK_LEN];
        hex::decode_to_slice(trimmed, &mut key).map_err(|_| {
            FleetError::Configuration(format!(
                "{CONTENT_KEY_ENCRYPTION_KEY_ENV} is not valid hexadecimal"
            ))
        })?;
        if key == [0_u8; KEK_LEN] {
            return Err(FleetError::Configuration(format!(
                "{CONTENT_KEY_ENCRYPTION_KEY_ENV} must not be the all-zero key"
            )));
        }
        Ok(Self { key })
    }

    /// Construct from raw key material already held in memory.
    ///
    /// Test-only on purpose: production key material arrives through
    /// [`Self::from_hex`] from configuration, so there is no in-process path
    /// that mints a KEK from a literal.
    #[cfg(test)]
    pub(crate) const fn from_bytes(key: [u8; KEK_LEN]) -> Self {
        Self { key }
    }

    fn aead(&self) -> EvidenceAppendResult<LessSafeKey> {
        UnboundKey::new(&AES_256_GCM, &self.key)
            .map(LessSafeKey::new)
            .map_err(|_| integrity("content key-encryption key is not a valid AES-256 key"))
    }
}

/// Exact associated data both AEAD operations bind.
///
/// Every field here is server-derived by admission. Binding them means a
/// ciphertext is only openable in the row, scope, protection domain, and
/// retention class it was sealed for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedContentAssociatedDataV1 {
    pub schema_version: u32,
    pub scope: AuthenticatedProjectScopeV1,
    pub storage_identity: Sha256Digest,
    pub content: GovernedContentIdentityV1,
    pub retention_class: RetentionClass,
    pub retention_policy: RegistryReferenceV1,
}

/// One governed payload with its server-derived identity and its plaintext.
///
/// Constructed only by evidence admission, which is what proves the plaintext
/// actually hashes to `content.content_digest` and that `storage_identity` was
/// derived rather than asserted.
#[derive(Clone, PartialEq, Eq)]
pub struct GovernedContentObjectV1 {
    scope: AuthenticatedProjectScopeV1,
    content: GovernedContentIdentityV1,
    storage_identity: Sha256Digest,
    retention_class: RetentionClass,
    retention_policy: RegistryReferenceV1,
    plaintext: Vec<u8>,
}

impl fmt::Debug for GovernedContentObjectV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedContentObjectV1")
            .field("scope", &self.scope)
            .field("content", &self.content)
            .field("storage_identity", &self.storage_identity)
            .field("retention_class", &self.retention_class)
            .field("retention_policy", &self.retention_policy)
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

impl GovernedContentObjectV1 {
    pub(super) const fn from_admitted(
        scope: AuthenticatedProjectScopeV1,
        content: GovernedContentIdentityV1,
        storage_identity: Sha256Digest,
        retention_class: RetentionClass,
        retention_policy: RegistryReferenceV1,
        plaintext: Vec<u8>,
    ) -> Self {
        Self {
            scope,
            content,
            storage_identity,
            retention_class,
            retention_policy,
            plaintext,
        }
    }

    #[must_use]
    pub const fn content(&self) -> &GovernedContentIdentityV1 {
        &self.content
    }

    #[must_use]
    pub const fn storage_identity(&self) -> Sha256Digest {
        self.storage_identity
    }

    #[must_use]
    pub const fn scope(&self) -> &AuthenticatedProjectScopeV1 {
        &self.scope
    }

    fn associated_data(&self) -> GovernedContentAssociatedDataV1 {
        GovernedContentAssociatedDataV1 {
            schema_version: ASSOCIATED_DATA_SCHEMA_VERSION,
            scope: self.scope.clone(),
            storage_identity: self.storage_identity,
            content: self.content.clone(),
            retention_class: self.retention_class,
            retention_policy: self.retention_policy.clone(),
        }
    }

    /// Wrap a fresh per-object DEK under `kek` and seal the body under it.
    pub fn seal(&self, kek: &ContentKeyEncryptionKey) -> EvidenceAppendResult<SealedContentObject> {
        let associated = encode_canonical(&self.associated_data())?;
        let random = SystemRandom::new();

        let mut dek = [0_u8; DEK_LEN];
        random
            .fill(&mut dek)
            .map_err(|_| integrity("system randomness is unavailable for a content DEK"))?;

        let mut wrapped_dek = random_nonce(&random)?;
        wrapped_dek.extend_from_slice(&dek);
        seal_in_place(&kek.aead()?, &associated, &mut wrapped_dek)?;

        let body_key = UnboundKey::new(&AES_256_GCM, &dek)
            .map(LessSafeKey::new)
            .map_err(|_| integrity("derived content DEK is not a valid AES-256 key"))?;
        dek.fill(0);

        let mut encrypted_bytes = random_nonce(&random)?;
        encrypted_bytes.extend_from_slice(&self.plaintext);
        seal_in_place(&body_key, &associated, &mut encrypted_bytes)?;

        Ok(SealedContentObject {
            scope: self.scope.clone(),
            content: self.content.clone(),
            storage_identity: self.storage_identity,
            retention_class: self.retention_class,
            retention_policy: self.retention_policy.clone(),
            wrapped_dek,
            encrypted_bytes,
        })
    }
}

/// One governed content object as it is stored: identity in the clear, bytes
/// under the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedContentObject {
    scope: AuthenticatedProjectScopeV1,
    content: GovernedContentIdentityV1,
    storage_identity: Sha256Digest,
    retention_class: RetentionClass,
    retention_policy: RegistryReferenceV1,
    wrapped_dek: Vec<u8>,
    encrypted_bytes: Vec<u8>,
}

impl SealedContentObject {
    #[must_use]
    pub const fn content(&self) -> &GovernedContentIdentityV1 {
        &self.content
    }

    #[must_use]
    pub const fn storage_identity(&self) -> Sha256Digest {
        self.storage_identity
    }

    fn associated_data(&self) -> GovernedContentAssociatedDataV1 {
        GovernedContentAssociatedDataV1 {
            schema_version: ASSOCIATED_DATA_SCHEMA_VERSION,
            scope: self.scope.clone(),
            storage_identity: self.storage_identity,
            content: self.content.clone(),
            retention_class: self.retention_class,
            retention_policy: self.retention_policy.clone(),
        }
    }

    /// Unwrap the DEK and open the body, then re-verify the declared digest and
    /// length against the recovered plaintext.
    ///
    /// The re-verification is the point: a stored row whose ciphertext opens to
    /// bytes that do not hash to its own `content_digest` is an integrity
    /// collision, not a decryption success (EVID-01).
    pub fn open(&self, kek: &ContentKeyEncryptionKey) -> EvidenceAppendResult<Vec<u8>> {
        if self.wrapped_dek.len() != WRAPPED_DEK_LEN {
            return Err(integrity("stored wrapped DEK has the wrong length"));
        }
        let associated = encode_canonical(&self.associated_data())?;
        let mut wrapped = self.wrapped_dek.clone();
        let dek = open_in_place(&kek.aead()?, &associated, &mut wrapped)?;
        let dek: [u8; DEK_LEN] = dek
            .try_into()
            .map_err(|_| integrity("stored wrapped DEK did not unwrap to 32 bytes"))?;
        let body_key = UnboundKey::new(&AES_256_GCM, &dek)
            .map(LessSafeKey::new)
            .map_err(|_| integrity("unwrapped content DEK is not a valid AES-256 key"))?;

        let mut sealed = self.encrypted_bytes.clone();
        let plaintext = open_in_place(&body_key, &associated, &mut sealed)?;
        let declared_length = parse_byte_length(&self.content)?;
        if u64::try_from(plaintext.len()).unwrap_or(u64::MAX) != declared_length
            || Sha256Digest::from_bytes(Sha256::digest(&plaintext).into())
                != self.content.content_digest
        {
            return Err(integrity(
                "stored governed content does not reproduce its declared digest or length",
            ));
        }
        Ok(plaintext)
    }
}

/// What one `memory_content_objects` write did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentObjectWrite {
    /// A new row was inserted in this transaction.
    Inserted,
    /// The exact governed object was already stored; every governed column
    /// matched. No second row was written (EVID-01).
    AlreadyStored,
}

/// Store one governed content object inside an existing transaction.
///
/// This is the only write path. It is called from an [`AppendProjection`], so
/// the row commits in the SAME serializable transaction as its accepted event
/// (EVENT-03) and a rolled-back append leaves no content row.
pub async fn store_governed_content(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    project: &str,
    sealed: &SealedContentObject,
    now: DateTime<Utc>,
) -> EvidenceAppendResult<ContentObjectWrite> {
    let byte_length = i64::try_from(parse_byte_length(&sealed.content)?)
        .map_err(|_| integrity("governed content length exceeds INT8"))?;
    let affected = sqlx::query(INSERT_CONTENT_OBJECT_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(sealed.storage_identity.as_bytes().to_vec())
        .bind(sealed.content.protection_domain_id.as_str())
        .bind(sealed.content.media_type.as_str())
        .bind(byte_length)
        .bind(sealed.content.content_digest.as_bytes().to_vec())
        .bind(retention_class_label(sealed.retention_class))
        .bind(sealed.retention_policy.entry_id.as_str())
        .bind(
            i32::try_from(sealed.retention_policy.version)
                .map_err(|_| integrity("governed content retention policy version exceeds INT4"))?,
        )
        .bind(sealed.retention_policy.entry_digest.as_bytes().to_vec())
        .bind(sealed.wrapped_dek.clone())
        .bind(sealed.encrypted_bytes.clone())
        // The four erasure axes stay NULL: see the module documentation. A
        // deduplicated content row has no single representation, source fact,
        // resource, or privacy subject to name.
        .bind(Option::<Vec<u8>>::None)
        .bind(Option::<Vec<u8>>::None)
        .bind(Option::<Vec<u8>>::None)
        .bind(Option::<Vec<u8>>::None)
        .bind(now)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
    if affected > 1 {
        return Err(integrity(
            "content object insert affected more than one row",
        ));
    }
    if affected == 1 {
        return Ok(ContentObjectWrite::Inserted);
    }
    require_stored_object_matches(transaction, tenant_id, project, sealed).await?;
    Ok(ContentObjectWrite::AlreadyStored)
}

/// Read one stored governed content object back.
///
/// Exposed so a proof can demonstrate the decrypt round-trip and so a later
/// retrieval path has exactly one reader.
pub async fn fetch_governed_content<'executor, E>(
    executor: E,
    tenant_id: Uuid,
    project: &str,
    scope: &AuthenticatedProjectScopeV1,
    storage_identity: Sha256Digest,
) -> EvidenceAppendResult<Option<SealedContentObject>>
where
    E: Executor<'executor, Database = Postgres>,
{
    let Some(row) = sqlx::query(SELECT_CONTENT_OBJECT_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(storage_identity.as_bytes().to_vec())
        .fetch_optional(executor)
        .await?
    else {
        return Ok(None);
    };
    let stored = decode_stored_columns(&row)?;
    Ok(Some(SealedContentObject {
        scope: scope.clone(),
        content: stored.content,
        storage_identity,
        retention_class: stored.retention_class,
        retention_policy: stored.retention_policy,
        wrapped_dek: stored.wrapped_dek,
        encrypted_bytes: stored.encrypted_bytes,
    }))
}

/// The [`AppendProjection`] that commits one governed content object with its
/// accepted event.
///
/// The object is sealed ONCE, at construction. `with_serializable_retry` may
/// call `project` again after a rolled-back attempt, and re-sealing there would
/// draw new nonces on every retry; sealing once keeps the projection idempotent
/// within one logical append, which is exactly what [`AppendProjection`]
/// requires.
#[derive(Debug)]
pub struct GovernedContentProjection {
    tenant_id: Uuid,
    project: String,
    sealed: SealedContentObject,
}

impl GovernedContentProjection {
    /// Seal `object` under `kek` and bind it to the repository's physical scope.
    ///
    /// The semantic scope carried by the object must be the repository's own;
    /// a mismatch is a scope-crossing attempt and fails closed (EVID-04).
    pub fn new(
        scope: &TrustedControlScope,
        object: &GovernedContentObjectV1,
        kek: &ContentKeyEncryptionKey,
    ) -> EvidenceAppendResult<Self> {
        if object.scope() != scope.semantic_scope() {
            return Err(integrity(
                "governed content object is not scoped to this repository",
            ));
        }
        Ok(Self {
            tenant_id: scope.tenant_id(),
            project: scope.project().to_owned(),
            sealed: object.seal(kek)?,
        })
    }

    /// The sealed object this projection will write.
    #[must_use]
    pub const fn sealed(&self) -> &SealedContentObject {
        &self.sealed
    }
}

#[async_trait]
impl AppendProjection for GovernedContentProjection {
    async fn project(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        _context: ProjectionContext,
    ) -> EvidenceAppendResult<()> {
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
            .fetch_one(&mut **transaction)
            .await?;
        store_governed_content(
            transaction,
            self.tenant_id,
            &self.project,
            &self.sealed,
            now,
        )
        .await?;
        Ok(())
    }
}

struct StoredColumns {
    content: GovernedContentIdentityV1,
    retention_class: RetentionClass,
    retention_policy: RegistryReferenceV1,
    wrapped_dek: Vec<u8>,
    encrypted_bytes: Vec<u8>,
}

fn decode_stored_columns(row: &sqlx::postgres::PgRow) -> EvidenceAppendResult<StoredColumns> {
    let byte_length: i64 = row.try_get("byte_length")?;
    let content = GovernedContentIdentityV1 {
        protection_domain_id: contract_id(row.try_get("protection_domain_id")?)?,
        media_type: contract_id(row.try_get("media_type")?)?,
        byte_length: crate::memory_contracts::common::CanonicalDecimal::parse(
            byte_length.to_string(),
        )?,
        content_digest: stored_digest(row.try_get("content_digest")?)?,
    };
    let retention_class_label: String = row.try_get("retention_class")?;
    let retention_class = match retention_class_label.as_str() {
        "ephemeral" => RetentionClass::Ephemeral,
        "governed" => RetentionClass::Governed,
        "immutable" => RetentionClass::Immutable,
        other => {
            return Err(integrity(format!(
                "stored content object has unknown retention class {other}"
            )));
        }
    };
    let policy_version: i32 = row.try_get("retention_policy_entry_version")?;
    let retention_policy = RegistryReferenceV1 {
        entry_id: contract_id(row.try_get("retention_policy_entry_id")?)?,
        version: u32::try_from(policy_version)
            .map_err(|_| integrity("stored retention policy version is negative"))?,
        entry_digest: stored_digest(row.try_get("retention_policy_digest")?)?,
    };
    Ok(StoredColumns {
        content,
        retention_class,
        retention_policy,
        wrapped_dek: row.try_get("wrapped_dek")?,
        encrypted_bytes: row.try_get("encrypted_bytes")?,
    })
}

async fn require_stored_object_matches(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    project: &str,
    sealed: &SealedContentObject,
) -> EvidenceAppendResult<()> {
    let row = sqlx::query(SELECT_CONTENT_OBJECT_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(sealed.storage_identity.as_bytes().to_vec())
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| {
            integrity("content object insert conflicted yet no stored row is visible")
        })?;
    let stored = decode_stored_columns(&row)?;
    // Ciphertext columns are deliberately excluded: fresh nonces make equal
    // plaintext produce different bytes. Everything compared here IS a function
    // of the storage identity or of the activated retention policy, so a
    // divergence is a stored-row tamper or an undeclared policy migration, not
    // a lawful second reference to the same bytes.
    if stored.content != sealed.content
        || stored.retention_class != sealed.retention_class
        || stored.retention_policy != sealed.retention_policy
    {
        return Err(integrity(
            "stored governed content object diverges from the admitted object under one storage identity",
        ));
    }
    Ok(())
}

fn random_nonce(random: &SystemRandom) -> EvidenceAppendResult<Vec<u8>> {
    let mut nonce = vec![0_u8; NONCE_LEN];
    random
        .fill(&mut nonce)
        .map_err(|_| integrity("system randomness is unavailable for a content nonce"))?;
    Ok(nonce)
}

/// Seal `buffer[NONCE_LEN..]` in place, appending the tag.
fn seal_in_place(
    key: &LessSafeKey,
    associated: &[u8],
    buffer: &mut Vec<u8>,
) -> EvidenceAppendResult<()> {
    let nonce = nonce_from(&buffer[..NONCE_LEN])?;
    let mut body = buffer.split_off(NONCE_LEN);
    key.seal_in_place_append_tag(nonce, Aad::from(associated), &mut body)
        .map_err(|_| integrity("governed content could not be sealed"))?;
    buffer.append(&mut body);
    Ok(())
}

/// Open `buffer[NONCE_LEN..]` in place and return the plaintext.
fn open_in_place(
    key: &LessSafeKey,
    associated: &[u8],
    buffer: &mut Vec<u8>,
) -> EvidenceAppendResult<Vec<u8>> {
    if buffer.len() < NONCE_LEN + AEAD_TAG_LEN {
        return Err(integrity("sealed governed content is truncated"));
    }
    let nonce = nonce_from(&buffer[..NONCE_LEN])?;
    let mut body = buffer.split_off(NONCE_LEN);
    let plaintext = key
        .open_in_place(nonce, Aad::from(associated), &mut body)
        .map_err(|_| {
            integrity("governed content did not open under this key and associated data")
        })?;
    Ok(plaintext.to_vec())
}

fn nonce_from(bytes: &[u8]) -> EvidenceAppendResult<Nonce> {
    let raw: [u8; NONCE_LEN] = bytes
        .try_into()
        .map_err(|_| integrity("governed content nonce is not 12 bytes"))?;
    Ok(Nonce::assume_unique_for_key(raw))
}

fn parse_byte_length(content: &GovernedContentIdentityV1) -> EvidenceAppendResult<u64> {
    content.validate()?;
    content
        .byte_length
        .as_str()
        .parse::<u64>()
        .map_err(|_| integrity("governed content length is not a positive integer"))
}

const fn retention_class_label(class: RetentionClass) -> &'static str {
    match class {
        RetentionClass::Ephemeral => "ephemeral",
        RetentionClass::Governed => "governed",
        RetentionClass::Immutable => "immutable",
    }
}

fn contract_id(value: String) -> EvidenceAppendResult<ContractId> {
    ContractId::new(value).map_err(EvidenceAppendError::Contract)
}

fn stored_digest(value: Vec<u8>) -> EvidenceAppendResult<Sha256Digest> {
    let raw: [u8; 32] = value
        .try_into()
        .map_err(|_| integrity("stored content digest column is not 32 bytes"))?;
    Ok(Sha256Digest::from_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_contracts::common::CanonicalDecimal;

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.fixture").unwrap(),
            ContractId::new("project.fixture").unwrap(),
        )
    }

    fn object(plaintext: &[u8]) -> GovernedContentObjectV1 {
        let content_digest = Sha256Digest::from_bytes(Sha256::digest(plaintext).into());
        GovernedContentObjectV1::from_admitted(
            scope(),
            GovernedContentIdentityV1 {
                protection_domain_id: ContractId::new("project.fixture").unwrap(),
                media_type: ContractId::new("application.json").unwrap(),
                byte_length: CanonicalDecimal::parse(plaintext.len().to_string()).unwrap(),
                content_digest,
            },
            Sha256Digest::from_bytes([7; 32]),
            RetentionClass::Governed,
            RegistryReferenceV1 {
                entry_id: ContractId::new("retention.default").unwrap(),
                version: 3,
                entry_digest: Sha256Digest::from_bytes([9; 32]),
            },
            plaintext.to_vec(),
        )
    }

    fn kek(byte: u8) -> ContentKeyEncryptionKey {
        ContentKeyEncryptionKey::from_bytes([byte; 32])
    }

    #[test]
    fn sealing_round_trips_under_the_same_key() {
        let plaintext = br#"{"push":"abc"}"#;
        let sealed = object(plaintext).seal(&kek(1)).unwrap();
        assert_eq!(sealed.wrapped_dek.len(), WRAPPED_DEK_LEN);
        assert_eq!(
            sealed.encrypted_bytes.len(),
            NONCE_LEN + plaintext.len() + AEAD_TAG_LEN
        );
        assert_eq!(sealed.open(&kek(1)).unwrap(), plaintext);
    }

    #[test]
    fn a_different_kek_cannot_open_the_object() {
        let sealed = object(b"payload").seal(&kek(1)).unwrap();
        assert!(matches!(
            sealed.open(&kek(2)),
            Err(EvidenceAppendError::LedgerIntegrity(_))
        ));
    }

    #[test]
    fn ciphertext_is_bound_to_the_storage_identity() {
        let mut sealed = object(b"payload").seal(&kek(1)).unwrap();
        sealed.storage_identity = Sha256Digest::from_bytes([8; 32]);
        assert!(matches!(
            sealed.open(&kek(1)),
            Err(EvidenceAppendError::LedgerIntegrity(_))
        ));
    }

    #[test]
    fn ciphertext_is_bound_to_the_semantic_scope() {
        let mut sealed = object(b"payload").seal(&kek(1)).unwrap();
        sealed.scope = AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.other").unwrap(),
            ContractId::new("project.fixture").unwrap(),
        );
        assert!(matches!(
            sealed.open(&kek(1)),
            Err(EvidenceAppendError::LedgerIntegrity(_))
        ));
    }

    #[test]
    fn ciphertext_is_bound_to_the_retention_class() {
        let mut sealed = object(b"payload").seal(&kek(1)).unwrap();
        sealed.retention_class = RetentionClass::Immutable;
        assert!(matches!(
            sealed.open(&kek(1)),
            Err(EvidenceAppendError::LedgerIntegrity(_))
        ));
    }

    #[test]
    fn two_seals_of_one_object_differ_yet_both_open() {
        let object = object(b"payload");
        let first = object.seal(&kek(1)).unwrap();
        let second = object.seal(&kek(1)).unwrap();
        assert_ne!(first.encrypted_bytes, second.encrypted_bytes);
        assert_ne!(first.wrapped_dek, second.wrapped_dek);
        assert_eq!(first.open(&kek(1)).unwrap(), second.open(&kek(1)).unwrap());
    }

    #[test]
    fn a_truncated_envelope_fails_closed() {
        let mut sealed = object(b"payload").seal(&kek(1)).unwrap();
        sealed.encrypted_bytes.truncate(NONCE_LEN + 1);
        assert!(matches!(
            sealed.open(&kek(1)),
            Err(EvidenceAppendError::LedgerIntegrity(_))
        ));
        let mut sealed = object(b"payload").seal(&kek(1)).unwrap();
        sealed.wrapped_dek.pop();
        assert!(matches!(
            sealed.open(&kek(1)),
            Err(EvidenceAppendError::LedgerIntegrity(_))
        ));
    }

    #[test]
    fn a_stored_object_whose_plaintext_lies_about_its_digest_is_an_integrity_failure() {
        let mut object = object(b"payload");
        object.content.content_digest = Sha256Digest::from_bytes([0xAB; 32]);
        let sealed = object.seal(&kek(1)).unwrap();
        assert!(matches!(
            sealed.open(&kek(1)),
            Err(EvidenceAppendError::LedgerIntegrity(_))
        ));
    }

    #[test]
    fn kek_hex_parsing_is_exact() {
        let valid = "0".repeat(63) + "1";
        assert!(ContentKeyEncryptionKey::from_hex(&valid).is_ok());
        assert!(ContentKeyEncryptionKey::from_hex(&"0".repeat(64)).is_err());
        assert!(ContentKeyEncryptionKey::from_hex(&"a".repeat(63)).is_err());
        assert!(ContentKeyEncryptionKey::from_hex(&"a".repeat(65)).is_err());
        assert!(ContentKeyEncryptionKey::from_hex(&"A".repeat(64)).is_err());
        assert!(ContentKeyEncryptionKey::from_hex(&"z".repeat(64)).is_err());
    }

    #[test]
    fn the_plaintext_bound_matches_the_migration_ciphertext_bound() {
        assert_eq!(MAX_GOVERNED_CONTENT_BYTES, 1_048_548);
        assert_eq!(
            MAX_GOVERNED_CONTENT_BYTES + (NONCE_LEN as u64) + 16,
            1_048_576
        );
    }

    #[test]
    fn a_content_object_from_another_scope_cannot_be_projected() {
        let deployment = crate::FleetScope::new(
            uuid::Uuid::now_v7(),
            "physical-project",
            "content-store-test",
            None,
            ostk_recall_core::PrivacyTier::T1Project,
        )
        .unwrap();
        let bound = TrustedControlScope::from_trusted_context(&deployment, scope()).unwrap();
        GovernedContentProjection::new(&bound, &object(b"payload"), &kek(1)).unwrap();

        let foreign = TrustedControlScope::from_trusted_context(
            &deployment,
            AuthenticatedProjectScopeV1::from_trusted_context(
                ContractId::new("tenant.other").unwrap(),
                ContractId::new("project.other").unwrap(),
            ),
        )
        .unwrap();
        assert!(matches!(
            GovernedContentProjection::new(&foreign, &object(b"payload"), &kek(1)),
            Err(EvidenceAppendError::LedgerIntegrity(_))
        ));
    }

    #[test]
    fn the_key_and_the_object_redact_their_secrets() {
        assert!(format!("{:?}", kek(3)).contains("<redacted>"));
        assert!(!format!("{:?}", kek(3)).contains("0303"));
        let debug = format!("{:?}", object(b"secret-payload"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-payload"));
    }
}
