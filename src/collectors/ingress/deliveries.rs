//! The hint queue's keys and the receiver's statements (ADR 0008 D12,
//! migration 0036).
//!
//! * **Dedupe.** A delivery's key is
//!   `D(IngressDeliveryKeyV1; provider, instance, signed id)`: a Slack
//!   `event_id`, the SHA-256 of a Linear body (Linear's `Linear-Delivery`
//!   header is not signed, so it is never trusted as identity), or a Standard
//!   Webhooks `webhook-id`. A replayed or retried delivery inserts nothing.
//! * **Rejections.** A refused request is a dead letter keyed by
//!   `sha256(instance, reason, minute)`, so a flood of unsigned requests
//!   writes at most one row per instance, reason, and minute. It keeps the
//!   digest of the refused body and a static diagnostic, never the body.
//!
//! Every statement binds `tenant_id = $1` and `project = $2` first. The
//! receiver only inserts; the worker settles hints
//! ([`crate::collectors::sink::CollectedItemSink::pending_hints`] and its
//! siblings).

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{FleetError, Result};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, framed_digest};
use crate::store::cockroach::{COLLECTOR_INGRESS_SCHEMA_VERSION, read_schema_version};

use super::super::cockroach::{MAX_DEAD_LETTER_DIAGNOSTIC_BYTES, bounded, framed_sha256};
use super::super::sink::DeadLetterReasonV1;
use super::{DeliveryMappingV1, VerifiedDeliveryV1};

/// Longest delivery id a row keeps; a longer signed id is kept as its digest.
pub const MAX_DELIVERY_ID_BYTES: usize = 64;

const INSUFFICIENT_PRIVILEGE_SQLSTATE: &str = "42501";
const UNDEFINED_TABLE_SQLSTATE: &str = "42P01";

/// The policy file that grants the receiver what it needs.
pub const INGRESS_GRANTS_POLICY: &str = "deploy/cockroach/ingress-receiver-role-grants.sql";

const INSERT_DELIVERY_SQL: &str = "INSERT INTO public.memory_ingress_deliveries_v1 (\
     tenant_id, project, collector_instance_id, delivery_key, provider, delivery_id, \
     raw_body_sha256, raw_body_bytes, event_kind, disposition, hint_kind, object_kind, \
     external_id, container_id, provider_event_at, state, attempts, next_attempt_at, \
     settled_at, last_error, received_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 0, \
     NULL, NULL, NULL, pg_catalog.statement_timestamp()) \
     ON CONFLICT (tenant_id, project, collector_instance_id, delivery_key) DO NOTHING";

const INSERT_REJECTION_SQL: &str = "INSERT INTO public.memory_collector_dead_letters_v1 (\
     tenant_id, project, dead_letter_id, collector_instance_id, collection_mode, provider, \
     reason, stage_id, delivery_id, payload_digest, diagnostic, created_at\
     ) VALUES ($1, $2, $3, $4, 'push', $5, $6, NULL, NULL, $7, $8, \
     pg_catalog.statement_timestamp()) \
     ON CONFLICT (tenant_id, project, dead_letter_id) DO NOTHING";

const COUNT_PENDING_HINTS_SQL: &str = "SELECT count(*)::INT8 \
     FROM public.memory_ingress_deliveries_v1 \
     WHERE tenant_id = $1 AND project = $2 AND state = 'pending' \
       AND ($3::STRING IS NULL OR provider = $3)";

/// What the receiver needs, probed in a transaction that is rolled back.
const RECEIVER_PROBES: [&str; 2] = [
    "INSERT INTO public.memory_ingress_deliveries_v1 \
     SELECT * FROM public.memory_ingress_deliveries_v1 WHERE false",
    "INSERT INTO public.memory_collector_dead_letters_v1 \
     SELECT * FROM public.memory_collector_dead_letters_v1 WHERE false",
];

/// The dedupe key of one delivery.
#[must_use]
pub fn delivery_key(provider: &str, instance: &str, signed_id: &[u8]) -> Sha256Digest {
    framed_digest(
        DigestDomain::IngressDeliveryKeyV1,
        &[provider.as_bytes(), instance.as_bytes(), signed_id],
    )
}

/// The key of a rejection's dead letter: one per instance, reason, and
/// minute of the receiver's clock.
#[must_use]
pub fn rejection_letter_id(
    instance: &str,
    reason: DeadLetterReasonV1,
    now: DateTime<Utc>,
) -> Sha256Digest {
    let minute = now.timestamp().div_euclid(60).to_be_bytes();
    framed_sha256(
        "ostk-ingress-rejection-v1",
        &[instance.as_bytes(), reason.as_str().as_bytes(), &minute],
    )
}

/// The delivery id a row keeps: the signed id, or its digest when longer
/// than a row holds.
#[must_use]
pub fn stored_delivery_id(signed_id: &[u8]) -> Vec<u8> {
    if !signed_id.is_empty() && signed_id.len() <= MAX_DELIVERY_ID_BYTES {
        signed_id.to_vec()
    } else {
        framed_sha256("ostk-ingress-delivery-id-v1", &[signed_id])
            .as_bytes()
            .to_vec()
    }
}

/// One verified delivery to record.
#[derive(Debug, Clone, Copy)]
pub struct DeliveryRecordV1<'a> {
    /// The collector instance it was addressed to.
    pub instance: &'a str,
    /// The instance's provider.
    pub provider: &'a str,
    /// What it maps to.
    pub delivery: &'a VerifiedDeliveryV1,
    /// The SHA-256 of the raw body.
    pub raw_body_sha256: &'a Sha256Digest,
    /// The raw body's length.
    pub raw_body_bytes: usize,
}

/// One refused request to record.
#[derive(Debug, Clone, Copy)]
pub struct RejectionRecordV1<'a> {
    /// The collector instance it was addressed to.
    pub instance: &'a str,
    /// The instance's provider.
    pub provider: &'a str,
    /// Why.
    pub reason: DeadLetterReasonV1,
    /// A digest of what was refused.
    pub payload_digest: &'a Sha256Digest,
    /// A static diagnostic.
    pub diagnostic: &'a str,
    /// The receiver's clock.
    pub now: DateTime<Utc>,
}

/// The receiver's statements, bound to one physical `(tenant_id, project)`.
#[derive(Clone)]
pub struct IngressStoreV1 {
    pool: PgPool,
    tenant_id: Uuid,
    project: String,
}

impl std::fmt::Debug for IngressStoreV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IngressStoreV1")
            .field("tenant_id", &self.tenant_id)
            .field("project", &self.project)
            .finish_non_exhaustive()
    }
}

impl IngressStoreV1 {
    /// Bind the statements to `(tenant_id, project)`.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] for a project that is empty, longer than
    /// 256 bytes, or holds a control character.
    pub fn new(pool: PgPool, tenant_id: Uuid, project: &str) -> Result<Self> {
        if project.is_empty() || project.len() > 256 || project.chars().any(char::is_control) {
            return Err(FleetError::Configuration(
                "the ingress project must be 1 to 256 bytes with no control character".to_owned(),
            ));
        }
        Ok(Self {
            pool,
            tenant_id,
            project: project.to_owned(),
        })
    }

    /// The pool.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Check, before the receiver listens, that the schema has the hint queue
    /// and the login may insert deliveries and dead letters. Nothing is
    /// written.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] for an older schema, or naming the table
    /// the login may not insert into and the policy that grants it; any other
    /// database failure as itself.
    pub async fn probe(&self) -> Result<()> {
        let schema = read_schema_version(&self.pool).await?;
        if schema < COLLECTOR_INGRESS_SCHEMA_VERSION {
            return Err(FleetError::Configuration(format!(
                "the ingress needs the schema through migration \
                 {COLLECTOR_INGRESS_SCHEMA_VERSION}, but this database has reached {schema}; run \
                 `ostk-fleet-recall migrate`"
            )));
        }
        let mut transaction = self.pool.begin().await?;
        let mut outcome = Ok(());
        for (statement, table) in RECEIVER_PROBES.iter().zip([
            "memory_ingress_deliveries_v1",
            "memory_collector_dead_letters_v1",
        ]) {
            match sqlx::query(statement).execute(&mut *transaction).await {
                Ok(_) => {}
                Err(sqlx::Error::Database(error))
                    if error.code().as_deref() == Some(INSUFFICIENT_PRIVILEGE_SQLSTATE) =>
                {
                    outcome = Err(FleetError::Configuration(format!(
                        "the ingress login lacks SELECT and INSERT on public.{table}; apply \
                         {INGRESS_GRANTS_POLICY} after `migrate`, then restart the ingress"
                    )));
                    break;
                }
                Err(error) => {
                    outcome = Err(error.into());
                    break;
                }
            }
        }
        transaction.rollback().await?;
        outcome
    }

    /// Record one verified delivery; `true` when it is new, `false` for a
    /// replay.
    ///
    /// # Errors
    ///
    /// A database failure: the receiver then answers 503 and the provider
    /// retries.
    pub async fn record_delivery(&self, record: &DeliveryRecordV1<'_>) -> Result<bool> {
        let delivery = record.delivery;
        let key = delivery_key(record.provider, record.instance, &delivery.signed_id);
        let (disposition, state, hint) = match &delivery.mapping {
            DeliveryMappingV1::Hint(hint) => ("hint", "pending", Some(hint)),
            DeliveryMappingV1::Ignored => ("ignored", "none", None),
            DeliveryMappingV1::Challenge(_) => ("challenge", "none", None),
        };
        let written = sqlx::query(INSERT_DELIVERY_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(record.instance)
            .bind(key.as_bytes().as_slice())
            .bind(record.provider)
            .bind(stored_delivery_id(&delivery.signed_id))
            .bind(record.raw_body_sha256.as_bytes().as_slice())
            .bind(i64::try_from(record.raw_body_bytes).unwrap_or(i64::MAX))
            .bind(&delivery.event_kind)
            .bind(disposition)
            .bind(hint.map(|hint| hint.kind.as_str()))
            .bind(hint.map(|hint| hint.object_kind.as_str()))
            .bind(hint.map(|hint| hint.external_id.as_str()))
            .bind(hint.and_then(|hint| hint.container_id.as_deref()))
            .bind(hint.map(|hint| hint.provider_event_at))
            .bind(state)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(written == 1)
    }

    /// Record one refused request as a digest-only dead letter; a second
    /// refusal of the same instance and reason in the same minute writes
    /// nothing.
    ///
    /// # Errors
    ///
    /// A database failure.
    pub async fn record_rejection(&self, rejection: &RejectionRecordV1<'_>) -> Result<()> {
        let id = rejection_letter_id(rejection.instance, rejection.reason, rejection.now);
        sqlx::query(INSERT_REJECTION_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(id.as_bytes().as_slice())
            .bind(rejection.instance)
            .bind(rejection.provider)
            .bind(rejection.reason.as_str())
            .bind(rejection.payload_digest.as_bytes().as_slice())
            .bind(bounded(
                rejection.diagnostic,
                MAX_DEAD_LETTER_DIAGNOSTIC_BYTES,
            ))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// Hints received and not yet settled in one scope, of one provider or of
/// every provider: `None` before migration 36, or when the login cannot read
/// the queue.
///
/// # Errors
///
/// Any other database failure.
pub async fn count_pending_hints(
    pool: &PgPool,
    tenant_id: Uuid,
    project: &str,
    provider: Option<&str>,
) -> Result<Option<u64>> {
    match sqlx::query_scalar::<_, i64>(COUNT_PENDING_HINTS_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(provider)
        .fetch_one(pool)
        .await
    {
        Ok(count) => Ok(Some(u64::try_from(count).map_err(|_| {
            FleetError::Memory("the pending hint count is negative".to_owned())
        })?)),
        Err(sqlx::Error::Database(error))
            if matches!(
                error.code().as_deref(),
                Some(INSUFFICIENT_PRIVILEGE_SQLSTATE | UNDEFINED_TABLE_SQLSTATE)
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    #[test]
    fn a_delivery_key_names_the_provider_the_instance_and_the_signed_id() {
        let key = delivery_key("slack", "slack.acme", b"Ev07CHG00001");
        assert_eq!(key, delivery_key("slack", "slack.acme", b"Ev07CHG00001"));
        assert_ne!(key, delivery_key("slack", "slack.other", b"Ev07CHG00001"));
        assert_ne!(key, delivery_key("linear", "slack.acme", b"Ev07CHG00001"));
        assert_ne!(key, delivery_key("slack", "slack.acme", b"Ev07CHG00002"));
    }

    #[test]
    fn a_rejection_is_one_row_per_instance_reason_and_minute() {
        let at = |seconds: i64| Utc.timestamp_opt(seconds, 0).unwrap();
        let first = rejection_letter_id(
            "slack.acme",
            DeadLetterReasonV1::InvalidSignature,
            at(1_790_008_200),
        );
        assert_eq!(
            first,
            rejection_letter_id(
                "slack.acme",
                DeadLetterReasonV1::InvalidSignature,
                at(1_790_008_259)
            )
        );
        for other in [
            rejection_letter_id(
                "slack.acme",
                DeadLetterReasonV1::InvalidSignature,
                at(1_790_008_260),
            ),
            rejection_letter_id(
                "slack.acme",
                DeadLetterReasonV1::StaleSignature,
                at(1_790_008_200),
            ),
            rejection_letter_id(
                "linear.acme",
                DeadLetterReasonV1::InvalidSignature,
                at(1_790_008_200),
            ),
        ] {
            assert_ne!(first, other);
        }
    }

    #[test]
    fn a_long_signed_id_is_kept_as_its_digest() {
        assert_eq!(stored_delivery_id(b"Ev07CHG00001"), b"Ev07CHG00001");
        let long = [b'x'; 65];
        assert_eq!(stored_delivery_id(&long).len(), 32);
        assert_eq!(stored_delivery_id(b"").len(), 32);
    }
}
