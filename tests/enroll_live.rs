//! Enrollment and grants run under separate least-privilege database roles.
mod common;
use chrono::Utc;
use common::runtime_role::RuntimeProbeRole;
use ostk_fleet_recall::auth::grant::{GrantError, GrantIssuer, GrantKind};
use ostk_fleet_recall::auth::jose::Ed25519Signer;
use ostk_fleet_recall::auth::registry::{
    Ceiling, DeclarationFile, PrincipalDeclaration, PrincipalRegistry, PrincipalRole, RegistryError,
};
use std::sync::Arc;
use uuid::Uuid;
static ENROLL_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn declaration(role: PrincipalRole) -> PrincipalDeclaration {
    let id = Uuid::now_v7();
    PrincipalDeclaration {
        principal_id: id,
        anchor_id: format!("test-{id}"),
        subject_pattern: "identity".into(),
        role,
        tenant_id: Uuid::now_v7(),
        project: "remote-test".into(),
        ceiling: Ceiling::Project,
        agent_pattern: "sandbox-*".into(),
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One complete enrollment/bootstrap/prune lifecycle.
async fn enrollment_is_idempotent_atomic_and_least_privileged() {
    let Some(url) = common::test_database_url() else {
        return;
    };
    let _guard = ENROLL_TEST_LOCK.lock().await;
    let owner = common::migrated_pool(&url).await;
    let enrollment = RuntimeProbeRole::create_enrollment(&owner, &url).await;
    let runtime = RuntimeProbeRole::create_remote_runtime(&owner, &url).await;
    let registry = PrincipalRegistry::new(enrollment.pool.clone());
    let first = declaration(PrincipalRole::Operator);
    let file = DeclarationFile {
        principals: vec![first.clone()],
    };
    let report =
        ostk_fleet_recall::enroll::apply(enrollment.pool.clone(), &file, false, Some("live-test"))
            .await
            .unwrap();
    assert_eq!(report.apply.changed, 1);
    assert_eq!(report.bootstrapped_scopes, 1);
    let active: String = sqlx::query_scalar(
        "SELECT embedding_model FROM public.memory_corpus_models WHERE tenant_id=$1 AND project=$2",
    )
    .bind(first.tenant_id)
    .bind(&first.project)
    .fetch_one(&enrollment.pool)
    .await
    .unwrap();
    assert_eq!(active, "live-test");
    assert_eq!(registry.apply(&file, false).await.unwrap().unchanged, 1);
    assert_eq!(registry.get(first.principal_id).await.unwrap().revision, 1);
    assert!(
        matches!(PrincipalRegistry::new(runtime.pool.clone()).apply(&file,false).await,Err(RegistryError::Database(ref e)) if e.as_database_error().and_then(sqlx::error::DatabaseError::code).as_deref()==Some("42501"))
    );
    let denied = sqlx::query("SELECT claim_id FROM public.memory_claims LIMIT 1")
        .fetch_all(&enrollment.pool)
        .await
        .unwrap_err();
    assert_eq!(
        denied
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("42501")
    );
    let mut changed = first.clone();
    changed.subject_pattern = "other".into();
    registry
        .apply(
            &DeclarationFile {
                principals: vec![changed],
            },
            false,
        )
        .await
        .unwrap();
    assert_eq!(registry.get(first.principal_id).await.unwrap().revision, 2);
    assert!(registry.revoke(first.principal_id).await.unwrap());
    assert!(!registry.revoke(first.principal_id).await.unwrap());
    assert!(matches!(
        registry.resolve(&first.anchor_id, "other").await,
        Err(RegistryError::Revoked)
    ));
    registry.apply(&file, false).await.unwrap();
    assert_eq!(registry.get(first.principal_id).await.unwrap().revision, 4);
    // Invalid later entries cannot partially apply earlier desired changes.
    let mut invalid = declaration(PrincipalRole::Operator);
    invalid.ceiling = Ceiling::Trusted;
    assert!(
        registry
            .apply(
                &DeclarationFile {
                    principals: vec![first.clone(), invalid]
                },
                false
            )
            .await
            .is_err()
    );
    assert_eq!(registry.get(first.principal_id).await.unwrap().revision, 4);
    let retain = registry
        .list()
        .await
        .unwrap()
        .into_iter()
        .filter(|p| p.revoked_at.is_none() && p.principal_id != first.principal_id)
        .map(|p| PrincipalDeclaration {
            principal_id: p.principal_id,
            anchor_id: p.anchor_id,
            subject_pattern: p.subject_pattern,
            role: p.role,
            tenant_id: p.tenant_id,
            project: p.project,
            ceiling: p.ceiling,
            agent_pattern: p.agent_pattern,
        })
        .collect();
    assert_eq!(
        registry
            .apply(&DeclarationFile { principals: retain }, true)
            .await
            .unwrap()
            .revoked,
        1
    );
    assert!(matches!(
        registry.get(first.principal_id).await,
        Err(RegistryError::Revoked)
    ));
    enrollment.drop_role(&owner).await;
    runtime.drop_role(&owner).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One complete delegation/revision/revocation lifecycle.
async fn grant_rows_precede_tokens_and_revocation_or_revision_invalidates_them() {
    let Some(url) = common::test_database_url() else {
        return;
    };
    let _guard = ENROLL_TEST_LOCK.lock().await;
    let owner = common::migrated_pool(&url).await;
    let enrollment = RuntimeProbeRole::create_enrollment(&owner, &url).await;
    let runtime = RuntimeProbeRole::create_remote_runtime(&owner, &url).await;
    let registry = PrincipalRegistry::new(enrollment.pool.clone());
    let decl = declaration(PrincipalRole::Launcher);
    registry
        .apply(
            &DeclarationFile {
                principals: vec![decl.clone()],
            },
            false,
        )
        .await
        .unwrap();
    let principal = registry.get(decl.principal_id).await.unwrap();
    let signer = Arc::new(Ed25519Signer::from_seed_hex("test", &"11".repeat(32)).unwrap());
    let issuer = GrantIssuer::new(
        runtime.pool.clone(),
        signer,
        "https://recall.test/mcp".into(),
        3600,
        0,
    )
    .unwrap();
    let minted = issuer
        .issue(
            &principal,
            GrantKind::Agent,
            "sandbox-one",
            Some("box-one"),
            None,
        )
        .await
        .unwrap();
    assert!(!minted.token.is_empty());
    assert_eq!(
        issuer.check(minted.grant.jti).await.unwrap().agent,
        "sandbox-one"
    );
    assert!(matches!(
        issuer
            .issue(&principal, GrantKind::Agent, "unrelated", None, None)
            .await,
        Err(GrantError::Forbidden)
    ));
    assert!(matches!(
        issuer
            .issue(
                &principal,
                GrantKind::Agent,
                "sandbox-one",
                None,
                Some(86401)
            )
            .await,
        Err(GrantError::Request(_))
    ));
    assert!(matches!(
        issuer
            .check_at(minted.grant.jti, Utc::now() + chrono::Duration::hours(2))
            .await,
        Err(GrantError::Invalid)
    ));
    issuer.revoke(minted.grant.jti, &principal).await.unwrap();
    assert!(matches!(
        issuer.check(minted.grant.jti).await,
        Err(GrantError::Invalid)
    ));
    let minted = issuer
        .issue(&principal, GrantKind::Shipper, "sandbox-two", None, None)
        .await
        .unwrap();
    let mut edited = decl.clone();
    edited.agent_pattern = "sandbox-t*".into();
    registry
        .apply(
            &DeclarationFile {
                principals: vec![edited],
            },
            false,
        )
        .await
        .unwrap();
    assert!(matches!(
        issuer.check(minted.grant.jti).await,
        Err(GrantError::Invalid)
    ));
    assert!(matches!(
        issuer
            .issue(&principal, GrantKind::Agent, "sandbox-three", None, None)
            .await,
        Err(GrantError::Forbidden)
    ));
    let current = registry.get(decl.principal_id).await.unwrap();
    let final_grant = issuer
        .issue(&current, GrantKind::Agent, "sandbox-three", None, None)
        .await
        .unwrap();
    registry.revoke(decl.principal_id).await.unwrap();
    assert!(matches!(
        issuer.check(final_grant.grant.jti).await,
        Err(GrantError::Invalid)
    ));
    assert!(matches!(
        issuer
            .issue(&current, GrantKind::Agent, "sandbox-three", None, None)
            .await,
        Err(GrantError::Forbidden)
    ));
    let mut operator = declaration(PrincipalRole::Operator);
    operator.tenant_id = decl.tenant_id;
    operator.project.clone_from(&decl.project);
    let outsider = declaration(PrincipalRole::Operator);
    registry
        .apply(
            &DeclarationFile {
                principals: vec![operator.clone(), outsider.clone()],
            },
            false,
        )
        .await
        .unwrap();
    assert!(matches!(
        issuer
            .revoke(
                final_grant.grant.jti,
                &registry.get(outsider.principal_id).await.unwrap()
            )
            .await,
        Err(GrantError::Forbidden)
    ));
    issuer
        .revoke(
            final_grant.grant.jti,
            &registry.get(operator.principal_id).await.unwrap(),
        )
        .await
        .unwrap();
    enrollment.drop_role(&owner).await;
    runtime.drop_role(&owner).await;
}
