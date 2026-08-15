use uuid::Uuid;

use crate::memory_contracts::common::AuthenticatedProjectScopeV1;
use crate::{FleetScope, Result};

/// Constructor-bound bridge between physical SQL isolation and semantic scope.
///
/// `FleetScope` contains request-attention fields in addition to its trusted
/// tenant/project coordinates. The control log deliberately retains only the
/// physical tenant/project pair plus the exact credential-bound semantic scope
/// from deployment configuration. It therefore has no deserialization or
/// request-time scope-resolution path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedControlScope {
    tenant_id: Uuid,
    project: String,
    semantic_scope: AuthenticatedProjectScopeV1,
}

impl TrustedControlScope {
    /// Bind an already trusted deployment scope to its exact semantic scope.
    ///
    /// The defensive validation prevents direct construction of `FleetScope`
    /// through its public fields from bypassing the deployment invariants.
    pub fn from_trusted_context(
        deployment_scope: &FleetScope,
        semantic_scope: AuthenticatedProjectScopeV1,
    ) -> Result<Self> {
        deployment_scope.validate()?;
        Ok(Self {
            tenant_id: deployment_scope.tenant_id,
            project: deployment_scope.project.clone(),
            semantic_scope,
        })
    }

    /// Physical tenant coordinate bound into every control-log SQL query.
    #[must_use]
    pub const fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// Physical project coordinate bound into every control-log SQL query.
    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }

    /// Exact semantic authority scope verified by the memory contracts.
    #[must_use]
    pub const fn semantic_scope(&self) -> &AuthenticatedProjectScopeV1 {
        &self.semantic_scope
    }
}

#[cfg(test)]
mod tests {
    use ostk_recall_core::PrivacyTier;

    use super::*;
    use crate::FleetError;
    use crate::memory_contracts::common::ContractId;

    fn deployment_scope(agent: &str, session_id: Option<&str>) -> FleetScope {
        FleetScope::new(
            Uuid::parse_str("0198a849-f6ae-7d61-9800-000000000001").unwrap(),
            "physical-project",
            agent,
            session_id.map(str::to_owned),
            PrivacyTier::T1Project,
        )
        .unwrap()
    }

    fn semantic_scope(project: &str) -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.authority").unwrap(),
            ContractId::new(project).unwrap(),
        )
    }

    #[test]
    fn retains_only_physical_coordinates_and_exact_semantic_scope() {
        let semantic = semantic_scope("project.authority");
        let trusted = TrustedControlScope::from_trusted_context(
            &deployment_scope("agent-a", Some("session-1")),
            semantic.clone(),
        )
        .unwrap();

        assert_eq!(
            trusted.tenant_id(),
            Uuid::parse_str("0198a849-f6ae-7d61-9800-000000000001").unwrap()
        );
        assert_eq!(trusted.project(), "physical-project");
        assert_eq!(trusted.semantic_scope(), &semantic);
    }

    #[test]
    fn attention_fields_cannot_change_control_log_routing() {
        let first = TrustedControlScope::from_trusted_context(
            &deployment_scope("agent-a", Some("session-1")),
            semantic_scope("project.authority"),
        )
        .unwrap();
        let second = TrustedControlScope::from_trusted_context(
            &deployment_scope("agent-b", Some("session-2")),
            semantic_scope("project.authority"),
        )
        .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn semantic_scope_is_explicit_and_never_derived_from_sql_coordinates() {
        let deployment = deployment_scope("agent-a", None);
        let first = TrustedControlScope::from_trusted_context(
            &deployment,
            semantic_scope("project.authority"),
        )
        .unwrap();
        let second =
            TrustedControlScope::from_trusted_context(&deployment, semantic_scope("project.other"))
                .unwrap();

        assert_ne!(first, second);
        assert_eq!(first.project(), second.project());
    }

    #[test]
    fn defensively_rejects_an_invalid_public_fleet_scope() {
        let invalid = FleetScope {
            tenant_id: Uuid::nil(),
            project: "physical-project".into(),
            agent: "agent-a".into(),
            session_id: None,
            privacy_tier: PrivacyTier::T1Project,
        };

        assert!(matches!(
            TrustedControlScope::from_trusted_context(
                &invalid,
                semantic_scope("project.authority")
            ),
            Err(FleetError::InvalidScope(_))
        ));
    }
}
