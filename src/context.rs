use ostk_recall_core::PrivacyTier;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{FleetError, Result};

/// Complete isolation key for every distributed memory operation.
///
/// `tenant_id` is deliberately not part of Recall's public MCP scope. It is a
/// trusted deployment boundary supplied by Fleet Recall configuration; an
/// agent cannot cross tenants by changing its tool arguments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetScope {
    pub tenant_id: Uuid,
    pub project: String,
    pub agent: String,
    pub session_id: Option<String>,
    pub privacy_tier: PrivacyTier,
}

/// Untrusted attention refinements accepted at a protocol boundary.
///
/// Tenant identity is intentionally absent. Project and agent are assertions
/// about the deployment-bound identity, not caller-selectable routing fields.
/// `privacy_tier` remains an optional compatibility assertion. An omitted
/// value inherits deployment policy; a different value is rejected until the
/// durable data plane can enforce owner/tier visibility.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestedScope {
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub privacy_tier: Option<PrivacyTier>,
}

impl FleetScope {
    pub fn new(
        tenant_id: Uuid,
        project: impl Into<String>,
        agent: impl Into<String>,
        session_id: Option<String>,
        privacy_tier: PrivacyTier,
    ) -> Result<Self> {
        let scope = Self {
            tenant_id,
            project: project.into(),
            agent: agent.into(),
            session_id,
            privacy_tier,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        if self.tenant_id.is_nil() {
            return Err(FleetError::InvalidScope(
                "tenant_id must not be the nil UUID".into(),
            ));
        }
        validate_component("project", &self.project)?;
        validate_component("agent", &self.agent)?;
        if let Some(session_id) = &self.session_id {
            validate_component("session_id", session_id)?;
        }
        Ok(())
    }

    /// Resolve an untrusted attention request against this deployment scope.
    ///
    /// Project and agent can only be repeated as exact assertions. The caller
    /// may select a session within that identity. Privacy must match the
    /// deployment tier until row-level owner/tier visibility is implemented.
    pub(crate) fn resolve_requested(&self, requested: &RequestedScope) -> Result<Self> {
        validate_optional_component("scope.project", requested.project.as_deref())?;
        validate_optional_component("scope.agent", requested.agent.as_deref())?;
        validate_optional_component("scope.session_id", requested.session_id.as_deref())?;

        if requested
            .project
            .as_deref()
            .is_some_and(|project| project != self.project)
        {
            return Err(FleetError::InvalidScope(
                "scope.project must match the deployment-bound project".into(),
            ));
        }
        if requested
            .agent
            .as_deref()
            .is_some_and(|agent| agent != self.agent)
        {
            return Err(FleetError::InvalidScope(
                "scope.agent must match the deployment-bound agent".into(),
            ));
        }

        let privacy_tier = requested.privacy_tier.unwrap_or(self.privacy_tier);
        if privacy_rank(privacy_tier) > privacy_rank(self.privacy_tier) {
            return Err(FleetError::InvalidScope(format!(
                "scope.privacy_tier cannot exceed the deployment maximum ({:?})",
                self.privacy_tier
            )));
        }
        if privacy_tier != self.privacy_tier {
            return Err(FleetError::InvalidScope(
                "scope.privacy_tier refinement is unavailable until owner/tier visibility is enforced in the durable data plane"
                    .into(),
            ));
        }

        let resolved = Self {
            tenant_id: self.tenant_id,
            project: self.project.clone(),
            agent: self.agent.clone(),
            session_id: requested
                .session_id
                .clone()
                .or_else(|| self.session_id.clone()),
            privacy_tier,
        };
        resolved.validate()?;
        Ok(resolved)
    }
}

const fn privacy_rank(tier: PrivacyTier) -> u8 {
    match tier {
        PrivacyTier::T0Private => 0,
        PrivacyTier::T1Project => 1,
        PrivacyTier::T2Trusted => 2,
        PrivacyTier::T3Public => 3,
    }
}

fn validate_optional_component(name: &str, value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        validate_component(name, value)?;
    }
    Ok(())
}

fn validate_component(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(FleetError::InvalidScope(format!(
            "{name} must not be empty"
        )));
    }
    if value != value.trim() {
        return Err(FleetError::InvalidScope(format!(
            "{name} must not have leading or trailing whitespace"
        )));
    }
    if value.len() > 256 {
        return Err(FleetError::InvalidScope(format!(
            "{name} exceeds 256 bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(FleetError::InvalidScope(format!(
            "{name} must not contain control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> Uuid {
        Uuid::parse_str("0198a849-f6ae-7d61-9800-000000000001").unwrap()
    }

    #[test]
    fn rejects_nil_tenant() {
        let result = FleetScope::new(
            Uuid::nil(),
            "project",
            "agent",
            None,
            PrivacyTier::T1Project,
        );
        assert!(matches!(result, Err(FleetError::InvalidScope(_))));
    }

    #[test]
    fn resolves_matching_identity_and_session() {
        let base = FleetScope::new(
            tenant(),
            "default-project",
            "default-agent",
            Some("base-session".into()),
            PrivacyTier::T1Project,
        )
        .unwrap();
        let requested = RequestedScope {
            project: Some("default-project".into()),
            agent: Some("default-agent".into()),
            session_id: Some("turn-7".into()),
            privacy_tier: Some(PrivacyTier::T1Project),
        };

        let resolved = base.resolve_requested(&requested).unwrap();
        assert_eq!(resolved.tenant_id, tenant());
        assert_eq!(resolved.project, "default-project");
        assert_eq!(resolved.agent, "default-agent");
        assert_eq!(resolved.session_id.as_deref(), Some("turn-7"));
        assert_eq!(resolved.privacy_tier, PrivacyTier::T1Project);
    }

    #[test]
    fn omitted_fields_inherit_trusted_scope_including_privacy() {
        let base = FleetScope::new(
            tenant(),
            "default-project",
            "default-agent",
            Some("base-session".into()),
            PrivacyTier::T1Project,
        )
        .unwrap();

        let resolved = base.resolve_requested(&RequestedScope::default()).unwrap();
        assert_eq!(resolved, base);
    }

    #[test]
    fn rejects_identity_override_and_privacy_change() {
        let base = FleetScope::new(
            tenant(),
            "default-project",
            "default-agent",
            None,
            PrivacyTier::T1Project,
        )
        .unwrap();

        for requested in [
            RequestedScope {
                project: Some("other-project".into()),
                ..RequestedScope::default()
            },
            RequestedScope {
                agent: Some("other-agent".into()),
                ..RequestedScope::default()
            },
            RequestedScope {
                privacy_tier: Some(PrivacyTier::T0Private),
                ..RequestedScope::default()
            },
            RequestedScope {
                privacy_tier: Some(PrivacyTier::T2Trusted),
                ..RequestedScope::default()
            },
            RequestedScope {
                privacy_tier: Some(PrivacyTier::T3Public),
                ..RequestedScope::default()
            },
        ] {
            assert!(matches!(
                base.resolve_requested(&requested),
                Err(FleetError::InvalidScope(_))
            ));
        }
    }
}
