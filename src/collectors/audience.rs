//! Who may read a collected item, decided by the server before it is staged
//! (ADR 0008 D6).
//!
//! In v1 every admitted item is visible to the whole project, so the only
//! question is whether an item may be admitted at all. [`classify`] answers it
//! from facts a collector learned from the provider and from operator
//! configuration, never from a pulled payload's own claims or an agent's
//! declaration:
//!
//! | Where the item is | Decision |
//! |---|---|
//! | a direct or group-direct conversation (Slack `im`, `mpim`) | refused, always |
//! | a container shared with another organization (Slack Connect) | refused, always |
//! | a public, unshared container (Slack public channel) | `provider_public` |
//! | a public team (Linear `visibility=public`) | `team_public` |
//! | a restricted container (private channel, private or restricted team, a Granola folder) | `operator_declared` only when the operator listed it, else refused |
//! | an operator-scoped source (documents root, Granola key, import) | `operator_declared` only when the instance declares it, else refused |
//! | an agent capture | `verified_container` when a verified collector or an operator import recorded the container as readable, else `operator_capture_scope` when the operator listed the scope, else refused |
//!
//! A visibility hint from an importer or an agent can only narrow: `private`
//! and `dm` refuse the item, and no hint admits anything the server would
//! refuse. A container the memory has recorded as withdrawn refuses a capture
//! into it.

use crate::memory_contracts::collected_item::{
    AudienceBasisV1, CollectionModeV1, VisibilityHintV1,
};

/// What a collector learned from the provider about the item's container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAudienceV1 {
    /// Every member of the provider scope can read it, and it is not shared
    /// outside the scope.
    ScopePublic,
    /// A team inside the scope is public.
    TeamPublic,
    /// Only some members of the scope can read it.
    Restricted,
    /// Shared with another organization.
    ExternallyShared,
    /// A direct or group-direct conversation.
    DirectMessage,
    /// The source has no provider audience of its own; the operator's
    /// declaration is the only basis (a documents root, a Granola key).
    OperatorScoped,
}

/// Instance audience policy, from the operator's sources file or import flags.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudiencePolicyV1 {
    /// The operator declares this source visible to the whole project.
    #[serde(default)]
    pub operator_declared: bool,
    /// Restricted containers the operator lists as visible to the whole
    /// project, by provider-stable container id.
    #[serde(default)]
    pub private_containers: Vec<String>,
}

/// Which containers of a capture scope the operator admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureContainersV1 {
    /// Every container of the scope, and items with no container.
    All,
    /// Only these container ids.
    Listed(Vec<String>),
}

/// One operator-declared capture scope
/// (`FLEET_RECALL_COLLECTED_CAPTURE_SCOPES`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureScopeV1 {
    /// The provider kind.
    pub provider: String,
    /// The provider scope id.
    pub provider_scope_id: String,
    /// Which containers.
    pub containers: CaptureContainersV1,
}

impl CaptureScopeV1 {
    fn admits(&self, provider: &str, provider_scope_id: &str, container_id: Option<&str>) -> bool {
        self.provider == provider
            && self.provider_scope_id == provider_scope_id
            && match (&self.containers, container_id) {
                (CaptureContainersV1::All, _) => true,
                (CaptureContainersV1::Listed(ids), Some(id)) => {
                    ids.iter().any(|listed| listed == id)
                }
                (CaptureContainersV1::Listed(_), None) => false,
            }
    }
}

/// What the memory already recorded about the item's container
/// (`memory_collector_containers_v1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownContainerV1 {
    /// No verified collector or operator import has recorded it.
    Unknown,
    /// Recorded as readable by the project, on this basis.
    Readable(AudienceBasisV1),
    /// Recorded, and since withdrawn: its audience narrowed.
    Withdrawn,
}

/// Everything one audience decision reads.
#[derive(Debug, Clone, Copy)]
pub struct AudienceInputV1<'a> {
    /// The channel the item arrives through.
    pub mode: CollectionModeV1,
    /// The provider kind.
    pub provider: &'a str,
    /// The provider scope id.
    pub provider_scope_id: &'a str,
    /// The provider-stable container id, when the item has a container.
    pub container_id: Option<&'a str>,
    /// What the collector learned from the provider, when it read the
    /// container itself (pull, push, an export's channel list).
    pub provider_audience: Option<ProviderAudienceV1>,
    /// A visibility hint from an importer or an agent.
    pub hint: Option<VisibilityHintV1>,
    /// The instance's policy.
    pub policy: &'a AudiencePolicyV1,
    /// The operator's capture scopes.
    pub capture_scopes: &'a [CaptureScopeV1],
    /// What the memory recorded about the container.
    pub known_container: KnownContainerV1,
}

/// Why an item may not be admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudienceRefusalV1 {
    /// A direct or group-direct conversation: never listed, fetched, or staged.
    DirectMessage,
    /// A container shared with another organization.
    ExternallyShared,
    /// A restricted container the operator did not list.
    RestrictedUnlisted,
    /// An operator-scoped source whose instance does not declare it.
    OperatorDeclarationRequired,
    /// A capture into a container nothing verified and no capture scope
    /// covers.
    CaptureUnverified,
    /// The container was withdrawn.
    ContainerWithdrawn,
    /// The importer or agent declared the item private or direct.
    HintRefused,
    /// A verified channel with no provider audience and no recorded container.
    AudienceUnknown,
}

impl AudienceRefusalV1 {
    /// Stable label, for a dead letter's diagnostic and a capture's
    /// `withheld_reason`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectMessage => "direct_message",
            Self::ExternallyShared => "externally_shared",
            Self::RestrictedUnlisted => "restricted_unlisted",
            Self::OperatorDeclarationRequired => "operator_declaration_required",
            Self::CaptureUnverified => "audience_unverified",
            Self::ContainerWithdrawn => "container_withdrawn",
            Self::HintRefused => "audience_refused",
            Self::AudienceUnknown => "audience_unknown",
        }
    }
}

/// One audience decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudienceDecisionV1 {
    /// Admit on this basis.
    Admit(AudienceBasisV1),
    /// Refuse; the item becomes a digest-only `audience_refused` dead letter.
    Refuse(AudienceRefusalV1),
}

/// Decide whether one item may be admitted, and on what basis.
#[must_use]
pub fn classify(input: &AudienceInputV1<'_>) -> AudienceDecisionV1 {
    if input.hint.is_some_and(VisibilityHintV1::refuses) {
        return AudienceDecisionV1::Refuse(AudienceRefusalV1::HintRefused);
    }
    match input.mode {
        CollectionModeV1::Pull | CollectionModeV1::Push => classify_verified(input),
        CollectionModeV1::Import => classify_import(input),
        CollectionModeV1::Capture => classify_capture(input),
    }
}

fn listed(input: &AudienceInputV1<'_>) -> bool {
    input.container_id.is_some_and(|id| {
        input
            .policy
            .private_containers
            .iter()
            .any(|listed| listed == id)
    })
}

/// The decision table for a container whose provider audience is known.
fn from_provider(input: &AudienceInputV1<'_>, audience: ProviderAudienceV1) -> AudienceDecisionV1 {
    use AudienceDecisionV1::{Admit, Refuse};
    match audience {
        ProviderAudienceV1::DirectMessage => Refuse(AudienceRefusalV1::DirectMessage),
        ProviderAudienceV1::ExternallyShared => Refuse(AudienceRefusalV1::ExternallyShared),
        ProviderAudienceV1::ScopePublic => Admit(AudienceBasisV1::ProviderPublic),
        ProviderAudienceV1::TeamPublic => Admit(AudienceBasisV1::TeamPublic),
        ProviderAudienceV1::Restricted if listed(input) => Admit(AudienceBasisV1::OperatorDeclared),
        ProviderAudienceV1::Restricted => Refuse(AudienceRefusalV1::RestrictedUnlisted),
        ProviderAudienceV1::OperatorScoped if input.policy.operator_declared => {
            Admit(AudienceBasisV1::OperatorDeclared)
        }
        ProviderAudienceV1::OperatorScoped => {
            Refuse(AudienceRefusalV1::OperatorDeclarationRequired)
        }
    }
}

/// Pull and push: the provider's own facts, else a container a verified
/// collector already recorded as readable (a push tombstone for an item a
/// pull admitted).
fn classify_verified(input: &AudienceInputV1<'_>) -> AudienceDecisionV1 {
    if let Some(audience) = input.provider_audience {
        return from_provider(input, audience);
    }
    match input.known_container {
        KnownContainerV1::Readable(basis)
            if matches!(
                basis,
                AudienceBasisV1::ProviderPublic
                    | AudienceBasisV1::TeamPublic
                    | AudienceBasisV1::OperatorDeclared
            ) =>
        {
            AudienceDecisionV1::Admit(basis)
        }
        KnownContainerV1::Withdrawn => {
            AudienceDecisionV1::Refuse(AudienceRefusalV1::ContainerWithdrawn)
        }
        KnownContainerV1::Readable(_) | KnownContainerV1::Unknown => {
            AudienceDecisionV1::Refuse(AudienceRefusalV1::AudienceUnknown)
        }
    }
}

/// Import: the operator's declaration is the basis, and an export's own
/// channel list can still refuse a direct, shared, or unlisted restricted
/// container.
fn classify_import(input: &AudienceInputV1<'_>) -> AudienceDecisionV1 {
    if !input.policy.operator_declared {
        return AudienceDecisionV1::Refuse(AudienceRefusalV1::OperatorDeclarationRequired);
    }
    match input.provider_audience {
        None
        | Some(
            ProviderAudienceV1::ScopePublic
            | ProviderAudienceV1::TeamPublic
            | ProviderAudienceV1::OperatorScoped,
        ) => AudienceDecisionV1::Admit(AudienceBasisV1::OperatorDeclared),
        Some(audience) => match from_provider(input, audience) {
            AudienceDecisionV1::Admit(_) => {
                AudienceDecisionV1::Admit(AudienceBasisV1::OperatorDeclared)
            }
            refused @ AudienceDecisionV1::Refuse(_) => refused,
        },
    }
}

/// Capture: never the agent's word. A container recorded readable by a
/// verified collector or an operator import, else an operator capture scope.
fn classify_capture(input: &AudienceInputV1<'_>) -> AudienceDecisionV1 {
    match input.known_container {
        KnownContainerV1::Withdrawn => {
            AudienceDecisionV1::Refuse(AudienceRefusalV1::ContainerWithdrawn)
        }
        KnownContainerV1::Readable(_) => {
            AudienceDecisionV1::Admit(AudienceBasisV1::VerifiedContainer)
        }
        KnownContainerV1::Unknown
            if input.capture_scopes.iter().any(|scope| {
                scope.admits(input.provider, input.provider_scope_id, input.container_id)
            }) =>
        {
            AudienceDecisionV1::Admit(AudienceBasisV1::OperatorCaptureScope)
        }
        KnownContainerV1::Unknown => {
            AudienceDecisionV1::Refuse(AudienceRefusalV1::CaptureUnverified)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(
        mode: CollectionModeV1,
        policy: &'a AudiencePolicyV1,
        scopes: &'a [CaptureScopeV1],
    ) -> AudienceInputV1<'a> {
        AudienceInputV1 {
            mode,
            provider: "slack",
            provider_scope_id: "T07ACME0001",
            container_id: Some("C07PLATENG1"),
            provider_audience: None,
            hint: None,
            policy,
            capture_scopes: scopes,
            known_container: KnownContainerV1::Unknown,
        }
    }

    fn refused(decision: AudienceDecisionV1) -> AudienceRefusalV1 {
        match decision {
            AudienceDecisionV1::Refuse(reason) => reason,
            AudienceDecisionV1::Admit(basis) => panic!("admitted on {}", basis.as_str()),
        }
    }

    #[test]
    fn direct_messages_are_refused_whatever_the_operator_lists() {
        let policy = AudiencePolicyV1 {
            operator_declared: true,
            private_containers: vec!["C07PLATENG1".into()],
        };
        for mode in [
            CollectionModeV1::Pull,
            CollectionModeV1::Push,
            CollectionModeV1::Import,
        ] {
            let mut item = input(mode, &policy, &[]);
            item.provider_audience = Some(ProviderAudienceV1::DirectMessage);
            assert_eq!(refused(classify(&item)), AudienceRefusalV1::DirectMessage);
            item.provider_audience = Some(ProviderAudienceV1::ExternallyShared);
            assert_eq!(
                refused(classify(&item)),
                AudienceRefusalV1::ExternallyShared
            );
        }
    }

    #[test]
    fn a_public_channel_and_a_public_team_are_admitted_on_the_providers_word() {
        let policy = AudiencePolicyV1::default();
        let mut item = input(CollectionModeV1::Pull, &policy, &[]);
        item.provider_audience = Some(ProviderAudienceV1::ScopePublic);
        assert_eq!(
            classify(&item),
            AudienceDecisionV1::Admit(AudienceBasisV1::ProviderPublic)
        );
        item.provider_audience = Some(ProviderAudienceV1::TeamPublic);
        assert_eq!(
            classify(&item),
            AudienceDecisionV1::Admit(AudienceBasisV1::TeamPublic)
        );
    }

    #[test]
    fn a_private_channel_is_admitted_only_when_listed() {
        let unlisted = AudiencePolicyV1::default();
        let mut item = input(CollectionModeV1::Pull, &unlisted, &[]);
        item.provider_audience = Some(ProviderAudienceV1::Restricted);
        assert_eq!(
            refused(classify(&item)),
            AudienceRefusalV1::RestrictedUnlisted
        );

        let listed = AudiencePolicyV1 {
            operator_declared: false,
            private_containers: vec!["C07PLATENG1".into()],
        };
        let mut item = input(CollectionModeV1::Pull, &listed, &[]);
        item.provider_audience = Some(ProviderAudienceV1::Restricted);
        assert_eq!(
            classify(&item),
            AudienceDecisionV1::Admit(AudienceBasisV1::OperatorDeclared)
        );
    }

    #[test]
    fn docs_granola_and_import_require_the_operator_declaration() {
        let undeclared = AudiencePolicyV1::default();
        let declared = AudiencePolicyV1 {
            operator_declared: true,
            private_containers: Vec::new(),
        };
        for (provider, mode) in [
            ("docs", CollectionModeV1::Pull),
            ("granola", CollectionModeV1::Pull),
            ("slack", CollectionModeV1::Import),
        ] {
            let mut item = input(mode, &undeclared, &[]);
            item.provider = provider;
            item.provider_audience = Some(ProviderAudienceV1::OperatorScoped);
            assert_eq!(
                refused(classify(&item)),
                AudienceRefusalV1::OperatorDeclarationRequired,
                "{provider} {} admitted without a declaration",
                mode.as_str()
            );
            let mut item = input(mode, &declared, &[]);
            item.provider = provider;
            item.provider_audience = Some(ProviderAudienceV1::OperatorScoped);
            assert_eq!(
                classify(&item),
                AudienceDecisionV1::Admit(AudienceBasisV1::OperatorDeclared)
            );
        }
    }

    #[test]
    fn an_import_of_an_unlisted_private_channel_is_refused() {
        let declared = AudiencePolicyV1 {
            operator_declared: true,
            private_containers: Vec::new(),
        };
        let mut item = input(CollectionModeV1::Import, &declared, &[]);
        item.provider_audience = Some(ProviderAudienceV1::Restricted);
        assert_eq!(
            refused(classify(&item)),
            AudienceRefusalV1::RestrictedUnlisted
        );
    }

    #[test]
    fn a_capture_into_an_unknown_container_is_refused() {
        let policy = AudiencePolicyV1::default();
        let item = input(CollectionModeV1::Capture, &policy, &[]);
        assert_eq!(
            refused(classify(&item)),
            AudienceRefusalV1::CaptureUnverified
        );
    }

    #[test]
    fn a_capture_into_a_verified_container_or_a_declared_scope_is_admitted() {
        let policy = AudiencePolicyV1::default();
        let mut item = input(CollectionModeV1::Capture, &policy, &[]);
        item.known_container = KnownContainerV1::Readable(AudienceBasisV1::ProviderPublic);
        assert_eq!(
            classify(&item),
            AudienceDecisionV1::Admit(AudienceBasisV1::VerifiedContainer)
        );

        let scopes = [CaptureScopeV1 {
            provider: "slack".into(),
            provider_scope_id: "T07ACME0001".into(),
            containers: CaptureContainersV1::Listed(vec!["C07PLATENG1".into()]),
        }];
        let item = input(CollectionModeV1::Capture, &policy, &scopes);
        assert_eq!(
            classify(&item),
            AudienceDecisionV1::Admit(AudienceBasisV1::OperatorCaptureScope)
        );
        let mut other_channel = input(CollectionModeV1::Capture, &policy, &scopes);
        other_channel.container_id = Some("C07OTHER001");
        assert_eq!(
            refused(classify(&other_channel)),
            AudienceRefusalV1::CaptureUnverified
        );
    }

    #[test]
    fn a_capture_hint_can_narrow_but_never_widen() {
        let policy = AudiencePolicyV1::default();
        // Every widening hint into an unknown container is still refused.
        for hint in [
            VisibilityHintV1::PublicChannel,
            VisibilityHintV1::TeamPublic,
            VisibilityHintV1::Project,
            VisibilityHintV1::Document,
        ] {
            let mut item = input(CollectionModeV1::Capture, &policy, &[]);
            item.hint = Some(hint);
            assert_eq!(
                refused(classify(&item)),
                AudienceRefusalV1::CaptureUnverified,
                "the hint {} widened a capture",
                hint.as_str()
            );
        }
        // A narrowing hint refuses even a verified container.
        for hint in [VisibilityHintV1::Private, VisibilityHintV1::Dm] {
            let mut item = input(CollectionModeV1::Capture, &policy, &[]);
            item.known_container = KnownContainerV1::Readable(AudienceBasisV1::ProviderPublic);
            item.hint = Some(hint);
            assert_eq!(refused(classify(&item)), AudienceRefusalV1::HintRefused);
        }
    }

    #[test]
    fn a_withdrawn_container_refuses_a_capture_and_an_unfetched_push() {
        let policy = AudiencePolicyV1::default();
        let scopes = [CaptureScopeV1 {
            provider: "slack".into(),
            provider_scope_id: "T07ACME0001".into(),
            containers: CaptureContainersV1::All,
        }];
        for mode in [CollectionModeV1::Capture, CollectionModeV1::Push] {
            let mut item = input(mode, &policy, &scopes);
            item.known_container = KnownContainerV1::Withdrawn;
            assert_eq!(
                refused(classify(&item)),
                AudienceRefusalV1::ContainerWithdrawn
            );
        }
    }

    #[test]
    fn a_verified_channel_with_no_audience_facts_fails_closed() {
        let policy = AudiencePolicyV1 {
            operator_declared: true,
            private_containers: Vec::new(),
        };
        let item = input(CollectionModeV1::Pull, &policy, &[]);
        assert_eq!(refused(classify(&item)), AudienceRefusalV1::AudienceUnknown);
        let mut recorded = input(CollectionModeV1::Push, &policy, &[]);
        recorded.known_container = KnownContainerV1::Readable(AudienceBasisV1::TeamPublic);
        assert_eq!(
            classify(&recorded),
            AudienceDecisionV1::Admit(AudienceBasisV1::TeamPublic)
        );
    }
}
