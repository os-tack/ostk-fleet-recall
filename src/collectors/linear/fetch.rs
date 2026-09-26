//! Re-reading the Linear issue or comment an ingress hint names (ADR 0008
//! D12).
//!
//! The fetch reads the one node exactly as a sweep reads it, under the
//! collector's credential and team rules:
//!
//! 1. The scope query (once per tick): the credential's organization must be
//!    the pin; it gives each configured team's key and visibility.
//! 2. The node, by id (`issues` or `comments` filtered on it, archived and
//!    trashed included); a comment's issue is read too, for its team and
//!    whether it is in the trash.
//! 3. The team must be one `settings.teams` lists and the credential sees; a
//!    team the instance does not admit is observed, which withdraws it, as a
//!    pass's observation would, and nothing in it is read.
//! 4. The node becomes a draft as a sweep's does.
//!
//! Some changes are the pass's alone, since only a sweep reads what they
//! imply: an issue the memory holds in another team, in the trash, or
//! withdrawn, and one it never held (their comments need a whole read the
//! sweep queues), and a comment on an issue in the trash (the trash hides
//! everything on the issue). For those the hint stages nothing and the next
//! pass, which runs right after the hints in the same tick, settles them.

use async_trait::async_trait;
use tokio::sync::OnceCell;

use crate::error::Result;
use crate::memory_contracts::collected_item::{ContainerKindV1, ObjectKindV1, ProviderKindV1};

use super::graphql::{LinearApiV1, LinearCallErrorV1, LinearScopeV1, PageNodeV1};
use super::render::{
    COMMENT_OBJECT_KIND, CommentDraftV1, ISSUE_OBJECT_KIND, LINEAR_PROVIDER, LinearTeamContextV1,
    TEAM_CONTAINER_KIND, comment_draft, is_linear_id, issue_draft, issue_lifecycle,
};
use super::{LinearSettingsV1, admitted_teams, shown_id, team_decision};
use crate::collectors::audience::AudienceDecisionV1;
use crate::collectors::pull::{
    FetchedObjectV1, HintedObjectV1, ObjectFetcherV1, PageStager, PullPassInputV1, PulledItemV1,
};
use crate::collectors::sink::{ContainerObservationV1, DeadLetterReasonV1};

/// Re-reads hinted issues and comments of one configured organization.
#[derive(Debug)]
pub struct LinearFetchV1 {
    settings: LinearSettingsV1,
    api: LinearApiV1,
    /// The scope answer, once its organization is the pin.
    scope: OnceCell<LinearScopeV1>,
}

fn failed(what: &str, error: &LinearCallErrorV1) -> FetchedObjectV1 {
    FetchedObjectV1::Failed(format!("the Linear {what} query failed: {error}"))
}

impl LinearFetchV1 {
    /// A fetcher over `settings` through `api`.
    #[must_use]
    pub const fn new(settings: LinearSettingsV1, api: LinearApiV1) -> Self {
        Self {
            settings,
            api,
            scope: OnceCell::const_new(),
        }
    }

    async fn scope(&self, pinned: &str) -> std::result::Result<&LinearScopeV1, FetchedObjectV1> {
        self.scope
            .get_or_try_init(|| async {
                let mut teams = self.settings.teams.clone();
                teams.sort();
                let scope = self
                    .api
                    .scope(&teams)
                    .await
                    .map_err(|error| failed("organization", &error))?;
                if !scope.organization.id.eq_ignore_ascii_case(pinned) {
                    return Err(FetchedObjectV1::Failed(format!(
                        "the Linear credential belongs to organization {}, but the collector is \
                         pinned to organization {pinned}",
                        shown_id(&scope.organization.id)
                    )));
                }
                Ok(scope)
            })
            .await
    }
}

#[async_trait]
impl ObjectFetcherV1 for LinearFetchV1 {
    #[allow(clippy::too_many_lines)] // one linear scope -> node -> team -> draft read
    async fn fetch(
        &self,
        input: &PullPassInputV1<'_>,
        hint: &HintedObjectV1<'_>,
        stager: &mut PageStager<'_>,
    ) -> Result<FetchedObjectV1> {
        let is_comment = match hint.object_kind {
            ISSUE_OBJECT_KIND => false,
            COMMENT_OBJECT_KIND => true,
            _ => return Ok(FetchedObjectV1::Nothing("unknown_object_kind")),
        };
        if !is_linear_id(hint.external_id) {
            return Ok(FetchedObjectV1::Nothing("malformed_id"));
        }
        let scope = match self.scope(input.instance.provider_scope_id.as_str()).await {
            Ok(scope) => scope,
            Err(failure) => return Ok(failure),
        };
        let comment = if is_comment {
            match self.api.comment(hint.external_id).await {
                Ok(Some(PageNodeV1::Node(comment))) => Some(comment),
                Ok(Some(PageNodeV1::Malformed(digest))) => {
                    stager
                        .dead_letter(
                            None,
                            DeadLetterReasonV1::ParseFailed,
                            digest,
                            "a Linear comment is not the documented shape",
                        )
                        .await?;
                    return Ok(FetchedObjectV1::Nothing("unparseable"));
                }
                Ok(None) => return Ok(FetchedObjectV1::Nothing("not_found")),
                Err(error) => return Ok(failed("comment", &error)),
            }
        } else {
            None
        };
        let issue_id = match &comment {
            Some(comment) => match comment.issue.as_ref() {
                Some(issue) if is_linear_id(&issue.id) => issue.id.clone(),
                _ => return Ok(FetchedObjectV1::Nothing("not_on_an_issue")),
            },
            None => hint.external_id.to_owned(),
        };
        let issue = match self.api.issue(&issue_id).await {
            Ok(Some(PageNodeV1::Node(issue))) => issue,
            Ok(Some(PageNodeV1::Malformed(digest))) => {
                stager
                    .dead_letter(
                        None,
                        DeadLetterReasonV1::ParseFailed,
                        digest,
                        "a Linear issue is not the documented shape",
                    )
                    .await?;
                return Ok(FetchedObjectV1::Nothing("unparseable"));
            }
            Ok(None) => return Ok(FetchedObjectV1::Nothing("not_found")),
            Err(error) => return Ok(failed("issue", &error)),
        };
        let Some(team) = issue
            .team
            .as_ref()
            .map(|team| team.id.clone())
            .filter(|team| {
                self.settings
                    .teams
                    .iter()
                    .any(|listed| listed.eq_ignore_ascii_case(team))
            })
        else {
            return Ok(FetchedObjectV1::Nothing("team_not_read"));
        };
        let Some(info) = scope.team(&team) else {
            return Ok(FetchedObjectV1::Nothing("team_not_visible"));
        };
        let (audience, decision) = team_decision(input, &team, info);
        let kind = ContainerKindV1::new(TEAM_CONTAINER_KIND)?;
        let key = stager.container_key(&kind, &team);
        let observation = ContainerObservationV1 {
            kind,
            id: team.clone(),
            label: info.key.clone(),
            provider_audience: audience,
        };
        if let AudienceDecisionV1::Refuse(_) = decision {
            return Ok(FetchedObjectV1::Stage {
                items: Vec::new(),
                observations: vec![observation],
            });
        }
        // What only a sweep may do: moves, the trash, withdrawals, and items
        // the memory never held.
        let object_kind = ObjectKindV1::new(hint.object_kind)?;
        let held = stager.held(&object_kind, hint.external_id).await?;
        let issue_in_trash = issue_lifecycle(&issue).is_tombstone();
        let settled_here = held.as_ref().is_some_and(|held| {
            !held.withdrawn
                && !held.lifecycle.is_tombstone()
                && held.container.as_ref().is_some_and(|(kind, id)| {
                    kind == TEAM_CONTAINER_KIND && id.eq_ignore_ascii_case(&team)
                })
        });
        let left_to_the_pass = if is_comment {
            issue_in_trash || held.as_ref().is_some_and(|_| !settled_here)
        } else {
            !settled_here
        };
        if left_to_the_pass {
            return Ok(FetchedObjectV1::Stage {
                items: Vec::new(),
                observations: vec![observation],
            });
        }
        let mut teams = self.settings.teams.clone();
        teams.sort();
        let admitted = admitted_teams(input, &teams, scope);
        let provider = ProviderKindV1::new(LINEAR_PROVIDER)?;
        let context = LinearTeamContextV1 {
            provider: &provider,
            provider_scope_id: input.instance.provider_scope_id.as_str(),
            team_id: &team,
            team_key: info.key.as_deref(),
            admitted_teams: &admitted,
        };
        let draft = comment.as_ref().map_or_else(
            || issue_draft(&context, &issue).map(Some),
            |comment| match comment_draft(&context, comment) {
                Ok(CommentDraftV1::Item(draft)) => Ok(Some(*draft)),
                Ok(CommentDraftV1::Skip) => Ok(None),
                Err(diagnostic) => Err(diagnostic),
            },
        );
        let items = match draft {
            Ok(draft) => draft
                .map(|draft| PulledItemV1 {
                    draft,
                    provider_audience: Some(audience),
                })
                .into_iter()
                .collect(),
            Err(diagnostic) => {
                stager
                    .dead_letter(
                        Some(key),
                        DeadLetterReasonV1::ValidationFailed,
                        crate::collectors::cockroach::framed_sha256(
                            "ostk-linear-hinted-node-v1",
                            &[hint.external_id.as_bytes()],
                        ),
                        diagnostic,
                    )
                    .await?;
                Vec::new()
            }
        };
        Ok(FetchedObjectV1::Stage {
            items,
            observations: vec![observation],
        })
    }
}
