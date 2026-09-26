//! The Linear GraphQL API the collector reads, over the provider HTTP seam
//! (ADR 0008 D8).
//!
//! Three operations, each a `POST` of one named query to the endpoint:
//!
//! * `FleetRecallLinearScope` ([`SCOPE_QUERY`]): the organization the
//!   credential belongs to, and the configured teams with their key and
//!   visibility;
//! * `FleetRecallLinearIssues` ([`ISSUES_QUERY`]): one page of one team's
//!   issues updated after an instant, `orderBy: updatedAt`, archived and
//!   trashed ones included;
//! * `FleetRecallLinearComments` ([`COMMENTS_QUERY`]): one page of the
//!   comments on one team's issues, the same way, or of every comment on one
//!   issue (an issue that moved into a team the collector reads, whose
//!   comments kept their old `updatedAt`);
//! * `FleetRecallLinearIssueTeams` ([`ISSUE_TEAMS_QUERY`]): where a batch of
//!   issues the memory holds is now, by id: each one's team and `updatedAt`,
//!   or nothing for an issue the credential can no longer see.
//!
//! Every filter is a variable (`IssueFilter`, `CommentFilter`), so no value
//! is ever spliced into a query's text. Linear reports most failures in a
//! GraphQL `errors` array, under a `200` or a `4xx`
//! ([`crate::collectors::http::ProviderHttpV1::post_graphql`]);
//! [`LinearCallErrorV1`] tells a rate limit (`RATELIMITED`, or HTTP 429), a
//! refused credential (`AUTHENTICATION_ERROR`, or HTTP 401 or 403, which fail
//! the whole pass), and a refusal of one read (anything else) apart. Only an
//! error's code is ever read from a body, cut to the characters a code has.
//! A page's nodes are parsed one by one, so one malformed node is one dead
//! letter rather than a lost page, and the `x-ratelimit-*` headers of every
//! answer are read back ([`RateLimitV1`]).

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::collectors::cockroach::framed_sha256;
use crate::collectors::http::{ProviderHttpErrorV1, ProviderHttpV1, ProviderResponseV1};
use crate::memory_contracts::digest::Sha256Digest;

/// The scope query: the organization and the configured teams.
pub const SCOPE_QUERY: &str = "query FleetRecallLinearScope($teams: [ID!]!) { \
     organization { id } \
     teams(filter: { id: { in: $teams } }, first: 250) { nodes { id key name visibility } } }";

/// One page of one team's issues.
pub const ISSUES_QUERY: &str = "query FleetRecallLinearIssues($filter: IssueFilter!, \
     $first: Int!, $after: String) { \
     issues(filter: $filter, orderBy: updatedAt, includeArchived: true, first: $first, \
     after: $after) { \
     nodes { id identifier title description url createdAt updatedAt archivedAt trashed \
     state { name type } team { id } creator { id } botActor { id name type } \
     externalUserCreator { id } parent { id url team { id } } \
     project { id name url teams(first: 50) { nodes { id } } } } \
     pageInfo { hasNextPage endCursor } } }";

/// Where a batch of issues is now: each one's team and `updatedAt`, by id.
pub const ISSUE_TEAMS_QUERY: &str = "query FleetRecallLinearIssueTeams($filter: IssueFilter!, \
     $first: Int!) { \
     issues(filter: $filter, includeArchived: true, first: $first) { \
     nodes { id updatedAt trashed team { id } } pageInfo { hasNextPage endCursor } } }";

/// The most issues one [`ISSUE_TEAMS_QUERY`] asks about.
pub const MAX_ISSUE_TEAMS_BATCH: usize = 100;

/// The most teams a project may have for its link to be kept: a project
/// whose teams could not all be read is not linked.
pub const MAX_PROJECT_TEAMS: usize = 50;

/// One page of the comments on one team's issues.
pub const COMMENTS_QUERY: &str = "query FleetRecallLinearComments($filter: CommentFilter!, \
     $first: Int!, $after: String) { \
     comments(filter: $filter, orderBy: updatedAt, includeArchived: true, first: $first, \
     after: $after) { \
     nodes { id body url createdAt updatedAt editedAt archivedAt issue { id } parent { id } \
     user { id } botActor { id name type } externalUser { id } } \
     pageInfo { hasNextPage endCursor } } }";

/// Longest error code kept.
const MAX_ERROR_CODE_BYTES: usize = 64;

/// Why one Linear call gave no usable answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinearCallErrorV1 {
    /// Rate-limited: HTTP 429, or `RATELIMITED`.
    #[error("Linear rate-limited the call")]
    RateLimited,
    /// The credential is unusable: `AUTHENTICATION_ERROR`, HTTP 401 or 403.
    #[error("Linear refused the credential: {0}")]
    Credential(String),
    /// Linear refused this read (`FORBIDDEN`, an invalid cursor, ...).
    #[error("Linear refused the call: {0}")]
    Refused(String),
    /// The request failed below Linear's own answer.
    #[error("{0}")]
    Http(ProviderHttpErrorV1),
    /// The answer is not the documented shape.
    #[error("Linear's answer is malformed: {0}")]
    Malformed(&'static str),
}

impl From<ProviderHttpErrorV1> for LinearCallErrorV1 {
    fn from(error: ProviderHttpErrorV1) -> Self {
        match error {
            ProviderHttpErrorV1::RateLimited { .. } => Self::RateLimited,
            other => Self::Http(other),
        }
    }
}

/// What the `x-ratelimit-*` headers of one answer said is left.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RateLimitV1 {
    /// `x-ratelimit-requests-remaining`.
    pub requests_remaining: Option<u64>,
    /// `x-ratelimit-complexity-remaining`.
    pub complexity_remaining: Option<u64>,
}

impl RateLimitV1 {
    fn of(response: &ProviderResponseV1) -> Self {
        let read = |name: &str| {
            response
                .header(name)
                .and_then(|value| value.trim().parse::<u64>().ok())
        };
        Self {
            requests_remaining: read("x-ratelimit-requests-remaining"),
            complexity_remaining: read("x-ratelimit-complexity-remaining"),
        }
    }

    /// Whether the answer reported anything.
    #[must_use]
    pub const fn reported(&self) -> bool {
        self.requests_remaining.is_some() || self.complexity_remaining.is_some()
    }
}

#[derive(Deserialize)]
struct ErrorExtensionsV1 {
    #[serde(default)]
    code: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
}

#[derive(Deserialize)]
struct GraphqlErrorV1 {
    #[serde(default)]
    extensions: Option<ErrorExtensionsV1>,
}

#[derive(Deserialize)]
struct AnswerV1 {
    #[serde(default)]
    data: Option<serde_json::Value>,
    #[serde(default)]
    errors: Vec<GraphqlErrorV1>,
}

/// An error's code as Linear sent it (`extensions.code`, else
/// `extensions.type`), upper-cased and cut to the letters, digits, and
/// underscores a code has; spaces become underscores.
fn error_code(error: &GraphqlErrorV1) -> String {
    let raw = error
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.code.as_deref().or(extensions.kind.as_deref()))
        .unwrap_or("unknown_error");
    let code: String = raw
        .chars()
        .map(|scalar| if scalar == ' ' { '_' } else { scalar })
        .filter(|scalar| scalar.is_ascii_alphanumeric() || *scalar == '_')
        .take(MAX_ERROR_CODE_BYTES)
        .collect::<String>()
        .to_ascii_uppercase();
    if code.is_empty() {
        "UNKNOWN_ERROR".to_owned()
    } else {
        code
    }
}

/// What a set of GraphQL errors means for the call.
fn classify(errors: &[GraphqlErrorV1], status: u16) -> LinearCallErrorV1 {
    let codes: Vec<String> = errors.iter().map(error_code).collect();
    let compact = |code: &String| code.replace('_', "");
    if status == 429 || codes.iter().any(|code| compact(code) == "RATELIMITED") {
        return LinearCallErrorV1::RateLimited;
    }
    if let Some(code) = codes.iter().find(|code| {
        matches!(
            compact(code).as_str(),
            "AUTHENTICATIONERROR" | "UNAUTHENTICATED"
        )
    }) {
        return LinearCallErrorV1::Credential(code.clone());
    }
    if matches!(status, 401 | 403) {
        return LinearCallErrorV1::Credential(format!("HTTP_{status}"));
    }
    LinearCallErrorV1::Refused(
        codes
            .into_iter()
            .next()
            .unwrap_or_else(|| "UNKNOWN_ERROR".to_owned()),
    )
}

/// Decode one answer's `data`, mapping its errors (and a client-error status
/// with none) to the call's error.
fn decode<T: DeserializeOwned>(response: &ProviderResponseV1) -> Result<T, LinearCallErrorV1> {
    let Ok(answer) = serde_json::from_slice::<AnswerV1>(&response.body) else {
        return Err(match response.status {
            401 | 403 => LinearCallErrorV1::Credential(format!("HTTP_{}", response.status)),
            status if status >= 400 => {
                LinearCallErrorV1::Http(ProviderHttpErrorV1::Status { status })
            }
            _ => LinearCallErrorV1::Malformed("not a GraphQL answer"),
        });
    };
    if !answer.errors.is_empty() {
        return Err(classify(&answer.errors, response.status));
    }
    if response.status >= 400 {
        return Err(classify(&[], response.status));
    }
    let data = answer.data.ok_or(LinearCallErrorV1::Malformed(
        "an answer with neither data nor errors",
    ))?;
    serde_json::from_value(data)
        .map_err(|_| LinearCallErrorV1::Malformed("an unexpected field shape"))
}

/// The organization the credential belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LinearOrganizationV1 {
    /// Its id.
    pub id: String,
}

/// One team, as the scope query describes it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LinearTeamV1 {
    /// Its id.
    pub id: String,
    /// Its key (`ENG`): a mutable label.
    #[serde(default)]
    pub key: Option<String>,
    /// Its name.
    #[serde(default)]
    pub name: Option<String>,
    /// `public`, `private`, or `restricted`.
    #[serde(default)]
    pub visibility: Option<String>,
}

impl LinearTeamV1 {
    /// Whether Linear says every member of the organization can read it.
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.visibility.as_deref() == Some("public")
    }
}

#[derive(Debug, Deserialize)]
struct NodesV1<T> {
    nodes: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct ScopeAnswerV1 {
    organization: LinearOrganizationV1,
    teams: NodesV1<LinearTeamV1>,
}

/// What the scope query read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearScopeV1 {
    /// The organization.
    pub organization: LinearOrganizationV1,
    /// The configured teams the credential can see.
    pub teams: Vec<LinearTeamV1>,
    /// The answer's rate-limit headers.
    pub rate: RateLimitV1,
}

impl LinearScopeV1 {
    /// One team, by id.
    #[must_use]
    pub fn team(&self, id: &str) -> Option<&LinearTeamV1> {
        self.teams
            .iter()
            .find(|team| team.id.eq_ignore_ascii_case(id))
    }
}

/// A node named by its id only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct LinearIdV1 {
    /// Its id.
    pub id: String,
}

/// The ids of a connection's nodes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct LinearIdsV1 {
    /// The nodes.
    #[serde(default)]
    pub nodes: Vec<LinearIdV1>,
}

/// A reference to another node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct LinearRefV1 {
    /// Its id.
    pub id: String,
    /// Its link, when asked for.
    #[serde(default)]
    pub url: Option<String>,
    /// Its name, when asked for.
    #[serde(default)]
    pub name: Option<String>,
    /// Its team, when asked for (an issue's parent).
    #[serde(default)]
    pub team: Option<LinearIdV1>,
    /// Its teams, when asked for (a project).
    #[serde(default)]
    pub teams: Option<LinearIdsV1>,
}

/// A bot or integration that acted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct LinearBotV1 {
    /// Its id, when it has one.
    #[serde(default)]
    pub id: Option<String>,
    /// Its display name.
    #[serde(default)]
    pub name: Option<String>,
    /// What kind of bot (`github`, `slack`, ...).
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
}

/// A workflow state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct LinearStateV1 {
    /// Its name (`In Progress`).
    #[serde(default)]
    pub name: Option<String>,
    /// Its type (`started`).
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
}

/// One issue, as [`ISSUES_QUERY`] reads it. Unknown fields are ignored.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinearIssueV1 {
    /// Its id: its identity.
    pub id: String,
    /// `ENG-412`: a label, which changes when the issue moves team.
    pub identifier: String,
    /// Its title.
    pub title: String,
    /// Its markdown description.
    #[serde(default)]
    pub description: Option<String>,
    /// Its link.
    #[serde(default)]
    pub url: Option<String>,
    /// When it was created.
    pub created_at: String,
    /// When it last changed: its version marker.
    pub updated_at: String,
    /// When it was archived.
    #[serde(default)]
    pub archived_at: Option<String>,
    /// Whether it is in the trash.
    #[serde(default)]
    pub trashed: Option<bool>,
    /// Its workflow state.
    #[serde(default)]
    pub state: Option<LinearStateV1>,
    /// Its team.
    #[serde(default)]
    pub team: Option<LinearIdV1>,
    /// The person who created it.
    #[serde(default)]
    pub creator: Option<LinearRefV1>,
    /// The bot that created it.
    #[serde(default)]
    pub bot_actor: Option<LinearBotV1>,
    /// The external user who created it.
    #[serde(default)]
    pub external_user_creator: Option<LinearRefV1>,
    /// Its parent issue.
    #[serde(default)]
    pub parent: Option<LinearRefV1>,
    /// Its project.
    #[serde(default)]
    pub project: Option<LinearRefV1>,
}

/// Identity only: an issue is provider content and is never logged.
impl std::fmt::Debug for LinearIssueV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LinearIssueV1")
            .field("id", &self.id)
            .field("updated_at", &self.updated_at)
            .field(
                "description_bytes",
                &self.description.as_deref().map_or(0, str::len),
            )
            .finish_non_exhaustive()
    }
}

/// One comment, as [`COMMENTS_QUERY`] reads it. Unknown fields are ignored.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinearCommentV1 {
    /// Its id: its identity.
    pub id: String,
    /// Its markdown body.
    #[serde(default)]
    pub body: String,
    /// Its link.
    #[serde(default)]
    pub url: Option<String>,
    /// When it was created.
    pub created_at: String,
    /// When it last changed: its version marker.
    pub updated_at: String,
    /// When its body was last edited.
    #[serde(default)]
    pub edited_at: Option<String>,
    /// When it was archived.
    #[serde(default)]
    pub archived_at: Option<String>,
    /// The issue it is on: its thread root.
    #[serde(default)]
    pub issue: Option<LinearRefV1>,
    /// The comment it replies to.
    #[serde(default)]
    pub parent: Option<LinearRefV1>,
    /// The person who wrote it.
    #[serde(default)]
    pub user: Option<LinearRefV1>,
    /// The bot that wrote it.
    #[serde(default)]
    pub bot_actor: Option<LinearBotV1>,
    /// The external user who wrote it.
    #[serde(default)]
    pub external_user: Option<LinearRefV1>,
}

/// Identity only: a comment is provider content and is never logged.
impl std::fmt::Debug for LinearCommentV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LinearCommentV1")
            .field("id", &self.id)
            .field("updated_at", &self.updated_at)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// One node of a page: parsed, or the digest of what did not parse.
#[derive(Debug, Clone)]
pub enum PageNodeV1<T> {
    /// The node.
    Node(Box<T>),
    /// A node that is not the documented shape: the digest of its JSON.
    Malformed(Sha256Digest),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PageInfoV1 {
    #[serde(default)]
    has_next_page: bool,
    #[serde(default)]
    end_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionV1 {
    #[serde(default)]
    nodes: Vec<serde_json::Value>,
    page_info: PageInfoV1,
}

#[derive(Deserialize)]
struct IssuesAnswerV1 {
    issues: ConnectionV1,
}

#[derive(Deserialize)]
struct CommentsAnswerV1 {
    comments: ConnectionV1,
}

/// Where one issue the memory holds is now.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinearIssuePlaceV1 {
    /// Its id.
    pub id: String,
    /// When it last changed.
    #[serde(default)]
    pub updated_at: Option<String>,
    /// Its team.
    #[serde(default)]
    pub team: Option<LinearIdV1>,
}

#[derive(Deserialize)]
struct IssueTeamsNodesV1 {
    #[serde(default)]
    nodes: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct IssueTeamsAnswerV1 {
    issues: IssueTeamsNodesV1,
}

/// One page of a listing.
#[derive(Debug, Clone)]
pub struct LinearPageV1<T> {
    /// Its nodes, in Linear's order.
    pub nodes: Vec<PageNodeV1<T>>,
    /// Where the next page starts, when there is one.
    pub next_cursor: Option<String>,
    /// Linear said there is more but gave no cursor: the listing cannot be
    /// read to its end.
    pub unfinished: bool,
    /// The answer's rate-limit headers.
    pub rate: RateLimitV1,
}

fn page<T: DeserializeOwned>(
    connection: ConnectionV1,
    domain: &str,
    rate: RateLimitV1,
) -> LinearPageV1<T> {
    let nodes = connection
        .nodes
        .into_iter()
        .map(|value| {
            let digest = framed_sha256(
                domain,
                &[serde_json::to_string(&value).unwrap_or_default().as_bytes()],
            );
            serde_json::from_value::<T>(value).map_or(PageNodeV1::Malformed(digest), |node| {
                PageNodeV1::Node(Box::new(node))
            })
        })
        .collect();
    let next_cursor = connection
        .page_info
        .end_cursor
        .filter(|cursor| !cursor.is_empty());
    let more = connection.page_info.has_next_page;
    LinearPageV1 {
        nodes,
        unfinished: more && next_cursor.is_none(),
        next_cursor: next_cursor.filter(|_| more),
        rate,
    }
}

/// The team filter of an issue listing, and the instant it reads after.
#[must_use]
pub fn issue_filter(team: &str, since: Option<&str>) -> serde_json::Value {
    let mut filter = serde_json::json!({"team": {"id": {"eq": team}}});
    if let Some(since) = since {
        filter["updatedAt"] = serde_json::json!({"gt": since});
    }
    filter
}

/// The filter of a listing of every comment on one issue.
#[must_use]
pub fn issue_comment_filter(issue: &str) -> serde_json::Value {
    serde_json::json!({"issue": {"id": {"eq": issue}}})
}

/// The filter of a lookup of issues by id.
#[must_use]
pub fn issue_id_filter(ids: &[String]) -> serde_json::Value {
    serde_json::json!({"id": {"in": ids}})
}

/// The filter of a listing of the comments on a team's issues.
#[must_use]
pub fn comment_filter(team: &str, since: Option<&str>) -> serde_json::Value {
    let mut filter = serde_json::json!({"issue": {"team": {"id": {"eq": team}}}});
    if let Some(since) = since {
        filter["updatedAt"] = serde_json::json!({"gt": since});
    }
    filter
}

/// The GraphQL API over one credential.
#[derive(Debug, Clone)]
pub struct LinearApiV1 {
    http: ProviderHttpV1,
    endpoint: String,
    page_size: u32,
}

impl LinearApiV1 {
    /// The API at `endpoint` (a method path under `http`'s base), reading
    /// `page_size` nodes per page.
    #[must_use]
    pub fn new(http: ProviderHttpV1, endpoint: impl Into<String>, page_size: u32) -> Self {
        Self {
            http,
            endpoint: endpoint.into(),
            page_size,
        }
    }

    async fn call(
        &self,
        operation: &str,
        query: &str,
        variables: serde_json::Value,
    ) -> Result<ProviderResponseV1, LinearCallErrorV1> {
        let body = serde_json::json!({
            "operationName": operation,
            "query": query,
            "variables": variables,
        });
        Ok(self.http.post_graphql(&self.endpoint, &body).await?)
    }

    /// The organization, and the teams of `teams` the credential can see.
    ///
    /// # Errors
    ///
    /// Every [`LinearCallErrorV1`].
    pub async fn scope(&self, teams: &[String]) -> Result<LinearScopeV1, LinearCallErrorV1> {
        let response = self
            .call(
                "FleetRecallLinearScope",
                SCOPE_QUERY,
                serde_json::json!({"teams": teams}),
            )
            .await?;
        let answer: ScopeAnswerV1 = decode(&response)?;
        Ok(LinearScopeV1 {
            organization: answer.organization,
            teams: answer.teams.nodes,
            rate: RateLimitV1::of(&response),
        })
    }

    /// One page of `team`'s issues updated after `since` (all of them when
    /// `None`), from `after`.
    ///
    /// # Errors
    ///
    /// Every [`LinearCallErrorV1`].
    pub async fn issues_page(
        &self,
        team: &str,
        since: Option<&str>,
        after: Option<&str>,
    ) -> Result<LinearPageV1<LinearIssueV1>, LinearCallErrorV1> {
        let response = self
            .call(
                "FleetRecallLinearIssues",
                ISSUES_QUERY,
                serde_json::json!({
                    "filter": issue_filter(team, since),
                    "first": self.page_size,
                    "after": after,
                }),
            )
            .await?;
        let answer: IssuesAnswerV1 = decode(&response)?;
        Ok(page(
            answer.issues,
            "ostk-linear-issue-v1",
            RateLimitV1::of(&response),
        ))
    }

    /// One page of the comments on `team`'s issues updated after `since`,
    /// from `after`.
    ///
    /// # Errors
    ///
    /// Every [`LinearCallErrorV1`].
    pub async fn comments_page(
        &self,
        team: &str,
        since: Option<&str>,
        after: Option<&str>,
    ) -> Result<LinearPageV1<LinearCommentV1>, LinearCallErrorV1> {
        let response = self
            .call(
                "FleetRecallLinearComments",
                COMMENTS_QUERY,
                serde_json::json!({
                    "filter": comment_filter(team, since),
                    "first": self.page_size,
                    "after": after,
                }),
            )
            .await?;
        let answer: CommentsAnswerV1 = decode(&response)?;
        Ok(page(
            answer.comments,
            "ostk-linear-comment-v1",
            RateLimitV1::of(&response),
        ))
    }

    /// One page of every comment on `issue`, whatever its `updatedAt`,
    /// from `after`.
    ///
    /// # Errors
    ///
    /// Every [`LinearCallErrorV1`].
    pub async fn issue_comments_page(
        &self,
        issue: &str,
        after: Option<&str>,
    ) -> Result<LinearPageV1<LinearCommentV1>, LinearCallErrorV1> {
        let response = self
            .call(
                "FleetRecallLinearComments",
                COMMENTS_QUERY,
                serde_json::json!({
                    "filter": issue_comment_filter(issue),
                    "first": self.page_size,
                    "after": after,
                }),
            )
            .await?;
        let answer: CommentsAnswerV1 = decode(&response)?;
        Ok(page(
            answer.comments,
            "ostk-linear-comment-v1",
            RateLimitV1::of(&response),
        ))
    }

    /// Where each of `ids` (at most [`MAX_ISSUE_TEAMS_BATCH`]) is now: the
    /// issues the credential can see, by id. An issue missing from the answer
    /// is one it cannot see. A node that does not parse is left out, as if
    /// unseen.
    ///
    /// # Errors
    ///
    /// Every [`LinearCallErrorV1`].
    pub async fn issue_places(
        &self,
        ids: &[String],
    ) -> Result<(Vec<LinearIssuePlaceV1>, RateLimitV1), LinearCallErrorV1> {
        let ids = &ids[..ids.len().min(MAX_ISSUE_TEAMS_BATCH)];
        let response = self
            .call(
                "FleetRecallLinearIssueTeams",
                ISSUE_TEAMS_QUERY,
                serde_json::json!({
                    "filter": issue_id_filter(ids),
                    "first": ids.len(),
                }),
            )
            .await?;
        let answer: IssueTeamsAnswerV1 = decode(&response)?;
        let places = answer
            .issues
            .nodes
            .into_iter()
            .filter_map(|value| serde_json::from_value(value).ok())
            .collect();
        Ok((places, RateLimitV1::of(&response)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, body: &str) -> ProviderResponseV1 {
        ProviderResponseV1 {
            status,
            headers: vec![
                ("x-ratelimit-complexity-remaining".into(), "2999000".into()),
                ("x-ratelimit-requests-remaining".into(), "4999".into()),
            ],
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn the_recorded_issues_page_parses_node_by_node_with_its_cursor() {
        let fixture = response(200, include_str!("fixtures/issues_page.json"));
        let answer: IssuesAnswerV1 = decode(&fixture).unwrap();
        let issues: LinearPageV1<LinearIssueV1> = page(
            answer.issues,
            "ostk-linear-issue-v1",
            RateLimitV1::of(&fixture),
        );
        assert_eq!(issues.nodes.len(), 1);
        assert_eq!(
            issues.next_cursor.as_deref(),
            Some("N2MzZTFhNTItOWI0ZC00ZjZlLThhMjEtM2Q1YzdlOWYxYjIw")
        );
        assert!(!issues.unfinished);
        assert_eq!(
            issues.rate,
            RateLimitV1 {
                requests_remaining: Some(4999),
                complexity_remaining: Some(2_999_000),
            }
        );
        let PageNodeV1::Node(issue) = &issues.nodes[0] else {
            panic!("the recorded issue parses");
        };
        assert_eq!(issue.id, "7c3e1a52-9b4d-4f6e-8a21-3d5c7e9f1b20");
        assert_eq!(issue.identifier, "ENG-412");
        assert_eq!(issue.updated_at, "2026-09-22T09:41:07.113Z");
        assert_eq!(
            issue.state.as_ref().unwrap().name.as_deref(),
            Some("In Progress")
        );
        assert_eq!(
            issue.creator.as_ref().unwrap().id,
            "a11ce000-0000-4000-8000-000000000001"
        );
        assert_eq!(issue.trashed, None);
        assert!(
            !format!("{issue:?}").contains("Retry budget"),
            "no text in Debug"
        );

        let comments = response(200, include_str!("fixtures/comments_page.json"));
        let answer: CommentsAnswerV1 = decode(&comments).unwrap();
        let comments: LinearPageV1<LinearCommentV1> = page(
            answer.comments,
            "ostk-linear-comment-v1",
            RateLimitV1::default(),
        );
        assert_eq!(
            comments.next_cursor, None,
            "hasNextPage=false ends the listing"
        );
        let parsed: Vec<&LinearCommentV1> = comments
            .nodes
            .iter()
            .filter_map(|node| match node {
                PageNodeV1::Node(comment) => Some(comment.as_ref()),
                PageNodeV1::Malformed(_) => None,
            })
            .collect();
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[1].parent.as_ref().map(|parent| parent.id.as_str()),
            Some("d4e5f6a7-0000-4000-8000-00000000c001")
        );
        assert!(matches!(comments.nodes[2], PageNodeV1::Malformed(_)));
    }

    #[test]
    fn an_answer_is_decoded_or_its_errors_classified() {
        let scope: ScopeAnswerV1 = decode(&response(
            200,
            r#"{"data":{"organization":{"id":"0a9c0000-0000-4000-8000-0000000ac3e1"},
                "teams":{"nodes":[{"id":"4e6b8d0f-1a2b-4c3d-9e8f-7a6b5c4d3e2f","key":"ENG",
                "name":"Engineering","visibility":"public"},
                {"id":"t2","key":"SEC","visibility":"private"}]}}}"#,
        ))
        .unwrap();
        assert!(scope.teams.nodes[0].is_public());
        assert!(!scope.teams.nodes[1].is_public());
        let error =
            |status: u16, body: &str| decode::<ScopeAnswerV1>(&response(status, body)).unwrap_err();
        assert_eq!(
            error(
                400,
                r#"{"errors":[{"message":"slow","extensions":{"code":"RATELIMITED"}}]}"#
            ),
            LinearCallErrorV1::RateLimited
        );
        assert_eq!(
            error(
                200,
                r#"{"errors":[{"extensions":{"type":"ratelimited"}}],"data":null}"#
            ),
            LinearCallErrorV1::RateLimited
        );
        assert_eq!(
            error(
                400,
                r#"{"errors":[{"extensions":{"code":"AUTHENTICATION_ERROR"}}]}"#
            ),
            LinearCallErrorV1::Credential("AUTHENTICATION_ERROR".into())
        );
        assert_eq!(
            error(
                200,
                r#"{"errors":[{"extensions":{"type":"authentication error"}}]}"#
            ),
            LinearCallErrorV1::Credential("AUTHENTICATION_ERROR".into())
        );
        assert_eq!(
            error(401, "<html>no</html>"),
            LinearCallErrorV1::Credential("HTTP_401".into())
        );
        assert_eq!(
            error(200, r#"{"errors":[{"extensions":{"code":"FORBIDDEN"}}]}"#),
            LinearCallErrorV1::Refused("FORBIDDEN".into())
        );
        assert_eq!(
            error(
                400,
                r#"{"errors":[{"extensions":{"code":"<b>BAD</b> cursor!"}}]}"#
            ),
            LinearCallErrorV1::Refused("BBADB_CURSOR".into())
        );
        assert_eq!(
            error(200, r#"{"errors":[{"message":"no extensions"}]}"#),
            LinearCallErrorV1::Refused("UNKNOWN_ERROR".into())
        );
        assert_eq!(
            error(404, "not json"),
            LinearCallErrorV1::Http(ProviderHttpErrorV1::Status { status: 404 })
        );
        assert!(matches!(
            error(200, "<html>"),
            LinearCallErrorV1::Malformed(_)
        ));
        assert!(matches!(
            error(200, r#"{"data":null}"#),
            LinearCallErrorV1::Malformed(_)
        ));
        assert!(matches!(
            error(200, r#"{"data":{"organization":{}}}"#),
            LinearCallErrorV1::Malformed(_)
        ));
    }

    #[test]
    fn a_page_without_a_cursor_cannot_be_read_to_its_end() {
        let connection: ConnectionV1 = serde_json::from_str(
            r#"{"nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":null}}"#,
        )
        .unwrap();
        let broken: LinearPageV1<LinearIssueV1> =
            page(connection, "ostk-linear-issue-v1", RateLimitV1::default());
        assert!(broken.unfinished);
        assert_eq!(broken.next_cursor, None);
    }

    #[test]
    fn filters_are_variables_and_name_the_team_and_the_instant() {
        assert_eq!(
            issue_filter("t1", Some("2026-09-22T09:36:07.113Z")),
            serde_json::json!({"team": {"id": {"eq": "t1"}},
                               "updatedAt": {"gt": "2026-09-22T09:36:07.113Z"}})
        );
        assert_eq!(
            issue_filter("t1", None),
            serde_json::json!({"team": {"id": {"eq": "t1"}}})
        );
        assert_eq!(
            comment_filter("t1", None),
            serde_json::json!({"issue": {"team": {"id": {"eq": "t1"}}}})
        );
        for query in [SCOPE_QUERY, ISSUES_QUERY, COMMENTS_QUERY] {
            assert_eq!(
                query.matches('{').count(),
                query.matches('}').count(),
                "{query}"
            );
        }
        assert!(ISSUES_QUERY.contains("includeArchived: true"));
        assert!(COMMENTS_QUERY.contains("orderBy: updatedAt"));
    }
}
