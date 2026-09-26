//! Linear issues and comments as drafts (ADR 0008 D8).
//!
//! * **Identity.** An issue is object kind `issue` and a comment object kind
//!   `comment`, each with its Linear id (a UUID) as external id. An issue's
//!   `identifier` (`ENG-412`) and its team's key are labels: they change when
//!   the issue moves team, so they are in its title and its container's label,
//!   never in its identity. The container is `linear.team`, the issue's team
//!   id, labelled with the team's key.
//! * **Versions.** The marker is Linear's `updatedAt`, exactly as sent, and
//!   the order is its microseconds.
//! * **Lifecycle.** An issue in the trash (`trashed`) is a `trashed`
//!   tombstone: no text, and it hides the item. An archived issue or comment
//!   (`archivedAt`) is an `archived` version that stays searchable. A comment
//!   with `editedAt` is `edited`; anything else is `live`.
//! * **Text.** An issue's title is `<identifier> <title>`, and its markdown
//!   text is its workflow state, then its description. A comment's text is its
//!   markdown body; a comment with none is not an item. A comment's thread root
//!   is its issue, and its parent the comment it replies to, else the issue.
//! * **Links.** An issue links its parent issue (`parent`) and its project
//!   (`project`) by their Linear URLs, and every `http(s)` link in the
//!   markdown is an outbound `url` link, labelled when it is `[label](url)`.
//!   Links are exact strings, so a Slack message that links an issue's URL is
//!   found among the issue's inbound links.
//! * **Authors.** A person (`creator`, `user`) is kept by id only (a display
//!   name is a mutable profile field); a bot (`botActor`) by its id, else its
//!   kind, with its name; an external user by id.

use crate::collectors::draft::{
    CollectedItemDraftV1, DraftAuthorV1, DraftContainerV1, DraftLinkV1, DraftSectionV1,
    DraftThreadV1,
};
use crate::memory_contracts::collected_item::{
    AuthorKindV1, ContainerKindV1, ItemLifecycleV1, LinkRelV1, MAX_LINKS, ObjectKindV1,
    ProviderKindV1, TextFormatV1, provider_timestamp, timestamp_micros,
};
use crate::memory_contracts::common::CanonicalTimestamp;

use super::graphql::{LinearBotV1, LinearCommentV1, LinearIssueV1, LinearRefV1};

/// The provider kind.
pub const LINEAR_PROVIDER: &str = "linear";

/// The object kind of an issue.
pub const ISSUE_OBJECT_KIND: &str = "issue";

/// The object kind of a comment.
pub const COMMENT_OBJECT_KIND: &str = "comment";

/// The container kind of a team.
pub const TEAM_CONTAINER_KIND: &str = "linear.team";

/// The longest Linear id taken as identity.
const MAX_LINEAR_ID_BYTES: usize = 64;

/// Where an issue or comment is read: its organization and team.
#[derive(Debug, Clone, Copy)]
pub struct LinearTeamContextV1<'a> {
    /// The provider kind (`linear`).
    pub provider: &'a ProviderKindV1,
    /// The organization id.
    pub provider_scope_id: &'a str,
    /// The team id.
    pub team_id: &'a str,
    /// The team's key (`ENG`).
    pub team_key: Option<&'a str>,
}

/// Whether `value` can be a Linear id: 1 to 64 ASCII letters, digits, and
/// dashes.
#[must_use]
pub fn is_linear_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LINEAR_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Whether `value` is a lowercase UUID: what a Linear organization or team id
/// is, and how the settings name one.
#[must_use]
pub fn is_lowercase_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn token<T>(parsed: crate::memory_contracts::ContractResult<T>) -> T {
    parsed.unwrap_or_else(|_| unreachable!("the Linear kinds are valid tokens"))
}

fn container(context: &LinearTeamContextV1<'_>) -> DraftContainerV1 {
    DraftContainerV1 {
        kind: token(ContainerKindV1::new(TEAM_CONTAINER_KIND)),
        id: context.team_id.to_owned(),
        label: context.team_key.map(str::to_owned),
    }
}

/// A Linear clock, and its order in microseconds.
fn clock(value: &str) -> Result<(CanonicalTimestamp, u64), &'static str> {
    let timestamp =
        provider_timestamp(value).map_err(|_| "a Linear clock is not an RFC 3339 timestamp")?;
    let micros = timestamp_micros(&timestamp).map_err(|_| "a Linear clock has no order")?;
    Ok((timestamp, micros))
}

/// Every `http(s)` link in markdown, in order, with its label when it is
/// `[label](url)`.
#[must_use]
pub fn markdown_links(text: &str) -> Vec<(String, Option<String>)> {
    let mut links = Vec::new();
    let mut from = 0;
    while let Some(found) = ["https://", "http://"]
        .iter()
        .filter_map(|scheme| text[from..].find(scheme))
        .min()
    {
        let start = from + found;
        let tail = &text[start..];
        let end = tail
            .find(|scalar: char| {
                scalar.is_whitespace()
                    || matches!(scalar, ')' | '(' | '<' | '>' | '"' | '`' | ']' | '[')
            })
            .unwrap_or(tail.len());
        let url = tail[..end].trim_end_matches(['.', ',', ';', ':', '!', '?', '\'', '*', '_']);
        if url.len() > "https://".len() && !links.iter().any(|(seen, _)| seen == url) {
            let label = text[..start].strip_suffix("](").and_then(|before| {
                let open = before.rfind('[')?;
                let label = &before[open + 1..];
                (!label.contains([']', '\n']) && !label.trim().is_empty())
                    .then(|| label.trim().to_owned())
            });
            links.push((url.to_owned(), label));
        }
        from = start + end.max(1);
    }
    links
}

fn push_link(links: &mut Vec<DraftLinkV1>, rel: &str, target: &str, label: Option<&str>) {
    let target = target.trim();
    if target.is_empty()
        || links.len() >= MAX_LINKS
        || links.iter().any(|link| link.target == target)
    {
        return;
    }
    links.push(DraftLinkV1 {
        rel: token(LinkRelV1::new(rel)),
        target: target.to_owned(),
        label: label
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(str::to_owned),
    });
}

fn bot(actor: &LinearBotV1) -> DraftAuthorV1 {
    DraftAuthorV1 {
        id: actor
            .id
            .clone()
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| format!("bot:{}", actor.kind.as_deref().unwrap_or("unknown"))),
        display: actor.name.clone(),
        kind: AuthorKindV1::Bot,
    }
}

fn author(
    person: Option<&LinearRefV1>,
    actor: Option<&LinearBotV1>,
    external: Option<&LinearRefV1>,
) -> Option<DraftAuthorV1> {
    if let Some(person) = person {
        return Some(DraftAuthorV1 {
            id: person.id.clone(),
            display: None,
            kind: AuthorKindV1::Human,
        });
    }
    if let Some(actor) = actor {
        return Some(bot(actor));
    }
    external.map(|external| DraftAuthorV1 {
        id: external.id.clone(),
        display: None,
        kind: AuthorKindV1::External,
    })
}

/// The lifecycle of an issue.
#[must_use]
pub fn issue_lifecycle(issue: &LinearIssueV1) -> ItemLifecycleV1 {
    if issue.trashed == Some(true) {
        ItemLifecycleV1::Trashed
    } else if issue.archived_at.is_some() {
        ItemLifecycleV1::Archived
    } else {
        ItemLifecycleV1::Live
    }
}

/// One issue as a draft, in `context`'s team.
///
/// # Errors
///
/// A static diagnostic when the issue's id or clocks are not what Linear
/// documents; the collector dead-letters it.
pub fn issue_draft(
    context: &LinearTeamContextV1<'_>,
    issue: &LinearIssueV1,
) -> Result<CollectedItemDraftV1, &'static str> {
    if !is_linear_id(&issue.id) {
        return Err("a Linear issue id is not an id");
    }
    let (created_at, _) = clock(&issue.created_at)?;
    let (updated_at, order_micros) = clock(&issue.updated_at)?;
    let lifecycle = issue_lifecycle(issue);
    let tombstone = lifecycle.is_tombstone();
    let (title, sections, links) = if tombstone {
        (None, Vec::new(), Vec::new())
    } else {
        let state = issue
            .state
            .as_ref()
            .and_then(|state| state.name.as_deref())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or("unknown");
        let mut text = format!("State: {state}");
        let description = issue.description.as_deref().unwrap_or_default().trim_end();
        if !description.trim().is_empty() {
            text.push_str("\n\n");
            text.push_str(description);
        }
        let mut links = Vec::new();
        if let Some(parent) = &issue.parent
            && let Some(url) = &parent.url
        {
            push_link(&mut links, "parent", url, None);
        }
        if let Some(project) = &issue.project
            && let Some(url) = &project.url
        {
            push_link(&mut links, "project", url, project.name.as_deref());
        }
        for (url, label) in markdown_links(description) {
            push_link(&mut links, "url", &url, label.as_deref());
        }
        (
            Some(
                format!("{} {}", issue.identifier.trim(), issue.title.trim())
                    .trim()
                    .to_owned(),
            ),
            vec![DraftSectionV1::whole(text)],
            links,
        )
    };
    Ok(CollectedItemDraftV1 {
        provider: context.provider.clone(),
        provider_scope_id: context.provider_scope_id.to_owned(),
        object_kind: token(ObjectKindV1::new(ISSUE_OBJECT_KIND)),
        external_id: issue.id.clone(),
        marker: Some(issue.updated_at.clone()),
        order_micros,
        lifecycle,
        container: Some(container(context)),
        thread: None,
        author: if tombstone {
            None
        } else {
            author(
                issue.creator.as_ref(),
                issue.bot_actor.as_ref(),
                issue.external_user_creator.as_ref(),
            )
        },
        created_at: Some(created_at),
        updated_at: Some(updated_at),
        title,
        sections,
        text_format: TextFormatV1::Markdown,
        links,
        provider_url: issue.url.clone(),
        visibility: None,
    })
}

/// What one comment is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommentDraftV1 {
    /// An item.
    Item(Box<CollectedItemDraftV1>),
    /// Not an item: a comment with no body, or one on something that is not
    /// an issue.
    Skip,
}

/// One comment as a draft, in `context`'s team.
///
/// # Errors
///
/// A static diagnostic when the comment's ids or clocks are not what Linear
/// documents; the collector dead-letters it.
pub fn comment_draft(
    context: &LinearTeamContextV1<'_>,
    comment: &LinearCommentV1,
) -> Result<CommentDraftV1, &'static str> {
    if !is_linear_id(&comment.id) {
        return Err("a Linear comment id is not an id");
    }
    let Some(issue) = &comment.issue else {
        return Ok(CommentDraftV1::Skip);
    };
    if !is_linear_id(&issue.id)
        || comment
            .parent
            .as_ref()
            .is_some_and(|parent| !is_linear_id(&parent.id))
    {
        return Err("a Linear comment's issue or parent is not an id");
    }
    let (created_at, _) = clock(&comment.created_at)?;
    let (updated_at, order_micros) = clock(&comment.updated_at)?;
    let body = comment.body.trim_end();
    if body.trim().is_empty() {
        return Ok(CommentDraftV1::Skip);
    }
    let lifecycle = if comment.archived_at.is_some() {
        ItemLifecycleV1::Archived
    } else if comment.edited_at.is_some() {
        ItemLifecycleV1::Edited
    } else {
        ItemLifecycleV1::Live
    };
    let mut links = Vec::new();
    for (url, label) in markdown_links(body) {
        push_link(&mut links, "url", &url, label.as_deref());
    }
    Ok(CommentDraftV1::Item(Box::new(CollectedItemDraftV1 {
        provider: context.provider.clone(),
        provider_scope_id: context.provider_scope_id.to_owned(),
        object_kind: token(ObjectKindV1::new(COMMENT_OBJECT_KIND)),
        external_id: comment.id.clone(),
        marker: Some(comment.updated_at.clone()),
        order_micros,
        lifecycle,
        container: Some(container(context)),
        thread: Some(DraftThreadV1 {
            root_external_id: issue.id.clone(),
            parent_external_id: Some(
                comment
                    .parent
                    .as_ref()
                    .map_or_else(|| issue.id.clone(), |parent| parent.id.clone()),
            ),
        }),
        author: author(
            comment.user.as_ref(),
            comment.bot_actor.as_ref(),
            comment.external_user.as_ref(),
        ),
        created_at: Some(created_at),
        updated_at: Some(updated_at),
        title: None,
        sections: vec![DraftSectionV1::whole(body.to_owned())],
        text_format: TextFormatV1::Markdown,
        links,
        provider_url: comment.url.clone(),
        visibility: None,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_contracts::collected_item::derive_item_key;

    const ORG: &str = "0a9c0000-0000-4000-8000-0000000ac3e1";
    const TEAM: &str = "4e6b8d0f-1a2b-4c3d-9e8f-7a6b5c4d3e2f";

    fn fixture_issue() -> LinearIssueV1 {
        let page: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/issues_page.json")).unwrap();
        serde_json::from_value(page["data"]["issues"]["nodes"][0].clone()).unwrap()
    }

    fn draft(issue: &LinearIssueV1, team_key: &str) -> CollectedItemDraftV1 {
        let provider = ProviderKindV1::new(LINEAR_PROVIDER).unwrap();
        issue_draft(
            &LinearTeamContextV1 {
                provider: &provider,
                provider_scope_id: ORG,
                team_id: TEAM,
                team_key: Some(team_key),
            },
            issue,
        )
        .unwrap()
    }

    #[test]
    fn the_recorded_issue_is_its_uuid_with_its_identifier_as_a_label() {
        let issue = fixture_issue();
        let draft = draft(&issue, "ENG");
        assert_eq!(draft.external_id, "7c3e1a52-9b4d-4f6e-8a21-3d5c7e9f1b20");
        assert_eq!(draft.object_kind.as_str(), ISSUE_OBJECT_KIND);
        assert_eq!(draft.marker.as_deref(), Some("2026-09-22T09:41:07.113Z"));
        assert_eq!(draft.order_micros, 1_790_070_067_113_000);
        assert_eq!(draft.lifecycle, ItemLifecycleV1::Live);
        assert_eq!(draft.title.as_deref(), Some("ENG-412 Cap worker retries"));
        assert_eq!(
            draft.sections[0].text,
            "State: In Progress\n\nRetry budget for the ingest worker is **3** attempts, \
             exponential backoff.\n\nSee #plat-eng thread."
        );
        let container = draft.container.as_ref().unwrap();
        assert_eq!(
            (
                container.kind.as_str(),
                container.id.as_str(),
                container.label.as_deref()
            ),
            (TEAM_CONTAINER_KIND, TEAM, Some("ENG"))
        );
        let author = draft.author.as_ref().unwrap();
        assert_eq!(author.id, "a11ce000-0000-4000-8000-000000000001");
        assert_eq!(author.kind, AuthorKindV1::Human);
        assert_eq!(author.display, None, "a person's display name is not kept");
        assert!(draft.thread.is_none());
        assert_eq!(
            draft.provider_url.as_deref(),
            Some("https://linear.app/acme-robotics/issue/ENG-412/cap-worker-retries")
        );
    }

    #[test]
    fn the_identifier_is_never_identity() {
        let issue = fixture_issue();
        let mut moved = issue.clone();
        moved.identifier = "OPS-7".to_owned();
        let before = draft(&issue, "ENG");
        let after = draft(&moved, "OPS");
        assert_eq!(before.external_id, after.external_id);
        let key = |draft: &CollectedItemDraftV1| {
            derive_item_key(
                &draft.provider,
                &draft.provider_scope_id,
                &draft.object_kind,
                &draft.external_id,
            )
        };
        assert_eq!(key(&before), key(&after), "a moved issue is the same item");
        assert_ne!(before.title, after.title, "its label is its new identifier");
    }

    #[test]
    fn trashed_is_a_tombstone_and_archived_stays_searchable() {
        let mut issue = fixture_issue();
        issue.archived_at = Some("2026-09-23T00:00:00.000Z".to_owned());
        let archived = draft(&issue, "ENG");
        assert_eq!(archived.lifecycle, ItemLifecycleV1::Archived);
        assert!(!archived.sections.is_empty());
        issue.trashed = Some(true);
        let trashed = draft(&issue, "ENG");
        assert_eq!(trashed.lifecycle, ItemLifecycleV1::Trashed);
        assert!(trashed.sections.is_empty() && trashed.title.is_none());
        assert!(trashed.links.is_empty() && trashed.author.is_none());
        assert_eq!(trashed.order_micros, archived.order_micros);
    }

    #[test]
    fn an_issue_links_its_parent_its_project_and_its_markdown_links() {
        let mut issue = fixture_issue();
        issue.parent = Some(LinearRefV1 {
            id: "p1".into(),
            url: Some("https://linear.app/acme-robotics/issue/ENG-400/parent".into()),
            name: None,
        });
        issue.project = Some(LinearRefV1 {
            id: "9e0b1c2d-0000-4000-8000-0000000000a1".into(),
            url: Some("https://linear.app/acme-robotics/project/ingest-reliability".into()),
            name: Some("Ingest reliability".into()),
        });
        issue.description = Some(
            "See [the thread](https://acme.slack.com/archives/C1/p1790006645000200) and \
             <https://github.com/acme/worker/pull/9>, or https://example.com/a_b. again: \
             https://github.com/acme/worker/pull/9"
                .into(),
        );
        let draft = draft(&issue, "ENG");
        let links: Vec<(&str, &str, Option<&str>)> = draft
            .links
            .iter()
            .map(|link| {
                (
                    link.rel.as_str(),
                    link.target.as_str(),
                    link.label.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            links,
            [
                (
                    "parent",
                    "https://linear.app/acme-robotics/issue/ENG-400/parent",
                    None
                ),
                (
                    "project",
                    "https://linear.app/acme-robotics/project/ingest-reliability",
                    Some("Ingest reliability")
                ),
                (
                    "url",
                    "https://acme.slack.com/archives/C1/p1790006645000200",
                    Some("the thread")
                ),
                ("url", "https://github.com/acme/worker/pull/9", None),
                ("url", "https://example.com/a_b", None),
            ]
        );
        assert!(markdown_links("no links, just http:// and https://").is_empty());
        assert_eq!(
            markdown_links("[x](https://é.example/ü) tail"),
            [("https://é.example/ü".to_owned(), Some("x".to_owned()))]
        );
    }

    #[test]
    fn a_comment_is_threaded_on_its_issue_and_parent() {
        let page: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/comments_page.json")).unwrap();
        let comment: LinearCommentV1 =
            serde_json::from_value(page["data"]["comments"]["nodes"][1].clone()).unwrap();
        let provider = ProviderKindV1::new(LINEAR_PROVIDER).unwrap();
        let context = LinearTeamContextV1 {
            provider: &provider,
            provider_scope_id: ORG,
            team_id: TEAM,
            team_key: Some("ENG"),
        };
        let CommentDraftV1::Item(draft) = comment_draft(&context, &comment).unwrap() else {
            panic!("a comment with a body is an item");
        };
        assert_eq!(draft.object_kind.as_str(), COMMENT_OBJECT_KIND);
        assert_eq!(draft.lifecycle, ItemLifecycleV1::Edited);
        let thread = draft.thread.as_ref().unwrap();
        assert_eq!(
            thread.root_external_id,
            "7c3e1a52-9b4d-4f6e-8a21-3d5c7e9f1b20"
        );
        assert_eq!(
            thread.parent_external_id.as_deref(),
            Some("d4e5f6a7-0000-4000-8000-00000000c001")
        );
        let root: LinearCommentV1 =
            serde_json::from_value(page["data"]["comments"]["nodes"][0].clone()).unwrap();
        let CommentDraftV1::Item(root) = comment_draft(&context, &root).unwrap() else {
            panic!("an item");
        };
        let thread = root.thread.as_ref().unwrap();
        assert_eq!(
            thread.parent_external_id.as_deref(),
            Some(thread.root_external_id.as_str()),
            "a top-level comment replies to its issue"
        );
        assert_eq!(root.links[0].label.as_deref(), Some("the thread"));

        let mut empty = comment.clone();
        empty.body = "  \n".into();
        assert_eq!(
            comment_draft(&context, &empty).unwrap(),
            CommentDraftV1::Skip
        );
        let mut orphan = comment.clone();
        orphan.issue = None;
        assert_eq!(
            comment_draft(&context, &orphan).unwrap(),
            CommentDraftV1::Skip
        );
        let mut broken = comment;
        broken.updated_at = "yesterday".into();
        assert!(comment_draft(&context, &broken).is_err());
    }

    #[test]
    fn ids_and_uuids_are_checked_exactly() {
        assert!(is_lowercase_uuid(ORG));
        assert!(!is_lowercase_uuid(&ORG.to_ascii_uppercase()));
        assert!(!is_lowercase_uuid("0a9c0000-0000-4000-8000-0000000ac3e"));
        assert!(!is_lowercase_uuid("0a9c0000x0000-4000-8000-0000000ac3e1"));
        assert!(!is_lowercase_uuid("ENG"));
        assert!(is_linear_id(TEAM) && is_linear_id("abc-123"));
        assert!(!is_linear_id("") && !is_linear_id("a b") && !is_linear_id(&"a".repeat(65)));
    }
}
