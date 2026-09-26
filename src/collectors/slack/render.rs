//! Slack messages as drafts (ADR 0008 D8).
//!
//! Timestamps, `mrkdwn` rendering, and one message to one
//! [`CollectedItemDraftV1`]. The pull collector and the export importer share
//! it, so a message pulled and the same message imported are the same item.
//!
//! * **Identity.** A message is object kind `message`, external id
//!   `<channel>:<ts>`, with `ts` kept as Slack's exact string (never a float);
//!   its container is `slack.channel` with the channel id, labelled with the
//!   channel's name. A reply's thread root and parent are its thread's root
//!   message; a thread broadcast is one reply, recorded once per
//!   `(channel, ts)`.
//! * **Versions.** The marker is Slack's own: `edited.ts` for an edited
//!   message, else `ts`; the order is the marker's microseconds. An edit is
//!   therefore a new version that supersedes the old one.
//! * **Text.** `mrkdwn` is rendered to text ([`render_mrkdwn`]): `<@U123>`
//!   becomes `@U123`, `<!subteam^S1|@team>` becomes `@S1`, `<#C1|name>`
//!   becomes `#name`, `<url|label>` becomes the label and an outbound link,
//!   `<!here>` becomes `@here`, and `&amp;`, `&lt;`, `&gt;` are unescaped. An
//!   attachment adds its title and text (or its fallback) and its title link.
//! * **Files are links only.** A file adds an outbound `file` link to its
//!   permalink, never its content, and a file link's own access token (a
//!   `t=xox...` query parameter, [`strip_file_token`]) is stripped. A message
//!   whose only content is files is its files' names.
//! * **Authors.** A message with a `bot_id` is a bot's (its `user`, else the
//!   bot id); any other message with a `user` is a person's. No display name
//!   is kept for a person (a mutable profile field); a bot's `username` is.
//! * **What is not an item.** Membership and housekeeping messages
//!   (`channel_join`, `channel_topic`, `pinned_item`, ...) and messages that
//!   render to nothing. A `tombstone` message (a thread root deleted while its
//!   replies remain) is a deletion ([`MessageDraftV1::Tombstone`]).

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::memory_contracts::collected_item::{
    AuthorKindV1, ContainerKindV1, ItemLifecycleV1, LinkRelV1, MAX_LINKS, ObjectKindV1,
    ProviderKindV1, TextFormatV1,
};
use crate::memory_contracts::common::CanonicalTimestamp;

use crate::collectors::draft::{
    CollectedItemDraftV1, DraftAuthorV1, DraftContainerV1, DraftLinkV1, DraftSectionV1,
    DraftThreadV1,
};

/// The provider kind.
pub const SLACK_PROVIDER: &str = "slack";

/// The object kind of one message.
pub const MESSAGE_OBJECT_KIND: &str = "message";

/// The container kind of a channel.
pub const CHANNEL_CONTAINER_KIND: &str = "slack.channel";

/// Subtypes that are an item: an ordinary message, a bot's, a thread
/// broadcast, a file share, a `/me` message.
const ITEM_SUBTYPES: [&str; 4] = [
    "bot_message",
    "thread_broadcast",
    "file_share",
    "me_message",
];

/// The subtype of a deleted thread root whose replies remain.
const TOMBSTONE_SUBTYPE: &str = "tombstone";

/// A Slack message timestamp, kept as its exact string: `<seconds>.<6
/// digits>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlackTsV1 {
    micros: u64,
    text: String,
}

impl SlackTsV1 {
    /// Parse one timestamp; `None` unless it is 1 to 12 digits, a dot, and
    /// exactly 6 digits.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (seconds, fraction) = text.split_once('.')?;
        if seconds.is_empty()
            || seconds.len() > 12
            || fraction.len() != 6
            || !seconds.bytes().all(|byte| byte.is_ascii_digit())
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let micros = seconds
            .parse::<u64>()
            .ok()?
            .checked_mul(1_000_000)?
            .checked_add(fraction.parse::<u64>().ok()?)?;
        Some(Self {
            micros,
            text: text.to_owned(),
        })
    }

    /// The timestamp of an instant in microseconds, as Slack writes it.
    #[must_use]
    pub fn from_micros(micros: u64) -> Self {
        Self {
            micros,
            text: format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000),
        }
    }

    /// The exact string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Microseconds since the epoch.
    #[must_use]
    pub const fn micros(&self) -> u64 {
        self.micros
    }

    /// The instant, when it is one.
    #[must_use]
    pub fn timestamp(&self) -> Option<CanonicalTimestamp> {
        micros_timestamp(self.micros)
    }
}

/// An instant in microseconds as a canonical timestamp.
#[must_use]
pub fn micros_timestamp(micros: u64) -> Option<CanonicalTimestamp> {
    let instant = i64::try_from(micros)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_micros)?;
    CanonicalTimestamp::from_datetime(&instant).ok()
}

/// A message's external id: `<channel>:<ts>`.
#[must_use]
pub fn message_external_id(channel: &str, ts: &str) -> String {
    format!("{channel}:{ts}")
}

/// `edited` on a message.
#[derive(Debug, Clone, Deserialize)]
pub struct SlackEditedV1 {
    /// When it was last edited.
    pub ts: String,
}

/// One file shared in a message; only its name and links are read.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SlackFileV1 {
    /// The file's name.
    #[serde(default)]
    pub name: Option<String>,
    /// The file's title.
    #[serde(default)]
    pub title: Option<String>,
    /// Its permalink in the workspace.
    #[serde(default)]
    pub permalink: Option<String>,
    /// Its download link, which may carry its own token.
    #[serde(default)]
    pub url_private: Option<String>,
}

/// One legacy attachment.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SlackAttachmentV1 {
    /// Its title.
    #[serde(default)]
    pub title: Option<String>,
    /// Where its title links.
    #[serde(default)]
    pub title_link: Option<String>,
    /// Its text.
    #[serde(default)]
    pub text: Option<String>,
    /// Its plain-text fallback.
    #[serde(default)]
    pub fallback: Option<String>,
    /// The URL it unfurls.
    #[serde(default)]
    pub from_url: Option<String>,
}

/// A bot's profile.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SlackBotProfileV1 {
    /// The bot's name.
    #[serde(default)]
    pub name: Option<String>,
}

/// One message as `conversations.history`, `conversations.replies`, and an
/// export's day files carry it. Unknown and volatile fields (reactions,
/// reply users, blocks, `client_msg_id`) are ignored.
#[derive(Clone, Deserialize)]
pub struct SlackMessageV1 {
    /// The subtype, for anything but an ordinary message.
    #[serde(default)]
    pub subtype: Option<String>,
    /// Its timestamp: its id in the channel.
    pub ts: String,
    /// Its thread root's timestamp, when it is in a thread.
    #[serde(default)]
    pub thread_ts: Option<String>,
    /// Its author.
    #[serde(default)]
    pub user: Option<String>,
    /// Its bot, when a bot posted it.
    #[serde(default)]
    pub bot_id: Option<String>,
    /// A bot's display name.
    #[serde(default)]
    pub username: Option<String>,
    /// Its `mrkdwn` text.
    #[serde(default)]
    pub text: Option<String>,
    /// Its last edit.
    #[serde(default)]
    pub edited: Option<SlackEditedV1>,
    /// Replies in its thread, on a root.
    #[serde(default)]
    pub reply_count: Option<u64>,
    /// Its newest reply's timestamp, on a root.
    #[serde(default)]
    pub latest_reply: Option<String>,
    /// Files it shares.
    #[serde(default)]
    pub files: Vec<SlackFileV1>,
    /// Legacy attachments.
    #[serde(default)]
    pub attachments: Vec<SlackAttachmentV1>,
    /// A bot's profile.
    #[serde(default)]
    pub bot_profile: Option<SlackBotProfileV1>,
}

/// Identity only: a message is provider content and is never logged.
impl std::fmt::Debug for SlackMessageV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SlackMessageV1")
            .field("subtype", &self.subtype)
            .field("ts", &self.ts)
            .field("thread_ts", &self.thread_ts)
            .field("text_bytes", &self.text.as_deref().map_or(0, str::len))
            .finish_non_exhaustive()
    }
}

impl SlackMessageV1 {
    /// Whether it is a thread's reply (a broadcast included), as opposed to a
    /// channel-level message or a thread's root.
    #[must_use]
    pub fn is_reply(&self) -> bool {
        self.thread_ts
            .as_deref()
            .is_some_and(|thread| thread != self.ts)
    }

    /// Its newest reply's timestamp, when it is a thread root with replies.
    #[must_use]
    pub fn latest_reply(&self) -> Option<SlackTsV1> {
        if self.is_reply() {
            return None;
        }
        self.latest_reply
            .as_deref()
            .and_then(SlackTsV1::parse)
            .filter(|_| self.reply_count.unwrap_or(1) > 0)
    }
}

/// `mrkdwn` rendered to text, with the links it held.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenderedTextV1 {
    /// The text.
    pub text: String,
    /// Outbound links, in order of appearance.
    pub links: Vec<(String, Option<String>)>,
}

/// Undo Slack's three escapes.
#[must_use]
pub fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Render one special `<...>` sequence's inside, adding a link when it is
/// one.
fn render_special(inner: &str, rendered: &mut RenderedTextV1) {
    let (target, label) = match inner.split_once('|') {
        Some((target, label)) => (target, Some(unescape(label))),
        None => (inner, None),
    };
    if let Some(user) = target.strip_prefix('@') {
        rendered.text.push('@');
        rendered.text.push_str(user);
    } else if let Some(channel) = target.strip_prefix('#') {
        rendered.text.push('#');
        rendered
            .text
            .push_str(label.as_deref().unwrap_or(channel).trim_start_matches('#'));
    } else if let Some(command) = target.strip_prefix('!') {
        if let Some(group) = command.strip_prefix("subteam^") {
            rendered.text.push('@');
            rendered.text.push_str(group);
        } else if matches!(command, "here" | "channel" | "everyone") {
            rendered.text.push('@');
            rendered.text.push_str(command);
        } else if let Some(label) = label {
            // `<!date^...|fallback>` and anything else Slack gives a
            // fallback for.
            rendered.text.push_str(&label);
        }
    } else {
        let url = unescape(target);
        rendered.text.push_str(label.as_deref().unwrap_or(&url));
        if url.contains(':') {
            rendered.links.push((url, label));
        }
    }
}

/// Render `mrkdwn` to text. See the module documentation.
#[must_use]
pub fn render_mrkdwn(raw: &str) -> RenderedTextV1 {
    let mut rendered = RenderedTextV1::default();
    let mut rest = raw;
    while let Some(open) = rest.find('<') {
        rendered.text.push_str(&unescape(&rest[..open]));
        let after = &rest[open + 1..];
        let Some(close) = after.find('>') else {
            rendered.text.push_str(&unescape(&rest[open..]));
            rest = "";
            break;
        };
        render_special(&after[..close], &mut rendered);
        rest = &after[close + 1..];
    }
    rendered.text.push_str(&unescape(rest));
    rendered
}

/// Strip a file link's own access token: every `t` query parameter whose
/// value is a Slack token (`xox...`). Anything else is left exactly as it was.
#[must_use]
pub fn strip_file_token(link: &str) -> String {
    let Ok(mut url) = url::Url::parse(link) else {
        return link.to_owned();
    };
    let has_token = url
        .query_pairs()
        .any(|(key, value)| key == "t" && value.starts_with("xox"));
    if !has_token {
        return link.to_owned();
    }
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, value)| !(key == "t" && value.starts_with("xox")))
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    if kept.is_empty() {
        url.set_query(None);
    } else {
        url.query_pairs_mut().clear().extend_pairs(kept);
    }
    url.to_string()
}

/// Where a message is read: its provider scope and channel.
#[derive(Debug, Clone, Copy)]
pub struct SlackChannelContextV1<'a> {
    /// The provider kind (`slack`).
    pub provider: &'a ProviderKindV1,
    /// The team id.
    pub provider_scope_id: &'a str,
    /// The channel id.
    pub channel_id: &'a str,
    /// The channel's name.
    pub channel_label: Option<&'a str>,
    /// The workspace's https URL (`https://acme.slack.com`), for permalinks.
    pub workspace_url: Option<&'a str>,
}

/// What one message is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageDraftV1 {
    /// An item.
    Item(Box<CollectedItemDraftV1>),
    /// A deleted thread root whose replies remain: the collector hides the
    /// item when the memory holds it.
    Tombstone,
    /// Not an item: a membership or housekeeping message, or nothing to
    /// read.
    Skip,
}

fn token<T>(parsed: crate::memory_contracts::ContractResult<T>) -> T {
    parsed.unwrap_or_else(|_| unreachable!("the Slack kinds are valid tokens"))
}

fn object_kind() -> ObjectKindV1 {
    token(ObjectKindV1::new(MESSAGE_OBJECT_KIND))
}

fn container(context: &SlackChannelContextV1<'_>) -> DraftContainerV1 {
    DraftContainerV1 {
        kind: token(ContainerKindV1::new(CHANNEL_CONTAINER_KIND)),
        id: context.channel_id.to_owned(),
        label: context.channel_label.map(str::to_owned),
    }
}

/// The message's permalink in the workspace.
fn permalink(
    context: &SlackChannelContextV1<'_>,
    ts: &str,
    thread: Option<&str>,
) -> Option<String> {
    let workspace = context.workspace_url?;
    let digits: String = ts.chars().filter(char::is_ascii_digit).collect();
    let mut link = format!(
        "{}/archives/{}/p{digits}",
        workspace.trim_end_matches('/'),
        context.channel_id
    );
    if let Some(thread) = thread {
        link.push_str("?thread_ts=");
        link.push_str(thread);
        link.push_str("&cid=");
        link.push_str(context.channel_id);
    }
    Some(link)
}

fn push_link(links: &mut Vec<DraftLinkV1>, rel: &str, target: &str, label: Option<String>) {
    let target = strip_file_token(target.trim());
    if target.is_empty()
        || links.len() >= MAX_LINKS
        || links.iter().any(|link| link.target == target)
    {
        return;
    }
    links.push(DraftLinkV1 {
        rel: token(LinkRelV1::new(rel)),
        target,
        label: label.filter(|label| !label.trim().is_empty()),
    });
}

/// A thread reply's thread, or `None` for a channel-level message or a root.
fn thread(context: &SlackChannelContextV1<'_>, message: &SlackMessageV1) -> Option<DraftThreadV1> {
    let root = message
        .thread_ts
        .as_deref()
        .filter(|_| message.is_reply())?;
    let root = message_external_id(context.channel_id, root);
    Some(DraftThreadV1 {
        root_external_id: root.clone(),
        parent_external_id: Some(root),
    })
}

fn author(message: &SlackMessageV1) -> Option<DraftAuthorV1> {
    if let Some(bot) = &message.bot_id {
        return Some(DraftAuthorV1 {
            id: message.user.clone().unwrap_or_else(|| bot.clone()),
            display: message.username.clone().or_else(|| {
                message
                    .bot_profile
                    .as_ref()
                    .and_then(|profile| profile.name.clone())
            }),
            kind: AuthorKindV1::Bot,
        });
    }
    message.user.as_ref().map(|user| DraftAuthorV1 {
        id: user.clone(),
        display: None,
        kind: AuthorKindV1::Human,
    })
}

/// One message's text and links: its `mrkdwn`, its attachments, its files.
fn body(message: &SlackMessageV1) -> (String, Vec<DraftLinkV1>) {
    let mut paragraphs = Vec::new();
    let mut links = Vec::new();
    let rendered = render_mrkdwn(message.text.as_deref().unwrap_or_default());
    if !rendered.text.trim().is_empty() {
        paragraphs.push(rendered.text.trim_end().to_owned());
    }
    for (target, label) in rendered.links {
        push_link(&mut links, "url", &target, label);
    }
    for attachment in &message.attachments {
        let title = attachment
            .title
            .as_deref()
            .map(|title| render_mrkdwn(title).text);
        let text = attachment
            .text
            .as_deref()
            .map(render_mrkdwn)
            .filter(|text| !text.text.trim().is_empty());
        let titled = title.as_deref().filter(|title| !title.trim().is_empty());
        if let Some(title) = titled {
            paragraphs.push(title.trim_end().to_owned());
        }
        let described = text.is_some();
        if let Some(text) = text {
            paragraphs.push(text.text.trim_end().to_owned());
            for (target, label) in text.links {
                push_link(&mut links, "url", &target, label);
            }
        }
        if titled.is_none()
            && !described
            && let Some(fallback) = attachment
                .fallback
                .as_deref()
                .filter(|fallback| !fallback.trim().is_empty())
        {
            paragraphs.push(render_mrkdwn(fallback).text.trim_end().to_owned());
        }
        for link in [&attachment.title_link, &attachment.from_url]
            .into_iter()
            .flatten()
        {
            push_link(&mut links, "url", link, title.clone());
        }
    }
    let mut names = Vec::new();
    for file in &message.files {
        let name = file.name.clone().or_else(|| file.title.clone());
        if let Some(target) = file.permalink.as_ref().or(file.url_private.as_ref()) {
            push_link(&mut links, "file", target, name.clone());
        }
        if let Some(name) = name.filter(|name| !name.trim().is_empty()) {
            names.push(format!("[file: {}]", name.trim()));
        }
    }
    if paragraphs.is_empty() && !names.is_empty() {
        paragraphs.push(names.join(" "));
    }
    (paragraphs.join("\n"), links)
}

/// One message as a draft, in `context`'s channel. `ts` must already have
/// parsed ([`SlackTsV1::parse`]).
#[must_use]
pub fn message_draft(
    context: &SlackChannelContextV1<'_>,
    message: &SlackMessageV1,
) -> MessageDraftV1 {
    let Some(ts) = SlackTsV1::parse(&message.ts) else {
        return MessageDraftV1::Skip;
    };
    match message.subtype.as_deref() {
        None => {}
        Some(TOMBSTONE_SUBTYPE) => return MessageDraftV1::Tombstone,
        Some(subtype) if ITEM_SUBTYPES.contains(&subtype) => {}
        Some(_) => return MessageDraftV1::Skip,
    }
    let (text, links) = body(message);
    if text.trim().is_empty() {
        return MessageDraftV1::Skip;
    }
    let edited = message
        .edited
        .as_ref()
        .and_then(|edited| SlackTsV1::parse(&edited.ts));
    let marker = edited.clone().unwrap_or_else(|| ts.clone());
    let thread = thread(context, message);
    MessageDraftV1::Item(Box::new(CollectedItemDraftV1 {
        provider: context.provider.clone(),
        provider_scope_id: context.provider_scope_id.to_owned(),
        object_kind: object_kind(),
        external_id: message_external_id(context.channel_id, ts.as_str()),
        marker: Some(marker.as_str().to_owned()),
        order_micros: marker.micros(),
        lifecycle: if edited.is_some() {
            ItemLifecycleV1::Edited
        } else {
            ItemLifecycleV1::Live
        },
        container: Some(container(context)),
        provider_url: permalink(
            context,
            ts.as_str(),
            thread.as_ref().and(message.thread_ts.as_deref()),
        ),
        thread,
        author: author(message),
        created_at: ts.timestamp(),
        updated_at: edited.and_then(|edited| edited.timestamp()),
        title: None,
        sections: vec![DraftSectionV1::whole(text)],
        text_format: TextFormatV1::SlackMrkdwnRendered,
        links,
        visibility: None,
    }))
}

/// A deletion of the message `external_id` in `context`'s channel, at
/// `order_micros`: no text, its thread kept.
#[must_use]
pub fn tombstone_draft(
    context: &SlackChannelContextV1<'_>,
    external_id: &str,
    thread_root: Option<&str>,
    order_micros: u64,
) -> CollectedItemDraftV1 {
    CollectedItemDraftV1 {
        provider: context.provider.clone(),
        provider_scope_id: context.provider_scope_id.to_owned(),
        object_kind: object_kind(),
        external_id: external_id.to_owned(),
        marker: None,
        order_micros,
        lifecycle: ItemLifecycleV1::Deleted,
        container: Some(container(context)),
        thread: thread_root
            .filter(|root| *root != external_id)
            .map(|root| DraftThreadV1 {
                root_external_id: root.to_owned(),
                parent_external_id: Some(root.to_owned()),
            }),
        author: None,
        created_at: None,
        updated_at: None,
        title: None,
        sections: Vec::new(),
        text_format: TextFormatV1::SlackMrkdwnRendered,
        links: Vec::new(),
        provider_url: None,
        visibility: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HISTORY: &str = include_str!("fixtures/conversations_history.json");
    const REPLIES: &str = include_str!("fixtures/conversations_replies.json");

    fn messages(page: &str) -> Vec<SlackMessageV1> {
        let value: serde_json::Value = serde_json::from_str(page).unwrap();
        serde_json::from_value(value["messages"].clone()).unwrap()
    }

    fn context(provider: &ProviderKindV1) -> SlackChannelContextV1<'_> {
        SlackChannelContextV1 {
            provider,
            provider_scope_id: "T07ACME0001",
            channel_id: "C07PLATENG1",
            channel_label: Some("plat-eng"),
            workspace_url: Some("https://acme-robotics.slack.com/"),
        }
    }

    fn item(draft: MessageDraftV1) -> CollectedItemDraftV1 {
        match draft {
            MessageDraftV1::Item(draft) => *draft,
            other => panic!("expected an item, got {other:?}"),
        }
    }

    #[test]
    fn a_timestamp_is_exact_and_ordered_by_its_microseconds() {
        let ts = SlackTsV1::parse("1790006645.000200").unwrap();
        assert_eq!(ts.micros(), 1_790_006_645_000_200);
        assert_eq!(ts.as_str(), "1790006645.000200");
        assert_eq!(SlackTsV1::from_micros(ts.micros()), ts);
        assert_eq!(
            ts.timestamp().unwrap().as_str(),
            "2026-09-21T16:04:05.000200000Z"
        );
        for bad in [
            "1790006645.0002",
            "1790006645",
            "a.000200",
            ".000200",
            "1e9.000000",
        ] {
            assert!(SlackTsV1::parse(bad).is_none(), "{bad}");
        }
        assert!(SlackTsV1::parse("9.000001") < SlackTsV1::parse("10.000000"));
    }

    #[test]
    fn mrkdwn_renders_mentions_channels_links_and_entities() {
        let rendered = render_mrkdwn(
            "cc <@U07ALICE001> and <!subteam^S07PLAT001|@plat> in <#C07PLATENG1|plat-eng> \
             &amp; <#C99> <!here>: see <https://linear.app/acme/issue/ENG-412|ENG-412> or \
             <https://example.com/a?b=1&amp;c=2> on <!date^1392734382^{date}|Feb 18> &lt;3 <oops",
        );
        assert_eq!(
            rendered.text,
            "cc @U07ALICE001 and @S07PLAT001 in #plat-eng & #C99 @here: see ENG-412 or \
             https://example.com/a?b=1&c=2 on Feb 18 <3 <oops"
        );
        assert_eq!(
            rendered.links,
            [
                (
                    "https://linear.app/acme/issue/ENG-412".to_owned(),
                    Some("ENG-412".to_owned())
                ),
                ("https://example.com/a?b=1&c=2".to_owned(), None),
            ]
        );
        assert_eq!(render_mrkdwn("plain").text, "plain");
    }

    #[test]
    fn a_file_token_is_stripped_and_nothing_else_changes() {
        let secret = "xoxe-EXAMPLE-NOT-A-FILE-TOKEN";
        assert_eq!(
            strip_file_token(&format!(
                "https://files.slack.com/files-pri/T1-F1/spec.md?t={secret}"
            )),
            "https://files.slack.com/files-pri/T1-F1/spec.md"
        );
        assert_eq!(
            strip_file_token(&format!("https://files.slack.com/f?x=1&t={secret}&y=2")),
            "https://files.slack.com/f?x=1&y=2"
        );
        for kept in [
            "https://files.slack.com/f?t=123",
            "https://example.com/a?b=1&amp;c",
            "not a url",
        ] {
            assert_eq!(strip_file_token(kept), kept);
        }
    }

    #[test]
    fn the_history_fixture_parses_into_drafts() {
        let provider = ProviderKindV1::new(SLACK_PROVIDER).unwrap();
        let context = context(&provider);
        let history = messages(HISTORY);
        assert_eq!(history.len(), 4);

        let file = item(message_draft(&context, &history[0]));
        assert_eq!(file.external_id, "C07PLATENG1:1790068531.002000");
        assert_eq!(file.sections[0].text, "Retry budget spec draft attached");
        assert_eq!(file.links.len(), 1);
        assert_eq!(file.links[0].rel.as_str(), "file");
        assert_eq!(
            file.links[0].target,
            "https://acme-robotics.slack.com/files/U07BOB0002/F07SPEC0001/retry-budget.md"
        );
        assert_eq!(file.links[0].label.as_deref(), Some("retry-budget.md"));

        let bot = item(message_draft(&context, &history[1]));
        let author = bot.author.as_ref().unwrap();
        assert_eq!(
            (author.id.as_str(), author.kind, author.display.as_deref()),
            ("B07LINEAR01", AuthorKindV1::Bot, Some("Linear"))
        );
        assert_eq!(
            bot.sections[0].text,
            "ENG-412 Cap worker retries\nStatus: In Progress"
        );
        assert_eq!(
            bot.links[0].target,
            "https://linear.app/acme-robotics/issue/ENG-412/cap-worker-retries"
        );

        let broadcast = item(message_draft(&context, &history[2]));
        let thread = broadcast.thread.as_ref().unwrap();
        assert_eq!(thread.root_external_id, "C07PLATENG1:1790006645.000200");
        assert_eq!(
            broadcast.provider_url.as_deref(),
            Some(
                "https://acme-robotics.slack.com/archives/C07PLATENG1/p1790007122004300?\
                 thread_ts=1790006645.000200&cid=C07PLATENG1"
            )
        );

        let root = item(message_draft(&context, &history[3]));
        assert!(root.thread.is_none(), "a root is not a reply");
        assert_eq!(root.lifecycle, ItemLifecycleV1::Edited);
        assert_eq!(root.marker.as_deref(), Some("1790007611.000000"));
        assert_eq!(root.order_micros, 1_790_007_611_000_000);
        assert_eq!(
            root.created_at.as_ref().map(CanonicalTimestamp::as_str),
            Some("2026-09-21T16:04:05.000200000Z")
        );
        assert_eq!(
            root.sections[0].text,
            "Should the ingest worker retry budget be 3 or 5? cc @S07PLAT001"
        );
        assert_eq!(root.text_format, TextFormatV1::SlackMrkdwnRendered);
        assert_eq!(
            history[3].latest_reply().map(|ts| ts.micros()),
            Some(1_790_007_122_004_300)
        );
        assert_eq!(history[2].latest_reply(), None, "a broadcast is a reply");
    }

    #[test]
    fn the_replies_fixture_parses_and_a_broadcast_is_the_same_item_in_both() {
        let provider = ProviderKindV1::new(SLACK_PROVIDER).unwrap();
        let context = context(&provider);
        let replies = messages(REPLIES);
        assert!(!replies[0].is_reply(), "the first message is the root");
        let reply = item(message_draft(&context, &replies[1]));
        assert_eq!(reply.external_id, "C07PLATENG1:1790006860.001100");
        assert_eq!(reply.sections[0].text, "3 — see ENG-412");
        assert_eq!(
            reply.thread.as_ref().unwrap().parent_external_id.as_deref(),
            Some("C07PLATENG1:1790006645.000200")
        );
        assert_eq!(reply.author.as_ref().unwrap().kind, AuthorKindV1::Human);
        let in_replies = item(message_draft(&context, &replies[2]));
        let in_history = item(message_draft(&context, &messages(HISTORY)[2]));
        assert_eq!(
            in_replies, in_history,
            "a thread broadcast is one item, whichever listing carried it"
        );
    }

    #[test]
    fn housekeeping_empty_and_tombstone_messages_are_not_items() {
        let provider = ProviderKindV1::new(SLACK_PROVIDER).unwrap();
        let context = context(&provider);
        let parse =
            |value: serde_json::Value| -> SlackMessageV1 { serde_json::from_value(value).unwrap() };
        let join = parse(serde_json::json!({
            "subtype": "channel_join", "ts": "1790000000.000100", "user": "U1",
            "text": "<@U1> has joined the channel"
        }));
        assert_eq!(message_draft(&context, &join), MessageDraftV1::Skip);
        let empty =
            parse(serde_json::json!({"ts": "1790000000.000200", "user": "U1", "text": " "}));
        assert_eq!(message_draft(&context, &empty), MessageDraftV1::Skip);
        let tombstone = parse(serde_json::json!({
            "subtype": "tombstone", "ts": "1790000000.000300", "text": "This message was deleted.",
            "reply_count": 2
        }));
        assert_eq!(
            message_draft(&context, &tombstone),
            MessageDraftV1::Tombstone
        );
        let only_file = parse(serde_json::json!({
            "subtype": "file_share", "ts": "1790000000.000400", "user": "U1", "text": "",
            "files": [{"name": "plan.pdf", "url_private":
                "https://files.slack.com/files-pri/T1-F2/plan.pdf?t=xoxe-EXAMPLE-NOT-A-FILE-TOKEN"}]
        }));
        let draft = item(message_draft(&context, &only_file));
        assert_eq!(draft.sections[0].text, "[file: plan.pdf]");
        assert_eq!(
            draft.links[0].target,
            "https://files.slack.com/files-pri/T1-F2/plan.pdf"
        );
        let deleted = tombstone_draft(
            &context,
            "C07PLATENG1:1790000000.000500",
            Some("C07PLATENG1:1790000000.000300"),
            7,
        );
        assert_eq!(deleted.lifecycle, ItemLifecycleV1::Deleted);
        assert!(deleted.sections.is_empty());
        assert_eq!(
            deleted.thread.unwrap().root_external_id,
            "C07PLATENG1:1790000000.000300"
        );
    }
}
