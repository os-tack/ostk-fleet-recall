//! The Slack Web API methods the collector calls, over the provider HTTP
//! seam (ADR 0008 D8).
//!
//! Every method is a `GET` with the bot token in the `Authorization` header:
//! `auth.test`, `conversations.info`, `conversations.history`, and
//! `conversations.replies`. Slack answers most failures as HTTP 200 with
//! `ok: false` and an error code; [`SlackCallErrorV1`] tells a rate limit, a
//! broken credential (which fails the whole pass), and a refusal of one
//! channel (`not_in_channel`, `missing_scope`, `channel_not_found`) apart.
//! A page's messages are parsed one by one, so one malformed message is one
//! dead letter rather than a lost page.

use serde::Deserialize;

use crate::collectors::audience::ProviderAudienceV1;
use crate::collectors::cockroach::framed_sha256;
use crate::collectors::http::{ProviderHttpErrorV1, ProviderHttpV1};
use crate::memory_contracts::digest::Sha256Digest;

use super::render::SlackMessageV1;

/// Error codes that mean the credential itself is unusable: the pass fails.
const CREDENTIAL_ERRORS: [&str; 8] = [
    "invalid_auth",
    "not_authed",
    "token_revoked",
    "token_expired",
    "account_inactive",
    "no_permission",
    "not_allowed_token_type",
    "team_access_not_granted",
];

/// Longest error code kept.
const MAX_ERROR_CODE_BYTES: usize = 64;

/// Why one Slack call gave no usable answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SlackCallErrorV1 {
    /// Rate-limited: HTTP 429, or `ok: false` with `ratelimited`.
    #[error("Slack rate-limited the call")]
    RateLimited,
    /// The credential is unusable (`invalid_auth`, `token_revoked`, ...).
    #[error("Slack refused the credential: {0}")]
    Credential(String),
    /// Slack refused the call for this channel or thread
    /// (`not_in_channel`, `missing_scope`, `channel_not_found`, ...).
    #[error("Slack refused the call: {0}")]
    Refused(String),
    /// The request failed below Slack's own answer.
    #[error("{0}")]
    Http(ProviderHttpErrorV1),
    /// The answer is not the documented shape.
    #[error("Slack's answer is malformed: {0}")]
    Malformed(&'static str),
}

impl From<ProviderHttpErrorV1> for SlackCallErrorV1 {
    fn from(error: ProviderHttpErrorV1) -> Self {
        match error {
            ProviderHttpErrorV1::RateLimited { .. } => Self::RateLimited,
            other => Self::Http(other),
        }
    }
}

/// An error code as Slack sent it, cut to the characters an error code has.
fn error_code(code: Option<&str>) -> String {
    let code: String = code
        .unwrap_or("unknown_error")
        .chars()
        .filter(|scalar| scalar.is_ascii_alphanumeric() || *scalar == '_')
        .take(MAX_ERROR_CODE_BYTES)
        .collect();
    if code.is_empty() {
        "unknown_error".to_owned()
    } else {
        code
    }
}

#[derive(Deserialize)]
struct StatusV1 {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}

/// Decode one answer, mapping `ok: false` to its error.
fn decode<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, SlackCallErrorV1> {
    let status: StatusV1 = serde_json::from_slice(body)
        .map_err(|_| SlackCallErrorV1::Malformed("not a Slack answer"))?;
    if !status.ok {
        let code = error_code(status.error.as_deref());
        return Err(if code == "ratelimited" {
            SlackCallErrorV1::RateLimited
        } else if CREDENTIAL_ERRORS.contains(&code.as_str()) {
            SlackCallErrorV1::Credential(code)
        } else {
            SlackCallErrorV1::Refused(code)
        });
    }
    serde_json::from_slice(body)
        .map_err(|_| SlackCallErrorV1::Malformed("an unexpected field shape"))
}

/// What `auth.test` says the token belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SlackAuthV1 {
    /// The workspace.
    pub team_id: String,
    /// The Enterprise Grid organization, on an org install.
    #[serde(default)]
    pub enterprise_id: Option<String>,
    /// The workspace's URL (`https://acme.slack.com/`).
    #[serde(default)]
    pub url: Option<String>,
}

/// One conversation, as `conversations.info` describes it. Only the audience
/// flags and the name are read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // Slack's own flags, read as it sends them
pub struct SlackChannelInfoV1 {
    /// The channel id.
    pub id: String,
    /// Its name.
    #[serde(default)]
    pub name: Option<String>,
    /// A direct conversation.
    #[serde(default)]
    pub is_im: bool,
    /// A group-direct conversation.
    #[serde(default)]
    pub is_mpim: bool,
    /// A private channel.
    #[serde(default)]
    pub is_private: bool,
    /// Shared with another organization (Slack Connect).
    #[serde(default)]
    pub is_ext_shared: bool,
    /// Invited to be shared with another organization.
    #[serde(default)]
    pub is_pending_ext_shared: bool,
    /// Shared with other workspaces of the same Enterprise Grid organization.
    #[serde(default)]
    pub is_org_shared: bool,
}

impl SlackChannelInfoV1 {
    /// Who Slack says can read the channel: a direct conversation, a
    /// channel shared outside the organization, a private or org-shared one
    /// (restricted to some members of this workspace), or a public one.
    #[must_use]
    pub const fn audience(&self) -> ProviderAudienceV1 {
        if self.is_im || self.is_mpim {
            ProviderAudienceV1::DirectMessage
        } else if self.is_ext_shared || self.is_pending_ext_shared {
            ProviderAudienceV1::ExternallyShared
        } else if self.is_private || self.is_org_shared {
            ProviderAudienceV1::Restricted
        } else {
            ProviderAudienceV1::ScopePublic
        }
    }
}

#[derive(Deserialize)]
struct InfoAnswerV1 {
    channel: SlackChannelInfoV1,
}

#[derive(Deserialize, Default)]
struct ResponseMetadataV1 {
    #[serde(default)]
    next_cursor: Option<String>,
}

#[derive(Deserialize)]
struct PageAnswerV1 {
    #[serde(default)]
    messages: Vec<serde_json::Value>,
    #[serde(default)]
    has_more: bool,
    #[serde(default)]
    response_metadata: Option<ResponseMetadataV1>,
}

/// One message of a page: parsed, or the digest of what did not parse.
#[derive(Debug, Clone)]
pub enum PageMessageV1 {
    /// The message.
    Message(Box<SlackMessageV1>),
    /// A message that is not the documented shape: the digest of its JSON.
    Malformed(Sha256Digest),
}

/// One page of a listing.
#[derive(Debug, Clone)]
pub struct SlackPageV1 {
    /// Its messages, in Slack's order.
    pub messages: Vec<PageMessageV1>,
    /// Where the next page starts, when there is one.
    pub next_cursor: Option<String>,
    /// Slack said there is more but gave no cursor: the listing cannot be
    /// read to its end.
    pub unfinished: bool,
}

fn page(answer: PageAnswerV1) -> SlackPageV1 {
    let next_cursor = answer
        .response_metadata
        .and_then(|metadata| metadata.next_cursor)
        .filter(|cursor| !cursor.is_empty());
    let messages = answer
        .messages
        .into_iter()
        .map(|value| {
            let digest = framed_sha256(
                "ostk-slack-message-v1",
                &[serde_json::to_string(&value).unwrap_or_default().as_bytes()],
            );
            serde_json::from_value::<SlackMessageV1>(value)
                .map_or(PageMessageV1::Malformed(digest), |message| {
                    PageMessageV1::Message(Box::new(message))
                })
        })
        .collect();
    SlackPageV1 {
        messages,
        unfinished: answer.has_more && next_cursor.is_none(),
        next_cursor: next_cursor.filter(|_| answer.has_more),
    }
}

/// The Web API over one workspace's bot token.
#[derive(Debug, Clone)]
pub struct SlackApiV1 {
    http: ProviderHttpV1,
    page_size: String,
}

impl SlackApiV1 {
    /// The API over `http`, reading `page_size` messages per page.
    #[must_use]
    pub fn new(http: ProviderHttpV1, page_size: u32) -> Self {
        Self {
            http,
            page_size: page_size.to_string(),
        }
    }

    async fn call(
        &self,
        method: &str,
        query: &[(&str, &str)],
    ) -> Result<Vec<u8>, SlackCallErrorV1> {
        Ok(self.http.get(method, query).await?.body)
    }

    /// `auth.test`: whose token this is.
    ///
    /// # Errors
    ///
    /// Every [`SlackCallErrorV1`].
    pub async fn auth_test(&self) -> Result<SlackAuthV1, SlackCallErrorV1> {
        decode(&self.call("auth.test", &[]).await?)
    }

    /// `conversations.info` of one channel.
    ///
    /// # Errors
    ///
    /// Every [`SlackCallErrorV1`].
    pub async fn conversation_info(
        &self,
        channel: &str,
    ) -> Result<SlackChannelInfoV1, SlackCallErrorV1> {
        let answer: InfoAnswerV1 = decode(
            &self
                .call("conversations.info", &[("channel", channel)])
                .await?,
        )?;
        if answer.channel.id != channel {
            return Err(SlackCallErrorV1::Malformed(
                "conversations.info described another channel",
            ));
        }
        Ok(answer.channel)
    }

    /// One page of `conversations.history`, newest first, of messages after
    /// `oldest` and before `latest` (both exclusive).
    ///
    /// # Errors
    ///
    /// Every [`SlackCallErrorV1`].
    pub async fn history_page(
        &self,
        channel: &str,
        oldest: Option<&str>,
        latest: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<SlackPageV1, SlackCallErrorV1> {
        let mut query = vec![("channel", channel), ("limit", self.page_size.as_str())];
        if let Some(oldest) = oldest {
            query.push(("oldest", oldest));
        }
        if let Some(latest) = latest {
            query.push(("latest", latest));
        }
        if let Some(cursor) = cursor {
            query.push(("cursor", cursor));
        }
        let answer: PageAnswerV1 = decode(&self.call("conversations.history", &query).await?)?;
        Ok(page(answer))
    }

    /// The one message `ts` of `channel`, when Slack still has it: from the
    /// history (a channel-level message, a thread's root, a broadcast), else
    /// from its thread (a reply). Each read is bounded to that one `ts`
    /// (`oldest` and `latest` both `ts`, inclusive); a thread's read may also
    /// return its root, which Slack always lists first, so the message is
    /// found by its exact `ts`. `None` when neither read returns it, or its
    /// thread is gone.
    ///
    /// # Errors
    ///
    /// Every [`SlackCallErrorV1`].
    pub async fn message(
        &self,
        channel: &str,
        ts: &str,
    ) -> Result<Option<Box<SlackMessageV1>>, SlackCallErrorV1> {
        let find = |page: SlackPageV1| {
            page.messages.into_iter().find_map(|message| match message {
                PageMessageV1::Message(message) if message.ts == ts => Some(message),
                _ => None,
            })
        };
        let history: PageAnswerV1 = decode(
            &self
                .call(
                    "conversations.history",
                    &[
                        ("channel", channel),
                        ("oldest", ts),
                        ("latest", ts),
                        ("inclusive", "true"),
                        ("limit", "1"),
                    ],
                )
                .await?,
        )?;
        if let Some(message) = find(page(history)) {
            return Ok(Some(message));
        }
        let replies = self
            .call(
                "conversations.replies",
                &[
                    ("channel", channel),
                    ("ts", ts),
                    ("oldest", ts),
                    ("latest", ts),
                    ("inclusive", "true"),
                    ("limit", "2"),
                ],
            )
            .await?;
        match decode::<PageAnswerV1>(&replies) {
            Ok(answer) => Ok(find(page(answer))),
            Err(SlackCallErrorV1::Refused(code)) if code == "thread_not_found" => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// One page of `conversations.replies`: the thread's root first, then
    /// its replies, oldest first.
    ///
    /// # Errors
    ///
    /// Every [`SlackCallErrorV1`].
    pub async fn replies_page(
        &self,
        channel: &str,
        root: &str,
        cursor: Option<&str>,
    ) -> Result<SlackPageV1, SlackCallErrorV1> {
        let mut query = vec![
            ("channel", channel),
            ("ts", root),
            ("limit", self.page_size.as_str()),
        ];
        if let Some(cursor) = cursor {
            query.push(("cursor", cursor));
        }
        let answer: PageAnswerV1 = decode(&self.call("conversations.replies", &query).await?)?;
        Ok(page(answer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_is_decoded_or_its_error_classified() {
        let auth: SlackAuthV1 = decode(
            br#"{"ok":true,"url":"https://acme-robotics.slack.com/","team":"Acme","team_id":"T07ACME0001","user_id":"U1","bot_id":"B1"}"#,
        )
        .unwrap();
        assert_eq!(auth.team_id, "T07ACME0001");
        assert_eq!(auth.enterprise_id, None);
        let error = |body: &[u8]| decode::<SlackAuthV1>(body).unwrap_err();
        assert_eq!(
            error(br#"{"ok":false,"error":"ratelimited"}"#),
            SlackCallErrorV1::RateLimited
        );
        assert_eq!(
            error(br#"{"ok":false,"error":"invalid_auth"}"#),
            SlackCallErrorV1::Credential("invalid_auth".into())
        );
        assert_eq!(
            error(br#"{"ok":false,"error":"not_in_channel"}"#),
            SlackCallErrorV1::Refused("not_in_channel".into())
        );
        assert_eq!(
            error(br#"{"ok":false,"error":"<script>bad code</script>"}"#),
            SlackCallErrorV1::Refused("scriptbadcodescript".into())
        );
        assert_eq!(
            error(br#"{"ok":false}"#),
            SlackCallErrorV1::Refused("unknown_error".into())
        );
        assert!(matches!(error(b"<html>"), SlackCallErrorV1::Malformed(_)));
        assert!(matches!(
            error(br#"{"ok":true}"#),
            SlackCallErrorV1::Malformed(_)
        ));
    }

    #[test]
    fn a_channel_audience_follows_its_flags() {
        let info = |flags: serde_json::Value| -> SlackChannelInfoV1 {
            let mut value = serde_json::json!({"id": "C1", "name": "general"});
            value
                .as_object_mut()
                .unwrap()
                .extend(flags.as_object().unwrap().clone());
            serde_json::from_value(value).unwrap()
        };
        for (flags, audience) in [
            (serde_json::json!({}), ProviderAudienceV1::ScopePublic),
            (
                serde_json::json!({"is_private": true}),
                ProviderAudienceV1::Restricted,
            ),
            (
                serde_json::json!({"is_org_shared": true}),
                ProviderAudienceV1::Restricted,
            ),
            (
                serde_json::json!({"is_ext_shared": true, "is_private": true}),
                ProviderAudienceV1::ExternallyShared,
            ),
            (
                serde_json::json!({"is_pending_ext_shared": true}),
                ProviderAudienceV1::ExternallyShared,
            ),
            (
                serde_json::json!({"is_im": true}),
                ProviderAudienceV1::DirectMessage,
            ),
            (
                serde_json::json!({"is_mpim": true, "is_private": true}),
                ProviderAudienceV1::DirectMessage,
            ),
        ] {
            assert_eq!(info(flags.clone()).audience(), audience, "{flags}");
        }
    }

    #[test]
    fn a_page_keeps_its_cursor_and_digests_what_does_not_parse() {
        let answer: PageAnswerV1 = serde_json::from_str(
            r#"{"ok":true,"messages":[{"ts":"1790000000.000100","text":"hi"},{"text":"no ts"}],
                "has_more":true,"response_metadata":{"next_cursor":"bmV4dA=="}}"#,
        )
        .unwrap();
        let page = page(answer);
        assert_eq!(page.next_cursor.as_deref(), Some("bmV4dA=="));
        assert!(!page.unfinished);
        assert!(matches!(page.messages[0], PageMessageV1::Message(_)));
        assert!(matches!(page.messages[1], PageMessageV1::Malformed(_)));

        let last: PageAnswerV1 = serde_json::from_str(
            r#"{"ok":true,"messages":[],"has_more":false,"response_metadata":{"next_cursor":"x"}}"#,
        )
        .unwrap();
        let last = super::page(last);
        assert_eq!(last.next_cursor, None, "has_more=false ends the listing");
        let broken: PageAnswerV1 =
            serde_json::from_str(r#"{"ok":true,"messages":[],"has_more":true}"#).unwrap();
        assert!(super::page(broken).unfinished);
    }
}
