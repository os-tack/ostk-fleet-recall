//! Re-reading the Slack message an ingress hint names (ADR 0008 D12).
//!
//! A hint names `<channel>:<ts>`. The fetch reads it exactly as a pass
//! would, under the collector's own token and audience rules:
//!
//! 1. The channel must be one `settings.channels` lists; any other is not
//!    this collector's to read. A message, or a reply whose thread root, is
//!    at or before `settings.backfill_since` is outside every pass's window,
//!    so it is not read either: a provider event never widens what the
//!    operator configured, and nothing is held that no reconciliation could
//!    tombstone.
//! 2. `auth.test` (once per tick): the token's team must be the pin, and its
//!    workspace URL gives permalinks, so a hinted message is the same
//!    envelope a pass stages.
//! 3. `conversations.info`: the channel's audience, recorded as a container
//!    observation. A channel whose audience the instance does not admit is
//!    never read; its observation withdraws it, as a pass's would.
//! 4. The message itself ([`super::api::SlackApiV1::message`]): the history
//!    bounded to its `ts`, else its thread. It becomes a draft as a pass's
//!    message does; a deleted thread root (`tombstone`) hides the item the
//!    memory holds.
//!
//! A message Slack no longer returns is nothing to stage: only a pass's
//! complete reads, or a signed `message_deleted`, tombstone a message.

use async_trait::async_trait;
use tokio::sync::OnceCell;

use crate::error::Result;
use crate::memory_contracts::collected_item::{
    CollectionModeV1, ContainerKindV1, ObjectKindV1, ProviderKindV1,
};

use super::api::{SlackApiV1, SlackCallErrorV1};
use super::render::{
    CHANNEL_CONTAINER_KIND, MESSAGE_OBJECT_KIND, MessageDraftV1, SLACK_PROVIDER,
    SlackChannelContextV1, SlackTsV1, message_draft, tombstone_draft,
};
use super::{SlackSettingsV1, shown_id, workspace_origin};
use crate::collectors::audience::{
    AudienceDecisionV1, AudienceInputV1, KnownContainerV1, ProviderAudienceV1, classify,
};
use crate::collectors::pull::{
    FetchedObjectV1, HintedObjectV1, ObjectFetcherV1, PageStager, PullPassInputV1, PulledItemV1,
};
use crate::collectors::sink::ContainerObservationV1;

/// A failed call, as the hint run takes it: one the provider refused for
/// this channel or message fails this hint; a rate limit, a refused
/// credential, or a request that failed below Slack's answer is the whole
/// provider's.
fn call_failed(what: &str, error: &SlackCallErrorV1) -> FetchedObjectV1 {
    let message = format!("{what}: {error}");
    match error {
        SlackCallErrorV1::Refused(_) | SlackCallErrorV1::Malformed(_) => {
            FetchedObjectV1::Failed(message)
        }
        SlackCallErrorV1::RateLimited
        | SlackCallErrorV1::Credential(_)
        | SlackCallErrorV1::Http(_) => FetchedObjectV1::Unavailable(message),
    }
}

/// Re-reads hinted messages of one configured workspace.
#[derive(Debug)]
pub struct SlackFetchV1 {
    settings: SlackSettingsV1,
    api: SlackApiV1,
    /// The workspace's https origin, once `auth.test` confirmed the pin.
    workspace: OnceCell<Option<String>>,
}

impl SlackFetchV1 {
    /// A fetcher over `settings` through `api`.
    #[must_use]
    pub const fn new(settings: SlackSettingsV1, api: SlackApiV1) -> Self {
        Self {
            settings,
            api,
            workspace: OnceCell::const_new(),
        }
    }

    /// The token's workspace origin, once its team is the pin.
    async fn workspace(&self, pinned: &str) -> std::result::Result<Option<String>, String> {
        self.workspace
            .get_or_try_init(|| async {
                let auth = self
                    .api
                    .auth_test()
                    .await
                    .map_err(|error| format!("Slack auth.test failed: {error}"))?;
                if auth.team_id != pinned {
                    return Err(format!(
                        "the Slack token belongs to team {}, but the collector is pinned to team \
                         {pinned}",
                        shown_id(&auth.team_id)
                    ));
                }
                if let Some(enterprise) = &self.settings.enterprise_id
                    && auth.enterprise_id.as_deref() != Some(enterprise.as_str())
                {
                    return Err(format!(
                        "the Slack token is not installed in organization {enterprise}"
                    ));
                }
                Ok(workspace_origin(auth.url.as_deref()))
            })
            .await
            .cloned()
    }

    /// Whether `ts` is at or before `settings.backfill_since`, where every
    /// pass's window starts (exclusive): what no pass reads, and so what no
    /// reconciliation could ever tombstone, is never read for a hint either.
    fn before_backfill(&self, ts: &SlackTsV1) -> bool {
        self.settings
            .backfill_micros()
            .is_some_and(|backfill| ts.micros() <= backfill)
    }
}

#[async_trait]
impl ObjectFetcherV1 for SlackFetchV1 {
    #[allow(clippy::too_many_lines)] // one linear id -> auth -> channel -> message -> draft read
    async fn fetch(
        &self,
        input: &PullPassInputV1<'_>,
        hint: &HintedObjectV1<'_>,
        stager: &mut PageStager<'_>,
    ) -> Result<FetchedObjectV1> {
        if hint.object_kind != MESSAGE_OBJECT_KIND {
            return Ok(FetchedObjectV1::Nothing("unknown_object_kind"));
        }
        let Some((channel, ts)) = hint
            .external_id
            .split_once(':')
            .and_then(|(channel, ts)| Some((channel, SlackTsV1::parse(ts)?)))
        else {
            return Ok(FetchedObjectV1::Nothing("malformed_id"));
        };
        if !self
            .settings
            .channels
            .iter()
            .any(|listed| listed == channel)
        {
            return Ok(FetchedObjectV1::Nothing("channel_not_read"));
        }
        if self.before_backfill(&ts) {
            return Ok(FetchedObjectV1::Nothing("before_backfill"));
        }
        let scope = input.instance.provider_scope_id.as_str();
        let workspace = match self.workspace(scope).await {
            Ok(workspace) => workspace,
            Err(message) => return Ok(FetchedObjectV1::Unavailable(message)),
        };
        let kind = ContainerKindV1::new(CHANNEL_CONTAINER_KIND)?;
        let listed = input
            .source
            .audience
            .private_containers
            .iter()
            .any(|listed| listed == channel);
        let info = match self.api.conversation_info(channel).await {
            Ok(info) => info,
            Err(SlackCallErrorV1::Refused(code)) if code == "channel_not_found" && !listed => {
                // As a pass: a narrowing, which withdraws the channel.
                return Ok(FetchedObjectV1::Stage {
                    items: Vec::new(),
                    observations: vec![ContainerObservationV1 {
                        kind,
                        id: channel.to_owned(),
                        label: None,
                        provider_audience: ProviderAudienceV1::Restricted,
                    }],
                });
            }
            Err(error) => return Ok(call_failed("Slack conversations.info failed", &error)),
        };
        let audience = info.audience();
        let observation = ContainerObservationV1 {
            kind,
            id: channel.to_owned(),
            label: info.name.clone(),
            provider_audience: audience,
        };
        let decision = classify(&AudienceInputV1 {
            mode: CollectionModeV1::Pull,
            provider: SLACK_PROVIDER,
            provider_scope_id: scope,
            container_id: Some(channel),
            provider_audience: Some(audience),
            hint: None,
            policy: &input.source.audience,
            capture_scopes: &[],
            known_container: KnownContainerV1::Unknown,
        });
        if let AudienceDecisionV1::Refuse(_) = decision {
            return Ok(FetchedObjectV1::Stage {
                items: Vec::new(),
                observations: vec![observation],
            });
        }
        let message = match self.api.message(channel, ts.as_str()).await {
            Ok(Some(message)) => message,
            Ok(None) => {
                return Ok(FetchedObjectV1::Stage {
                    items: Vec::new(),
                    observations: vec![observation],
                });
            }
            Err(error) => {
                return Ok(call_failed("Slack could not return the message", &error));
            }
        };
        // A reply in a thread whose root is before the window: no pass reads
        // that thread.
        if message
            .thread_ts
            .as_deref()
            .and_then(SlackTsV1::parse)
            .is_some_and(|root| self.before_backfill(&root))
        {
            return Ok(FetchedObjectV1::Nothing("before_backfill"));
        }
        let provider = ProviderKindV1::new(SLACK_PROVIDER)?;
        let context = SlackChannelContextV1 {
            provider: &provider,
            provider_scope_id: scope,
            channel_id: channel,
            channel_label: info.name.as_deref(),
            workspace_url: workspace.as_deref(),
        };
        let items = match message_draft(&context, &message) {
            MessageDraftV1::Item(draft) => vec![PulledItemV1 {
                draft: *draft,
                provider_audience: Some(audience),
            }],
            MessageDraftV1::Tombstone => {
                let object_kind = ObjectKindV1::new(MESSAGE_OBJECT_KIND)?;
                stager
                    .held(&object_kind, hint.external_id)
                    .await?
                    .filter(|held| !held.lifecycle.is_tombstone())
                    .map(|held| PulledItemV1 {
                        draft: tombstone_draft(
                            &context,
                            hint.external_id,
                            held.thread_root.as_deref(),
                            held.provider_order,
                        ),
                        provider_audience: Some(audience),
                    })
                    .into_iter()
                    .collect()
            }
            MessageDraftV1::Skip => Vec::new(),
        };
        Ok(FetchedObjectV1::Stage {
            items,
            observations: vec![observation],
        })
    }
}
