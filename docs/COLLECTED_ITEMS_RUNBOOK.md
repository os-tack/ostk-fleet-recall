# Collected items: operator runbook

This runbook puts in order what it takes to collect specs and documents,
Slack conversations, Linear tickets, and Granola meetings into a scope's
memory, let agents relay what they read, receive provider webhooks, and check
what agents then recall. The decisions behind it are
[ADR 0008](adr/0008-collected-items.md); the commands' full reference is the
[README](../README.md#memory-worker) and
[migration operations](MIGRATIONS.md). Everything here is private plane: the
public demo serves none of it.

[Local quickstart](../README.md#local-quickstart) step 10 runs the documents
collector, both import formats, and a capture against a local node. The last
section records an end-to-end run of every step below against a fresh secure
node, with local stand-ins for the three providers.

## 1. Prepare the scope

A scope collects items only at generation 3, with migration 36 and the
runtime grants in place.

- **A fresh scope.** Migrate as the migrator, then, before the database
  boundary retires the migrator, install the writer authority straight at
  generation 3 and keep the report's `pins`:

  ```bash
  FLEET_RECALL_DATABASE_URL="$MIGRATOR_URL" ostk-fleet-recall migrate
  FLEET_RECALL_DATABASE_URL="$MIGRATOR_URL" \
    FLEET_RECALL_CONTRACT_TENANT_NAMESPACE=tenant.acme \
    FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE=project.platform \
    ostk-authority-install apply --target generation-3 > authority.json
  ```

  Then apply the runtime and publication policies (the local boundary
  helper `deploy/localstack/database-boundary.sh`, or
  [cloud onboarding](CLOUD_ONBOARDING.md) step 6).
- **A scope at generation 2.** Follow
  [Generation-3 rollout order](MIGRATIONS.md#generation-3-rollout-order-adr-0008-d2):
  ship the release to every process that verifies the head (the projector
  container included), migrate and re-apply the grants, then run the same
  `apply --target generation-3` as the migrator. The pins do not change, and
  the run rebases the scope's spec families (its report lists each
  `rebased`).

Every event-first writer (`serve`, the worker, `collect`, `ostk-spec`)
exports the three pins from the report, and the worker, `collect import`,
and a `serve` that admits captures also hold `FLEET_RECALL_CONTENT_KEK_HEX`,
the scope's one content key.

## 2. Configure the collectors

The scope's one worker sources file lists each collector under `collectors`
([`examples/worker-sources.json`](../examples/worker-sources.json) has one of
each provider). One instance reads one provider scope: a documents root, a
Slack workspace (`team_id`), a Linear organization (its UUID), or a Granola
key's workspace (the operator's pin). The operator declares the audience:

| Provider | Credential (`settings.token_env`) | Audience |
|---|---|---|
| `docs` | none | `operator_declared` for the whole root |
| `slack` | an internal app's bot token, `FLEET_RECALL_SLACK_*` | public channels; a private channel only if `private_containers` lists it; never a DM, group DM, or Slack Connect channel |
| `linear` | a `lin_api_` key or an OAuth token, `FLEET_RECALL_LINEAR_*` | public teams; a private team only if `private_containers` lists it |
| `granola` | a `grn_` key, `FLEET_RECALL_GRANOLA_*` | `operator_declared`, plus `folders` or `all_notes_visible_to_key` |

The sources file names the variable, never the token. The worker reads the
token from its own environment on the host that runs the `collect` step, and
sends it only to its provider (`api_base` or `api_url` may name only the
provider's own host over https, or a loopback address for a local stand-in).
A collector's `stale_after_seconds` may not be shorter than its
`reconcile_every_seconds`. Then run a tick and read what each instance holds:

```bash
FLEET_RECALL_SLACK_BOT_TOKEN=... FLEET_RECALL_LINEAR_API_KEY=... FLEET_RECALL_GRANOLA_API_KEY=... \
  ostk-fleet-recall worker --once --sources worker-sources.json | jq '.steps.collect'
ostk-fleet-recall collect status | jq '.instances[] | {instance, source: .source.last_outcome, outbox, hints, dead_letters}'
ostk-fleet-recall collect dead-letters --since 2026-09-26T00:00:00Z
```

Every collector reads its whole scope on its first pass, which records
coverage; Slack and Granola record it again only on each
`reconcile_every_seconds` reconciliation, Linear and documents on every pass.
Schedule the tick (cron or a timer), one run per scope at a time.

## 3. Import snapshots

An import is the operator's word for a provider scope at one moment:

```bash
ostk-fleet-recall collect import --instance import.linear --principal principal.import \
  --provider linear --provider-scope <organization uuid> --audience operator-declared \
  --format items-jsonl --path linear-items.jsonl
ostk-fleet-recall collect import --instance import.slack-export --principal principal.import \
  --provider slack --provider-scope <team id> --audience operator-declared \
  --format slack-export --path acme-export.zip [--private-container <channel id> ...]
```

Imported items are `reported`; a collector's copy of the same item is
presented over them. `collect retire --instance <id>` takes an import's
snapshot out of the absence verdict and keeps its items recallable.

## 4. Let agents capture what they read

`serve` takes `FLEET_RECALL_COLLECTED_CAPTURE=stage_only` (the worker admits
captures; `serve` holds no content key) or `enabled` (admitted in the call,
with the content key in `serve`), and optionally
`FLEET_RECALL_COLLECTED_CAPTURE_SCOPES`, the scopes or containers the operator
declares readable by the whole project beyond those a collector or import
already recorded. `recall(status).remember_capture` says whether it is
served and why not.

## 5. Receive webhooks

Webhooks only shorten the pull interval: each is kept as a hint (provider ids,
no content), and the next tick re-reads the object through the collector's
own token, or hides a deleted one.

1. **The login.** Create `fleet_ingress` `NOLOGIN` (with its password),
   apply
   [`ingress-receiver-role-grants.sql`](../deploy/cockroach/ingress-receiver-role-grants.sql)
   after migration 36, clean its PUBLIC defaults, and enable it:
   `deploy/localstack/ingress-boundary.sh` does all of that on a local node,
   and [cloud onboarding](CLOUD_ONBOARDING.md) step 6 describes the audit
   around it elsewhere.
2. **The signing secrets.** Add `"push": {"signing_secret_env": ...}` to each
   collector that takes webhooks, naming a variable in the collector's own
   namespace (`FLEET_RECALL_SLACK_SIGNING_SECRET`,
   `FLEET_RECALL_LINEAR_WEBHOOK_SECRET`, `FLEET_RECALL_GRANOLA_WEBHOOK_SECRET`).
3. **The receiver.** Start it from an environment that holds only its own
   URL, the scope, and those secrets; it refuses to start beside any other
   database URL, the content key, or a provider token the sources file
   names:

   ```bash
   env -i PATH="$PATH" \
     FLEET_RECALL_INGRESS_DATABASE_URL="postgresql://fleet_ingress:...@host:26257/fleet_recall?sslmode=verify-full&sslrootcert=..." \
     FLEET_RECALL_TENANT_ID=... FLEET_RECALL_PROJECT=... \
     FLEET_RECALL_SLACK_SIGNING_SECRET=... FLEET_RECALL_LINEAR_WEBHOOK_SECRET=... \
     FLEET_RECALL_GRANOLA_WEBHOOK_SECRET=... \
     ostk-fleet-recall ingress --sources worker-sources.json
   ```

   It listens on `127.0.0.1:8787` (`--listen`, or
   `FLEET_RECALL_INGRESS_LISTEN`); `--allow-non-loopback` is only for a
   private address behind the relay.
4. **The relay and the providers.** Run a relay (a tunnel or a private load
   balancer) that forwards `https://<relay>/v1/hooks/<connector_instance>`
   unchanged, headers and body byte for byte, to the receiver. Give that URL
   and the secret to Slack's Event Subscriptions, a Linear webhook for the
   `Issue` and `Comment` resources, and a Granola webhook for note events.
5. **Check it.** `collect dead-letters --instance <id>` lists refusals by
   reason (`invalid_signature`, `stale_signature`, `unauthorized_scope`,
   `oversize`, `parse_failed`), and `collect status` counts each instance's
   hints by state after the next tick. A hint the worker could not re-read
   eight times is `dead`; `collect retry --delivery <hex>` reopens it.

## 6. Check what agents recall

- `recall(status)`: `evidence.collectors` (sources, pending parts, dead
  letters of the last day), `evidence.readiness` (`items_awaiting_admission`,
  `hints_awaiting_fetch`), and `remember_capture`.
- `recall(action="search", kind="item", query=..., source=...)`: current
  versions with provider, container, author, trust tier, supersession, and
  `injection_signals`; `include_history` adds superseded versions. The
  absence verdict is `absent` only over complete, fresh collectors with
  nothing waiting.
- `recall(action="get", kind="item", id=<item id | version id | URL>)`: every
  version's provenance (collector instance, mode, trust) and the claims that
  cite it.
- `recall(action="search", kind="evidence")`: collected bodies beside git,
  CI, and transcripts, each annotated with its item and whether its version
  is current. A deleted or withdrawn item is in neither answer.

## 7. First live run against each provider

The collectors are built and tested against the providers' documented
formats and recorded fixtures; the build environment never reaches the
providers. On the first run against a real account, check:

- **Slack:** `auth.test` names the pinned `team_id`; a channel with more than
  one page of history and a thread with more than one page of replies read
  completely; a `ratelimited` answer ends the pass partial and the next tick
  resumes it; the Events API request URL verifies, and a message edited,
  deleted, and posted in a thread each arrive as hints the next tick settles;
  a DM event is kept without ids.
- **Linear:** the key's organization is the pin; a team with more issues
  than one page sweeps completely; the `x-ratelimit-*` headers the report
  counts are read; an issue update and a comment removal arrive signed and
  settle; Linear does not disable the webhook after the receiver's answers.
- **Granola:** the key lists the notes the folders hold; `updated_after`
  returns what changed since the last pass (a note edited after it is read on
  the next pass); the pacer keeps under the rate limit; a `note.edited`
  webhook verifies with the `whsec_` secret and settles.
- **All:** `collect dead-letters` is empty apart from what was provoked, and
  no table holds a token (the collectors' live tests grep every table for
  their placeholder credential).

## 8. End-to-end record (2026-09-26)

The whole of sections 1 to 6 ran with the release's own binaries against a
fresh secure CockroachDB v26.2.3 single node (TLS, password logins, the
migrator retired by the boundary helper), with a local stand-in for each
provider on `127.0.0.1` that answered the Web API, GraphQL, and REST calls
from the recorded fixtures in `src/collectors/{slack,linear,granola}/fixtures`
and accepted only the placeholder credentials `xoxb-EXAMPLE-NOT-A-TOKEN`,
`lin_api_EXAMPLENOTAREALKEYEXAMPLENOTAREAL`, and `grn_EXAMPLE_NOT_A_KEY`.

| Step | What ran | What held |
|---|---|---|
| Scope | `migrate`; `ostk-authority-install apply --target generation-3` (twice); `database-boundary.sh`; `ingress-boundary.sh` | schema 36; generation 3, `collected_items_generation3`; the re-run changed nothing and kept the pins; `fleet_ingress_receiver` holds exactly its seven grants |
| Collectors | `worker --once` over `docs/` and `contracts/` (Markdown only), Slack, Linear, and Granola | every collector `ok` with complete coverage; each credential reached only its own provider, only in the `Authorization` header |
| Imports | `collect import` of `tests/fixtures/collected/items-linear.jsonl` and a Slack export zip | both snapshots recorded complete; the export's public channel imported, its unlisted private channel and DM folders never read, its file link's `?t=xoxe-...` token stripped |
| Ingress | the receiver as `fleet_ingress`; signed and wrongly signed deliveries | refused to start beside the writer URL, the content key, a provider token, or a non-loopback address; challenge echoed; `message_changed`, `message_deleted`, a Linear issue update and comment removal, and a Granola `note.edited` stored once as hints (a replay added nothing), a DM kept without ids; a wrong secret or timestamp `401`, another team or organization `403`, an oversize body `413`, an unknown instance `404`, each rejection one digest-only dead letter |
| Settling | item recall before the tick; `worker --once` after | an empty answer read `unknown` with five hints waiting; the tick re-read the three edits and staged them, tombstoned the two deletions in push mode, and settled every hint |
| MCP | two `serve` processes, capture `enabled` | capture admitted a channel message and withheld a DM (`direct_message`) and an unrecorded channel (`audience_unverified`); agent A's assert cited the capture by item id, agent B's the Linear issue by URL, and the conflict opened, was acknowledged, and closed when B conceded; citing the deleted message was `support_item_withdrawn`; `record` cited an item by URL |
| Recall | item search, get, `include_history`, `source`; evidence search | Slack, Linear, and Granola items with provenance and trust tiers; the edited issue and note current with their history kept; `cited_by` and `support_items` linked both ways; evidence hits annotated with their item and `current`; the deleted message and the removed comment in no answer; an unmatched query `absent` |
| Upgrade | a second scope at generation 2 with an active spec family, moved with `--target generation-3` | the family `rebased`, the pins unchanged; the migrator re-enabled for the run and retired again by rerunning the boundary helper; `ostk-spec check` then judged a commit and opened an episode, and the scope collected a documents root |
| Publication | `demo` as `fleet_publication`; every table read as each login | no collected text, `fleet.item` support row, asserted claim, or asserted conflict in any demo answer; the publication login reads its eight tables and the ingress login only the queue, the dead letters, and the migration history |
| Secrets | every table's rows as text | no placeholder token or signing secret, and no text of the unlisted channel, the DMs, or the DM webhook |

The run corrected the runbooks it followed: the README runbook now counts
migrations through 36 and names the generation-3 target, the ingress login,
and every holder of the content key; the quickstart gained step 10; the
ingress login has a local helper; and the generation-3 rollout says how to
re-enable a retired migrator and why the projector container must move with
the release.
