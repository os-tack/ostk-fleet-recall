# Collection and ingestion reference

[Documentation](../README.md) · [CLI](CLI.md) · [Configuration](CONFIGURATION.md)

Choose the path according to who attests the content:

| Path | Operator input | Result |
| --- | --- | --- |
| Collector pull | Provider credential and a project-visible source in the worker configuration. | Verified items read directly from the provider. |
| `collect import` | A scoped export and an explicit audience declaration. | Reported items and a snapshot coverage receipt. |
| `remember(capture)` | Items an authenticated agent read, inside an operator-authorized audience. | Reported items attested by the agent. |
| `ingress` webhook | Provider-signed notification and an isolated receiver credential. | An ID-only hint; the worker re-reads provider content. |
| `ingest` | Trusted operator NDJSON. | Chunks in the active corpus, outside the collected-item sink. |

Provision the schema, generation-3 writer authority and grants through the
[event-first guide](../guides/EVENT_FIRST_OPERATIONS.md) before enabling
collectors, import or capture. The [worker reference](WORKER.md#collector-configuration)
contains provider settings. Follow the [collected-items runbook](../COLLECTED_ITEMS_RUNBOOK.md)
for a first real provider run, token handling and coverage checks.

Run shell examples from the repository root. Examples using
`$FLEET_RECALL_BIN` and `$FLEET_RECALL_QUICKSTART_SOURCES` assume the variables
from the [local development](../tutorials/LOCAL_DEVELOPMENT.md) and
[memory pipelines](../tutorials/MEMORY_PIPELINES.md) tutorials; for an existing
deployment, use its binary, scoped sources file and role-specific environment.

- [Importing collected items](COLLECTION.md#importing-collected-items)
- [Capturing items an agent read](#capturing-items-an-agent-read)
- [Receiving provider webhooks](COLLECTION.md#receiving-provider-webhooks)
- [Ingestion contract](#ingestion-contract)

## Importing collected items

`ostk-fleet-recall collect import` stages one file of items for one collector
instance through the same sink every collector uses, admits them under
`connector.collected.import`, and records the file as a snapshot of its
provider scope ([ADR 0008 D9](../adr/0008-collected-items.md)):

```text
ostk-fleet-recall collect import --instance import.slack --principal principal.import \
  --provider slack --provider-scope T07ACME0001 --audience operator-declared \
  --format items-jsonl --path items-slack.jsonl [--no-drain] [--stale-after 2592000]
```

Each line of an `items-jsonl` file is one item: the plain-text shape an agent
capture carries, with `provider`, `provider_scope_id`, `object_kind`,
`external_id`, the text, and optionally a version, lifecycle, container,
thread, author, `created_at` and `updated_at`, title, links, URL, and a
`visibility` hint. [`tests/fixtures/collected`](../../tests/fixtures/collected)
holds one file each for a documents root, Slack, Linear, and Granola. The
command refuses, as digest-only dead letters, a line that is not an item, a
line of another provider or scope than the instance's
(`provider_scope_mismatch`), and a line with neither `updated_at` nor
`created_at`. The sink refuses the rest as it does for every collector: a
`visibility` of `private` or `dm`, a direct conversation's container (such as
`slack.im`), and a secret it cannot redact. `--audience operator-declared` is
the operator's declaration that everything else in the file is visible to the
whole project; it is required, and it is the only audience. An imported item
is `reported`: a verified collector's head of the same item is presented
instead.

A version is the line's own marker, or `o<order>:sha256:<content digest>` at
its `updated_at` (else `created_at`), so re-importing an unchanged file stages
nothing, an edited line (with a newer `updated_at`) supersedes, and a line
whose `lifecycle` is `deleted` hides the item everywhere. A line missing from
a later file deletes nothing: an export can be partial. Once every line it
staged is admitted, the import records a snapshot receipt, and an empty
answer over its provider becomes `absent`; a refused line leaves the
snapshot partial. The snapshot stays current for `--stale-after` seconds (30
days by default).

The command runs as `fleet_writer` with the writer-authority pins. It drains
what it stages, which needs `FLEET_RECALL_CONTENT_KEK_HEX`; with `--no-drain`
it only stages, reads no key, and the next `worker` tick whose steps include
`collect` drains the rows and records the snapshot. It prints one JSON report:
counts, refusals by reason, the file's digest, and where the snapshot stands.

A Slack workspace export backfills a Slack scope, as a directory or a zip:

```text
ostk-fleet-recall collect import --instance import.slack-export --principal principal.import \
  --provider slack --provider-scope T07ACME0001 --audience operator-declared \
  --format slack-export --path acme-export.zip [--private-container G07PLATSEC1 ...]
```

Every public channel in `channels.json` is imported, and a private channel in
`groups.json` only when `--private-container` names it; the other private
channels are recorded withdrawn and never opened, and direct conversations
(`dms.json`, `mpims.json`) are never read. Messages become the same items the
Slack collector pulls, so a pulled message supersedes its imported copy, and
file links lose the `?t=xoxe-...` token exports carry. A zip holds at most
100,000 entries of at most 64 MiB each, 2 GiB in all.

`collect status` lists every collector instance of the scope (its status row,
outbox rows by state, cursors, webhook hints by state, and dead letters by
reason), `collect
dead-letters [--since <RFC 3339>] [--instance <id>]` lists dead letters with
their digests, reasons, and static diagnostics, never provider text (the
webhook receiver's refusals among them), and
`collect retire --instance <id>` retires an import's status row so its
snapshot no longer counts toward absence; its items stay recallable, and
importing again re-activates it. An import never takes the name of a worker
source or a worker collector, and `retire` touches an import's row only.

## Capturing items an agent read

`remember(capture)` lets an agent relay what it read through its own MCP
connectors into the same sink every collector uses, bound to
`connector.collected.capture`
([ADR 0008 D10](../adr/0008-collected-items.md)). One call carries 1 to 32
items in the shape an [import](COLLECTION.md#importing-collected-items) line has, each
with its `https` provider `url`, `updated_at` (or `created_at`), and the text
as read (at most 262,144 characters; the server splits it); `via` optionally
names the tool it came through. A capture is one MCP frame, which the stdio
transport caps at 1 MiB, so the items' texts together are at most 768 KiB
(786,432 bytes) of UTF-8: split a larger batch across captures. An explicit
`version.order_micros` is microseconds since the Unix epoch and never ahead of
now (a later one is withheld as `clock_ahead`):

```json
{"action":"capture","idempotency_key":"readme/capture/v1","via":"slack.conversations_history","items":[{"provider":"slack","provider_scope_id":"T07ACME0001","object_kind":"message","external_id":"C07PLATENG1:1790006860.001100","container":{"kind":"slack.channel","id":"C07PLATENG1"},"author":{"id":"U07ALICE","kind":"human"},"updated_at":"2026-09-21T16:07:40Z","text":"the retry budget is five","url":"https://acme.slack.com/archives/C07PLATENG1/p1790006860001100"}]}
```

Each item answers, in order, with its `item_id` (what `recall(get,
kind=item)` takes), `version_id`, the version `uri`, `redacted_ranges`, its
`accepted_event_ids` (what an assertion cites as
`support_evidence_event_ids`), and a disposition: `admitted`, `staged` (the
worker's `collect` step admits it), `replayed` (the same item, already
admitted from this agent under another key), or `withheld` with a
`withheld_reason`. An `enabled` capture that admitted something also
reports its `projection` (`{bodies, lexical, dense, complete}`): the items
were projected in the call, by the worker's own projectors within a
ten-second budget, so `recall(search, kind=item)` finds them at once and the
scope's absence verdict does not read `body_projection_lag` for them; a
tier that ran out of budget or failed leaves `complete: false` and what it
committed, and the worker's next `project` and `embed` steps finish the
rest. The same key replays the stored answer; a different
request under a used key is an idempotency conflict. The receipt keeps the
request's digest, never an item's text, and that digest is taken with every
secret the redactor finds replaced, so it confirms no guess of one; two
requests that differ only in a redacted secret are the same capture.

The server, not the agent, decides who may read an item: it is admitted only
into a container a verified collector or an operator import already recorded
as readable by the project, or into a provider scope or container the
operator lists in `FLEET_RECALL_COLLECTED_CAPTURE_SCOPES`. Anything else is
withheld (`audience_unverified`), as is a container since withdrawn
(`container_withdrawn`), a direct or group-direct conversation (a container
kind such as `slack.im` or `slack.mpim`: `direct_message`, whatever the scopes
list, `"*"` included), and an item whose `visibility` is `private` or `dm`
(`audience_refused`); nothing an agent sends widens an audience. A captured
item is `reported` and attested by `agent.<FLEET_RECALL_AGENT>`: two agents'
captures are two attestations, a collector's own copy of the item is always
presented over it, and a newer captured version that differs sets the item's
`disagreement`. A deletion is never captured; only a collector or an import
reports one.

`serve` configures capture with:

- `FLEET_RECALL_COLLECTED_CAPTURE`: `disabled` (the default; nothing changes
  and nothing else is read), `stage_only` (captures are staged, and the
  worker's `collect` step admits them; `serve` needs no content key), or
  `enabled` (captures are admitted and projected in the call, which needs
  `FLEET_RECALL_CONTENT_KEK_HEX` in `serve` and the bodies, lexical, and
  dense steps' grants on its login);
- `FLEET_RECALL_COLLECTED_CAPTURE_SCOPES`: a JSON array of `{"provider",
  "provider_scope_id", "containers": "*" | ["<container id>", ...]}` the
  operator declares visible to the whole project, default `[]`;
- the writer-authority pins, over a generation-3 head (run
  `ostk-authority-install apply --target generation-3`), migration 34, and
  the runtime grants.

If any of them is missing or does not verify, `serve` logs why, starts
without capture, and `recall(status).remember_capture` reports `served:
false` with the reason. `FLEET_RECALL_REMEMBER_LIFECYCLE` does not govern
capture.

## Receiving provider webhooks

`ostk-fleet-recall ingress` receives Slack Events API, Linear, and Granola
webhooks and keeps each verified one as a hint: which object changed, by id,
never its text ([ADR 0008 D12](../adr/0008-collected-items.md)). A
collector takes webhooks when its entry in the worker's sources file names
the variable holding the provider's signing secret, in the collector's own
namespace:

```json
{"provider": "slack", "connector_principal": "principal.slack",
 "connector_instance": "slack.acme", "provider_scope_id": "T07ACME0001",
 "settings": {"token_env": "FLEET_RECALL_SLACK_BOT_TOKEN", "channels": ["C07PLATENG1"]},
 "push": {"signing_secret_env": "FLEET_RECALL_SLACK_SIGNING_SECRET"}}
```

```text
FLEET_RECALL_INGRESS_DATABASE_URL=postgresql://fleet_ingress:...@host:26257/fleet_recall?sslmode=verify-full \
FLEET_RECALL_TENANT_ID=... FLEET_RECALL_PROJECT=... FLEET_RECALL_SLACK_SIGNING_SECRET=... \
ostk-fleet-recall ingress --sources worker-sources.json [--listen 127.0.0.1:8787] [--allow-non-loopback]
```

Each provider posts to `/v1/hooks/<connector_instance>`. The receiver checks
the signature over the exact bytes it received (Slack's `v0` signature within
five minutes, Linear's `Linear-Signature` with its signed `webhookTimestamp`
within a minute, Granola's Standard Webhooks `whsec_` signature within five
minutes), the pinned team or organization, and a body limit
(`FLEET_RECALL_INGRESS_MAX_BODY_BYTES`, 1 MiB by default). It answers `401`,
`403`, `400`, or `413` to what it refuses, with at most one digest-only dead
letter per instance, reason, and minute, and `200` once a delivery is stored,
exactly once however often the provider retries it. It echoes Slack's URL
verification, keeps a direct message only as a replay guard with no ids, and
answers `503` when the database fails, so the provider retries.

The next `worker` tick whose steps include `collect` reads each collector's
pending hints before its pass: an edit or a new message, issue, comment, or
note is re-read through the collector's API, exactly as a pass reads it, and
staged; a Slack `message_deleted` or a Linear `remove` hides the item the
memory holds at once. Only then is the hint settled, in the same
transaction. A fetch that keeps failing backs off and, after eight attempts,
becomes a `retry_exhausted` dead letter; `collect retry --delivery <hex>`
reopens it. While a hint waits, evidence and item recall report
`hints_awaiting_fetch` and an empty answer is `unknown`; so is one read by a
login that cannot read the hint queue (`hints_unreadable`). A hint never
counts as coverage: only a pass's complete reads do.

The receiver runs as its own login, `fleet_ingress`, which may only read and
insert deliveries and dead letters
([`ingress-receiver-role-grants.sql`](../../deploy/cockroach/ingress-receiver-role-grants.sql));
it refuses to start beside the writer's or any other database URL (any
variable whose name ends in `DATABASE_URL`), the content key, or a provider
API credential the sources file names (`settings.token_env`), so run it from
an environment of its own, holding only its URL and the signing secrets. It
listens on loopback unless `--allow-non-loopback` says
otherwise (`FLEET_RECALL_INGRESS_LISTEN`): Linear and Granola need a public
HTTPS endpoint, which is a relay you run in front of it.

### Disposable development receiver setup

The following commands target only the disposable insecure development
tutorial, not the installed Lima/k0s HTTPS plane. On that tutorial's local
node, after the
[database boundary](../tutorials/LOCAL_DEVELOPMENT.md#4-establish-the-database-boundary-and-load-the-corpus-as-the-writer),
the checked-in helper creates the login quiesced, clears the PUBLIC routine
defaults its creation leaves, applies the policy, and only then enables it.
The helper speaks only to that insecure node (`cockroach sql --insecure` at
`cockroach:26257`): on a node with TLS and passwords, a cluster admin runs
the same statements in the order the
[collected-items runbook](../COLLECTED_ITEMS_RUNBOOK.md#5-receive-webhooks)
gives, and a shared or production cluster follows
[cloud onboarding](../CLOUD_ONBOARDING.md). The receiver serves only the
collectors whose entry has a `push`, and the quickstart's sources file has
none: add a collector like the Slack one above, with its `push`, to
`$FLEET_RECALL_QUICKSTART_SOURCES` and pass that file. The outer shell
expands the binary, the scope, and the secret before `env -i` clears the rest
of the environment:

```text
docker exec --interactive ostk-fleet-recall-crdb /bin/sh -s < deploy/localstack/ingress-boundary.sh
env -i PATH="$PATH" \
  FLEET_RECALL_INGRESS_DATABASE_URL="postgresql://fleet_ingress:local-ingress-only@127.0.0.1:26257/fleet_recall?sslmode=disable" \
  FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1 \
  FLEET_RECALL_TENANT_ID="$FLEET_RECALL_TENANT_ID" FLEET_RECALL_PROJECT="$FLEET_RECALL_PROJECT" \
  FLEET_RECALL_SLACK_SIGNING_SECRET="$FLEET_RECALL_SLACK_SIGNING_SECRET" \
  "$FLEET_RECALL_BIN" ingress --sources "$FLEET_RECALL_QUICKSTART_SOURCES"
```

Then give each provider the relay's URL for `/v1/hooks/<connector_instance>`
and the signing secret: Slack's Event Subscriptions request URL (it verifies
the URL with a signed challenge the receiver answers; subscribe the app to the
channel message events it reads), a Linear webhook for the `Issue` and
`Comment` resources, and a Granola webhook for its note events.
`collect dead-letters --instance <id>` lists what the receiver refused, and
`collect status` counts each instance's hints by state.

## Ingestion contract

`ingest --input PATH` reads NDJSON; `--input -` (the default) reads stdin:

```bash
"$FLEET_RECALL_BIN" ingest --input examples/demo.ndjson
"$FLEET_RECALL_BIN" ingest --input - < examples/demo.ndjson
```

Each nonblank line is one object:

```json
{"source":"markdown","source_id":"demo/architecture","text":"Fleet Recall keeps durable semantic memory in CockroachDB.","chunk_index":0,"facets":{"tags":["demo","architecture"]},"role":"primary"}
```

Required fields are `source`, `source_id`, and nonblank `text`. Optional fields
are `source_config_id` (default `fleet:ndjson:v1`), `chunk_index` (default 0),
RFC 3339 `ts`, `role` (`primary`, `evolution`, or `usage`), `links`, `facets`,
and object-valued `extra`. Unknown fields are rejected. Input cannot provide
tenant, project, agent, session, privacy, chunk ID, embedding, stale state, or
internal claim, conflict, or transcript-projection metadata. Trusted deployment
configuration supplies scope; the importer derives stable
chunk/content/embedding-input hashes.

The importer accepts at most 10,000 records, 1 MiB per physical line, 64 MiB
total input, and 256 KiB text per record, with additional facet/link bounds. It
also caps each whitespace-delimited text lexeme at 16,000 UTF-8 bytes, below
CockroachDB's 16,383-byte TSVECTOR lexeme limit. It parses, validates,
deduplicates, embeds, and vector-validates the full input before the first chunk
write. Upserts use stable IDs, so rerunning the same import is safe. A database
failure can leave a valid prefix applied; rerunning converges that prefix and
the remaining rows.
