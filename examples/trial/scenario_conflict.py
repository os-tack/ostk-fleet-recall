"""Scenario: two agents record incompatible claims citing items; conflict
surfaces; capture; lifecycle (not_owner refusal, acknowledge, resolve,
supersede)."""

import json
import os

from mcp import Serve, dump, show

T = os.environ["T"]
OUT = f"{T}/scenarios"
os.makedirs(OUT, exist_ok=True)
log = {}


def step(name, value):
    log[name] = value
    show(name, value, 3000)
    dump(f"{OUT}/conflict-scenario.json", log)
    return value


CAP = {"FLEET_RECALL_COLLECTED_CAPTURE": "enabled"}
alpha = Serve("agent-alpha", extra_env=CAP)
beta = Serve("agent-beta", extra_env=CAP)
gamma = Serve("agent-gamma", extra_env=CAP)

FR131 = "https://linear.app/ostk/issue/FR-131/keep-granola-transcripts-off-by-default"
CAPTURED_URL = "https://ostk.slack.com/archives/C07RECALLDEV/p1790150400000100"

# alpha: decision citing the Linear ticket
a1 = step("alpha.record(granola transcript default=false, cites FR-131)", alpha.remember(
    action="record", idempotency_key="trial/alpha/granola/v1", kind="decision",
    text="Granola transcripts stay off by default; the collector stages AI summaries only.",
    subject="granola collector", predicate="include-transcript default", value=False,
    support=[{"item": {"url": FR131}, "relation": "supports"}]))

# beta: captures a Slack message it read through its own Slack MCP connector
cap = step("beta.capture(new Slack message in #fleet-recall-dev + private channel + DM)", beta.remember(
    action="capture", idempotency_key="trial/beta/capture/v1", via="slack.conversations_history",
    items=[
        {"provider": "slack", "provider_scope_id": "T07OSTK0001", "object_kind": "message",
         "external_id": "C07RECALLDEV:1790150400.000100",
         "container": {"kind": "slack.channel", "id": "C07RECALLDEV"},
         "author": {"id": "U07JUNE0004", "kind": "human"}, "created_at": "2026-09-23T08:00:00.000100Z",
         "text": "Update from standup: Scott agreed Granola transcripts are ON by default for enterprise folders "
                 "starting October. FR-131 is reopened.",
         "url": CAPTURED_URL},
        {"provider": "slack", "provider_scope_id": "T07OSTK0001", "object_kind": "message",
         "external_id": "G07SECPRIV1:1790150500.000100",
         "container": {"kind": "slack.channel", "id": "G07SECPRIV1"},
         "author": {"id": "U07PRIYA002", "kind": "human"}, "created_at": "2026-09-23T08:01:40.000100Z",
         "text": "PRIVATE: rota phrase rotated to walrus-kettle.",
         "url": "https://ostk.slack.com/archives/G07SECPRIV1/p1790150500000100"},
        {"provider": "slack", "provider_scope_id": "T07OSTK0001", "object_kind": "message",
         "external_id": "D07SCOTTJUN:1790150600.000100",
         "container": {"kind": "slack.im", "id": "D07SCOTTJUN"},
         "author": {"id": "U07JUNE0004", "kind": "human"}, "created_at": "2026-09-23T08:03:20.000100Z",
         "text": "DM: between us, transcripts on by default is happening regardless.",
         "url": "https://ostk.slack.com/archives/D07SCOTTJUN/p1790150600000100"},
    ]))

b1 = step("beta.record(granola transcript default=true, cites captured message)", beta.remember(
    action="record", idempotency_key="trial/beta/granola/v1", kind="decision",
    text="Granola transcripts are on by default for enterprise folders from October.",
    subject="Granola Collector", predicate="include_transcript_default", value=True,
    support=[{"item": {"url": CAPTURED_URL}, "relation": "supports"}]))

step("gamma.recall(conflicts)", gamma.recall(action="conflicts"))
step("gamma.recall(search, kind=claim, 'Granola transcripts default')",
     gamma.recall(action="search", kind="claim", query="Granola transcripts default", limit=5))
step("gamma.recall(search, kind=chunk, 'Granola transcripts')",
     gamma.recall(action="search", kind="chunk", query="Granola transcripts", limit=5))
step("gamma.recall(search, kind=item, 'Granola transcripts default')",
     gamma.recall(action="search", kind="item", query="Granola transcripts default", limit=5))
step("gamma.recall(get, kind=item, FR-131 url)", gamma.recall(action="get", kind="item", id=FR131))
step("gamma.recall(get, kind=item, captured url)", gamma.recall(action="get", kind="item", id=CAPTURED_URL))

a_claim = (a1.get("data") or {}).get("claim", {})
b_claim = (b1.get("data") or {}).get("claim", {})
conflict_ids = b_claim.get("conflict_ids") or []
step("gamma.recall(get, kind=claim, alpha)", gamma.recall(action="get", kind="claim", id=a_claim.get("id")))

if conflict_ids:
    cid = conflict_ids[0]
    conflict = step("gamma.recall(get, kind=conflict)", gamma.recall(action="get", kind="conflict", id=cid))
    c = conflict["data"]["conflict"] if "conflict" in (conflict.get("data") or {}) else conflict["data"]
    step("gamma.retract(alpha's claim) -> expect not_owner", gamma.remember(
        action="retract", idempotency_key="trial/gamma/retract-alpha/v1", claim_id=a_claim["id"],
        expected_revision=2, reason="I think alpha is wrong"))
    step("alpha.acknowledge(conflict)", alpha.remember(
        action="acknowledge", idempotency_key="trial/alpha/ack/v1", conflict_id=cid,
        expected_revision=c.get("revision", 1), reason="checking with Scott"))
    b_now = beta.recall(action="get", kind="claim", id=b_claim["id"])["data"]["claim"]
    step("beta.resolve(retract own claim)", beta.remember(
        action="resolve", idempotency_key="trial/beta/resolve/v1", conflict_id=cid,
        expected_revision=c.get("revision", 1), expected_member_count=c.get("member_count", 2),
        retract_claim_ids=[b_claim["id"]],
        reason="the capture was a misread of standup; FR-131 stays Done"))
    step("gamma.recall(conflicts) after resolve", gamma.recall(action="conflicts"))
    step("gamma.recall(get, kind=conflict) after resolve", gamma.recall(action="get", kind="conflict", id=cid))
    step("gamma.recall(get, kind=claim, alpha) after resolve",
         gamma.recall(action="get", kind="claim", id=a_claim["id"]))

# Supersede path: tick interval
a2 = step("alpha.record(worker tick interval = 15 minutes)", alpha.remember(
    action="record", idempotency_key="trial/alpha/tick/v1", kind="decision",
    text="The memory worker ticks every 15 minutes; webhooks shorten the interval.",
    subject="memory worker", predicate="tick interval", value="15 minutes"))
b2 = step("beta.record(worker tick interval = 5 minutes)", beta.remember(
    action="record", idempotency_key="trial/beta/tick/v1", kind="decision",
    text="The memory worker ticks every 5 minutes in staging.",
    subject="memory worker", predicate="tick interval", value="5 minutes"))
b2c = (b2.get("data") or {}).get("claim", {})
step("gamma.recall(conflicts) with tick conflict", gamma.recall(action="conflicts"))
step("beta.supersede(own claim -> 15 minutes)", beta.remember(
    action="supersede", idempotency_key="trial/beta/tick-supersede/v1", claim_id=b2c.get("id"),
    expected_revision=b2c.get("revision"), reason="Priya: keep 15 and rely on webhooks",
    kind="decision", text="The memory worker ticks every 15 minutes.",
    subject="memory worker", predicate="tick interval", value="15 minutes"))
step("gamma.recall(conflicts) after supersede", gamma.recall(action="conflicts"))

for s in (alpha, beta, gamma):
    s.close()
