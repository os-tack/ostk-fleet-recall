"""Scenario part 2: beta re-keys its claim so it collides with alpha's; the
conflict surfaces on every read; lifecycle: not_owner, acknowledge, resolve."""

import os

from mcp import Serve, dump, show

T = os.environ["T"]
OUT = f"{T}/scenarios"
log = {}


def step(name, value, limit=2500):
    log[name] = value
    show(name, value, limit)
    dump(f"{OUT}/conflict-scenario2.json", log)
    return value


CAP = {"FLEET_RECALL_COLLECTED_CAPTURE": "enabled"}
alpha = Serve("agent-alpha", extra_env=CAP)
beta = Serve("agent-beta", extra_env=CAP)
gamma = Serve("agent-gamma", extra_env=CAP)
CAPTURED_URL = "https://ostk.slack.com/archives/C07RECALLDEV/p1790150400000100"
FR131 = "https://linear.app/ostk/issue/FR-131/keep-granola-transcripts-off-by-default"

old = beta.recall(action="get", kind="claim", id=6)["data"]["claim"]
step("beta.retract(mis-keyed claim 6)", beta.remember(
    action="retract", idempotency_key="trial/beta/retract6/v1", claim_id=6,
    expected_revision=old["revision"], reason="re-keying to match alpha's predicate"))
b = step("beta.record(same key as alpha, value=true, cites capture)", beta.remember(
    action="record", idempotency_key="trial/beta/granola/v2", kind="decision",
    text="Granola transcripts are on by default for enterprise folders from October.",
    subject="granola collector", predicate="include-transcript default", value=True,
    support=[{"item": {"url": CAPTURED_URL}, "relation": "supports"}]))
bc = b["data"]["claim"]
cid = bc["conflict_ids"][0]

step("gamma.recall(conflicts)", gamma.recall(action="conflicts"))
step("gamma.recall(search, kind=claim)", gamma.recall(action="search", kind="claim",
                                                      query="Granola transcripts default", limit=5))
step("gamma.recall(search, kind=chunk)", gamma.recall(action="search", kind="chunk",
                                                      query="Granola transcripts", limit=5), 6000)
step("gamma.recall(search, kind=item)", gamma.recall(action="search", kind="item",
                                                     query="Granola transcripts default", limit=5), 6000)
step("gamma.recall(get, kind=item, FR-131)", gamma.recall(action="get", kind="item", id=FR131))
step("gamma.recall(get, kind=item, capture)", gamma.recall(action="get", kind="item", id=CAPTURED_URL))
step("gamma.recall(get, kind=claim, beta)", gamma.recall(action="get", kind="claim", id=bc["id"]))
c = step("gamma.recall(get, kind=conflict)", gamma.recall(action="get", kind="conflict", id=cid))["data"]
conflict = c.get("conflict", c)
a_now = gamma.recall(action="get", kind="claim", id=5)["data"]["claim"]
step("gamma.retract(alpha claim 5) -> expect not_owner", gamma.remember(
    action="retract", idempotency_key="trial/gamma/retract5/v1", claim_id=5,
    expected_revision=a_now["revision"], reason="gamma disagrees"))
step("gamma.resolve(naming alpha claim) -> expect not_owner", gamma.remember(
    action="resolve", idempotency_key="trial/gamma/resolve/v1", conflict_id=cid,
    expected_revision=conflict["revision"], expected_member_count=conflict["member_count"],
    retract_claim_ids=[5]))
step("alpha.acknowledge", alpha.remember(
    action="acknowledge", idempotency_key="trial/alpha/ack/v2", conflict_id=cid,
    expected_revision=conflict["revision"], reason="asking Scott in #fleet-recall-dev"))
step("gamma.recall(conflicts) after ack", gamma.recall(action="conflicts"))
step("beta.resolve(retract own member)", beta.remember(
    action="resolve", idempotency_key="trial/beta/resolve/v2", conflict_id=cid,
    expected_revision=conflict["revision"], expected_member_count=conflict["member_count"],
    retract_claim_ids=[bc["id"]], reason="standup capture was a misread; FR-131 stays Done"))
step("gamma.recall(conflicts) after resolve", gamma.recall(action="conflicts"))
step("gamma.recall(get, kind=conflict) after resolve", gamma.recall(action="get", kind="conflict", id=cid))
step("gamma.recall(get, kind=claim, alpha) after resolve", gamma.recall(action="get", kind="claim", id=5))
step("gamma.recall(search, kind=claim) after resolve", gamma.recall(action="search", kind="claim",
                                                                    query="Granola transcripts default", limit=5))
for s in (alpha, beta, gamma):
    s.close()
