"""Upstream deletion scenario: probe before/after importing later snapshots."""

import json
import os
import sys

from mcp import Serve, dump

T = os.environ["T"]
phase = sys.argv[1]  # before | after
PROBES = [
    ("marco hot-take root (tombstoned in v2)", "item", "Hot take Slack display names users.json lookup"),
    ("priya reply under tombstoned root", "item", "display name mutable profile field"),
    ("june plain message (absent from v2)", "item", "quokka-7 box"),
    ("priya edited message", "item", "source failing unknown source_failed bug"),
    ("FR-150 (deleted in v2)", "item", "Decide the memory worker tick interval"),
    ("FR-131 (edited in v2)", "item", "Keep Granola transcripts off by default"),
    ("quokka via evidence", "evidence", "quokka-7 box"),
    ("hot take via evidence", "evidence", "Hot take Slack display names users.json lookup"),
]


def brief(result):
    d = result.get("data") or {}
    return {
        "verdict": (d.get("absence") or {}).get("verdict"),
        "reasons": (d.get("absence") or {}).get("reasons"),
        "hits": [{
            "item_id": (h.get("item_id") or (h.get("item") or {}).get("item_id") or "")[:12],
            "provider": h.get("provider") or (h.get("item") or {}).get("provider"),
            "matched_by": h.get("matched_by"),
            "current": h.get("current", (h.get("item") or {}).get("current")),
            "superseded_versions": h.get("superseded_versions"),
            "snippet": (h.get("snippet") or "")[:110],
        } for h in d.get("hits", [])[:4]],
    }


s = Serve("agent-alpha", extra_env={"FLEET_RECALL_COLLECTED_CAPTURE": "enabled"})
out = {}
ids = {}
for label, kind, query in PROBES:
    r = s.recall(action="search", kind=kind, query=query, limit=4)
    out[label] = {"query": query, "kind": kind, "raw": r, "brief": brief(r)}
    print(f"[{phase}] {label}: {json.dumps(out[label]['brief'], ensure_ascii=False)[:900]}")
    if kind == "item":
        lex = [h for h in (r.get("data") or {}).get("hits", []) if h.get("matched_by") in ("lexical", "lexical_and_dense")]
        if lex:
            ids[label] = lex[0]["item_id"]

if phase == "before":
    # a claim that cites the soon-deleted FR-150 and the soon-tombstoned root
    cite = [{"item": {"url": "https://linear.app/ostk/issue/FR-150/decide-the-memory-worker-tick-interval"}, "relation": "supports"}]
    if "marco hot-take root (tombstoned in v2)" in ids:
        cite.append({"item": {"item_id": ids["marco hot-take root (tombstoned in v2)"]}, "relation": "supports"})
    r = s.remember(action="record", idempotency_key="trial/alpha/cites-doomed/v1", kind="note",
                   text="Open questions: tick interval (FR-150) and whether to keep Slack display names.",
                   subject="open questions", predicate="tracking", support=cite)
    out["record citing doomed items"] = r
    print("[before] record citing doomed items:", json.dumps(r.get("error") or {"id": r["data"]["claim"]["id"], "support": len(r["data"]["claim"]["support"])}))
    json.dump(ids, open(f"{T}/scenarios/delete-ids.json", "w"))
else:
    ids = json.load(open(f"{T}/scenarios/delete-ids.json"))
    for label, item_id in ids.items():
        g = s.recall(action="get", kind="item", id=item_id)
        out[f"get {label}"] = g
        d = g.get("data") or {}
        it = (d.get("item") or {})
        print(f"[after] get {label}: error={json.dumps(g.get('error'))[:300]} item={json.dumps(it.get('item'))[:300]} "
              f"history={len(it.get('history') or [])} current_text={json.dumps(((it.get('current') or {}).get('parts') or [{}])[0].get('text'))[:160]}")
    claims = s.recall(action="search", kind="claim", query="Open questions tick interval display names", limit=10)
    note = [h for h in claims["data"]["hits"] if h["claim"]["text"].startswith("Open questions")]
    if note:
        g = s.recall(action="get", kind="claim", id=note[0]["claim"]["id"])
        out["get note claim"] = g
        print("[after] note claim support_items:", json.dumps([{k: si.get(k) for k in ("provider", "current", "hidden_reason", "withdrawn", "trust")} for si in g["data"].get("support_items", [])]), "independent_sources=", g["data"].get("independent_sources"))
    h = s.recall(action="search", kind="item", query="source failing unknown source_failed bug", include_history=True, limit=3)
    out["priya edited include_history"] = h
    print("[after] include_history:", json.dumps([{"snippet": x.get("snippet", "")[:120], "current": x.get("current"), "version": x.get("version")} for x in h["data"]["hits"]])[:1200])
dump(f"{T}/scenarios/delete-{phase}.json", out)
s.close()
