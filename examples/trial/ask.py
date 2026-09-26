"""Run questions.json over MCP as one agent; save raw answers and a compact view."""

import json
import os
import sys

from mcp import Serve, dump

T = os.environ["T"]
QA = f"{T}/qa"
os.makedirs(QA, exist_ok=True)


def compact_hit(hit):
    item = hit.get("item") or {}
    src = hit
    title = src.get("title") or item.get("title")
    author = (src.get("author") or item.get("author") or {}).get("id")
    return {
        "kind": src.get("media_type") or src.get("object_kind") or item.get("object_kind"),
        "provider": src.get("provider") or item.get("provider"),
        "container": ((src.get("container") or item.get("container") or {}).get("label")),
        "author": author,
        "title": title,
        "matched_by": src.get("matched_by"),
        "lex": src.get("lexical_score"),
        "dense": src.get("dense_similarity"),
        "current": src.get("current", item.get("current")),
        "disagreement": src.get("disagreement", item.get("disagreement")),
        "conflicts": src.get("conflicts") or item.get("conflicts"),
        "snippet": (src.get("snippet") or src.get("text") or "")[:220],
        "url": src.get("provider_url") or item.get("provider_url"),
    }


def compact(result):
    if "error" in result:
        return {"error": result["error"]}
    data = result.get("data") or {}
    out = {}
    if isinstance(data, dict):
        if "absence" in data:
            out["absence"] = data["absence"]
        if "hits" in data:
            hits = []
            for h in data["hits"][:8]:
                if "claim" in h:
                    c = h["claim"]
                    hits.append({"claim_id": c.get("id"), "key": c.get("claim_key"), "value": c.get("value"),
                                 "state": c.get("state"), "text": c.get("text")})
                else:
                    hits.append(compact_hit(h))
            out["hits"] = hits
        for key in ("conflicts", "discrepancies", "specs"):
            if key in data:
                out[key] = data[key]
    out["warnings"] = (result.get("structured") or {}).get("warnings")
    return out


def main():
    agent = sys.argv[1] if len(sys.argv) > 1 else "asker"
    only = set(int(x) for x in sys.argv[2:]) if len(sys.argv) > 2 else None
    questions = json.load(open(f"{T}/questions.json"))
    s = Serve(agent)
    for q in questions:
        if only and q["n"] not in only:
            continue
        record = {"n": q["n"], "question": q["question"], "expected": q["expected"]}
        for label in ("call", "retry"):
            args = q.get(label)
            if not args:
                continue
            args = dict(args)
            args.setdefault("limit", 5)
            if args["action"] in ("conflicts", "discrepancies"):
                args.pop("limit")
            result = s.recall(**args)
            record[label] = {"args": args, "raw": result, "compact": compact(result)}
        dump(f"{QA}/q{q['n']:02d}.json", record)
        print(f"#### Q{q['n']}: {q['question']}")
        print(f"   expected: {q['expected']}")
        for label in ("call", "retry"):
            if label in record:
                print(f"   [{label}] {json.dumps(record[label]['args'])}")
                print("   " + json.dumps(record[label]["compact"], ensure_ascii=False)[:3500])
        sys.stdout.flush()
    s.close()


if __name__ == "__main__":
    main()
