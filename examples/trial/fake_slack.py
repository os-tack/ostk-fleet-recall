"""A local fake of the four Slack Web API methods the collector calls, serving
the synthetic workspace from data/slack-export-v1. Requests are logged (the
Authorization header is logged only as its scheme) to fake_slack_requests.log.

POST /control/delete?channel=C..&ts=...  removes a message (as Slack would).
"""

import glob
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
EXPORT = os.path.join(HERE, "data", "slack-export-v1")
TEAM = "T07OSTK0001"
LOG = open(os.path.join(HERE, "fake_slack_requests.log"), "a")
LOCK = threading.Lock()


def micros(ts):
    s, f = ts.split(".")
    return int(s) * 1_000_000 + int(f)


def load():
    world = {}
    for ch in json.load(open(os.path.join(EXPORT, "channels.json"))):
        top, threads = [], {}
        for day in sorted(glob.glob(os.path.join(EXPORT, ch["name"], "*.json"))):
            for m in json.load(open(day)):
                if m.get("subtype") == "channel_join":
                    continue
                t = m.get("thread_ts")
                if t and t != m["ts"]:
                    threads.setdefault(t, []).append(m)
                    if m.get("subtype") == "thread_broadcast":
                        top.append(m)
                else:
                    top.append(m)
        for m in top:
            reps = threads.get(m["ts"])
            if reps and m.get("thread_ts") == m["ts"]:
                m["latest_reply"] = max((r["ts"] for r in reps), key=micros)
                m["reply_count"] = len(reps)
        world[ch["id"]] = {"name": ch["name"], "top": top, "threads": threads}
    return world


WORLD = load()


def page(messages, q):
    limit = int(q.get("limit", ["100"])[0])
    cursor = q.get("cursor", [""])[0]
    offset = int(cursor[1:]) if cursor.startswith("o") else 0
    end = min(offset + limit, len(messages))
    more = end < len(messages)
    return {"ok": True, "messages": messages[offset:end], "has_more": more,
            "response_metadata": {"next_cursor": f"o{end}" if more else ""}}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_any(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if self.command == "POST" and self.headers.get("content-length"):
            q.update(parse_qs(self.rfile.read(int(self.headers["content-length"])).decode()))
        auth = self.headers.get("authorization", "")
        LOG.write(json.dumps({"method": self.command, "path": url.path,
                              "params": {k: v[0] for k, v in q.items() if k != "token"},
                              "auth_scheme": auth.split(" ")[0] if auth else None,
                              "token_in_query": "token" in q}) + "\n")
        LOG.flush()
        method = url.path.rsplit("/", 1)[-1]
        with LOCK:
            if url.path.startswith("/control/delete"):
                ch = WORLD[q["channel"][0]]
                ts = q["ts"][0]
                before = len(ch["top"])
                ch["top"] = [m for m in ch["top"] if m["ts"] != ts]
                return self.reply({"ok": True, "removed": before - len(ch["top"])})
            chan_id = q.get("channel", [None])[0]
            ch = WORLD.get(chan_id)
            if method == "auth.test":
                return self.reply({"ok": True, "url": "https://ostk.slack.com/", "team": "OSTK", "user": "fleet-recall",
                                   "team_id": TEAM, "user_id": "U07BOT0001", "bot_id": "B07BOT0001",
                                   "is_enterprise_install": False})
            if method.startswith("conversations.") and ch is None:
                return self.reply({"ok": False, "error": "channel_not_found"})
            if method == "conversations.info":
                return self.reply({"ok": True, "channel": {
                    "id": chan_id, "name": ch["name"], "is_channel": True, "is_group": False, "is_im": False,
                    "is_mpim": False, "is_private": False, "is_archived": False, "is_ext_shared": False,
                    "is_org_shared": False, "is_shared": False, "is_pending_ext_shared": False}})
            if method == "conversations.history":
                oldest = q.get("oldest", [None])[0]
                latest = q.get("latest", [None])[0]
                msgs = [m for m in ch["top"]
                        if (oldest is None or micros(m["ts"]) > micros(oldest))
                        and (latest is None or micros(m["ts"]) < micros(latest))]
                msgs.sort(key=lambda m: -micros(m["ts"]))
                return self.reply(page(msgs, q))
            if method == "conversations.replies":
                root_ts = q.get("ts", [""])[0]
                root = next((m for m in ch["top"] if m["ts"] == root_ts), None)
                if root is None:
                    return self.reply({"ok": False, "error": "thread_not_found"})
                replies = sorted(ch["threads"].get(root_ts, []), key=lambda m: micros(m["ts"]))
                return self.reply(page([root] + replies, q))
        return self.reply({"ok": False, "error": "unknown_method"}, 404)

    do_GET = handle_any
    do_POST = handle_any


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18765
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
