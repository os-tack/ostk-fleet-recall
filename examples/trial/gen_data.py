"""Generate a realistic synthetic Slack export (two snapshots) and Linear items
about real topics of ostk-fleet-recall, with deliberate disagreements.

Outputs under trial/data/:
  slack-export-v1/   first export (directory form)
  slack-export-v2/   later export: a thread root deleted (tombstone), a plain
                     message deleted (simply absent), one message edited
  linear-v1.jsonl    Linear issues and comments (items-jsonl)
  linear-v2.jsonl    later Linear file: FR-150 deleted, FR-131 edited
"""

import json
import os
import shutil
from datetime import datetime, timezone

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
TEAM = "T07OSTK0001"
DEV = "C07RECALLDEV"
OPS = "C07FLEETOPS"
PRIV = "G07SECPRIV1"
USERS = [
    {"id": "U07SCOTT001", "name": "scott", "real_name": "Scott Meyer"},
    {"id": "U07PRIYA002", "name": "priya", "real_name": "Priya Raman"},
    {"id": "U07MARCO003", "name": "marco", "real_name": "Marco Bellini"},
    {"id": "U07JUNE0004", "name": "june", "real_name": "June Park"},
]
SCOTT, PRIYA, MARCO, JUNE = (u["id"] for u in USERS)


def ts(iso, micro=0):
    dt = datetime.fromisoformat(iso).replace(tzinfo=timezone.utc)
    return f"{int(dt.timestamp())}.{micro:06d}"


def msg(user, when, text, micro=0, thread=None, subtype=None, **extra):
    m = {"type": "message", "user": user, "ts": ts(when, micro), "text": text}
    if thread:
        m["thread_ts"] = thread
        if thread != m["ts"]:
            m["parent_user_id"] = extra.pop("parent_user", None) or SCOTT
    if subtype:
        m["subtype"] = subtype
    m.update(extra)
    return m


def dev_messages(version):
    days = {}
    # Thread 1: migrations. Marco proposes per-replica migrate; Priya objects;
    # Scott decides single dedicated migrator; Marco keeps a residual ask.
    t1 = ts("2026-09-08T15:02:11", 100)
    days.setdefault("2026-09-08", []).extend([
        msg(MARCO, "2026-09-08T15:02:11", "Proposal: have every `serve` replica run `migrate` on startup so we never "
            "forget a migration after a deploy. One less job to babysit.", 100, thread=t1,
            reply_count=4, reply_users=[PRIYA, SCOTT, MARCO]),
        msg(PRIYA, "2026-09-08T15:09:40", "Strong no. MIGRATIONS.md says never run multiple migrators concurrently: most "
            "migrations run without a wrapping transaction, so two replicas racing can leave half-applied DDL "
            "behind. And serve only holds the DML-only fleet_writer login anyway.", 200, thread=t1, parent_user=MARCO),
        msg(SCOTT, "2026-09-08T15:21:05", "Decision: schema migrations run from a single dedicated migrator job (the "
            "fleet_migrator login), and the boundary helper retires that login right after. serve never gets DDL. "
            "Tracking in FR-118.", 300, thread=t1, subtype="thread_broadcast", parent_user=MARCO),
        msg(MARCO, "2026-09-08T15:30:52", "Fine, single migrator. I still want serve to refuse to start on a schema "
            "mismatch instead of failing on the first query though.", 400, thread=t1, parent_user=MARCO),
        msg(JUNE, "2026-09-08T15:33:10", "+1 to Marco's startup check. `health` already checks the schema prefix, "
            "serve could reuse it.", 500, thread=t1, parent_user=MARCO),
    ])
    # Thread 2: Granola transcripts. June wants them on by default, Priya and
    # Scott decide off by default; June carves out an exception.
    t2 = ts("2026-09-10T09:14:03", 100)
    days.setdefault("2026-09-10", []).extend([
        msg(JUNE, "2026-09-10T09:14:03", "Can we flip Granola `include_transcript` on by default? The AI summaries miss "
            "half the action items from standup.", 100, thread=t2, reply_count=3, reply_users=[PRIYA, SCOTT, JUNE]),
        msg(PRIYA, "2026-09-10T09:20:44", "No. Transcripts carry every word anyone said in a meeting, including things "
            "nobody meant to hand to a fleet of agents. Keep include_transcript off by default and make it an explicit "
            "per-collector opt-in.", 200, thread=t2, parent_user=JUNE),
        msg(SCOTT, "2026-09-10T09:31:17", "Agree with Priya: Granola transcripts stay off by default, summaries only. "
            "An operator can opt a folder in. Writing it up in FR-131.", 300, thread=t2, subtype="thread_broadcast",
            parent_user=JUNE),
        msg(JUNE, "2026-09-10T09:40:02", "OK. For the fleet-ops standup folder I'm turning transcripts on anyway, "
            "that meeting is all action items.", 400, thread=t2, parent_user=JUNE),
    ])
    # Thread 3: absence verdict bug + disagreement on staleness.
    t3 = ts("2026-09-15T13:05:29", 100)
    priya_bug = ("If a source was failing the answer should have been `unknown` with `source_failed`. The verdict is "
                 "`absent` only when every source is healthy, fresh, and completely covered. That's a bug, filed FR-127.")
    if version == 2:
        priya_bug += " (edit: it was the Linear import snapshot, not the collector; see FR-127 comments)"
    priya_extra = {"edited": {"user": PRIYA, "ts": ts("2026-09-16T08:00:00", 0)}} if version == 2 else {}
    days.setdefault("2026-09-15", []).extend([
        msg(MARCO, "2026-09-15T13:05:29", "An agent asked \"did we ever pick a retry budget for the Linear collector\" "
            "and got `absent`. That can't be right, the Linear collector had been failing since Tuesday.", 100,
            thread=t3, reply_count=4, reply_users=[PRIYA, JUNE, SCOTT]),
        msg(PRIYA, "2026-09-15T13:11:02", priya_bug, 200, thread=t3, parent_user=MARCO, **priya_extra),
        msg(JUNE, "2026-09-15T13:18:45", "I don't think it was failing, it was stale. The stale window is a day, so a "
            "source whose last success was 20 hours ago still counts as fresh.", 300, thread=t3, parent_user=MARCO),
        msg(SCOTT, "2026-09-15T13:26:12", "Then shorten stale_after to 6 hours for every collector.", 400, thread=t3,
            parent_user=MARCO),
        msg(PRIYA, "2026-09-15T13:34:58", "That won't validate: stale_after_seconds may not be shorter than "
            "reconcile_every_seconds, and Slack reconciles every 86400. Six hours needs a faster reconcile first.",
            500, thread=t3, parent_user=MARCO),
    ])
    # Thread 4: why was forget removed.
    t4 = ts("2026-09-17T16:40:00", 100)
    days.setdefault("2026-09-17", []).extend([
        msg(JUNE, "2026-09-17T16:40:00", "Why did we remove `forget` from the remember actions? I had an agent that "
            "wanted to purge a leaked token it had recorded in a claim.", 100, thread=t4, reply_count=2,
            reply_users=[SCOTT, PRIYA]),
        msg(SCOTT, "2026-09-17T16:52:31", "We pulled forget because erasure is not a row delete. Once a body is "
            "projected, its plaintext sits in memory_body_objects_v1 plus the lexical and dense rows, and destroying "
            "the content key no longer erases it. A forget that only retires the claim would lie about what it did. "
            "It stays reserved until we design a real purge.", 200, thread=t4, parent_user=JUNE),
        msg(PRIYA, "2026-09-17T17:01:09", "For the leaked token: retract the claim now, and rotate the token. The "
            "redactor should have caught it at capture anyway.", 300, thread=t4, parent_user=JUNE),
    ])
    # Thread 5: worker cadence disagreement (no decision).
    t5 = ts("2026-09-18T10:00:00", 100)
    days.setdefault("2026-09-18", []).extend([
        msg(MARCO, "2026-09-18T10:00:00", "The README cron runs the memory worker every 15 minutes. Is that what we "
            "run in staging?", 100, thread=t5, reply_count=2, reply_users=[JUNE, PRIYA]),
        msg(JUNE, "2026-09-18T10:04:12", "Staging runs the worker every 5 minutes. 15 is too slow for Slack threads "
            "people are actively arguing in.", 200, thread=t5, parent_user=MARCO),
        msg(PRIYA, "2026-09-18T10:09:30", "Keep 15. Webhooks shorten the interval: ingress keeps each delivery as a "
            "hint and the next tick re-reads the object. Running every 5 minutes just burns Slack rate limit.", 300,
            thread=t5, parent_user=MARCO),
    ])
    # Thread 6: display names (root later deleted, replies remain -> tombstone).
    t6 = ts("2026-09-19T11:11:11", 100)
    root6 = msg(MARCO, "2026-09-19T11:11:11", "Hot take: we should keep Slack display names on collected messages so "
                "agents can answer who said what without a users.json lookup.", 100, thread=t6, reply_count=1,
                reply_users=[PRIYA])
    if version == 2:
        root6 = {"type": "message", "subtype": "tombstone", "user": "USLACKBOT", "ts": t6, "thread_ts": t6,
                 "text": "This message was deleted.", "reply_count": 1, "reply_users": [PRIYA], "hidden": True}
    days.setdefault("2026-09-19", []).extend([
        root6,
        msg(PRIYA, "2026-09-19T11:20:00", "No: a display name is a mutable profile field. We keep the user id, and an "
            "agent resolves it when it needs a name.", 200, thread=t6, parent_user=MARCO),
    ])
    # A plain (non-thread) message that is later deleted in Slack: absent from v2.
    if version == 1:
        days.setdefault("2026-09-20", []).append(
            msg(JUNE, "2026-09-20T18:45:00", "Posting here by mistake: the staging worker cron moved to the "
                "quokka-7 box, ping me if ticks stop.", 100))
    days.setdefault("2026-09-20", []).append(
        msg(SCOTT, "2026-09-20T19:02:00", "Reminder: evidence recall only says `absent` for a word that appears "
            "nowhere when the git source's last check is fresh and covered its whole range.", 200))
    # Channel join noise (skipped by the importer)
    days["2026-09-08"].insert(0, {"type": "message", "subtype": "channel_join", "user": JUNE,
                                   "ts": ts("2026-09-08T09:00:00", 1), "text": "<@U07JUNE0004> has joined the channel"})
    return days


def ops_messages(version):
    return {
        "2026-09-12": [
            msg(SCOTT, "2026-09-12T08:30:00", "Heads up: the public demo must never show asserted claims. The "
                "predicate's publication default is denied. If you see one on the demo page, page me.", 100),
            msg(JUNE, "2026-09-12T08:41:00", "FLEET_RECALL_CONTENT_KEK_HEX has to be the same key on every host of a "
                "scope. Please nobody rotate it casually, project unwraps with it everything ingest wrapped.", 200),
            msg(MARCO, "2026-09-12T09:02:00", "Debug token for the local fake Slack, don't use elsewhere: "
                "xoxb-EXAMPLE-NOT-A-TOKEN", 300),
        ],
        "2026-09-22": [
            msg(PRIYA, "2026-09-22T14:00:00", "Postmortem for the Tuesday absence incident is in FR-127. Short "
                "version: an import snapshot stayed current for 30 days after its source had moved on.", 100),
        ],
    }


def priv_messages():
    return {"2026-09-13": [msg(PRIYA, "2026-09-13T10:00:00", "PRIVATE: the pager rota secret phrase is "
                                "marmalade-otter; never paste it in public channels.", 100)]}


def write_export(root, version):
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(root)
    with open(os.path.join(root, "users.json"), "w") as f:
        json.dump(USERS, f, indent=1)
    channels = [
        {"id": DEV, "name": "fleet-recall-dev", "created": 1780000000, "creator": SCOTT, "is_archived": False,
         "is_general": False, "members": [SCOTT, PRIYA, MARCO, JUNE], "topic": {"value": "Fleet Recall development"},
         "purpose": {"value": "Design and implementation of ostk-fleet-recall"}},
        {"id": OPS, "name": "fleet-ops", "created": 1780000000, "creator": SCOTT, "is_archived": False,
         "is_general": False, "members": [SCOTT, PRIYA, MARCO, JUNE], "topic": {"value": "Operating the fleet"},
         "purpose": {"value": "Deploys, workers, keys"}},
    ]
    with open(os.path.join(root, "channels.json"), "w") as f:
        json.dump(channels, f, indent=1)
    with open(os.path.join(root, "groups.json"), "w") as f:
        json.dump([{"id": PRIV, "name": "security-private", "created": 1780000000, "creator": PRIYA,
                    "is_archived": False, "members": [PRIYA, SCOTT]}], f, indent=1)
    with open(os.path.join(root, "dms.json"), "w") as f:
        json.dump([{"id": "D07SCOTTJUN", "created": 1780000000, "members": [SCOTT, JUNE]}], f, indent=1)
    with open(os.path.join(root, "mpims.json"), "w") as f:
        json.dump([], f)
    for folder, days in [("fleet-recall-dev", dev_messages(version)), ("fleet-ops", ops_messages(version)),
                         ("security-private", priv_messages()),
                         ("D07SCOTTJUN", {"2026-09-14": [msg(JUNE, "2026-09-14T12:00:00",
                                                             "DM: honestly I think Marco's migrate idea was fine", 1)]})]:
        os.makedirs(os.path.join(root, folder))
        for day, messages in days.items():
            with open(os.path.join(root, folder, f"{day}.json"), "w") as f:
                json.dump(sorted(messages, key=lambda m: m["ts"]), f, indent=1)


ORG = "0a9c0000-0000-4000-8000-00000000f1ee"
TEAMID = "7b1d0c00-0000-4000-8000-0000000000f1"
LU = {
    "scott": "5c0770aa-0000-4000-8000-000000000001",
    "priya": "5c0770aa-0000-4000-8000-000000000002",
    "marco": "5c0770aa-0000-4000-8000-000000000003",
    "june": "5c0770aa-0000-4000-8000-000000000004",
}


def issue(n, uid, title, state, body, author, created, updated, lifecycle="live", links=None):
    ident = f"FR-{n}"
    slug = title.lower().replace(" ", "-").replace("`", "")[:40].strip("-")
    item = {
        "provider": "linear", "provider_scope_id": ORG, "object_kind": "issue", "external_id": uid,
        "version": {"marker": updated}, "lifecycle": lifecycle,
        "container": {"kind": "linear.team", "id": TEAMID, "label": "FR"},
        "author": {"id": LU[author], "display": author, "kind": "human"},
        "created_at": created, "updated_at": updated, "title": title,
        "text": f"{ident} {title}\nState: {state}\n\n{body}", "text_format": "markdown",
        "url": f"https://linear.app/ostk/issue/{ident}/{slug}", "visibility": "team_public",
    }
    if links:
        item["links"] = links
    return item


def comment(cid, issue_uid, issue_ident, author, when, text, lifecycle="live"):
    return {
        "provider": "linear", "provider_scope_id": ORG, "object_kind": "comment", "external_id": cid,
        "version": {"marker": when}, "lifecycle": lifecycle,
        "container": {"kind": "linear.team", "id": TEAMID, "label": "FR"},
        "thread": {"root_external_id": issue_uid},
        "author": {"id": LU[author], "display": author, "kind": "human"},
        "created_at": when, "updated_at": when, "text": text, "text_format": "markdown",
        "url": f"https://linear.app/ostk/issue/{issue_ident}#comment-{cid[:8]}", "visibility": "team_public",
    }


I118 = "a1180000-0000-4000-8000-000000000118"
I127 = "a1270000-0000-4000-8000-000000000127"
I131 = "a1310000-0000-4000-8000-000000000131"
I140 = "a1400000-0000-4000-8000-000000000140"
I144 = "a1440000-0000-4000-8000-000000000144"
I150 = "a1500000-0000-4000-8000-000000000150"
I155 = "a1550000-0000-4000-8000-000000000155"


def linear_items(version):
    items = [
        issue(118, I118, "Run schema migrations from a single dedicated migrator", "Done",
              "Decided in #fleet-recall-dev: `migrate` runs once, from one dedicated job holding the `fleet_migrator` "
              "login, before serve takes traffic. The database boundary helper then retires the migrator. Serve "
              "replicas never run migrate (they hold the DML-only `fleet_writer`).\n\nFollow-up (Marco): serve should "
              "refuse to start on a schema mismatch.", "scott", "2026-09-08T15:25:00.000Z", "2026-09-09T10:00:00.000Z"),
        issue(127, I127, "Absence verdict reads absent while a collector is failing", "In Progress",
              "Repro: agent asked whether we picked a retry budget for the Linear collector; `recall(kind=item)` "
              "answered `absence.verdict = absent` although the Linear collector had failed since Tuesday.\n\n"
              "Expected: `unknown` with reason `source_failed` (or `source_stale`). `absent` is only allowed when "
              "every source is healthy, fresh, and completely covered.", "priya", "2026-09-15T13:40:00.000Z",
              "2026-09-22T14:05:00.000Z"),
        comment("c1270001-0000-4000-8000-000000000001", I127, "FR-127", "marco", "2026-09-16T09:00:00.000Z",
                "Root cause: the Linear *import* snapshot was still current (30 day --stale-after), so the absence "
                "judge counted linear as covered even though the live collector was failing."),
        comment("c1270002-0000-4000-8000-000000000002", I127, "FR-127", "june", "2026-09-16T09:30:00.000Z",
                "I disagree with that root cause. The collector was stale, not failing, and the stale window is too "
                "long. We should shorten stale_after to 6 hours."),
        issue(131, I131, "Keep Granola transcripts off by default", "Done" if version == 1 else "Reopened",
              "Granola `include_transcript` stays **false** by default; the collector stages AI summaries only. An "
              "operator can opt a folder in. Private notes and attendees are never read." +
              ("" if version == 1 else "\n\nReopened by June: enterprise customers are asking for transcripts on by "
               "default."), "scott", "2026-09-10T09:35:00.000Z",
              "2026-09-10T11:00:00.000Z" if version == 1 else "2026-09-23T08:00:00.000Z",
              lifecycle="live" if version == 1 else "edited"),
        comment("c1310001-0000-4000-8000-000000000001", I131, "FR-131", "june", "2026-09-11T08:00:00.000Z",
                "For the record I still think transcripts should default to on for standup folders."),
        issue(140, I140, "Webhook ingress keeps hints only, never content", "Done",
              "`ostk-fleet-recall ingress` verifies Slack, Linear, and Granola signatures and stores a hint of "
              "provider ids only. The worker's collect step re-reads the object through the collector's API token. "
              "A hint never counts as coverage.", "priya", "2026-09-05T12:00:00.000Z", "2026-09-06T12:00:00.000Z"),
        issue(144, I144, "Public demo must withhold asserted claims", "In Review",
              "The publication plane (demo) serves the record-only surface. Asserted claims, their synthetic chunks, "
              "and their conflicts must never show, because the predicate's publication default is denied.",
              "scott", "2026-09-12T08:35:00.000Z", "2026-09-12T08:35:00.000Z"),
        issue(150, I150, "Decide the memory worker tick interval", "Backlog",
              "README cron says every 15 minutes; staging runs every 5. Priya: keep 15 and rely on webhooks. June: 5.",
              "marco", "2026-09-18T10:15:00.000Z", "2026-09-18T10:15:00.000Z"),
        issue(155, I155, "Keep Slack display names on collected messages", "Canceled",
              "Canceled: display names are mutable profile fields; collected Slack messages keep the user id only.",
              "marco", "2026-09-19T11:30:00.000Z", "2026-09-19T12:00:00.000Z"),
    ]
    if version == 2:
        items = [i for i in items if i["external_id"] not in (I150,)]
        gone = issue(150, I150, "Decide the memory worker tick interval", "Backlog", "(deleted)", "marco",
                     "2026-09-18T10:15:00.000Z", "2026-09-24T09:00:00.000Z", lifecycle="deleted")
        items.append(gone)
    return items


def main():
    os.makedirs(OUT, exist_ok=True)
    write_export(os.path.join(OUT, "slack-export-v1"), 1)
    write_export(os.path.join(OUT, "slack-export-v2"), 2)
    for version in (1, 2):
        with open(os.path.join(OUT, f"linear-v{version}.jsonl"), "w") as f:
            for item in linear_items(version):
                f.write(json.dumps(item) + "\n")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
