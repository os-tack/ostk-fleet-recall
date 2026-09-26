# Recall trial kit

The question set, synthetic Slack and Linear data, and scripts behind the
hands-on trial recorded in
[`docs/TRIAL_FINDINGS_2026-09-26.md`](../../docs/TRIAL_FINDINGS_2026-09-26.md).
Rerun it with the real `potion-retrieval-32M` model to measure what the first
trial could not: dense-lane relevance, and whether `absent` still happens once
every query embeds.

Everything here is synthetic. The only token-shaped strings are obvious
placeholders (`xoxb-EXAMPLE-NOT-A-TOKEN`), and the private channel and DM in
the export exist to prove they are never read.

| File | What it does |
| --- | --- |
| `questions.json` | 20 questions, each with a natural-language `call`, a keyword `retry`, and the `expected` source written before the first run |
| `gen_data.py` | Writes `data/`: two Slack export versions (v2 deletes a thread root and edits a reply) and two Linear JSONL versions (v2 deletes FR-150 and edits FR-131) |
| `mcp.py` | Minimal stdio MCP client that starts `serve` as a named agent |
| `ask.py` | Runs every question (natural, then retry) as one agent; saves raw and compact answers to `qa/` |
| `scenario_conflict.py`, `scenario_conflict2.py` | Capture, claims citing items, a two-agent conflict, `not_owner`, acknowledge, resolve |
| `scenario_delete.py` | `before` / `after` probes around the v2 imports that delete and edit items |
| `fake_slack.py` | Local fake Slack Web API over `data/slack-export-v1`, for the pull collector |

## Rerun

1. Finish the README's **Local quickstart** steps 1 to 10 with the real model.
   Keep that shell's environment: the scope, the writer URL, the pins, the
   content key, and `$FLEET_RECALL_BIN`.
2. Point the kit at the checkout and the writer:

   ```sh
   export REPO="$PWD"                    # the repository root
   export T="$REPO/examples/trial"       # outputs land in ignored data/, qa/, scenarios/
   export WRITER_URL="$FLEET_RECALL_DATABASE_URL"
   ```

3. Generate the data and import the first versions:

   ```sh
   python3 "$T/gen_data.py"
   "$FLEET_RECALL_BIN" collect import --instance import.slack-ostk --principal principal.import \
     --provider slack --provider-scope T07OSTK0001 --audience operator-declared \
     --format slack-export --path "$T/data/slack-export-v1"
   "$FLEET_RECALL_BIN" collect import --instance import.linear-ostk --principal principal.import \
     --provider linear --provider-scope 0a9c0000-0000-4000-8000-00000000f1ee \
     --audience operator-declared --format items-jsonl --path "$T/data/linear-v1.jsonl"
   ```

   Also add this repository's `docs/` and `README.md` as a documents source
   and its git history as a git source in the quickstart's worker sources
   file, then run the worker once with `--steps all` so everything is admitted
   and projected (the questions expect ADRs, the README, and commit subjects).
4. Ask:

   ```sh
   cd "$T" && python3 ask.py asker | tee qa/run.txt
   ```

   Grade each answer against its `expected` field **before** looking at the
   previous grades in the findings doc, then compare.
5. Optional scenarios: `python3 scenario_conflict.py`, `python3
   scenario_conflict2.py`, then `python3 scenario_delete.py before`, import the
   `-v2` data the same way as step 3, run a worker `project` tick, and
   `python3 scenario_delete.py after`. They read ids from earlier steps, so run
   them in that order on the same database.

## What to look for with the real model

- Do natural-language questions (Q1, Q3, Q5, Q13, Q14, Q20) now find the
  right source through the dense lane, or does all-terms lexical matching
  still decide the answer?
- Does the dense lane put unrelated neighbours above correct lexical hits?
- Q19 (a topic that was never discussed): does it still come back `absent`, or
  does any neighbour at cosine ≥ 0.18 turn it `present` (ADR 0006 D4)?
- Q18 (claim search is dense only): is the migration-strategy claim first?
