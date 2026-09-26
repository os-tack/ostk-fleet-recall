# Hands-on trial findings, 2026-09-26

**Tested:** branch `claude/remove-verification-code-z0st2q` at `93660f8`, by
driving the real binaries, not by reading tests. One evaluator followed the
README's Local quickstart literally and then used the system as a fleet of
agents would. A second, skeptical reviewer re-checked every claim against the
saved transcripts and reproduced the key findings on a fresh stack. Neither
changed the code. The questions, synthetic data and scripts are in
[`examples/trial/`](../examples/trial/README.md) so the run can be repeated
with the real embedding model.

## Verdict

- **The mechanics work.** Every quickstart step ran, and every multi-agent
  scenario below behaved as documented: conflicts, lifecycle, capture,
  citations, deletions, the absence verdict, and the public boundary.
- **Semantic recall quality is untested, not proven bad.** The pinned model
  could not be downloaded here, so the dense lane ran on a 1,884-word stand-in
  whose vectors mean nothing. Keyword (lexical) recall alone scored 8 good,
  9 partial, 3 poor over 20 questions, and most misses trace to the lexical
  lane requiring every query word.
- **Do not ingest real agent transcripts yet.** The transcript connector's
  redactor misses provider tokens (see issue 1).

## Environment and substitutions

| Item | Used | Why |
| --- | --- | --- |
| Embedding model | a 512-dim, 1,884-word stand-in bundle instead of `potion-retrieval-32M` | Hugging Face is blocked from the build environment |
| CockroachDB image | `mirror.gcr.io/cockroachdb/cockroach:v26.2.3` | Docker Hub rate limit |
| Host port | 26259 | 26257 was taken |
| Slack, Linear, Granola | synthetic export and JSONL imports, plus a local fake Slack Web API | provider APIs are unreachable |
| Build | debug, separate target directory | keep the checkout untouched |

## Quickstart (README "Local quickstart", steps 1 to 10)

Every step ran with only the substitutions above. Notes worth acting on:

- **Step 1:** `model-digest` worked as written. The `hf` download step could not run here.
- **Step 3:** every database command refuses to start when *any* variable whose name starts with `PG` is set. The error is clear, but the rule is broader than libpq's own variable set, and an unrelated `PGPORT_HOST` was enough to trip it.
- **Step 5:** the README's own demo query, "What happens when fleet agents disagree?", returned 0 hits. The stand-in cannot embed it, and the lexical lane requires every word. Keyword queries ("explainable conflict") hit. Recheck with the real model.
- **Steps 3, 9, 10:** `$PWD/target/debug/ostk-authority-install` is hard-coded (twice), so a non-default target directory needs manual edits. Port 26257 appears 10 times.
- **Step 8:** the git connector ingests commit and ref facts only. File contents, such as `docs/spec.md` in the scratch repository, are not searchable evidence.
- The readiness loops contain `exit 1`, which closes an interactive shell if pasted.

## Scenarios

| Scenario | Result | Evidence |
| --- | --- | --- |
| Two agents record incompatible claims | worked | The conflict appears in `recall(conflicts)` with both members; claim hits show `state=disputed` and `conflict_ids` |
| Retract and resolve | worked | A third agent was refused `not_owner` (key not consumed); `acknowledge` set lifecycle `acknowledged`; the owner's `resolve` closed the conflict and restored the other claim |
| Capture an item read through the agent's own MCP, then cite it | worked | The public-channel message was admitted; the private channel and the DM were withheld as digest-only dead letters; `record` citing the item's URL was accepted, and `get` shows `cited_by` |
| Upstream delete and edit | worked | Export v2 tombstoned a thread root and Linear v2 deleted FR-150, so both were hidden; edits superseded with history kept; citing the deleted item was refused |
| Absence verdict | worked | `absent` with healthy sources; `unknown` with `source_failed`, `source_stale` or `no_sources_registered`, scoped per provider |
| Public demo boundary | worked | 17 probes returned no collected, evidence or asserted content; the publication login cannot read those tables |
| Slack pull against a local fake API | worked | The token was sent only as a Bearer header; 28 messages across 6 threads; pulled copies are `trust=verified` with permalinks and merged provenance |
| Git history of this repository | worked | 158 commits, 159 facts in 42 s (debug build); commit subjects are searchable |

## Recall quality

The evaluator wrote the expected source before each query, asked the natural
question first and then a keyword retry, and graded the best of the two.
**Dense hits were not credited**, since the stand-in's vectors are noise.

| # | Question | Grade | Why |
| --- | --- | --- | --- |
| 1 | Where is the absence verdict (absent vs unknown) specified? | partial | The natural question fails lexically ('specified' appears nowhere, and plainto_tsquery ANDs all terms). The retry surfaces the README summary but not the ADR section that defines it. Dense hits come from the stand-in and are not credited. |
| 2 | What did we decide about how schema migrations run? | good | The ticket carrying the decision ranked first on the natural question. The Slack decision appears on the retry. Marco's residual objection is not surfaced as a disagreement. |
| 3 | What did we decide about Granola transcripts? | partial | The natural question misses the decision ('decide' does not stem-match 'Decision'). The keyword retry is good and shows both sides. Priya's reply lacks the word 'Granola' and never ranks. |
| 4 | Why was forget removed from the remember actions? | poor | The answer is a thread reply that does not contain the question's words. recall(get) on the root lists no replies (links_in/out empty), so an agent cannot walk from the question to the answer. |
| 5 | Which ticket tracks the absence verdict bug? | partial | 'ticket', 'tracks' and 'bug' are not in the text, so the natural question is lexically empty. The keyword retry is exact. |
| 6 | Who said in Slack that Granola transcripts should stay off by default? | partial | The retry finds the right people, but only as Slack user ids. Display names are deliberately not kept and users.json is ignored, so 'who' needs an external lookup. |
| 7 | Who proposed running migrate on every serve replica at startup? | good | Exact hit at rank 1 on the natural question (author id only). |
| 8 | Which commit added the webhook ingress? | partial | The commit is found only on the keyword retry, behind docs (evidence search cannot filter to git). The git snippet is a raw flattened fact. |
| 9 | Why was redaction::secrets renamed? | good | Correct commit at #1 on the natural question. |
| 10 | How often should the memory worker tick, every 5 or 15 minutes? | partial | The disagreement is visible only after a retry, and one side's argument (Priya) is missing because her message lacks the word 'worker'. |
| 11 | Are there open conflicts between agents right now? | good | Exact, with members, values and lifecycle. |
| 12 | Which spec discrepancies are open? | good | Exact. |
| 13 | Is the public demo allowed to show asserted claims? | partial | The natural question is lexically empty ('allowed' and 'show' are absent). The keyword retry is strong. |
| 14 | Can we shorten stale_after to 6 hours for collectors? | partial | The natural question returns only the proposals, which read as 'yes', and misses the refutation. The keyword retry gets the rule and the rebuttal. |
| 15 | Does the content key have to be the same on every host? | good | After stopwords are removed, every term is present in the right passages. |
| 16 | Why don't we keep Slack display names? | good | The ticket carries the reason at #1. Priya's reply is missing (it does not contain 'Slack'). |
| 17 | Which commits touched the Linear collector? | poor | Collected docs crowd commits out of evidence results, there is no way to restrict evidence to git, and a list-style question is not what hybrid search does. |
| 18 | What claim do we hold about the migration strategy? | partial | Found, but claim search is dense-only (stand-in, 4 claims, so the ranking is not meaningful) and hits drop the typed value. |
| 19 | Did we ever discuss Kubernetes Helm charts? (absence probe) | good | Behaves per contract. Caveat: absent only because the stand-in could not embed the query. Any dense neighbour at cosine >= 0.18 would make it 'present' (ADR 0006 D4 open calibration). |
| 20 | Where is the absence verdict specified? (agent omits kind) | poor | By default recall searches the 3-chunk seed corpus plus claims. Everything collected (docs, Slack, Linear, git) is invisible unless the agent knows to pass kind=item or evidence, and nothing hints at it. |

The skeptic's adjustments to these grades:

- **Q4** is partly the retry's fault: "forget remember erasure" needs *remember*, which the answer lacks. `forget erasure` matches it. The thread problem stands.
- **Q10:** the first retry hit, FR-150, already states both sides. "Priya's side is missing" was overstated.
- **Q19** is inconclusive, not good. It came back `absent` only because the stand-in could not embed the query. With a real model every query embeds, and any neighbour at cosine ≥ 0.18 makes the answer `present` (ADR 0006 D4 leaves that floor as an open calibration).
- **Q20:** the `recall` tool description does say which kinds cover Slack, Linear, documents and git. What is missing is a hint in an *empty* chunk answer.

## Issues, ranked

### 1. Security: the transcript connector does not redact provider tokens (major)

**Fixed on 2026-09-26** (redaction profile 3, one crate-wide redactor at transcript and git ingress; see `TRIAL_RETEST_2026-09-26.md`, fix round).

The transcript redactor (`src/redaction/credential_shapes.rs`, `SecretClassV1`)
knows six shapes: a PEM private key, an AWS access key id, a Bearer header, a
`…key`/`…token`/`…secret` assignment, a password assignment, and credentials
in a URL. Slack, GitHub, Linear, Granola and Stripe tokens are caught only by
the collected-items redactor (`src/collectors/redaction.rs`). A token pasted
into an agent session is therefore stored and recallable in plaintext by every
agent, and with no `forget` or purge it cannot be erased. SECURITY.md also
defers git ingress redaction, so a secret in a commit message is stored raw.

**Fix:** give the transcript path (and git) the collected-items provider
shapes, or one shared redactor.

### 2. Conflict detection misses a spelling difference (major)

**Fixed on 2026-09-26** (`_`, `-` and whitespace are one separator; legacy rows are not rewritten, `recall(status)` counts them; see the retest doc).

`normalize_key_part` (`src/ledger/conflict.rs:20`) lowercases and joins
whitespace with `-` but keeps `_`. `Rollout Mode` and `rollout mode` share a
key and open a conflict; `rollout_mode` does not. Reproduced live. The
contract is exact-key detection, but underscores and spaces are
interchangeable in practice, so real contradictions go unnoticed.

**Fix:** treat `_` like whitespace in the normalizer. This changes keys, so
existing claims need a re-key or read-time aliasing.

### 3. The lexical lane requires every query word (major for usability)

Every lexical lane uses `plainto_tsquery` (store, evidence recall, item
recall), which ANDs all non-stopword terms. "What did we decide…" misses
"Decision: …", because *decide* stems to `decid`. Words like "specified",
"ticket" or "why" that are absent from the text empty the lane. Most
**partial** grades trace here.

**Fix:** rank on any-term matches (an OR query ranked with `ts_rank_cd`, or
`websearch_to_tsquery` plus an OR fallback) so partial overlap still ranks.

### 4. No thread context (major for "why" questions)

Hits are single messages. A thread root's `get` lists no replies, and a reply
exposes its root only on `get`, which does not accept external ids. The answer
to "why was forget removed" is a reply that shares no words with the
question, so an agent cannot walk from the question to the answer (Q4).

**Fix:** return thread replies (bounded) on `get` of a root, and the root on
`get` of a reply.

### 5. Collected content is hard to reach (minor to major)

- The default `recall` kind is `chunk`, which searches the seed corpus and claims; docs, Slack, Linear and git need `kind=item` or `kind=evidence`, and an empty chunk answer gives no hint (Q20).
- Evidence search has no `source` filter, so collected docs crowd out git commits (Q8, Q17).
- Evidence search returns a superseded version next to the current one.
- Git snippets are raw flattened facts (`recorded_parents <ts> <email> …`).
- "Who said" answers carry Slack user ids only (display names are deliberately not kept, and the export's `users.json` is ignored).
- Slack export imports have no permalink, so they cannot be cited by URL; pulled copies can.

### 6. Capture is not searchable until the next projection tick (minor)

**Fixed on 2026-09-26** for `enabled` captures, which are projected in the call (see the retest doc).

`remember(capture)` in `enabled` mode admits the item, but it is not
searchable until a worker `project` tick runs. An agent that captures and then
searches does not find what it just captured.

### 7. Smaller findings

- **Claim hits drop the value:** claim search hits return `claim.value: null` (and no support) for claims that have a value. This is intentional (`SEARCH_CLAIM_PROJECTION_SQL`, `src/ledger/cockroach.rs:74`), but a null with no `value_elided` flag reads as "no value".
- **Public demo shows retracted claims:** the demo returns retracted and superseded claims as ordinary hits, ranked above the surviving claim. This is documented (the demo serves the record-only surface), but questionable.
- **Duplicate URL in a fixture:** in `tests/fixtures/collected/items-linear.jsonl`, comments c001 and c002 share one provider URL, so get-by-URL silently returns one of them. Real Linear permalinks are unique; fix the fixture and consider an ambiguity signal.
- **Item hits hide claim disputes:** item hits carry no sign that a claim citing the item is disputed (`conflict_coverage` is `not_evaluated`). The hit's `disagreement` field means reported-versus-verified copy divergence, which is easy to misread.

## Not exercised

- The real embedding model: dense relevance, the 0.18 floor, and whether `absent` still occurs.
- Real Slack, Linear and Granola APIs. The Linear and Granola pull collectors were not run even against fakes in this trial; they have their own fixture-backed live tests.
- Webhook ingress end to end, the CI connector, and `ostk-observer-run`.
- Multiple hosts: a shared content key, concurrent workers, a multi-node cluster.
- Two projects in one database (SECURITY.md notes the publication credential can read claim and chunk rows in every project).
- Scale and release-build latency (about 250 doc sections, about 30 Slack and Linear items, 158 commits, debug build).
- A real LLM choosing tools. All 20 questions were scripted calls, so whether an agent picks `kind=item` or retries with keywords is untested.
- Erasure: `forget` is not implemented, and projected bodies survive key destruction (SECURITY.md).

## Retest with the real model

Done on 2026-09-26: see
[`TRIAL_RETEST_2026-09-26.md`](TRIAL_RETEST_2026-09-26.md).

Follow [`examples/trial/README.md`](../examples/trial/README.md). Grade each
answer against its `expected` field before comparing with the table above. The
questions that tell the most:

- Q1, Q3, Q5, Q13, Q14, Q20: does the dense lane now carry natural-language questions that the lexical lane cannot?
- Q19: does a never-discussed topic still return `absent`?
- Q18: claim search is dense-only; is the migration-strategy claim first?
- Across all questions: do unrelated dense neighbours outrank correct lexical hits?

## Suggested next steps

1. Fix issue 1 before pointing the transcript connector at real sessions.
2. Normalize `_` in claim keys (issue 2).
3. Any-term lexical ranking (issue 3) and thread context (issue 4).
4. Collected content by default, a `source` filter on evidence, current-only evidence hits (issue 5).
5. Project captured items in the capture transaction or trigger a projection (issue 6).
6. Rerun this kit with the real model and decide the dense floor.
