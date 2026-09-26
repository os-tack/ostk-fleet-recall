# Retest with the real model, 2026-09-26

**Tested:** `main` at `be3b010`, on a macOS host with the real
`potion-retrieval-32M` bundle, by following the README's Local quickstart
steps 1 to 10 literally and then [`examples/trial/README.md`](../examples/trial/README.md).
This is the rerun that [`TRIAL_FINDINGS_2026-09-26.md`](TRIAL_FINDINGS_2026-09-26.md)
asked for. Nothing in the code was changed.

## Verdict

- **Every quickstart step ran as written**, with no substitutions this time:
  the pinned model downloaded and its bytes matched a bundle already on the
  host, the official CockroachDB image pulled, and port 26257 was free.
- **The dense lane carries natural-language questions.** Over the same 20
  questions the grades moved from 8 good, 9 partial, 3 poor to **15 good,
  2 partial, 2 poor, and 1 contract failure (Q19)**. The README's own demo
  query, which returned nothing before, now returns the conflict chunk first.
- **`absent` is unreliable with a real model.** A never-discussed topic in
  the project's own domain reads `present` because some document lands above
  the 0.18 cosine floor. Only topics far outside the domain still read
  `absent` (issue 8 below).
- **Lane fusion is lexical-first, not score-aware.** A lexical match with
  `ts_rank` 0.0 outranks a dense hit at 0.53. This, not the model, decides
  the two remaining partial grades (issue 7).
- **Issue 1 (provider tokens in transcripts) is confirmed live**, and the
  same holds for a token in a git commit message. Do not point the transcript
  or git connectors at real sessions or repositories yet.
- **Issue 2 (underscore in claim keys) reproduced live**: the trial's own
  scenario opens no conflict between `include-transcript default` and
  `include_transcript_default`.

## Environment

| Item | Used |
| --- | --- |
| Model | `potion-retrieval-32M` at `6fc8051f…`, bundle digest `2b0a5284…`; identical bytes to the host's August download |
| CockroachDB | `cockroachdb/cockroach:v26.2.3` from Docker Hub, port 26257 |
| Build | debug, default target directory |
| Sources | quickstart scratch repo; this repository's git history (501 commits, 502 facts); `docs/` as one documents root; `README.md` as a second root; the two fixture imports; the trial's Slack and Linear v1 imports; one transcript file (issue 1 probe) |
| Timing | first full tick with the repository's history and README: 71 s; a docs-only tick: 37 s |

One correction was needed before grading. `docs/` now contains the previous
findings doc, which quotes every trial question verbatim, so it ranked first
on Q1, Q3, Q4, Q8, Q10, Q13, Q14, Q16, Q17 and Q19. The docs collector was
re-pointed at a copy of `docs/` without that file (the collector keys items by
relative path, so the other 17 files kept their identity and the findings doc
was tombstoned), and every question was asked again. The grades below are
from the clean run; the contaminated run is kept in
`examples/trial/qa-run1-with-findings-doc/` for comparison. The trial kit
should exclude its own findings from the documents root.

## Recall quality

Same method as before: expected source written first, natural question then
keyword retry, best of the two graded. Dense scores are cosine similarity;
lexical scores are `ts_rank`. Correct hits scored between 0.45 and 0.78 on the
dense lane in this run.

| # | Question | Before | Now | What changed |
| --- | --- | --- | --- | --- |
| 1 | Where is the absence verdict specified? | partial | good | The natural question is lexically empty, and the dense lane alone returns FR-127, ADR 0006's consequences, and Priya's absent-versus-unknown explanation. |
| 2 | Decision on schema migrations | good | good | Marco's residual objection now surfaces on the retry (dense 0.37). |
| 3 | Decision on Granola transcripts | partial | partial | The right items (FR-131, June's question, Scott's decision) are ranks 3 to 5 on the natural question, behind two lexical hits scored 0.0 (issue 7). Priya's reply, which lacks the word Granola, never ranks. |
| 4 | Why was forget removed? | poor | good | June's question is first and Scott's reply, which shares no words with the question, is second at dense 0.54. Thread context is still missing, but dense recall found the reply anyway. |
| 5 | Which ticket tracks the absence bug? | partial | good | FR-127 first on the natural question, dense only. |
| 6 | Who said transcripts stay off? | partial | good | Scott, June and Priya in that order, dense only. Author ids only, as before. |
| 7 | Who proposed migrate on every replica? | good | good | Marco first, Priya's refusal second, the decision third. |
| 8 | Which commit added webhook ingress? | partial | partial | 997d242 is rank 4 on the natural question (dense 0.52) behind three lexical hits scored 0.10, 0.10 and 0.001 (issue 7). The fix commits are not in the top five. |
| 9 | Why was redaction::secrets renamed? | good | good | 93660f8 first. |
| 10 | Worker tick, 5 or 15 minutes? | partial | good | The natural question returns FR-150 and all three voices (Priya, Marco, June). |
| 11 | Open conflicts | good | good | Exact. |
| 12 | Open discrepancies | good | good | Exact. |
| 13 | May the public demo show asserted claims? | partial | good | FR-144, Scott's heads-up and ADR 0005 D8 on the natural question. The README section arrives on the retry. |
| 14 | Shorten stale_after to 6 hours? | partial | good | The proposals and Priya's refutation both appear on the natural question. |
| 15 | Same content key on every host? | good | good | README first, June's reminder fifth. |
| 16 | Why no Slack display names? | good | good | FR-155 and Marco's hot take. Priya's reply still does not rank on either query. |
| 17 | Which commits touched the Linear collector? | poor | poor | The natural question returns items about the Linear collector, no commits; the retry returns five docs sections. No source filter, and lexical-first fusion buries the commits. |
| 18 | Claim about the migration strategy | partial | good | Claim 1 first on both queries, ahead of the two disputed asserts and the retry-budget claim. `value` is still null in hits. |
| 19 | Kubernetes Helm charts (absence probe) | inconclusive | **fails** | `present` on items and evidence: Cloud onboarding at 0.257, the AWS primer at 0.256. See issue 8. |
| 20 | Absence verdict, kind omitted | poor | poor | Still an empty chunk answer with no hint. |

## Scenarios

All three kit scenarios behaved as documented, and the same eight scenario
rows as the first trial hold with the real model:

- **Conflict 1:** alpha and beta cite FR-131 and a captured Slack message;
  the private-channel and DM captures were withheld; the tick-interval
  conflict opened, and beta's supersede closed it and restored alpha's claim.
  The Granola claims did **not** conflict, because their keys differ only by
  `_` versus `-` (issue 2, reproduced).
- **Conflict 2:** beta re-keyed to match alpha, conflict 3 opened, gamma was
  refused `not_owner` on both retract and resolve, alpha acknowledged, beta
  resolved, claim 5 returned to `active`, and claim search reflected each
  state.
- **Delete:** after the v2 imports the tombstoned Slack root and FR-150 read
  `lifecycle: deleted` with no current text and one history entry; the two
  edits read `edited` with the old version kept; the note claim citing both
  doomed items now shows both supports `current: false`. June's plain message,
  merely missing from v2, stayed live, which is what the README promises ("a
  line missing from a later file deletes nothing").

## Issues found or confirmed in this run

### 7. Lane fusion is lexical-first, so a zero-score lexical hit outranks every dense hit (major for ranking)

`fuse` in `src/item_recall/cockroach.rs` emits every lexical row in lexical
order, then appends the dense rows the lexical lane did not find. No score
takes part. Observed: Q3's natural question puts two sections with `ts_rank`
0.0 above FR-131 at dense 0.53; Q8 puts three sections scored 0.10, 0.10 and
0.001 above the right commit at 0.52; Q17's retry returns five docs sections
over every commit. With the stand-in model this was invisible because the
dense lane was noise; with the real model it is the main remaining ranking
defect. **Fix:** fuse by score (reciprocal-rank or a normalized blend), and
drop lexical rows whose rank is 0.

### 8. The 0.18 dense floor makes `absent` rare and wrong for in-domain topics (major for the absence contract)

Ten never-discussed probes, items and evidence, after every source was
projected:

| Probe | Verdict | Top dense |
| --- | --- | --- |
| Kubernetes Helm chart | present | 0.257 (Cloud onboarding) |
| Oracle RAC licensing renewal | present | 0.269 (project primer) |
| GDPR data subject access requests | present | 0.400 (architecture doc) |
| Rust async runtime, tokio vs async-std | present | 0.403 (project primer) |
| quarterly sales forecast for EMEA | absent | none |
| chocolate birthday cake recipe | absent | none |
| flux capacitor | absent | none |
| office parking permit | absent | none |
| xqzv plorth (nonsense) | items absent, evidence present | 0.291 (a raw git fact) |

Correct answers in the question set scored 0.45 to 0.78, weak neighbours 0.22
to 0.40, so no single floor separates them: 0.30 would fix Helm and Oracle
and still call GDPR and tokio `present`. Raw git facts also attract nonsense
queries. **Options:** anchor the verdict on the lexical lane and report the
best dense similarity so an agent can judge; or raise the floor and rank the
`present` reasons by lane; or exclude `application.ostk-git-fact-v1` bodies
from the dense neighbourhood that decides the verdict.

### 9. One un-projected capture turns every absence verdict `unknown` (widens issue 6)

Between scenario 1's `remember(capture)` and the next `project` tick, every
item and evidence search in the scope, on any topic, answered `unknown` with
`body_projection_lag`, and the warning named one waiting event. Issue 6 said
the capturing agent cannot find its own item; the blast radius is the whole
scope's absence verdict until a worker runs.

### 1 (confirmed). Transcript and git ingress keep provider tokens in plaintext

A three-turn session file with fake tokens was ingested through the
`transcripts` source. The turn holding an AWS access key id and a Bearer
header was redacted (`turns_redacted: 1`). The turns holding `xoxb-`,
`ghp_`, `lin_api_` and `sk_live_` shaped strings were stored and served
verbatim by `recall(kind=evidence)`, and a search for the literal token string
finds the turn. A `xoxb-` string in a git commit message on the scratch
repository was likewise served verbatim in its git fact. The collected-items
redactor did its job in the same run: Marco's "debug token" Slack message
reads `[REDACTED]` (Q16).

### Smaller observations

- README step 8 and step 10 both use "zeppelin" as the word that appears
  nowhere. Once `README.md` is collected as a documents root, that probe reads
  `present` on the README itself. Pick a word the README does not contain.
- Claim search hits still carry `value: null` (issue 7 of the first trial).
- Item hits for disputed claims' cited items still show no dispute marker;
  chunk search over claim text reports `conflict_coverage: partial`.
- Q16's natural question ranks Marco's redacted debug-token message fourth on
  the dense lane, above Priya's actual reason.

## Not exercised

Same list as the first trial minus the real model: real Slack, Linear and
Granola APIs; webhook ingress; the CI connector; `ostk-observer-run`;
multiple hosts; two projects in one database; scale beyond about 600 bodies;
an LLM choosing tools; erasure.

## Suggested order

1. Issue 1: give the transcript and git connectors the collected-items
   provider shapes.
2. Issue 7: score-aware fusion. This alone would move Q3 and Q8 to good.
3. Issue 8: decide what `absent` means with a real model, and whether git
   facts should vote.
4. Issue 2: treat `_` as whitespace in claim keys.
5. Issues 3 to 6 and 9 as listed in the first trial.

## Fix round, 2026-09-26

Merged on `main` after `be3b010`: `d7589c0`/`2907af9` (fusion), `333a6fe`
to `eb1a406` (claim keys), `ae5e2b6` to `f60f103` (redaction), `c8bd3d8`
to `d3834f5` (absence verdict and capture projection), and `68e1fbb` (dense
re-embed after the normalization bump). The trial was rerun on the merged
binary against the same stack; the earlier answers are kept in
`examples/trial/qa-run2-before-fixes/`.

| Issue | Change | Re-measured |
| --- | --- | --- |
| 1 | One crate-wide redactor (profile 3, Stripe added) runs at transcript and git ingress and on the recall plane; lexical normalization version 3 re-projects and re-embeds stored rows | A fresh transcript turn and commit with the placeholders were redacted at ingress; no lexical row holds a raw literal, 54 carry `[REDACTED]`; searches for each literal return no matching text. The earlier realistic-shaped probe tokens are gone from the served copy. Bodies stay raw at rest (documented) |
| 7 | Reciprocal-rank fusion (K=60), `ts_rank` cutoff 0.001, lanes five deep, fused `score` on every hit | Q3 natural: FR-131 first, then June and Scott, all dense. Q8 natural: 997d242 rank 3 behind a both-lane git fact and one lexical section (was rank 4 behind three near-zero rows); retry FR-140 then 997d242 |
| 2 | `_`, `-` and whitespace are one separator; supersede compares stored parts under the new rule; `recall(status)` reports `legacy_claim_keys` | `rollout_mode` and `rollout mode` from two agents share `merged-build::rollout-mode` and open a conflict |
| 8 | Verdict is lexical-anchored; a dense-only hit votes at cosine ≥ 0.45; git facts never vote dense-only; `present_by`, `strongest_dense_similarity`, `weak_neighbours` added | Q19 and the in-domain probes read `absent` with the neighbours listed; off-topic probes `absent` with no hits |
| 9 | `remember(capture)` in `enabled` mode projects its own events in the call | An item search in the same session finds the capture with zero pending events |

**Trade-off to watch.** Q5 and Q10 on their natural wording now read
`absent` while the right answer is still the first hit (dense 0.34 and
0.41, under the 0.45 bound); their keyword retry reads `present`. An agent
must read the hits, not only the verdict. Lowering the bound to 0.42 would
not rescue them and would flip the GDPR and tokio probes to `present`.

**Found while verifying.** The first tick after the version bump failed
the dense step: the embedding identity carries the preprocessing version,
so every stored row was refused as a collision, and the re-embed was tied
to the same tick's lexical pass, so it was never retried. Fixed in
`68e1fbb`: the upsert moves vector, identity and version together when
only the preprocessing version advanced, and the dense step keeps its own
stale count. 859 rows re-embedded on the stack.

**Still open from this list:** issues 3 (any-term lexical ranking), 4
(thread context), 5 (evidence `source` filter, default kind hint: Q17 and
Q20 unchanged), 6 for worker-ingested lag, and the smaller observations.
