# Final video plan and reproducible terminal footage

> **Agents are replaceable. Their memory shouldn't be—and when two disagree,
> memory should say so.**

Build the final cut around three verbs: **ASK**, **DISAGREE**, and **SURVIVE**.
ASK shows the current conflict-first public interface. DISAGREE proves the
typed A → B → C → B decision, action, conflict, and cited-escalation chain.
SURVIVE proves that the cited memory remained recallable after the complete
Fargate serving-task set changed. End with a short local-first-to-fleet coda;
OSTK is an optional adapter, not an install or runtime requirement.

## Submission eligibility boundary

Neither the sanitized rehearsal nor a standalone-only local capture is the
final hackathon video. The [official rules](https://cockroachdb-ai.devpost.com/rules)
require an AWS-deployed project; the video must show it functioning and the
CockroachDB memory layer at work. Film the current public demo, then show
reviewed excerpts of the verified reference-agent and replacement receipts and
the representative query plans. Keep every local/cloud provenance label
visible so one segment cannot be mistaken for another.

The public conflict-first UI is the current revision 4 deployment. The
correlated four-task agent and fully disjoint replacement receipts are verified
**pre-polish revision 3** evidence from run
`devpost-final-20260814T021819Z`; they were not rerun on revision 4. Do not cut
the two sources together in a way that implies one revision or one continuous
live take.

## Final cut: ASK → DISAGREE → SURVIVE

Target **2:40**, leaving a 20-second safety margin under the practical three-minute
limit for transitions or platform encoding. Record at 1600×900 or better, keep
the browser at a readable zoom, and hold every receipt view long enough to read
the relevant `verified`, run, task-definition revision, citation, and
persistence fields.

Use these exact two-line provenance cards. Do not abbreviate away the revision
or source boundary:

```text
LIVE PUBLIC DEMO · AWS + COCKROACHDB CLOUD · CURRENT REVISION 4 UI
PUBLIC READ-ONLY ENDPOINT

VERIFIED CLOUD AGENT RECEIPT · AWS FARGATE + COCKROACHDB CLOUD
PRE-POLISH REVISION 3 · RUN devpost-final-20260814T021819Z

VERIFIED CLOUD REPLACEMENT RECEIPT · AWS FARGATE + COCKROACHDB CLOUD
PRE-POLISH REVISION 3 · RUN devpost-final-20260814T021819Z

PUBLICATION-SAFE COCKROACHDB CLOUD EXPLAIN · DISPOSABLE FIXTURE
PRODUCTION DATABASE UNTOUCHED

DESIGN CODA · LOCAL-FIRST RECALL → COCKROACHDB FLEET RECALL
ANY MCP CLIENT · OSTK OPTIONAL, NOT REQUIRED
```

### 0:00–0:10 — thesis

Show the product name over the public URL, then say the thesis verbatim:
“Agents are replaceable. Their memory shouldn't be—and when two disagree,
memory should say so.” Cut directly to the live browser; do not spend the
opening on architecture.

### 0:10–0:52 — ASK

Show <https://d13zrqfh66r7ub.cloudfront.net> with the live-public-demo label.
Keep the `/api/status` chip in frame, submit the default conflict question, and
pause on the rendered answer: the open-conflict callout first, then two or
three readable memory cards with their claim or source coordinates. Follow a
linked repository path only if that row is present in the deployed corpus; do
not describe a plain claim ID as a file citation. Point out “fused in …ms” as
server recall time and “round trip …ms” as browser-to-cloud time. These
are different measurements. Do not call RRF rank artifacts confidence scores.

Narrate: “This is the current read-only AWS deployment, backed by CockroachDB
Cloud. I can ask in normal language and get readable, cited memories—not a wall
of JSON. The memory also surfaces the open disagreement and its matching
operator escalation instead of silently choosing a winner.” Leave “View raw
evidence envelope” collapsed until the cards are understood; a brief expansion
can establish the bounded raw evidence, but it must not become the interface.

End the act with a short, legible cutaway to
[`evidence/cockroach-cloud-explain.txt`](evidence/cockroach-cloud-explain.txt)
under the publication-safe EXPLAIN label. Say only that the separately captured
fixture plans selected the scoped vector and lexical indexes; index-ready
status and RRF diagnostics alone do not prove physical plan selection.

### 0:52–1:40 — DISAGREE

Show the reviewed reference-agent receipt projection below with the verified
cloud-agent label. Hold the `agents`, step sequence, `memory`, and `actions`
fields in view. The exact chain is:

1. Agent A records migration decision claim 5: “single dedicated migrator.”
2. Agent B recalls it through lexical+dense RRF and records action claim 6,
   citing claim 5.
3. Agent C records “every worker migrates independently” as incompatible claim
   7 under the same typed migration-strategy key, opening conflict 2.
4. The same bound B identity records escalation claim 8, “pause rollout for
   operator review,” citing conflict 2.

Narrate: “These were four separately bound Fargate tasks over one CockroachDB
memory plane. A and C made incompatible current claims under the same typed
key. Fleet Recall preserved both, opened conflict 2, and B persisted an
operator handoff that cites that conflict.” This is precise typed, same-key,
current-interval conflict detection—not a claim of corpus-wide natural-language
contradiction detection or LLM reasoning.

### 1:40–2:12 — SURVIVE

Switch to the reviewed replacement receipt projection under the verified cloud
replacement label. Keep `task_definition`, `before`, `after`, and `persistence`
visible. Narrate: “This pre-polish revision 3 proof forced a new ECS deployment.
The before and after task sets were fully disjoint, while desired capacity
stayed one. Exact action and escalation claims 6 and 8 were recalled both before
and after through lexical+dense RRF. The workers were replaceable; CockroachDB
remained the memory source of truth.” Explicitly say this receipt is revision 3
evidence, separate from the current revision 4 UI.

### 2:12–2:30 — local-first → fleet coda

Show the storage boundary in [`ARCHITECTURE.md`](ARCHITECTURE.md) or the public
repository landing page under the design-coda label. Narrate: “Recall stays
local-first for one agent. When agents need to share memory across processes
and hosts, the same small MCP contract can use CockroachDB as a durable fleet
plane. It works with any MCP client; OSTK is optional, not required.” Do not
show or imply an OSTK run unless separately authorized and labeled as described
below.

### 2:30–2:40 — close

Return to the public endpoint and repository URL. Close with: “Local Recall for
one agent; CockroachDB Fleet Recall when the whole fleet has to remember—and
disagree—together.”

## Publication-safe receipt views

Validate the correlated operator-held receipts off camera before recording.
The verifier's output is validation-only and is not a substitute for the two
live-cloud receipts:

```bash
REFERENCE_RECEIPT=target/aws-evidence/reference-agent-devpost-final-20260814T021819Z.json
REPLACEMENT_RECEIPT=target/aws-evidence/replacement-devpost-final-20260814T021819Z.json

./deploy/aws/verify-publication-receipts.sh \
  "$REFERENCE_RECEIPT" "$REPLACEMENT_RECEIPT" >/dev/null
```

For DISAGREE, project only the correlation fields. This deliberately omits
task IDs and log-stream coordinates:

```bash
jq '{
  schema, verified, deployment, run_id, agents,
  task_definition: .aws.task_definition,
  steps: [.aws.tasks[] | {step, agent}],
  memory, actions,
  public_verification: {
    health: .public_demo.health,
    exact_claim_ids_observed: .public_demo.exact_claim_ids_observed,
    retrieval_lanes: .public_demo.retrieval_lanes,
    fusion: .public_demo.fusion
  }
}' "$REFERENCE_RECEIPT"
```

For SURVIVE, show the bounded replacement and persistence fields without the
before/after task identifiers:

```bash
jq '{
  schema, verified, deployment, run_id,
  task_definition: .aws.task_definition,
  replacement_strategy: .aws.replacement_strategy,
  desired_count_before: .aws.desired_count_before,
  desired_count_after: .aws.desired_count_after,
  before: .public_demo.before,
  after: .public_demo.after,
  persistence
}' "$REPLACEMENT_RECEIPT"
```

Review even these projections frame by frame before publication. The chosen run
ID, project/service names, public URL, and any visible terminal or browser chrome
still require human approval.

## Reproducible terminal source footage

The final cut can use a real four-pane tmux sequence instead of edited terminal
screenshots. Agent A writes durable memory, Agent B retrieves it and takes a
cited action, Agent C creates an incompatible decision, and the same B identity
resumes to pause and escalate. A narrow fifth pane keeps CockroachDB, retrieval,
provenance, and scenario state visible throughout.

Fleet Recall has two first-class recording modes that require no OSTK, agent
orchestrator, LLM, model API, or cloud account. A third, explicitly optional
mode can render an already verified OSTK adapter run. Local or rehearsal clips
are supporting footage for DISAGREE; they never replace the live-cloud proof.

## Fresh standalone Fleet Recall recording

This is the primary live **local** source-footage path. It is not AWS evidence.
Start the local smoke environment and leave it running:

```bash
KEEP_LOCALSTACK=1 ./deploy/localstack/smoke.sh
```

Then run a new three-identity scenario, atomically capture its verified JSON,
and render it:

```bash
./demo/video/capture-fleet.sh devpost-live
./demo/video/render.sh --fleet-live devpost-live
open demo/video/generated/fleet-live.mp4
```

`capture-fleet.sh` talks directly to three separately deployment-bound Fleet
Recall MCP processes. It makes no OSTK or LLM call. Its evidence is written to
`target/fleet-demo/<run-id>/final.json` only after the scenario and the video
contract both pass. It atomically claims a new run directory and refuses unsafe
run IDs, symlinked paths, and any existing run destination; concurrent,
successful, or interrupted captures therefore cannot overwrite evidence.

The contract proves the complete displayed story: Agent A's commit and exact
idempotent replay, B's lexical+dense RRF hit and cross-project rejection, B's
persisted action citing A, C's incompatible claim, the exact open two-member
conflict, and B's persisted escalation citing that conflict. The generated
footer reads **LOCAL LIVE MCP EVIDENCE · local CockroachDB run `<run-id>` · NO
AWS/CLOUD · no OSTK/LLM**. Do not crop it.

For an interactive preview instead of an MP4:

```bash
./demo/video/run.sh --fleet-live devpost-live
```

## Rehearsal recording

The default tape reads checked-in, sanitized evidence from
`docs/evidence/local-fleet-scenario.json`. It does not start services, launch
OSTK agents, call a model, access cloud resources, read `.env`, or print
credentials. The generated footer reads **REHEARSAL · sanitized evidence · no
cloud/LLM calls** and must remain visible. Never describe it as a fresh run.

```bash
./demo/video/tests/run.sh
./demo/video/render.sh --rehearsal
open demo/video/generated/rehearsal.mp4
```

The generated directory is intentionally ignored. The 1600×900 MP4 is a 16:9
source suitable for narration, a Devpost edit, or direct upload. The terminal
sequence is about 46 seconds, leaving ample room within the three-minute limit
for a title, architecture explanation, and deployment proof.

For a quick interactive preview:

```bash
./demo/video/run.sh --rehearsal
```

The runner detaches automatically after the final evidence card. Use tmux's
normal `Ctrl-b d` binding to leave earlier.

## Optional OSTK adapter recording

OSTK is not part of either mode above. If an explicitly authorized, potentially
billable adapter run has already been completed and verified according to
`docs/OSTK_DEMO.md`, its evidence can be rendered from:

```text
target/ostk-demo/<run-id>/final.json
```

Use the deliberately explicit flag:

```bash
./demo/video/render.sh --ostk-live '<run-id>'
open demo/video/generated/ostk-live.mp4
```

`--ostk-live` only renders existing JSON; it does not launch OSTK or make a
model call. It rejects missing evidence, unsafe run IDs, the wrong OSTK
version, unverified summaries, missing retrieval lanes, broken citations, and
non-LocalStack action receipts. The generated footer reads **OPTIONAL OSTK
EVIDENCE · verified 7.7.7 run `<run-id>`**. The ambiguous old `--live` spelling
is intentionally unsupported, so an OSTK artifact cannot accidentally become
the default live path.

The optional OSTK summary proves the initial commit but does not include the
deterministic retry receipt. Its Agent A pane therefore says replay is not
asserted. It likewise labels scope injection as a separate deterministic gate
instead of borrowing either claim from the standalone evidence.

## Standalone source-footage narration

If the final DISAGREE act includes local terminal footage, keep its local or
rehearsal provenance footer continuously visible and use this bounded
narration. Do not imply that the clip came from AWS:

1. “This is a fresh standalone Fleet Recall run—three independently bound MCP
   identities, local CockroachDB underneath, and no AWS, OSTK, or LLM required.”
2. “Agent A commits a migration decision. An identical retry resolves to the
   same claim, so fleet retries do not duplicate memory.”
3. “Agent B asks with different wording. CockroachDB combines lexical and
   C-SPANN vector lanes with reciprocal-rank fusion, then B persists an action
   citing the retrieved claim.”
4. “Agent C writes an incompatible value under the same typed key. Fleet Recall
   preserves both claims and opens a conflict instead of silently overwriting
   one agent's memory.”
5. “The same B identity resumes, recalls the disputed claims, and pauses the
   rollout for operator review with a conflict citation.”

The footer calls stateless application replacement a **separate smoke gate**.
Scenario evidence proves the memory/action/conflict chain;
`deploy/localstack/smoke.sh` separately checks S3 model delivery, Secrets
Manager, and recall after replacing the application container.

## Recording gates

- `vhs validate 'demo/video/*.tape'` parses all three tapes without launching
  them.
- `demo/video/tests/run.sh` validates shell syntax and both evidence schemas,
  exercises all three modes through the real tmux layout at accelerated speed,
  and adversarially checks run identity, provenance, claim/action/conflict
  correlations, exact conflict membership, timestamps, and symlink rejection.
- `demo/video/verify.sh` is shared by capture, preview, test, and render paths,
  so no mode can reach the final verification footer with weaker evidence.
- `demo/video/render.sh` runs an accelerated, headless version of the exact
  requested choreography before opening VHS, so invalid live evidence fails
  before recording begins.
- Inspect the MP4 at full resolution before using it. All four agent panes, the
  provenance label, retrieval lanes, citations, and final banner should remain
  readable.
- Use `ffprobe` to confirm 1600×900 dimensions and a duration below three
  minutes before publication.

For the final narrated export, run the stricter machine-readable gate:

```bash
./docs/assets/verify-media.sh --final-video path/to/final.mp4
```

It requires a 16:9 H.264/yuv420p video at 720p or better, a non-empty audio
stream, and a duration strictly below 180 seconds. Then complete the checks a
local file cannot prove:

- Watch the entire upload from a logged-out browser at 720p and confirm all
  terminal text, citations, cloud provenance, and the final URL are legible.
- Confirm the YouTube or Vimeo page is public, embedding/playback is enabled,
  captions are accurate, and the Devpost preview plays without authentication.
- Show the application functioning on AWS and CockroachDB memory changing the
  agent's behavior; architecture slides and repository tests alone do not meet
  that footage requirement.
- Use original narration and no music. Do not add third-party logos, brand
  artwork, or copyrighted media unless permission has been confirmed; plain
  service names should appear only where needed to explain the integration.
- Rewatch once for account IDs, secret ARNs, credentials, tenant-sensitive
  logs, browser autofill, notifications, and shell history before publishing.

VHS 0.11+, tmux 3.4+, `jq`, Bash, an H.264-capable FFmpeg installation, and
the Menlo font selected by the tapes are recording prerequisites. The fresh
capture additionally requires the already-running local environment described
above. Change all three `FontFamily` settings together if Menlo is unavailable;
every checked-in orchestration helper remains POSIX shell.
