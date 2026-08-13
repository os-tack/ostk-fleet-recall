# Reproducible terminal video

The submission video can use a real four-pane tmux sequence instead of edited
terminal screenshots. Agent A writes durable memory, Agent B retrieves it and
takes a cited action, Agent C creates an incompatible decision, and the same B
identity resumes to pause and escalate. A narrow fifth pane keeps CockroachDB,
retrieval, provenance, and scenario state visible throughout.

Fleet Recall has two first-class recording modes that require no OSTK, agent
orchestrator, LLM, model API, or cloud account. A third, explicitly optional
mode can render an already verified OSTK adapter run.

## Submission eligibility boundary

Neither the sanitized rehearsal nor a standalone-only local capture is the
final hackathon video. The [official rules](https://cockroachdb-ai.devpost.com/rules)
require footage of the project functioning as deployed on AWS and footage of
the CockroachDB memory layer at work. Use the terminal sequence as one proof
segment in the final cut, then add fresh cloud footage showing the public demo,
the verified reference-agent receipt, CockroachDB-backed recall before and
after ECS task replacement, and the representative query plans. Keep the
local/cloud provenance labels visible so one segment cannot be mistaken for
the other.

## Fresh standalone Fleet Recall recording

This is the primary live evidence path. Start the local smoke environment and
leave it running:

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
conflict, and B's persisted escalation citing that conflict. Live evidence is
labeled **LOCAL LIVE MCP EVIDENCE · NO AWS/CLOUD · no OSTK/LLM** on screen.

For an interactive preview instead of an MP4:

```bash
./demo/video/run.sh --fleet-live devpost-live
```

## Rehearsal recording

The default tape reads checked-in, sanitized evidence from
`docs/evidence/local-fleet-scenario.json`. It does not start services, launch
OSTK agents, call a model, access cloud resources, read `.env`, or print
credentials. The recording labels itself **REHEARSAL** and must not be
described as a fresh run.

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
non-LocalStack action receipts. The on-screen provenance says **OPTIONAL OSTK
EVIDENCE**. The ambiguous old `--live` spelling is intentionally unsupported,
so an OSTK artifact cannot accidentally become the default live path.

The optional OSTK summary proves the initial commit but does not include the
deterministic retry receipt. Its Agent A pane therefore says replay is not
asserted. It likewise labels scope injection as a separate deterministic gate
instead of borrowing either claim from the standalone evidence.

## Suggested narration

1. “This is a fresh standalone Fleet Recall run—three independently bound MCP
   identities, CockroachDB underneath, and no OSTK or LLM required.”
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
