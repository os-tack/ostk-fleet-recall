# Reproducible terminal video

The submission video can use a real four-pane tmux sequence instead of edited
terminal screenshots. Agent A writes durable memory, Agent B retrieves that
memory and takes a cited action, Agent C creates an incompatible decision, and
the original B lineage resumes to pause and escalate. A narrow fifth pane keeps
CockroachDB, retrieval, provenance, and scenario state visible throughout.

## Rehearsal recording (safe and deterministic)

The default tape reads the checked-in sanitized
`docs/evidence/local-fleet-scenario.json`. It does not start OSTK agents, call a
model, access cloud resources, read `.env`, or print credentials. The recording
labels itself **REHEARSAL** on screen; it must not be described as a live agent
run.

```bash
./demo/video/tests/run.sh
./demo/video/render.sh --rehearsal
open demo/video/generated/rehearsal.mp4
```

The generated directory is intentionally ignored. The 1600×900 MP4 is a
16:9 source suitable for narration, a Devpost video edit, or direct upload. The
terminal sequence is about 44 seconds, leaving ample room within the
three-minute submission limit for a title, architecture explanation, and live
HTTP/Cockroach Cloud proof.

For a quick interactive preview without recording:

```bash
./demo/video/run.sh --rehearsal
```

The runner detaches automatically after the final evidence card. Use tmux's
normal `Ctrl-b d` binding to leave earlier.

## Live evidence recording (explicit and fail-closed)

The live tape does not launch a model or paid service. It only renders a
previously completed, verified opt-in OSTK run from:

```text
target/ostk-demo/<run-id>/final.json
```

After following `docs/OSTK_DEMO.md` and verifying the run, render it with:

```bash
./demo/video/render.sh --live '<run-id>'
open demo/video/generated/live.mp4
```

Live mode rejects missing evidence, unsafe run IDs, the wrong OSTK version,
unverified summaries, missing retrieval lanes, broken claim/conflict citations,
and non-LocalStack action receipts. Its on-screen provenance changes to
**LIVE EVIDENCE** and names the verified run. Because the current OSTK
`final.json` proves the initial commit but does not contain the deterministic
retry receipt, the live Agent A pane says that replay is not asserted; it does
not borrow that claim from the rehearsal fixture. The same rule applies to the
cross-project injection check: the live pane labels it as a separate
deterministic gate because the current OSTK summary does not attest it.

## Suggested narration

1. “This rehearsal is rendered from checked-in, sanitized evidence; the same
   layout can render a verified OSTK run without rerunning paid agents.”
2. “Agent A commits a migration decision. An identical retry resolves to the
   same claim, so fleet retries do not duplicate memory.”
3. “Agent B asks with different wording. CockroachDB combines its lexical and
   C-SPANN vector lanes with reciprocal-rank fusion, then B persists an action
   citing the retrieved claim.”
4. “Agent C writes an incompatible value under the same typed key. Fleet Recall
   preserves both claims and opens a conflict instead of silently overwriting
   one agent's memory.”
5. “The original B lineage resumes, recalls the disputed claims, and pauses the
   rollout for operator review with a conflict citation.”

The footer deliberately calls stateless application replacement a **separate
smoke gate**. This scenario evidence proves the memory/action/conflict chain;
`deploy/localstack/smoke.sh` is the distinct contract that checks S3 model
delivery, Secrets Manager, and recall after replacement.

## Recording gates

- `vhs validate 'demo/video/*.tape'` parses both tapes without launching them.
- `demo/video/tests/run.sh` validates shell syntax, exercises the real tmux
  layout at accelerated speed, checks the required story beats, and proves that
  live mode fails closed when evidence is absent.
- Inspect the MP4 at full resolution before using it: all four panes, the
  rehearsal/live provenance label, retrieval lanes, citations, and final
  verification banner should remain readable.
- Use `ffprobe` to confirm 1600×900 dimensions and a duration below three
  minutes before publication.

VHS 0.11+, tmux 3.4+, `jq`, Bash, an H.264-capable FFmpeg installation, and
the Menlo font selected by the tapes are the recording prerequisites. Change
the two `FontFamily` settings together if Menlo is unavailable on the
recording host; every checked-in orchestration helper remains POSIX shell.
