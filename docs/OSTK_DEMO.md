# Opt-in OSTK fleet demo

OSTK is **not** required to build, run, deploy, or use Fleet Recall. It is not
required for the deterministic three-identity MCP scenario or the default
tmux/VHS rehearsal. This directory is an optional integration experiment for
people who already use OSTK and explicitly choose to launch bounded model
sessions.

This demo connects real OSTK agent sessions to Fleet Recall's stdio MCP server,
then proves that recalled memory changes an external action. It runs entirely
against the repository's CockroachDB + LocalStack environment; it does not need
an AWS account.

The integration is intentionally a **non-native bridge**. OSTK 7.7.7 does not
expose an MCP-server registration flag on `ostk agent`, so an agent uses its
Bash tool to invoke the checked-in [`mcp-client.sh`](../demo/ostk/mcp-client.sh).
That helper maps the OSTK-kernel-stamped `OSTK_AGENT` process identity to the
deployment-bound `FLEET_RECALL_AGENT` value on a fresh stdio MCP process. Agent
identity is never accepted as a helper argument.

## OSTK 7.7.7 feasibility audit

The demo targets the exact 7.7.7 CLI contract. A local development build suffix
such as `ostk 7.7.7+1251cf9f4-dirty` is accepted; another semantic version is
rejected.

| Checked surface | 7.7.7 result | Demo use |
|---|---|---|
| `ostk agent <NAME> --prompt-file --model --budget --lifetime job` | Available | Starts A, B, and C with an explicit model and finite USD cap |
| `ostk agent await <NAME> --timeout` | Available | Makes every dependency and evidence check deterministic |
| `ostk agent resume <NAME> -p --budget` | Available | Resumes B's lineage after C creates a conflict |
| `ostk fleet` | Manifest signing and profile verification only | Not represented as a runnable fleet scheduler |
| Native MCP registration on `ostk agent` | No exposed 7.7.7 flag | Bash-to-stdio helper, clearly labeled non-native |

Run the no-agent plan to verify the installed CLI and see the exact four
bounded invocations:

```bash
export OSTK_DEMO_MODEL='your-configured/model'
export OSTK_DEMO_BUDGET_USD='0.10'
./demo/ostk/run.sh --plan
```

`--plan` calls only `ostk --version`; it never invokes `ostk agent`.

## Scenario

The runner coordinates this dependency chain:

1. Agent A records the decision that one dedicated migrator must finish before
   workers serve traffic.
2. Agent B searches with different wording. The bridge requires a
   lexical+dense RRF hit on A's claim, then writes a tangible LocalStack S3
   receipt that holds workers and cites the recalled claim ID.
3. Agent C records the incompatible decision that every worker migrates on
   startup. CockroachDB marks both claims disputed and exposes an open conflict.
4. The runner resumes the original B lineage. B recalls the open conflict, then
   writes a second S3 receipt that pauses rollout, cites the conflict ID, and
   escalates to an operator.
5. [`verify.sh`](../demo/ostk/verify.sh) downloads both S3 objects and checks the
   complete claim, conflict, OSTK identity, retrieval, and action-receipt chain.

The LLM is asked only to execute one fixed Bash helper per turn. Correctness
does not depend on prose in the model response: every step must produce bounded
JSON evidence, and the runner fails closed when evidence is absent or
inconsistent. The runner writes a prompt for each run containing an explicit,
validated `--run-id`; this non-secret argv value survives OSTK's daemon process
boundary without relying on launcher environment inheritance. The helper still
derives agent identity exclusively from kernel-stamped `OSTK_AGENT`.

## Run locally

Prerequisites are Docker, AWS CLI, `jq`, OSTK 7.7.7, a model configured for
OSTK, and the model bundle required by the LocalStack smoke environment.

First keep the already-tested local stack running. The smoke script reads a
LocalStack token from its documented environment or exact root `.env`
assignment without sourcing that file.

```bash
export FLEET_RECALL_MODEL_BUNDLE="$PWD/.models/potion-retrieval-32M/hf-6fc8051fab2a1e0ee76689cf08c853792ac285e7"
KEEP_LOCALSTACK=1 ./deploy/localstack/smoke.sh
```

Only if you choose to run this optional adapter, initialize an OSTK project at
this exact repository root and validate its boot state:

```bash
ostk init
ostk boot --bail
```

The generated `.ostk/` directory is local, ignored, and must never be
committed. The runner requires this exact directory and refuses to inherit an
OSTK project from a parent directory. It does not auto-initialize or repair
OSTK state.

Next inspect the plan, then explicitly authorize the model calls:

```bash
export OSTK_DEMO_MODEL='your-configured/model'
export OSTK_DEMO_BUDGET_USD='0.10'
./demo/ostk/run.sh --plan

export OSTK_DEMO_ALLOW_BILLING=I_UNDERSTAND_FOUR_AGENT_RUNS_MAY_BILL
./demo/ostk/run.sh
```

There is no default model, default budget, or unlimited-budget mode. The USD
cap is passed to each of three initial agent invocations and the B resume. A
conservative authorization ceiling is therefore four times
`OSTK_DEMO_BUDGET_USD`; a cap is not a promise that the full amount will be
spent.

Progress and agent output go to ignored local state instead of contaminating
the machine-readable stdout. A successful run prints one final JSON document
and saves it at:

```text
target/ostk-demo/<run-id>/final.json
```

The two action receipts remain queryable in LocalStack:

```text
s3://fleet-recall-local-actions/ostk-demo/<run-id>/agent-b/hold-workers.json
s3://fleet-recall-local-actions/ostk-demo/<run-id>/agent-b/pause-rollout.json
```

Re-run the deterministic evidence gate for a known run:

```bash
./demo/ostk/verify.sh --run-id '<run-id>' | jq .
```

## Trust and scope limits

- The bridge accepts AWS endpoints only on loopback and always supplies
  LocalStack's dummy credentials. It cannot accidentally target an AWS account.
- Neither the runner nor the helpers source or evaluate `.env`, print
  credentials, or expose the CockroachDB connection secret.
- Run IDs accept only 1–48 ASCII letters, digits, hyphens, and underscores.
  Helpers derive state under the repository's ignored
  `target/ostk-demo/<run-id>` directory, which OSTK's project sandbox permits
  agents to write; environment variables cannot redirect that path.
- `OSTK_AGENT` is trusted here because OSTK stamps it on the managed agent
  process and its Bash children. The bridge checks the exact expected A/B/C
  lineage name before every semantic or action step.
- This mapping is not workload identity or cryptographic attestation. A process
  already able to mutate its own environment can impersonate a demo role. A
  production integration should use native OSTK-to-MCP identity propagation or
  signed workload identity when that surface exists.
- LocalStack and a single-node CockroachDB container validate contracts and
  data flow, not AWS availability or CockroachDB distributed fault tolerance.
- The non-billable gates validate CLI shape and the bridge contract. Actual
  OSTK sandbox execution remains unclaimed until an explicitly authorized live
  run produces `target/ostk-demo/<run-id>/final.json`.

## Non-billable tests

The test suite uses fake OSTK, MCP, Docker, and AWS executables. It never runs
`ostk agent` or contacts a model provider:

```bash
./demo/ostk/tests/run.sh
```

It checks POSIX shell syntax, forbids `eval`, exercises stdio identity mapping,
proves the four-step claim/action/conflict/pause chain, validates S3 evidence,
and tests the OSTK 7.7.7 plan plus billing-consent gate. When `shellcheck` is
installed, the same command treats its findings as failures.
