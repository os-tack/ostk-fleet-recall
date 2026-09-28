# Fleet Recall

Shared, persistent memory for agent fleets, backed by CockroachDB.

Fleet Recall gives agents two MCP tools: **`recall`** retrieves memory with
provenance and conflict information; **`remember`** records claims and their
lifecycle. Agents can be replaced or run on different hosts while their shared
memory remains available. Codex and Claude Code are supported; OSTK is optional.

## Start here

| I want to… | Start with |
| --- | --- |
| Try Fleet Recall on a disposable local database | [Local development tutorial](docs/tutorials/LOCAL_DEVELOPMENT.md) |
| Learn the tools and record a disagreement | [Using Recall tutorial](docs/tutorials/USING_RECALL.md) |
| Operate the existing local HTTPS installation | [Operator guide](docs/guides/OPERATING.md) |
| Connect a client, enroll a user, or launch a sandbox | [Operator tasks](docs/guides/OPERATING.md) and [remote protocol guide](docs/REMOTE_PLANE.md) |
| Diagnose a failed login, missing evidence, or unhealthy service | [Troubleshooting](docs/guides/TROUBLESHOOTING.md) |
| Choose a deployment or understand what is actually supported | [Deployment profiles](docs/reference/DEPLOYMENT_PROFILES.md) |

The **[documentation index](docs/README.md)** organizes tutorials, operator
procedures, configuration/API references, architecture, and qualification records.
Use the [glossary](docs/reference/GLOSSARY.md) for terms such as writer authority,
principal, grant, projection, and registry generation.

## What it does

- Searches a shared corpus with lexical and vector retrieval, using a pinned
  local model or a private embedding service.
- Records attributed claims and detects incompatible typed values on the same
  functional key. Agents can retract or supersede their own claims; conflicts
  remain visible until the lifecycle rules resolve them.
- Collects git history, supported agent transcripts, CI runs and provider items
  through a worker, preserving provenance and reporting search freshness.
- Serves stdio MCP or authenticated HTTP MCP. Remote identities are explicitly
  enrolled; sandboxes receive separate revocable agent and shipper grants.
- Runs Codex, Claude or synthetic harnesses in Docker/Kubernetes sandboxes and
  ships transcripts for later recall.

Conflict detection compares typed propositions; it does not infer arbitrary
natural-language contradictions. An empty search is not proof of absence.
Recalled text is evidence, never instructions or authorization. See the
[MCP reference](docs/reference/MCP.md) and [security model](docs/SECURITY.md).

## Deployment status

The single-Mac Lima/k0s HTTPS deployment is locally qualified through M4.3:
client access, restart/outage handling, certificate renewal, isolated restore,
transcript replay and monitoring have been exercised. It uses one receiver and
accepts maintenance interruptions; Mac sleep stops availability. LocalStack is
optional and disabled in that reference installation.

The disposable developer tutorial is a separate environment. Older local HTTP
bootstrap commands are retained for their original profiles and must not be
used to reconcile the upgraded HTTPS installation. The existing AWS Terraform
is for the read-only publication demo. **The AWS remote stack (M4.4) is on hold**;
second-machine access and the release soak remain unqualified. See
[deployment status and limits](docs/reference/STATUS.md).

## Operator essentials

An installation needs more than a running process. The guides explain how to:

- Select the original state directory and matching kubeconfig, including from
  another worktree, in the [operator guide](docs/guides/OPERATING.md).
- Assign credentials to the correct process and preserve model/authority pins
  using the [configuration reference](docs/reference/CONFIGURATION.md).
- Enroll identities, retain launch state, and stop sandboxes with grant
  revocation using the [remote guide](docs/REMOTE_PLANE.md).
- Verify readiness, worker progress and alerts using
  [telemetry operations](docs/TELEMETRY.md).
- Retain recovery inputs, rehearse restore and distinguish image rollback from
  database recovery using the [recovery runbook](deploy/local/https/RECOVERY.md).

## Develop

Rust 1.94 or newer is required. From the repository root:

```sh
cargo build --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

Building does not provision a database, download a model, or enable the live
SQL tests. Follow the [developer workflow](docs/DEVELOPMENT.md) for the complete
checks and disposable test-database requirements, or the
[local tutorial](docs/tutorials/LOCAL_DEVELOPMENT.md) for an end-to-end setup.

For design details, read the [project primer](docs/PROJECT_PRIMER.md),
[architecture](docs/ARCHITECTURE.md), and
[decision records](docs/README.md#architecture-and-decisions).
[`ostk-recall`](https://github.com/os-tack/ostk-recall) is the separate local-first
sibling; Fleet Recall does not require its agent tooling.

## License

Apache-2.0 or MIT. The pinned MinishLab embedding model is separately licensed
under MIT; see the model attribution in the
[local tutorial](docs/tutorials/LOCAL_DEVELOPMENT.md#1-acquire-and-pin-the-local-embedding-model).
