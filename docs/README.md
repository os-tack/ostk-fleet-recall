# Fleet Recall documentation

Start with a task. Tutorials build a disposable environment; operating guides
maintain an existing installation; references define commands and behavior.
Architecture and qualification records explain decisions and tested limits.

## First use

| Task | Guide | What you need first |
| --- | --- | --- |
| Understand the product | [Project primer](PROJECT_PRIMER.md) | No installation |
| Choose where to run it | [Deployment profiles](reference/DEPLOYMENT_PROFILES.md) | Decide between a disposable experiment and a retained service |
| Build and load a demo corpus | [Local development](tutorials/LOCAL_DEVELOPMENT.md) | Rust, Docker, model download tools; a disposable database |
| Call the tools and record conflicting claims | [Using Recall](tutorials/USING_RECALL.md) | The preceding tutorial's database and environment |
| Add a git source, spec check and collected items | [Memory pipelines](tutorials/MEMORY_PIPELINES.md) | The same tutorial environment; creates and retains a content key |
| Join an existing HTTPS installation | [Operator guide](guides/OPERATING.md) | Its canonical URL, public CA trust and an enrolled identity |

The three tutorials are sequential. Their shell commands run from the
repository root and use their own database/state. Do not substitute the live
Lima database into tutorial or test commands.

## Operate and maintain

| Task | Procedure |
| --- | --- |
| Prepare an operator session, restart after Mac boot, inspect health, connect clients | [Operating the local HTTPS service](guides/OPERATING.md) |
| Work through a symptom | [Troubleshooting](guides/TROUBLESHOOTING.md) |
| Enroll identities or understand OAuth/grants | [Remote HTTP MCP](REMOTE_PLANE.md) |
| Launch/stop Docker or Kubernetes sandboxes | [Sandbox guide](../deploy/local/sandbox/README.md), reached through the current-profile examples in the [operator guide](guides/OPERATING.md) |
| Provision the earlier local baseline | [Local bootstrap](../deploy/local/README.md) — historical HTTP profile, not HTTPS repair |
| Perform the local HTTPS cutover and configure native trust | [HTTPS deployment](../deploy/local/https/README.md) |
| Deploy an image, renew a leaf, rehearse outages or worker exclusion | [Lifecycle operations](../deploy/local/https/OPERATIONS.md) |
| Back up and test recovery | [Operator backup task](guides/OPERATING.md), then [isolated recovery](../deploy/local/https/RECOVERY.md) |
| Read dashboards, diagnose worker progress, inspect alerts | [Telemetry](TELEMETRY.md) and [monitoring installation](../deploy/observability/README.md) |
| Install authority, schedule content processing, run spec checks | [Event-first operations](guides/EVENT_FIRST_OPERATIONS.md) |
| Configure collectors/imports/capture/webhooks | [Collected-items runbook](COLLECTED_ITEMS_RUNBOOK.md) |
| Change schema or SQL role policies | [Migration operations](MIGRATIONS.md) and [private control bootstrap](CONTROL_BOOTSTRAP.md) |

Keep the installation's original private state and deployment identities. A
new worktree does not contain its credentials, and a plan or old checkpoint
is not a current operating procedure. The operating guide makes the remaining
manual responsibilities explicit: startup, backup retention, alert delivery
and recovery promotion are not all automated.

## References

| Reference | Use it for |
| --- | --- |
| [Configuration](reference/CONFIGURATION.md) | Setting ownership, required inputs, defaults, trust and credential boundaries |
| [CLI](reference/CLI.md) | Runtime commands versus workstation-only ceremonies and their SQL identities |
| [MCP](reference/MCP.md) | Tool behavior, search/absence semantics, brief/status and trust boundaries |
| [Claims](reference/CLAIMS.md) | Assertion, citations, lifecycle examples and refusals |
| [Worker](reference/WORKER.md) | Source configuration, tick stages, retained inputs and progress |
| [Collection and ingestion](reference/COLLECTION.md) | Imports, capture, provider webhooks and NDJSON contract |
| [Deployment profiles](reference/DEPLOYMENT_PROFILES.md) | Which environment and procedure an instruction applies to |
| [Status and limits](reference/STATUS.md) | Implemented behavior, qualification gaps and deferred features |
| [Glossary](reference/GLOSSARY.md) | Operational terms and the difference between schemas, generations and milestones |
| [Security](SECURITY.md) | Threat boundaries, privileges, key handling and dependency exceptions |

Configuration references are backed by the parsers in `src/`; deployment
runbooks describe how those settings are supplied in a particular environment.
Use `--help` from the same binary build as the service when checking flags.

## Develop and validate

[Development workflow](DEVELOPMENT.md) covers builds, lint, unit/integration
checks and the separate disposable database required by live SQL tests.
[Examples](../examples/README.md) contains fixtures; the
[trial kit](../examples/trial/README.md) drives a broader hands-on exercise.
The [optional OSTK demo](OSTK_DEMO.md) is a separate adapter demonstration.

## Architecture and decisions

- [Architecture](ARCHITECTURE.md): current components, storage and roadmap.
- [Dynamic memory architecture](DYNAMIC_MEMORY_ARCHITECTURE.md): staged target
  design; some described capabilities are intentionally not runnable yet.
- ADRs: [product/backend boundary](adr/0001-product-and-backend-boundary.md),
  [runtime foundations](adr/0002-stage4-runtime-foundations.md),
  [conflict tolerance](adr/0003-consolidation-and-conflict-tolerance.md),
  [claim lifecycle](adr/0004-serving-conflict-lifecycle.md),
  [event-first authority](adr/0005-event-first-assert-and-writer-authority.md),
  [worker/evidence](adr/0006-stage5-worker-and-evidence-recall.md),
  [spec conformance](adr/0007-spec-conformance-chain.md),
  [collected items](adr/0008-collected-items.md),
  [remote plane](adr/0009-remote-plane.md).
- [Contract corpus](../contracts/dynamic-memory/README.md): versioned artifacts
  and conformance vectors, rather than deployment instructions.

## Plans, evidence and cloud material

[M4 remote-access plan](M4_REMOTE_ACCESS_PLAN.md) records local/cloud scope and
acceptance gates. Local implementation is qualified through M4.3; M4.4 AWS work
is on hold. The [M4.2 record](../deploy/local/https/QUALIFICATION.md) and
[M4.3 record](../deploy/local/https/LIFECYCLE_QUALIFICATION.md) state what actually
passed and what remains unqualified. Earlier trial findings and retests are
[historical evidence](TRIAL_FINDINGS_2026-09-26.md), with a
[separate retest record](TRIAL_RETEST_2026-09-26.md).

The checked-in [AWS Terraform](../deploy/aws/README.md),
[cloud onboarding](CLOUD_ONBOARDING.md) and
[LocalStack harness](../deploy/localstack/README.md) describe the publication
demo/AWS integration path. They do not deploy the planned authenticated M4.4
remote stack. See the profiles reference before applying any deployment guide.
