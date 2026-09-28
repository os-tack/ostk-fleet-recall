# Implementation and deployment status

[Documentation](../README.md) · [CLI](CLI.md) · [Configuration](CONFIGURATION.md)

This page separates shipped capabilities from future work. The architecture
and ADRs describe a broader target; a design or compiled contract alone does
not mean a deployed service supports it. Use `tools/list` and
[`recall(status)`](MCP.md#reading-status) for a running writer's
actual capabilities.

## Qualified local deployment

The single-Mac Lima/k0s HTTPS deployment completed M4.3 lifecycle qualification
on 2026-09-27: authenticated Codex access, application/VM restarts, bounded
dependency outages, image rollback, worker exclusion, leaf renewal, isolated
restore, interrupted transcript uploads and alert firing/recovery. The
[qualification record](../../deploy/local/https/LIFECYCLE_QUALIFICATION.md) gives the
versions, retained evidence and precise limits. Use the
[local operations](../../deploy/local/https/OPERATIONS.md) and
[recovery](../../deploy/local/https/RECOVERY.md) guides for the installed plane.

**M4.4 cloud deployment is on hold.** LAN/VPN access from a second machine,
AWS remote-plane qualification and the M4.5 24-hour soak remain unqualified.
The local deployment is a single replica with `Recreate`, not a high-availability
service; automatic alert delivery also needs a configured notification receiver.
[M4's plan](../M4_REMOTE_ACCESS_PLAN.md) records the remaining slices.

## Not built yet

The design in
[Dynamic corpus and causal runtime architecture](../DYNAMIC_MEMORY_ARCHITECTURE.md)
goes well beyond what runs. Two pieces of library code in `src` still have no
runner:

- relation projection (`src/relation_projection`): nothing emits relation
  attestations yet;
- contract vectors and pure contract modules for later stages (for example
  action, causal, consolidation, erasure, telemetry, and ledger epochs) under
  `contracts/dynamic-memory/v3` and `src/memory_contracts`.

ADRs 0005 to 0008 record the deferred dynamic-memory capabilities. Contract
telemetry in that design is separate from the operational Prometheus/Grafana
stack that runs today. The main deferred items are:

- **Writer authority and governance.** A registry package past generation 3
  (the strict witness knows only the compiled generation-1, generation-2,
  and generation-3 packages); deployment-keyed governance signers, since
  every successor from generation 1 on is signed with the public fixture
  keys; an `ostk-authority-install inspect` command and a generation-1
  target; moving `ostk-bootstrap-manifest-import` onto the shared
  writer-authority runtime; and a separate worker role.
- **Assert.** Event-first retraction, supersession, and correction; more
  predicates, resource-valued claims, and other admission bases; replaying a
  committed assert receipt after assert is turned off; publishing an
  assertion whose predicate allows it; `accepted_event_id` in search and
  conflict projections.
- **Worker and evidence recall.** A long-running `--interval` loop and
  managed cloud scheduling (`deploy/local` already has a five-minute k0s
  CronJob with `Forbid`); `git` and `gh` in the production image; changed-path
  git scans; supersession of transcript turns admitted before
  redaction profile 3 (the git residual is closed by
  `ostk-evidence-supersede`; a raw transcript turn's body stays raw at rest,
  counted by the pass as `transcript_turns_raw_at_rest`, with only its recall
  text redacted, because its revision closes over the body digest and the
  outbox keeps a copy); transcript tool-use,
  tool-result, and thinking records; publication-plane evidence recall (and
  the publication grant on migration 23's filtered views); fusing evidence
  into chunk recall; registering the coverage labels in a package; a body
  plane that stays encrypted after
  projection; a re-embed step; content-bearing webhooks (Slack Socket Mode,
  Linear history), a public relay, and Arrow transport.
- **Spec conformance.** `ostk-spec retire` and `inspect`; episode
  `acknowledge` and `waive`; any episode lifecycle over MCP; a
  `closed_world_verified` observer that can verify absence and so
  auto-resolve an episode; statements with more than one proposition;
  measuring the observer binary against its admitted digest; rebasing
  normative heads outside the installer's generation-3 run (an `ostk-spec
  rebase`, or a rebase onto generation 2); a spec-check worker step; other
  finding types, predicates, and observers.

## AWS publication demo

The existing AWS module is the read-only publication demo, separate from the
planned M4.4 authenticated remote plane. It does not establish evidence that
M4.4 is deployed or qualified.

The checked-in AWS Terraform provisions ECS/Fargate task definitions and a
service, an ALB behind CloudFront, ECR, IAM roles, and CloudWatch logging. Tasks
load the pinned model from a private S3 prefix and receive separate migrator,
private-writer, or publication-reader database URLs from Secrets Manager
secrets created outside Terraform. The module passes `terraform validate` and
its Terraform tests, but its current form has not been applied. See the
[AWS Terraform runbook](../../deploy/aws/README.md),
[cloud onboarding](../CLOUD_ONBOARDING.md), and the
[LocalStack harness](../../deploy/localstack/README.md), which builds the real image
and exercises its S3 and Secrets Manager interfaces against a local
CockroachDB. Terraform runs no `serve`, memory worker, or operator CLI and
provisions no writer-authority pins or content key; the
[runbook](../guides/EVENT_FIRST_OPERATIONS.md) steps run outside it.
