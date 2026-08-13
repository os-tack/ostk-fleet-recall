# AWS deployment runbook

This Terraform module deploys the public, read-only Fleet Recall demo to an
ECS/Fargate service behind an Application Load Balancer. CockroachDB Cloud is
the durable memory plane. A private S3 prefix delivers the pinned local
model2vec bundle to each replaceable task.

The module is intentionally safe to bootstrap: its default service and
autoscaling minimum are zero. Run the one-off migration successfully before
starting any application task.

This is a deployment runbook, not deployment evidence. As of the current
repository state, the real AWS/CockroachDB Cloud run, public HTTPS URL, cloud
query plans, reference-agent result, and post-replacement recall are pending.
Keep those claims and their submission placeholders unresolved until the live
commands succeed and their redacted artifacts are reviewed.

## Prerequisites

- Terraform 1.7 or newer, AWS CLI v2, Docker Buildx, and `jq`.
- An AWS account and an existing VPC. Supply public ALB subnets and private ECS
  subnets in at least two availability zones. Private subnets need NAT egress,
  or VPC endpoints for ECR, S3, Secrets Manager, and CloudWatch plus a route to
  CockroachDB Cloud.
- A CockroachDB Cloud database and two SQL users in production: a
  DDL-capable migrator and a least-privilege runtime user. See
  [MIGRATIONS.md](../../docs/MIGRATIONS.md).
- Two Secrets Manager secrets whose *raw values* are the corresponding
  `postgresql://` URLs. Keep `sslmode=verify-full`. Terraform receives only
  their ARNs, so credentials never enter Terraform configuration or state.
- A private, encrypted S3 bucket containing exactly the model files consumed
  at runtime under one immutable release prefix:

  ```text
  s3://BUCKET/models/potion-retrieval-32M/RELEASE_ID/config.json
  s3://BUCKET/models/potion-retrieval-32M/RELEASE_ID/model.safetensors
  s3://BUCKET/models/potion-retrieval-32M/RELEASE_ID/tokenizer.json
  ```

  Enable S3 versioning and block all public access. The task role can read only
  those three object ARNs. It cannot list the bucket or write objects.

CockroachDB Cloud must allow the tasks' stable egress address. A NAT gateway
with an Elastic IP is the simplest demo arrangement; add that IP to the Cloud
cluster allowlist. Private connectivity is preferable for a production fleet.

## 1. Prepare and pin the model bundle

The bundle entries must be regular files, not Hugging Face cache symlinks.
Dereference them into a release directory, then calculate the application-level
digest:

```bash
ostk-fleet-recall model-digest /absolute/path/to/release-bundle
aws s3 cp /absolute/path/to/release-bundle/ \
  s3://BUCKET/models/potion-retrieval-32M/RELEASE_ID/ \
  --recursive --sse AES256
```

Set the printed digest as `embedding_model_sha256`. The container downloads
only the three allowlisted files and verifies the same domain-separated digest
both immediately after download and immediately before process startup. A
truncated, replaced, or mismatched bundle fails closed.

## 2. Create the ECR repository and push an image

Copy the example inputs and replace every placeholder. Do not put a database
URL in the file.

```bash
cd deploy/aws
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform test
terraform apply -target=aws_ecr_repository.app
```

The current Terraform suite contains eleven runs covering dormant bootstrap,
TLS hostname binding, model-prefix/bucket validation, capacity ordering, and
supported CloudWatch retention. Passing it validates configuration logic; it
does not prove that AWS resources have been deployed.

Log in to the output repository and push one immutable, architecture-matched
tag. Run this from the repository root:

```bash
AWS_REGION=us-east-1
REPOSITORY_URL=$(terraform -chdir=deploy/aws output -raw ecr_repository_url)
IMAGE_TAG=git-0123456789ab
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "${REPOSITORY_URL%%/*}"
docker buildx build \
  --platform linux/amd64 \
  --build-arg VCS_REF=0123456789abcdef \
  --tag "$REPOSITORY_URL:$IMAGE_TAG" \
  --push .
```

The Dockerfile uses Rust 1.94 and `cargo build --locked`. ECR tag mutability is
disabled; select a new commit-derived tag for every release.

## 3. Create dormant infrastructure

Keep these values at zero for the first full apply:

```hcl
service_desired_count      = 0
autoscaling_min_capacity   = 0
log_retention_days         = 60
enable_deletion_protection = true
```

Then review and apply:

```bash
terraform -chdir=deploy/aws plan
terraform -chdir=deploy/aws apply
```

This creates the ALB and service definition, but no application container can
race the initial schema migration.

## 4. Run exactly one migration task

The initial migration includes CockroachDB vector-index builds and is
explicitly non-transactional. Keep the service at zero and do not run two
migrators concurrently.

```bash
./deploy/aws/run-migration.sh
aws logs tail "$(terraform -chdir=deploy/aws output -raw log_group_name)" \
  --region us-east-1 --since 30m
```

The wrapper starts one Fargate task from the dedicated migration task
definition, waits for it to stop, and propagates its exit code. It never prints
the injected database URL.

## 5. Seed the immutable demo corpus

After migration and runtime-user grants, run the idempotent one-off seed task:

```bash
./deploy/aws/run-seed.sh
aws logs tail "$(terraform -chdir=deploy/aws output -raw log_group_name)" \
  --region us-east-1 --since 30m
```

The production image contains only the repository's three-record synthetic
`examples/demo.ndjson` at `/opt/ostk/demo/demo.ndjson`; it contains no tenant
authority or secret. The seed task uses the least-privilege runtime database
secret, loads and verifies the same pinned S3 model, and invokes the trusted
`ingest` CLI. Stable source coordinates make rerunning this task safe. Do not
start the public service until this task exits zero.

## 6. Start and verify the demo

Change the desired and minimum counts to `1` (or `2` for task-level
redundancy), apply again, and inspect the service rollout:

```bash
terraform -chdir=deploy/aws apply
aws ecs wait services-stable \
  --cluster "$(terraform -chdir=deploy/aws output -raw cluster_name)" \
  --services "$(terraform -chdir=deploy/aws output -raw service_name)"
DEMO_URL=$(terraform -chdir=deploy/aws output -raw demo_url)
curl --fail "$DEMO_URL/healthz"
curl --fail --silent --show-error \
  --header 'content-type: application/json' \
  --data '{"query":"durable shared semantic memory across restarts","limit":5}' \
  "$DEMO_URL/api/recall" | jq -e '.data.hits | length >= 1'
```

For the public submission, point a DNS name at the ALB and set both an ACM
`certificate_arn` and its covered `demo_hostname`. Terraform changes port 80
into an HTTPS redirect and outputs the application hostname—not the ALB's
`amazonaws.com` name, which normally does not match the certificate. DNS record
creation remains explicit because the authoritative Route 53 zone may live in
another account. The listener serves TLS 1.2 or newer.

After the first successful recall, force one ECS task replacement and repeat
the exact query. The replacement must return a hit from the unchanged
CockroachDB corpus before the URL is used in Devpost.

## 7. Run the standalone reference policy fleet

After the public demo is deployed, healthy, and post-replacement recall has
succeeded, use the deterministic reference policy agent as the default AWS
agent proof. It is Fleet Recall application code and uses neither OSTK nor an
LLM. OSTK remains a strictly optional adapter and is not required for this task
definition or wrapper.

The wrapper requires `aws`, `curl`, `jq`, and `terraform`. Choose a fresh,
non-secret run ID and preserve stdout as the candidate evidence artifact;
progress and failure diagnostics go to stderr:

```bash
RUN_ID=devpost-cloud-YYYYMMDDTHHMMSSZ
mkdir -p target/aws-evidence
./deploy/aws/run-reference-agent.sh "$RUN_ID" \
  >"target/aws-evidence/reference-agent-$RUN_ID.json"

jq -e '
  .schema == "fleet-reference-agent-run-v1" and
  .verified == true and
  .deployment == "amazon-ecs-fargate" and
  .run_id == $run and
  (.public_demo.url | startswith("https://")) and
  (.aws.tasks | length) == 4 and
  .public_demo.health == "ready" and
  .public_demo.read_only_verification == true and
  (.public_demo.exact_claim_ids_observed | length) == 2 and
  .public_demo.retrieval_lanes == ["lexical", "dense"] and
  .public_demo.fusion == "rrf" and
  .public_demo.cockroachdb_capabilities.vector_index_enabled == true and
  .public_demo.cockroachdb_capabilities.lexical_index_enabled == true and
  .public_demo.cockroachdb_capabilities.conflict_membership_index_enabled == true and
  .public_demo.cockroachdb_capabilities.cosine_distance_supported == true and
  .public_demo.cockroachdb_capabilities.schema_version > 0 and
  .public_demo.cockroachdb_capabilities.embedding_dimension == 512
' --arg run "$RUN_ID" \
  "target/aws-evidence/reference-agent-$RUN_ID.json"
```

The wrapper reads the machine-readable `reference_agent_task` Terraform output
and `demo_url`. Before any mutation it requires `/healthz` to be ready, then
checks `/api/status` for a CockroachDB version, positive schema version, the
vector, lexical, and conflict-membership indexes, working cosine distance, a
named embedding model, and dimension 512. It then launches four one-off Fargate
tasks sequentially from the dedicated task definition:

1. `record-decision` as deployment-bound `agent-a` records the migration
   decision and proves an identical idempotent replay. Its receipt key includes
   a SHA-256 project namespace so tenant-wide keys cannot collide across
   projects.
2. `recall-and-act` as `agent-b` finds A's claim through lexical+dense RRF,
   resolves it through exact `recall(get)`, persists a rollout action citing
   that claim, and rereads the durable action before reporting evidence.
3. `record-conflict` as `agent-c` persists an incompatible decision and proves
   that the open conflict contains exactly the disputed A/C claims and expected
   incompatible values.
4. `recall-conflict-and-escalate` as the same `agent-b` identity reads the open
   conflict, persists `pause rollout for operator review` citing it, and rereads
   the durable escalation before reporting evidence.

For each step the wrapper verifies the exact override, waits for the task to
stop with exit code zero, and selects structured evidence for the exact
run/step/agent from that task's CloudWatch log stream. It cross-checks claim,
action, conflict, and escalation identifiers—including the exact A decision and
C incompatible claim IDs in both conflict-producing steps—then queries the
public read-only recall API and requires the exact persisted action and
escalation claim IDs. Only that fully correlated path emits one `verified: true`
summary. Each task uses the least-privilege runtime database secret and the
pinned S3 model bundle.

The successful JSON is intentionally publication-sanitized. `aws.task_definition`
is a `family:revision` coordinate, `aws.log_stream_prefix` is
`fleet/<container>`, and each `aws.tasks[]` entry contains only `step`, `agent`,
`task_id`, `log_stream_suffix`, and `stopped_at`. Full task-definition/task ARNs,
account IDs, a single full `log_stream` field, and raw per-step CloudWatch
evidence are not embedded; the publication fields retain only the common
prefix and per-task suffix. `public_demo.cockroachdb_capabilities` contains the
sanitized status proof, alongside the URL, ready state, read-only verification
flag, exact observed action/escalation claim IDs, and lexical+dense RRF
diagnostics.

Treat the file as cloud evidence only when the wrapper actually ran against the
submission ECS cluster, public demo, and CockroachDB Cloud database. Unit tests,
Terraform tests, LocalStack, or a handcrafted JSON object do not satisfy this
gate. The emitted receipt is designed for publication, but still review chosen
run/project names, the demo URL, cluster coordinate, task IDs, and model/version
metadata before sharing it. Never supplement it with the database URL, account
ID, task ARN, secret ARN, or raw CloudWatch log export.

## 8. Replace the complete serving task set and prove persistence

Preserve the verified reference-agent receipt, then use it to force a fresh ECS
service deployment. This is an intentional live AWS mutation: it replaces the
running serving tasks and can briefly consume additional Fargate capacity while
ECS rolls the deployment. Do not run it until the HTTPS service is healthy and
the reference-agent wrapper has succeeded.

```bash
REFERENCE_RECEIPT="target/aws-evidence/reference-agent-$RUN_ID.json"
REPLACEMENT_RECEIPT="target/aws-evidence/replacement-$RUN_ID.json"

./deploy/aws/run-replacement-proof.sh "$REFERENCE_RECEIPT" \
  >"$REPLACEMENT_RECEIPT"

./deploy/aws/verify-publication-receipts.sh \
  "$REFERENCE_RECEIPT" "$REPLACEMENT_RECEIPT"
```

Before replacement, the wrapper requires one stable, nonzero ECS service and
observes the exact action and escalation claim IDs from the reference-agent
receipt through public lexical+dense RRF. It invokes
`aws ecs update-service --force-new-deployment`, waits for the service to
stabilize, requires the complete post-deployment task-ID set to be disjoint
from the pre-deployment set, and observes the same exact claims again. The
resulting `fleet-ecs-replacement-run-v1` JSON contains only task IDs and bounded
service coordinates, never task ARNs or account IDs.

The publication verifier checks both complete schemas, internal claim/action
correlations, the full-task-set replacement, before/after observations, and
cross-receipt run/project/URL/deployment identity. It also rejects full AWS
ARNs, 12-digit account IDs, database URLs, credential-bearing URLs,
secret-bearing keys, and raw log-stream fields. Its success output is marked
`validation_only: true`; it validates live receipts but is not a substitute for
running either live wrapper.

## Cloud `EXPLAIN` boundary

Index presence from `/api/status` and observed lexical+dense RRF are not a
substitute for the required representative Cloud `EXPLAIN`. The existing Rust
plan test inserts more than 10,000 rows and is explicitly limited to a
disposable database; do not point it at the submission corpus merely to fill
the evidence checkbox. A publication-safe Cloud plan receipt remains pending
until it can run the production query shapes against a separately approved
disposable CockroachDB Cloud database (or through a bounded one-off diagnostic
task) without exposing the database URL. Keep `[CAPTURE_CLOUD_PLAN]` unresolved
until that real plan is captured and reviewed.

## Runtime and least privilege

- The runtime container is UID/GID `10001`, with no shell login and no inbound
  port except ALB-to-task TCP/8080. The writable layer is required only because
  Fargate downloads a verified model into ephemeral storage on cold start.
- The execution role reads the declared database secrets. The application task
  role reads only three model objects. There is no wildcard bucket access.
- The runtime SQL user needs DML on the Fleet Recall tables and read access to
  `_sqlx_migrations`; it does not need schema creation. The separate migration
  task definition can inject a different, DDL-capable secret.
- Each task is permanently bound to one tenant, project, agent, privacy tier,
  embedding model, and bundle digest through deployment configuration. Public
  request data cannot select a different tenant or project.
- Multiply `max_database_connections` by `autoscaling_max_capacity` before
  selecting the CockroachDB Cloud connection limit. The default is eight per
  task.
- CloudWatch retains application logs for 60 days by default to preserve
  judging evidence. Container Insights, ECR image scanning, deployment rollback,
  ALB deletion protection, and ALB invalid-header dropping are enabled.

The broad service egress rule supports CockroachDB Cloud and all AWS control
plane endpoints. For a long-lived production deployment, replace internet
egress with VPC endpoints/prefix lists, private Cockroach connectivity, and a
dedicated egress policy. Add AWS WAF/rate limiting before exposing a mutable
HTTP API; the hackathon demo surface is intentionally read-only.

## Availability through judging

The [official rules](https://cockroachdb-ai.devpost.com/rules) require the
working project to remain available free of charge and without restriction
through the end of judging. Once submitted, keep the ECS service, ALB and
HTTPS/DNS route, CockroachDB Cloud database, S3 model bundle, runtime secret,
network egress, and required logs available through **September 15, 2026 at
5:00 PM EDT / 4:00 PM CDT**. Monitor `/healthz` and a bounded recall query, and
repair failures without revoking judge access.

Do not set the service or autoscaling minimum to zero, delete supporting
resources, revoke credentials or network access, or run Terraform destroy
before that deadline. A one-off reference-agent task may stop after each step;
the submitted public demo and its durable memory plane must remain available.
Keep `enable_deletion_protection = true` and the 60-day log retention throughout
the judging hold.

## Rollback and post-judging teardown

ECS deployment circuit breaking rolls the service back to the last healthy task
definition when a new image fails health checks. Database changes are
roll-forward only; do not couple schema rollback to an ECS rollback. See the
migration recovery rules before changing the database.

After the judging hold expires, set the service count and autoscaling minimum
back to zero before intentional teardown. Terraform teardown removes AWS
compute infrastructure but does not delete the externally managed CockroachDB
database, S3 bucket, or secrets. Review and approve those destructive external
deletions separately; preserving evidence and backups comes first.

The protected ALB cannot be destroyed until protection is deliberately removed.
After the hold, set `enable_deletion_protection = false`, review and apply that
specific change, confirm the ALB is no longer protected, and only then review a
separate `terraform plan -destroy`. Never weaken protection as part of an
unreviewed destroy attempt.
