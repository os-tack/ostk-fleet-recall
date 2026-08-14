# AWS deployment runbook

This Terraform module deploys the public, read-only Fleet Recall demo to an
ECS/Fargate service behind an Application Load Balancer. An optional CloudFront
distribution provides an HTTPS front door on its generated `cloudfront.net`
hostname. CockroachDB Cloud is the durable memory plane. A private S3 prefix
delivers the pinned local model2vec bundle to each replaceable task.

The module is intentionally safe to bootstrap: its default service and
autoscaling minimum are zero. Run the one-off migration successfully before
starting any application task.

This remains the reproducible deployment runbook. At the recorded revision-10
release boundary, its live submission candidate is available at
<https://d13zrqfh66r7ub.cloudfront.net>. Immutable image `git-56b577c82b9c`
at source commit `56b577c82b9c5a5c80d73103f7f6b56d51698872` runs with all
four task-definition families at revision 10, and the service is 1/1 healthy.
The idempotent rich-seed task exited zero and upserted exactly 552 rows: 346 documentation
chunks, 2 code chunks, and 204 operations chunks. The public API returned the
exact release revision and line ranges. Final desktop and 390px mobile QA
verified safe inline Markdown, immutable exact `#Lx-Ly` links, a relative
repository link rendered as a code-styled anchor, and no horizontal overflow.
The final seven-query smoke gate passed. The ECR Basic OS-package scan is `COMPLETE`
with an empty severity
count, without claiming language or application-dependency coverage. GitHub
Actions run
[`31832684235`](https://github.com/os-tack/ostk-fleet-recall/actions/runs/31832684235)
completed all five jobs successfully. The checked-in public-relevance receipt
is historical revision-7 evidence. The source-conflict self-audit,
reference-agent, replacement, and validation artifacts are historical
revision-6 evidence; Cloud `EXPLAIN` is separately captured historical plan
evidence. None was rerun for revision 10.

## Prerequisites

- Terraform 1.10 or newer, AWS CLI v2, Docker Buildx, and `jq`.
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
cp backend.hcl.example backend.hcl
cp terraform.tfvars.example terraform.tfvars
# Edit backend.hcl and terraform.tfvars.
terraform init -backend-config=backend.hcl
terraform test
terraform apply -target=aws_ecr_repository.app
```

The private, encrypted, versioned S3 object configured by `backend.hcl` is the
authoritative state. Preserve its versions and access through the judging hold
and until every managed resource has been intentionally destroyed. Native S3
lock files require Terraform 1.10 or newer.

The current Terraform suite contains thirteen runs covering dormant bootstrap,
direct TLS hostname binding, the isolated CloudFront front door,
mutually-exclusive TLS modes, model-prefix/bucket validation, capacity
ordering, and supported CloudWatch retention. Passing it validates
configuration logic; it does not prove that AWS resources have been deployed.

Log in to the output repository and push one immutable, architecture-matched
tag. Run this from the repository root:

```bash
AWS_REGION=us-east-1
REPOSITORY_URL=$(terraform -chdir=deploy/aws output -raw ecr_repository_url)
IMAGE_TAG=git-0123456789ab
IMAGE_PLATFORM=linux/arm64 # Must match cpu_architecture = "ARM64".
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "${REPOSITORY_URL%%/*}"
docker buildx build \
  --platform "$IMAGE_PLATFORM" \
  --target production \
  --build-arg VCS_REF=0123456789abcdef0123456789abcdef01234567 \
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
./deploy/aws/run-seed.sh --rich-demo
aws logs tail "$(terraform -chdir=deploy/aws output -raw log_group_name)" \
  --region us-east-1 --since 30m
```

The recorded revision-10 production image `git-56b577c82b9c` contains the
repository's deterministic rich corpus. Its one-off rich-seed task exited zero
and upserted exactly 552 rows: 346 documentation chunks, 2 code chunks, and 204
operations chunks. The default and rich corpora contain no tenant authority or
secrets. The default invocation ingests
`/opt/ostk/demo/demo.ndjson`; `--rich-demo` selects
`/opt/ostk/demo/rich-demo.ndjson`. Both one-off tasks use the least-privilege
runtime database secret, load and verify the same pinned S3 model, and invoke
the trusted `ingest` CLI. Stable source coordinates make rerunning either task
safe. Do not start the public service until both tasks exit zero.

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

Choose exactly one HTTPS mode for the public submission:

- The fail-safe default is `enable_cloudfront = true`,
  `alb_ingress_cidrs = []`, and `certificate_arn = null`. It uses the
  generated CloudFront hostname. Terraform outputs
  `https://<distribution>.cloudfront.net`, requires HTTPS from viewers, disables
  caching, and forwards request bodies and `Content-Type` but no viewer cookies,
  query strings, or `Authorization` header. The default behavior accepts only
  `GET`/`HEAD`; the ordered `/api/recall` behavior accepts all CloudFront methods
  so the bounded `POST` endpoint works. Security response headers and
  `Cache-Control: no-store, max-age=0` are applied at the edge, and transient
  500/502/503/504 responses have a zero error-cache TTL.
- To use your own hostname, explicitly set `enable_cloudfront = false`, provide
  a reviewed non-empty `alb_ingress_cidrs` allowlist, point DNS at the ALB, and
  set both a regional ACM `certificate_arn` and its covered
  `demo_hostname`. Terraform changes port 80 into an HTTPS redirect and outputs
  the application hostname—not the ALB's `amazonaws.com` name, which normally
  does not match the certificate. DNS creation remains explicit because the
  authoritative Route 53 zone may live in another account. The ALB listener
  serves TLS 1.2 or newer.

The modes are mutually exclusive. The default CloudFront certificate requires
the generated `cloudfront.net` hostname and AWS fixes its viewer security policy
at a TLSv1 minimum; it still negotiates newer TLS with capable clients. A custom
CloudFront certificate/security policy is intentionally out of scope. Use the
direct ACM mode when a custom hostname or a TLS 1.2 minimum is required.

CloudFront connects to the ALB over HTTP port 80. That hop is deliberately
isolated in two layers: the ALB security group replaces public CIDR ingress with
AWS's `com.amazonaws.global.cloudfront.origin-facing` managed prefix list, and
the listener returns 403 unless a 48-character origin header matches. Terraform
generates the header with the Random provider, treats it as sensitive, persists
it in encrypted remote Terraform state, and never outputs it. Anyone who can
read Terraform state can still recover it, so keep state access
least-privileged. The managed prefix list consumes 55 security-group rule quota
entries; confirm the account's security-group quota before enabling this mode.
Distribution creation and updates can take several minutes.

The live candidate selected CloudFront mode and currently resolves at
<https://d13zrqfh66r7ub.cloudfront.net>. This proves viewer HTTPS with the
default CloudFront certificate; it does **not** prove end-to-end TLS or a TLS
1.2 viewer minimum because the viewer policy has a TLSv1 minimum and the
CloudFront-to-ALB hop is restricted HTTP.

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

### Prove a source-backed documentation/code conflict

After schema 2 is migrated and `./deploy/aws/run-seed.sh --rich-demo` has
completed, run the separate self-audit proof with a fresh ID. It does not alter
the four-step publication receipt above:

```bash
SELF_AUDIT_RUN_ID=devpost-self-audit-YYYYMMDDTHHMMSSZ
SELF_AUDIT_RECEIPT="target/aws-evidence/self-audit-$SELF_AUDIT_RUN_ID.json"

./deploy/aws/run-self-audit-proof.sh "$SELF_AUDIT_RUN_ID" \
  >"$SELF_AUDIT_RECEIPT"

jq -e '
  .schema == "fleet-source-conflict-self-audit-run-v1" and
  .verified == true and
  .run_id == $run and
  .claims.spec.actor == "agent-a" and
  .claims.spec.value == true and
  .claims.implementation.actor == "agent-c" and
  .claims.implementation.value == false and
  .conflict.state == "open" and
  .conflict.member_count == 2 and
  .conflict.surfaced_by_semantic_recall == true and
  .retrieval.support_claims_matched > 0 and
  .retrieval.support_claims_truncated == false and
  .cockroachdb_capabilities.schema_version == 2 and
  .cockroachdb_capabilities.claim_support_chunk_index_enabled == true
' --arg run "$SELF_AUDIT_RUN_ID" "$SELF_AUDIT_RECEIPT"
```

The wrapper launches `record-retraction-spec-claim` as `agent-a`, backed by the
exact `examples/README.md` chunk, followed by
`record-retraction-implementation-claim` as `agent-c`, backed by exact chunks
from `src/mcp/tools.rs` and `src/application.rs`. It requires the exact Fargate
overrides, two distinct exit-zero tasks, and exactly one structured evidence
event per task with the expected schema, run ID, agent, project, and
`source-backed-mcp-contract-self-audit-v1` policy. It then correlates the
Boolean claims and their SHA-256 source coordinates before querying the public
demo with `Does MCP remember support deliberate retractions?`.

Success requires that semantic query to surface at least one of those exact
source chunks and project its exact open, complete, two-member conflict through
the source-support index. The receipt contains no task ARN, account ID, log
group/stream coordinate, raw log event, database URL, or secret. As with the
main receipt, mock success proves only the wrapper contract; only a real run
against the submission stack is cloud evidence.

Treat the file as cloud evidence only when the wrapper actually ran against the
submission ECS cluster, public demo, and CockroachDB Cloud database. Unit tests,
Terraform tests, LocalStack, or a handcrafted JSON object do not satisfy this
gate. The emitted receipt is designed for publication, but still review chosen
run/project names, the demo URL, cluster coordinate, task IDs, and model/version
metadata before sharing it. Never supplement it with the database URL, account
ID, task ARN, secret ARN, or raw CloudWatch log export.

The following receipts are historical revision-6 cloud evidence. They were not
rerun for revision 10. The revision-6 self-audit
produced the
checked-in, publication-safe
[receipt](../../docs/evidence/self-audit-devpost-self-audit-20260814T133640Z-rev6.json).
It correlated documentation-backed claim 9 and code-backed claim 10 with exact
open conflict 3, then required semantic recall to surface the cited source
chunks and project that conflict. CockroachDB reported schema version 2, all
four capability indexes, working cosine distance, and embedding dimension 512.

Historical revision-6 run `devpost-final6-20260814T143523Z` then produced the
[reference-agent](../../docs/evidence/reference-agent-devpost-final6-20260814T143523Z.json),
[replacement](../../docs/evidence/replacement-devpost-final6-20260814T143523Z.json),
and [validation](../../docs/evidence/publication-validation-devpost-final6-20260814T143523Z.json)
receipts. Reference-agent task definition revision 6 correlated decision claim
15, action claim 16 citing it, incompatible claim 17, open conflict 5, and
escalation claim 18 citing that conflict. Public verification observed exact
claims 16 and 18 through lexical/dense RRF.

Those historical receipts are bound to immutable ARM64 image tag
`git-ba884f24858a`, digest
`sha256:7d154a37fff589d2e68ec71c230025f3324cea96f85f7b51158f2d3097f2320b`,
and source commit `ba884f24858a58b09a915e0358e60e7fcc7e2c34`; serving,
migration, seed, and reference-agent task definitions were all revision 6.

The current live release uses immutable image tag `git-56b577c82b9c` at source
commit `56b577c82b9c5a5c80d73103f7f6b56d51698872`, with all four
task-definition families at revision 10 and the service 1/1 healthy. Its
idempotent rich-seed task exited zero and upserted exactly 552 rows (346 documentation, 2
code, and 204 operations). The public API returned the exact release revision
and inclusive source-line ranges. Final desktop and 390px mobile QA verified
safe inline Markdown, immutable exact `#Lx-Ly` links, a relative repository
link rendered as a code-styled anchor, and no horizontal overflow. The final
seven-query smoke gate passed. The ECR Basic OS-package scan completed with an empty
finding-severity count, and CI run
[`31832684235`](https://github.com/os-tack/ostk-fleet-recall/actions/runs/31832684235)
completed all five jobs successfully.
The checked-in seven-query public-relevance receipt is historical revision-7
evidence for the prior 548-row release and was not regenerated for revision 10.

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

For historical revision-6 run `devpost-final6-20260814T143523Z`, the
replacement wrapper exercised serving task definition revision 6 and changed
the complete task set to a fully disjoint set. Desired count remained one, the
service returned ready, and the before/after public checks observed the same
exact claims 16 and 18 through lexical/dense RRF. This replacement proof was
not rerun for revision 10.

## Cloud `EXPLAIN` evidence

Index presence from `/api/status` and observed lexical+dense RRF are not a
substitute for physical plan evidence. The publication-safe
[CockroachDB Cloud `EXPLAIN` artifact](../../docs/evidence/cockroach-cloud-explain.txt)
records that evidence with SHA-256
`0ec1fb873b2305adaf7f83a39c09e1132a7f1916d0c962a153823dd1bcff28f2`.

The proof ran the exact production project-vector, source-vector, and selective
lexical SQL shapes through SQLx against a 10,001-row disposable logical
database on CockroachDB Cloud Basic, AWS `us-east-1`, version 26.2.5. The plans
select `vector search` with `memory_chunks_semantic_idx`, `vector search` with
`memory_chunks_source_semantic_idx`, and `scan` with
`memory_chunks_lexical_idx`; all assertions pass.

The lexical query initially ran immediately after `ANALYZE` on a long-lived
connection and briefly saw stale zero-row statistics. The unchanged query
selected the inverted index after fresh statistics became visible roughly two
minutes later. No `FORCE_INDEX` hint was used or implied. The production
database was neither queried nor modified, the disposable database was
dropped, and the temporary workstation network rule was removed after capture.

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
- CloudWatch retains application logs for 60 days to preserve judging evidence.
  ECR image scanning, deployment rollback, ALB deletion protection, and ALB
  invalid-header dropping are enabled. Container Insights is configurable but
  disabled on the cost-constrained live candidate.

The broad service egress rule supports CockroachDB Cloud and all AWS control
plane endpoints. For a long-lived production deployment, replace internet
egress with VPC endpoints/prefix lists, private Cockroach connectivity, and a
dedicated egress policy. Add AWS WAF/rate limiting before exposing a mutable
HTTP API; the hackathon demo surface is intentionally read-only.

## Availability through judging

The [official rules](https://cockroachdb-ai.devpost.com/rules) require the
working project to remain available free of charge and without restriction
through the end of judging. Once submitted, keep the ECS service, ALB,
CloudFront distribution when enabled, HTTPS/DNS route, CockroachDB Cloud
database, S3 model bundle, runtime secret, network egress, and required logs
available through **September 15, 2026 at 5:00 PM EDT / 4:00 PM CDT**. Monitor
`/healthz` and a bounded recall query, and repair failures without revoking judge
access.

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
