# AWS deployment runbook

This Terraform module deploys the public, read-only Fleet Recall demo to an
ECS/Fargate service behind an Application Load Balancer. An optional CloudFront
distribution provides an HTTPS front door on its generated `cloudfront.net`
hostname. CockroachDB Cloud is the durable memory plane. A private S3 prefix
delivers the pinned local model2vec bundle to each replaceable task.

The module is intentionally safe to bootstrap: its default service and
autoscaling minimum are zero. Run the one-off migration successfully before
starting any application task.

## Prerequisites

- Terraform 1.10 or newer, AWS CLI v2, Docker Buildx, and `jq`.
- An AWS account and an existing VPC. Supply public ALB subnets and private ECS
  subnets in at least two availability zones. Private subnets need NAT egress,
  or VPC endpoints for ECR, S3, Secrets Manager, and CloudWatch plus a route to
  CockroachDB Cloud.
- A CockroachDB Cloud database and three externally provisioned SQL logins: a
  DDL-capable migrator, a private writer for seed/MCP DML, and the
  fixed `fleet_publication` login for the public demo. See
  [MIGRATIONS.md](../../docs/MIGRATIONS.md).
- Three distinct Secrets Manager secrets whose *raw values* are the
  corresponding `postgresql://` URLs. Keep `sslmode=verify-full`. Terraform
  requires all three concrete ARNs and rejects missing, wildcard, or colliding
  references, so credentials never enter Terraform configuration or state.
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

**Upgrade gate before any plan or apply:**
`publication_database_url_secret_arn`, `database_url_secret_arn`, and
`migration_database_url_secret_arn` are required pairwise-distinct concrete
inputs for the publication reader, private writer, and DDL-only migrator. An
older workspace or `terraform.tfvars` with only one or two database secrets is
not ready to plan this module. Provision the fixed `fleet_publication` login
outside Terraform in exact quiesced `NOLOGIN` state; Terraform does not create
CockroachDB identities, memberships, grants, or authentication material. Store
each strict-TLS URL as one raw value in its own secret and record only its ARN.

If customer-managed secret encryption is used, supply concrete
`publication_database_secret_kms_key_arns` that are disjoint from the
writer/migrator `database_secret_kms_key_arns`. Review a plan showing distinct
publication execution and task roles, the public task consuming only the
publication secret, and publication decrypt restricted to those
publication-specific CMKs through the exact Secrets Manager service and secret
encryption context. The local Terraform tests cover enabled, empty, collision,
wildcard, and isolation cases. They do not apply AWS resources. Secret
creation, plan approval, and any apply remain separate operator-authorized
actions.

The private commands under `src/bin` (such as `ostk-control-bootstrap`,
`ostk-registry-activate`, `ostk-registry-successor-activate`, and
`ostk-conflict-reconcile`) are workstation-only. The Terraform module has no
secret variable, execution role, SQL-role provisioning, task definition,
startup hook, image binary, runtime invocation, or route for any of them. Stage 2 and genesis Stage
3 use dedicated SQL principals only when their private ceremonies run; do not
reuse any current-module Terraform secret for those credentials. See the
[security policy](../../docs/SECURITY.md) and
[migration privilege boundary](../../docs/MIGRATIONS.md).

The successor repository and workstation CLI exist in source, and both
successor activation and conflict reconciliation have cluster-admin-applied,
database-local one-shot logical-role policies. Neither is deployed runtime
authority. The successor policy does not provision a login or any cloud
credential; the migration-12-through-14 tables remain quarantined from every
production application role. Only a separately authorized local ceremony may
temporarily enable an externally provisioned successor-role member.

That local ceremony is outside this module. Apply the control and genesis
policies and successor quarantine first. Then quiesce private members, freeze
role/grant/default/ownership/schema-DDL changes, explicitly clean forbidden
non-target PUBLIC routine defaults (including reconciliation's creator row if
that optional role exists) and either-direction successor/reconciliation
edges, audit the successor role and PUBLIC authority across every database,
then reapply the successor policy immediately before the exclusive member's
enable/use/disable window. A later reconciliation ceremony performs the
symmetric cleanup and audit, including the successor creator row; successor is
optional, not a reconciliation prerequisite. Neither database-local policy can
perform those cross-database and conditional cleanup steps by itself.

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
authoritative state. Preserve its versions and access until every managed
resource has been intentionally destroyed. Native S3 lock files require
Terraform 1.10 or newer.

The Terraform test suite covers dormant bootstrap, publication
enable/empty/collision isolation, three-secret and KMS separation, IAM wildcard
rejection, direct TLS hostname binding, the isolated CloudFront front door,
mutually exclusive TLS modes, model-prefix/bucket validation, capacity
ordering, and supported CloudWatch retention. Passing it validates
configuration logic; it does not apply AWS resources.

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

The embedded migrator applies every version in [`migrations/`](../../migrations).
Every version except 12 through 14 executes outside a wrapping SQL transaction
because of CockroachDB schema-changer and schema-lock constraints. Versions 10, 11, and
15 through 17 are resumable online index transitions that fail closed unless
the committed public catalog has the exact expected definition. Version 18 is
resumable for the same reason: every object it creates uses `IF NOT EXISTS`,
and its closing catalog assertions pin the exact column shape, the complete
committed constraint set, and the authority view's owner and definition, so a
same-name object it did not create fails with SQLSTATE `55000` instead of being
adopted. Versions 12
through 14 run with SQLx bookkeeping in one transaction on a dedicated session
with `autocommit_before_ddl = false`; that session is closed rather than
returned to the runtime pool.

Keep the service at zero and do not run two migrators concurrently or replay
migration SQL manually. Afterward, verify that every embedded version recorded
a successful row. [MIGRATIONS.md](../../docs/MIGRATIONS.md) describes the
serving and private compatibility floors.

```bash
./deploy/aws/run-migration.sh
aws logs tail "$(terraform -chdir=deploy/aws output -raw log_group_name)" \
  --region us-east-1 --since 30m
```

The wrapper starts one Fargate task from the dedicated migration task
definition, waits for it to stop, and propagates its exit code. It never prints
the injected database URL.

Before starting the runtime, the cluster security operator must
apply/reapply the frozen control and genesis-activation logical-role policies,
then apply the deny-only
[`successor-schema-quarantine-grants.sql`](../cockroach/successor-schema-quarantine-grants.sql).
The quarantine requires all fourteen successful rows, revokes every successor
table privilege from `public` and the existing application roles, and grants
nothing. Do not provision or enable a conflict-reconciliation member as part of
serving startup. Its prefix-16 logical-role policy must be applied by a cluster
admin; database ownership alone is insufficient. The policy and one-shot CLI
are a separate, explicitly authorized workstation operation.

The fixed external `fleet_publication` login must remain drained and exact
`NOLOGIN` while a cluster admin audits both publication principals and
inherited PUBLIC authority across every database and applies
[`publication-reader-role-grants.sql`](../cockroach/publication-reader-role-grants.sql).
Freeze role, grant, default, ownership, and schema-DDL changes; repeat the
external audit if necessary and reapply the policy immediately before the
separate exact authentication-enable operation. Quiesce/drain the login and
repeat the sequence after every migration or grant change. Terraform does not
perform any of these CockroachDB identity or grant operations.

## 5. Seed the immutable demo corpus

After migration and private-writer grants, run the idempotent one-off seed task:

```bash
./deploy/aws/run-seed.sh
aws logs tail "$(terraform -chdir=deploy/aws output -raw log_group_name)" \
  --region us-east-1 --since 30m
```

The task ingests `/opt/ostk/demo/demo.ndjson`, which is bundled in the image
and contains no tenant authority or secrets. It uses the least-privilege
private-writer database secret, loads and verifies the same pinned S3 model,
and invokes the trusted `ingest` CLI. Stable source coordinates make rerunning
it safe. Do not start the public service until it exits zero.

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

Choose exactly one HTTPS mode for the public demo:

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

To check persistence, force one ECS task replacement with
`aws ecs update-service --force-new-deployment` and repeat the exact query. The
replacement must return a hit from the unchanged CockroachDB corpus.

## Runtime and least privilege

- The runtime container is UID/GID `10001`, with no shell login and no inbound
  port except ALB-to-task TCP/8080. The writable layer is required only because
  Fargate downloads a verified model into ephemeral storage on cold start.
- The publication, private-writer, and migration execution paths each read only
  their own database secret. The public application has distinct publication
  execution and task roles and receives only the publication-reader secret.
  Its secret policy allows exactly `secretsmanager:GetSecretValue` on that ARN;
  optional `kms:Decrypt` is limited to concrete publication-specific CMKs with
  `kms:ViaService` bound to regional Secrets Manager and
  `kms:EncryptionContext:SecretARN` bound to that exact secret. Those CMKs are
  disjoint from the writer/migrator list. The publication task role reads only
  the three exact model object ARNs, with no list, write, or wildcard access.
- The private writer needs the documented DML and legacy-sequence surface for
  seed/MCP work; it does not need schema creation. The migration task
  injects only its distinct DDL-capable secret. Neither secret reaches the
  public application environment.
- The fixed external `fleet_publication` login is a member only of the logical
  `fleet_publication_reader` role, which is forced to `NOLOGIN`. Its entire
  positive surface is `CONNECT` on `fleet_recall`, `USAGE` on schema `public`,
  and `SELECT` on exactly `_sqlx_migrations`, `memory_corpus_models`,
  `memory_chunks`, `memory_claim_embeddings`, `memory_claim_support`,
  `memory_claims`, `memory_conflict_members`, and `memory_conflicts`. It has no
  DML, DDL, sequence, system, private-table, ownership, grant-option, or
  future-default authority. The process also verifies both the decoded URL
  username and connected `current_user` are exactly `fleet_publication`.
- Do not grant runtime or any prior one-shot role access to
  `memory_registry_transitions`,
  `memory_registry_genesis_bridge_consumptions`, or
  `memory_registry_current_heads_v2`. Those successor tables remain unavailable
  to the production application roles under the quarantine. The private
  successor policy may grant only its exact bounded surface to a temporary,
  externally provisioned member during an exclusive local ceremony; it does
  not grant production authority or create AWS wiring.
- No AWS role or task receives a private control, genesis-activation,
  successor-activation, or conflict-reconciliation credential. Their one-shot
  commands remain workstation-only until a separately reviewed deployment
  increment explicitly wires one.
- The production image contains only the `ostk-fleet-recall` binary; none of
  the private workstation binaries under `src/bin` is built into it.
- Each task is permanently bound to one tenant, project, agent, privacy tier,
  embedding model, and bundle digest through deployment configuration. Public
  request data cannot select a different tenant or project.
- Multiply `max_database_connections` by `autoscaling_max_capacity` before
  selecting the CockroachDB Cloud connection limit. The default is eight per
  task.
- CloudWatch retains application logs for 60 days by default. ECR image
  scanning, deployment rollback, ALB deletion protection, and ALB
  invalid-header dropping are enabled. Container Insights is configurable.

The broad service egress rule supports CockroachDB Cloud and all AWS control
plane endpoints. For a long-lived production deployment, replace internet
egress with VPC endpoints/prefix lists, private Cockroach connectivity, and a
dedicated egress policy. Add AWS WAF/rate limiting before exposing a mutable
HTTP API; the public demo surface is intentionally read-only.

## Rollback and teardown

ECS deployment circuit breaking rolls the service back to the last healthy task
definition when a new image fails health checks. Database changes are
roll-forward only; do not couple schema rollback to an ECS rollback. See the
migration recovery rules before changing the database.

Before an intentional teardown, set the service count and autoscaling minimum
back to zero. Terraform teardown removes AWS compute infrastructure but does not
delete the externally managed CockroachDB database, S3 bucket, or secrets.
Review and approve those destructive external deletions separately, after
taking any backups you need.

The protected ALB cannot be destroyed until protection is deliberately removed.
Set `enable_deletion_protection = false`, review and apply that specific change,
confirm the ALB is no longer protected, and only then review a separate
`terraform plan -destroy`. Never weaken protection as part of an unreviewed
destroy attempt. Destroy the [private network stack](network/README.md) last.
