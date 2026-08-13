# AWS deployment runbook

This Terraform module deploys the public, read-only Fleet Recall demo to an
ECS/Fargate service behind an Application Load Balancer. CockroachDB Cloud is
the durable memory plane. A private S3 prefix delivers the pinned local
model2vec bundle to each replaceable task.

The module is intentionally safe to bootstrap: its default service and
autoscaling minimum are zero. Run the one-off migration successfully before
starting any application task.

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
terraform apply -target=aws_ecr_repository.app
```

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
service_desired_count    = 0
autoscaling_min_capacity = 0
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
- CloudWatch retains application logs for 30 days by default. Container
  Insights, ECR image scanning, deployment rollback, and ALB invalid-header
  dropping are enabled.

The broad service egress rule supports CockroachDB Cloud and all AWS control
plane endpoints. For a long-lived production deployment, replace internet
egress with VPC endpoints/prefix lists, private Cockroach connectivity, and a
dedicated egress policy. Add AWS WAF/rate limiting before exposing a mutable
HTTP API; the hackathon demo surface is intentionally read-only.

## Rollback and teardown

ECS deployment circuit breaking rolls the service back to the last healthy task
definition when a new image fails health checks. Database changes are
roll-forward only; do not couple schema rollback to an ECS rollback. See the
migration recovery rules before changing the database.

Set the service count and autoscaling minimum back to zero before intentional
maintenance. Terraform teardown removes AWS compute infrastructure but does not
delete the externally managed CockroachDB database, S3 bucket, or secrets.
