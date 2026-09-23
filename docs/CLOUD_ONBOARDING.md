# Cloud onboarding

This is the human-approved path from a validated LocalStack run to a real AWS
and CockroachDB Cloud deployment. It does not automate account creation,
billing choices, DNS ownership, or database credentials. Do not place database
URLs, passwords, AWS access keys, or secret values in this repository,
Terraform variables, command-line arguments, screenshots, or shell history.

The labels below are gates:

- **APPROVAL REQUIRED** means the account owner must approve the named choice
  before anyone performs it.
- **COST-BEARING** means the action can create a billable resource. Free-tier
  credits are not a spending limit, and an AWS Budget sends alerts but does not
  stop resources.

## 0. Safe local preflight

These checks do not print secret values or change cloud state:

```bash
cd /absolute/path/to/ostk-fleet-recall

command -v aws docker jq
aws --version
docker buildx version
docker info --format 'server={{.ServerVersion}} arch={{.Architecture}}'

terraform version

# This must succeed after AWS SSO onboarding. It prints identity metadata only.
AWS_PROFILE=ostk-fleet-recall
AWS_REGION=us-east-1
export AWS_PROFILE AWS_REGION
aws sts get-caller-identity --query Arn --output text
```

Deployment-workstation notes:

- AWS SSO sessions are temporary; authenticate again before any follow-up
  operation.
- `deploy/aws/run-migration.sh` and the other wrappers require `terraform` to
  be on `PATH`.
- Keep the model bundle as regular files under the ignored
  `.models/potion-retrieval-32M/hf-6fc8051fab2a1e0ee76689cf08c853792ac285e7/`
  directory. Git does not track the 129 MB weights.

## 1. Create and secure the AWS account

**APPROVAL REQUIRED — COST-BEARING:** Approve creation of an AWS account and a
payment method. Choose the Paid account plan if the final ECS/Fargate stack
needs services unavailable on the Free plan. New-customer credits can still
apply, but usage beyond credits is pay-as-you-go. Review the official
[AWS plan comparison](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/free-tier-plans.html).

Before deploying anything:

1. Enable phishing-resistant MFA or, at minimum, TOTP MFA on the root user.
2. Do not create root access keys. Store root recovery information securely and
   stop using root for routine deployment.
3. Create an AWS Budget with a small monthly amount and email alerts well below
   it. Confirm the alert email. See
   [AWS Budgets](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html)
   and [AWS MFA guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html).

Record, without credentials: the 12-digit account ID, billing owner, approved
budget, and region. This runbook assumes `us-east-1`.

## 2. Configure the non-root deployment identity

**APPROVAL REQUIRED:** Enable IAM Identity Center, create a human deploy user,
and assign it to this account. For a short-lived demo deployment, approve
either a time-limited administrator permission set or a reviewed custom set
covering the resources in `deploy/aws`. The Terraform deployer must be able to
manage IAM roles and policies, ECR, ECS/Fargate, EC2 security groups, ALB,
Application Auto Scaling, and CloudWatch; ordinary `PowerUserAccess` alone does
not grant all required IAM administration.

Configure temporary SSO credentials rather than static access keys:

```bash
aws configure sso --profile ostk-fleet-recall
aws sso login --profile ostk-fleet-recall

AWS_PROFILE=ostk-fleet-recall
AWS_REGION=us-east-1
export AWS_PROFILE AWS_REGION
aws sts get-caller-identity --query Arn --output text
aws configure get region --profile "$AWS_PROFILE"
```

Follow the official [AWS CLI SSO guide](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html).
The last two commands expose no secret values. Re-run `aws sso login` when the
temporary session expires.

## 3. Approve the region and network

**APPROVAL REQUIRED — COST-BEARING:** Use one AWS region for ECR, ECS, S3,
Secrets Manager, ALB, and ACM. Use the same provider/region for CockroachDB
Cloud when available. The current default is `us-east-1`.

Recommended demo network:

- one VPC;
- two public ALB subnets in distinct availability zones;
- two private ECS task subnets in those availability zones;
- `assign_public_ip = false`;
- one NAT Gateway with one Elastic IP, with both private-subnet default routes
  using it; and
- the NAT Elastic IP as the only application CIDR in the CockroachDB allowlist.

One NAT is the lower-cost demo choice but is a single-AZ egress dependency and
can incur cross-AZ charges. A NAT Gateway per AZ is the more resilient,
higher-cost production choice. Public task subnets avoid NAT charges, but task
IPs are not stable and would force a broad database allowlist; do not use that
shortcut for a public deployment. AWS documents the trade-off in
[ECS outbound networking](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/networking-outbound.html)
and bills NAT per hour and per processed GB under
[NAT Gateway pricing](https://docs.aws.amazon.com/en_en/vpc/latest/userguide/nat-gateway-pricing.html).

After creation, collect only the VPC ID, four subnet IDs, NAT Gateway ID, and
NAT Elastic IP. Inspect them without changing state:

```bash
aws ec2 describe-subnets \
  --subnet-ids subnet-ALB_A subnet-ALB_B subnet-TASK_A subnet-TASK_B \
  --query 'Subnets[].{id:SubnetId,az:AvailabilityZone,cidr:CidrBlock}' \
  --output table

aws ec2 describe-nat-gateways \
  --nat-gateway-ids nat-NAT_ID \
  --query 'NatGateways[0].{state:State,public_ips:NatGatewayAddresses[].PublicIp}' \
  --output json
```

## 4. Prepare the public HTTPS name

The default Terraform CloudFront mode uses a generated `*.cloudfront.net`
hostname and needs no custom domain or ACM certificate. CloudFront's default
certificate terminates viewer
HTTPS, and AWS fixes the generated-hostname viewer policy at a TLSv1 minimum
while permitting negotiation of newer TLS. CloudFront connects to the ALB over
HTTP port 80. The origin is restricted to AWS's CloudFront origin-facing
managed prefix list and a Terraform-generated secret header. This is not
end-to-end TLS and must not be described as enforcing a TLS 1.2 viewer minimum.

The following custom-domain path is an alternative.

**APPROVAL REQUIRED — COST-BEARING:** Approve an existing domain and DNS
provider, or explicitly approve purchase of a non-refundable domain. Route 53
hosted zones and DNS queries are billable; domain registration is a separate
annual charge. See [Route 53 pricing](https://aws.amazon.com/route53/pricing/).

Choose an exact hostname, for example `recall.example.com`. Request a
non-exportable public ACM certificate for that hostname in the same region as
the ALB, select DNS validation, and publish the provided validation CNAME. ACM
certificates used directly by ALB have no additional certificate charge. See
[ACM regional requirements](https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html)
and [DNS validation](https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html).

Record the certificate ARN and hostname. The Terraform module creates the ALB
but deliberately does not create DNS records. After the ALB exists, publish an
alias/CNAME from the hostname to its DNS name. Safe certificate inspection:

```bash
aws acm describe-certificate \
  --certificate-arn arn:aws:acm:us-east-1:ACCOUNT:certificate/CERTIFICATE_ID \
  --query 'Certificate.{status:Status,names:SubjectAlternativeNames,in_use_by:InUseBy}' \
  --output json
```

For the custom-domain path only, do not enable the service until the certificate
status is `ISSUED` and the hostname resolves to the ALB.

## 5. Create the CockroachDB Cloud memory plane

**APPROVAL REQUIRED — COST-BEARING:** Create one CockroachDB Cloud **Basic**
cluster on AWS in the same region as ECS. Choose explicit finite RU and storage
limits—never unlimited. For this demo, keep both within the currently published
Basic allowance when the UI permits, and approve any overage separately.
Review current values immediately before creation in
[CockroachDB pricing](https://www.cockroachlabs.com/pricing/) and
[Basic cluster planning](https://www.cockroachlabs.com/docs/cockroachcloud/plan-your-cluster-basic).

Then:

1. Create a dedicated empty database named `fleet_recall`.
2. Add the NAT Elastic IP as a `/32` SQL authorized network. Do not retain a
   `0.0.0.0/0` rule. See
   [CockroachDB network authorization](https://www.cockroachlabs.com/docs/cockroachcloud/network-authorization).
3. Confirm vector indexes are enabled for the selected cloud version.
4. Confirm the cluster's managed backup state and retention in the Cloud
   console before loading data.

Record only non-secret metadata: organization, cluster ID/name, cloud region,
database name, approved RU/storage limits, and authorized NAT `/32`.

## 6. Create database identities and AWS secrets

**APPROVAL REQUIRED — COST-BEARING:** For the current AWS module, approve three
CockroachDB SQL users and three AWS Secrets Manager secrets. Secrets Manager
charges per secret and API use; use its AWS-managed encryption key unless a
separately approved customer KMS key is required. See
[Secrets Manager pricing](https://aws.amazon.com/secrets-manager/pricing/).

Create:

- `fleet_migrator`: DDL-capable for the one-off schema migration;
- `fleet_writer`: no admin membership; after policy application it receives
  membership only in the hardened `NOLOGIN` `fleet_runtime` logical role for
  the private seed/MCP DML grants documented in
  [MIGRATIONS.md](MIGRATIONS.md); and
- `fleet_publication`: the fixed public-application login, provisioned outside
  Terraform and kept in exact `NOLOGIN` state until its policy ceremony is
  complete.

CockroachDB Cloud UI-created SQL users initially receive `admin`. Revoke it
from `fleet_writer` and `fleet_publication` before use; immediately quiesce
`fleet_publication` with exact `NOLOGIN`. After migration, apply the reviewed
runtime policy
[`deploy/cockroach/runtime-role-grants.sql`](../deploy/cockroach/runtime-role-grants.sql)
to the `fleet_runtime` logical role: per-table private-writer verbs on the
legacy corpus, claim, conflict, receipt, and event tables, `USAGE` on only the
claim, claim-support, and conflict ID sequences, `SELECT` on
`_sqlx_migrations`, the Stage-4 evidence-plane append surface
(`SELECT`/`INSERT` on `memory_evidence_events`, `memory_evidence_quarantine`,
and `memory_content_objects`, and `SELECT`/`INSERT`/`UPDATE` on
`memory_evidence_shard_heads`, `memory_relation_projection_v1`, and
`memory_relation_projection_watermarks_v1`), and `SELECT` on the
migrator-owned view `memory_writer_authority_v1`
(see [MIGRATIONS.md](MIGRATIONS.md)); the policy itself
installs the sole `fleet_writer` membership edge. Never use `ON ALL TABLES`, and never grant the
writer, publication reader, or `public` role access to `memory_control_bootstraps`,
`memory_control_log_epochs`, `memory_control_shard_heads`, or
`memory_control_events`. Also grant no runtime, bootstrap, or genesis-activation
access to `memory_registry_transitions`,
`memory_registry_genesis_bridge_consumptions`, or
`memory_registry_current_heads_v2`: those migration-12-through-14 tables remain
unavailable to normal production application credentials. The successor
repository, workstation CLI, and cluster-admin-only one-shot logical-role
policy exist, but no successor login, AWS credential, task, image binary, or
runtime path exists. After the prefix reaches 14 and the two earlier frozen
private logical-role policies have run, apply the deny-only
[quarantine policy](../deploy/cockroach/successor-schema-quarantine-grants.sql);
it gates on all fourteen successful rows, revokes every existing application
role named by that policy, and grants nothing. Later migrations add no
successor tables, so they do not change the quarantine's table set. See
[CockroachDB access management](https://www.cockroachlabs.com/docs/cockroachcloud/managing-access).

The publication login never receives those writer grants directly. After the
complete successful prefix 1 through 17 (the policy's own gate; later
migrations remain compatible), a cluster admin applies
[`publication-reader-role-grants.sql`](../deploy/cockroach/publication-reader-role-grants.sql)
while `fleet_publication` is drained and exact `NOLOGIN`. The policy creates
and hardens the logical `fleet_publication_reader` role to `NOLOGIN`, then
grants only `CONNECT` on `fleet_recall`, `USAGE` on schema `public`, and
`SELECT` on exactly `_sqlx_migrations`, `memory_corpus_models`,
`memory_chunks`, `memory_claim_embeddings`, `memory_claim_support`,
`memory_claims`, `memory_conflict_members`, and `memory_conflicts`. It grants
no DML, DDL, sequence, system, private-table, ownership, grant-option, or
future-default authority.

Before that apply, audit direct grants, ownership, future defaults, role edges,
and inherited PUBLIC authority for both publication principals across every
database. Freeze role, grant, default, ownership, and schema-DDL changes,
repeat the audit if necessary, and reapply the policy immediately before the
separate exact authentication-enable operation. Quiesce/drain the login and
repeat that audit/reapply sequence after each migration or grant change.
Terraform does not provision CockroachDB identities, memberships, grants, or
authentication material.

For each user, obtain a URL-encoded raw connection URL for `fleet_recall` with
exactly one `sslmode=verify-full`. Do not copy a workstation-only
`sslrootcert=/Users/...` path into ECS. CockroachDB Basic's Let's Encrypt CA may
already be trusted by the image's system roots; use the General Connection
String guidance and verify it with this image. If verification fails, mount the
correct CA instead of weakening `sslmode`. See
[Connect to a Basic cluster](https://www.cockroachlabs.com/docs/cockroachcloud/connect-to-a-basic-cluster).

Create these Secrets Manager entries by pasting their raw URL as the entire
secret value in the AWS console:

- `ostk-fleet-recall/database/writer-url`
- `ostk-fleet-recall/database/migrator-url`
- `ostk-fleet-recall/database/publication-url`

Do not use a JSON wrapper. Record only their ARNs. Verify metadata—not values:

```bash
aws secretsmanager describe-secret \
  --secret-id ostk-fleet-recall/database/writer-url \
  --query '{arn:ARN,name:Name,kms:KmsKeyId}' --output json

aws secretsmanager describe-secret \
  --secret-id ostk-fleet-recall/database/migrator-url \
  --query '{arn:ARN,name:Name,kms:KmsKeyId}' --output json

aws secretsmanager describe-secret \
  --secret-id ostk-fleet-recall/database/publication-url \
  --query '{arn:ARN,name:Name,kms:KmsKeyId}' --output json
```

Never run `get-secret-value` during a recorded session.

Terraform accepts only these writer, migrator, and publication secret ARNs and
rejects missing, wildcard, or colliding references. The public application has
distinct publication execution and task roles, consumes only the publication
secret, and uses only its concrete publication-specific CMKs for conditional
decrypt. The publication CMK list must be disjoint from the writer/migrator
list. The module's Terraform tests cover these boundaries. The module has no
control-bootstrap, genesis-activation, successor, or conflict-reconciliation
secret input, IAM execution role, ECS task, startup hook, or public route. Do
not overload any deployed AWS secret with a private ceremony credential.

The successor repository and `ostk-registry-successor-activate` apply/inspect
CLI are workstation source surfaces only. The checked-in
[`fleet_registry_successor_activation` policy](../deploy/cockroach/successor-activation-role-grants.sql)
creates a hardened database-local `NOLOGIN` logical role, not a login or cloud
route. Before a separately approved local use, a cluster admin must freeze
authority changes, clean every forbidden non-target PUBLIC routine default
(including the reconciliation role's creator-scoped row when that optional role
exists), remove either-direction successor/reconciliation role edges, audit
every other database for direct role grants/ownership and inherited PUBLIC
authority, and reapply the policy.
Only then may one external login receive exclusive temporary membership; revoke
membership and disable the login afterward. There is no AWS credential/task,
production-image binary, startup hook, or runtime route; the migrator/schema
owner is not a ceremony credential.

Conflict reconciliation has an apply-only workstation CLI and a checked-in
database-local one-shot role policy. Only a cluster admin may apply it;
database ownership alone is insufficient. Apply it after its prefix-16 and
prior-role gates; successor remains optional. Before every apply/use, freeze
authority changes and clean every forbidden non-target PUBLIC routine default,
including successor's creator-scoped row when that optional role exists, plus
either-direction role edges. Then externally audit every other database for
direct reconciliation grants/ownership and inherited PUBLIC authority before
applying the policy. The local SQL file cannot perform that conditional cleanup
or cross-database audit. No Terraform, AWS, image, runtime, MCP, or HTTP wiring
exists.

If the separately reviewed Stage-2 ceremony is actually run, create a separate
private SQL principal with no admin membership and only the grants in
[CONTROL_BOOTSTRAP.md](CONTROL_BOOTSTRAP.md). Supply its dedicated URL to the
local operator process; disable the login or remove the secret afterward. If
the Stage-3 genesis-activation ceremony is run, create another distinct
principal with the exact activation grants in [MIGRATIONS.md](MIGRATIONS.md)
and retire it after use. That genesis repository keeps its prefix-1-through-9
compatibility gate as later migrations land; it has no successor-table
authority. The successor repository keeps its prefix-14 gate,
and reconciliation keeps prefix 16; neither one-shot logical role nor any
member is authorized by any of the three planned AWS credentials. All private
ceremonies remain local until a separate deployment increment adds and reviews
explicit cloud wiring. Their artifacts, pins, profiles, and URL rules are
summarized in [SECURITY.md](SECURITY.md).

## 7. Preserve and upload the pinned model

Copy the bundle out of temporary storage into the Git-ignored `.models/`
directory. Verify the regular-file release bundle and recompute its
application digest before upload:

```bash
cd /absolute/path/to/ostk-fleet-recall
MODEL_RELEASE=hf-6fc8051fab2a1e0ee76689cf08c853792ac285e7
MODEL_DIR="$PWD/.models/potion-retrieval-32M/$MODEL_RELEASE"
export MODEL_RELEASE MODEL_DIR

for name in config.json model.safetensors tokenizer.json; do
  test -f "$MODEL_DIR/$name"
  test ! -L "$MODEL_DIR/$name"
done
chmod -R go-rwx "$MODEL_DIR"

MODEL_DIGEST=$(docker run --rm \
  --user "$(id -u):$(id -g)" \
  --volume "$MODEL_DIR:/model:ro" \
  --entrypoint /usr/local/bin/ostk-fleet-recall \
  ostk-fleet-recall:localstack model-digest /model)
test "${#MODEL_DIGEST}" -eq 64
test "$MODEL_DIGEST" = 2b0a528493d642b36bbc193c74bf657cf8034e0e995f205cc04b315174e05fa1
export MODEL_DIGEST
```

The digest is deployment metadata, not a credential. Keep the source revision,
release ID, and digest together in release notes.

**APPROVAL REQUIRED — COST-BEARING:** Create a globally unique private S3
bucket in the approved region, enable versioning and Block Public Access, and
upload exactly the three files under an immutable prefix. S3 storage, requests,
and transfer can incur charges.

For `us-east-1`, after selecting a unique bucket name:

```bash
MODEL_BUCKET=UNIQUE-PRIVATE-BUCKET
export MODEL_BUCKET

aws s3api create-bucket --bucket "$MODEL_BUCKET" --region "$AWS_REGION"
aws s3api put-public-access-block --bucket "$MODEL_BUCKET" \
  --public-access-block-configuration \
  'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
aws s3api put-bucket-versioning --bucket "$MODEL_BUCKET" \
  --versioning-configuration Status=Enabled

for name in config.json model.safetensors tokenizer.json; do
  aws s3 cp "$MODEL_DIR/$name" \
    "s3://$MODEL_BUCKET/models/potion-retrieval-32M/$MODEL_RELEASE/$name" \
    --sse AES256 --only-show-errors
done

for name in config.json model.safetensors tokenizer.json; do
  aws s3api head-object --bucket "$MODEL_BUCKET" \
    --key "models/potion-retrieval-32M/$MODEL_RELEASE/$name" \
    --query '{bytes:ContentLength,version:VersionId,encryption:ServerSideEncryption}' \
    --output json
done
```

Do not grant public access. Terraform grants the ECS task role read access to
only those three object ARNs.

## 8. Hand off to the deployment runbook

**APPROVAL REQUIRED — COST-BEARING:** Approve the Terraform plan before every
apply. The module creates an ECR repository, ALB, ECS/Fargate definitions,
CloudWatch log group, IAM roles, security groups, and autoscaling resources;
Container Insights is optional. The dormant service still leaves the ALB and
other resources billable. ALB is billed hourly/LCU and running Fargate tasks
are billed by requested CPU, memory, and storage; see
[ALB pricing](https://aws.amazon.com/elasticloadbalancing/pricing/) and
[Fargate pricing](https://aws.amazon.com/fargate/pricing/).

Continue with [the AWS deployment runbook](../deploy/aws/README.md), using:

- the approved region, VPC ID, and four subnet IDs;
- `assign_public_ip = false`;
- all three database secret ARNs, never their values;
- `arn:aws:s3:::${MODEL_BUCKET}` and
  `models/potion-retrieval-32M/${MODEL_RELEASE}`;
- `MODEL_DIGEST` as `embedding_model_sha256`;
- a generated tenant UUID and the trusted project/agent names;
- an immutable commit-derived ECR image tag; and
- exactly one public HTTPS mode: `enable_cloudfront = true` with no certificate
  ARN for the generated hostname, or a covered ACM certificate ARN plus exact
  custom demo hostname.

Keep the safe defaults from `terraform.tfvars.example`:

```hcl
log_retention_days         = 60
enable_deletion_protection = true
```

Keep `service_desired_count = 0` and `autoscaling_min_capacity = 0` through the
first apply. Run exactly one migration task, grant only the private writer,
then apply/audit the publication policy while `fleet_publication` remains
quiesced. Under a dependency freeze, repeat the external audit and reapply the
policy immediately before enabling that exact login. Run the one-off
idempotent seed task with the writer secret, then approve scaling the public
service, which receives only the publication secret, to one.
The migration task must finish the complete uninterrupted prefix of embedded
migrations; see [MIGRATIONS.md](MIGRATIONS.md) for the per-version transaction
policy and recovery rules. Do not substitute manual SQL or a Docker-only smoke
for that step. Validate HTTPS and recall, force a task replacement, and check
recall again. To confirm production query plans, capture representative
`EXPLAIN` output against a disposable fixture database; capability flags and
RRF observations are not a physical-plan substitute.

## 9. Teardown

**APPROVAL REQUIRED — DESTRUCTIVE AND COST-BEARING:** Teardown deletes or
disconnects resources and can destroy data. Preserve anything you still need
and obtain explicit approval for every external deletion.

1. Set ECS desired/minimum capacity to zero and apply; verify no tasks remain.
2. Preserve required logs and any cloud plans you want to keep.
3. Set `enable_deletion_protection = false`, review and apply that deliberate
   change, and verify that ALB protection is disabled. Only then run and review
   a separate `terraform plan -destroy` before approving `terraform destroy`.
   The ECR repository may need its immutable images deleted first.
4. Separately review resources Terraform does not own: NAT Gateway and Elastic
   IP, S3 objects/versions and bucket, the three database Secrets Manager secrets
   used by Terraform, DNS and domain registration, ACM certificate,
   VPC/subnets, and CockroachDB Cloud. Separately inventory any out-of-band
   private-ceremony secret; it is not owned by this module.
5. Delete or retain each external resource deliberately. NAT, ALB, Fargate,
   public IPv4, Secrets Manager, CloudWatch, S3/ECR, DNS, and CockroachDB can
   continue accruing charges until their resources are actually removed.
6. Check AWS Billing/Cost Explorer and CockroachDB Cloud billing after teardown.
   A stopped ECS service alone does not stop ALB, NAT, storage, secret, DNS, or
   database charges.

Do not delete the CockroachDB database, S3 versions, secrets, Terraform state,
or registered domain merely to reduce cost without a separate destructive
approval and a verified backup plan.
