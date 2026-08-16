# Cloud onboarding for the hackathon demo

This is the human-approved path from the validated LocalStack deployment to a
real AWS and CockroachDB Cloud demo. It does not automate account creation,
billing choices, DNS ownership, or database credentials. Do not place database
URLs, passwords, AWS access keys, or secret values in this repository,
Terraform variables, command-line arguments, screenshots, or shell history.

Recorded revision-10 release state: the onboarding path was completed for the
live submission candidate at
<https://d13zrqfh66r7ub.cloudfront.net>. Immutable image `git-56b577c82b9c`
at source commit `56b577c82b9c5a5c80d73103f7f6b56d51698872` runs with all
four task-definition families at revision 10; the service is 1/1 healthy. The
idempotent rich-seed task exited zero and upserted exactly 552 rows: 346 documentation
chunks, 2 code chunks, and 204 operations chunks. The public API returned the
exact release revision and source-line ranges for repository-backed hits.
Final desktop and 390px mobile QA verified safe inline Markdown, immutable exact
`#Lx-Ly` links, a relative repository link rendered as a code-styled anchor,
and no horizontal overflow. The final seven-query smoke gate passed.
The ECR Basic OS-package scan is `COMPLETE` with an empty finding-severity
count; this does not claim
language or application-dependency coverage. GitHub Actions run
[`31832684235`](https://github.com/os-tack/ostk-fleet-recall/actions/runs/31832684235)
completed all five jobs successfully. The checked-in seven-query public
relevance receipt remains historical revision-7 evidence. The self-audit,
reference-agent, replacement, and validation artifacts remain historical
revision-6 evidence; the Cloud `EXPLAIN` is separately captured historical plan
evidence. None was rerun for revision 10.

The current checkout is newer than that recorded deployment. Its embedded
migrator now contains versions 1 through 17, including private control-ledger,
genesis-activation and successor-schema projections, detector-versioned
conflict uniqueness, and exact reconciliation/current-projection indexes.
Current source release completion requires exactly the seventeen successful
rows 1 through 17. Serving requires an uninterrupted successful prefix of at
least 17 and remains compatible with later additive migrations. The private
compatibility gates remain control 3, genesis 9, successor repository 14, and
conflict reconciliation 16. Do not
reinterpret the live revision-10 schema-2 status or 552-row seed as evidence
that the later migrations, roles, or private ceremonies were deployed. This
source and runbook update is not approval to rerun migration, change
CockroachDB grants, or take any AWS action against the recorded live candidate.

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

# Terraform is currently cached here even though it is not on PATH.
export PATH="/private/tmp/terraform-1.15.8:$PATH"
terraform version

# This must succeed after AWS SSO onboarding. It prints identity metadata only.
AWS_PROFILE=ostk-hackathon
AWS_REGION=us-east-1
export AWS_PROFILE AWS_REGION
aws sts get-caller-identity --query Arn --output text
```

Deployment-workstation notes:

- AWS CLI, Docker, Buildx, `jq`, and the cached Terraform binary were used for
  the live deployment. AWS SSO sessions are temporary; authenticate again
  before any follow-up operation.
- `deploy/aws/run-migration.sh` and the other wrappers require `terraform` to
  be on `PATH`.
- The migration, runtime grants, and publication-safe Cloud `EXPLAIN` capture
  were completed. The plan fixture used a separate logical database; production
  data was untouched, the fixture database was dropped, and the temporary
  workstation network rule was removed.
- The tested bundle is preserved as regular files under the ignored
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
and assign it to this account. For the short hackathon deployment, approve
either a time-limited administrator permission set or a reviewed custom set
covering the resources in `deploy/aws`. The Terraform deployer must be able to
manage IAM roles and policies, ECR, ECS/Fargate, EC2 security groups, ALB,
Application Auto Scaling, and CloudWatch; ordinary `PowerUserAccess` alone does
not grant all required IAM administration.

Configure temporary SSO credentials rather than static access keys:

```bash
aws configure sso --profile ostk-hackathon
aws sso login --profile ostk-hackathon

AWS_PROFILE=ostk-hackathon
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

Recommended hackathon network:

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
shortcut for the public submission. AWS documents the trade-off in
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

The live submission candidate uses the Terraform CloudFront mode and generated
hostname <https://d13zrqfh66r7ub.cloudfront.net>; it did not require a custom
domain or ACM certificate. CloudFront's default certificate terminates viewer
HTTPS, and AWS fixes the generated-hostname viewer policy at a TLSv1 minimum
while permitting negotiation of newer TLS. CloudFront connects to the ALB over
HTTP port 80. The origin is restricted to AWS's CloudFront origin-facing
managed prefix list and a Terraform-generated secret header. This is not
end-to-end TLS and must not be described as enforcing a TLS 1.2 viewer minimum.

The following custom-domain path remains available as an alternative, but it
was not used for this deployment.

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

**APPROVAL REQUIRED — COST-BEARING:** For the current AWS module, approve two
CockroachDB SQL users and two AWS Secrets Manager secrets. Secrets Manager
charges per secret and API use; use its AWS-managed encryption key unless a
separately approved customer KMS key is required. See
[Secrets Manager pricing](https://aws.amazon.com/secrets-manager/pricing/).

Create:

- `fleet_migrator`: DDL-capable for the one-off schema migration;
- `fleet_runtime`: no admin membership and only the runtime grants documented
  in [MIGRATIONS.md](MIGRATIONS.md).

CockroachDB Cloud UI-created SQL users initially receive `admin`. Revoke it
from `fleet_runtime` before use. After migration, grant runtime DML only on
`memory_corpus_models`, `memory_chunks`,
`memory_chunk_history`, `memory_claims`, `memory_claim_support`,
`memory_claim_embeddings`, `memory_claim_events`, `memory_conflicts`,
`memory_conflict_members`, `memory_claim_links`, `memory_claim_link_events`,
`memory_mutation_receipts`, `memory_events`, and `memory_attention`; grant only
the four legacy sequences and `_sqlx_migrations` access listed in
[MIGRATIONS.md](MIGRATIONS.md). Never use `ON ALL TABLES`, and never grant the
runtime or `public` role access to `memory_control_bootstraps`,
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
role named by that policy, and grants nothing. Migrations 15 through 17 add or
replace indexes and do not change the quarantine's table set. See
[CockroachDB access management](https://www.cockroachlabs.com/docs/cockroachcloud/managing-access).

For each user, obtain a URL-encoded raw connection URL for `fleet_recall` with
exactly one `sslmode=verify-full`. Do not copy a workstation-only
`sslrootcert=/Users/...` path into ECS. CockroachDB Basic's Let's Encrypt CA may
already be trusted by the image's system roots; use the General Connection
String guidance and verify it with this image. If verification fails, mount the
correct CA instead of weakening `sslmode`. See
[Connect to a Basic cluster](https://www.cockroachlabs.com/docs/cockroachcloud/connect-to-a-basic-cluster).

Create these Secrets Manager entries by pasting their raw URL as the entire
secret value in the AWS console:

- `ostk-fleet-recall/database/runtime-url`
- `ostk-fleet-recall/database/migrator-url`

Do not use a JSON wrapper. Record only their ARNs. Verify metadata—not values:

```bash
aws secretsmanager describe-secret \
  --secret-id ostk-fleet-recall/database/runtime-url \
  --query '{arn:ARN,name:Name,kms:KmsKeyId}' --output json

aws secretsmanager describe-secret \
  --secret-id ostk-fleet-recall/database/migrator-url \
  --query '{arn:ARN,name:Name,kms:KmsKeyId}' --output json
```

Never run `get-secret-value` during a recorded session.

Terraform accepts only these runtime and migrator secret ARNs. It has no
control-bootstrap, genesis-activation, successor, or conflict-reconciliation
secret input, IAM execution role, ECS task, startup hook, or public route. Do
not overload either AWS secret with a private ceremony credential.

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

If the separately reviewed Stage-2 ceremony is actually run, create a third,
private SQL principal with no admin membership and only the grants in
[CONTROL_BOOTSTRAP.md](CONTROL_BOOTSTRAP.md). Supply its dedicated URL to the
local operator process; disable the login or remove the secret afterward. If
the Stage-3 genesis-activation ceremony is run, create a fourth, distinct
principal with the exact activation grants in [MIGRATIONS.md](MIGRATIONS.md)
and retire it after use. That genesis repository keeps its prefix-1-through-9
compatibility gate even when the current release prefix reaches 17; it has no
successor-table authority. The successor repository keeps its prefix-14 gate,
and reconciliation keeps prefix 16; neither one-shot logical role nor any
member is authorized by either AWS credential. All private ceremonies remain
local until a separate deployment increment adds and reviews explicit cloud
wiring. Their artifacts, pins, profiles, and URL rules are summarized in
[SECURITY.md](SECURITY.md).

## 7. Preserve and upload the pinned model

The tested bundle has already been copied out of temporary storage into the
Git-ignored `.models/` directory. Verify the regular-file release bundle and
recompute its application digest before upload:

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
- both database secret ARNs, never their values;
- `arn:aws:s3:::${MODEL_BUCKET}` and
  `models/potion-retrieval-32M/${MODEL_RELEASE}`;
- `MODEL_DIGEST` as `embedding_model_sha256`;
- a generated tenant UUID and the trusted project/agent names;
- an immutable commit-derived ECR image tag; and
- exactly one public HTTPS mode: `enable_cloudfront = true` with no certificate
  ARN for the generated hostname (the selected live mode), or a covered ACM
  certificate ARN plus exact custom demo hostname.

Retain the safe judging defaults from `terraform.tfvars.example`:

```hcl
log_retention_days         = 60
enable_deletion_protection = true
```

Keep `service_desired_count = 0` and `autoscaling_min_capacity = 0` through the
first apply. Run exactly one migration task, grant the runtime user, run the
one-off idempotent seed task, then approve scaling the public service to one.
For a separately approved deployment of the current checkout, that migration
task must finish exactly the uninterrupted prefix 1 through 17: versions 1
through 11 use the nontransactional policy (with resumable exact-catalog
assertions in v10/v11), v12 through v14 use the dedicated transactional
session, and v15 through v17 return to resumable nontransactional online DDL.
Serving remains compatible with a later additive successful prefix, but the
current release artifact contains exactly 1–17. Do not substitute manual SQL or
a Docker-only smoke for that release gate.
Validate HTTPS and recall, force a task replacement, and prove recall again.
Capture representative Cloud `EXPLAIN` separately with the approved bounded
method before final submission; capability flags and RRF observations are not
a physical-plan substitute. The completed capture is documented in
[`docs/evidence/cockroach-cloud-explain.txt`](evidence/cockroach-cloud-explain.txt).
Only after the public demo is running and healthy should you run the standalone
deterministic reference policy fleet:

```bash
RUN_ID=devpost-cloud-YYYYMMDDTHHMMSSZ
mkdir -p target/aws-evidence
./deploy/aws/run-reference-agent.sh "$RUN_ID" \
  >"target/aws-evidence/reference-agent-$RUN_ID.json"
jq -e '.schema == "fleet-reference-agent-run-v1" and .verified == true' \
  "target/aws-evidence/reference-agent-$RUN_ID.json"
```

For the current revision-10 deployment, immutable image `git-56b577c82b9c` at
source commit `56b577c82b9c5a5c80d73103f7f6b56d51698872` runs with the
serving, migration, seed, and reference-agent task-definition families all at
revision 10; the service is 1/1 healthy. The idempotent rich-seed task exited zero and
upserted exactly 552 rows: 346 documentation chunks, 2 code chunks, and 204
operations chunks. Current public API results carry the exact release revision
and source-line ranges. Final desktop and 390px mobile QA verified safe inline
Markdown, immutable exact `#Lx-Ly` links, a relative repository link rendered
as a code-styled anchor, and no horizontal overflow. The final seven-query
smoke gate passed. The ECR Basic OS-package scan completed with an empty
finding-severity count,
and GitHub Actions run
[`31832684235`](https://github.com/os-tack/ostk-fleet-recall/actions/runs/31832684235)
completed all five jobs successfully.
The checked-in
[seven-query public relevance receipt](evidence/public-relevance-efe6fbf-20260814.json)
is historical revision-7 evidence for the prior 548-row release, not the
revision-10 smoke receipt.

The checked-in artifacts that follow are historical revision-6 cloud evidence;
the reference-agent and replacement proofs were not rerun for revision 10. The
[source-conflict self-audit](evidence/self-audit-devpost-self-audit-20260814T133640Z-rev6.json)
verified documentation-backed claim 9, code-backed claim 10, and their exact
open conflict 3 through semantic recall. Historical revision-6 run
`devpost-final6-20260814T143523Z` then produced the checked-in
[reference-agent](evidence/reference-agent-devpost-final6-20260814T143523Z.json),
[replacement](evidence/replacement-devpost-final6-20260814T143523Z.json), and
[publication-validation](evidence/publication-validation-devpost-final6-20260814T143523Z.json)
receipts. Reference-agent task definition revision 6 correlated
decision/action/incompatible/escalation claims 15/16/17/18 with open conflict
5. Public lexical/dense RRF observed exact action and escalation claims 16 and
18. Serving task definition revision 6 then changed the complete task set to a
fully disjoint set and observed those same exact claims afterward.

The separately captured historical Cloud `EXPLAIN` proof exercised the exact
production project-vector, source-vector, and lexical SQL shapes on a
10,001-row disposable fixture. It selected `memory_chunks_semantic_idx`,
`memory_chunks_source_semantic_idx`, and `memory_chunks_lexical_idx`; all
assertions passed. Production was untouched, the fixture database was dropped,
and the temporary workstation network rule was removed. It was not rerun on
revision 10. The first lexical plan ran immediately after `ANALYZE` and briefly
saw stale statistics; the unchanged
query selected the inverted index once fresh statistics became visible roughly
two minutes later. No `FORCE_INDEX` hint was used or implied.

The wrapper requires `aws`, `curl`, `jq`, and `terraform`. It derives the real
Terraform `demo_url`, fails unless `/healthz` succeeds, then starts four one-off
Fargate tasks in sequence: Agent A records and idempotently replays the
migration decision; Agent B finds it through lexical+dense RRF, verifies it by
exact get, persists a cited action, and rereads that action; Agent C records an
incompatible decision and proves the exact disputed A/C members and values;
then the same deployment-bound B identity recalls the open conflict, persists a
cited escalation, and rereads it. It validates each task override, exit, and
structured CloudWatch receipt, then uses the public read-only recall API to
require the exact action and escalation claim IDs. It emits a final JSON object
only when the AWS tasks, CockroachDB memory chain, and public demo all
correlate. This is the default AWS agent proof and invokes neither OSTK nor an
LLM. A local run or Terraform test is not a substitute for the completed live
Fargate/CockroachDB Cloud capture.

The receipt includes four per-step task/log coordinates and a `public_demo`
section with the ready state, exact observed action/escalation claim IDs, and
lexical+dense RRF diagnostics. Protect the raw JSON artifact, local Terraform
state, and `terraform.tfvars`; all are ignored but remain operationally
sensitive. Redact AWS account/infrastructure identifiers before screenshots or
publication. The final video should lead with the live AWS UI and show reviewed,
redacted cloud agent and replacement receipts. A fresh standalone Fleet Recall
capture is optional local terminal footage; an OSTK render is an explicitly
optional alternate. Neither is cloud proof.

## Judging availability hold, then teardown

The [official rules](https://cockroachdb-ai.devpost.com/rules) require the
working project to remain available free of charge and without restriction
until the judging period ends. Once the URL is submitted, keep the public ECS
service, CockroachDB Cloud data plane, S3 model objects, runtime secrets,
networking, DNS/TLS, and required logs operational through **September 15, 2026
at 5:00 PM EDT / 4:00 PM CDT**. Monitor and repair the deployment during that
hold; do not scale it to zero, revoke judging access, destroy it, or begin the
steps below before the deadline. Keep ALB deletion protection enabled and the
60-day CloudWatch log retention intact for the entire judging window.

**APPROVAL REQUIRED — DESTRUCTIVE AND COST-BEARING:** Teardown deletes or
disconnects resources and can destroy evidence or data. Preserve submission
evidence, wait until the judging hold has expired, and obtain explicit approval
for every external deletion.

1. Set ECS desired/minimum capacity to zero and apply; verify no tasks remain.
2. Preserve required logs, screenshots, cloud plans, and the final demo URL.
3. Set `enable_deletion_protection = false`, review and apply that deliberate
   change, and verify that ALB protection is disabled. Only then run and review
   a separate `terraform plan -destroy` before approving `terraform destroy`.
   The ECR repository may need its immutable images deleted first.
4. Separately review resources Terraform does not own: NAT Gateway and Elastic
   IP, S3 objects/versions and bucket, the two database Secrets Manager secrets
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
approval and a verified backup/evidence plan.
