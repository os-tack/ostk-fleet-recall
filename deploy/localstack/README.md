# Local AWS contract test

This harness runs the real Fleet Recall image against a disposable CockroachDB
26.2 node and emulates the AWS interfaces the container consumes. It is a
preflight tool, not evidence that an AWS deployment occurred.

## What it proves

- The production Dockerfile builds and runs as UID/GID 10001.
- `FLEET_RECALL_DATABASE_URL` can be retrieved from an AWS Secrets Manager API
  contract without printing the value.
- The exact three-file model bundle can be delivered through S3 and passes the
  application's domain-separated digest before model loading.
- The recorded then-current embedded schema migration completed once on
  CockroachDB 26.2.
- Synthetic NDJSON ingestion works with the pinned model.
- Three deployment-bound MCP agent identities exercise record/replay, hybrid
  recall, a persisted claim-linked execution plan, scope rejection, conflict
  projection, and a persisted escalation against one shared CockroachDB
  project.
- The real `demo --listen 0.0.0.0:8080` process becomes ready and returns at
  least one hybrid recall hit through its bounded HTTP API.
- Replacing only that stateless demo container preserves the same recall hit in
  the unchanged CockroachDB node.

The Compose harness runs the application container directly. It intentionally
does **not** claim to emulate Fargate scheduling, ALB TLS/health registration,
ECR push/pull, AWS IAM enforcement, multi-AZ networking, ECS Secrets Manager
injection, or CloudWatch delivery. Those remain real-AWS staging gates.

The current checkout now embeds migrations 1 through 14. Versions 1 through 11
are nontransactional, with resumable exact-catalog assertions in v10 and v11;
v12 through v14 are transactional on a dedicated session with
`autocommit_before_ddl = false`. Fresh, populated-upgrade, interruption,
catalog-drift, and rollback correctness passed against the official
CockroachDB v26.2.3 binary. The recorded Docker/Compose smoke below predates
migrations 10 through 14 and has not been rerun for those bytes, so it is not
current Docker-image parity evidence. The harness also provides no successor
repository, RBAC, or CLI proof; the three successor tables remain
migrator/schema-owner only. Full quarantine allow/deny/grant-option checks
belong to the separate Docker RBAC scripts, not this application-image harness
or the official-binary migration lane.

On 2026-08-13 the combined then-current-source smoke (through migration 9)
passed with the production Rust 1.94 image. One run verified the S3 and Secrets
Manager contracts, migration, model delivery, ingestion, the full
three-identity memory/action/conflict flow, forced application-container
replacement, and recall from the unchanged CockroachDB 26.2.3 node afterward.
This is historical local emulator/application evidence, not proof of current
container parity, Fargate, IAM, ALB, or CockroachDB Cloud behavior.

## Requirements

- Docker Engine with Compose v2.
- AWS CLI v2, `curl`, and `jq` on the host.
- A LocalStack Auth Token supplied as `LOCALSTACK_AUTH_TOKEN` or the legacy
  `LOCAL_STACK_API_KEY` name, either in the process environment or the
  repository-root `.env`.
- An absolute path to a model2vec bundle containing regular, non-symlink
  `config.json`, `model.safetensors`, and `tokenizer.json` files.

The harness pins LocalStack `2026.07.0` and CockroachDB `v26.2.3`. Current
LocalStack documentation requires an Auth Token for the LocalStack for AWS
image. S3 and Secrets Manager are available on Hobby and higher plans.
ECR, ECS, and ELBv2 start at Base; IAM policy enforcement also starts at Base.
This base harness therefore tests S3/Secrets Manager on the smallest tier and
does not silently skip paid control-plane assertions.

The disposable Cockroach node is deliberately insecure and addressed by the
Compose-only hostname `cockroach`. The harness explicitly sets
`FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1`; application configuration
rejects that escape hatch for non-local hosts. The AWS runbook never sets it
and requires `sslmode=verify-full`.

Official LocalStack references reviewed on 2026-08-13:

- <https://docs.localstack.cloud/aws/getting-started/installation/>
- <https://docs.localstack.cloud/aws/licensing/>
- <https://docs.localstack.cloud/aws/services/ecs/>
- <https://docs.localstack.cloud/aws/connecting/infrastructure-as-code/terraform/>

## Run

```bash
export LOCALSTACK_AUTH_TOKEN='...'
export FLEET_RECALL_MODEL_BUNDLE=/absolute/path/to/potion-retrieval-32M
./deploy/localstack/smoke.sh
```

Token precedence is exported `LOCALSTACK_AUTH_TOKEN`, exported
`LOCAL_STACK_API_KEY`, root `.env` `LOCALSTACK_AUTH_TOKEN`, then root `.env`
`LOCAL_STACK_API_KEY`. The script recognizes only exact assignments (optionally
prefixed by `export`) and strips one matching pair of single or double quotes.
It does not source or evaluate `.env`, does not print the token, disables shell
tracing before assigning it, and prevents Compose from loading `.env`
independently. Keep `.env` untracked and never put the token in command-line
arguments.

`smoke.sh` builds the image, computes the bundle digest inside that image,
starts LocalStack/CockroachDB, creates the S3 objects and secret, runs migration
and ingestion as one-shot containers, starts the demo, and checks the AWS,
HTTP, and three-identity MCP contracts. Identity B records a rollout plan after
recalling identity A's decision, then pauses and escalates after detecting
identity C's incompatible claim. The harness then force-recreates only the demo
container, waits for its replacement to become healthy, and repeats recall of
the exact durable Agent A claim against the unchanged Cockroach node. It tears
the environment down on success or failure.

To inspect the running environment after the smoke gate:

```bash
KEEP_LOCALSTACK=1 ./deploy/localstack/smoke.sh
./deploy/localstack/fleet-demo.sh
docker compose --env-file /dev/null -f deploy/localstack/compose.yaml logs -f app
docker compose --env-file /dev/null -f deploy/localstack/compose.yaml down --volumes
```

Defaults:

| Endpoint | Address |
|---|---|
| Fleet Recall demo | <http://127.0.0.1:8088> |
| LocalStack gateway | <http://127.0.0.1:4566> |
| CockroachDB SQL | `postgresql://root@127.0.0.1:26257/defaultdb?sslmode=disable` |
| CockroachDB console | <http://127.0.0.1:8081> |

Set `FLEET_RECALL_DEMO_PORT`, `LOCALSTACK_PORT`,
`COCKROACH_SQL_PORT`, or `COCKROACH_HTTP_PORT` to avoid local port conflicts.

## Optional Base-plan control-plane work

LocalStack's official ECS documentation says local Fargate tasks execute as
Docker containers and can be placed on the LocalStack Docker network. Its
official ECR/ECS/Fargate tutorial also exercises ECR, ECS, VPC, and load
balancing. Those APIs are Base-tier features as of this review.

If a Base-or-higher token is available, add a separate, explicit control-plane
test that pushes `ostk-fleet-recall:localstack` into LocalStack ECR and registers
an ECS task/service. Do not mix it into the baseline smoke gate: ECS/ELB local
networking differs materially from AWS `awsvpc`, and a passing emulator run
does not establish TLS certificate, NAT allowlist, multi-AZ, secret injection,
or Fargate platform behavior.

## Real AWS staging gate

Before publishing the Devpost URL, follow `deploy/aws/README.md` and verify all
of the following in AWS:

1. push the commit-tagged image into immutable ECR;
2. apply dormant ECS/ALB infrastructure with zero service tasks;
3. run exactly one migration task with the DDL secret;
4. start the runtime service with the least-privilege secret;
5. confirm S3 download, digest verification, CloudWatch logs, ALB target health,
   HTTPS hostname/certificate validation, and bounded recall;
6. replace an ECS task and prove the same CockroachDB memory remains;
7. inspect real IAM role access and CockroachDB Cloud connection/allowlist
   behavior.

This checklist is not authorization to take AWS action against the recorded
live candidate. Any new image, migration, grant, plan, or apply requires its
own operator approval and must preserve the historical evidence boundary.
