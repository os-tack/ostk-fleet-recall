# Local AWS runtime/publication-boundary harness

This harness runs the real production Fleet Recall image against a disposable
CockroachDB 26.2.3 node while LocalStack emulates the S3 and Secrets Manager
APIs. It is a local bring-up of the deployment topology, not a substitute for
an AWS deployment or real IAM authorization.

## How the stack is wired

The harness separates five database capabilities before starting either
long-lived process:

1. `database-bootstrap` creates `fleet_recall` and enables only the temporary
   `fleet_migrator` principal.
2. `migrate` fetches only the migrator raw-URL secret and applies every
   embedded migration.
3. `database-boundary` retires the migrator and provisions both fixed external
   principals, `fleet_writer` and `fleet_publication`, in quiesced `NOLOGIN`
   state.
4. The boundary applies the runtime and publication policies from
   `deploy/cockroach`, removes creator-scoped PUBLIC routine defaults for both
   logical roles and both principals in every mutable database, and only then
   enables the two external principals.
5. Ingestion and MCP work use the private writer container. The externally
   reachable app starts last with only the publication database capability.

Retirement does not reassign schema ownership. `fleet_migrator` remains the
owner of `_sqlx_migrations` and the objects created by migrations, but its
options are exactly `NOLOGIN`; its temporary `admin` membership, every role
edge, and all system privileges are removed.

Both policies are mounted read-only from `deploy/cockroach` and fail closed on
their own preconditions. The runtime policy
([`runtime-role-grants.sql`](../cockroach/runtime-role-grants.sql)) grants the
`NOLOGIN` logical role `fleet_runtime` the writer's database, schema, table, and
sequence privileges; `fleet_writer` has no direct grants and inherits them
through a single edge from that role. The publication policy
([`publication-reader-role-grants.sql`](../cockroach/publication-reader-role-grants.sql))
grants the `NOLOGIN` logical role `fleet_publication_reader` database
`CONNECT`, public-schema `USAGE`, and `SELECT` on the public read tables;
`fleet_publication` is its only member. Neither policy grants access to the
control, activation, or successor tables, and the policy files are the
authoritative grant lists.

The harness runs no webhook receiver. `ingress-boundary.sh`, beside the
boundary helper, provisions its `fleet_ingress` login the same way on the
README quickstart's local node: quiesced, under
[`ingress-receiver-role-grants.sql`](../cockroach/ingress-receiver-role-grants.sql),
with the PUBLIC-default cleanup, and enabled last (see the README's
[receiving provider webhooks](../../README.md#receiving-provider-webhooks)).

## Image and secret boundary

Two images are intentionally built from one source commit:

- `ostk-fleet-recall:localstack-production` is the exact Dockerfile
  `production` target. It runs as UID/GID 10001, contains the normal S3 client,
  contains no AWS CLI, and is the only image exposed on the demo port.
- `ostk-fleet-recall:localstack-private` is the AWS-CLI-bearing `localstack`
  target. Only one-shot secret resolution, migration, ingestion, and the
  unexposed writer use it.

LocalStack holds three distinct raw URL secrets for `fleet_migrator`,
`fleet_writer`, and `fleet_publication`. A one-shot helper resolves only the
publication secret into a mode-0400, UID-10001 file on a named volume. The
production app's harness wrapper rejects every private database URL/secret ID,
reads that fixed handoff, exports only
`FLEET_RECALL_PUBLICATION_DATABASE_URL`, and launches only `demo`.
`PublicationConfig` repeats the private-variable and canonical identity checks
inside the Rust process.

The production app does receive LocalStack's test AWS credentials and endpoint
so its baked S3 client can download the three-file model bundle. That is
expected and is not database-secret leakage. This emulator does not exercise
real AWS IAM enforcement.

This local database is deliberately insecure: the three URL credential fields
exercise application-side secret separation, but CockroachDB does not store or
authenticate them. The application escape hatch is accepted only for
loopback/Compose `cockroach` hosts with explicit `sslmode=disable`.

## Requirements

- Docker Engine with Compose v2.
- `curl`, `git`, and `jq` on the host.
- A LocalStack Auth Token supplied as `LOCALSTACK_AUTH_TOKEN` or the legacy
  `LOCAL_STACK_API_KEY`, either in the process environment or the ignored
  repository-root `.env`.
- An absolute path to a model2vec bundle containing regular, non-symlink
  `config.json`, `model.safetensors`, and `tokenizer.json` files.

The harness pins LocalStack `2026.07.0` and CockroachDB `v26.2.3`. It does not
silently skip unavailable paid control-plane features; ECR/ECS/ELB and IAM
enforcement are outside this baseline rather than simulated as successes.

## Run

```bash
export LOCALSTACK_AUTH_TOKEN='...'
export FLEET_RECALL_MODEL_BUNDLE=/absolute/path/to/potion-retrieval-32M
./deploy/localstack/smoke.sh
```

`smoke.sh` builds both images, computes the model digest, brings the stack up,
checks the public demo's health, status, and recall, runs the three-agent fleet
scenario in the private writer, confirms the public demo recalls its claim, and
then tears the stack down.

Token precedence is exported `LOCALSTACK_AUTH_TOKEN`, exported
`LOCAL_STACK_API_KEY`, root `.env` `LOCALSTACK_AUTH_TOKEN`, then root `.env`
`LOCAL_STACK_API_KEY`. The script recognizes exact assignments only, never
sources/evaluates `.env`, disables inherited shell tracing before secret
resolution, prevents Compose from loading `.env`, and never prints raw URLs or
the LocalStack token.

To keep the stack running for inspection:

```bash
KEEP_LOCALSTACK=1 ./deploy/localstack/smoke.sh
./deploy/localstack/fleet-demo.sh
docker compose --env-file /dev/null -f deploy/localstack/compose.yaml logs -f app writer
FLEET_RECALL_VCS_REF="$(git rev-parse HEAD)" \
FLEET_RECALL_EMBEDDING_MODEL_SHA256=cleanup-only \
  docker compose --env-file /dev/null -f deploy/localstack/compose.yaml \
  down --volumes --remove-orphans
```

`fleet-demo.sh` discovers only the unexposed `writer` container. It never
executes mutation-capable commands in the public app.

Defaults:

| Endpoint | Address |
|---|---|
| Fleet Recall demo | <http://127.0.0.1:8088> |
| LocalStack gateway | <http://127.0.0.1:4566> |
| CockroachDB SQL | `postgresql://root@127.0.0.1:26257/fleet_recall?sslmode=disable` |
| CockroachDB console | <http://127.0.0.1:8081> |

Set `FLEET_RECALL_DEMO_PORT`, `LOCALSTACK_PORT`, `COCKROACH_SQL_PORT`, or
`COCKROACH_HTTP_PORT` to avoid local port conflicts.

## Real AWS staging gate

Before publishing a live URL, follow `deploy/aws/README.md` and separately
verify immutable commit-tagged ECR publication, dormant infrastructure before
migration, one dedicated migration task, publication-only service secret/task
role, S3 digest verification, CloudWatch delivery, ALB TLS and target health,
task replacement, real IAM access, and CockroachDB Cloud network/identity
behavior. No command in this directory authorizes an AWS plan or apply.

Official LocalStack references previously reviewed for this harness:

- <https://docs.localstack.cloud/aws/getting-started/installation/>
- <https://docs.localstack.cloud/aws/licensing/>
- <https://docs.localstack.cloud/aws/services/ecs/>
- <https://docs.localstack.cloud/aws/connecting/infrastructure-as-code/terraform/>
