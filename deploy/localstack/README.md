# Local AWS publication-boundary test

This harness runs the real production Fleet Recall image against a disposable
CockroachDB 26.2.3 node while LocalStack emulates the S3 and Secrets Manager
APIs. It is a source-bound application/database preflight, not evidence that an
AWS deployment or IAM authorization occurred.

## PUBLIC-03 invariant

The harness separates four database capabilities before starting the public
process:

1. `database-bootstrap` creates `fleet_recall` and enables only the temporary
   `fleet_migrator` principal.
2. `migrate` fetches only the migrator raw-URL secret and applies the complete
   embedded migration prefix 1 through 17.
3. `database-boundary` retires the migrator, provisions the DML-only
   `fleet_writer`, provisions the fixed `fleet_publication` principal in its
   quiesced `NOLOGIN` state, and applies the checksum-pinned publication policy.
4. The boundary inventories reader/principal ownership, direct grants, future
   defaults, and inherited PUBLIC authority across every local database,
   reapplies the policy, and only then enables `fleet_publication`.
5. Ingestion and MCP/reference-agent-capable work use the private writer
   container. The externally reachable app starts last with only the
   publication database capability.

The publication policy is mounted read-only from
`deploy/cockroach/publication-reader-role-grants.sql` and must match SHA-256
`ff3ada75aba9443875efb1f430a14829ef864b3f7409ae5d23f7bd381cb65226`.
Its exact reader surface is database `CONNECT`, public-schema `USAGE`, and
`SELECT` on these eight tables:

- `_sqlx_migrations`
- `memory_corpus_models`
- `memory_chunks`
- `memory_claim_embeddings`
- `memory_claim_support`
- `memory_claims`
- `memory_conflict_members`
- `memory_conflicts`

There is no publication sequence, DML, DDL, role-delegation, system, or private
writer grant.

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
expected and is not database-secret leakage or IAM evidence. The smoke checks
that the app has no database secret ID/private database URL and that it runs the
exact production image config. The separate AWS Terraform suite's 21/21 static
tests passed for the planned publication execution/task-role policy bodies, but
that configuration remains unapplied. Neither those tests nor this emulator
exercise proves real AWS IAM enforcement.

## What a current run proves

A successful run emits one JSON receipt binding:

- the clean checked-out 40-hex commit and both OCI revision labels;
- production/private image config and BuildKit manifest digests;
- the exact successful migration-prefix-17 catalog fingerprint;
- the reviewed policy digest and exact ten-row reader-grant fingerprint;
- the production app's database environment boundary;
- public health, status, and bounded hybrid recall;
- direct publication read success plus DML, DDL, and role-delegation denials;
- denial of writer-protocol startup inside the public app container;
- the writer-side three-agent record/replay/action/conflict/escalation receipt;
- recall of the same durable rows after replacing only the production app
  container while the CockroachDB container remains unchanged;
- successful removal of every fixed-project container and the named
  publication-secret volume before the verified receipt is emitted.

The receipt explicitly records `aws_apply_performed: false`,
`iam_enforcement_proved: false`, `tls_proved: false`,
`database_password_authentication_proved: false`, and `fargate_proved: false`.
This local database is deliberately insecure: the three URL credential fields
exercise application-side secret separation, but CockroachDB does not store or
authenticate them. The application escape hatch is accepted only for
loopback/Compose `cockroach` hosts with explicit `sslmode=disable`.

## Current evidence status

The historical Docker/Compose run from 2026-08-13 covered then-current source
through migration 9. It did not prove migrations 10 through 17 or this
publication boundary. Do not reinterpret that historical through-9 run as
current image parity.

The full current `smoke.sh` subsequently passed from clean source commit
`cd6ecfca2c1a6d112ba058aad899a21aa34bb0f4`. The accepted
[PUBLIC-03 local-emulator receipt](../../docs/evidence/localstack-publication-cd6ecfc-20260816.json)
binds prefix 1 through 17, the exact production/private image digests, policy
and ten-row grant fingerprints, reader-only status/recall, writer-command
denial, application replacement with durable recall, and zero fixed-project
container or publication-secret-volume residue. This supersedes only the
current harness's former pending label; it does not turn the historical
through-9 run into current evidence.

The accepted exact-v26.2.3 TLS local wrapper separately covers the complete
prefix through 17, rollback/interruption/drift behavior, live repositories,
private CLIs, and the publication product boundary. The publication-reader
Docker RBAC proof also passed as secondary policy-packaging parity. This
LocalStack lane is the production-image/publication integration layer after
those database proofs. All three results are local: the accepted receipt
explicitly records no TLS, database-password authentication, IAM enforcement,
Fargate, or AWS apply for the LocalStack run.

## Requirements

- Docker Engine with Compose v2 and Buildx.
- AWS CLI v2, `curl`, `git`, `jq`, and `shasum` on the host.
- A LocalStack Auth Token supplied as `LOCALSTACK_AUTH_TOKEN` or the legacy
  `LOCAL_STACK_API_KEY`, either in the process environment or the ignored
  repository-root `.env`.
- An absolute path to a model2vec bundle containing regular, non-symlink
  `config.json`, `model.safetensors`, and `tokenizer.json` files.
- A clean tracked and untracked source tree at the checked-out commit. Commit
  the coherent candidate before producing a receipt.

The harness pins LocalStack `2026.07.0` and CockroachDB `v26.2.3`. It does not
silently skip unavailable paid control-plane features; ECR/ECS/ELB and IAM
enforcement are outside this baseline rather than simulated as successes.

## Run

```bash
export LOCALSTACK_AUTH_TOKEN='...'
export FLEET_RECALL_MODEL_BUNDLE=/absolute/path/to/potion-retrieval-32M
./deploy/localstack/smoke.sh > /tmp/localstack-publication-receipt.json
jq -e '.schema == "fleet-localstack-publication-proof-v1" and .verified' \
  /tmp/localstack-publication-receipt.json
```

Token precedence is exported `LOCALSTACK_AUTH_TOKEN`, exported
`LOCAL_STACK_API_KEY`, root `.env` `LOCALSTACK_AUTH_TOKEN`, then root `.env`
`LOCAL_STACK_API_KEY`. The script recognizes exact assignments only, never
sources/evaluates `.env`, disables inherited shell tracing before secret
resolution, prevents Compose from loading `.env`, and never includes raw URLs
or the LocalStack token in the receipt.

To inspect a successful stack:

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
`KEEP_LOCALSTACK=1` is an explicitly interactive mode: it leaves the stack for
inspection and emits no verified JSON receipt. In the default release mode,
teardown failure is terminal, preserves bounded diagnostics under the reported
temporary path, and cannot be converted into a verified receipt.

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
