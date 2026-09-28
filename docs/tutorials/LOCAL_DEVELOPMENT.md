# Local development: model, database, and HTTP demo

[Documentation](../README.md) · Next: [Using Recall](USING_RECALL.md)

Build Fleet Recall, start a disposable CockroachDB node, load the pinned
512-dimension model, and query a synthetic corpus through the HTTP demo.
At the end, you can stop with a working demo or continue to the MCP and memory
pipeline tutorials in the same shell. The original step numbers run across all
three tutorials.

This is the **disposable developer stack**: one insecure Docker database on
port 26257, a host Rust binary, and no identity provider. It does not use
LocalStack. An existing HTTPS installation under Lima/k0s is a separate
environment; use the [operator guide](../guides/OPERATING.md) to operate it.
Do not substitute that installation's database, keys, or `.state` directory
into these commands. A single node does not demonstrate production
availability or distributed topology.

### Prerequisites

- [Rust](https://rustup.rs/) 1.94 or newer, including Cargo, rustfmt, and
  Clippy. The crate's MSRV is 1.94.
- [Docker Engine](https://docs.docker.com/engine/install/). Docker Desktop is
  sufficient on macOS and Windows.
- CockroachDB 26.2.3. The quickstart uses the pinned official Docker image and
  invokes `cockroach sql` inside it, so a separate host CLI install is not
  required.
- The official Hugging Face
  [`hf` CLI](https://huggingface.co/docs/huggingface_hub/main/en/guides/cli).
- `curl` and `jq` for the HTTP and MCP smoke calls, and `git` 2.28 or newer
  for the memory worker in step 8.
- Approximately 3 GB free for Rust dependencies, the CockroachDB image/data,
  and the 129 MB model weights.

Run all commands below from the repository root, in a dedicated shell without
an existing Fleet deployment's environment or any `PG*` variables. The binary
rejects `PG*` variables to prevent implicit database configuration. Keep this
shell open across the tutorials: they share model coordinates, database roles,
scope, and the authority report. The [configuration reference](../reference/CONFIGURATION.md)
explains which process owns each setting.

The Docker container name `ostk-fleet-recall-crdb` and host ports 26257, 8081,
and 8088 must be available. If a container with that name already holds work
you want, use the stop/resume guidance below instead of initializing over it.
First build the locked Rust dependency graph:

```bash
rustc --version
cargo build --locked
export FLEET_RECALL_BIN="$PWD/target/debug/ostk-fleet-recall"
```

### 1. Acquire and pin the local embedding model

Fleet Recall uses MinishLab's
[`potion-retrieval-32M`](https://huggingface.co/minishlab/potion-retrieval-32M)
model, published under the MIT license. The command below pins the model
repository to commit
[`6fc8051fab2a1e0ee76689cf08c853792ac285e7`](https://huggingface.co/minishlab/potion-retrieval-32M/tree/6fc8051fab2a1e0ee76689cf08c853792ac285e7)
instead of following a mutable branch:

```bash
export FLEET_RECALL_MODEL_REVISION=6fc8051fab2a1e0ee76689cf08c853792ac285e7
export FLEET_RECALL_MODEL_STAGE="$PWD/.model-stage/potion-retrieval-32M"
export FLEET_RECALL_MODEL_DIR="$PWD/.models/potion-retrieval-32M-$FLEET_RECALL_MODEL_REVISION"

mkdir -p "$FLEET_RECALL_MODEL_STAGE" "$FLEET_RECALL_MODEL_DIR"
hf download minishlab/potion-retrieval-32M \
  config.json model.safetensors tokenizer.json \
  --local-dir "$FLEET_RECALL_MODEL_STAGE" \
  --revision "$FLEET_RECALL_MODEL_REVISION"

for file in config.json model.safetensors tokenizer.json; do
  cp -L "$FLEET_RECALL_MODEL_STAGE/$file" "$FLEET_RECALL_MODEL_DIR/$file"
  test -f "$FLEET_RECALL_MODEL_DIR/$file" && test ! -L "$FLEET_RECALL_MODEL_DIR/$file"
done
```

`hf download --local-dir` is the official local-folder flow. The explicit
`cp -L` creates a release bundle of regular, dereferenced files even if a local
Hugging Face cache uses links. Fleet Recall rejects a required bundle entry if
it is a symlink or not a regular file.

The repository revision pins the upstream source; Fleet Recall separately
pins the exact runtime bytes. Compute its domain-separated digest:

```bash
export FLEET_RECALL_EMBEDDING_MODEL_SHA256=$(
  "$FLEET_RECALL_BIN" model-digest "$FLEET_RECALL_MODEL_DIR"
)
printf '%s\n' "$FLEET_RECALL_EMBEDDING_MODEL_SHA256"
```

The digest covers the filename, size, and contents of exactly `config.json`,
`model.safetensors`, and `tokenizer.json`, sorted under the
`ostk-fleet-recall-model-bundle-v1` domain. Unrelated directory entries and the
host path are excluded. `migrate`, `ingest`, `health`, `demo`, and `serve`
verify this digest; model-loading paths verify before and after loading. The
database registry identity is the stable logical model ID plus this digest,
never a machine-specific path.

If maintainers intentionally advance the Hugging Face revision, keep the new
revision explicit, recompute the Fleet Recall digest, and use a new empty or
fully re-embedded corpus generation. Do not silently change model bytes under
an existing corpus.

### 2. Start a local CockroachDB 26.2 node

The image and command match the repository's live-test target and CockroachDB's
[`start-single-node`](https://www.cockroachlabs.com/docs/stable/cockroach-start-single-node)
development flow:

```bash
docker volume create ostk-fleet-recall-crdb
docker run --detach \
  --name ostk-fleet-recall-crdb \
  --hostname ostk-fleet-recall-crdb \
  --add-host cockroach:127.0.0.1 \
  --publish 127.0.0.1:26257:26257 \
  --publish 127.0.0.1:8081:8080 \
  --volume ostk-fleet-recall-crdb:/cockroach/cockroach-data \
  --volume "$PWD/deploy/cockroach:/localstack:ro" \
  cockroachdb/cockroach:v26.2.3 \
  start-single-node \
  --insecure \
  --http-addr=ostk-fleet-recall-crdb:8080 \
  --store=/cockroach/cockroach-data

FLEET_RECALL_CRDB_READY=0
for _attempt in $(seq 1 120); do
  if docker exec ostk-fleet-recall-crdb \
    cockroach sql --insecure --host=127.0.0.1:26257 \
    --execute='SELECT 1' >/dev/null 2>&1; then
    FLEET_RECALL_CRDB_READY=1
    break
  fi
  if [ "$(docker inspect --format '{{.State.Running}}' ostk-fleet-recall-crdb 2>/dev/null)" != true ]; then
    docker logs ostk-fleet-recall-crdb
    exit 1
  fi
  sleep 1
done
if [ "$FLEET_RECALL_CRDB_READY" -ne 1 ]; then
  docker logs ostk-fleet-recall-crdb
  exit 1
fi

docker exec ostk-fleet-recall-crdb \
  cockroach sql --insecure --host=127.0.0.1:26257 \
  --execute='
    CREATE DATABASE IF NOT EXISTS fleet_recall;
    CREATE USER IF NOT EXISTS fleet_migrator;
    ALTER USER fleet_migrator WITH LOGIN NOCREATEDB NOCREATEROLE;
    GRANT admin TO fleet_migrator;
  '
```

The SQL endpoint is `127.0.0.1:26257`; the local DB Console is
<http://127.0.0.1:8081>. The named volume keeps local data across container
restarts.

This node has no TLS, authentication, replication, or production isolation.
Fleet Recall accepts an insecure database URL only when
`FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1` and the host is loopback (or the
Compose-only `cockroach` hostname). Production configuration must omit that
escape hatch and use `sslmode=verify-full`.

### 3. Migrate through the private schema capability

Set every required runtime coordinate. Tenant, project, and agent are
deployment authority, not request routing fields. The sample tenant is non-nil;
generate a different stable UUID for every real fleet.

```bash
local_pg_scheme=postgresql
local_migrator_password=local-migrator-only
export FLEET_RECALL_DATABASE_URL="${local_pg_scheme}://fleet_migrator:${local_migrator_password}@127.0.0.1:26257/fleet_recall?sslmode=disable"
export FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1
export FLEET_RECALL_TENANT_ID=0198a849-f6ae-7d61-9800-000000000001
export FLEET_RECALL_PROJECT=quickstart
export FLEET_RECALL_AGENT=quickstart-agent
export FLEET_RECALL_MAX_CONNECTIONS=4
export FLEET_RECALL_EMBEDDING_MODEL=minishlab/potion-retrieval-32M
export FLEET_RECALL_EMBEDDING_MODEL_PATH="$FLEET_RECALL_MODEL_DIR"
export RUST_LOG=ostk_fleet_recall=info
```

This migrator URL is the only database capability in the process while it
applies the embedded schema. Do not start the public demo yet:

```bash
"$FLEET_RECALL_BIN" migrate
```

While the migrator is still the only capability, give this physical scope its
writer authority. The installer takes `(tenant, project)` to an active
generation-2 registry head under the contract namespaces you choose and prints
the pins every event-first writer exports; keep the report for step 7. It is
idempotent, and its fixture-key signatures are nominal (see the
[writer-authority installer](../CONTROL_BOOTSTRAP.md#writer-authority-installer)).
The demo and basic MCP calls do not need the pins. Installing authority now,
while the migrator is available, lets step 7 introduce event-first writes:

```bash
export FLEET_RECALL_QUICKSTART_DIR="$PWD/.fleet-recall/quickstart"
mkdir -p "$FLEET_RECALL_QUICKSTART_DIR"
FLEET_RECALL_CONTRACT_TENANT_NAMESPACE=tenant.quickstart \
FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE=project.quickstart \
  "$PWD/target/debug/ostk-authority-install" apply \
  > "$FLEET_RECALL_QUICKSTART_DIR/authority.json"
jq '{generation, package, pins}' "$FLEET_RECALL_QUICKSTART_DIR/authority.json"
```

Expected result: the report names generation `2` and the
`connector_generation2` package. Preserve `authority.json`; the next tutorial
exports its pins when it introduces event-first assertions. This is the
default installer target; collected items require the explicit generation-3
transition in step 10.

`migrate` applies every embedded migration in [`migrations/`](../../migrations) in
order. Most run without a wrapping SQL transaction because of CockroachDB
schema-changer and schema-lock constraints, so an interruption can leave
committed DDL behind; versions 12 through 14 run transactionally on a
dedicated migration session with `autocommit_before_ddl = false`. Never run
multiple migrators concurrently or run the migration files manually as a
substitute for that policy. See
[migration and recovery rules](../MIGRATIONS.md) before recovering a failed
migration.

`migrate` and `ostk-authority-install` are the only commands that
authenticate as `fleet_migrator`. `ingest`, `health`, `serve`, the worker, and
`ostk-spec` accept only the private `fleet_writer` login, which does not exist
until the next step provisions it.

### 4. Establish the database boundary and load the corpus as the writer

The checked-in boundary helper retires the migrator login, provisions the
private `fleet_writer` and the fixed `fleet_publication` login, applies the
reviewed runtime and publication-reader policies from `deploy/cockroach/`, and
only then enables the two logins. On a shared or production cluster, follow
the audit and change-freeze steps in [migration operations](../MIGRATIONS.md)
instead:

```bash
docker exec --interactive ostk-fleet-recall-crdb \
  /bin/sh -s < deploy/localstack/database-boundary.sh
```

Replace the retired migrator URL with the DML-only writer the helper
provisioned, and keep every other coordinate from step 3. Load the included
non-sensitive corpus and check readiness as that writer:

```bash
local_writer_password=local-writer-only
export FLEET_RECALL_DATABASE_URL="${local_pg_scheme}://fleet_writer:${local_writer_password}@127.0.0.1:26257/fleet_recall?sslmode=disable"

"$FLEET_RECALL_BIN" ingest --input examples/demo.ndjson
"$FLEET_RECALL_BIN" health
```

Expected result: ingestion completes and `health` succeeds. If either fails,
stop here and resolve the reported model, database, or role error before
starting a service. Do not restore the migrator credential to make a runtime
command succeed.

### 5. Exercise the HTTP demo

The public demo refuses to start while a private database URL is set. Remove
the writer URL and give it only the fixed publication login:

```bash
unset FLEET_RECALL_DATABASE_URL
local_publication_password=local-publication-only
export FLEET_RECALL_PUBLICATION_DATABASE_URL="${local_pg_scheme}://fleet_publication:${local_publication_password}@127.0.0.1:26257/fleet_recall?sslmode=disable"
```

The demo now has only its publication URL. On every new and reused pooled
connection it re-witnesses the fixed login, database, application name, and
canonical search path before any recall SQL runs. Start the local server, wait
for readiness, recall the ingested idea, and stop it:

```bash
"$FLEET_RECALL_BIN" demo --listen 127.0.0.1:8088 &
FLEET_RECALL_DEMO_PID=$!

FLEET_RECALL_DEMO_READY=0
for _attempt in $(seq 1 120); do
  if curl --fail --silent http://127.0.0.1:8088/healthz >/dev/null; then
    FLEET_RECALL_DEMO_READY=1
    break
  fi
  if ! kill -0 "$FLEET_RECALL_DEMO_PID" 2>/dev/null; then
    wait "$FLEET_RECALL_DEMO_PID"
    exit 1
  fi
  sleep 1
done
if [ "$FLEET_RECALL_DEMO_READY" -ne 1 ]; then
  kill "$FLEET_RECALL_DEMO_PID" 2>/dev/null || true
  wait "$FLEET_RECALL_DEMO_PID" || true
  exit 1
fi

curl --fail --silent --show-error http://127.0.0.1:8088/api/status | jq
curl --fail --silent --show-error \
  --header 'content-type: application/json' \
  --data '{"query":"What happens when fleet agents disagree?","limit":5}' \
  http://127.0.0.1:8088/api/recall | jq

kill "$FLEET_RECALL_DEMO_PID"
wait "$FLEET_RECALL_DEMO_PID" || true
```

The HTTP service exposes only `/`, `/healthz`, `/api/status`, and bounded
`POST /api/recall`. It is a demonstrator, not an authenticated multi-tenant
control plane. Its recall cards render the bounded inline Markdown retained by
the corpus and link every repository-backed documentation or code chunk to the
immutable source commit and exact inclusive line range recorded at ingestion;
synthetic records without a checked-in source stay visibly unlinked.

Expected result: status responds, and recall returns cards from the demo
corpus. The background demo process is now stopped. You can finish here or
continue to [step 6: exercise the MCP server](USING_RECALL.md#6-exercise-the-mcp-server).
Keep the database running and the current shell open when continuing. The
shell currently contains only the publication database URL; step 6 switches
it back to the private writer.

## Stop and resume without losing data

Use this section only when pausing the tutorials. Stop the local database
while preserving its named volume:

```bash
docker stop ostk-fleet-recall-crdb
```

Restart it later with `docker start ostk-fleet-recall-crdb`. In the same shell,
your exported coordinates remain available. In a new shell, after completing
step 4 previously, restore the following settings from the repository root.
This block uses the existing model bundle and writer login; it does not
download, migrate, install authority, or ingest again:

```bash
export FLEET_RECALL_BIN="$PWD/target/debug/ostk-fleet-recall"
export FLEET_RECALL_QUICKSTART_DIR="$PWD/.fleet-recall/quickstart"
export FLEET_RECALL_MODEL_REVISION=6fc8051fab2a1e0ee76689cf08c853792ac285e7
export FLEET_RECALL_MODEL_DIR="$PWD/.models/potion-retrieval-32M-$FLEET_RECALL_MODEL_REVISION"
FLEET_RECALL_EMBEDDING_MODEL_SHA256=$("$FLEET_RECALL_BIN" model-digest "$FLEET_RECALL_MODEL_DIR") || exit 1
export FLEET_RECALL_EMBEDDING_MODEL_SHA256
export FLEET_RECALL_EMBEDDING_MODEL=minishlab/potion-retrieval-32M
export FLEET_RECALL_EMBEDDING_MODEL_PATH="$FLEET_RECALL_MODEL_DIR"
local_pg_scheme=postgresql
local_migrator_password=local-migrator-only
local_writer_password=local-writer-only
unset FLEET_RECALL_PUBLICATION_DATABASE_URL
export FLEET_RECALL_DATABASE_URL="${local_pg_scheme}://fleet_writer:${local_writer_password}@127.0.0.1:26257/fleet_recall?sslmode=disable"
export FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1
export FLEET_RECALL_TENANT_ID=0198a849-f6ae-7d61-9800-000000000001
export FLEET_RECALL_PROJECT=quickstart
export FLEET_RECALL_AGENT=quickstart-agent
export FLEET_RECALL_MAX_CONNECTIONS=4
export RUST_LOG=ostk_fleet_recall=info
"$FLEET_RECALL_BIN" health
```

Wait for `health` to succeed before continuing; immediately after Docker starts,
the database may still be starting. If you stopped before step 4, resume at
your unfinished setup step instead: the writer may not have been provisioned.

- For basic MCP, continue at [step 6](USING_RECALL.md#6-exercise-the-mcp-server).
- For event-first assertions or workers, run the pin-export `for` loop at the
  start of [step 7](USING_RECALL.md#7-assert-a-claim-from-two-agents) using the
  existing `authority.json`. There is no need to repeat the assertion calls.
- After step 8, follow [the pipeline resume block](MEMORY_PIPELINES.md#resume-after-step-8)
  to restore the content key, repository, sources file and commit before
  proceeding to spec checks or collected items.
- To revisit the HTTP demo, use step 5's credential switch first; the resume
  block deliberately leaves the private writer configured.

The named volume contains the local memory corpus. The model bundle and
`.fleet-recall/quickstart` also persist; later steps add the installer reports,
scratch repository, sources file, content key, and spec files there. Keep
those artifacts together with their database. Losing the content key makes
already wrapped bodies unreadable. Container, volume, and artifact removal
are separate explicit decisions; this tutorial does not remove them.
