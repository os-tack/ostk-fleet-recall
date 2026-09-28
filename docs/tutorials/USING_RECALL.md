# Using Recall: MCP, claims, and two agents

[Documentation](../README.md) · Previous: [Local development](LOCAL_DEVELOPMENT.md) · Next: [Memory pipelines](MEMORY_PIPELINES.md)

Make real MCP calls, record a claim, and have two agents assert incompatible
values about the same subject. These are direct stdin/stdout requests to the
local binary; no Claude or Codex subscription is needed to run them.

Complete [steps 1–5](LOCAL_DEVELOPMENT.md) first and keep that shell and database
running. This tutorial carries forward `FLEET_RECALL_BIN`, the model settings,
the `quickstart` scope, `local_pg_scheme`, and
`FLEET_RECALL_QUICKSTART_DIR/authority.json`. Step 6 uses the private writer
created by the boundary helper; step 7 adds the generation-2 authority pins.
Run commands from the repository root.

For the existing HTTPS Lima/k0s installation, use the
[operator guide](../guides/OPERATING.md) and its client connection instructions.
Do not put its credentials into this disposable developer setup. For settings
and ownership, see the [configuration reference](../reference/CONFIGURATION.md).

### 6. Exercise the MCP server

`serve` speaks newline-delimited JSON-RPC/MCP on stdin/stdout. The following is
a complete direct smoke exchange. Keep each JSON request on one physical line;
the initialized notification intentionally has no response. The public
capability is removed first and the step 4 writer URL restored, because MCP
includes the private `remember` tool; the boundary helper provisioned this
DML-only writer without DDL authority.

```bash
unset FLEET_RECALL_PUBLICATION_DATABASE_URL
local_writer_password=local-writer-only
export FLEET_RECALL_DATABASE_URL="${local_pg_scheme}://fleet_writer:${local_writer_password}@127.0.0.1:26257/fleet_recall?sslmode=disable"

"$FLEET_RECALL_BIN" serve <<'JSONRPC'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"readme-smoke","version":"1.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"recall","arguments":{"action":"search","scope":{"project":"quickstart","agent":"quickstart-agent","session_id":"readme","privacy_tier":"t1_project"},"query":"How does fleet memory survive agent restarts?","kind":"chunk","limit":5}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"remember","arguments":{"action":"record","scope":{"project":"quickstart","agent":"quickstart-agent","session_id":"readme","privacy_tier":"t1_project"},"idempotency_key":"readme/single-migrator/v1","kind":"decision","text":"Fleet schema migration runs through one dedicated migrator before serving traffic.","subject":"fleet deployment","predicate":"migration strategy","value":"single dedicated migrator","actor":"quickstart-agent"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"recall","arguments":{"action":"search","query":"How should schema migration run?","kind":"claim","limit":5}}}
JSONRPC
```

Rerunning the same `remember` request with the same tenant-wide idempotency key
returns the stored mutation with `idempotent_replay` set and does not create a
second durable mutation. A changed full request using that key is rejected.
This is at-most-one committed mutation behavior, not exactly-once response
delivery; after an ambiguous response, retry the same full request and key.

Expected result: initialization and tool listing succeed, search finds demo
chunks, `remember(record)` returns a claim, and the last search finds that
claim. JSON-RPC responses are on stdout; diagnostics are on stderr.

#### Read context before changing it

In an MCP client, start with `recall` and the argument object
`{"action":"brief"}`. A subject-specific brief, such as
`{"action":"brief","subject":"fleet deployment"}`, narrows the current
claims and conflicts. Use `get` with the returned claim or conflict id before
making a lifecycle change: mutation requests use the revision you just read.

The [MCP reference](../reference/MCP.md#start-with-a-brief) explains brief,
search, and get responses. The [claims reference](../reference/CLAIMS.md#claim-and-conflict-lifecycle)
explains authorship, revisions, retries, and the available lifecycle actions:

| Your intent | Action |
| --- | --- |
| Retire your current claim | `remember(retract)` |
| Replace your current claim while keeping its key and kind | `remember(supersede)` |
| Mark an open conflict as seen | `remember(acknowledge)` |
| Concede your claims and ask the detector to verify resolution | `remember(resolve)` |
| Adjudicate as an uninvolved agent, when explicitly enabled | `remember(dismiss)` or `remember(waive)` |

An acknowledgement or waiver leaves the incompatible claims visible. Treat a
brief's unavailable or truncated block as incomplete information, and re-read
after a stale-revision response before retrying a mutation.

#### Connect a stdio client

Most stdio MCP clients use a configuration shaped like the following. Replace
the absolute paths and digest; this example deliberately contains only local,
insecure development credentials. Client-specific configuration file names and
top-level keys vary.

```json
{
  "mcpServers": {
    "ostk-fleet-recall": {
      "command": "/absolute/path/to/ostk-fleet-recall/target/debug/ostk-fleet-recall",
      "args": ["serve"],
      "env": {
        "FLEET_RECALL_DATABASE_URL": "REPLACE_WITH_PRIVATE_WRITER_URL",
        "FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE": "1",
        "FLEET_RECALL_TENANT_ID": "0198a849-f6ae-7d61-9800-000000000001",
        "FLEET_RECALL_PROJECT": "quickstart",
        "FLEET_RECALL_AGENT": "quickstart-agent",
        "FLEET_RECALL_MAX_CONNECTIONS": "4",
        "FLEET_RECALL_EMBEDDING_MODEL": "minishlab/potion-retrieval-32M",
        "FLEET_RECALL_EMBEDDING_MODEL_PATH": "/absolute/path/to/ostk-fleet-recall/.models/potion-retrieval-32M-6fc8051fab2a1e0ee76689cf08c853792ac285e7",
        "FLEET_RECALL_EMBEDDING_MODEL_SHA256": "PASTE_MODEL_DIGEST_HERE",
        "RUST_LOG": "ostk_fleet_recall=info"
      }
    }
  }
}
```

Do not put a production CockroachDB URL into a checked-in MCP configuration.
Use the client's secret/environment facility and a TLS URL instead. This
example configures the basic calls in step 6. To use event-first assertions
through that client, also supply the three pins exported in step 7; the
memory pipeline tutorial introduces the separate content key for operations
that wrap or unwrap source bodies.

### 7. Assert a claim from two agents

Export the pins from the step 3 report. `serve` verifies them at startup,
serves `remember(assert)`, and adds it to `tools/list`. Each assert then
re-verifies the head:

```bash
for pin in FLEET_RECALL_CONTRACT_TENANT_NAMESPACE \
           FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE \
           FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST; do
  export "$pin=$(jq --exit-status --raw-output --arg pin "$pin" '.pins[$pin]' \
    "$FLEET_RECALL_QUICKSTART_DIR/authority.json")"
done

"$FLEET_RECALL_BIN" serve <<'JSONRPC' | jq --compact-output 'select(.id > 1) | .result.structuredContent.data // .error'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"readme-smoke","version":"1.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"recall","arguments":{"action":"status"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"remember","arguments":{"action":"assert","idempotency_key":"readme/assert/v1","assertion":{"kind":"decision","text":"remember(assert) allowed is true at this commit in production.","modality":"attested","value":{"kind":"boolean","value":true},"subject":{"provider_repository_id":"908172635"},"applicability":{"repository_commit":{"commit_oid":"3d99ec111a583e80533cbbc0c06798bb628e0979"},"runtime_environment":{"environment_id":"production"}}}}}}
JSONRPC
```

The status's `remember_assert` block reports `served: true`, the verified
head (`generation` 2 and the `connector_generation2` package), and the route
described under [asserting a claim](../reference/CLAIMS.md#asserting-a-claim). It also carries
`evidence` and `spec_conformance` blocks, because the runtime policy that
step 4 applied lets this login read the Stage-5 and Stage-6 tables. The assert's
`data` holds the claim and its `accepted_event`.

A second agent, which is another process with its own `FLEET_RECALL_AGENT`,
asserts the opposite value about the same repository, commit, and
environment:

```bash
FLEET_RECALL_AGENT=quickstart-reviewer "$FLEET_RECALL_BIN" serve <<'JSONRPC' | jq --compact-output 'select(.id > 1) | .result.structuredContent.data // .error'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"readme-smoke","version":"1.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"remember","arguments":{"action":"assert","idempotency_key":"readme/assert-reviewer/v1","assertion":{"kind":"decision","text":"remember(assert) allowed is false at this commit in production.","modality":"attested","value":{"kind":"boolean","value":false},"subject":{"provider_repository_id":"908172635"},"applicability":{"repository_commit":{"commit_oid":"3d99ec111a583e80533cbbc0c06798bb628e0979"},"runtime_environment":{"environment_id":"production"}}}}}}
JSONRPC
```

Its response lists the conflict in `conflicts_opened`, and both claims now
read `disputed`. `recall(conflicts)` and the [claim and conflict lifecycle](../reference/CLAIMS.md#claim-and-conflict-lifecycle)
treat this conflict like any other.

Expected result: two event-first assertions address the same applicability,
and the second reports an open conflict. These fixture assertions illustrate
the contract; their literal `production` field does not contact or configure
a production deployment.

You can stop here after learning MCP and claims. To inspect why evidence is
present, absent, or unknown, continue to
[step 8: run the memory worker](MEMORY_PIPELINES.md#8-run-the-memory-worker-over-a-scratch-repository)
in the same shell. Preserve the pins you just exported. To pause instead,
[stop the development database while preserving its data](LOCAL_DEVELOPMENT.md#stop-and-resume-without-losing-data).
