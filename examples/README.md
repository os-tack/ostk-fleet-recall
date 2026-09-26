# Demo corpus

`demo.ndjson` is synthetic, non-sensitive seed data for the public demo. It
contains no tenant or project authority fields; ingestion derives those fields
from trusted deployment configuration.

After migration and model verification:

```bash
ostk-fleet-recall ingest --input examples/demo.ndjson
```

Ingestion is deterministic and idempotent for the same source coordinates,
source configuration, chunk index, text, and active model. Deliberate claim and
conflict scenarios should be created through the MCP `remember` action so they
exercise receipts, provenance, serializable writes, and conflict transitions.
The LocalStack harness does this automatically through
`deploy/localstack/fleet-demo.sh`, using three distinct deployment-bound MCP
identities and checking hybrid recall, replay deduplication, scope isolation,
a persisted recall-driven action, an open two-member conflict, and a persisted
operator escalation.

# Worker sources

`worker-sources.json` is an example sources file for
`ostk-fleet-recall worker --once`, with one git ref, one transcript directory,
and one CI workflow, and one collector of each provider: a documents root,
a Slack workspace, a Linear organization, and a Granola account. Each source
and collector is its own connector instance. Replace the paths, repository
coordinates, provider ids, and token variables with your own, and drop the
collectors you do not run; a collector needs the scope at generation 3. See
[memory worker](../README.md#memory-worker) for the environment the command
reads and where each step can run, and
[receiving provider webhooks](../README.md#receiving-provider-webhooks) for
the `push` entry a collector adds to take webhooks.
