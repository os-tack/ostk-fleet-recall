# Demo corpus

`demo.ndjson` is synthetic, non-sensitive seed data for the public hackathon
demo. It contains no tenant or project authority fields; ingestion derives
those fields from trusted deployment configuration.

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
identities and asserting hybrid recall, replay deduplication, scope isolation,
a persisted recall-driven action, an open two-member conflict, and a persisted
operator escalation.
