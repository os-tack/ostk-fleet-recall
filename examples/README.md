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

## Rich corpus

[`rich-demo/`](rich-demo/) contains a deterministic generator for a
larger publication-safe corpus. It chunks an explicit allowlist of checked-in
documentation and adds a synthetic twelve-week operations narrative, producing
500–1,000 useful records without network, Docker, or database access. Generated
NDJSON is ignored rather than committed.

```bash
mkdir -p examples/rich-demo/generated
./examples/rich-demo/generate.sh \
  > examples/rich-demo/generated/rich-demo.ndjson
./examples/rich-demo/verify.sh \
  examples/rich-demo/generated/rich-demo.ndjson
./examples/rich-demo/test.sh
```

The rich corpus describes decisions, supersessions, one retraction, and varied
disagreement scenarios as searchable narrative text. It does **not** create
claim-ledger state. Use MCP `remember` for deliberate claims, supersessions,
retractions, and conflicts so their provenance and transaction semantics are
actually exercised. The public demo seeds this verified corpus, then records
typed claims with exact chunk coordinates and content hashes. Ordinary narrative
remains search evidence; only those source-backed typed claims can carry a
conflict signal into semantic recall.
