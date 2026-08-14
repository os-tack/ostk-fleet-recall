# Rich demo corpus

This package deterministically builds a publication-safe Fleet Recall corpus
without contacting a network or database. It combines section-aware chunks
from twelve checked-in project, architecture, submission, migration, AWS,
LocalStack, and examples documents, two exact checked-in Rust excerpts, and a
synthetic twelve-week fleet-operations narrative.

The operations narrative includes accepted and contingency decisions,
observations, changes, handoffs, 11 explicit supersessions, exactly one
retraction, and eight different disagreement scenarios. Three have narrative
resolutions; five remain pending operator review.
Those records are searchable narrative passages only. **Ingesting this NDJSON
does not create typed claims, supersessions, retractions, or conflicts in the
claim ledger.** Create and evolve deliberate claim state through the MCP
`remember` tool so provenance, idempotency receipts, serializable writes,
supersession rules, and conflict membership are exercised.

## Generate and verify

The scripts require a POSIX shell, `awk`, and `jq`; the verifier and reproduction
test also use standard local text utilities. The generated directory is
ignored. From the repository root:

```bash
mkdir -p examples/rich-demo/generated
./examples/rich-demo/generate.sh \
  > examples/rich-demo/generated/rich-demo.ndjson
./examples/rich-demo/verify.sh \
  examples/rich-demo/generated/rich-demo.ndjson
```

Run the deterministic reproduction test with:

```bash
./examples/rich-demo/test.sh
```

The verifier requires 500–1,000 unique chunks, twelve documentation sources,
the two exact self-audit code excerpts, 204 operations records across twelve
weeks, the expected decision and correction mix, zero-based source chunk
indexes, bounded physical lines and text, only the public ingest allowlist, and
no credential-, token-, private-key-, account ARN-, or credential-bearing
database URL patterns.

Documentation and code `source_id` values are the original repository-relative
paths. The code records are extracted fail-closed from the current
`src/mcp/tools.rs` and `src/application.rs` contents; they are not duplicated
fixtures. Synthetic operations records use stable
`rich-demo/operations/week-NN/event-name` identifiers instead of pretending
that their generated narratives are checked-in source files.

To inspect the generated mix without ingesting it:

```bash
jq -s '{
  chunks: length,
  by_kind: (group_by(.facets.record_kind[0])
    | map({key: .[0].facets.record_kind[0], value: length})
    | from_entries),
  event_types: ([.[] | select(.facets.event_type)
    | .facets.event_type[0]] | group_by(.)
    | map({key: .[0], value: length}) | from_entries)
}' examples/rich-demo/generated/rich-demo.ndjson
```

The verified artifact is baked into the production image as an explicit
operator seed option. Generating or verifying it locally does not itself
authorize ingestion into any live AWS/CockroachDB deployment.
