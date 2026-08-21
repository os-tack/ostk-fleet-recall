# Rich demo corpus

This package deterministically builds a publication-safe Fleet Recall corpus
without contacting a network or database. It combines section-aware chunks
from the complete publication-safe tracked Markdown surface, bounded chunks
from the repository's application code, MCP implementation, migrations,
Terraform, deployment automation, CI, demos, and build configuration, two
exact checked-in Rust excerpts used by the conflict proof, and a synthetic
twelve-week fleet-operations narrative. The result makes the project itself
semantically recallable without pretending that binary or private workstation
state is useful agent memory.

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

The verifier requires exactly 7,676 unique chunks: 1,296 documentation chunks
from 54 sources, 6,174 repository chunks from 559 source/configuration files,
the two exact self-audit code excerpts, and 204 operations records across twelve
weeks. It also requires the expected decision and correction mix, zero-based
per-source chunk indexes, bounded physical lines and text, only the public
ingest allowlist, and no credential-, token-, private-key-, account ARN-, or
credential-bearing database URL patterns. `test.sh`
independently derives the full allowlisted set from `git ls-files` and compares
it with both checked-in manifests, so a new safe tracked file cannot silently
remain absent from the demo corpus.

The publication boundary excludes binary media, dependency and Terraform lock
files, generated example corpora, evidence receipts, license/vendor text,
ignored or private files, and a small explicit set of public test fixtures whose
dummy URLs or AWS account IDs intentionally resemble credentials. Connected
CockroachDB CLI proof wrappers and credential-bearing LocalStack fixtures
remain outside the publication boundary because they construct or contain
password-bearing database URLs. The admitted `src/private_postgres.rs`
connection-policy source plus the private successor-activation and
conflict-reconciliation CLIs are the narrow exceptions: their closed sets of
inert credential-shaped URL fixtures are removed only from the final
sensitive-pattern projection after exact source-coordinate verification. Any
different credential-bearing URL still fails the scan. The manifests enumerate
what is admitted; they do not crawl the operator's worktree at image-build time.

Documentation and code `source_id` values are the original repository-relative
paths. Repository records use `source: "code"`,
`record_kind: "source_code"`, and language plus subsystem facets such as
`mcp_interface`, `aws_infrastructure`, and `cockroach_store`; this keeps a
document/code filter simple while making questions such as “where is MCP
configured?” or “which AWS services are used?” semantically specific. Each
repository-backed record also carries its immutable 40-hex source revision and
the minimal inclusive physical line range containing that chunk in bounded
`extra` metadata. Local generation uses an all-zero sentinel; release builds
pass the full source commit through `RICH_DEMO_SOURCE_REVISION`, and the public
UI only creates exact line links for a nonzero immutable revision. The verifier
reconstructs every normalized snippet from the checked-in linked range and
rejects widened, narrowed, shifted, mutated, missing, or mislabeled records.
The two conflict-proof code records are extracted fail-closed from the current
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
