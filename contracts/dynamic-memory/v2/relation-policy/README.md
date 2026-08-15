# Relation proof v2 policy

This directory freezes the structural `registry.relation_proof` schema-v2
contract for the first Stage-4 relation target. The positive entry admits only
an authenticated actor's `declared` attestation with verdict `supports` and
between 1 and 256 cited accepted-event IDs. Inferred, provider-attested, and
verifier-result bases are not variants of this body schema and therefore fail
closed. A future basis requires a new typed result/run and coverage contract,
not a label-only reference.

The first target also freezes `many_to_many` multiplicity and
`temporal_overlap_required: false`; alternate cardinality or temporal policy is
a different contract target and is rejected by this body.

The entry closes source, target, and each applicability dimension over exact
resource-kind-schema and identity-recipe references. Its two required
dimensions are `repository_commit` and `runtime_environment`. At active
admission, the successor package must resolve every full referenced entry from
one package and prove each recipe embeds the exact kind and URI form. The
repository must then obtain trusted locator witnesses, rederive every resource
URI, authenticate the project-scoped actor, and re-audit all support events in
the same active registry head before append. URI shape and entry-ID agreement
alone are never identity or authority proof.

All four payload authority switches are frozen `false`: callers may not select
the attestor, registry head, relation proof, or verified state. The server
routes a unique proof from trusted scope and relation ID, then compares the
payload's proof reference as an assertion. A structurally resolved entry is not
an active-package or active-head witness.

The dependency digests in this first structural fixture are deterministic
test-only assertions for the proposed target revisions. They grant no runtime
authority. The real Stage-4 target package must replace them with digests of
checked-in full `RegistryEntryV1` preimages and resolve the complete transitive
closure before activation.

The legacy relation-proof v1 entry cannot authorize the frozen relation event
vectors. It carries no exact source/target identity recipes and cannot bind the
resource kind and identity recipe closure for both applicability dimensions.
Matching a URI's surface kind or form is insufficient; active admission must
resolve every exact full-entry reference and rederive every URI.

## Frozen vector DAG

`positive-cases-v2.jsonl` and `negative-cases-v2.jsonl` are independent,
canonical `TestVectorManifest`-domain preimages. Their domain digests are
embedded in `relation-proof-v2-entry.jsonl`, so the full entry digest commits
to both case sets. `vector-suite.jsonl` then pins the full entry digest, the two
case-manifest digests, and the raw SHA-256 of every artifact. The entry never
references the aggregate suite, keeping the graph acyclic. A literal Rust
constant raw-pins the suite itself.

Every JSONL file is exactly one canonical JSON record followed by one LF.
