# Generation-3 collected-items registry package

`registry-package.jsonl` is the canonical generation-3 registry package: one
`RegistryPackageV1` record under the frozen `ostk-canonical-json-v1` profile,
plus exactly one repository-framing LF. Its digest is
`b5103302073c26cd42d727e1f907acecb9803d7f3da7166dd0f98d29255ac54b`.

The package is the generation-2 connector package carried forward byte for
byte, plus the 13 entries of one generic, provider-parameterized collected-item
family ([ADR 0008](../../../../docs/adr/0008-collected-items.md) D1):

- the provider-scope chain `namespace.collected.provider_scope`,
  `collected_provider_scope`, and `identity.collected.provider_scope`, keyed on
  `[provider_kind, provider_scope_id]`;
- the item chain `namespace.collected.item`, `collected_item_revision`,
  `collected_item_version`, `identity.collected.item_revision`, and
  `identity.collected.item_version`, keyed on `immutable_revision`;
- the evidence schema `evidence.collected.item`;
- one connector schema per trust channel: `connector.collected.pull`,
  `connector.collected.push`, `connector.collected.capture`, and
  `connector.collected.import`.

These bytes are the artifact (AUTH-04). The registry witness compiles them in
as `KnownRegistryPackage::CollectedItemsGeneration3`, and a head that
activates this digest is admitted by digest exactly like generations 1 and 2.
Nothing here activates anything: a scope reaches generation 3 only through
`ostk-authority-install apply --target generation-3`.

## Regeneration

`generation_three_registry_package` in
`src/memory_contracts/generation3_registry.rs` composes these bytes from the
compiled generation-2 package, and a non-ignored test fails if the composition
and this file ever disagree. Once any head names the digest, the bytes are
frozen: a change is a new generation, not an edit. Before that, a deliberate
change is regenerated with

```bash
cargo test --lib -- --ignored regenerate_generation_three_package
```

which rewrites this file and prints the new digest to pin in the tests and in
ADR 0008.

## Golden identity vectors

`vectors.jsonl` holds one canonical record per line, each one part of one
collected item sealed through the collector pipeline
(`src/collectors/draft.rs`): the exact `CollectedItemEnvelopeV1` and the
digests it must derive (`item_key`, `version_key`, `immutable_revision`, and
`container_key`), under the domains `ostk-collected-item-key-v1`,
`ostk-collected-item-content-v1`, `ostk-collected-item-version-v1`,
`ostk-collected-item-revision-v1`, and `ostk-collected-container-key-v1`. The
cases cover a pulled Slack message, the same message captured by two agents
(one version, three revisions), an imported Linear issue with its provider
marker, a two-part document under the default marker, and a revoked tombstone.

Two tests hold them: the contract test re-derives every digest from the
envelope alone, and the pipeline test seals the same drafts again and requires
these exact bytes. An envelope stored as evidence is identity-bearing, so a
deliberate change is a new envelope schema or redaction profile (the vectors
record profile 3, the crate-wide profile of `crate::redaction`: the shared
shapes plus the provider shapes, Stripe included), regenerated with

```bash
cargo test --lib -- --ignored regenerate_collected_item_vectors
```
