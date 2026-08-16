# Generation-2 registry composition

This directory freezes the offline composition contract for the generation
`1 -> 2` registry transition. Nothing here activates anything: these are
canonical bytes, digests, and closure rules. Activation still requires the
governing predecessor policy, verified approval attestations, a server-derived
eligibility verdict, and a compare-and-swap against the exact durable head.

## What the manifest says

`composition-manifest.jsonl` is one canonical `Generation2CompositionManifestV1`
record under the frozen `ostk-canonical-json-v1` profile. It states three
things and nothing more.

1. **Carry-forward roots.** The exact Stage-4 capability roots a generation-2
   package must contain, each by full `(kind, entry_id, version,
   entry_schema_id, entry_schema_version, entry_digest)` reference: the
   activation-policy v2 root, the remember admission rule, the connector
   schema, the remember predicate schema, and the relation proof. A root is
   named by digest, so a re-cut entry with the same ID and version does not
   satisfy it.
2. **Predecessor head.** The exact generation-1 head the transition expects to
   replace — activation ID, package digest, and activation-policy digest —
   copied from `../../v2/successor-activation/activated-head.jsonl`. Binding the
   activation ID and not only the package digest is what rejects a stale
   proposal after an `A -> B -> A` package sequence. Reproducing these bytes is
   not authority: a repository must still compare-and-swap its own durable head.
3. **Reserved slots.** Every generation-2 body-schema slot whose typed body is
   not wired in this binary, each bound to its closed-table slot digest. Listing
   a slot reserves a name; it does not admit a body. Any package entry that
   selects a reserved slot fails closed in the genesis closure, the generic
   successor closure, and the composition closure alike.

The closure rule is: every listed root resolves exactly once by full reference,
every package entry selects a dispatched triple, exactly one activation-policy
v2 entry is present, and both listed sets are strictly sorted with no
duplicates.

## The closed body-schema slot table

`body-schema-slots.jsonl` is the canonical projection of the compiled
`BODY_SCHEMA_SLOTS` table: every `(kind, entry schema ID, entry schema version)`
triple a generation-2 package may name, each classified as
`generation1_dispatched`, `generation2_dispatched`, or `generation2_reserved`.
A triple outside the table classifies as `unknown` and every consumer fails
closed on it.

Freezing the table as bytes is the point. Wiring a typed body for a reserved
slot, promoting a reserved slot to dispatched, or widening the table at all
changes this artifact's digest, so the change cannot arrive silently in a
refactor. The Rust test recomputes the table from the compiled constant and
rejects any record that disagrees, so the file can never assert a dispatch
decision this binary does not actually make.

The three generation-2-only kinds — `parser_contract`, `log_epoch_recipe`, and
`arrow_batch_schema` — appear only as reserved slots. The frozen generation-1
closures (genesis package and Stage-4 target package) reject them outright with
an explicit error, because no v1 body schema covers them and no verifier in this
binary can close one.

`registry.connector_schema` v2 is **dispatched**, not reserved: the
transcript-session and git-history connector families are instances of that
existing schema, not new schemas, so they need no new slot.

## Negative vectors

Each negative is one canonical record that violates exactly one rule.

| File | Rule violated |
| --- | --- |
| `negative-missing-required-kind.jsonl` | required activation-policy v2 root absent |
| `negative-duplicate-root.jsonl` | one carry-forward root listed twice |
| `negative-unknown-kind.jsonl` | a `kind` name outside the closed enum |
| `negative-wrong-predecessor-head.jsonl` | predecessor activation ID off by one bit |
| `negative-v1-kind-at-v2.jsonl` | `retention_policy` claimed at entry schema v2 |
| `negative-reserved-wrong-version.jsonl` | reserved `parser_contract` slot at v2 |
| `negative-unsorted-roots.jsonl` | carry-forward roots not in canonical order |

`negative-unknown-kind.jsonl` exists only as bytes. No typed constructor can
express a kind outside the closed enum, so that case is built by editing the
serialized value and must be rejected at decode.

## Freeze discipline

`vector-suite.jsonl` pins the manifest digest, the slot-table digest, the
predecessor head, the frozen Stage-4 package digest, and the raw SHA-256 of
every artifact in this directory. Literal Rust constants in
`src/memory_contracts/generation2.rs` raw-pin the suite itself, so the graph is
acyclic and every artifact is reachable from a compiled constant.

Every JSONL file is exactly one canonical JSON record followed by one LF. These
bytes are frozen: correcting one is a new version, never an edit in place.
Regenerate with the maintainer-only ignored test:

    GENERATION2_VECTOR_OUTPUT=contracts/dynamic-memory/v3/registry-gen2 \
      cargo +1.94 test --locked --lib \
      memory_contracts::generation2::tests::regenerate_generation2_artifacts \
      -- --exact --ignored --nocapture

## Invariants

- **AUTH-04.** Normativity is designated by a registry and its activation
  policy. A manifest that lists a slot or a root designates nothing on its own;
  no field inside it can establish its own authority, and reserving a slot name
  never admits a body.
- **REPLAY-01.** Every digest here is a pure function of canonical bytes under
  one fixed domain prefix. Replaying the same manifest yields the same identity,
  and any ordered semantic change yields a different one.
