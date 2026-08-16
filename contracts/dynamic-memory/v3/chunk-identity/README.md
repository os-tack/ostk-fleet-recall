# Chunk and embedding identity v3 contract vectors

These fixtures freeze `src/memory_contracts/chunk_identity.rs`, the W0-CHUNK
deliverable for `docs/DYNAMIC_MEMORY_ARCHITECTURE.md`, "Chunk and embedding
identity across parser versions" and "Canonical resource identity". None of
these values carry runtime authority: the parser artifact digests, source
URIs, and registry references below are deterministic test material, not
proof that any real parser, registry package, or coverage receipt exists.

Every `.jsonl` file contains exactly one canonical JSON record plus exactly
one trailing LF. The raw-byte SHA-256 pin is over the exact checked-in bytes
with that LF included; the record's own identity digest (computed after
stripping the LF and decoding) necessarily excludes it, since the LF is
framing, not part of the canonical JSON record. Every record is byte-frozen:
the Rust test suite `include_bytes!`s each file, asserts the raw file SHA-256
against a hardcoded constant, decodes it with `canonical::require_canonical`
and `canonical::decode_typed_canonical` (duplicate-safe strict parsing, plus
requiring the checked-in bytes to be exactly the typed value's own canonical
re-encoding — closing the positional-array/omitted-optional-key class for
every fixture, not just document-level canonicality), and recomputes the
record's identity digest against a second hardcoded constant. Changing any
field, byte, or digest below is a contract-version change, not a fixture
update.

## What each positive vector proves

- `parser-key-v1.jsonl` — `ParserKeyV1`. Binds parser/extractor artifact
  digest, version, configuration digest, and a strictly sorted, closed set of
  declared normalization rules (EVID-02: exact, versioned parser identity —
  never a bare "current parser" label).
- `chunk-occurrence-v1.jsonl` — `ChunkOccurrencePreimageV1` and its derived
  `ChunkOccurrenceId`. Binds the source-object *version* URI, the parser key,
  an ordered non-contiguous span list, the occurrence's own ordinal among its
  manifest's occurrences, the reused `body_digest` body-content ID, and the
  redaction/publication-classifier versions. It has no `manifest_id` field:
  see `negative-manifest-id-inside-occurrence.jsonl` (EVID-02, REPLAY-01).
- `parse-run-manifest-v1.jsonl` — `ParseRunManifestPreimageV1` and its
  derived `ParseManifestId`, citing the occurrence ID above. The manifest ID
  is a pure digest of already-complete canonical run metadata — it is
  computed strictly after every occurrence ID it cites, and no occurrence
  preimage ever depends on it (REPLAY-01: same parser key, same source
  representation, same canonical inputs reproduces the identical manifest).
- `manifest-supersession-v1.jsonl` — `ManifestSupersessionV1`, an explicit
  predecessor/successor link recorded when a parser/configuration change
  rechunks a source. The predecessor manifest is never mutated or reused; it
  remains an independently addressable historical value.
- `generation-pointer-v1.jsonl` and
  `generation-pointer-switch-proposal-v1.jsonl` — `GenerationPointerV1` and
  `GenerationPointerSwitchProposalV1`. The proposal is a compare-and-swap
  preimage naming its exact `expected_prior_pointer`; a shadow generation may
  only become current through
  `GenerationPointerSwitchProposalV1::checked_against` succeeding against a
  trusted current-pointer witness, and `AdmittedGenerationSwitchV1` has no
  production constructor in this contract-only stage.
- `embedding-identity-body-v1.jsonl` and
  `embedding-identity-occurrence-v1.jsonl` — `EmbeddingIdentityPreimageV1`
  under the two `EmbeddingInputV1` selector arms. The selector and its input
  digest are one tagged field, not a separate selector-plus-digest pair, and
  `EmbeddingInputV1` carries `#[serde(deny_unknown_fields)]` (matching every
  other tagged enum in this module tree), so a selector/digest mismatch
  cannot be constructed: an internally-tagged enum without
  `deny_unknown_fields` only requires the *selected* arm's own fields to be
  present, it does not by itself reject an unrelated key riding alongside
  that arm — `deny_unknown_fields` is what closes that gap. Embedding
  nondeterminism (a remote model's retried output) cannot affect this
  identity because no embedding vector byte is a field of the preimage.
- `storage-identity-v1.jsonl` — `StorageIdentityPreimageV1` and its derived
  `StorageIdentityId`. Domain-keyed: the protection-domain identifier is
  hashed into the same preimage as the body-content digest, so the emitted
  storage identity cannot leak an unkeyed digest-equality join across
  protection domains (see the protection-domain dedup vectors below).
- `body-reference-state-v1.jsonl` — `BodyReferenceStateV1`, the input to the
  EVID-08 reference-count predicate `may_reclaim_shared_storage` and the pure
  transition `apply_occurrence_erasure`.

## What each negative vector proves

- `negative-manifest-id-inside-occurrence.jsonl` — the same
  `ChunkOccurrencePreimageV1` record as the positive fixture, with an
  additional `manifest_id` key inserted. `#[serde(deny_unknown_fields)]`
  rejects it: occurrence identity cannot be made to depend on the manifest
  that cites it, even by a payload that merely names one.
- `negative-line-number-field.jsonl` — a `ChunkOccurrencePreimageV1` record
  with a `line` key added. Rejected for the same reason: line numbers are
  display metadata only and have no field to occupy in this identity.
- `negative-empty-span.jsonl` — a span list containing one zero-length
  `[5, 5)` span. `SourceSpanV1::validate` requires `byte_start < byte_end`.
- `negative-overlapping-spans.jsonl` — two spans `[0, 10)` and `[5, 20)`.
  `validate_span_list` requires `spans[i].byte_end <= spans[i+1].byte_start`.
- `negative-unsorted-spans.jsonl` — two spans supplied out of byte order
  (`[10, 20)` before `[0, 5)`) with ordinals `0, 1` matching list position.
  Rejected because the spans are not strictly ordered by byte offset.
- `negative-unknown-normalization-flag.jsonl` — a `ParserKeyV1` record whose
  `declared_normalization_rules` contains `"not_a_real_rule"`. The closed
  `NormalizationRuleV1` enum has no such variant, so decoding fails before
  any structural validation runs.
- `negative-embedding-input-extra-field.jsonl` — the `embedding-identity-body-v1.jsonl`
  record with an `occurrence_id` key added inside the `input` object
  alongside the `body` arm's own `body_content_id`. Before
  `EmbeddingInputV1` carried `#[serde(deny_unknown_fields)]`, this exact
  shape decoded successfully with the stray `occurrence_id` silently
  dropped, so `EmbeddingIdentityPreimageV1::embedding_identity_id` computed
  the same identity as the clean `embedding-identity-body-v1.jsonl` record —
  a selector/digest mismatch was constructible. `deny_unknown_fields` now
  rejects it at decode time.
- `negative-degenerate-generation-pointer.jsonl` — a `GenerationPointerV1`
  record with `generation_sequence: 0` and both digests set to
  `Sha256Digest::ZERO`. It decodes structurally (no unrecognized field), but
  `GenerationPointerV1::validate` now rejects it: unlike every other
  preimage in this module, `GenerationPointerV1` used to check only
  `schema_version`, so this all-zero, uninitialised pointer would validate
  and receive a real `GenerationPointerId` — making a degenerate pointer a
  legal CAS witness for the registry's active-parser-generation anchor.
- `negative-zero-successor-supersession.jsonl` — a `ManifestSupersessionV1`
  record whose `predecessor_manifest_id` is the real, pinned
  `parse-run-manifest-v1.jsonl` manifest ID and whose `successor_manifest_id`
  is `Sha256Digest::ZERO`. It decodes structurally, but
  `ManifestSupersessionV1::validate` now rejects it: `ZERO` is this module's
  sentinel for missing/uninitialised, not a real manifest, so this shape
  would otherwise record a live manifest as superseded by nothing and mint a
  real, addressable `ManifestSupersessionId` for a link to nothing
  (REPLAY-01, fail-closed on missing). The mirror shape (a `ZERO`
  *predecessor*, i.e. minting a link that claims to supersede nothing) is
  covered only in Rust (`supersession_rejects_a_zero_predecessor`), since it
  is the same validation branch and does not need a second frozen fixture.

## Vectors proved only in Rust (not separately fixture-frozen)

The following vectors from the workstream brief are proved by the extensive
`#[cfg(test)]` suite in `chunk_identity.rs` using programmatically
constructed values rather than a separate frozen fixture file, because their
claim is about a *relationship between two records* (determinism, collision,
supersession, dedup) rather than about one record's own byte shape:

- determinism: identical canonical inputs reproduce identical occurrence IDs
  and manifest IDs (`manifest_id_is_deterministic`,
  `occurrence_id_is_deterministic`);
- manifest collision: the same parser key and source representation
  reproducing a different occurrence/body-digest/coverage set classifies as
  `ChunkIntegrityCollisionV1::ManifestOccurrenceSetCollision`, never as a
  legitimate new generation
  (`manifest_reissue_with_same_key_and_source_but_different_occurrences_is_a_collision`);
  a different parser key or source is *not* a collision — it is a new,
  unrelated manifest (`manifest_reissue_with_different_parser_key_is_a_new_generation_not_a_collision`);
- body digest/bytes collision: `classify_body_reuse` first verifies its own
  precondition — that the caller-supplied `retained_digest` actually
  reproduces from `retained_bytes` — and returns `Err`, never a silent
  `Ok(ChunkIntegrityCollisionV1::None)`, for a retained pair it cannot verify,
  even when the candidate happens to equal the (already-inconsistent)
  retained bytes
  (`body_reuse_rejects_an_inconsistent_retained_pair_even_when_candidate_matches_bytes`,
  `body_reuse_rejects_an_inconsistent_retained_pair_against_any_candidate`);
  a verified retained pair with matching candidate bytes is not a collision
  (`body_reuse_with_matching_bytes_is_not_a_collision`). A genuine
  same-digest-different-bytes SHA-256 collision cannot be constructed to
  exercise the `BodyDigestBytesCollision` arm itself — that arm's soundness
  rests on SHA-256 collision resistance, not on a test fixture;
- manifest and supersession `ZERO`-element rejection: `Sha256Digest::ZERO` is
  this module's sentinel for missing/uninitialised, never a real identity, so
  it must never be admitted anywhere an ID gets minted from it.
  `ManifestSupersessionV1::validate` rejects a `ZERO` predecessor
  (`supersession_rejects_a_zero_predecessor`) and — frozen in
  `negative-zero-successor-supersession.jsonl` above — a `ZERO` successor.
  `ParseRunManifestPreimageV1::validate` rejects a `ZERO` element inside
  `occurrence_ids` (`manifest_preimage_rejects_a_zero_occurrence_id`) or
  `body_digests` (`manifest_preimage_rejects_a_zero_body_digest`);
- rechunking: a new parser configuration yields a different manifest and
  occurrence set, linked by an explicit `ManifestSupersessionV1`, while the
  predecessor manifest remains valid, unmutated, historical evidence
  (`rechunking_with_new_parser_config_yields_new_manifest_and_occurrences`);
- stable source-span citation: automatic equivalence requires the same
  source URI and byte-identical ordered spans; a span shifted to a different
  offset is not automatically equivalent even though its length and content
  are unchanged (`stable_source_span_citations_require_identical_spans_and_digests`);
- protection-domain-limited dedup: the same body-content digest under the
  same protection domain always produces the same storage identity; under
  two different protection domains it never does
  (`storage_identity_dedups_within_one_protection_domain`,
  `storage_identity_does_not_leak_equality_across_protection_domains`);
- parser-added headers excluded from body identity: two occurrences whose
  raw spans differ only by whether they include a parser-added header, but
  whose extracted body bytes are identical, share one body-content ID and one
  storage identity while remaining two distinct occurrences
  (`parser_added_headers_are_excluded_from_body_identity`);
- non-contiguous span lists: a two-span list with a large byte gap between
  spans is accepted (`occurrence_accepts_non_contiguous_spans`);
- generation-pointer CAS and late-reclaim: a legitimate `1 -> 2` switch
  succeeds; a late proposal still naming generation 1 as its
  `expected_prior_pointer`, submitted after the pointer already advanced to
  generation 2, fails `checked_against` with `ContractError::StaleRegistryHead`
  rather than reclaiming the pointer
  (`late_old_parser_work_cannot_reclaim_a_since_advanced_pointer`); a proposal
  whose `generation_sequence` does not advance by exactly one is rejected at
  `validate` (`generation_switch_rejects_a_non_advancing_sequence`);
  `AdmittedGenerationSwitchV1` has no `#[cfg(not(test))]`-visible constructor;
- EVID-08 erasure: erasing the last lawful reference to a body flips
  `may_reclaim_shared_storage` from `false` to `true`; erasing one of two
  references leaves the predicate `false`
  (`erasure_removes_occurrence_immediately_and_predicate_flips_when_last_reference_gone`).

## How digests are pinned

Every fixture file's raw SHA-256 (the exact checked-in bytes, LF included)
and its decoded record's identity digest (via the relevant `*_id`/
`*_identity` method, which excludes the LF and any framing this repository
adds around the file) are both hardcoded as `&str` constants in
`chunk_identity.rs`'s test module. A test loads the fixture with
`include_bytes!`, asserts the raw SHA-256 first (so a silent byte-level edit
to the checked-in file is caught even before decoding), then asserts
`canonical::require_canonical` accepts the bytes unchanged (the checked-in
file *is* its own canonical form), decodes it, and asserts the recomputed
identity digest against the second constant.

`vector-suite.jsonl` is pinned the same way for its raw bytes (a hardcoded
`VECTOR_SUITE_RAW_SHA256` constant), but it is not itself a decoded contract
record — it is a restatement, so its trustworthiness depends on every field
it restates being independently cross-checked against a real recomputation,
never merely asserted to decode. `vector_suite_fixture_restates_only_recomputable_digests_and_all_match`
is that cross-check: it decodes `vector-suite.jsonl` as JSON and asserts
every digest field equals either an already-pinned `*_ID` constant or a
value freshly recomputed from a checked-in preimage fixture (`body_content_id`
from `chunk-occurrence-v1.jsonl`'s own field; `generation_2_id` from
`pointer_id()` of `generation-pointer-switch-proposal-v1.jsonl`'s own
`proposed_pointer`), plus the closed `negative_cases` list. It restates no
field that lacks such a source: an earlier draft additionally restated
`parser_key_v2_id`, `occurrence_v2_id`, and `manifest_v2_id` for a
hypothetical "generation 2" parser key, occurrence, and manifest that this
directory has no checked-in preimage for, so no test could ever have caught
those three digests going stale or simply being wrong. They were removed
rather than left as unfalsifiable claims; a real second generation belongs
in its own fixture set once one actually exists.

`vector-suite.jsonl` was refrozen once, honestly, in a closeout fix: only its
`negative_cases` array gained the `"zero_successor_supersession"` entry
(alphabetically ordered, matching the new frozen negative fixture above); no
other field changed. `VECTOR_SUITE_RAW_SHA256` in `chunk_identity.rs` was
recomputed from the new checked-in bytes, not hand-edited.
