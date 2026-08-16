# Canonical quarantine v1 contract vectors

These fixtures freeze the dead-letter boundary for rejected deliveries. Every
`.jsonl` file contains one canonical JSON record plus exactly one repository-
framing LF. The LF is excluded from `quarantine_id()` and every other
*contract* digest — it is trailing whitespace to the frozen canonicalization
profile's parser, not part of the canonical document — but it is included in
the pinned raw *file* SHA-256 constants below, which hash the file exactly as
it sits in the repository. None of the fixture scope, connector identity,
delivery ID, or digest carries runtime authority — these are structural
assertions, not active-registry or admission witnesses.

## What `QuarantineRecordV1` is, and is not

`docs/DYNAMIC_MEMORY_ARCHITECTURE.md` ("Ingestion and projections") is
explicit that rejected deliveries create only bounded quarantine records and
never enter searchable projections, and that transport delivery IDs
deduplicate ingress attempts only — they are not the semantic-effect key.
"Failure, convergence, and history" adds that invalid signatures,
identity/payload collisions, and unauthorized scope are quarantined before
projection, and the Arrow transport boundary fails closed into quarantine on
unknown schemas, duplicate event positions, oversized batches, or
row/preimage disagreement.

`QuarantineRecordV1` therefore carries exactly: a schema version; an
authenticated tenant/project scope (constructed only through
`AuthenticatedProjectScopeV1::from_trusted_context`, never a payload claim —
EVID-04); the connector principal and instance that produced the rejected
attempt; the transport delivery ID and a bounded attempt count; an optional
best-effort `source_fact_id`/`representation_key` digest pair, present only
when identity could be derived before the delivery was rejected; the
canonical payload's SHA-256 **digest only**, never its bytes; a closed
`QuarantineReasonV1`; one bounded `BoundedDiagnosticV1`; and a `received_at`
timestamp.

There is no dedicated field that can hold the rejected payload's raw bytes
(only its digest, above), no second or payload-selected scope field, and no
"release to projection" affordance of any kind. `#[serde(deny_unknown_fields)]`
means a delivery that tries to add any of those keys is rejected before it
is ever interpreted — the negative vectors below prove exactly that, per
key. `BoundedDiagnosticV1.message` is a bounded, but content-unconstrained,
`String` (up to `MAX_DIAGNOSTIC_MESSAGE_BYTES` = 512 bytes): the type does
not itself forbid a caller from copying payload text or secrets into it, so
"non-secret" is a calling-convention this contract expects trusted ingress
code to uphold, not a type-level guarantee the way the digest-only payload
field is. The searchable-leakage vector below only proves the record's
*structural* fields carry no payload bytes; it does not probe
`diagnostic.message` content.

Two more bounds are enforced by `validate()`, matching the rest of this
crate's identity-bearing durable timestamps and its bounded, non-payload
fields:

- `received_at` must be microsecond-aligned (`is_microsecond_aligned()`,
  i.e. its last three nanosecond digits are `000`), matching
  `evidence_v2`/`remember_v2`/`successor_activation` and the CockroachDB
  writers that reject unaligned timestamps. `quarantine_id()` hashes
  `received_at`'s exact nanosecond text, so an unaligned value that a
  microsecond-precision `TIMESTAMPTZ` column cannot store byte-for-byte
  would make the identity unreproducible from the durably stored row.
- `transport_delivery_id` is capped at `MAX_TRANSPORT_DELIVERY_ID_BYTES` (64
  bytes) by `validate()`, tighter than the generic `HexBytes` newtype's
  4,096-byte ceiling. This field deduplicates ingress attempts, not payload;
  the bound is the leakage guarantee for this field specifically — no more
  than 64 bytes of transport- or payload-controlled data can ever ride into
  a dead-letter record through it.

## Reasons

`QuarantineReasonV1` is a closed, exhaustively matched enum:
`integrity_collision`, `invalid_signature`, `unauthorized_scope`,
`unknown_schema`, `oversize`, `duplicate_position`, `preimage_disagreement`,
`redaction_failure`, `unknown_representation_version`. One positive fixture
exists per reason. Whether `source_fact_id`/`representation_key` are present
varies by reason, and the fixtures are not uniform within the "in between"
group: `unknown_schema`, `oversize`, and `invalid_signature` fire before any
identity could be trusted, so both fields are `null` in those fixtures;
`unauthorized_scope`, `duplicate_position`, and `unknown_representation_version`
carry only `source_fact_id`; `redaction_failure` carries both
`source_fact_id` and `representation_key` (validate() only requires
`diagnostic.redaction_required`, but this particular fixture happens to have
both identity links derivable too); and `integrity_collision` /
`preimage_disagreement` require both, enforced below. The per-fixture
diagnostic message cites the exact invariant or document section it
demonstrates.

Two of these presence rules are not just convention: `validate()` enforces
them and fails closed on a violation (`QuarantineRecordV1::
validate_reason_conditioned_identity`).

- `integrity_collision` and `preimage_disagreement` are only defined
  relative to a source-fact **and** representation identity ("Canonical
  evidence event": "different canonical bytes for the same source-fact and
  representation identity"), so both `source_fact_id` and
  `representation_key` must be `Some` — a record with either missing does
  not decode-then-validate; `validate()` rejects it.
- `redaction_failure` means redaction could not be confirmed complete, so
  `diagnostic.redaction_required` must be `true` on that record; `false`
  contradicts the reason it is attached to and is rejected.

Every other reason carries no enforced presence requirement on
`source_fact_id`/`representation_key` beyond the general "best-effort, `Some`
only when non-zero" rule `validate()` already applies to both fields.

## Identity

`QuarantineRecordV1::quarantine_id()` is:

```
SHA-256("ostk-quarantine-record-v1" || 0x00 || canonical_record_bytes)
```

computed over the record's own canonical bytes, including
`attempt_count` and the diagnostic — two rejections of the same delivery
under different attempt counts, or with different diagnostic detail,
produce distinct dead-letter identities. This identity is a *method*, not a
stored field: unlike a redundant stored digest, it cannot itself diverge
from its own preimage, because there is no field for it to diverge from.
`ostk-quarantine-record-v1` is a closed `DigestDomain` variant added in the
`// --- W0-QUAR domains ---` slot of `src/memory_contracts/digest.rs`.

## Resolution is additive, never a record edit

A quarantined delivery is resolved only by a new accepted event under a
corrected representation, linked back to this record only through
`source_fact_id` when one was recorded. The seal for this rule lives on
`QuarantinedDeliveryV1`, the *durable* dead-letter form — mirroring
`remember_v2::AdmittedRememberStatementV2` — which has a private field, no
production constructor at this contract-only stage, no `&mut self` method,
and no setter of any kind: once a rejection is durable there is no API
surface with which to edit its reason, diagnostic, or any other field.

`QuarantineRecordV1` itself is *not* sealed this way, and is not claimed to
be: like every other pre-admission candidate value type in this crate (for
example `remember_v2::RememberIngressCandidateV2`), every one of its twelve
fields is `pub`, so it is freely constructible and mutable in-process —
`record.reason = ...` and `record.diagnostic.message = ...` compile and are
exercised by this module's own tests before a record is validated and
wrapped. That is expected and consistent with the rest of the crate: the
resolution rule is about what can happen to a record *once it is durable*,
which is exactly the boundary `QuarantinedDeliveryV1` enforces.

## The "cannot become an accepted event or projection input" proof

`QuarantinedDeliveryV1`'s field is private, mirroring
`remember_v2::AdmittedRememberStatementV2`: no production constructor exists
in this contract-only stage, only a `#[cfg(test)]` witness. The
`NotProjectable` marker trait names the narrower and honest claim this
module can actually make — neither `QuarantineRecordV1` nor
`QuarantinedDeliveryV1` implements `From`/`Into` for any type in this crate
today, and neither exposes a method returning an evidence or remember
accepted-event type — and that claim is machine-checked by a source
self-audit test, `source_self_audit_projectable_types_expose_no_conversion`
in `quarantine.rs`, which scans the module's own text (excluding comments)
for exactly those patterns and fails if any appear. A second, separate test,
`not_projectable_marker_is_implemented`, checks only that both types
implement the empty marker trait — that one is a shape check, not a
guarantee check; the self-audit test is what actually enforces the claim.
Rust still has no mechanism to forbid a future conversion impl written
against these public types from some other module in the crate; within this
file, today, "no conversion exists" is compiler-run, not merely
reviewer-facing.

## Vectors

Nine positive fixtures, one per `QuarantineReasonV1` variant:

- `quarantine-integrity-collision.jsonl`
- `quarantine-invalid-signature.jsonl`
- `quarantine-unauthorized-scope.jsonl`
- `quarantine-unknown-schema.jsonl`
- `quarantine-oversize.jsonl`
- `quarantine-duplicate-position.jsonl`
- `quarantine-preimage-disagreement.jsonl`
- `quarantine-redaction-failure.jsonl`
- `quarantine-unknown-representation-version.jsonl`

Five adversarial fixtures, each proving one boundary:

- `negative-raw-payload-field.jsonl` — adds `raw_payload_bytes`; the type has
  no slot for payload bytes, so this is rejected as an unknown key.
- `negative-oversized-diagnostic.jsonl` — a 600-byte diagnostic message,
  decodes structurally but fails `QuarantineRecordV1::validate()` against
  `MAX_DIAGNOSTIC_MESSAGE_BYTES` (512).
- `negative-payload-selected-tenant-field.jsonl` — adds a second,
  payload-declared `payload_declared_scope` object alongside the one
  authenticated `scope` field; rejected as an unknown key rather than merged
  or preferred (EVID-04).
- `negative-missing-delivery-id.jsonl` — omits the required
  `transport_delivery_id` field entirely; fails to decode.
- `negative-release-to-projection-field.jsonl` — adds a
  `release_to_projection` boolean; the type defines no such affordance, so
  this is rejected as an unknown key.

One searchable-leakage property, proven in
`quarantined_record_does_not_contain_the_payloads_canonical_bytes` (Rust
test, not a fixture file, since it must construct the raw payload bytes
in-process to compare them against the canonicalized record): the record's
own canonical bytes never contain the raw payload as a byte substring, and
the payload's digest — rendered as hex — appears exactly once, in
`canonical_payload_digest`, never duplicated into a second, informally
"searchable" location.

`vector-suite.jsonl` is a single canonical JSON summary record pinning the
digest-domain prefix, every positive fixture's file name/reason/
`quarantine_id`, the closed list of negative-case labels, and the leakage
test's name. Its own raw bytes are pinned from Rust exactly like every other
fixture in this directory.

## Digests are pinned, not regenerated

Every fixture's raw file SHA-256 and every positive fixture's derived
`quarantine_id` are hardcoded as Rust `const`s in
`src/memory_contracts/quarantine.rs`'s test module and asserted on every
test run. Changing any canonical record, the digest-domain prefix, or the
byte/attempt-count bounds is a contract-version change, not a fixture
regeneration.
