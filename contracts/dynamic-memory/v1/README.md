# Dynamic memory v1 contract fixtures

These files freeze the Stage-1 byte contract. JSON artifacts use one canonical
JSON record followed by exactly one LF as repository framing. The final LF is
not part of the canonical JSON preimage and is never included in a contract
digest. Consumers must reject any other prefix or suffix.

`canonical-profile.jsonl` is the normative descriptor for
`ostk-canonical-json-v1`. Its profile digest is SHA-256 over:

```text
"ostk-canonical-profile-v1" || NUL || canonical_profile_bytes
```

`conformance-manifest.jsonl` is the profile's required conformance set. Its
manifest digest uses the `ostk-test-vector-manifest-v1` domain in the same
domain-separated form. `stage1-vector-suite.jsonl` pins the expected identities
for the resource, evidence, registry, and bootstrap fixtures. The genesis
package contains and semantically closes all 20 required v1 entry kinds; a
manifest-only package must never be presented as genesis authority.

The bootstrap keys are fixtures, not secrets and not authorities. For
reproducibility, their Ed25519 private seeds are respectively 32 repetitions of
bytes `01`, `02`, and `03`. They MUST NOT appear in deployment configuration,
authorize a live registry, or sign runtime data.

`genesis-activation/` freezes the separate Stage-3 request ceremony that may
propose the first active registry head after the Stage-2 bootstrap has been
durably accepted. Its test result, statement, approvals, receipt, and event are
deterministic non-authoritative fixtures. Runtime authority additionally
requires the private repository to re-audit the persisted bootstrap, choose one
database acceptance time, and atomically append the event and install the head.

Changing any canonical JSON record, expected digest, signature, profile rule,
or vector outcome is a contract-version change. Cosmetic prose in this README
is not identity-bearing.
