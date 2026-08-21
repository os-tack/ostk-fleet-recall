# Evidence v2 admission vectors (W1-EVID)

These records freeze the runtime admission stage that turns one
`EvidenceIngressCandidateV2` into the production `EvidenceStatementV2` the
general accepted-event ledger appends. Every `.jsonl` file holds exactly one
canonical JSON record followed by exactly one LF. The LF is repository framing
and is excluded from every contract digest.

Nothing here is authority. These are inputs and expected outputs of a
derivation. The authority is the writer-authority view read inside the append
transaction (ADR 0002 D4); the vectors only prove that, given one exact active
package and one exact head, admission produces exactly these bytes.

## The active package these vectors are admitted against

`contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl`, bound to
a synthetic head whose `package_digest` is that package's own digest. Binding a
package to a head is the whole point of `ActiveStage4Package`: a candidate can
name a connector, but only the package digest reported by the active head can
prove the named connector is the activated one (AUTH-04, EVID-04).

The canonical redacted payload every vector refers to is the exact byte string

```text
{"provider_event":"push","revision":"sha256:abc"}
```

pinned in Rust as `CANONICAL_PAYLOAD`. It is deliberately not a file in this
directory: it is opaque governed content, not a canonical contract record, and
this directory's rule is one canonical record per file.

## Positive vectors

| file | what it pins |
| --- | --- |
| `ingress-candidate.jsonl` | the asserted, transport-bearing candidate |
| `ingress-locators.jsonl` | the trusted locator coordinates for URI rederivation |
| `admitted-statement.jsonl` | the exact `EvidenceStatementV2` admission derives from the two above |

`admitted-statement.jsonl` is the load-bearing one. It pins, in bytes:

- the scope, which is the credential-bound scope of the active head and never
  the candidate's declared `scope` field;
- both resource URIs, rederived through the activated identity recipes and only
  then compared with what the candidate declared;
- the visibility, retention, and publication classes, read out of the activated
  `classifier.default`, `retention.default`, and `publication.default` bodies;
- `integrity_state: transport_authenticated`, which is the strongest state this
  stage can itself prove and which no input can raise;
- the erasure scopes, derived from the proven source-fact and resource
  identities.

The representation axis is deliberately absent from `erasure_scopes`: the
representation key is derived from that list, so naming it would be a
self-referential preimage. The governed content row leaves all four
`erasure_*_digest` columns NULL for a different reason — a storage identity is
`f(protection domain, content digest)` and therefore deduplicates across
representations and source facts, so no single axis names it. See the
`content_store` module documentation.

## Negative vectors

Each negative is a complete, decodable candidate that differs from
`ingress-candidate.jsonl` in exactly one way, admitted against the same locators
and the same payload. The Rust test named beside it asserts the exact typed
error.

| file | rejection | asserted by |
| --- | --- | --- |
| `negative-payload-scope.jsonl` | `PayloadSelectedScope` | `a_payload_selected_scope_is_rejected_before_any_derivation` |
| `negative-foreign-connector.jsonl` | `ConnectorNotInActivePackage` | `a_connector_outside_the_active_package_is_rejected` |
| `negative-resource-identity.jsonl` | `ResourceIdentityMismatch(CanonicalResource)` | `a_rederived_resource_identity_must_equal_the_declared_one` |
| `negative-storage-identity.jsonl` | `StorageIdentityMismatch` | `the_declared_storage_identity_must_be_the_derived_one` |
| `negative-clock-inversion.jsonl` | `ClockOrder(ObservedBeforeOccurred)` | `the_three_clocks_must_point_the_right_way` |
| `negative-private-raw.jsonl` | `PrivateRawArtifactUnsupported` | `a_private_raw_artifact_is_refused` |

`vector-suite.jsonl` lists every file with its raw SHA-256 plus the derived
identities, and `src/evidence_ledger/admission.rs` pins each of those hashes as
a Rust constant.

## What these vectors deliberately do not cover

- A private raw artifact. EVID-05 requires a separate key, policy, and retention
  boundary for the private raw archive; it does not exist, so a candidate
  offering one is refused rather than stored under the governed key.
- A `version`-form resource whose locator names a parent entity. Deriving the
  parent is a later seam, and guessing it would be the self-asserted identity
  this stage exists to prevent.
- `provider_verified` / `signature_verified` integrity. Those are claims about a
  provider signature this stage does not check, and EVID-04 forbids taking them
  from a payload.

Changing a canonical record, a domain prefix, an expected digest, an outcome, or
an ordering rule is a contract-version change. Prose here is not
identity-bearing.
