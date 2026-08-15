# Successor activation-policy foundation

This directory freezes the unwired, contract-only foundation for the first
registry successor. `activation-policy-v2.jsonl` is a complete
`RegistryEntryV1`, not a body-only policy artifact. Its kind is
`activation_policy`, its entry schema version is 2, and the digest named by a
successor registry head is the existing `RegistryEntryV1::digest()` over the
entire entry. The body is key-complete: every eligible governance principal has
one exact nonzero Ed25519 public key, principals and keys are independently
unique, bindings are strictly principal-sorted, author and proposer must
differ, neither may approve, and self-authorization and break glass are
disabled. Structural resolution proves only entry/body agreement; it does not
prove active-package membership or grant authority.

`genesis-successor-key-bridge-v1.jsonl` exists only because the active v1
activation policy names eligible principals without their verification keys.
It binds the frozen canonical profile, trusted tenant/project scope, complete
open genesis head, exact current v1 activation-policy reference, and a key map
whose principal set must equal the semantically closed v1 policy exactly. It is
valid only for generation `0` to `1`. That first transition retains the frozen
v1 existential separation-of-duty rule: the canonical eligible approval set
must meet the v1 threshold and include at least one principal distinct from the
package author. An otherwise eligible author approval may count, and the
trusted proposer is not excluded merely for being proposer. The stronger v2
author/proposer-disjoint rule governs later transitions only after v2 is active.

These public fixture bytes grant no authority. A later private repository seam
must authenticate an opaque deployment pin, resolve and fully re-audit the
immutable genesis package and full root head in the same transaction, verify
fresh approvals under the v1 threshold, and separately prove under its stable
stream lock that generation zero is current and the bridge has never been
consumed before it consumes generation zero and installs the successor head
atomically. Immutable bridge closure deliberately remains re-verifiable after
acceptance so exact replay can audit the historical request without pretending
the bridge is still fresh. Database bytes, artifact bytes, or a caller-
constructed witness cannot replace that trusted path. The contract module
therefore exposes no production constructor for its immutable-genesis witness;
its fixture constructor exists only in tests.

The bridge uses the shared `DigestDomain::GenesisSuccessorKeyBridgeV1` domain,
whose frozen prefix is:

- `ostk-genesis-successor-key-bridge-v1\0`

`positive-vectors.jsonl`, `negative-vectors.jsonl`, and `vector-suite.jsonl`
all use the shared `TestVectorManifest` digest domain. The positive and negative
case manifests do not contain the activation-policy entry digest; the entry
binds those two manifest digests, and the aggregate suite then pins the full
entry and bridge. This directed dependency avoids a self-ratifying hash cycle.

Changing canonical bytes, a prefix, an expected digest, or an outcome is a
contract-version change. Fixture public keys are public test material and must
never authorize a deployment.
