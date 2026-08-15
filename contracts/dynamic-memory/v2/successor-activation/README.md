# First successor registry activation

This directory freezes the pure generation `0 -> 1` registry-activation
contract. Every JSONL artifact contains one canonical record plus exactly one
repository-framing LF; the LF is excluded from contract/domain digests and is
included in the literal raw SHA-256 pins. The fixture seeds and structural
bytes are public test material and carry no runtime authority.

The contract has three deliberately separate authority layers:

1. The public statement commits the frozen profile, trusted project scope,
   complete open predecessor head (including its activation ID and effective
   interval), exact active-v1 policy, Stage-4 package and key-complete v2
   policy, pinned conformance result, one-time genesis key bridge, generation
   `0 -> 1`, effective time, trusted proposer, and trusted package author.
2. Fresh Ed25519 approvals use the bridge's exact active-v1 principal/key map,
   threshold, and existential package-author-independence rule. The target v2
   policy is installed in the resulting head and is used only for later
   transitions; it cannot reinterpret the `0 -> 1` ceremony retroactively.
3. Verification returns an opaque but non-durable request. Immutable bridge
   pin closure can be repeated when auditing an accepted historical request,
   but grants no freshness. For a new insertion, a repository must lock and
   re-audit the exact predecessor head, active genesis package and policy,
   persisted predecessor acceptance time, current generation zero, and the
   unconsumed bridge in the same transaction as its compare-and-swap. Only then
   may repository code call the crate-private receipt, event, and resulting-
   head constructors.

The frozen target package digest is
`16f98d5df93b74dab5b2188274cbd1da21d089ff7a64cd8fc29679946e7fe2c9`;
its installed v2 activation-policy entry digest is
`5611a4fea75d0a8132395bf6e3040ce97638a3447e290f5cabc183c1bb9faa6c`.
The deployment-pinned bridge digest is
`e15309eba5118e21996a7cee6b3780c1a237982bdf4f22460bca4da189ef6592`.
The target conformance result commits that package, its positive and negative
vector roots, the frozen profile/vector manifest, runner artifact and
configuration, passing outcome, and a microsecond-aligned completion time.
The public fixture runner pins are respectively
`a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1`
and
`a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2`;
deployments must supply their corresponding out-of-band trusted pins rather
than deriving them from result bytes.

`accepted_at` comes only from repository server time. All persisted timestamps
use canonical UTC with nine fractional digits and must round-trip CockroachDB's
microsecond precision. `effective_from` is strictly later than the predecessor
head's effective start, no earlier than the predecessor's trusted acceptance
time, no earlier than test completion, and no later than successor acceptance.
The first successor head is open-ended; a requested expiry fails closed.

Genesis and successor events share the scope-local `registry.activation`
consistency stream. Statement, approval ID, and receipt identities use the
shared closed digest domains:

- `ostk-registry-successor-activation-statement-v1\0`
- `ostk-registry-successor-activation-approval-v1\0`
- `ostk-registry-successor-activation-receipt-v1\0`

Approval signatures use the distinct direct Ed25519 message prefix
`ostk-registry-successor-activation-approval-signature-v1\0`. It is not a
digest-enum variant. Genesis statement/signature bytes therefore cannot be
replayed as successor identities or approvals.

The checked-in artifact graph is acyclic and non-self-ratifying:

1. `positive-vectors.jsonl` and `negative-vectors.jsonl` are independent
   semantic case manifests; neither names any generated activation identity.
2. `registry-test-result.jsonl` commits only the already-frozen Stage-4 package
   and its own package-conformance vector roots, never the activation manifests.
3. `activation-statement.jsonl` commits the test-result, target-package,
   target-policy, predecessor-head, and bridge digests.
4. `activation-approval-set.jsonl` contains principal-sorted fresh signatures
   over the successor-only statement ID.
5. `activation-receipt.jsonl`, `activated-head.jsonl`, and
   `activation-event.jsonl` are deterministic outputs of the verified request
   plus repository server time.
6. `vector-suite.jsonl` is downstream of every other artifact. It pins all
   semantic identities, both independent case-manifest digests, the exact
   predecessor/resulting heads, and LF-inclusive raw hashes for generated and
   external target/bridge preimages. Rust alone pins the suite's own raw and
   domain digests, avoiding a self-reference.

The adversarial matrix covers genesis-signature replay; full predecessor
activation-ID drift; current-v1 policy, target package, target policy, bridge,
test-result and runner-pin drift; non-microsecond or prematurely effective
times; unknown principals, wrong keys/signatures, non-canonical signer order,
insufficient threshold; package-author independence and receipt separation-of-
duty tampering; wrong generation; and altered receipt/event/head bindings. An
author-only approval set is rejected even before durable authority can exist.
