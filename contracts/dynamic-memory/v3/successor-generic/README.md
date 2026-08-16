# Generic `N -> N+1` successor registry activation (`N >= 1`)

This directory freezes the pure, repeatable registry-activation contract for
every generation after the one-time `0 -> 1` ceremony, plus the contested-set
record and its resolution. Each JSONL artifact holds one canonical record and
exactly one repository-framing LF; the LF is excluded from contract and domain
digests and included in the literal raw SHA-256 pins. Every seed, key, and
structural byte here is public test material and carries no runtime authority.

## Why this is a different contract from `v2/successor-activation`

Generation zero has no installed activation-policy v2, so the frozen `0 -> 1`
contract borrows verification keys from a deployment-pinned genesis key bridge.
Generation one and later already carry a key-complete `ActivationPolicyEntryV2`
inside the active package, so this contract has:

- **no bridge, no bridge digest field, and no bridge signature prefix.** A
  statement carrying `genesis_successor_key_bridge_digest` is rejected by
  `deny_unknown_fields`; an approval minted under the v1 bridge prefix
  `ostk-registry-successor-activation-approval-signature-v1\0` fails signature
  verification under the v2 prefix
  `ostk-registry-successor-activation-approval-signature-v2\0`.
- **the strong v2 separation-of-duty rule**, not the weaker existential v1 one.
  `ActivationPolicyEntryV2::validate_approval_principal_set`
  (`src/memory_contracts/successor_policy.rs`) is the sole encoding of that
  rule: package author and proposer must be distinct, and neither may be counted
  as an approver. `successor_generic.rs` calls exactly that function; it does not
  restate the rule as a verifier convention.

The **currently active** policy decides eligibility and threshold. The proposed
package's own activation policy is checked for structural closure and installed
into the resulting head, but never authorizes its own activation, so a package
cannot lower the threshold, widen the signer set, or relax separation of duty to
admit itself.

## Digest domains

- `ostk-registry-successor-activation-statement-v2\0`
- `ostk-registry-successor-activation-approval-v2\0`
- `ostk-registry-successor-activation-receipt-v2\0` (the activation ID)
- `ostk-registry-contested-set-v1\0`
- `ostk-registry-contested-resolution-statement-v1\0`
- `ostk-registry-contested-resolution-approval-v1\0`
- `ostk-registry-contested-resolution-receipt-v1\0` (the resolution ID)

Approval signature messages use direct byte prefixes, not digest-enum variants:
`ostk-registry-successor-activation-approval-signature-v2\0` and
`ostk-registry-contested-resolution-approval-signature-v1\0`. Genesis,
first-successor, generic-successor, and resolution signatures are therefore
mutually non-replayable.

## External inputs (read, never rewritten)

| Path | Role |
| --- | --- |
| `../../v2/stage4-successor/registry-package.jsonl` | the generation-1 package |
| `../../v2/successor-activation/activated-head.jsonl` | the frozen generation-1 head |
| `../../v2/successor-policy/activation-policy-v2.jsonl` | the installed activation-policy v2 entry |

`vector-suite.jsonl` pins the LF-inclusive raw SHA-256 of all three under
`external_artifact_pins`, so a silent edit to any of them breaks this suite.

## The frozen chain

`generation-2-package.jsonl` is a real, manifest-verified package holding
exactly one activation-policy v2 entry — the same entry generation 1 installed,
so governance is unchanged while the package changes. Its suite roots are that
entry's own frozen vector roots.

1. **Generation 1 -> 2.** `activation-test-result.jsonl` binds the generation-2
   package digest, both vector roots, the frozen profile and vector manifest,
   the runner artifact/configuration pins, a passing outcome, and a
   microsecond-aligned completion time before `effective_from`.
   `activation-statement.jsonl` binds the frozen generation-1 head *including its
   activation ID*, the currently active policy reference, the target package
   digest, the policy the target installs, the conformance-result digest,
   generations `1 -> 2`, the effective interval, and the trusted proposer and
   package author. `activation-approval-set.jsonl` holds fresh
   principal-sorted Ed25519 approvals from `principal.alice` and
   `principal.bob`, the two eligible signers of the installed policy (threshold
   two). `activation-receipt.jsonl`, `activated-head.jsonl`, and
   `activation-event.jsonl` are deterministic outputs of the verified request
   plus repository server time.
2. **Rollback at generation 3.** `rollback-*.jsonl` activates the **earlier**
   generation-1 package digest as generation 3. This is admissible: reverting
   means appending a new activation for an earlier package digest. No prior
   interval or activation identity is rewritten — `rollback-activated-head.jsonl`
   repeats the generation-1 *package* digest under a brand-new *activation* ID.
3. **Contest.** `contested-rival-*.jsonl` is a second, independently valid
   successor of the same generation-1 head, over the same effective interval,
   proposed and authored by different principals. `contested-set.jsonl` records
   both contenders — each with its own activation ID, statement ID, target
   generation, activated head, proposer, author, and principal-sorted approver
   set — the last common unambiguous head, and that head's policy. That file is
   a **projection**, not an input: `AuditedContestedSetV1::from_durable_audit`
   (crate-private) computes every one of those fields from the contenders'
   audited activations, and `verify_contested_set_resolution` accepts nothing
   else.

   What makes a contender an activation rather than a claim is *not* that its
   statement, receipt, and event agree with each other. The activation ID is a
   digest over the receipt itself, so that agreement is self-anchoring: a wholly
   synthetic triple reproduces exactly as well as a real one.
   `AuditedContenderActivationV2::from_durable_audit` therefore re-runs the full
   `verify_generic_successor_activation` over the persisted request bytes,
   against three pieces of evidence that live outside those artifacts — the
   authorizing `InstalledSuccessorPolicyV2` (whose installed keys every approval
   signature must verify under, at that policy's threshold and under its
   separation-of-duty rule), the `StructurallyClosedSuccessorTargetV2` built
   from the target package's real manifest-verified bytes, and the
   runner-pinned `VerifiedGenericSuccessorTestResult`. Only then are the receipt
   and event admitted, and only by full re-derivation: the receipt must be the
   one that verified request produces (approval attestations, threshold and
   separation-of-duty verdict included) and the event must be the one the
   receipt and the request produce. A package that never passed conformance, a
   policy that was never installed, and an approver set that never signed cannot
   enter a contender at all. `contested_generation` comes from the authorizing
   policy's generation plus one, and `AuditedContestedSetV1::from_durable_audit`
   re-applies that policy to every contender's receipt so a witness minted under
   another policy cannot be carried into this contest. While such a record
   stands the projection is `ambiguous`.
4. **Resolution.** `contested-resolution-statement.jsonl` compare-and-swaps the
   exact contested activation-ID set and selects one member. Its
   `proposer_principal_id` is not taken on the payload's word: verification
   requires it to equal a `ContestedResolutionPrincipalBinding` supplied by
   authenticated configuration, exactly as an activation's proposer must equal
   its `GenericSuccessorPrincipalBinding`. Without that, the no-self-selection
   bar would test a string the requester chose, and a barred contestant could
   drive the resolution by writing a different name.
   `contested-resolution-approval-set.jsonl` is approved under the last common
   unambiguous predecessor policy, and
   `contested-resolution-receipt.jsonl` binds the sorted approval attestations,
   the server-derived threshold, and the self-selection verdict. Minting that
   receipt takes the *re-audited* policy and the *re-audited* contested set, so
   the accepted form cannot exist unless the authority and the contest are still
   what they were at verification time.

## Frozen identities

These are pinned as Rust literals in
`src/memory_contracts/successor_generic.rs`; changing any of them is a contract
version change, never a fixture refresh.

| Identity | Digest |
| --- | --- |
| generation-2 package | `49fb2c6db81008b5ed8acd781e297e7d0a3ed49f6b1ff639618cd7d83296190a` |
| generation `1 -> 2` statement | `64fd15dc659c800496ca3fa598b06a51d605b08788870f7acc1f35380f557bf6` |
| generation `1 -> 2` activation | `0fc0b1e4214c2c9e11f3ee63af05ea46de93e39a02aadd115cecaf4247ac7b31` |
| generation `1 -> 2` accepted event | `2ddccbc871e8b4dd89c503d06fc8341254d6a4a6ec5957bf639ee20262b85597` |
| rollback statement | `c900386b859932a89cb9a221f8675baa46d9b19e37754b12328a1fbc58f96b84` |
| rollback activation | `ac335f07967e0bb8861274984731b835caac5aebb5aca45b56bb05f769f4bcab` |
| rollback accepted event | `cf0352dc993c96ca710e49d521fc51805df532fbdf00ae1988e763b1ac68fb4f` |
| rival statement | `4c82bb9903393f82c3c9f13e9ede86db576856e8aceac02a1f5d6492a8d949e1` |
| rival activation | `a0468c76b84897e6783ca0e0f2c7ef1edc36a8ee00a5cf4e8ee6144ed7fc0118` |
| contested set | `6c5bff5cdc424d44400dfb8f50ec18cf4376605ed47a99893ebe661030c52b82` |
| resolution statement | `97665d1abeb5c33e517d2be2cc4e5ca3d54d39f9700dcc0e80adeb7a268b1410` |
| resolution receipt | `0f42d0373321e061ba3dfb286bc391fbc6fb66726a0afd7fc44fe93b80f01187` |
| positive case manifest | `77e02c9c9565ac6b25c1dc1084a58ae1e8c8b07b62180a8d23bafa9310d8eedb` |
| negative case manifest | `04b82a8819842356925ca00ff032bb86ffecf9708207058ced8fb48fd1a45614` |
| `vector-suite.jsonl` raw SHA-256 | `52de3abd84b961c6c654bfe6d06d39b967533f747420c716a1337a45c1c886f7` |
| `vector-suite.jsonl` manifest digest | `101342044d9080270267c58b7790dc264d8f67d6d8e2d144d03e3afcbbc88519` |

The activation consistency key is
`9921b7e572be77d3e100eb3d3093fb0d8ff4b3b5965f75110c18bfd34479b5ec` under family
`registry.activation` — byte-identical to the one the frozen `0 -> 1` contract
uses, because genesis, first-successor, and generic transitions share exactly
one scope-local ordering stream.

## Invariants proved here

- **AUTH-03 — agents cannot self-promote.** No artifact in this directory can
  mint durable state. `InstalledSuccessorPolicyV2` (the only authority input)
  has a crate-private constructor fed exclusively by a durable audit;
  `receipt_at`, `resulting_registry_head`, and
  `GenericSuccessorActivatedEventV2::from_verified` are crate-private, so an
  accepted receipt, head, or event cannot be built from untrusted bytes.
  `receipt_at` additionally takes a *re-audited* `InstalledSuccessorPolicyV2`
  and re-checks the whole expected head, generation, scope, and governing policy
  against it, so the accepted form cannot exist unless the head presented at
  mint time is still the exact head the statement named. The
  proposed package never authorizes itself, and the author and proposer cannot
  approve.

  For a contest, **both sides** of the no-self-selection comparison are
  authenticated. The barred principal sets are read out of
  `AuditedContestedSetV1`, whose constructor is crate-private for the same
  reason, so nobody can bar a legitimate arbiter by inventing a contender that
  names them, or un-bar a real party by omitting one — naming any principal in a
  contender costs a real threshold-satisfying ceremony under the authorizing
  policy's own keys. The subject being tested is the
  `ContestedResolutionPrincipalBinding`, which comes from authenticated
  configuration rather than from the request payload, so relabelling the
  proposer no longer escapes the bar.

  The rule is exactly this, and is deliberately asymmetric: no contender's
  proposer, package author, **or approver** may *propose* a resolution, and no
  contender's proposer or package author may be counted among its *approvers*. A
  contender's approvers may still approve a resolution. They are eligible
  signers of the last common unambiguous predecessor policy — the authority the
  contest falls back to — and barring them would make a contest between two
  quorum-approved contenders structurally unresolvable whenever that policy's
  signer set is no larger than its threshold, which is precisely the frozen
  fixture's shape.
  `VerifiedContestedSetResolution::receipt_at` likewise takes the re-audited
  policy *and* the re-audited contested set.
  *To break it:* make `InstalledSuccessorPolicyV2::from_durable_audit`,
  `AuditedContenderActivationV2::from_durable_audit`,
  `AuditedContestedSetV1::from_durable_audit`, `receipt_at`,
  `resulting_registry_head`, or `from_verified` public; drop the
  re-audited head argument from either `receipt_at`; let
  `verify_contested_set_resolution` take a bare `RegistryContestedSetV1` again,
  or drop its `ContestedResolutionPrincipalBinding` parameter and read the
  proposer out of the payload; verify approvals against
  `target.activation_policy()` instead of the installed predecessor policy; drop
  either `ActivationPolicyEntryV2::validate_approval_principal_set` call — the
  activation one or the contender re-application in
  `AuditedContestedSetV1::from_durable_audit`.
- **AUTH-04 — normativity is designated.** Only a verified activation produces
  a head, and only a package a registry activation designates is normative. An
  activation event moves the head forward. A contested resolution does not mint
  a head of its own: it selects among heads that activations already produced,
  and it can install no other, because every member of the contest is an
  `AuditedContenderActivationV2` — a persisted request whose approval
  signatures, target package bytes, and runner-pinned conformance result were
  all re-verified under the authorizing policy before the contest existed as a
  value. Mutual consistency among a statement, a receipt, and an event is *not*
  accepted as that proof: the activation ID is a digest over the receipt, so a
  synthetic triple reproduces just as well as a real one. The
  statement binds the exact package digest, the policy that governs it, the
  policy it installs, and the conformance result. A contest is resolvable only
  under the policy of the generation it forks from: `contested_generation` is
  the audited policy's `generation() + 1` (checked_add, fail-closed on
  overflow), derived at audit time and re-checked in
  `verify_contested_set_resolution` and again at receipt mint. A resolution may
  not take effect before the contenders it chooses between. Checking a package
  in proposes it; nothing here activates it.
  *To break it:* let `validate_shape` accept a zero or unbound
  `target_package_digest`; stop requiring
  `statement.target_activation_policy == target.activation_policy()`; let the
  event's `activated_head` name a policy digest other than the target's; let
  `AuditedContenderActivationV2::from_durable_audit` accept a contender on the
  strength of its own three artifacts — drop the
  `verify_generic_successor_activation` re-run, or its
  `StructurallyClosedSuccessorTargetV2` or `VerifiedGenericSuccessorTestResult`
  argument, or either `validate_against` re-derivation; or drop the
  `contested_generation == authorizing_policy.generation() + 1` comparison.
- **REPLAY-01 — semantic projections are rebuildable.** Every identity is a
  domain-separated digest over canonical bytes: replaying the same statement and
  approvals yields the same statement ID, approval IDs, activation ID, accepted
  event ID, and head. `classify_generic_successor_replay` makes exact replay a
  no-op, a differing preimage under one statement ID an integrity collision, a
  differing approval ceremony a conflict, and a differing statement ID stale —
  the same four cases the frozen `0 -> 1` repository seam distinguishes.
  *To break it:* introduce receipt time, delivery order, or any non-canonical
  field into an identity preimage; sort a set at hash time instead of rejecting
  an unsorted one; or collapse two replay classes into one.

## How digests are pinned

`src/memory_contracts/successor_generic.rs` embeds every file here with
`include_bytes!`, regenerates each canonical record from the contract types, and
asserts byte equality. `vector-suite.jsonl` is downstream of every other
artifact: it pins the semantic identities, both independent case-manifest
digests, the exact predecessor/generation-2/rollback heads, and the LF-inclusive
raw SHA-256 of every local and external input. The test additionally recomputes
each file's raw hash and compares it to the suite's own pin, then pins the
suite's raw hash and its `ostk-test-vector-manifest-v1` digest as Rust literals —
avoiding a self-reference inside the suite.

`positive-vectors.jsonl` and `negative-vectors.jsonl` are independent semantic
case manifests. Neither names any generated identity, so they cannot ratify the
artifacts they describe. Regenerate with:

    SUCCESSOR_GENERIC_VECTOR_OUTPUT=<dir> cargo +1.94 test --locked --lib \
      memory_contracts::successor_generic::tests::regenerate_generic_successor_artifacts \
      -- --ignored --exact --nocapture

## Adversarial matrix (`negative-vectors.jsonl`)

| Case | What it proves |
| --- | --- |
| `stale-expected-head` | a statement whose expected head is not the audited current head fails during verification, not only at CAS |
| `stale-head-at-receipt-mint` | a request verified while generation `N` was current cannot mint a receipt once the head has moved on |
| `aba-stale-after-package-digest-returns` | after `A -> B -> A` the head names package `A` again under a new activation ID, so the original proposal is still stale |
| `author-counted-as-approver` | the installed v2 rule bars the package author from approving |
| `approval-below-threshold` | the installed policy's threshold, not the proposed one, is applied |
| `approval-under-uninstalled-principal` | a principal the installed policy does not list has no key here |
| `revoked-signer-key` | a listed principal signing with a rotated key verifies against nothing |
| `approval-under-key-bridge-prefix` | generation `>= 1` accepts no bridge-domain approval |
| `key-bridge-field-in-statement` | a canonical statement carrying a bridge digest is not a generic statement |
| `wrong-scope` | scope comes from authenticated context, never from payload |
| `wrong-generation-step` | `to_generation` must be exactly `from_generation + 1`, and generation zero belongs to the frozen contract |
| `genesis-generation-statement` | `from_generation = 0` is rejected outright |
| `reactivating-the-current-package` | re-activating the exact current package is a no-op, not a transition |
| `contested-resolution-by-a-contestant` | no contested successor's proposer, author, or approver may *propose* the resolution, and no contender's proposer or author may be counted among its approvers (a contender's approvers may still approve — they are the fallback authority) |
| `contested-resolution-proposer-disagrees-with-trusted-binding` | the resolution proposer is an authenticated identity, not a payload label: the same ceremony with the proposer relabelled is rejected before the barred sets are consulted |
| `contested-resolution-set-drift` | resolution compare-and-swaps the exact contested activation-ID set, so a later contender cannot be silently excluded — at verification and again at receipt mint |
| `proposer-counted-as-approver` | the installed v2 rule bars the trusted proposer from approving, symmetrically with the author |
| `fabricated-contested-contender` | a contender naming an arbitrary head, proposer, author, or approver set has no activation to audit and cannot enter a contested set |
| `contested-contender-package-never-passed-conformance` | three artifacts forged *coherently* — statement, receipt, and an event whose head reproduces from that receipt's own digest, signed for by the two really installed keys — still cannot mint a contender, because the audit binds the statement to real package bytes and to a runner-pinned conformance result |
| `contested-contender-approvals-not-derived-from-the-verified-request` | a receipt rewritten to a lower threshold, or naming an approver who never signed, is rejected: the receipt is admitted only if it is the one the re-run verifier derives, and an approval by a principal the installed policy does not list has no key to verify against |
| `contested-contender-head-does-not-reproduce-from-its-activation` | a contender whose activated head, activation ID, or statement does not reproduce from its own receipt is rejected |
| `contested-contender-of-another-predecessor-head` | a genuine activation of a different predecessor head is not a contender of this contest |
| `contested-generation-does-not-follow-the-authorizing-policy` | `contested_generation` must be exactly the authorizing policy's generation plus one |
| `contested-resolution-before-its-contenders` | a resolution cannot claim to take effect before the contest it resolves existed |
| `stale-contested-authority-at-receipt-mint` | the resolution receipt seam re-audits the policy and the contested set, so a moved head cannot mint the accepted form |
