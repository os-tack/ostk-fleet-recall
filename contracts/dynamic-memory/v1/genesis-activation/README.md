# Genesis registry activation v1 fixtures

These records freeze the genesis-only activation contract. Each JSONL file is
one canonical JSON value followed by exactly one repository-framing LF. The LF
is not part of any digest or signature preimage.

The activation approvals are fresh signatures over the registry-activation
message domain. They are not the signatures from `../bootstrap-receipt.jsonl`;
replaying those bootstrap signatures must fail verification.

The v1 separation-of-duty rule is deliberately the minimum rule frozen in the
architecture: the verified threshold must include at least one eligible
approver distinct from the package author. An otherwise eligible author
approval may still count toward the threshold, and v1 does not separately
exclude the trusted proposer from approval. Deployments needing disjoint
author/proposer/approver role sets must introduce that as an explicit,
versioned activation-policy rule rather than silently reinterpret v1.

The deterministic Ed25519 seeds are the public Stage-1 fixture seeds. These
files and keys have no runtime authority. They must never be deployment pins,
production test receipts, or live registry approvals.

The test-result, approval, statement, receipt, and event domains are frozen by
`vector-suite.jsonl`. Changing their canonical bytes, identities, signatures,
or expected failure cases is a contract-version change.
