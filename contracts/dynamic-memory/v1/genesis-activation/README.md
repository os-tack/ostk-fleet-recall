# Genesis registry activation v1 fixtures

These records freeze the genesis-only activation contract. Each JSONL file is
one canonical JSON value followed by exactly one repository-framing LF. The LF
is not part of any digest or signature preimage.

The activation approvals are fresh signatures over the registry-activation
message domain. They are not the signatures from `../bootstrap-receipt.jsonl`;
replaying those bootstrap signatures must fail verification.

The deterministic Ed25519 seeds are the public Stage-1 fixture seeds. These
files and keys have no runtime authority. They must never be deployment pins,
production test receipts, or live registry approvals.

The test-result, approval, statement, receipt, and event domains are frozen by
`vector-suite.jsonl`. Changing their canonical bytes, identities, signatures,
or expected failure cases is a contract-version change.
