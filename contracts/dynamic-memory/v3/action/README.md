# Action protocol contract vectors

These fixtures freeze the structural W0-ACT seam: `ActionProposalV1`,
`AuthorizationV1`, `ExecutionRequestV1`/`ExecutionAttemptV1`,
`ExecutionReceiptV1`, and `VerificationV1`. They carry no runtime authority —
the named scope, principals, environments, and states are deterministic test
material. Recommendation, authorization, execution, and verification remain
distinct authorities (ACT-01): the fixtures below never let a shared
"confidence" or "risk" field stand in for a real decision-maker.

## What each vector proves

- `proposal.jsonl` — `ActionProposalV1` for a production deployment rollback.
  Its immutable digest is `SHA-256("ostk-action-proposal-v1" || 0x00 ||
  canonical_bytes)`. `desired_outcome_digest` and `rollback_plan_digest`
  reference off-band structured narrative by content hash rather than
  carrying free-form prose in the typed contract (ACT-02, ACT-04).
- `authorization.jsonl` — `AuthorizationV1` binding the exact proposal
  digest, environment, current/target state, preconditions, scope, expiry,
  and permitted uses named by ACT-02. Its `decision_maker_principal_id`
  differs from the proposal's `proposer_principal_id`; `authorize()` in
  `action.rs` rejects the identical-principal case as self-promotion
  (AUTH-03).
- `execution-attempt.jsonl` — `ExecutionAttemptV1` wrapping an
  `ExecutionRequestV1` (proposal digest + authorization digest + idempotency
  key). `ExecutionRequestV1::attempt_id()` excludes every timestamp and the
  provider request ID, so a retried or timed-out attempt that resupplies the
  same request recomputes the identical `AttemptIdV1` — a timeout never mints
  a new action identity (ACT-03).
- `execution-receipt.jsonl` — `ExecutionReceiptV1` with a `Reconciled`
  outcome and a present `after_state`. `reconcile_receipt()` in `action.rs`
  requires the receipt's `provider_request_id` to equal the attempt's exact
  value before it accepts a `ReconciledExecutionV1` (ACT-03).
- `verification.jsonl` — `VerificationV1` recording a verified metric result
  together with a `Mitigated` conclusion. `mitigation_conclusion` is
  structurally independent of `result`: the test suite also exercises
  `Refuted` + `Mitigated` and `Verified` + `NotMitigated` to prove recovery is
  never conflated with root-cause resolution (ACT-04).
- `vector-suite.jsonl` — raw-pins all five artifacts above and names the
  negative cases exercised by the Rust contract tests in `action.rs`.

## How digests are pinned

Every fixture is canonical JSON (profile `ostk-canonical-json-v1`) with
exactly one trailing LF; `raw_sha256` in the vector suite pins the exact
framed bytes read by `include_bytes!`. `action.rs`'s
`hard_coded_fixtures_match_canonical_vectors` test re-encodes each Rust value
and asserts byte-for-byte equality with its fixture, then re-derives every
identity digest (`ActionProposalDigestV1`, `AuthorizationDigestV1`,
`AttemptIdV1`, `ReceiptIdV1`, `VerificationIdV1`) and the vector-suite's own
`TestVectorManifest` digest, comparing each against a literal hex constant in
the test module. Regenerating these fixtures (`cargo +1.94 test
regenerate_action_contract_artifacts -- --ignored --nocapture` with
`ACTION_VECTOR_OUTPUT` set) is a maintainer-only path; it must be followed by
updating every literal constant in `action.rs`'s test module.

## Invariants exercised

- **ACT-01** — no field on `AuthorizationV1` or `ExecutionAttemptV1` carries
  confidence, trust, or risk; `no_confidence_or_risk_field_can_grant_permission`
  scans their canonical bytes for forbidden substrings.
- **ACT-02** — `AuthorizationV1`'s field set is exactly proposal digest,
  environment, current/target state, preconditions, scope, expiry, and
  permitted uses; `authorize()` binds the exact proposal digest and rejects a
  mismatched one (`wrong_authorization_proposal_digest`).
- **ACT-03** — `revalidate_authorization()` fails closed on a changed current
  state (`stale_current_state_fails_closed`), a changed precondition set
  (`stale_preconditions_fail_closed`), an expired authorization
  (`authorization_expiry_reached`), and exhausted uses (`uses_exhausted`);
  `check_idempotency_reuse()` rejects the same key with a different proposal
  or authorization digest (`idempotency_reuse_different_proposal`,
  `idempotency_reuse_different_authorization`) and accepts it unchanged;
  `timeout_retry_never_mints_a_new_attempt_identity` proves two attempts that
  differ only in timestamp and provider request ID share one `AttemptIdV1`;
  `reconcile_receipt()` rejects a receipt bound to the wrong attempt
  (`receipt_wrong_attempt_binding`), the wrong provider request ID
  (`receipt_provider_request_id_mismatch`), or one that predates the attempt
  (`receipt_predates_attempt`); an ambiguous provider result may only pair
  with `Indeterminate` reconciliation and no `after_state`
  (`ambiguous_provider_result_requires_indeterminate`,
  `reconciliation_state_result_mismatch`).
- **ACT-04** — `mitigation_conclusion_is_independent_of_verification_result`
  proves `Mitigated` coexists with `Refuted` and `NotMitigated` coexists with
  `Verified`; no pure function in `action.rs` derives one from the other.

## How a reviewer could try to break this

Attempt to grant execution by lowering `risk` or adding a `confidence` field
to `AuthorizationV1` — rejected by `deny_unknown_fields` and the forbidden-
substring test. Attempt to skip `authorize()` and hand-construct an
`ExecutionRequestV1` with a self-chosen `authorization_digest` — the type
compiles, but `revalidate_authorization()` and `reconcile_receipt()` still
require it to match a real `AuthorizationV1`'s derived digest, and
`AuthorizedActionV1::open_execution_request` is the only production path that
also proves non-self-promotion. Attempt to reuse an idempotency key for a
different proposal to bypass CAS — rejected by `check_idempotency_reuse`.
Attempt to resubmit a timed-out attempt hoping for a fresh identity — the
identity is invariant under retry by construction.
