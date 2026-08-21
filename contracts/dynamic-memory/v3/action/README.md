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
  a new action identity (ACT-03). Its `revalidated_at` equals `started_at`
  (revalidation coinciding with dispatch, the tightest legal case);
  `ExecutionAttemptV1::validate_shape` rejects any `revalidated_at` that
  falls *after* `started_at`, and separately bounds how far before it may
  fall (a declared freshness window), so "immediately before execution"
  (ACT-03) is structural, not narrative.
- `execution-receipt.jsonl` — `ExecutionReceiptV1` with a `Reconciled`
  outcome and a present `after_state`. `reconcile_receipt()` in `action.rs`
  requires the receipt's `provider_request_id` to equal the attempt's exact
  value, its `before_state` to equal the attempt's `revalidated_current_state`,
  and its `scope`/`profile` to equal the attempt's, before it accepts a
  `ReconciledExecutionV1` (ACT-03; scope binding is APPL-01).
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
  mismatched one (`wrong_authorization_proposal_digest`), and separately
  rejects an authorization whose `expiry` outlives its proposal's own
  `expiry` — an approval cannot outlive the intent it approves
  (`authorization_expiry_outlives_proposal_rejected`).
  `revalidate_authorization()` re-checks this same binding at execution time,
  independently of `authorize()`: it rejects an `ExecutionAttemptV1` whose
  `request.proposal_digest` differs from `authorized.proposal_digest`
  (`attempt_declares_unauthorized_proposal_digest`) — a hand-assembled
  `ExecutionRequestV1` (it derives `Deserialize`) naming an unapproved
  proposal is rejected at revalidation even though it never went through
  `authorize()`/`open_execution_request`. `AuthorizationV1::preconditions`'s
  `MAX_PRECONDITIONS` bound is exercised at the exact boundary — 64
  preconditions valid, 65 rejected
  (`authorization_preconditions_exceed_max_rejected`) — rather than only with
  the 2-precondition fixture, which cannot distinguish the bound from a
  looser or tighter one.
- **AUTH-03** — `revalidate_authorization()` takes the `AuthorizedActionV1`
  `authorize()` produced, not a bare `AuthorizationV1`, and rejects unless
  that proof's `authorization_digest` names the exact `AuthorizationV1`
  presented alongside it. This makes a self-authorized authorization
  (`self_authorized_authorization_cannot_revalidate`) and one whose expiry
  outlives its proposal (`authorization_outliving_proposal_cannot_revalidate`)
  structurally unreachable at revalidation, not merely rejected by a
  duplicated check: neither can ever produce the `AuthorizedActionV1`
  `revalidate_authorization` requires, and a legitimately authorized proof
  for a *different*, compliant pairing cannot be laundered onto them because
  the digest cross-check fails. `reconcile_receipt()` mirrors this one stage
  later: it takes the `RevalidatedAuthorizationV1` `revalidate_authorization`
  produced for the exact attempt being reconciled, checked two ways.
  `revalidated.attempt_id` pins the request identity (proposal digest +
  authorization digest + idempotency key), but that identity is deliberately
  invariant across a retry (ACT-03), so it alone does not prove *this*
  `ExecutionAttemptV1`'s observational fields — scope, revalidated current
  state/preconditions/timestamp, provider request ID, started time — are the
  ones that were actually revalidated. `reconcile_receipt()` additionally
  recomputes `ExecutionAttemptV1::revalidation_binding()`, a digest over the
  *entire* canonical attempt, and rejects unless it matches the digest
  `RevalidatedAuthorizationV1` carries from revalidation time
  (`reconciled_attempt_is_not_the_revalidated_attempt`,
  `cross_tenant_attempt_reuses_a_foreign_revalidation`) — so a receipt can
  never close an attempt whose observational fields differ from the one that
  was actually revalidated (`receipt_without_revalidation_rejected`).
- **ACT-03** — `revalidate_authorization()` fails closed on a changed current
  state (`stale_current_state_fails_closed`), a changed precondition set
  (`stale_preconditions_fail_closed`), an expired authorization
  (`authorization_expiry_reached`), exhausted uses (`uses_exhausted`), and a
  mismatched attempt scope/profile (`attempt_scope_or_profile_mismatch_rejected`);
  `check_idempotency_reuse()` rejects the same key with a different proposal
  or authorization digest (`idempotency_reuse_different_proposal`,
  `idempotency_reuse_different_authorization`) and accepts it unchanged;
  `timeout_retry_never_mints_a_new_attempt_identity` proves two attempts that
  differ only in timestamp and provider request ID share one `AttemptIdV1`;
  `ExecutionAttemptV1::validate_shape` rejects a `revalidated_at` recorded
  after `started_at` (`revalidated_at_after_started_at_rejected`) and one
  that precedes it by more than the declared freshness window
  (`revalidation_gap_exceeds_freshness_window_rejected`) — revalidation must
  be immediately before execution, never after it and never stale; the same
  function rejects `revalidated_preconditions` past the `MAX_PRECONDITIONS`
  boundary (`execution_attempt_preconditions_exceed_max_rejected`) and a
  legal-length set that is unsorted or carries a duplicate
  (`execution_attempt_preconditions_unsorted_or_duplicate_rejected`), and
  `ExecutionAttemptV1`/`ExecutionReceiptV1` both reject an unrecognized
  `schema_version`
  (`execution_attempt_schema_version_mismatch_rejected`,
  `execution_receipt_schema_version_mismatch_rejected`) — none of these
  conjuncts was previously isolated from its neighbors by any committed
  vector;
  `reconcile_receipt()` rejects a receipt bound to the wrong attempt
  (`receipt_wrong_attempt_binding`), the wrong provider request ID
  (`receipt_provider_request_id_mismatch`), a `before_state` that does not
  match the attempt's revalidated current state
  (`receipt_before_state_mismatch`), a mismatched scope/profile
  (`receipt_scope_mismatch` — a cross-tenant receipt can never close another
  tenant's attempt), or one that predates the attempt
  (`receipt_predates_attempt`); an ambiguous provider result may only pair
  with `Indeterminate` reconciliation and no `after_state`
  (`ambiguous_provider_result_requires_indeterminate`,
  `reconciliation_state_result_mismatch` — a representative sample of the
  invalid `(provider_result, reconciliation_state, after_state)` combinations
  outside the three closed cases is exercised directly (`Success` marked
  `Failed`, `Failure` missing `after_state`, `Success` missing `after_state`,
  and `Ambiguous` coerced to `Failed` in the sibling test); the full invalid
  space is larger and is excluded by the closed `match` in
  `ExecutionReceiptV1::validate_shape` by construction rather than by an
  exhaustive per-triple vector), and `ExecutionReceiptV1::validate_shape`
  separately rejects
  a zero `completion_digest`
  (`execution_receipt_completion_digest_zero_rejected`).
- **ACT-04** — `mitigation_conclusion_is_independent_of_verification_result`
  proves `Mitigated` coexists with `Refuted` and `NotMitigated` coexists with
  `Verified`; no pure function in `action.rs` derives one from the other.

## How a reviewer could try to break this

Attempt to grant execution by lowering `risk` or adding a `confidence` field
to `AuthorizationV1` — rejected by `deny_unknown_fields` and the forbidden-
substring test. Attempt to skip `authorize()` and hand-construct an
`ExecutionRequestV1` with a self-chosen `authorization_digest` — the type
compiles, but `revalidate_authorization()` requires an `AuthorizedActionV1`
as a *separate, non-optional* argument from the `AuthorizationV1` it
revalidates, cross-checked by digest, and the only way to obtain that value
is a successful call to `authorize()`. `AuthorizedActionV1::open_execution_request`
remains the production path that mints a matching `ExecutionRequestV1` from
it directly.

Attempt to launder a self-authorized authorization (AUTH-03), or one whose
expiry outlives its own proposal (ACT-02), through revalidation by pairing
it with an `AuthorizedActionV1` obtained from a *different*, compliant
proposal/authorization pair — rejected, because `revalidate_authorization`
checks `authorized.authorization_digest` against the exact `AuthorizationV1`
presented, and a self-authorized or expiry-outliving authorization was never
the one that produced `authorized` in the first place
(`self_authorized_authorization_cannot_revalidate`,
`authorization_outliving_proposal_cannot_revalidate`). Attempt to close a
receipt for an attempt that was never actually revalidated by supplying a
`RevalidatedAuthorizationV1` minted for some *other* attempt — rejected by
`reconcile_receipt`'s `revalidated.attempt_id == attempt.attempt_id()` check
(`receipt_without_revalidation_rejected`). Attempt the narrower version of
the same laundering: hold a genuine `RevalidatedAuthorizationV1`, then hand
`reconcile_receipt` a *different* `ExecutionAttemptV1` that shares the exact
same request (so `attempt_id` still matches) but carries a tampered scope,
`revalidated_current_state`, `provider_request_id`, or timestamps — such as
a cross-tenant scope or a pre-state the proof never actually revalidated —
rejected by `reconcile_receipt`'s second, independent check, which
recomputes `ExecutionAttemptV1::revalidation_binding()` (a digest over the
entire canonical attempt) and rejects unless it matches the digest
`RevalidatedAuthorizationV1` recorded at revalidation time
(`reconciled_attempt_is_not_the_revalidated_attempt`,
`cross_tenant_attempt_reuses_a_foreign_revalidation`). `attempt_id` alone
cannot catch this: it is derived only from the request (proposal digest +
authorization digest + idempotency key) and is deliberately invariant across
a retry that resupplies that same request (ACT-03), so it never encodes any
observational field. Attempt to reuse an idempotency key for a different
proposal to bypass CAS — rejected by `check_idempotency_reuse`. Attempt to
resubmit a timed-out attempt hoping for a fresh identity — the identity is
invariant under retry by construction.

Attempt to hand-assemble an `ExecutionAttemptV1`/`ExecutionRequestV1` that
binds the *right* authorization digest but declares a *different*
`proposal_digest` than that authorization actually approved — rejected by
`revalidate_authorization`, which independently re-checks
`attempt.request.proposal_digest == authorized.proposal_digest`; matching
only the authorization digest is not sufficient, exactly because
`ExecutionRequestV1` derives `Deserialize` and can otherwise be
hand-assembled. Attempt to record a revalidation *after* execution already
started, or one so far before it that it is no longer meaningfully "before
execution" — both rejected by `ExecutionAttemptV1::validate_shape`. Attempt
to smuggle an oversized, unsorted, or duplicated precondition set past
either `AuthorizationV1` or `ExecutionAttemptV1`, or an unrecognized
`schema_version` past `ExecutionAttemptV1`/`ExecutionReceiptV1`, or a zero
`completion_digest` past `ExecutionReceiptV1` — every one of these now has
an exact-boundary or exact-value vector, not only the always-valid 2-item
fixture. Attempt to close an attempt with a receipt whose `before_state`
names a different pre-state than what was actually revalidated, or whose
`scope` names a different tenant/project than the attempt's own — both
rejected by `reconcile_receipt`, so neither a rewritten CAS history nor a
cross-tenant receipt can produce an accepted `ReconciledExecutionV1`.
Attempt to approve a proposal with an authorization that stays valid after
the proposal's own declared expiry — rejected by `authorize`.
