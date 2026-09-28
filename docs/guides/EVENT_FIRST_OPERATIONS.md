# Operating the event-first plane

[Documentation](../README.md) · [CLI](../reference/CLI.md) · [Configuration](../reference/CONFIGURATION.md)

This guide establishes writer authority and puts event-first writers in order.
It is for the operator holding the migrator and writer credentials, not an MCP
client. Run examples from the repository root. Use a private environment for
each role and retain the installer report and content key outside Git.

Before changing an existing deployment, inspect its migration prefix,
authority pins and current worker schedule. The installed local HTTPS profile
already has generation-3 authority and current role policies; its normal
restart, backup and restore procedures are in the
[local operations guide](../../deploy/local/https/OPERATIONS.md).

Assert, the memory worker, the collectors, and the spec chain all append to
the accepted-event ledger under one writer authority per physical
`(tenant, project)`. Run them in this order; [local quickstart](../tutorials/LOCAL_DEVELOPMENT.md)
step 3 establishes the schema; [Using Recall](../tutorials/USING_RECALL.md#7-assert-a-claim-from-two-agents)
step 7 and [Memory pipelines](../tutorials/MEMORY_PIPELINES.md) steps 8 to 10
walk through the writers against that local node. The
[collected-items runbook](../COLLECTED_ITEMS_RUNBOOK.md) adds what running
the collectors and the webhook receiver for real takes.

1. **Migrate.** Run `ostk-fleet-recall migrate` as the migrator using the
   current release. Its embedded schema currently reaches migration 39.
   Migration 36 is the webhook feature gate, not the current deployment
   target. Apply role policies from the same release: they require an exact
   migration prefix ([migration operations](../MIGRATIONS.md)).
2. **Install the writer authority, once per physical scope.** Before you
   retire the migrator credential, run `ostk-authority-install apply` as the
   migrator with `FLEET_RECALL_TENANT_ID`, `FLEET_RECALL_PROJECT`,
   `FLEET_RECALL_CONTRACT_TENANT_NAMESPACE`, and
   `FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE`. It takes the scope to an active
   generation-2 registry head, or with `--target generation-3` to the
   generation-3 collected-items package that collectors, imports, capture,
   and item citations need, and prints one JSON report. Keep its `pins`.
   A scope already at generation 2 moves later with the same command and the
   same pins, which rebases its spec families
   ([Generation-3 rollout order](../MIGRATIONS.md#generation-3-rollout-order-adr-0008-d2)).
   Its signatures use public fixture keys and prove nothing; what protects
   the scope is who holds the migrator credential and the pins each writer
   loads. See the
   [writer-authority installer](../CONTROL_BOOTSTRAP.md#writer-authority-installer).
3. **Apply the runtime policy.**
   [`deploy/cockroach/runtime-role-grants.sql`](../../deploy/cockroach/runtime-role-grants.sql)
   gives `fleet_runtime`, the role of the `fleet_writer` login, everything
   assert, the worker and its collectors, `collect`, evidence and item
   recall, capture, and the spec chain use; see
   [migration operations](../MIGRATIONS.md#privilege-separation). The
   publication reader gains nothing. Where provider webhooks are received,
   also provision the `fleet_ingress` login under
   [`ingress-receiver-role-grants.sql`](../../deploy/cockroach/ingress-receiver-role-grants.sql)
   (`deploy/localstack/ingress-boundary.sh` does it on a local node; see
   [receiving provider webhooks](../reference/COLLECTION.md#receiving-provider-webhooks)).
4. **Export the pins to every event-first writer.** Set
   `FLEET_RECALL_CONTRACT_TENANT_NAMESPACE`,
   `FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE`, and
   `FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST` from the report (and optionally
   `FLEET_RECALL_EXPECTED_ACTIVATION_ID` from its `activation_id`) for
   `serve`, the worker, `collect`, and `ostk-spec`. The worker's `ingest`,
   `collect`, and `project` steps, `collect import` (unless `--no-drain`),
   `serve` with `FLEET_RECALL_COLLECTED_CAPTURE=enabled`, and
   `ostk-spec check` also need `FLEET_RECALL_CONTENT_KEK_HEX`, a
   64-hex-character key. Generate it once per scope and keep it: `project`
   unwraps every object with the key `ingest` or the sink wrapped it under.
5. **Restart `serve`.** It probes once at startup. It serves assert when the
   pins verify, `recall(kind=evidence)` when migration 30 is applied and the
   login may read the Stage-5 tables, `recall(discrepancies)` when
   migration 31 is applied and the login may read the discrepancy, normative,
   and spec tables, `recall(kind=item)` when migration 34 is applied and
   the login may read the collector tables, item citations when migration 35
   is, and `remember(capture)` when `FLEET_RECALL_COLLECTED_CAPTURE` turns it
   on over a generation-3 head. Anything it does not serve stays out of
   `tools/list`.
6. **Schedule the worker.** Run the [memory worker](../reference/WORKER.md) with one
   sources file per scope. Git and CI ingest need a host with `git`, `gh`
   and the repositories, which also holds the content key and writer login.
   The `collect` step reads each collector's
   provider token from the variable its `settings.token_env` names, in the
   worker's environment. `--steps project,embed` can run in the container,
   on the same release as the ingest host. Transcript-only ingest can run
   there too. The local remote-plane CronJob already selects
   `ingest,project,embed` every five minutes with `Forbid`; use
   [worker scheduling](../reference/WORKER.md#scheduling) to coordinate manual
   runs. On standalone hosts, provide a schedule and exclusion that ensure
   one run per scope at a time.
7. **Make specs normative and check commits.** Activate specs only once the
   scope has its head from step 2: a later registry head change
   strands every family activated under the old head
   ([ADR 0007 D11](../adr/0007-spec-conformance-chain.md)), except that
   `ostk-authority-install apply --target generation-3` rebases every spec
   family onto the generation-3 head as it moves the scope
   ([ADR 0008 D3](../adr/0008-collected-items.md)); redraft any draft made
   before the move. Then:
   - `ostk-spec draft` binds byte spans of a spec document at one commit to
     one expectation and writes `proposal.jsonl` and `expectation.jsonl`;
   - `ostk-spec approve`, once per approver, signs the draft offline. The
     active policy's approvers are `principal.alice` and `principal.bob`,
     whose keys come from the public fixture seeds `0x01` and `0x02`, so
     approval is nominal;
   - `ostk-spec activate` verifies the approvals and makes the statement
     normative from its `effective_from`;
   - once the statement is in force and the worker's git step has covered
     the commit, `ostk-spec check` judges it through the worker's sources
     file (see [memory worker](../reference/WORKER.md)). A verified nonconformance opens
     an episode that `recall(discrepancies)` lists. A check appends the spec
     blob's git fact and the observer run as evidence events. The next worker
     `project` step makes the blob fact searchable like any git fact (its
     commit, path, and blob id, not the file's text); the observer run names
     no source version, so the step counts it under `events_unprojectable`
     and it is never recalled as evidence;
   - `ostk-spec episode resolve` or `ostk-spec episode dismiss` closes an
     episode. No check closes one.
8. **Receive webhooks, optionally.** Run
   [`ostk-fleet-recall ingress`](../reference/COLLECTION.md#receiving-provider-webhooks) from an
   environment of its own, holding only `FLEET_RECALL_INGRESS_DATABASE_URL`
   (the `fleet_ingress` login), the scope, and the signing secrets the sources
   file names, behind a relay you run for the providers. The next worker tick
   whose steps include `collect` settles what it received.

## Closing the pre-profile-3 residual

A git fact admitted before redaction profile 3 keeps its raw rendering at
rest (its content object under the key, and its projected body in
plaintext), and every full walk re-presents it redacted and quarantines it
as a preimage disagreement: `recall(status).quarantine` names them, and
`recall(brief)` and the trial notes call that set the worklist. One pass
rewrites them. First follow the
[supersession role gate](../MIGRATIONS.md#at-rest-supersession-gate) and load
`FLEET_RECALL_SUPERSESSION_DATABASE_URL` privately for its dedicated one-shot
login, using `sslmode=verify-full` and the database CA. Replace the scope
placeholders below; retain the worker's authority pins and content key:

```bash
: "${FLEET_RECALL_SUPERSESSION_DATABASE_URL:?Load the dedicated supersession login URL first}"
export FLEET_RECALL_SUPERSESSION_TENANT_ID='REPLACE_WITH_TENANT_UUID'
export FLEET_RECALL_SUPERSESSION_PROJECT='REPLACE_WITH_PROJECT'
# plus the writer-authority pins and FLEET_RECALL_CONTENT_KEK_HEX the worker uses
cargo run --locked --bin ostk-evidence-supersede -- apply --sources sources.json --dry-run
```

Review the dry-run decisions before applying the rewrite:

```bash
cargo run --locked --bin ostk-evidence-supersede -- apply --sources sources.json
```

The dry run prints the decisions (`superseded`, `unchanged_under_profile`,
`skipped_with_successor`, `source_unbound`, `transcript_turns_raw_at_rest`)
and writes nothing. The apply appends, for each raw fact, its redacted
rendering as a `supersedes` successor through the same admission seam the
git ingress uses, and in the same transaction removes the raw body, the
occurrences, spans, lexical, dense, and visibility rows derived from it, its
manifest and generation pointer, and its content object when no other
accepted event shares the digest; `rows_removed` counts them per table and
the raw event row stays as the tombstone. It is idempotent (a second run
reports `skipped_with_successor`), exits 1 if the ledger quarantined a
successor, and runs under the separately privileged `fleet_supersession`
role (`deploy/cockroach/supersession-role-grants.sql`). Like the other
one-shot ceremonies the binary refuses a URL without `sslmode=verify-full`
and has no insecure-local escape, so the insecure quickstart node applies
no policy and cannot run the binary at all: there the pass is reachable only
as the library call (`evidence_supersession::run_supersession`) the
connected proof in `tests/evidence_supersession_live.rs` makes as root.
Afterwards the next full walk reports the facts
`replayed`, a full re-projection counts them under
`events_superseded_erased`, and `recall(status)` reports
`resolved_preimage_disagreements` and stops warning about them. Transcript
turns are counted, not rewritten.

## Acceptance and handoff

After restarting the serving process, inspect `tools/list` and
`recall(status)`: verify the capabilities you enabled report served, the
expected writer authority is present and source failures are understood.
Run one coordinated worker tick and inspect its JSON report before enabling
an unattended schedule. A partial collector read keeps absence `unknown`;
that is a coverage limitation to resolve, not proof that no item exists.

Retain the authority report/pins, the scope's content key, the sources file
and provider-secret names with the deployment's recovery material. Record
who can use the migrator, writer and ingress credentials. Projected body rows
are plaintext even though admitted content objects are wrapped by the key;
key deletion alone does not erase that content. See
[security and recovery limits](../SECURITY.md#event-first-writers-and-the-content-key).
