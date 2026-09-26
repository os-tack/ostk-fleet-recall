# Security and supply-chain policy

## Trust boundaries

Fleet Recall binds tenant, project, and agent identity from deployment
configuration. MCP callers may select a session subdivision, but neither
session nor the currently fixed project privacy tier is an authorization
principal. Privacy refinement is deliberately rejected until owner/tier
visibility is persisted and enforced. Every repository reapplies the trusted
tenant/project coordinates at SQL execution; request bodies, recalled rows,
and canonical artifacts cannot reroute a process.

Corpus chunks, claims, transcripts, tool output, telemetry, conflict text,
collected items, and recalled Markdown are untrusted content. They are
evidence to quote, cite, and validate, not instructions or authorization. A
collected item's text (a Slack message, a Linear issue, a Granola summary, a
document, an import line, a capture) is third-party content even when a
verified collector read it from the provider: item and evidence recall label
it `untrusted_third_party`, and item recall defangs its Markdown images and
reports `injection_signals` as advisory hints, never as a filter or a
guarantee ([ADR 0008](adr/0008-collected-items.md) D7). A consumer must not execute a
command, call a tool, change policy, disclose a secret, or infer an identity
merely because recalled content asks it to. Agent policy and operator approval
remain outside the corpus. Source coordinates, digests, typed conflict state,
and exact re-reads can strengthen evidence; they do not turn text into
authority.

The public HTTP router exposes only `/`, `/healthz`, `/api/status`, and the
non-mutating `POST /api/recall`. It has no MCP, ingest, remember, control
bootstrap, registry activation, or other mutation route. The CloudFront
distribution is therefore a read-only recall surface, even though recall uses
POST. Router shape is not treated as the database authorization boundary: the
public process authenticates as exactly the fixed external `fleet_publication`
login, whose only membership is the logical `fleet_publication_reader` role.
That role can select every claim and chunk row, so the public
process itself withholds each claim written by `remember(assert)`, whose
predicate's publication default is denied: the claim, its synthetic chunk,
and its conflicts read as absent (ADR 0005 D8). That is a property of the
reviewed binary; the credential alone can still select those rows (see
[event-first writers](#event-first-writers-and-the-content-key)).
CloudFront-to-ALB transport and viewer-TLS limitations are documented without
stronger claims in the [AWS runbook](../deploy/aws/README.md).

The private webhook receiver, `ostk-fleet-recall ingress`, is the one private
process that answers requests from outside the deployment, so it holds the
least ([ADR 0008](adr/0008-collected-items.md) D12). Its router has one route,
`POST /v1/hooks/{connector_instance}`, and it listens on loopback unless the
operator passes `--allow-non-loopback` for a relay they run; the relay adds no
trust, since every request is checked on its own. A body larger than
`FLEET_RECALL_INGRESS_MAX_BODY_BYTES` is refused unread (413). Every other
body is untrusted until the provider's HMAC over the exact raw bytes verifies
under the instance's signing secret, compared in constant time, with a signed
timestamp inside the provider's window (Slack and Granola ±300 s, Linear's
signed `webhookTimestamp` ±60 s); then the delivery must name the instance's
pinned Slack team or Linear organization (a Granola secret is its own pin). A
refusal answers 401, 403, or 400 and records one digest-only dead letter per
instance, reason, and minute, so a flood of bad requests cannot grow the table
faster than that. A verified delivery is a hint, never content: the receiver
keeps the provider's ids, the body's digest and length, and a bounded event
label, deduplicated by the id the provider signed, and discards the text. Only
the worker, with the provider's own API token, re-reads the object, through
the same adapter, redactor, and audience rules as a pull, so even a hint that
should not have been accepted can at most make the worker read what it could
already read. A deletion hint is taken on the signed delivery's word, since
the object is gone, but never mints an item: it tombstones only one the memory
already holds, in the container and thread its head records. A direct or
group-direct Slack conversation is kept only as a replay guard, without ids.
The receiver holds its own `fleet_ingress` login and the signing secrets named
in the sources file, never a provider token, the writer login, or the content
key; its role can insert deliveries and dead letters and read nothing else the
memory holds.

## Offline authority and append-only control state

The private control plane is deliberately absent from normal serving
configuration. Stage 2 verifies an out-of-band-pinned bootstrap receipt against
the supplied genesis package. Stage 3 additionally verifies the
deployment-pinned conformance result and runner artifact/configuration
digests, then verifies a canonical activation statement and its freshly signed
approval set. CLI arguments provide only
bounded canonical artifact paths. Physical scope, semantic scope,
receipt/result and runner digests, and principal bindings come only from
dedicated environment configuration.

The raw receipt digest is checked before its profile or scope is trusted.
Artifacts must be exact canonical records with no unknown fields and must name
the canonicalization profile and vector suite frozen into the binary. A signed
or pinned artifact cannot select a new parser or profile implementation simply
by naming another digest. Replays re-read and revalidate the persisted
canonical bytes and their database projections; partial, orphaned, or
mismatched state is corruption, never an implicit repair opportunity.

The implemented first-successor process preserves the same offline-authority
shape. Its workstation CLI accepts only eight bounded canonical artifact paths;
the dedicated `FLEET_RECALL_SUCCESSOR_*` environment binds its physical and
semantic scopes, bootstrap/genesis/target/runner/bridge pins, principals, and
strict-TLS database URL. It verifies the artifact graph before connecting, then
the repository reauthenticates the one-time bridge and candidate against the
locked durable genesis root inside the serializable generation-0-to-1
transition. This repository/CLI is source capability, not deployed SQL
authority. Its checked-in `fleet_registry_successor_activation` policy creates
only a hardened, database-local `NOLOGIN` logical role; an exclusive login,
temporary membership, and the complete operator audit/enable/use/disable
ceremony remain external and have no AWS or serving path.

Accepted control and activation events are append-only and source-positioned.
Bootstrap/activation transactions use one database acceptance time, scoped
head locking and compare-and-swap, exact event positions and chain digests, and
complete durable predecessor audits. Compound writes execute in one
serializable transaction; only CockroachDB SQLSTATE `40001` retries the whole
operation. Application claim, support, conflict, event, and receipt mutations
follow the same bounded idempotent/serializable rule.

Migrations 3 through 9 add and harden the private control and
genesis-activation projections; migrations 10 through 14 add exact
genesis-root indexes and three durable successor tables; migrations 15 through
17 version conflict uniqueness by detector and add the exact
reconciliation/current-projection indexes; migration 18 adds the Stage-4
evidence plane, governed content store, relation projection, and the
migrator-owned writer-authority view (ADR 0002); and later migrations add
private-plane tables for the dynamic-memory runtimes (see
[MIGRATIONS.md](MIGRATIONS.md)). Normal recall, remember, ingest, MCP, health,
and public-demo paths require an uninterrupted successful prefix through at
least version 18 and remain compatible with later additive migrations. The
private writer serves evidence recall only after a startup probe finds
migration 30 and its read grants, and discrepancies only after one finds 31
and theirs; the memory worker checks migration 30 and every privilege its
steps use before each tick. The private compatibility gates remain control
3, genesis 9, successor repository 14, and conflict reconciliation 16. A
later successful row cannot mask a missing or failed prerequisite in any
gate.

Versions 1 through 11 are nontransactional schema changes; v10 and v11 recover
an interrupted exact index through `IF NOT EXISTS` plus a fail-closed catalog
shape assertion. Versions 12 through 14 run with SQLx bookkeeping in one
transaction on a dedicated session with `autocommit_before_ddl = false`.
Versions 15 onward return to resumable nontransactional online DDL: v15
admits only its exact detector-index transition states and rewrites no conflict
data; v16/v17 commit one covering backfill and assert its exact catalog shape;
v18 creates every new relation with `IF NOT EXISTS`, commits, and then fails
closed with SQLSTATE `55000` unless each one -- including the authority view's
owner and exact definition, and the complete committed constraint set of every
table it creates, so the D1 governance-exclusion CHECK and the event-id UNIQUE
cannot be dropped by an adopted same-name table -- has the shape this migration
defines, so a same-name object is never silently adopted as a successful
version 18.
The dedicated session is closed rather than returned to the runtime pool.
These mechanics establish durable shape, not an application authorization
boundary.

## Identities, URLs, and secrets

The current AWS Terraform defines exactly three planned database credential
paths: a publication-reader URL for the public application task, a private
writer URL for seed/MCP DML, and a distinct DDL-capable migrator URL.
Their three concrete secret ARNs must be pairwise distinct. The public task has
distinct publication execution and task roles and receives only the
publication secret. Its execution policy permits exactly
`secretsmanager:GetSecretValue` on that ARN. When customer-managed encryption
is configured, `kms:Decrypt` is limited to concrete publication-specific CMK
ARNs, `kms:ViaService` is bound to Secrets Manager in the deployment region,
and `kms:EncryptionContext:SecretARN` is bound to the exact publication secret;
those CMKs must be disjoint from the writer/migrator CMK list. The publication
task role can read only the three exact model object ARNs, with no bucket list,
write, or wildcard access.

Terraform does not create CockroachDB identities, memberships, grants, or
authentication material. The externally provisioned `fleet_publication` login
is a member only of the logical `fleet_publication_reader` role, which is
forced to `NOLOGIN`. Its complete positive SQL grant surface is `CONNECT` on
`fleet_recall`, `USAGE` on schema `public`, and `SELECT` on exactly these eight
objects: `_sqlx_migrations`, `memory_corpus_models`, `memory_chunks`,
`memory_claim_embeddings`, `memory_claim_support`, `memory_claims`,
`memory_conflict_members`, and `memory_conflicts`. It has no DML, DDL,
sequence, SYSTEM, private-table, ownership, grant-option, or future-default
authority.

Before every publication-policy apply or reapply, drain the external login and
set it to exact `NOLOGIN`. A cluster admin must audit both publication
principals and inherited PUBLIC authority across every database, freeze role,
grant, default, ownership, and schema-DDL changes, apply
[`publication-reader-role-grants.sql`](../deploy/cockroach/publication-reader-role-grants.sql),
repeat the external audit if the freeze was not continuous, and reapply the
policy immediately before the separate exact authentication-enable operation.
Quiesce and repeat that sequence after every migration or grant change.

The Terraform module has no control-bootstrap, genesis-activation, successor,
or conflict-reconciliation secret, IAM role, task definition, route, or startup
hook. When a private local ceremony runs, each uses a separate SQL login and
dedicated URL; those one-shot credentials are never fallbacks for any deployed
credential and should be disabled or removed afterward.

The successor repository and workstation apply/inspect CLI have a separately
checked-in one-shot
[`fleet_registry_successor_activation` policy](../deploy/cockroach/successor-activation-role-grants.sql).
Only a cluster admin may apply it in the exact `fleet_recall` database after
successful prefix 1 through 14 and after the runtime, control-bootstrap, and
genesis-activation roles are hardened to exact `NOLOGIN`; database ownership
alone is insufficient. The policy creates a `NOLOGIN` logical role with only
`CONNECT`, public-schema `USAGE`, and the exact read/write table surface used by
the successor repository. It grants no sequence, `DELETE`, DDL, SYSTEM,
ownership, grant-option, or unrelated-object authority.

The companion
[quarantine policy](../deploy/cockroach/successor-schema-quarantine-grants.sql)
remains deny-only: after prefix 1 through 14 it revokes every successor-table
privilege from `public`, runtime, bootstrap, and genesis activation and grants
nothing. It does not conflict with the separate successor boundary. Before
every successor-policy apply and use, a cluster admin must drain members and
freeze role, grant, default, ownership, and schema-DDL changes. Clean forbidden
future defaults, including an optional reconciliation role's creator-scoped
PUBLIC routine default, and remove either-direction successor/reconciliation
membership edges. Then enumerate every other database for direct successor-role
grants and ownership and separately inventory inherited PUBLIC authority.
Reapply the successor policy immediately before granting an externally
provisioned login exclusive membership, run the reviewed CLI ceremony, then
revoke membership and disable the login. The SQL file cannot perform the
cross-database audit or provision the login. No AWS task, production-image
binary, startup hook, or public/runtime route exists.

Conflict reconciliation has a different, explicitly implemented one-shot
boundary. Only a cluster admin may apply the database-local policy; database
ownership alone is insufficient. Apply the
[`fleet_conflict_reconciliation` policy](../deploy/cockroach/conflict-reconciliation-role-grants.sql)
after successful prefix 1 through 16 and the three prior logical roles are
hardened. A separately provisioned login may temporarily receive
membership only in that `NOLOGIN` logical role for the apply-only workstation
CLI. The successor role is optional, not an additional prerequisite. Before every
reconciliation apply and use, quiesce members and freeze authority changes. If
the successor role exists, explicitly remove its creator-scoped PUBLIC routine
default and either direction of successor/reconciliation membership. Then
enumerate all other databases for direct reconciliation grants/ownership and
account separately for inherited PUBLIC authority before applying the
reconciliation policy. The reciprocal cleanup-before-audit order is required
before a successor policy apply when reconciliation exists. Both edge shapes
fail closed before policy mutation, but neither SQL file can perform the other
role's conditional default cleanup or the cross-database audit. Remove
membership and disable the login afterward. No Terraform, runtime, image, ECS,
MCP, or HTTP wiring exists.

All database URL surfaces require `postgres`/`postgresql`, a hostname, and a
closed parameter set. Serving and Stage-2 control require exactly
`sslmode=verify-full` outside the explicit local escape; that escape requires
`FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1` and a loopback or Compose-only
`cockroach` host. Genesis Stage-3, successor, and reconciliation URLs ignore the
escape and always require exactly `sslmode=verify-full`. Each private process
uses only its dedicated variable and never falls back to a serving, migrator,
or other ceremony URL. The only additional accepted query parameter is one
bounded absolute `sslrootcert` path. Fragments, duplicate parameters, aliases
such as `options`, routing overrides, relative certificate paths, and unknown
parameters fail closed. Do not set the local escape in cloud or shared
environments. Debug output redacts database URLs, authority pins, and bound
reconciliation scope.

The publication process additionally requires the decoded URL username and
the connected CockroachDB `current_user` to be exactly `fleet_publication`;
private database URL variables are rejected from its environment.
`tests/publication_reader_live.rs` exercises that boundary against a real
CockroachDB database. The ingress receiver likewise requires `fleet_ingress`
on its own `FLEET_RECALL_INGRESS_DATABASE_URL`, pinned on every connection,
and refuses to start beside any other database URL (any variable whose name
ends in `DATABASE_URL`), `FLEET_RECALL_CONTENT_KEK_HEX`, or a provider API
credential a collector's `settings.*_env` names in the sources file it shares
with the worker. A push signing secret is named in the sources
file by an environment variable in the provider's own
`FLEET_RECALL_<PROVIDER>_` namespace, never inline, and never the variable
that holds the provider's API token.

Apply the exact current-object/PUBLIC policies described in
[MIGRATIONS.md](MIGRATIONS.md) and
[CONTROL_BOOTSTRAP.md](CONTROL_BOOTSTRAP.md). Runtime has no control-table
privilege. The private logical roles are non-login, have no admin or SYSTEM
privileges, and receive only the table operations required by their reviewed
one-shot repositories. Re-audit actual migrator default privileges after every
migration; broad `ALL TABLES` or future-object grants would defeat this
boundary.

## Conflict-detector lineage

`same_key_functional_value_v2` is an immutable, proposition-aware contract for
one functional `subject::predicate` key over overlapping half-open intervals.
Different affirmative values conflict; affirmation and negation conflict only
when they name the same exact JSONB value; two negations are compatible. This
is typed proposition comparison, not natural-language inference or a general
set-valued predicate rule.

Rows written by the original `same_key_typed_value` detector keep their
original meaning. Normal v2 writes fail closed on an unreconciled legacy
lineage rather than append to it or relabel it. The reconciliation repository
locks one exact legacy conflict revision, preserves the legacy row and
memberships byte-for-byte, derives a complete bounded v2 pair graph, and
appends a distinct v2 lineage, idempotency receipt, audit event, and any
claim-state transitions atomically. A compatible graph produces a durable
dismissed v2 lineage; it never deletes the legacy evidence.

## Claim and conflict lifecycle authority

`remember(retract)` and `remember(supersede)` are the serving lifecycle
mutations ([ADR 0004](adr/0004-serving-conflict-lifecycle.md)). Their authority
rests on the deployment-asserted `FLEET_RECALL_AGENT`: the stored claim must
name that agent as its actor, have `operator_asserted` origin, be `active` or
`disputed`, and sit at the revision the caller read. A caller-supplied `actor`
is still only an assertion that must match. A claim with no recorded actor can
be retired by no one. A supersede successor is written with the trusted agent
as its actor and must keep the predecessor's kind, normalized key, and
conflict eligibility, so an agent cannot end a dispute by moving its claim
out of the detector's view. No request can name a conflict outcome: the server closes a v2 conflict
only after its own Rust and SQL pair computations agree that no incompatible
lifecycle-current pair remains (apart from pairs an adjudicator dismissed,
below), and it writes the resolution reason from a fixed template, so agent
text never reaches `memory_conflicts`. A close returns each disputed member
that no other open conflict holds to `active` at a new revision, whoever wrote
it; that is the only change it makes to another agent's claim. The optional
audit note stays in the private plane: in the claim event and receipt, and,
for a logged close, in the lifecycle event's cause, which every agent in the
project can read through the conflict's history. Keys with only an
unreconciled legacy lineage are refused rather than changed.

`remember(acknowledge)` and concession `remember(resolve)` extend this without
widening it. Any agent in the project may acknowledge a conflict, including an
implicated one, because an acknowledgement changes only the lifecycle overlay,
never a claim, a conflict row, or the read side. `resolve` retracts only
claims that pass the same owner checks, and it closes the conflict only
through the same detector verification; a pair left anywhere refuses the whole
request, so no agent can end a dispute by retiring another agent's claim
(DISC-03). Anyone may ask the detector to re-verify, since the outcome depends
on data alone (AUTH-03).

Adjudication, `remember(dismiss)` and `remember(waive)`, is the one way an
agent can end or tolerate a dispute it did not concede, so it is off unless
the deployment sets `FLEET_RECALL_CONFLICT_ADJUDICATION=enabled`. Enable it
only where every agent sharing the writer credential may act as an
adjudicator. The ledger refuses both as `adjudication_disabled` without the
switch, and the switch has no effect without the probed lifecycle capability
(startup logs an error). The adjudicator must have authored none of the
conflict's member claims in any episode (`implicated`), and a member with no
recorded actor refuses everyone (`unattributed_member`), because an anonymous
claim could be the adjudicator's own. A dismissal changes no claim's value,
author, or applicability: it closes the conflict row with the closed
`dismissed:<reason_kind>` vocabulary and a fixed reason, returns its disputed
members to `active`, and records the judged pairs, which later re-evaluations
of that conflict leave out. Every writer holding the lifecycle capability
leaves them out, whether or not it serves adjudication: switching
`FLEET_RECALL_CONFLICT_ADJUDICATION` off stops new dismissals and waivers but
does not withdraw recorded dismissals, so a conflict they judged can still
close past them. Such a close writes the resolution kind
`no_undismissed_incompatibility` rather than `no_current_incompatibility`, so
a reader can tell that incompatible pairs remain current. A waiver writes only
its lifecycle event, and its expiry and review time come from the database
clock. The required rationale
of both stays in the private lifecycle log, where every agent in the project
can read it through the overlay and history, and never reaches
`memory_conflicts` or the publication reader. Waivers are not signed and not
bound to an active policy (ADR 0004 D5).

Retract and supersede need no migration and no new grant: the runtime role's
existing `SELECT`/`UPDATE` on `memory_claims` and `memory_conflicts`, `SELECT`
on `memory_conflict_members`, `INSERT` on the two event tables, and its
receipt privileges cover them, and a supersede successor uses exactly the
inserts `remember(record)` already holds. The conflict actions and the
lifecycle overlay also need migration 29's `memory_conflict_lifecycle_events_v1`,
on which the runtime policy grants `SELECT` and `INSERT` only. With no
`UPDATE` or `DELETE`, the runtime cannot rewrite or remove a logged event, and
the publication reader has no grant on the table at all. The writer probes
those two privileges once at startup and serves the conflict lifecycle only
when both are present. Every agent in one deployment shares one
`fleet_writer` credential, so this is authority over agents that run the
reviewed binary with their own `FLEET_RECALL_AGENT`, not cryptographic
workload identity. A holder of that credential can issue the same SQL
directly (see below), including appending lifecycle events with arbitrary
attribution. `FLEET_RECALL_REMEMBER_LIFECYCLE=disabled` withdraws every
lifecycle action and restores the record-only lifecycle surface; a lifecycle
request committed before the switch still replays when its identical request
is retried. The switch does not withdraw `remember(assert)`, which is served
whenever its writer-authority pins verify
([ADR 0005](adr/0005-event-first-assert-and-writer-authority.md) D9),
`remember(capture)`, which `FLEET_RECALL_COLLECTED_CAPTURE` governs
([ADR 0008](adr/0008-collected-items.md) D10), or
`recall(kind=evidence)`, `recall(kind=item)`, and
`recall(action="discrepancies")`, which are served whenever their startup
probes pass. With the switch disabled, a writer whose
pins verify therefore still serves `remember` with the actions `record` and
`assert`, and `assert` still appends `memory.claim.accepted` events.
`tools/list` is the historical record-only list only on a writer that serves
none of them. To withdraw assert, unset the pin group and restart `serve`;
to withdraw capture, set `FLEET_RECALL_COLLECTED_CAPTURE=disabled` (the
default) and restart it.

## Event-first writers and the content key

`remember(assert)`, the memory worker, and `ostk-spec` append accepted events
under the writer authority that `ostk-authority-install` installs
([ADR 0005](adr/0005-event-first-assert-and-writer-authority.md)).

**The installer credential.** `ostk-authority-install` runs the control
bootstrap, genesis activation, and both successor ceremonies once per physical
`(tenant_id, project)` as the schema owner/migrator login, like `migrate`. Its
signatures use the public Ed25519 fixture keys (seeds `0x01` and `0x02`) and
authenticate nothing (ADR 0005 D2; see the
[writer-authority installer](CONTROL_BOOTSTRAP.md#writer-authority-installer)),
so the migrator credential is what decides which registry head a scope gets.
Withdraw it after the run, as after `migrate`. The pins it prints are
integrity anchors, not secrets: each writer verifies the head against its
receipt-digest pin, and a writer given the wrong pins refuses it (`serve`
starts with assert off; the worker's `ingest` and `project` steps and every
`ostk-spec` command but the offline `approve` refuse to run). Distribute them
as configuration nobody else may change.

**One runtime role for every writer.** `serve`, the worker, and `ostk-spec`
all authenticate as `fleet_writer` and so run as `fleet_runtime`; there is no
worker or spec role. A holder of that credential can therefore do anything
any of them does, directly in SQL: append evidence events, write spec
statements, checks, and episode lifecycle events under any principal name,
and upsert worker status rows. A leaked writer login can make an evidence
absence verdict or the spec plane lie, for example by writing a fresh `ok`
status row. The runtime policy keeps the Stage-5 and Stage-6 logs,
statements, checks, receipts, and bodies append-only by privilege (`SELECT`
and `INSERT`, no `UPDATE` or `DELETE`), grants `UPDATE` only on heads,
cursors, projections, the transcript outbox's drain state, the ingress hint
queue's settlement, and worker status for their compare-and-set advances and
`SELECT ... FOR UPDATE` locks, and grants `DELETE` on none of them. It also
grants table-level `UPDATE` on
`memory_content_objects`, because CockroachDB v26.2.3 requires it for the
content store's `SELECT ... FOR UPDATE` dedupe lock, which the worker's
transcript path takes whenever a resumed session file repeats a turn. No
runtime statement updates that table, but the grant lets the writer login
rewrite any governed content row (see
[residual SQL authority](#residual-sql-authority-and-recovery)).

**The worker host.** The host that runs the worker's `ingest` steps holds the
writer login, the content key-encryption key (`FLEET_RECALL_CONTENT_KEK_HEX`),
the `gh` credential its CI step uses, the repositories, and the transcript
files, and is as sensitive as all of them together. The key wraps each
governed content object's data key. The `project` step unwraps them and
writes the bodies in plaintext to `memory_body_objects_v1`, which the writer
login, and so `serve`, reads without the key. Once a body is projected, the
key no longer limits who can read it, and destroying the key no longer erases
it: erasure must also purge the body rows and the lexical and dense rows
derived from them (ADR 0006 D9). Every ingress redacts under one profile
(`REDACTION_PROFILE_VERSION`, profile 3: the six shared shapes plus the
provider shapes, Stripe included): a transcript turn is redacted before the
outbox, a git fact's message, author, committer, and path before its ingress
is built, and the lexical recall text that evidence recall returns is
redacted again before the row is written. Residual: facts are
content-addressed, so a body admitted before profile 3 stays raw at rest;
only its recall text is redacted, on the first worker tick after deploy,
which re-projects every lexical row stored under an older normalization
version (`rows_reprojected`). On that tick the git step also re-walks each
ref from the root, and every historical commit whose text is now redacted
re-presents with a different payload under the same source-fact identity
and lands in quarantine as a `PreimageDisagreement`: expect a one-time
`quarantined` count equal to the number of such commits. Closing that
residual needs supersession or erasure. `ostk-spec check` needs the key too. `serve` needs it
only with `FLEET_RECALL_COLLECTED_CAPTURE=enabled`, which admits captures in
the call; `stage_only` leaves admission to the worker and keeps the key out
of `serve`.

**Agent capture.** `remember(capture)` stores text an agent says it read
elsewhere ([ADR 0008](adr/0008-collected-items.md) D10). Nothing in it is
provider proof: every captured item is `reported`, attested by the
deployment-bound `agent.<FLEET_RECALL_AGENT>` (a claim of the reviewed binary,
not cryptographic workload identity, since every agent shares the writer
credential), never presented over a verified collector's copy, and recalled
as `untrusted_third_party` text. The agent never decides who may read it:
the server admits an item only into a container a verified collector or an
operator import recorded as readable by the project, or into a scope the
operator lists in `FLEET_RECALL_COLLECTED_CAPTURE_SCOPES`, and an agent's
`private` or `dm` hint withholds it. A direct or group-direct conversation
(a container kind such as `slack.im` or `slack.mpim`) is refused whatever
the scopes list. The collector redactor scrubs every item before it is
staged, a refusal keeps only a digest, and the capture's receipt keeps the
request's digest, never its text; that digest (and every delivery id derived
from it) is taken with every secret the redactor finds replaced, so reading
it never confirms a guess of a redacted secret. An order ahead of the clock
is refused, so no capture pins an item's head. A capture cannot withdraw,
re-open, or delete anything, and a URL it reports never takes over the
permalink of an item a collector admitted.

**The publication reader gains nothing.** The event-first plane changes only
the runtime policy. `fleet_publication_reader` keeps `SELECT` on exactly its
eight tables and receives nothing on the accepted-event ledger, the content
store, the body, recall-projection, coverage, connector, worker, normative,
spec, or discrepancy tables, or migration 23's filtered views, whose
publication grant is still deferred. The publication process serves no
assert, capture, evidence recall, or discrepancies.

**Asserted claims and the public demo.** The publication reader does hold
table-level `SELECT` on `memory_claims` and `memory_chunks`, where an
asserted claim's projection and synthetic chunk live, and the only assertable
predicate's publication default is denied. The reviewed demo binary
therefore withholds every claim with an `accepted_event_id`, its synthetic
chunk, and every conflict it belongs to, so the demo may read a physical
project where assert is enabled (ADR 0005 D8). The grant does not enforce
that: the `fleet_publication` credential can select every claim and chunk row
in the database, in every project, asserted ones included. Where asserted
claims must stay unreadable to the holder of that credential, do not serve
the public demo from the same database.

**Claims that cite collected items.** A claim's item citations
([ADR 0008](adr/0008-collected-items.md) D11) are private. Which item,
version, and part a claim cites lives only in `memory_claim_item_links_v1`,
which the runtime role may read and append (never update or delete) and the
publication reader cannot read at all. A `record` citation also writes a
`memory_claim_support` row, which the publication reader can select; that
row holds only `fleet.item`, `item-link`, and a random link id, never an item
id, provider, URL, excerpt, or digest, and the reviewed demo binary drops it
from every claim it returns. An `assert` citation adds the cited parts'
accepted events to the claim's accepted event, which the publication reader
cannot read either. A citation is resolved in the claim's own project only,
so a claim cannot rest on another project's item, and an item the project may
not read (deleted, its container or itself withdrawn, or a version admitted
in a container since withdrawn) is refused rather than cited, whether an
assertion names it through `support_items` or lists its accepted event
directly; one hidden later stays cited, and the private claim get says it
is hidden, without its text.

## Residual SQL authority and recovery

CockroachDB grants table operations, not prepared-statement identities. A
holder of a private writer URL can issue SQL outside the reviewed binary.
That includes rewriting any governed content row: the runtime role holds
table-level `UPDATE` on `memory_content_objects` only because CockroachDB
requires it for the content store's `SELECT ... FOR UPDATE` dedupe lock, and
no runtime statement issues `UPDATE` there (see
[MIGRATIONS.md](MIGRATIONS.md#privilege-separation)). The publication reader
has no write table operation or sequence authority. The
bootstrap role's required raw inserts can occupy an immutable singleton or
plant a detached future offset. The activation role can occupy immutable
activation/head rows or misuse its table-level shard-head update. The unique
predecessor index prevents one class of fork but cannot prove a new event is
the head-authorized append. These credentials are therefore exclusive
ceremony capabilities, not operator shells or general service accounts.

The existing genesis-activation credential is genesis-only. It has no authority
over the successor tables. The successor repository, workstation CLI, and
dedicated logical-role policy are implemented, but they are not an enabled
production successor runtime: there is no deployed login, AWS secret or task,
image binary, startup hook, or route. The migrator/schema owner retains
technical authority and must not be repurposed as the ceremony credential,
with one sanctioned exception: `ostk-authority-install` runs the control
bootstrap, genesis activation, `0 -> 1`, and `1 -> 2` ceremonies under the
migrator login (see
[CONTROL_BOOTSTRAP.md](CONTROL_BOOTSTRAP.md#writer-authority-installer)). Its
signatures use the public fixture keys and prove nothing. From generation 1
onward that is true of every successor: the compiled activation policy's
eligible signers are the fixture keys, so any credential that can write the
successor tables (the migrator, or a `fleet_registry_successor_activation`
login) can activate a successor the compiled packages admit. What
protects an installed physical scope is who holds the migrator and ceremony
credentials, plus each writer's receipt-digest pin. Deployments that need
separated ceremony credentials run the four ceremony CLIs, each under its own
role.

The same holds for spec statements. `ostk-spec activate` verifies approvals
under the active package's activation policy, whose eligible signers are the
fixture keys, so the gate on which specs become normative is the
`fleet_writer` credential, and the author, proposer, approver, and episode
actor principals are unauthenticated payload. `ostk-spec check` runs the
observer under a declaration copied from the genesis admission, so the
executable, dependency-closure, and configuration digests its results and
episodes name are not measured from the binary that ran
([ADR 0007 D10](adr/0007-spec-conformance-chain.md)).

The successor role necessarily has raw `INSERT` and `UPDATE` table authority,
including table-level `UPDATE` for its `FOR UPDATE`/compare-and-swap paths.
CockroachDB RBAC cannot limit that credential to the repository's prepared
statements. Keep its login quiesced outside the exclusive ceremony, repeat the
external audit and policy immediately before membership/use, and treat direct
SQL misuse or a partial projection as corruption requiring an audited forward
repair.

The reconciliation role necessarily has a bounded mix of
`SELECT`/`INSERT`/`UPDATE` on its exact legacy-ledger table set and `USAGE` on
the conflict-ID sequence; CockroachDB also requires table-level `UPDATE` for
its `FOR UPDATE` locks. RBAC cannot restrict a credential holder to the
repository's prepared statements. Keep its login quiesced except for one
reviewed apply, preserve the external cross-database audit/change freeze, and
treat direct-SQL misuse or a partial projection as corruption requiring an
audited forward repair.

The one-shot roles intentionally lack delete and broad repair authority, so an
invalid direct write can wedge a scope. Stop the writer, preserve rows and
logs, inspect canonical bytes, constraints, positions, migration history, and
schema-change jobs, then design a separately reviewed forward repair for the
exact observed state and prove it on a copy. Never silently delete evidence,
rewrite migration history, or teach replay to accept a partial shape.

## Dependency and artifact integrity

The embedding bundle is local, content-addressed, and restricted to three
regular non-symlink files. The runtime verifies the same domain-separated
digest before use and does not resolve a model remotely. Release container
images and release source-linked corpus records use immutable revisions;
Secrets Manager values, database URLs, raw cloud logs, and Terraform state are
not publication-safe artifacts.

## Dependency audit exception

`RUSTSEC-2023-0071` affects `rsa 0.9`, which appears in Cargo's lockfile through
SQLx's optional MySQL driver. This application enables only SQLx PostgreSQL;
`cargo tree --target <deployment-target> -i rsa` and `-i sqlx-mysql` must both
remain empty. There is no fixed `rsa` release listed by the advisory.
The exception is therefore confined to an inactive optional package, not a
linked runtime dependency, and should be removed as soon as SQLx's graph no
longer records it.

Warnings for unmaintained `number_prefix` and `paste` currently arrive through
the disclosed upstream model2vec embedding stack. They contain no published
vulnerability; upgrades remain tracked upstream.
