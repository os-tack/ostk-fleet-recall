# Connected CockroachDB proof substrates

## Authoritative official process

Connected correctness is authoritative only when it runs against the official
CockroachDB `v26.2.3` binary. The official process accepts only an already
verified binary; the Linux AMD64 release archive has frozen SHA-256
`3eca6d7bc6fefa3ba0847e89733fc69f61226c80b8fab0af6578e1be672f27d3`,
and `cockroach version --build-tag` must equal `v26.2.3` exactly.
`registry-activation-cli.sh` repeats the build-tag check and owns one secure
local CockroachDB server process for the complete proof.

Every opt-in Rust test is first found by an exact line match in the applicable
`cargo test --locked ... -- --list` output. The wrapper then invokes only that
name with `--exact` and binds the required live URL on that same command. A
renamed, filtered, zero-test, or environment-skipped invocation therefore
cannot count as connected success.

| Connected surface | Exact test target | Required live URL |
| --- | --- | --- |
| Stage-2 control repository | `--test control_log_live` / `live_stage2_genesis_repository_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Genesis Stage-3 repository | `--test registry_activation_live` / `live_genesis_registry_activation_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Successor repository | `--test successor_activation_live` / `live_first_successor_activation_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Current-projection whole-unit retry | `--lib` / `ledger::cockroach::tests::live_current_projection_whole_unit_retry_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Current-projection snapshot race | `--lib` / `ledger::cockroach::tests::live_current_projection_snapshot_race_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Functional-polarity conflict matrix | `--lib` / `ledger::cockroach::tests::live_conflict_polarity_matrix_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Conflict-detector reconciliation | `--lib` / `ledger::reconciliation::tests::live_reconciliation_is_inert_without_its_exact_database_url` | `FLEET_RECONCILIATION_TEST_DATABASE_URL` |
| Online-index interruption recovery and drift rejection | `--lib` / `store::cockroach::tests::live_online_index_migrations_recover_and_reject_drift_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Transactional-DDL rollback | `--lib` / `store::cockroach::tests::live_transactional_migration_rolls_back_ddl_on_history_conflict_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Claim ledger conflict, replay, and transaction lifecycle | `--lib` / `ledger::cockroach::tests::live_claim_conflict_and_replay_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Store migration, cast, and index-lane round trip | `--lib` / `store::cockroach::tests::live_cockroach_round_trip_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Dense retrieval uses the C-SPANN vector index | `--lib` / `store::cockroach::tests::live_cockroach_dense_plan_uses_vector_index_when_configured` | `FLEET_RECALL_TEST_DATABASE_URL` |
| Publication reader recall/deny boundary | `--test publication_reader_live` / `publication_reader_executes_the_real_recall_surface` | `FLEET_RECALL_PUBLICATION_DATABASE_URL` plus the mode-0600 test-only admin secret-file path |

The same isolated server also exercises all four private workstation CLIs:
inspect/apply/replay for control and genesis activation; offline artifact
binding, pre-genesis and failed-prefix rejection, then
`Ready`/`Inserted`/`Accepted`/`ExactReplay`/`Stale` for successor activation;
and materialize/exact replay for apply-only conflict reconciliation. It
requires exactly 18 successful SQLx rows with versions 1 through 18, the three
successor authority tables, the two genesis-root indexes, and the exact indexes
introduced by migrations 15, 16, and 17. The retired pre-v15 conflict
uniqueness index must be absent. The proof replays the resumable
index-transition bytes, exercises online recovery, and shows that failed
migration 12 is not masked by successful migration 18.
Migrations 15 through 17 add or replace indexes rather than successor tables,
and migration 18 adds only evidence-plane, content, projection, and
writer-authority objects, so the exact successor table set remains the three
tables introduced by migrations 12 through 14.

The successor CLI portion first cross-wires the approval set's top-level
statement ID and every approval statement ID to prove exact artifact binding
fails before an unreachable database URL is used. It then opens two bounded
role-membership windows separated by genesis activation and fresh fixture
emission: the first proves pre-genesis `NotReady` and migration-14 failure
without changing the seven-table successor-state fingerprint set; the second
proves the current state matrix and timestamp/control/legacy invariants. Membership is
absent between and after those windows. Final cleanup revokes it, restores
`NOLOGIN`, clears the login password, proves authentication fails, and requires
no successor membership residue.

That exact 1-through-18 assertion freezes the current HEAD release; it is
distinct from the serving compatibility floor, which accepts a complete
successful prefix of at least 18.

These current-release assertions do not widen the private compatibility gates:
Stage 2 still requires the complete successful prefix through 3, genesis Stage
3 through 9, the successor repository through 14, and conflict reconciliation
through 16.

The successor repository test and successor CLI matrix are distinct checks
inside the same one-server result; do not report either as a separate server
result. The checked-in `fleet_registry_successor_activation` role policy is a
short-lived, exclusive credential boundary, not a deployment route. Conflict
reconciliation and its logical role are likewise one-shot workstation
surfaces. None of the four private CLIs has an AWS, Terraform, task, production
image, runtime, startup, or server-route surface; the production image excludes
all four.

Run the authoritative proof with an already checksum-verified binary:

```bash
FLEET_RECALL_CRDB_BINARY=/absolute/path/to/cockroach \
  ./deploy/cockroach/tests/registry-activation-cli.sh
```

At clean source commit
`cd6ecfca2c1a6d112ba058aad899a21aa34bb0f4`, this exact TLS wrapper passed
against official `v26.2.3`, including its absolute-final PUBLIC-03 phase and
the real publication recall/deny product test. The independently packaged
`publication-reader-role-grants.sh` Docker RBAC proof also passed. These are
local official-binary and Docker results, respectively, not evidence that the
current publication role, principal, grants, or Terraform changes were deployed
to AWS. The separate accepted
[LocalStack production-image receipt](../../../docs/evidence/localstack-publication-cd6ecfc-20260816.json)
is likewise explicitly local and insecure.

## Result accounting and Docker parity

The complete official matrix above shares one CockroachDB server process and
produces one authoritative official-binary result. Its individual test rows are
not separate server results, and neither the process nor its result may be
counted as Docker evidence.

| Reported result | Substrate and scope | Relationship to authority |
| --- | --- | --- |
| Official-binary correctness | One checksum-pinned, build-tag-pinned TLS `v26.2.3` server running the complete matrix and all four private CLIs | The single authoritative connected result |
| Control RBAC parity | `control-role-grants.sh` in its own Docker container | Secondary packaging/RBAC result only |
| Activation RBAC parity | `registry-activation-role-grants.sh` in its own Docker container | Secondary packaging/RBAC result only |
| Successor-activation RBAC parity | `successor-activation-role-grants.sh` in its own Docker container | Secondary packaging/RBAC result only |
| Conflict-reconciliation RBAC parity | `conflict-reconciliation-role-grants.sh` in its own Docker container | Secondary packaging/RBAC result only |
| Runtime-writer RBAC parity | `runtime-role-grants.sh` in its own Docker container | Secondary packaging/RBAC result only |
| Publication-reader RBAC parity | `publication-reader-role-grants.sh` in its own Docker container | Secondary packaging/RBAC result only |
| Control bootstrap CLI parity | `control-bootstrap-cli.sh` in its own Docker container | Secondary packaging/CLI result only |

Each Docker proof requires the running server's build tag to equal `v26.2.3`.
That confirms image-version parity, but Docker parity cannot substitute for the
checksum-pinned official-binary correctness proof. Report the authoritative
result and each Docker parity result separately; do not summarize one substrate
as evidence that another passed. Every script owns bounded temporary state and
cleans it on success, failure, or interruption.

The runtime-writer parity proof freezes the reviewed source snapshot
underpinning the current matrix before Docker starts; it does not claim
unreviewed future reachability. Its exact SHA-256 inputs are `config.rs`
`66e14beaa4faf10d26e9ebfdc3e079cdfc7dcf2f7c777eb04b9b48676747f33a`,
`main.rs` `7084682294585060cf1350e5c74ba2c5676c6d06c7eb39929aa7878b5a37f983`,
`private_postgres.rs`
`7718c15393872a139956732629c472d813a2a014395f943a5382191966162745`,
`store/cockroach.rs`
`586f6c9c935140de9580e4b4490df3fc24a9f30e9f4c6c6bf1e194c6e6fc9d1e`,
`ledger/cockroach.rs`
`b8c3ffbd3dfe7a74f76a06815f317db3e79b3129adaa14e2da5bea43f60b069f`,
`service.rs` `6f0c6874072baed1070204063ac65df0761eda2da862e51775ba85cc5a34b522`,
`application.rs`
`5c1707702371016d7d35a58ffe8179e6015d48564e12e36df81cfc8b2c5f5e70`,
and `reference_agent.rs`
`2bfc742926ef753ee90458a294bb59dbddf2afa2e9983484548f2fe0b7b77d26`.

The exact logical `fleet_runtime` matrix is database `CONNECT`, public-schema
`USAGE`, 42 table-privilege rows, and `USAGE` on only the claim, support, and
conflict ID sequences (47 rows in total). Sixteen of those table rows are the
Stage-4 evidence plane of ADR 0002 D2 as amended on 2026-08-16:
`SELECT`/`INSERT` on `memory_evidence_events`, `memory_evidence_quarantine`,
and `memory_content_objects`, `SELECT`/`INSERT`/`UPDATE` on
`memory_evidence_shard_heads`, `memory_relation_projection_v1`, and
`memory_relation_projection_watermarks_v1`, and `SELECT` on the
migrator-owned view `memory_writer_authority_v1`. The connected proof creates
`memory_evidence_shard_heads` and `memory_evidence_events` from the real
migration-0018 text rather than from foreign-key-free stand-ins, then executes
the lazy head seed, one accepted-event append, and the head CAS advance as
`fleet_writer`; an event under an unseeded head must be rejected by the real
`memory_evidence_event_head_fk`. That fixture is why this class of failure
cannot pass again: migration 0018's head table carries no foreign key to any
control or registry parent, because CockroachDB v26.2.3 would then demand a
control-table `SELECT` grant from the appending role. Active chunk upsert has `SELECT`/`INSERT`/`UPDATE` on
`memory_chunks` plus only the keyed `DELETE` on `memory_chunk_history` and the
`SELECT` CockroachDB requires to evaluate that `DELETE`'s `WHERE` clause; the
connected proof issues that keyed `DELETE` as `fleet_writer` and requires it to
succeed.
The production-shaped receipt reservation omits all three nullable FK keys;
the proof revokes only claim-link `SELECT`, requires that same reservation to
fail naming `memory_claim_links`, then reapplies the policy and requires it to
succeed. Adjacent verbs and control, registry, attention, claim-link-event,
claim-link-sequence, DDL, role, system, ownership, default, direct-principal,
and PUBLIC authority are denied. Exhaustive external helpers enumerate every
database and application schema, subject/PUBLIC current and future grants,
database/schema/relation/function/type ownership, and cluster-global external
connections before an audited LOGIN and at the terminal boundary. The fixed
external `fleet_writer` is quiesced as exact `{NOLOGIN}` for policy application
and inherits one non-admin leaf edge. Static-only mode exits before installing
Docker cleanup or invoking Docker. This Docker lane remains secondary evidence;
it does not assert application to LocalStack or AWS.

The control and activation RBAC proofs apply migrations 3 through 14 over
explicit stand-ins for the legacy v1/v2 objects, then synthesize the complete
successful SQLx history 1 through 14. They retain the private commands' narrower
semantic preflights (bootstrap through 3, genesis activation through 9), inject
successor-table privilege and grant-option drift, then apply and reapply
`successor-schema-quarantine-grants.sql`. That dedicated policy first requires
all migration rows 1 through 14 to exist and be successful; only then does it
statically revoke every privilege on the three new authority tables from
`public`, runtime, bootstrap, and genesis activation. It is separate because
CockroachDB v26.2 cannot conditionally execute privilege DDL inside PL/pgSQL,
while the two base role policies must remain applicable at their original v3/v9
deployment stages. These Docker policy-compatibility proofs do not claim the
current exact prefix through 18.

The successor-activation RBAC proof is a separate secondary Docker result for
the admin-only `fleet_registry_successor_activation` policy. It uses
privilege-shaped stand-ins for the ten reachable authority tables; repository
correctness remains in the authoritative official-binary Rust row. Static
extraction freezes the production successor and shared-witness SQL at exact
two-part `public.*` qualification, the schema check's leading
`pg_catalog.current_database() = 'fleet_recall'`, the direct
`SELECT`/`INSERT`/`UPDATE` targets, the two shared read-only control tables, and
the absence of `DELETE` or sequence functions. The policy independently pins
`search_path` to `pg_catalog, public, pg_temp` and qualifies every grant target.

The policy rejects prefix 13 and a failed migration 14 even when successful
rows 15 through 17 are present. It admits a complete
successful bounded prefix 1 through 14 while ignoring later rows, and requires
the runtime, control-bootstrap, and genesis registry-activation roles to exist
with options exactly `{NOLOGIN}` before target creation. Wrong-database and two
same-session temporary-shadow adversaries prove that neither migration history
nor grant targets can be redirected through `search_path`. The proof reapplies
the policy at prefix 17 and after option, system, object, grant-option,
PUBLIC, default-privilege, and named bidirectional-role drift, then applies it
again to freeze idempotence.

The exact successor grant matrix is 16 non-grantable table rows: SQLx history
`SELECT`; read-only control bootstrap and epoch rows; control events
`SELECT`/`INSERT`; control heads `SELECT`/`UPDATE`; read-only genesis activation
and head rows; successor transitions and genesis-bridge consumptions
`SELECT`/`INSERT`; and current v2 heads `SELECT`/`INSERT`/`UPDATE`. The role has
only database `CONNECT`, public-schema `USAGE`, and zero sequence, `DELETE`,
DDL, system, grant-option, ownership, or unrelated-object authority. The policy
also reasserts that PUBLIC and all three prior application roles have no grant
on the three successor authority tables. CockroachDB v26.2 requires table-level
`UPDATE` for the control-head `FOR UPDATE` lock; the proof contrasts a
SELECT-only principal with the successor member for that lock. Current-head
`UPDATE` is a direct repository write. Table-wide raw `INSERT` and `UPDATE`
remain residual credential capabilities,
so the login must be exclusive to the reviewed repository, enabled only for
the one-shot transaction, then have membership removed and `NOLOGIN` restored.

The successor policy carries the same v26.2 fail-closed default, PUBLIC system,
virtual-schema, external-connection, current-database ownership, and
cross-database external-audit model as conflict reconciliation. Its optional
`fleet_conflict_reconciliation` coexistence path does not require or create
that role. If the role exists, its non-target creator-scoped PUBLIC routine
default is an explicit cluster-admin cleanup prerequisite, just like every
other non-target routine default. CockroachDB v26.2 cannot conditionally run the
missing-role-sensitive, grantee-targeted default audit across every grantor, so
the policy does not admit that row by name. The proof creates and retains the
real row, verifies the default gate preserves unrelated target drift, cleans it
explicitly, and only then reapplies. Any membership edge between reconciliation
and successor likewise fails before mutation for explicit cleanup because v26.2
cannot conditionally revoke an optional role name without creating it. This is
a fail-closed coexistence boundary, not a claim that the two independently
ordered policies compose without their documented operator preflight.

The conflict-reconciliation RBAC proof uses privilege-shaped minimal stand-ins
for the six direct repository tables, the read-only `memory_claim_links`
receipt-FK parent, the conflict-ID sequence, and unrelated corpus/control/
registry/successor surfaces; repository correctness remains in the
official-binary Rust test. The policy pins `search_path` to
`pg_catalog, public, pg_temp`, explicitly qualifies every application object,
and first rejects any current database other than `fleet_recall`. The proof
shows a wrong-database attempt preserves existing grants and creates no role.
It rejects prefix 15 and failed migration 16 before any role or grant mutation,
also rejects missing hardened control/activation role prerequisites before
creating its role, admits the exact successful prefix through 16 with or
without later migration 17, and reapplies the policy after
privilege, grant-option, role-option, PUBLIC, and named bidirectional membership
drift.
The successor role remains optional rather than becoming a fourth prerequisite.
When it exists, the proof shows its creator-scoped PUBLIC routine default blocks
reconciliation before unrelated drift is normalized, performs the required
cluster-admin cleanup explicitly, freezes both exact successor/reconciliation
edge predicates, and dynamically proves both edge directions fail before
mutation even with a LOGIN successor and no admin option. The reconciliation
policy neither creates nor normalizes the successor role; passing these vectors
does not remove the documented cleanup, cross-database audit, and exclusive
member ceremony.
Two same-session temporary-schema adversaries freeze the name-resolution
boundary: a valid temporary 1-through-16 history cannot mask a missing or
failed real `public._sqlx_migrations` prefix, while a deliberately failed
temporary history cannot reject a valid real prefix or divert grants from any
fully qualified public repository table/sequence to its temporary namesake.
The policy admits only CockroachDB's exact non-grantable PUBLIC `CREATE` and
`USAGE` schema rows for a session-unique `pg_temp_*`
namespace; direct target grants on temporary objects remain forbidden.
Unexpected NOLOGIN-role inheritance, any additional application schema,
implicit ownership authority in `fleet_recall`, and current-database direct
reconciliation/PUBLIC grants outside the repairable `fleet_recall.public`
surface fail closed for operator repair.
All schema, routine, table, sequence, and type defaults to PUBLIC or the
reconciliation role are checked across every grantor with supported
grantee-targeted `SHOW DEFAULT PRIVILEGES` queries at both database and
public-schema scope. The CockroachDB
[v26.2.3 engine test](https://github.com/cockroachdb/cockroach/blob/v26.2.3/pkg/sql/logictest/testdata/logic_test/show_default_privileges)
synthesizes non-grantable PUBLIC routine `EXECUTE` and type `USAGE` for every
role and `FOR ALL ROLES`, in addition to exact self-owner `ALL` rows. This
stronger contract requires a cluster admin to revoke routine `EXECUTE` from
every pre-existing non-target role before applying this admin-only policy;
v26.2 cannot dynamically revoke arbitrary role identifiers in this policy.
CockroachDB v26.2.3 accepts an attempted `FOR ALL ROLES` revoke but
on the clean fixture descriptor synthesizes one exact non-grantable
routine-`EXECUTE` row, so the policy admits and the proof freezes only that
narrow engine baseline. `CREATE ROLE`
contributes one exact target-grantor PUBLIC routine row, which remains admitted
under the required quiescence because the final postconditions remove CREATE,
ownership, and inheritance authority. The proof expects that row explicitly;
every other PUBLIC routine or target/PUBLIC default is rejected, and the final
four-`SHOW` union is empty after those exact engine-baseline exclusions. The
policy admits only `public` plus CockroachDB's documented system/temporary
schemas, so no uninspected application-schema default can hide. The proof injects
arbitrary-grantor schema, routine, table, and sequence defaults plus a
grantable target-grantee type default, verifies pre-mutation preservation, and
removes them. Both admitted
routine rows remain inert only while member credentials are quiesced and no
current PUBLIC function grant survives the fail-closed object boundary; future
schema work must be cleaned and the policy reapplied before members are enabled.

`SHOW GRANTS FOR public` also reports v26.2.3's baseline visibility into the
four unmodifiable virtual schemas. The policy and proof admit only schema
`USAGE` and table `SELECT` (plus `pg_catalog` type `USAGE`), all non-grantable;
CockroachDB rejects application-object creation or shadowing in those schemas.
The proof freezes the exact nine grouped fallback shapes and counts, while any
routine, grant option, different privilege, or other object shape fails closed.

CockroachDB v26.2 does not implement delegated `SHOW` statements inside a
PL/pgSQL function body, including `DO`. The policy therefore keeps all nine
`SHOW`-backed assertions at statement scope and uses a short-circuited,
runtime-derived cast failure: successful gates return normally, while failed
gates retain their exact diagnostic substring with SQLSTATE `22P02`.
Catalog-only `DO` assertions remain SQLSTATE `55000`. The Docker proof also
statically rejects any future `SHOW` query added to a policy function body.

CockroachDB v26.2's no-target `SHOW GRANTS` union also includes cluster-global
external connections with a NULL database name. The policy rejects every
PUBLIC external-connection grant instead of losing those rows to its current-
database filter. The proof injects nodelocal `USAGE` and `DROP`, verifies the
fail-closed preflight preserves both grants and unrelated role drift, cleans the
exact external connection, and includes that cluster-global surface in the
final out-of-boundary audit.

Current-database `SHOW GRANTS` cannot make the SQL file an exact cluster-wide
object-authority normalizer. Its target/PUBLIC object-grant and ownership
contract is explicitly local to `fleet_recall`; before apply or use, a cluster
admin must enumerate every other database and revoke direct reconciliation-role
grants and ownership there. The Docker proof creates a second database, injects
target and PUBLIC table `SELECT`, target table ownership, and detects the new
database's default PUBLIC schema `CREATE`. Before that injection, it freezes and explicitly removes the
stock defaultdb/postgres PUBLIC `CREATE` rows. The inventory admits only two
additional exact system-database fallbacks that CockroachDB refuses to revoke:
non-grantable `system.public` schema `CREATE` and `system.public.comments`
`SELECT`; every differently shaped system row still surfaces. The proof freezes
target absence before first apply, then immediately audits the newly created
NOLOGIN role before injecting its cross-database adversaries. It shows the
external audit is read-only, cleans the injected rows, reapplies the policy, and
finally iterates every
`SHOW DATABASES` row to require zero direct target authority outside
`fleet_recall`. Because roles inherit PUBLIC, other databases' intentional
PUBLIC `CONNECT`, `TEMPORARY`, and schema `USAGE` remain ambient cluster state,
not a promise of this local policy; exclusive database confinement requires a
separate cluster-wide PUBLIC hardening pass. PUBLIC application-object
authority is inventoried separately in the proof. Cluster-global system and
external-connection gates remain enforced by the SQL policy itself.
These audits and policy statements are snapshots rather than locks. Production
must freeze concurrent role, grant, default-privilege, ownership, and schema-DDL
changes from external-audit start through policy completion and the one-shot
member's enable/use/disable, or repeat the audit immediately before enable/use
under the same change freeze. The Docker proof is intentionally single-threaded.

Because every role implicitly inherits PUBLIC, the policy also fails before
target-role creation if PUBLIC has any system privilege. The proof injects and
preserves a PUBLIC `CREATEROLE` system grant, removes it explicitly, and includes
PUBLIC in the final exact system-grant audit; the policy never silently revokes
cluster-wide PUBLIC authority.
Externally provisioned LOGIN members without ADMIN OPTION remain visible in the
complete membership audit. Exact `SHOW` output plus allowed/denied operations,
including allowed link reads and denied link `INSERT`, `UPDATE`, and `DELETE`,
freezes the one-shot logical role.

The role policy independently clears the complete CockroachDB v26.2 direct
option surface and system grants, including deprecated options that still have
authorization effect, and requires final options to be exactly `{NOLOGIN}`.
`NOREPLICATION` removes replication-mode drift, while `SQLLOGIN` removes legacy
`NOSQLLOGIN` drift and `NOLOGIN` remains the broader all-authentication-method
deny. `VALID UNTIL`, certificate `SUBJECT`, and
unremovable `PROVISIONSRC` identity drift fail before role mutation and require
identity replacement or external cleanup. Password hashes are not exposed by
`SHOW USERS`, and `PASSWORD NULL` cannot be exercised by this insecure Docker
substrate; exact `NOLOGIN` is the portable denial even if a stale hash exists,
while a secure-cluster operator can additionally clear a non-provisioned role's
password.

Static extraction freezes the six direct SQL tables, their exact
`SELECT`/`INSERT`/`UPDATE` targets, and the absence of `DELETE`; migration
extraction freezes the receipt's three outbound FK parents. CockroachDB
v26.2.3 initializes parent `SELECT` authorization while planning the receipt
reservation `INSERT`, before short-circuiting its omitted nullable `claim_id`,
`conflict_id`, and `link_id`.
Claims and conflicts are already direct reads, so the one indirect addition is
`SELECT` on `memory_claim_links`; the role receives neither link DML nor the
link-ID sequence. The exact table/sequence grant matrix is therefore 17 rows.

CockroachDB v26.2 also requires table-level `UPDATE` for the repository's `FOR
UPDATE` locks on conflict rows and memberships; the proof therefore freezes the
repository's actual `UPDATE` targets so that residual capability cannot
silently become an application write path. The serving runtime retains its
broader direct legacy-ledger DML because remember depends on it. The
reconciliation role is the supported least-privilege one-shot credential, not
an engine claim that a misused raw runtime credential cannot issue equivalent
table mutations; the parity proof snapshots and preserves that overlap while
proving there is no inheritance edge between the roles.

The publication-reader RBAC proof is a separate secondary Docker result for
the long-lived `fleet_publication_reader` logical role and one exact externally
provisioned principal, `fleet_publication`. The principal's password or
identity-provider binding remains outside the SQL policy. Before every apply,
the operator must drain its sessions and present it with exact `{NOLOGIN}`;
the policy never changes that authentication material or enables the login.
It rejects any direct/system/default/ownership authority on the principal and
any incident role edge other than the exact non-admin
`fleet_publication_reader -> fleet_publication` leaf edge. A missing expected
edge is installed only after every gate and logical-role grant succeeds.

The static phase runs before the first Docker command and can be selected
independently with `FLEET_RECALL_RBAC_STATIC_ONLY=1`. It freezes a complete SQL
`GRANT` allowlist: database `CONNECT`, public-schema `USAGE`, `SELECT` on the
exact eight tables used by public startup, status, chunk recall, claim recall,
support projection, and conflict hydration, plus the one fixed role edge. No
sequence, DML, DDL, function/type/external, system, grant-option, private-table,
or future-object authority is admitted. Static negative scans use status-safe
`awk` checks rather than treating every nonzero search status as success. They
also freeze all three system-default audit skips and reject any system database
target in the default-privilege normalization path. The exact eight-grantor,
four-mutable-database cleanup sets and their temporary-membership-to-empty-audit
lifecycle are frozen there as well.

The connected parity phase requires exact build tag `v26.2.3`, rejects the
wrong database, incomplete or failed prefix 18, a missing/non-quiesced
principal, and unsafe PUBLIC state before target creation. Pre-create PUBLIC
function, type, system, default, and cluster-global external-connection grants
leave the target absent. The proof injects the full v26.2 logical-role option
surface including replication, a nonportable `VALID UNTIL` identity option,
system/object/grant-option drift, target/principal/PUBLIC function/type/external
authority, ownership, extra schemas, FOR-ALL-ROLES and named-grantor defaults,
and mixed/transitive/admin role graphs. `SUBJECT` and system-managed
`PROVISIONSRC` remain statically frozen because the insecure fixture cannot
provision those identities portably.

For the late logical-role type adversary, the proof temporarily removes root's
database-scoped PUBLIC type default before creating the enum, because v26.2.3
also creates a separately granted `_reader_private_type` array alias that
cannot be revoked directly. It immediately restores and verifies the default,
requires zero PUBLIC grants across both descriptors, and then freezes the exact
single non-grantable reader grant on the base type. The subsequent PUBLIC type
gate likewise receives exactly one base-type row, followed by complete type and
default-state cleanup.

The read-only external inventory enumerates every other database and every
non-virtual application schema. It reports direct grants, ownership, and
database- or schema-scoped future defaults for both the logical role and fixed
principal, and separately reports PUBLIC current/future application authority;
only the documented v26.2 intrinsic default and virtual/system visibility rows
are excluded. The `system` database remains read-only: all three helpers audit
its current grants first, the subject helpers also audit ownership, and the
PUBLIC scan keeps its existing exact current-system exceptions. They then skip
only default/schema enumeration. CockroachDB v26.2.3 rejects both `ALTER DEFAULT
PRIVILEGES` and user `CREATE SCHEMA` there, while
`crdb_internal.default_privileges` synthesizes exact self-owner `ALL` and
non-grantable PUBLIC type `USAGE`/routine `EXECUTE` rows for each role, plus the
PUBLIC type/routine pair for the all-roles pseudo-role. Every differently shaped
current system grant still surfaces. Cross-database target, principal, and
PUBLIC defaults are injected at database and custom-schema scope, explicitly
removed, and followed by future object creation proving that none receives
authority. The stock cross-database PUBLIC schema `CREATE` remains installed
through its detection and read-only preservation assertions, then is revoked in
the explicit cleanup before the expected-empty inventory. Audit output is
captured in a status-checked assignment before an expected-empty comparison, so
a failed helper cannot masquerade as a clean inventory.
Bootstrap uses a principal-only inventory while the logical role is absent,
plus the full PUBLIC inventory, before the first role-creating apply; immediately
after creation it reruns the full two-subject and PUBLIC inventories under the
same single-threaded change freeze.
Creating the eight later fixture identities (`proof_external`, `proof_public`,
`proof_nologin`, `fleet_runtime`, `fleet_control_bootstrap`,
`fleet_registry_activation`, `fleet_registry_successor_activation`, and
`fleet_conflict_reconciliation`) synthesizes new creator-scoped PUBLIC routine
defaults in every database. Under temporary exact root membership, the proof
first requires the external inventory to return exactly 24 rows (eight grantors
across three non-system external databases). It then explicitly revokes those
defaults in `fleet_recall`, `defaultdb`, `postgres`, and
`proof_reader_other_database`, requiring exactly eight matching rows before and
zero after each revoke. It never mutates `system`, removes the memberships, and
requires both current and external PUBLIC audits to be empty before any later
policy apply or member use.

After the exact pre-use audit, the fixture externally enables
`fleet_publication`, exercises representative reads over all eight tables, and
rejects `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, DDL, sequence use, temporary
shadows, delegation, and private control/registry/reconciliation reads. It then
returns the principal to exact `{NOLOGIN}` before any reapply. A future table is
created before its denial probe. The sole connected PASS is emitted only after
the final two clean reapplies and a complete terminal audit of exact direct
grants, principal state, system/default/ownership/edge/PUBLIC/external surfaces,
dedicated schemas, future objects, and every other database.
