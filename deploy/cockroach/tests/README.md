# Connected CockroachDB proof substrates

## Authoritative official process

Connected correctness is authoritative only when it runs against the official
CockroachDB `v26.2.3` binary. CI downloads the Linux AMD64 archive, verifies the
frozen SHA-256
`3eca6d7bc6fefa3ba0847e89733fc69f61226c80b8fab0af6578e1be672f27d3`,
and requires `cockroach version --build-tag` to equal `v26.2.3` exactly.
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

The same isolated server also exercises inspect/apply/replay for the control and
genesis-activation CLIs, plus materialize/exact replay for the apply-only
conflict-reconciliation CLI. It requires exactly 17 successful SQLx
rows with versions 1 through 17, the three successor authority tables, the two
genesis-root indexes, and the exact indexes introduced by migrations 15, 16,
and 17. The retired pre-v15 conflict uniqueness index must be absent. The proof
replays the resumable index-transition bytes, exercises online recovery, and
shows that failed migration 12 is not masked by successful migration 17.
Migrations 15 through 17 add or replace indexes rather than successor tables,
so the exact successor table set remains the three tables introduced by
migrations 12 through 14.

That exact 1-through-17 assertion freezes the current HEAD release; it is
distinct from the serving compatibility floor, which accepts a complete
successful prefix of at least 17.

These current-release assertions do not widen the private compatibility gates:
Stage 2 still requires the complete successful prefix through 3, genesis Stage
3 through 9, the successor repository through 14, and conflict reconciliation
through 16.

Do not count the live successor-repository row as a successor-CLI result. The
three private CLIs in this authoritative wrapper are control bootstrap, genesis
activation, and conflict reconciliation. The source-present
`ostk-registry-successor-activate` command is workstation-only and has no
checked-in successor write-grant role policy or deployment route. Conflict
reconciliation and its logical role are likewise one-shot workstation
surfaces. None of the four private CLIs has an AWS, Terraform, task, production
image, runtime, startup, or server-route surface; the production image excludes
all four.

Run the authoritative proof with an already checksum-verified binary:

```bash
FLEET_RECALL_CRDB_BINARY=/absolute/path/to/cockroach \
  ./deploy/cockroach/tests/registry-activation-cli.sh
```

## Result accounting and Docker parity

The complete official matrix above shares one CockroachDB server process and
produces one authoritative official-binary result. Its individual test rows are
not separate server results, and neither the process nor its result may be
counted as Docker evidence.

| Reported result | Substrate and scope | Relationship to authority |
| --- | --- | --- |
| Official-binary correctness | One checksum-pinned, build-tag-pinned TLS `v26.2.3` server running the complete matrix and the control, genesis-activation, and conflict-reconciliation CLIs | The single authoritative connected result |
| Control RBAC parity | `control-role-grants.sh` in its own Docker container | Secondary packaging/RBAC result only |
| Activation RBAC parity | `registry-activation-role-grants.sh` in its own Docker container | Secondary packaging/RBAC result only |
| Conflict-reconciliation RBAC parity | `conflict-reconciliation-role-grants.sh` in its own Docker container | Secondary packaging/RBAC result only |
| Control bootstrap CLI parity | `control-bootstrap-cli.sh` in its own Docker container | Secondary packaging/CLI result only |

Each Docker proof requires the running server's build tag to equal `v26.2.3`.
That confirms image-version parity, but Docker parity cannot substitute for the
checksum-pinned official-binary correctness proof. Report the authoritative
result and each Docker parity result separately; do not summarize one substrate
as evidence that another passed. Every script owns bounded temporary state and
cleans it on success, failure, or interruption.

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
current exact prefix through 17.

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
