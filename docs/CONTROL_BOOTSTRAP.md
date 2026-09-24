# Private control-ledger bootstrap

Stage 2 has one mutation boundary: a one-shot private process may accept the
out-of-band-pinned genesis receipt into the append-only control ledger. It is
not an HTTP route, an MCP tool, an ingest option, or a serving startup hook.
The CloudFront demo remains read-only and the current public process
authenticates only as the fixed `fleet_publication` login through the
`fleet_publication_reader` logical role.

This command is currently a workstation/operator tool built with Cargo. The
production image copies only `ostk-fleet-recall` and does not contain this
binary or the canonical contract artifacts. No ECS bootstrap task or secret
wiring exists yet; adding one is a separate reviewed deployment increment.

## Authority and artifact inputs

The `ostk-control-bootstrap` binary accepts only two path arguments:

- `--receipt`: one canonical bootstrap receipt plus exactly one final LF;
- `--genesis-package`: one canonical, semantically closed registry package
  plus exactly one final LF.

Routing and authority are available only through deployment environment:

- the normal physical scope in `FLEET_RECALL_TENANT_ID` and
  `FLEET_RECALL_PROJECT`;
- semantic authority scope in `FLEET_RECALL_CONTROL_TENANT_NAMESPACE` and
  `FLEET_RECALL_CONTROL_PROJECT_NAMESPACE`;
- the out-of-band root in `FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST`;
- a private `FLEET_RECALL_CONTROL_DATABASE_URL` whose login has only the bootstrap
  grants below.

The private command never falls back to `FLEET_RECALL_DATABASE_URL`. This
prevents a stale exported runtime or migrator URL from silently becoming the
bootstrap credential. The control URL permits only one `sslmode` parameter and
an optional absolute `sslrootcert` path; SQLx aliases, routing overrides,
session `options`, duplicate keys, unknown parameters, and URL fragments fail
closed before any connection attempt.

The command checks the raw receipt digest against the deployment pin before it
uses the receipt's profile reference. It then requires canonical bytes,
manifest closure, all genesis entry kinds and dependencies, exact semantic
scope, valid Ed25519 attestations, and the signer threshold before connecting
to CockroachDB. After connecting it requires exactly three successful SQLx rows
for the uninterrupted prefix 1 through 3 before touching the control tables; a
later successful migration cannot mask a failed or missing prerequisite. This
is deliberately a Stage-2 compatibility gate, not proof that every embedded
migration has been applied, that serving's minimum prefix is ready, or that
genesis/successor/reconciliation authority exists. Neither artifact may
override physical or semantic routing.

Apply once, then audit a replay using the same authority:

```bash
cargo run --locked --bin ostk-control-bootstrap -- apply \
  --receipt contracts/dynamic-memory/v1/bootstrap-receipt.jsonl \
  --genesis-package contracts/dynamic-memory/v1/genesis-registry-package.jsonl

cargo run --locked --bin ostk-control-bootstrap -- inspect \
  --receipt contracts/dynamic-memory/v1/bootstrap-receipt.jsonl \
  --genesis-package contracts/dynamic-memory/v1/genesis-registry-package.jsonl
```

`apply` reports `inserted` or `exact_replay`. `inspect` reports `absent` or
`complete`. The committed offset is a canonical decimal string, so no JSON
consumer can lose integer precision. Output contains content identities and the
append coordinate, not canonical authority bytes, signatures, database URLs,
or secrets. A different integrity-valid receipt in an occupied physical scope
is an explicit conflict; the stored receipt is checked for signatures,
threshold, scope, package closure, and the complete database shape, but it is
not accepted as current deployment-pinned authority. A partial or mismatched
stored shape is corruption and is never repaired implicitly.

The checked-in Stage-1 signing keys are public test fixtures. Never use their
receipt as live authority. Generate and independently pin deployment artifacts
before any non-test bootstrap.

## SQL principals

The current checked-in application/Terraform design has three distinct database
capability paths and raw secret values:

1. the migrator owns/applies schema and is dormant afterward;
2. the private writer performs seed/MCP DML through only the
   hardened `NOLOGIN` `fleet_runtime` logical role; and
3. the fixed external `fleet_publication` login serves only the read-only demo
   through the non-login `fleet_publication_reader` logical role.

The publication reader receives only `CONNECT` on `fleet_recall`, `USAGE` on
schema `public`, and `SELECT` on exactly `_sqlx_migrations`,
`memory_corpus_models`, `memory_chunks`, `memory_claim_embeddings`,
`memory_claim_support`, `memory_claims`, `memory_conflict_members`, and
`memory_conflicts`. It receives no DML, DDL, sequence, system, private-table,
ownership, grant-option, or future-default authority. The external login must
remain drained and exact `NOLOGIN` while a cluster admin performs the external
cross-database/PUBLIC/default/ownership audit and applies the
[`publication-reader-role-grants.sql`](../deploy/cockroach/publication-reader-role-grants.sql)
policy. Freeze role, grant, default, ownership, and schema-DDL changes, reapply
immediately before enabling that exact login, and repeat the ceremony after
each migration or grant change.

Stage-2 control bootstrap is a separate out-of-band capability. When the
ceremony runs, its login is a member only of the non-login
`fleet_control_bootstrap` logical role, uses a dedicated private URL, runs this
command once, and is disabled or its secret is removed afterward. The
migration URL must never fall back to the writer, publication, or bootstrap
URL; none of those URLs may be reused for another capability. The migrator
must not grant writer or publication access through `ALL TABLES` or an
`ALTER DEFAULT PRIVILEGES ... ALL TABLES` rule, because that silently grants
future control tables. Terraform wires the three planned secret paths but
does not provision CockroachDB identities, memberships, or grants; it has no
Stage-2 control secret or task.

The base policy can first be applied after migration 0003 and must remain
runnable at that original Stage-2 boundary. Reapply it after later migrations
create objects. Once the database is past migration 0014, also apply or
reapply the genesis-activation base role policy, followed by the deny-only
[quarantine policy](../deploy/cockroach/successor-schema-quarantine-grants.sql).
The quarantine deliberately retains its complete successful prefix 1 through
14 gate because migrations 12 through 14 create its three successor tables and
later migrations add none. It revokes those tables from the existing
application roles and grants nothing. Connect to the dedicated
`fleet_recall` database as a cluster admin, or as a dedicated security operator
with `CREATEROLE`, the required role admin options and SYSTEM grant options,
plus grant authority on every object in the policy, and apply
[`deploy/cockroach/control-role-grants.sql`](../deploy/cockroach/control-role-grants.sql).
If the database has another name, produce and review a copy with the database
identifier changed; do not interpolate an unchecked identifier into SQL.
Database ownership alone cannot perform the role-option, membership, and SYSTEM
hardening.

The resulting bootstrap role has:

| Object | Privileges |
| --- | --- |
| `memory_control_bootstraps` | `SELECT`, `INSERT` |
| `memory_control_log_epochs` | `SELECT`, `INSERT` |
| `memory_control_shard_heads` | `SELECT`, `INSERT`, `UPDATE` |
| `memory_control_events` | `SELECT`, `INSERT` |
| `_sqlx_migrations` | `SELECT` (schema-version preflight only) |

The runtime and bootstrap logical roles are forced to `NOLOGIN`,
`NOCREATEROLE`, and `NOCREATEDB`; the policy removes direct SYSTEM grants,
inherited admin, and both runtime/bootstrap inheritance directions. Bootstrap
has no `DELETE`, `CREATE`, `DROP`, role administration, system privilege,
legacy-memory-table/sequence access, or grant option. Runtime and `public` have
no privilege on any control table. The policy also re-revokes `public` grants
on all current tables and sequences. The schema owner retains authority for
forward migrations and audited repair procedures.

The policy resets current objects and does not create a universal future-object
default. Run `SHOW DEFAULT PRIVILEGES` as the actual migrator and require no
table/sequence default granting `public` or either application logical role;
reapply and re-audit after migrations create objects.

After migration 0014, that audit must show no `public`,
runtime, bootstrap, or genesis-activation grant on
`memory_registry_transitions`,
`memory_registry_genesis_bridge_consumptions`, or
`memory_registry_current_heads_v2`. A successor repository, workstation
apply/inspect CLI, and separate cluster-admin-only
[`fleet_registry_successor_activation` policy](../deploy/cockroach/successor-activation-role-grants.sql)
now exist. That policy creates a hardened `NOLOGIN` logical role with the
repository's exact bounded grant matrix, but no login or deployment surface.
Before a separately authorized local ceremony, freeze authority changes, clean
forbidden defaults and either-direction successor/reconciliation membership
edges, audit every other database for direct successor-role grants/ownership
and inherited PUBLIC authority, and reapply the policy immediately before
giving one quiesced external login temporary exclusive membership. Revoke
membership and disable the login afterward. There is no AWS secret/task,
production-image binary, startup hook, or runtime/public route. These source
capabilities do not expand Stage-2 authority.

After the complete successful prefix 1 through 17, a second repeatable
generation `N -> N+1` runtime and its own private workstation CLI
(`ostk-registry-generic-successor-activate`, apply/inspect only, no fixture
emitter) run the same ceremony under the same
`fleet_registry_successor_activation` role. It needs no new grant: its
production SQL surface reaches only `memory_control_events`,
`memory_control_shard_heads`, `memory_registry_transitions`,
`memory_registry_current_heads_v2`, and the migration-history preflight, all of
which the first-successor role already covers. At generation `N >= 1` there is
no key bridge: the authorizing keys come from the package the current head
installs, which the ceremony supplies as an artifact so its whole approval
closure is checked offline before any database URL is parsed. Like the
first-successor CLI it has no Terraform, production-image, ECS, MCP, HTTP, or
serving-runtime wiring, and the production image does not contain it.

After the complete successful prefix 1 through 16, conflict reconciliation has
its own separate database-local one-shot
[role policy](../deploy/cockroach/conflict-reconciliation-role-grants.sql); a
later successful migration 17 is compatible. Apply it only after the control
and genesis policies are hardened, as a cluster admin only; database ownership
alone is insufficient. Its required audit of
direct grants/ownership in every other database and inherited `public`
authority remains an external operator step under a role/grant/schema-DDL
change freeze. The successor role is optional, not an additional prerequisite;
when it exists, the operator must explicitly remove its creator-scoped PUBLIC
routine default and either-direction successor/reconciliation membership before
reconciliation apply/reapply. The reciprocal cleanup applies before successor
policy reapply. The role edges fail closed before mutation, and neither SQL
file performs the cross-database or conditional-default cleanup for the other.
The reconciliation role and apply-only workstation CLI have no Terraform,
production-image, ECS, MCP, HTTP, or serving-runtime wiring and do not expand
the Stage-2 role.

The required raw `INSERT` surface is still powerful: direct SQL can occupy a
scope singleton with invalid canonical bytes or plant a detached future event
offset, permanently wedging that scope for this intentionally non-repair role.
The scoped unique index
`memory_control_events_predecessor_unique_idx` rejects duplicate forks from one
digest but cannot compare a new event with the mutable head row. Keep the
credential exclusive to the reviewed command and treat a wedge as corruption
requiring an audited forward repair, never implicit deletion or healing.

CockroachDB documents that grants are object-specific and do not automatically
cover new tables. It also documents the default `public` database/schema
grants, which this dedicated-database policy replaces explicitly:

- <https://www.cockroachlabs.com/docs/v26.2/grant>
- <https://www.cockroachlabs.com/docs/stable/security-reference/authorization>

`tests/control_log_live.rs` exercises the control-ledger repository against a
real CockroachDB database; see the README's
[development workflow](../README.md#development-workflow) for running the live
tests.

## Writer-authority installer

The ceremony CLIs above each take canonical artifacts that someone must author
and sign by hand at ceremony time. A deployment or disposable database that
only needs its event-first writers to run can use `ostk-authority-install`
instead. It drives the same four signed repositories in order, idempotently:
the control bootstrap, the genesis activation, the `0 -> 1` first successor to
the compiled Stage-4 package, and the generic `1 -> 2` transition to the
compiled generation-2 connector package. It then prints the writer-authority
pins. Generation 2 is its only target. Like the other ceremony binaries, it is
a workstation tool: it is not in the production image, and the CI image job
asserts that it is absent.

### Runbook

Run it once per physical `(tenant_id, project)`, after `ostk-fleet-recall
migrate` has applied the complete migration prefix:

```bash
export FLEET_RECALL_DATABASE_URL=...               # schema owner/migrator login
export FLEET_RECALL_TENANT_ID=...                  # physical tenant UUID
export FLEET_RECALL_PROJECT=...                    # physical project
export FLEET_RECALL_CONTRACT_TENANT_NAMESPACE=...   # for example tenant.acme
export FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE=... # for example project.recall
cargo run --locked --bin ostk-authority-install -- apply
```

- **Credential.** `FLEET_RECALL_DATABASE_URL` must authenticate as the schema
  owner/migrator (`fleet_migrator`), the same convention as `migrate`, and it
  is validated the same way (`sslmode=verify-full`, or
  `FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1` for a loopback database).
  The steps write the control and registry tables. No application role can
  write those tables; the migrator/schema owner keeps technical authority over
  them (see [migration operations](MIGRATIONS.md)). The installer adds no
  grant and needs none. The runtime and publication roles gain nothing.
  Withdraw the migrator credential afterward, as you would after `migrate`.
- **Output.** One JSON report: each step with `inserted` or
  `already_present`, the active `generation`, its `activation_id`, the
  activated `package`, and `pins`. The `pins` object's keys are the
  environment variables `FLEET_RECALL_CONTRACT_TENANT_NAMESPACE`,
  `FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE`, and
  `FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST`. Export them to every event-first
  writer for that physical scope. The optional break-glass
  `FLEET_RECALL_EXPECTED_ACTIVATION_ID` takes the reported `activation_id`.
  The run ends by verifying the strict writer-authority witness under exactly
  these pins. A writer loads them through `WriterAuthorityRuntime::from_env`
  (`src/registry_witness/runtime.rs`). It verifies the head once at startup
  and again for every request or tick, and caches nothing between the two.
- **Re-runs.** A re-run reports every step `already_present`, with the same
  pins and the same activation. A run that stopped partway resumes where it
  stopped. The genesis step resumes from the audited genesis root, because its
  statement is signed at ceremony time and cannot be replayed. Do not run two
  installers against one physical scope at the same time. The loser fails
  closed, and running it again completes the install.
- **Refusals.** The installer never repairs anything. It refuses a physical
  scope that already holds another bootstrap receipt, other contract
  namespaces, a package the strict witness does not know, or the generation-1
  package re-activated past generation 1. It reads the stored control
  bootstrap as well as the writer-authority view, so a scope bootstrapped by a
  hand-run `ostk-control-bootstrap`, or by an install for another request that
  stopped before `0 -> 1`, is refused the same way as an installed one. Every
  refusal is a configuration error and writes nothing. Installing other
  namespaces over an installed physical scope is therefore refused, and the
  installed head stays as it was.
- **Receipt.** The bootstrap receipt is a pure function of the request. It is
  the frozen `v1/bootstrap-receipt.jsonl` statement with its scope rewritten
  to the requested namespaces and its partition seed set to a domain digest
  of the physical tenant and project. Two physical scopes therefore never
  share a genesis epoch, even when they share namespaces.

### The signatures are nominal

Every signature the installer makes uses the public Ed25519 test fixture keys:
seeds `0x01` and `0x02`. The frozen receipt names these keys `principal.1` and
`principal.2`, and the compiled activation policy names them `principal.alice`
and `principal.bob`. The installer also mints the generation-2 conformance
result itself. Anyone can reproduce these signatures, so they authenticate
nothing. Two things carry the authority. First, database role separation:
only the owner/migrator login can write the tables this touches. Second, the
out-of-band receipt-digest pin that each writer process loads. A deployment
that needs real governance must author and sign its own ceremony artifacts
with the four CLIs above, and pin that receipt instead.

The connected tests install their authority through the same library function
(`tests/common/authority.rs`); `tests/authority_install_live.rs` proves
the install, its idempotency, and the refusal.
