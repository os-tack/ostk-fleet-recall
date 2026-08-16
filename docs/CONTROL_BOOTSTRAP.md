# Private control-ledger bootstrap

Stage 2 has one mutation boundary: a one-shot private process may accept the
out-of-band-pinned genesis receipt into the append-only control ledger. It is
not an HTTP route, an MCP tool, an ingest option, or a serving startup hook.
The CloudFront demo remains read-only.

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
for the uninterrupted prefix 1 through 3 before touching the control tables;
a later successful migration cannot mask a failed or missing prerequisite.
This is deliberately a Stage-2 compatibility gate, not proof that the current
release's exact prefix 1 through 17 is complete, that serving's minimum
uninterrupted prefix of 17 is ready, or that genesis/successor/reconciliation
authority exists. Neither artifact may override physical or semantic routing.

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

For this Stage-2 boundary, use three distinct login principals and three
distinct secret values:

1. the migrator owns/applies schema and is dormant afterward;
2. the runtime serves MCP and the read-only demo but has no control-table
   privilege;
3. the control bootstrap login is a member only of the non-login
   `fleet_control_bootstrap` logical role, runs this command once, and is
   disabled or its secret removed afterward.

The migration URL must never fall back to either the runtime URL or the
bootstrap URL. Deployment validation should reject equal or missing secret
references. The migrator must not grant runtime access through `ALL TABLES` or
an `ALTER DEFAULT PRIVILEGES ... ALL TABLES` rule, because that silently grants
future control tables.

The base policy can first be applied after migration 0003 and must remain
runnable at that original Stage-2 boundary. Reapply it after later migrations
create objects. For the current complete release prefix through migration 0017,
also apply or reapply the genesis-activation base role policy, followed by the
deny-only
[quarantine policy](../deploy/cockroach/successor-schema-quarantine-grants.sql).
The quarantine deliberately retains its complete successful prefix 1 through
14 gate because migrations 12 through 14 create its three successor tables and
15 through 17 only add/replace indexes. It revokes those tables from the
existing application roles and grants nothing. Connect to the dedicated
`fleet_recall` database as a cluster admin, or as a dedicated security operator
with `CREATEROLE`, the required role admin options and SYSTEM grant options,
plus grant authority on every object in the policy, and apply
[`deploy/cockroach/control-role-grants.sql`](../deploy/cockroach/control-role-grants.sql).
If the database has another name, produce and review a copy with the database
identifier changed; do not interpolate an unchecked identifier into SQL.
Database ownership alone cannot perform the role-option, membership, and SYSTEM
hardening; the checked-in proof requires those statements to fail for a
database-owner-only user.

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

After migration 0014, that audit and quarantine proof must show no `public`,
runtime, bootstrap, or genesis-activation grant on
`memory_registry_transitions`,
`memory_registry_genesis_bridge_consumptions`, or
`memory_registry_current_heads_v2`. A successor repository and workstation
apply/inspect CLI now exist, but the tables remain migrator/schema-owner only
because there is no dedicated successor SQL writer principal/logical role or
write-grant RBAC policy. There is likewise no AWS secret/task,
production-image binary, startup hook, or runtime/public route. These source
capabilities do not expand Stage-2 authority.

After the complete successful prefix 1 through 16, conflict reconciliation has
its own separate database-local one-shot
[role policy](../deploy/cockroach/conflict-reconciliation-role-grants.sql); a
later successful migration 17 is compatible. Apply it only after the control
and genesis policies are hardened, as a cluster admin only; database ownership
alone is insufficient. Its required audit of
direct grants/ownership in every other database and inherited `public`
authority remains an external operator step under a role/grant/schema-DDL
change freeze. The reconciliation role and apply-only workstation CLI have no
Terraform, production-image, ECS, MCP, HTTP, or serving-runtime wiring and do
not expand the Stage-2 role.

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

Run the disposable local proof before deployment:

```bash
./deploy/cockroach/tests/control-role-grants.sh
```

The proof starts an isolated local CockroachDB, applies the frozen
Stage-2/genesis migration slice 0003 through 0009, injects and repairs
role-option, SYSTEM, admin/cross-role, direct-object, and `public` drift,
asserts exact
current/default privileges, proves a database owner cannot run cluster-security
hardening, freezes the command's distinct successful-prefix-1-through-3 gate,
exercises each allowed statement, and rejects authorization escapes and a
duplicate predecessor. It prints the effective grants and removes the
container. This is the frozen Stage-2/genesis-role proof boundary, not a
successor writer or current application-image migration-parity proof. The
authoritative official CockroachDB v26.2.3 correctness lane covers versions 1
through 17 and exercises the successor repository, functional-polarity matrix,
and conflict-reconciliation repository/CLI. It does not supply successor RBAC,
run the successor workstation CLI, or replace the separate Docker
allow/deny/grant-option matrices. Neither substrate contacts AWS or needs
LocalStack.
