# Private control-ledger bootstrap

Stage 2 has one mutation boundary: a one-shot private process may accept the
out-of-band-pinned genesis receipt into the append-only control ledger. It is
not an HTTP route, an MCP tool, an ingest option, or a serving startup hook.
The CloudFront demo remains read-only.

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
- a private `FLEET_RECALL_DATABASE_URL` whose login has only the bootstrap
  grants below.

The command checks the raw receipt digest against the deployment pin before it
uses the receipt's profile reference. It then requires canonical bytes,
manifest closure, all genesis entry kinds and dependencies, exact semantic
scope, valid Ed25519 attestations, and the signer threshold before connecting
to CockroachDB. After connecting it requires the exact SQLx migration 3 row to
be successful before touching the control tables; a later successful migration
cannot mask a failed or missing control-ledger migration. Neither artifact may
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

Use three distinct login principals and three distinct secret values:

1. the migrator owns/applies schema and is dormant afterward;
2. the runtime serves MCP and the read-only demo but has no control-table
   privilege;
3. the control bootstrap login uses only the `fleet_control_bootstrap`
   principal (or is a member only of that logical role), runs this command once,
   and is disabled or its secret removed afterward.

The migration URL must never fall back to either the runtime URL or the
bootstrap URL. Deployment validation should reject equal or missing secret
references. The migrator must not grant runtime access through `ALL TABLES` or
an `ALTER DEFAULT PRIVILEGES ... ALL TABLES` rule, because that silently grants
future control tables.

After migration 0003, connect to the dedicated `fleet_recall` database as its
owner and apply
[`deploy/cockroach/control-role-grants.sql`](../deploy/cockroach/control-role-grants.sql).
If the database has another name, produce and review a copy with the database
identifier changed; do not interpolate an unchecked identifier into SQL.

The resulting bootstrap role has:

| Object | Privileges |
| --- | --- |
| `memory_control_bootstraps` | `SELECT`, `INSERT` |
| `memory_control_log_epochs` | `SELECT`, `INSERT` |
| `memory_control_shard_heads` | `SELECT`, `INSERT`, `UPDATE` |
| `memory_control_events` | `SELECT`, `INSERT` |
| `_sqlx_migrations` | `SELECT` (schema-version preflight only) |

It has no `DELETE`, `CREATE`, `DROP`, role administration, system privilege,
legacy-memory-table access, or grant option. The runtime and `public` roles
have no privilege on any control table. The schema owner retains authority for
forward migrations and audited repair procedures.

CockroachDB documents that grants are object-specific and do not automatically
cover new tables. It also documents the default `public` database/schema
grants, which this dedicated-database policy replaces explicitly:

- <https://www.cockroachlabs.com/docs/v26.2/grant>
- <https://www.cockroachlabs.com/docs/stable/security-reference/authorization>

Run the disposable local proof before deployment:

```bash
./deploy/cockroach/tests/control-role-grants.sh
```

The proof starts an isolated local CockroachDB, applies the control schema and
role policy, exercises each allowed statement, asserts denied runtime/public,
DDL, legacy-table, update, and delete paths, prints the effective grants, and
removes the container. It does not contact AWS or need LocalStack.
