# Isolated identity preflight

Run `deploy/local/bin/preflight-https-identity.py --state PRIVATE_STATE
--trusted-proxy-cidr ACTUAL_EDGE_POD_CIDR` to retain a private render. Add
`--apply` to create a **fresh** `fleet-https-preflight` namespace and the fresh
`hydra_https_preflight` / `kratos_https_preflight` databases and login roles on
the existing TLS-secured CockroachDB cluster. The helper refuses existing names;
it never adopts, resets or deletes data. Partial failures remain in private
state for inspection and explicitly scoped recovery.

The root SQL client uses its existing mounted client certificate over verified
TLS. Each fresh database and public schema is owned by its matching fresh role,
with PUBLIC database/schema rights removed. Before creating any role or
database, the helper inventories every existing database with an explicit
database selection, audits inherited PUBLIC object/system privileges, and
refuses data/DDL privileges outside the fresh databases. CONNECT/USAGE alone
may expose catalog names, but permit no application data or DDL. Individual
roles cannot opt out of PUBLIC membership. The roles receive no admin
membership, CREATEDB or CREATEROLE. No production role, grant, database, Secret,
or Ory deployment is modified. Ory's migrations run only against these fresh
databases, in init containers, with verify-full DSNs and the public database CA.
Passwords and independent cookie/system keys are generated privately; production
keys and identities are never copied into the preflight.

The same production HTTPS override files supply canonical browser URLs, secure
cookie attributes and dev-mode settings. These preflight overrides change only
private dependency namespaces, enable initialization of the fresh schemas, and
disable Hydra's unnecessary OAuth2-client controller. Network policy admits the
edge only on the public ports and permits egress only to DNS, the secure SQL
service, and the other preflight identity pods. An additional Kratos-only egress
policy permits TCP 443 to the current public DNS addresses of
`api.pwnedpasswords.com`, preserving its default breached-password check. The
private render records those addresses; regenerate this temporary policy if
they change. TLS still validates the API hostname. Keep the namespace trusted: its
identity applications necessarily call each other's private admin APIs.

After readiness, the edge owner temporarily selects these fixed backends:

- `http://hydra-public.fleet-https-preflight.svc:4444`
- `http://kratos-public.fleet-https-preflight.svc:80`
- `http://kratos-ui-kratos-selfservice-ui-node.fleet-https-preflight.svc:80`

Run the HTTPS headless smoke with a **new synthetic account** through the same
canonical names and certificate chain as the planned cutover. Production Recall
does not trust this fresh signing key; do not enroll or issue production grants.
After the proof, the edge owner switches to the existing Ory services together
with their URL cutover. Retain the preflight state for review; scale its workloads
to zero and retire its dedicated login roles when explicitly authorized. Do not
run the broad live-test migration suite against any existing database.

Production's eventual default-deny database ingress policy intentionally admits
the `ory` namespace only. Complete this isolated proof before enabling that
policy, or have its owner add a narrowly scoped temporary preflight allowance.

The initial local preflight exposed a pre-existing grant gap during independent
review: `hydra.public` and `kratos.public` granted CREATE/USAGE to PUBLIC, so the
new roles inherited potential DDL access outside their own databases. This
capability was not exercised. The completed preflight was retired: all three
deployments were scaled to zero, their SQL sessions drained, and both dedicated
roles changed to NOLOGIN. Databases and evidence remain. The new fail-closed
gate prevents repeating this setup on that unchanged baseline. Repairing the
existing Ory PUBLIC grants requires a separate coordinated change and runtime
verification; the preflight helper never silently changes them.

Role syntax and ownership follow [CockroachDB CREATE ROLE](https://www.cockroachlabs.com/docs/v26.2/create-role)
and [database ownership](https://www.cockroachlabs.com/docs/v26.2/alter-database).
The helper retains EXPLAIN output for its inventory queries and diagnostics for
administrative statements that do not implement EXPLAIN; these are separate
from the actual bootstrap results.
