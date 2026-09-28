# Operate the single-Mac HTTPS deployment

This guide is for the existing Lima/k0s installation qualified through M4.3.
Run commands on its Mac, from the repository root. The Mac must remain awake
and the VM running for Recall to be available. LocalStack is optional and is
disabled in the qualified installation.

For a fresh disposable development database, use the
[local development tutorial](../tutorials/LOCAL_DEVELOPMENT.md). For another
deployment shape, first read [deployment profiles](../reference/DEPLOYMENT_PROFILES.md).
The [HTTPS installation runbook](../../deploy/local/https/README.md) describes
the existing M3-to-HTTPS upgrade; it is not a fresh-machine installer.

## Select the installation before running commands

A Git worktree contains source, not a separate cluster. Every worktree that
operates the existing VM must use the **original installation's absolute state
path**. Do not let a helper silently select a new worktree's empty `.state`.

```sh
export FLEET_LOCAL_STATE=/absolute/original-checkout/deploy/local/.state
export KUBECONFIG="$FLEET_LOCAL_STATE/kubeconfig"
export FLEET_RECALL_BIN="$PWD/target/debug/ostk-fleet-recall"
export FLEET_RECALL_URL=https://recall.fleet.test:8443/mcp
export FLEET_RECALL_CA_PATH="$FLEET_LOCAL_STATE/https-edge/pki/root.pem"
export CODEX_CA_CERTIFICATE="$FLEET_RECALL_CA_PATH"
export FLEET_RECALL_ALLOW_HTTP=false

limactl list
kubectl config current-context
kubectl get namespace kube-system -o jsonpath='{.metadata.uid}{"\n"}'
```

Compare the cluster UID and state path with the checkpoint manifest for this
installation before maintenance. Keep `.state`, the Lima disk and private
launch records; a new clone does not replace them. Never run `bootstrap.sh up`,
the M3 deployment helper, or argument-free `serve-remote.sh` to repair this HTTPS
installation: those paths configure the earlier HTTP profile.

Day-to-day checks need Lima, kubectl, Python 3 and the installed public CA.
The full maintenance helpers also need Docker, Helm, OpenSSL and Python
`cryptography`/`PyYAML`. Build a changed workstation binary with
`cargo +1.94 build --locked --bin ostk-fleet-recall`; images must already be
available in the selected Docker/k0s runtime before launches or deployment.

## Know which identity you are using

| Identity | Owner and purpose |
| --- | --- |
| Human Ory account | The person signs in through Kratos/Hydra. Registration alone gives no Recall access. |
| Enrolled human principal | The enrollment operator binds the exact verified subject to a tenant, project, role and agent pattern. The local human anchor is `hydra`. |
| Launcher principal | The operator enrolls a local-key or Kubernetes identity that may mint scoped agent/shipper grants. A human login is not a replacement for this identity. |
| Sandbox grants | The launcher creates two separate short-lived credentials and must revoke both during teardown. |
| SQL principals and protected keys | The deployment administrator maintains the separate runtime/enrollment/migration authority. These credentials do not belong in clients or sandboxes. |

For a new human, register at `https://login.fleet.test:8443/registration` or
sign in at `https://login.fleet.test:8443/login`. In that same authenticated
browser, open `https://login.fleet.test:8443/sessions/whoami` and read only
`identity.id` from the successful JSON response. That Kratos identity UUID is
the Hydra subject for this deployment. A 401 means the browser has no active
session; log in before continuing. Give the enrollment operator that UUID,
not session cookies, tokens or the full response.

The existing [OAuth helper](../../deploy/local/bin/oauth-headless-smoke.py)
also obtains this identity through `/sessions/whoami` when creating a test
account and records `identity_id` in its protected `result.json`; an
existing-account run additionally requires `--expected-subject` and checks
the fresh OAuth claims against it. It is a stateful acceptance test, not a
read-only identity lookup. Do not create a smoke identity to enroll a person's
existing account.

The enrollment operator prepares a private principal declaration using the
[enrollment schema](../REMOTE_PLANE.md#prepare-the-database-and-enrollment-login).
Use the existing tenant/project and the intended exact subject; an email
address or an unverified decoded JWT is not the subject lookup procedure.
The local credential-isolating wrapper supports enrollment against the existing
database even though its argument-free server mode is legacy HTTP:

```sh
deploy/local/bin/serve-remote.sh enroll list
deploy/local/bin/serve-remote.sh enroll apply --file /absolute/private/principals.json
```

`--bootstrap-scopes` is only needed to initialize a new scope and requires the
pinned model configuration. `--prune` revokes every omitted principal, so it is
appropriate only for an intentionally complete registry declaration. To remove
one binding, use `enroll revoke PRINCIPAL_UUID`. Registry revocation preserves
history; direct identity requests reread it, while grant checks can cache it
for up to five seconds. Signing out of a client is not a principal revocation.

## Connect an enrolled client

On the Mac, first complete the [startup and trust checks](#start-after-reboot-or-sleep)
and select the environment above. For Codex, add the native HTTP MCP server
and authenticate with the enrolled Ory account:

```sh
codex mcp add recall-remote --url "$FLEET_RECALL_URL"
codex mcp login recall-remote --scopes openid,offline_access,fleet-recall
codex mcp get recall-remote
```

`add` may start OAuth immediately; `login` explicitly repeats it when needed.
If `recall-remote` is already configured, inspect it with `get` first and reuse
it when its URL is the canonical HTTPS address. A configuration listing proves
only configuration. Start a fresh Codex session with the CA setting inherited,
then ask it to call the remote server's `recall` tool with:

```json
{"action":"status"}
```

Then read a known claim in the enrolled scope (replace `13` with that claim's ID):

```json
{"action":"get","kind":"claim","id":13}
```

Confirm the real tool calls succeeded and the expected claim was returned.
An OAuth success alone does not prove enrollment or content access. These are
MCP tool arguments, not shell subcommands. The
[MCP reference](../reference/MCP.md#reading-status) explains the result, and
the [recall/remember walkthrough](../tutorials/USING_RECALL.md#6-exercise-the-mcp-server)
explains later memory operations; its setup section is for disposable stdio.
Codex's native HTTP/OAuth configuration is documented in the
[official MCP guide](https://learn.chatgpt.com/docs/extend/mcp); the private root
uses [Codex custom CA configuration](https://learn.chatgpt.com/docs/auth#custom-ca-bundles).

### Claude Code with the pinned Hydra

The pinned local Hydra needs Claude's public-client preregistration path;
the [registration helper](../../deploy/local/bin/register-mcp-client.py)
retains registration credentials privately and prints only the public client ID.
Keep the browser's public-root trust installed. For a terminal Claude process,
set its [additional CA bundle](https://code.claude.com/docs/en/network-config#custom-ca-certificates)
before registering and logging in:

```sh
export NODE_EXTRA_CA_CERTS="$FLEET_RECALL_CA_PATH"
FLEET_CLAUDE_CLIENT_ID=$(python3 deploy/local/bin/register-mcp-client.py \
  --profile https --state "$FLEET_LOCAL_STATE" --ca-path "$FLEET_RECALL_CA_PATH")
claude mcp add --transport http --callback-port 43110 \
  --client-id "$FLEET_CLAUDE_CLIENT_ID" recall-remote "$FLEET_RECALL_URL"
claude mcp login recall-remote
```

The helper registers both loopback callback variants on port 43110; the remote
service and issuer still use HTTPS. Inspect an existing client registration
before adding another, and keep the callback port consistent. Authenticate with
the enrolled identity and perform the same status/get tool checks. See
[troubleshooting](TROUBLESHOOTING.md) if trust, login or enrollment fails.

Use this canonical HTTPS URL for Docker and Kubernetes too. Docker launches
additionally need `--docker-host-gateway`; Kubernetes uses split DNS. Do not
change the issuer or resource audience to work around a routing problem.

## Start after reboot or sleep

Start the existing VM if stopped, then wait for the workloads to recover:

```sh
limactl start k0s --tty=false
kubectl get nodes
kubectl -n fleet-recall get pods
kubectl -n ory get pods
python3 deploy/local/bin/verify-https.py \
  --ca-path "$FLEET_RECALL_CA_PATH" --kubeconfig "$KUBECONFIG"
```

Cold boot can include database-dependent startup retries. Inspect readiness
and the verification result before launching work. A sleep/wake cycle does not
require recreating the VM or reapplying the deployment. Restore Docker access
as well if using Docker sandboxes. Use [troubleshooting](TROUBLESHOOTING.md) if
the canonical URLs remain unavailable.

No Mac boot/login autostart service is installed. Shell exports apply only to
new child processes. Before starting a fresh Codex desktop process after login
or reboot, reapply the per-login CA setting and restart the app when its active
work is complete:

```sh
launchctl setenv CODEX_CA_CERTIFICATE "$FLEET_RECALL_CA_PATH"
```

The macOS public-root trust installation is described in the
[HTTPS trust setup](../../deploy/local/https/README.md#name-resolution-and-the-mac-boundary).
Verify a real `recall` status/read in the actual harness; a working terminal
client does not prove that an already running desktop app inherited trust.

## Check service, authorization, and memory separately

| Check | What success establishes |
| --- | --- |
| `kubectl -n fleet-recall get pods` | Workload state and Kubernetes readiness, including Recall's core database check. |
| Private `/healthz` | The HTTP process is alive; database/issuer/embedding health is separate. |
| Private `/readyz` | A fresh successful database/schema/grant-capability check. Embedding and issuer availability do not gate it. |
| `verify-https.py` above | Trusted TLS, canonical discovery, protected routes and deployment/policy configuration. It does not log in or prove packet enforcement. |
| `recall` with `{"action":"status"}` in the client | An authenticated request succeeds and reports the caller's effective service status. |
| `recall` get of a known claim, then a known search | Existing content can be read and the expected retrieval path works. See [reading status](../reference/MCP.md#reading-status). |

Health/readiness and metrics are deliberately absent from the public HTTPS
routes. For a private diagnostic, keep this forward running in a separate
terminal, then use the two loopback URLs:

```sh
kubectl -n fleet-recall port-forward deployment/recall 18080:8080
```

```sh
curl --fail --silent --show-error http://127.0.0.1:18080/healthz
curl --fail --silent --show-error http://127.0.0.1:18080/readyz
```

This diagnostic tunnel does not replace the canonical HTTPS client endpoint.
An embedding outage can preserve claim reads and lexical search while
embedding-dependent work is unavailable. Cached OIDC keys can temporarily
verify requests during an issuer outage; a cold or expired cache fails closed.

## Run and finish sandbox work

Use an enrolled launcher and a qualified sandbox image. Keep launch state
under the original private state directory so maintenance can find it. This
Docker example runs the synthetic harness, which makes no provider calls:

```sh
FLEET_RECALL_LAUNCHER_KEY_HEX="$(cat "$FLEET_LOCAL_STATE/launcher-key.hex")" \
  "$FLEET_RECALL_BIN" launch up --backend docker --anchor local-key \
  --key-id launcher --scope TENANT_UUID/local-k0s --agent sandbox-check \
  --image ostk-sandbox:QUALIFIED_TAG \
  --url "$FLEET_RECALL_URL" --resource-url "$FLEET_RECALL_URL" \
  --sandbox-url "$FLEET_RECALL_URL" --docker-host-gateway \
  --ca-path "$FLEET_RECALL_CA_PATH" --state-dir "$FLEET_LOCAL_STATE/launches"
```

Replace the scope and tag with the enrolled scope and installed release.
For Codex/Claude provider credentials, harness limits, or the Kubernetes
backend, use the [sandbox guide](../../deploy/local/sandbox/README.md), applying
the HTTPS URL/CA rules above to its older HTTP examples.

Record the printed private `launch-state.json` path. Even after the agent exits,
finish the launch with the same anchor available:

```sh
FLEET_RECALL_LAUNCHER_KEY_HEX="$(cat "$FLEET_LOCAL_STATE/launcher-key.hex")" \
  "$FLEET_RECALL_BIN" launch down --state /absolute/private/launch-state.json
```

Teardown stops the agent, allows a final shipping flush and revokes both grants.
If it reports `cleanup-pending`, restore connectivity and retry the same state
file. Do not substitute direct container deletion for this procedure. The
receiver's acknowledged bytes are the durability boundary; unshipped bytes can
be lost with the sandbox. Kubernetes `emptyDir` data does not survive Pod
teardown. The [memory pipeline tutorial](../tutorials/MEMORY_PIPELINES.md)
explains how shipped transcripts become searchable evidence on worker ticks.

## Monitor routine operation

```sh
FLEET_OBSERVABILITY_REMOTE=true deploy/observability/install-k0s.sh verify
deploy/observability/install-k0s.sh forward
```

Keep the forward running and open `http://127.0.0.1:3000`. Use the
[monitoring access instructions](../../deploy/observability/README.md#install-on-the-local-k0s-vm)
to retrieve the password privately. Start in Overview, then Workers for stale
or failed ticks, Dependencies for embedding/issuer problems, and Kubernetes
or Logs & Events for restart/storage problems. Keep `FLEET_OBSERVABILITY_REMOTE=true`
on monitoring updates; the base profile suspends the remote probe and omits
its rules. `verify` checks the installed stack without installing changes.

The normal worker runs every five minutes with overlap forbidden. Monitor
freshness and the last run's outcome independently. The
[alert response reference](../TELEMETRY.md#remote-https-lifecycle-alerts) gives
thresholds and limitations. Alerts evaluate locally, but **notification delivery
is not configured**. Watching a dashboard is currently an operator duty.

## Pause, maintain, and recover

For a planned Mac/VM shutdown, stop new work, finish active client requests and
run `launch down` for every active or partial launch first. Preserve the current
worker state before suspending it:

```sh
umask 077
FLEET_MAINTENANCE_DIR="$FLEET_LOCAL_STATE/maintenance-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir "$FLEET_MAINTENANCE_DIR"
kubectl -n fleet-recall get cronjob worker -o json > "$FLEET_MAINTENANCE_DIR/worker-before.json"
kubectl -n fleet-recall patch cronjob worker --type=merge -p '{"spec":{"suspend":true}}'
kubectl -n fleet-recall get jobs
```

Wait for active scheduled **and manual** worker Jobs to finish; suspension does
not stop an existing Job. Then `limactl stop k0s` preserves the VM disk. After
starting it again, complete the checks above and inspect the saved
`spec.suspend`. Only if it was false, restore it with:

```sh
kubectl -n fleet-recall patch cronjob worker --type=merge -p '{"spec":{"suspend":false}}'
```

If the worker was already suspended, retain that state and resolve the earlier
maintenance result. Suspending a CronJob alone does not quiesce client writes.

For application upgrades, controlled restart/outage rehearsals and manual leaf
renewal, follow the [lifecycle runbook](../../deploy/local/https/OPERATIONS.md).
Its helpers require a current authenticated checkpoint, fresh enrolled OAuth
token, known claim/search, no active launches/grants, and an exclusive worker
lock. Run one at a time. They retain private results and resume the worker only
after recovery gates pass. A failed helper needs diagnosis before another run.

Create an encrypted checkpoint with:

```sh
python3 deploy/local/bin/backup-https-cutover.py --state "$FLEET_LOCAL_STATE"
```

The command captures sensitive state without printing it and validates native
backup files; it does **not** schedule backups, copy them off the Mac, quiesce
writers, or prove restore. For consistent SQL/spool recovery, use a maintenance
window with launches, receiver writes and workers quiesced. Retain the original
state path/cluster UID, encrypted artifacts, and separately protected recovery
key off the machine. The model bundle and qualified container images are also
needed for the application rehearsal.

Follow the [recovery runbook](../../deploy/local/https/RECOVERY.md) to restore
into an isolated new database and prove fresh OAuth, old claim reads and pending
work replay. It never promotes that copy to a public service. Post-backup
principal changes and Ory sessions require reconciliation before real promotion.
Use prior images with the current authorization database for deployment rollback;
an old database snapshot can resurrect revoked access.

The pilot targets are backup age at most 24 hours and recovery within four
hours. The [qualification record](../../deploy/local/https/LIFECYCLE_QUALIFICATION.md)
records measured local rehearsals, not an automated backup guarantee. Second-machine
LAN/VPN access, cloud deployment, a 24-hour soak, root/key rotation and off-device
disaster recovery remain separate qualifications.
