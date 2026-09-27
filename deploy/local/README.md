# Local production-shaped environment

A single-node Kubernetes (k0s) cluster in a Lima VM on this Mac, running the
Fleet Recall stack the way production is shaped: a secure CockroachDB with the
role boundary applied, the recall workloads, Ory Hydra + Kratos for identity,
and LocalStack for the AWS surfaces. It is the reference the production
Pulumi or Terraform program is derived from (ADR 0009).

```
deploy/local/bootstrap.sh up                # every phase, in order
deploy/local/bootstrap.sh phase <name>      # one phase (idempotent)
deploy/local/bootstrap.sh verify            # the checklist (bin/verify.sh)
deploy/local/bootstrap.sh down              # stop the VM, keep everything
deploy/local/bootstrap.sh reset --db        # asks; wipes data, keeps the VM
deploy/local/bootstrap.sh reset --all       # asks; deletes the VM and .state
```

Phases: `preflight vm images certs secrets cockroach migrate authority
boundary ory localstack recall verify`.

## Prerequisites

Apple Silicon M3 or later on macOS 15 or later (nested virtualization), Lima
2.x, OrbStack or another Docker with `buildx`, `kubectl` 1.34+, `helm`, `jq`,
`openssl`, the AWS CLI, a Rust toolchain, and the potion model bundle at
`.models/potion-retrieval-32M-<revision>/` (README "Local quickstart" step 1).
A LocalStack auth token in the environment (`LOCALSTACK_AUTH_TOKEN`) or in the
repository `.env` (`LOCAL_STACK_API_KEY`); it is never printed or committed.

LocalStack is optional for the mounted-model and Ory paths. To bring up or
verify that configuration without a LocalStack license:

```sh
FLEET_LOCAL_SKIP_LOCALSTACK=1 deploy/local/bootstrap.sh up
FLEET_LOCAL_SKIP_LOCALSTACK=1 deploy/local/bootstrap.sh verify
```

This explicitly skips the S3 model-download and AWS STS checks. Recall still
loads the mounted model bundle, and Ory still provides authentication. To add
the AWS surfaces later, configure a valid token and run `bootstrap.sh phase
localstack`, then run verification without the skip flag.

## What runs where

| Component | Where | Reach from the Mac |
|---|---|---|
| CockroachDB v26.2.3, secure single node | StatefulSet `fleet-recall/cockroach`, data on the VM disk | `127.0.0.1:26258` (SQL), `https://127.0.0.1:8082` |
| migrate, boundary, seed, Ory database bootstrap | Jobs in `fleet-recall` | `kubectl -n fleet-recall get jobs` |
| writer (stdio `serve` target), demo, ingress, worker CronJob | Deployments and a CronJob in `fleet-recall` | demo `127.0.0.1:8088`, ingress `127.0.0.1:8787` |
| Ory Hydra, Kratos, self-service UI | Helm releases in `ory` | Hydra `localhost:4444` (admin `4445`), Kratos `4433`, UI `4455` |
| LocalStack (s3, sts, iam, secretsmanager) | Helm release in `localstack` | `127.0.0.1:4566` |
| Kubernetes API | k0s in the VM | `https://127.0.0.1:6443`, kubeconfig in `.state/` |

Every Mac-side port is a Lima static forward to a fixed NodePort; nothing
listens on the Mac's non-loopback interfaces. OrbStack containers reach the
same ports through `host.docker.internal`.

## How the phases fit

1. **preflight, vm** create the VM from `lima/k0s.yaml` (Debian 13, `vz`,
   nested virtualization, 8 CPUs, 24 GiB) and install k0s pinned to the
   installed kubectl's skew window.
2. **images** builds the production image for `linux/arm64`, imports it into
   k0s's containerd (no registry), and records the model digest with the
   image's own binary.
3. **certs, secrets** generate the CockroachDB CA, node and root client
   certificates (also used from the Mac), one password per login, and the
   Kubernetes Secrets each pod mounts. Passwords live in `.state/passwords.env`
   (mode 0600). Nothing here is committed; `.state/` is gitignored.
4. **cockroach, migrate** start the secure node, create the database, the
   one-shot migrator and the quiesced long-lived logins, and run `migrate`.
5. **authority** installs the generation-3 writer authority **from the Mac**
   with `ostk-authority-install` (the ceremony binaries are deliberately absent
   from the image) while the migrator can still log in, and stores the pins in
   Secret `fleet-pins`.
6. **boundary** ports `deploy/localstack/database-boundary.sh` and
   `ingress-boundary.sh` to the secure cluster: quiesce, retire the migrator,
   clean the PUBLIC routine defaults for every role, apply the runtime,
   publication and ingress policies, enable the logins. The policies fail
   closed on their own gates.
7. **ory** creates the `hydra` and `kratos` databases and installs the three
   Ory charts (0.64.0) with the values under `helm/`. Hydra issues JWT access
   tokens, allows dynamic client registration, and includes the `fleet-recall`
   scope in the default scope set (ADR 0009 D8).
8. **localstack** installs the chart with a generated override holding the
   token and the model bundle path; the startup script seeds the model bucket.
9. **recall** ingests the demo corpus and starts writer, demo, ingress, and the
   worker CronJob (`project,embed` every five minutes).

## Verification

`bootstrap.sh verify` runs `bin/verify.sh`: nested virtualization, node,
image, secure SQL from the Mac, migration count, role edges, Jobs, pods, the
demo endpoints, an actual stdio MCP recall through the writer pod, one worker
tick with all selected steps `ok`, Hydra discovery, dynamic client
registration and JWKS, Kratos readiness, LocalStack STS and S3 model download,
and OrbStack reachability. The LocalStack checks are explicitly skipped when
`FLEET_LOCAL_SKIP_LOCALSTACK=1`.

`bin/oauth-smoke.sh` runs a PKCE authorization-code flow against Hydra and
Kratos in the browser and checks the returned issuer, expiry and scope without
printing tokens. `bin/oauth-headless-smoke.py` exercises the same public
registration, password login and consent forms with cookie jars, including
CSRF, callback state, PKCE, JWT claims and ID-token nonce. It creates a local
test identity and client on each run; credentials, tokens and diagnostics stay
in protected files under `.state/oauth-smoke/`.

## Resumed checkpoint (2026-09-27)

M1 is running with the mounted model and Ory. Verification passed 34 checks;
the three LocalStack checks were explicitly skipped. A complete public
registration → password login → consent → PKCE token exchange also passed.
LocalStack's configured license was expired, so its Deployment was scaled to
zero; the user chose to continue without it.

The recovered authority report was empty, despite the previous session's
success message. Bootstrap now validates the generation-3 report and its
three pins before accepting it, preserves invalid/partial outputs, and waits
for cluster networking and verified CockroachDB readiness after a VM restart.
The authority was then installed successfully, the boundary Job passed all
three policies, and the worker independently verified generation 3.

M2 adds remote HTTP MCP, identity anchors, principal enrollment and session
grants. M3 moves embedding into its own service and adds the shim, sandbox
launcher and transcript shipping. The detailed design is ADR 0009; the
original execution plan is
`~/.claude/plans/structured-dancing-willow.md` from session
`dae56076-9cff-4748-84d6-ad5f4f665b40`.

The pinned Hydra v26.2.0 returns empty optional dynamic-registration metadata
that current Claude Code rejects. [Ory documents this strict-client bug and
its v26.3.10 fix](https://changelog.ory.com/announcements/ory-hydra-v26-3-10-released).
The local instructions below use a pre-registered public client, supported
by stock Claude Code, with PKCE and no client secret.

## M2 HTTP service and human enrollment

The first M2 local service runs on the Mac at `http://localhost:8080/mcp`,
using the secure k0s database and its existing Ory issuer. This keeps Hydra's
issuer and discovery URL reachable exactly as advertised (`localhost:4444`)
and leaves the cluster's stdio writer available. The M2/M3 Kubernetes overlay
stays reserved until its identity routing and embedding service are deployed.
LocalStack is not required for the OIDC human path.
The full configuration, authorization model, and request examples are in
[Remote plane](../../docs/REMOTE_PLANE.md).

Build the Mac binary, apply the additive M2 migrations and updated role
boundary, then launch the HTTP service in a terminal:

```sh
cargo build --locked --bin ostk-fleet-recall
deploy/local/bin/upgrade-remote.py
ssh -F "$HOME/.lima/k0s/ssh.config" -O cancel \
  -L 127.0.0.1:8080:127.0.0.1:30080 lima-k0s
deploy/local/bin/serve-remote.sh
```

The upgrade helper preserves the M1 state and restores quiesced workloads
after installing migrations 38–39 and their role grants. This Mac-host
checkpoint does not require a new Kubernetes image: the existing pods keep
serving their original interfaces against the additive schema.

Lima reserves Mac port 8080 for the future Kubernetes MCP endpoint. The SSH
command cancels only that unused forward so the Mac service can bind it; the
database, Ory, and Kubernetes API forwards remain active. Repeat cancellation
after restarting the VM. After stopping the Mac service, restore the reserved
forward when needed with the same command using `-O forward` instead of
`-O cancel`.

With the service running, a second terminal can exercise the full automated
human path:

```sh
deploy/local/bin/remote-smoke.py
```

The smoke check performs an Ory OAuth login, enrolls the resulting subject,
calls status, records and reads a claim, and verifies revocation. Its tokens
and diagnostics stay in protected local state files. To connect your own
Claude Code identity, follow the enrollment steps below.

The launcher reads `.state/passwords.env`, `.state/authority.json`, the model
digest and CA. It connects with `verify-full` on port 26258, loads the pinned
model from the original checkout, and creates an idempotent, mode-0600 grant
signing key in `.state/remote-grant-signing-key.hex`. Its child receives only
the writer credential. The separate enrollment command receives only the
enrollment credential; neither command inherits other database URLs or `PG*`
variables from the terminal.

For a worktree sharing the existing local cluster, set `FLEET_LOCAL_STATE` to
the original checkout's `deploy/local/.state` and `FLEET_RECALL_BIN` to the
compiled binary. `FLEET_RECALL_MODEL_BUNDLE` overrides the mounted model's
Mac path when needed. Run the script with `--help` for its command forms.

Enroll a Kratos identity's exact ID as an operator. Obtain the ID from the
local Ory administration UI/API or an OAuth smoke run's protected state, then
write a private declaration file such as `.state/human-principal.json`:

```json
{
  "principals": [{
    "principal_id": "0198a849-f6ae-7d61-9800-000000000101",
    "anchor_id": "hydra",
    "subject_pattern": "REPLACE_WITH_KRATOS_IDENTITY_ID",
    "role": "operator",
    "tenant_id": "0198a849-f6ae-7d61-9800-000000000001",
    "project": "local-k0s",
    "ceiling": "project",
    "agent_pattern": "human-mac"
  }]
}
```

```sh
deploy/local/bin/serve-remote.sh enroll apply \
  --file deploy/local/.state/human-principal.json --bootstrap-scopes
deploy/local/bin/serve-remote.sh enroll list
recall_client_id=$(deploy/local/bin/register-mcp-client.py)
claude mcp add --transport http --callback-port 43110 --client-id "$recall_client_id" recall http://localhost:8080/mcp
claude mcp login recall
```

The registration helper prints only the public client ID and stores its full
response privately under `.state/mcp-clients/`. Use `claude mcp login recall
--no-browser` for a headless session, or `/mcp` within Claude Code. Log in
through Hydra/Kratos, then call
`recall(status)` and `remember(record)`. The subject must match the enrolled
identity. The caller's tool arguments cannot select another tenant, project,
or agent. To revoke that binding and its grants:

```sh
deploy/local/bin/serve-remote.sh enroll revoke 0198a849-f6ae-7d61-9800-000000000101
```

`GET /healthz` checks the HTTP listener. An unauthenticated `GET /mcp` returns
401 with a protected-resource metadata challenge;
`GET /.well-known/oauth-protected-resource/mcp` publishes the Hydra issuer and
`fleet-recall` scope. Direct identity tokens re-read the registry on every
request. For session grants, grant and principal revocation checks may be
cached for up to five seconds.

## M2 verified checkpoint (2026-09-27)

The Mac HTTP service is running against secure k0s CockroachDB with migrations
38–39 and all four audited role boundaries. The original Kubernetes workloads
were restored after upgrade. All 34 local environment checks passed; the three
LocalStack checks remain explicitly skipped.

Public Ory registration, password login, consent, and PKCE passed. The real
server then refused the unenrolled identity, accepted enrollment, completed
`recall(status)` → `remember(record)` → `recall(get)`, refused a cross-project
request, and rejected the same token immediately after revocation. Stock
Claude Code authenticated with a pre-registered public client and reports
**Connected**, including successful modern tool discovery. Its model-driven
tool smoke was blocked by the account's weekly usage limit (reported reset:
September 30, 4 p.m. America/Chicago); that final harness call has not passed.

Rust 1.94 validation: 2,707 tests passed across 53 targets, 19 ignored; strict
all-target Clippy and formatting passed. Separately, enrollment/grant tests
and the HTTP integration scenario ran against disposable CockroachDB with
the exact runtime/enrollment privileges. Both SQL policies applied and
reapplied with the expected 148 runtime and eight enrollment grants. These
connected tests were not run against the persistent k0s corpus.

`ubs --staged` encountered a sparse-workspace Rust scanner limitation. The
complete-worktree Rust scan ran instead, and changed-line findings were
reviewed; no actionable introduced finding was identified. Existing dependency
advisories were unchanged (including RSA under disabled `sqlx-mysql`; JWT
verification uses `ring`). Protected run evidence stays under
`.state/m2-upgrade-*`, `.state/remote-smoke/`, `.state/native-mcp-smoke/`, and
`.state/verify-m2.log`. No runtime credential or token is committed.

## Notes and known limits

- `serve` remains the stdio target; `serve --http` runs the remote endpoint.
  The writer Deployment remains the
  `kubectl exec -i deploy/writer -- container-entrypoint serve` target.
- Every recall pod mounts the model bundle because the image entrypoint
  requires it for every command; M3's embedding tier removes that.
- The worker's ingest steps need `git` and `gh`, which the image lacks; only
  `project` and `embed` run in the cluster.
- The local boundary applies runtime, publication, ingress and enrollment
  policies. The
  control and registry-activation policies (ceremony roles) are not applied
  by default.
- Kata Containers (VM-isolated pods) is optional: `helm/kata-values.yaml`
  targets `k8sDistribution: k0s` with the arm64 `qemu-runtime-rs` shim; the
  chart is an OCI artifact at `ghcr.io/kata-containers/kata-deploy-charts`.
  Kata's Firecracker shim is amd64-only; Firecracker itself runs directly on
  this VM (`/dev/kvm` and `vhost_vsock` are present) and is a later launcher
  backend.
- Hydra ignores the RFC 8707 `resource` parameter, so access tokens carry no
  audience; ADR 0009 D8 records the scope-based substitute the M2 service
  applies for this issuer.
