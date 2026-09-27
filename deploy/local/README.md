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

Add local monitoring with `deploy/local/bootstrap.sh phase observability`.
This optional phase installs Prometheus, Grafana, Loki, Alloy, node exporter,
and kube-state-metrics in `fleet-observability`; see the
[monitoring guide](../observability/README.md) for dashboards, access, storage,
and verification. It can also be installed from another worktree by explicitly
pointing its installer at this checkout's `.state/kubeconfig`.

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

The next checkpoint is M2: remote HTTP MCP, identity anchors, principal
enrollment and session grants. M3 moves embedding into its own service and
adds the shim, sandbox launcher and transcript shipping. These subcommands
are not implemented yet; the M2 overlay remains a placeholder. The detailed
design is ADR 0009; the original execution plan is
`~/.claude/plans/structured-dancing-willow.md` from session
`dae56076-9cff-4748-84d6-ad5f4f665b40`.

Before the M2 stock-harness OAuth check, review the pinned Hydra v26.2.0
image: [Hydra v26.3.10 fixes empty optional DCR metadata rejected by strict
MCP clients](https://changelog.ory.com/announcements/ory-hydra-v26-3-10-released).
The M1 form and token checks do not establish stock-harness compatibility.

## Notes and known limits

- `serve` is stdio-only until M2 lands `serve --http`; the writer Deployment is
  the `kubectl exec -i deploy/writer -- container-entrypoint serve` target.
- Every recall pod mounts the model bundle because the image entrypoint
  requires it for every command; M3's embedding tier removes that.
- The worker's ingest steps need `git` and `gh`, which the image lacks; only
  `project` and `embed` run in the cluster.
- The boundary applies the runtime, publication and ingress policies, the set
  the quickstart and Compose stack prove against this migration set. The
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
