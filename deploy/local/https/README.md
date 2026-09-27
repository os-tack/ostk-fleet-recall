# Local HTTPS deployment (M4.2)

This profile upgrades the existing M3 Lima/k0s deployment in place. It keeps
the database, principal registry, signing keys, writer authority pins, content
key and transcript volume. It does not rerun migrations or enrollment.

The canonical addresses are fixed for this private-CA profile:

| Service | Address |
| --- | --- |
| Recall MCP | `https://recall.fleet.test:8443/mcp` |
| Hydra issuer | `https://auth.fleet.test:8443/` |
| Login and Kratos browser API | `https://login.fleet.test:8443` |

The root private key stays on the Mac. An intermediate restricted to
`.fleet.test` signs renewable leaves through cert-manager in `fleet-pki`.
Traefik watches only `fleet-edge`; public backend URLs come from its file
provider, referenced by Gateway API routes. It cannot read the Ory, Recall or
PKI namespace Secrets. See [gateway pins and trust](gateway/README.md),
[Ory settings](ory/README.md), and [network policy limits](network/README.md).

## Prerequisites and preparation

Use an existing healthy M3 deployment and its original private state directory.
The examples run from the repository root. They require Docker Desktop,
Lima 2.2, kubectl, Helm, OpenSSL and Python 3. The encrypted checkpoint helper
also requires the Python `cryptography` package (the qualification host uses
3.12.0 with cryptography 46.0.3). No LocalStack dependency is introduced.

```sh
export FLEET_LOCAL_STATE="$PWD/deploy/local/.state"
export KUBECONFIG="$FLEET_LOCAL_STATE/kubeconfig"
```

Build the service and sandbox from the same checkout; use a new tag for changed
source. Build the workstation launcher with Rust 1.94 and `--locked`. Import
both Linux images into k0s; the image archive must be under a Lima mount.

```sh
docker buildx build --platform linux/arm64 --target production \
  -t ostk-fleet-recall:YOUR_TAG --load .
docker buildx build --platform linux/arm64 -f deploy/local/sandbox/Dockerfile \
  --build-arg RECALL_IMAGE=ostk-fleet-recall:YOUR_TAG \
  -t ostk-sandbox:YOUR_TAG --load .
docker save -o "$FLEET_LOCAL_STATE/images/YOUR_TAG.tar" \
  ostk-fleet-recall:YOUR_TAG ostk-sandbox:YOUR_TAG
limactl shell k0s sudo k0s ctr images import "$FLEET_LOCAL_STATE/images/YOUR_TAG.tar"
cargo +1.94 build --locked --bin ostk-fleet-recall
```

Before changing identity URLs, stop active launches with `launch down` while
their saved old URLs still work. Include failed/partial launch state. The
cutover helper checks local state, running containers/pods and active grant
rows, then drains the old receiver and rechecks grants before changing Ory.

Create a recovery checkpoint. The helper exports an encrypted native database
backup, validates its files, copies it off the VM disk, and encrypts Ory/Kubernetes
configuration, keys and spool separately with AES-256-GCM. Its manifest binds
the artifacts to this state directory and cluster. A local key beside the
archive is convenient recovery material, not protection from a compromised
Mac; off-device encrypted backup and restore rehearsal remain M4.3/M4.5 work.

```sh
python3 deploy/local/bin/backup-https-cutover.py --state "$FLEET_LOCAL_STATE"
```

Initialize trust once, then prepare and apply the pinned edge. Subsequent
preparations omit `--initialize-ca`; partial, mismatched or changed CA state is
refused rather than replaced. A failed installation retains its diagnostics.

```sh
python3 deploy/local/bin/prepare-https-edge.py prepare \
  --state "$FLEET_LOCAL_STATE" --initialize-ca
python3 deploy/local/bin/prepare-https-edge.py apply --state "$FLEET_LOCAL_STATE"
```

Only the public `https-edge/pki/root.pem` is distributed to clients. Never copy
`root-key.pem`, `intermediate-key.pem`, the recovery key or application Secrets
into a sandbox. The launcher snapshots the public CA with readable permissions
for its non-root agent and shipper.

## Name resolution and the Mac boundary

The single-Mac profile has three distinct routing mechanisms:

| Caller | Resolution of the canonical hostname |
| --- | --- |
| Mac/browser/native Codex | `/etc/hosts` maps the three names to `127.0.0.1` |
| Docker sandbox | Explicit `--docker-host-gateway` maps only its MCP hostname to Docker's host gateway |
| k0s pod | CoreDNS maps the three names to the edge Service's ClusterIP on port 8443 |

Review the host helper, then install its narrow mapping with administrator
access. It keeps a dated hosts-file backup and refuses conflicting mappings.

```sh
python3 deploy/local/bin/install-macos-https-hosts.py
sudo python3 deploy/local/bin/install-macos-https-hosts.py --apply
```

Pause the worker and drain any current tick before stopping the VM. The Lima
helper requires a stopped existing VM, saves its config, and adds only
`127.0.0.1:8443 -> NodePort30443`. It preserves disks and mounts. Retain the
original worker object below for restoration after acceptance; keep this earliest
record through retries, even when later cutover attempts record an already
suspended worker.

```sh
kubectl -n fleet-recall get cronjob worker -o json \
  > "$FLEET_LOCAL_STATE/https-worker-before-$(date -u +%Y%m%dT%H%M%SZ).json"
kubectl -n fleet-recall patch cronjob worker --type=merge -p '{"spec":{"suspend":true}}'
kubectl -n fleet-recall get jobs
# Wait until the currently active worker Job has completed before stopping k0s.
limactl stop k0s
python3 deploy/local/bin/reconcile-https-lima.py --state "$FLEET_LOCAL_STATE" --apply
limactl start k0s --tty=false
python3 deploy/local/bin/configure-https-dns.py --state "$FLEET_LOCAL_STATE" --apply
```

The DNS helper preserves the existing Corefile outside its marked `fleet.test`
block. Verify it after k0s configuration changes or upgrades. A failed or stale
mapping must be repaired before issuing new credentials; never fall back to
HTTP or a different issuer string.

For browser trust, add the generated public root to the user's login Keychain;
macOS may require user authorization. Codex HTTPS clients also need the
documented environment setting before their process starts:

```sh
security add-trusted-cert -r trustRoot -k "$HOME/Library/Keychains/login.keychain-db" \
  "$FLEET_LOCAL_STATE/https-edge/pki/root.pem"
export CODEX_CA_CERTIFICATE="$FLEET_LOCAL_STATE/https-edge/pki/root.pem"
export FLEET_RECALL_CA_PATH="$CODEX_CA_CERTIFICATE"
export FLEET_RECALL_URL=https://recall.fleet.test:8443/mcp
codex mcp add recall-remote --url "$FLEET_RECALL_URL"
codex mcp login recall-remote --scopes openid,offline_access,fleet-recall
```

An already running Codex desktop process does not inherit shell exports.
For a subsequently launched macOS desktop process, set the per-login user
launch environment, then restart Codex when ongoing work is complete:

```sh
launchctl setenv CODEX_CA_CERTIFICATE "$CODEX_CA_CERTIFICATE"
```

This setting needs reapplication after logging out or rebooting; it is not a
persistent startup service. The CLI check alone does not qualify the desktop
process. See the official
[Codex custom CA documentation](https://learn.chatgpt.com/docs/auth#custom-ca-bundles).

## Identity cutover and acceptance

First prove the canonical HTTPS form flow against the [isolated preflight
identity deployment](preflight/README.md). Restore the edge's production backend mapping before
cutover. The same production Ory configuration then retains existing database
subjects and cookie/signing keys, with development mode and insecure cookies
disabled.

Render and validate the runtime first; omit `--apply` for a read-only cluster
preparation. Use the actual edge node's pod CIDR and a complete checkpoint from
this cluster less than one day old. Recreate the checkpoint after relevant
state changes, including initial CA generation.

```sh
python3 deploy/local/bin/deploy-https-plane.py --state "$FLEET_LOCAL_STATE" \
  --image-tag YOUR_TAG --ca-path "$FLEET_RECALL_CA_PATH" \
  --trusted-proxy-cidr 10.244.0.0/24
python3 deploy/local/bin/deploy-https-plane.py --state "$FLEET_LOCAL_STATE" \
  --image-tag YOUR_TAG --ca-path "$FLEET_RECALL_CA_PATH" \
  --trusted-proxy-cidr 10.244.0.0/24 --backup COMPLETE_CHECKPOINT_PATH --apply
```

The helper preserves key fingerprints, closes old Recall/Ory NodePorts, installs
the namespace ingress policies and verifies public metadata/private endpoints.
It intentionally leaves the worker suspended until authenticated acceptance.
All cutover evidence and that attempt's prior worker object remain in the printed
private directory. On failure, inspect the recorded phase before retrying. The
helper compares protected Secret data with the authenticated checkpoint both
before and after cutover. Continue using the original checkpoint during recovery;
do not create a replacement checkpoint merely to make an unexpected key change
pass the gate.

Acceptance includes existing-account subject preservation, fresh OAuth login
and consent, native Codex, shim/launcher grant minting and revocation, Docker
and Kubernetes transcript shipping, rejected wrong/untrusted certificates,
and real pod network-denial checks. Example invocations:

```sh
python3 deploy/local/bin/verify-https.py --ca-path "$FLEET_RECALL_CA_PATH" \
  --kubeconfig "$KUBECONFIG"
python3 deploy/local/bin/oauth-headless-smoke.py --profile https \
  --state "$FLEET_LOCAL_STATE" --ca-path "$FLEET_RECALL_CA_PATH" \
  --account-file EXISTING_PRIVATE_ACCOUNT_FILE --expected-subject EXISTING_UUID
python3 deploy/local/bin/sandbox-smoke.py --backend both \
  --image ostk-sandbox:YOUR_TAG --shipper-image ostk-sandbox:YOUR_TAG \
  --bin target/debug/ostk-fleet-recall --state "$FLEET_LOCAL_STATE" \
  --url "$FLEET_RECALL_URL" --resource-url "$FLEET_RECALL_URL" \
  --docker-url "$FLEET_RECALL_URL" --kubernetes-url "$FLEET_RECALL_URL" \
  --docker-host-gateway --ca-path "$FLEET_RECALL_CA_PATH" --namespace fleet-recall
python3 deploy/local/bin/verify-https-network.py --kubeconfig "$KUBECONFIG" \
  --ca-path "$FLEET_RECALL_CA_PATH" --image ostk-sandbox:YOUR_TAG
```

The network proof pins ready backend sockets and brackets unrelated-pod
denials with successful connections from allowed identities. Its tokenless
control pods never become Ready, so they cannot receive production Service
traffic. Pods are retained for inspection and have bounded lifetimes.

For Docker launches, add `--docker-host-gateway`. Kubernetes uses split DNS and
must omit that flag. Both use the identical HTTPS URL and CA; neither needs
`--allow-http`. Re-register/re-login native OAuth clients using their actual
callback URL after changing the server URL; do not copy OAuth credential files
between hosts. Resume the worker to the suspension state in the earliest record
from before the Lima pause, only after the authenticated checks pass. A successful
retry's `worker-before.json` can contain `suspend: true` introduced by an earlier
attempt; it is not the original operational setting. The cutover helper never
resumes the worker automatically.

Rollback restores the old configuration, image and intentionally chosen URL
set together, using retained Helm history and manifests. Do not restore an old
authorization database snapshot to resurrect revoked grants. Obtain fresh
credentials after rollback and retain the one-receiver/one-worker constraints.
Keep the worker suspended while restoring and verifying the old receiver/Ory
configuration. Restore its earliest recorded suspension setting only after the
chosen rollback profile has passed authenticated checks; a later failed attempt's
paused state must not replace that record.

## LAN/VPN and cloud scope

This installer deliberately selects the single-Mac profile. A LAN/VPN profile
keeps the same hostnames and issuer but needs a stable selected Mac address,
client-restricted firewall rules for 8443, client DNS mappings and public-CA
distribution. Change only the HTTPS forward's bind address; administrative
forwards remain on loopback. Do not expose every Lima port or treat a DHCP
address as stable. Verify from a second physical machine before marking that
profile qualified. No second-machine qualification follows from the Docker
test.

The `.test` CA/NodePort/Lima files are not the cloud deployment. M4.4 uses the
[cloud profile](../../remote/profiles/cloud-https.env.example), public DNS
and ACM, private service targets and durable storage described in the
[M4 plan](../../../docs/M4_REMOTE_ACCESS_PLAN.md). Client URLs, grant lifetime
checks, provider credential separation and issuer metadata contracts are
shared between profiles.
