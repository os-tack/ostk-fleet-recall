# Local HTTPS gateway

This fixed development profile serves `auth.fleet.test`, `login.fleet.test`, and
`recall.fleet.test` on HTTPS port **8443**. The `fleet-edge` Service in namespace
`fleet-edge` is a NodePort Service: service/pod port 8443, node port 30443. Lima
forwarding and split DNS are configured separately. This is a single-workstation
deployment; Mac sleep, VM shutdown, or a disconnected LAN interrupts service.

## Prepare, review, apply

Prerequisites are Python 3.10+, OpenSSL 3, Helm 4, and kubectl for the existing
k0s cluster. No LocalStack dependency or HTTP-development opt-in is needed.
Run from the repository worktree, with the existing protected state directory:

```sh
python3 deploy/local/bin/prepare-https-edge.py prepare \
  --state /Users/scottmeyer/projects/aetia/deploy/local/.state --initialize-ca
```

`prepare` does not mutate Kubernetes. It downloads dependencies and verifies the
SHA-256 pins in `versions.json`, creates the CA only when explicitly requested,
checks certificate/key correspondence and remaining validity, and renders both
Helm charts. Existing PKI, including an interrupted initialization, is never
replaced automatically. Subsequent preparations omit `--initialize-ca`; providing
it again also preserves valid existing keys. Changes to an input manifest require
a new preparation before apply.

Review the private snapshot named in the JSON result, then run:

```sh
python3 deploy/local/bin/prepare-https-edge.py apply \
  --state /Users/scottmeyer/projects/aetia/deploy/local/.state \
  --kubeconfig /Users/scottmeyer/projects/aetia/deploy/local/.state/kubeconfig
```

The installer compares an existing cluster signer with the protected local
signer before any mutation. It refuses a different signer or conflicting Helm
release, preserves all private preparation/command artifacts, and serializes
operations with a state-directory lock. Failure leaves installed resources in
place for inspection; there is no automatic uninstall or replacement CA.
Same-version reruns reconcile the explicit manifests and Helm values. Dependency
upgrades require a reviewed pin and lifecycle change, not a silent version bump.

The resulting releases are `cert-manager` in `fleet-pki` and `fleet-edge` in
`fleet-edge`. The apply result reports the edge Service ClusterIP for split DNS.
Apply waits for current-generation Gateway/listener acceptance and programming,
and acceptance/resolved references for each of the four expected HTTPRoutes;
stale success from a previous generation does not satisfy this gate.
The canonical browser issuer/resource/Ory configuration and ingress policies
must be applied before qualifying the new profile. `verify-https.py` checks the
public routes; authenticated native OAuth and sandbox checks remain separate.

## Trust and access boundary

The root private key stays at `<state>/https-edge/pki/root-key.pem`, protected by
mode 0600 inside mode-0700 state. Distribute **only** `root.pem` to clients. The
825-day intermediate is constrained to DNS names under `.fleet.test` and has no
subordinate-CA depth. Only its private key and public certificate chain enter the
immutable `fleet-pki/fleet-intermediate-ca` Secret. The root key is neither a
Kubernetes object nor part of Helm values.

cert-manager is a privileged certificate controller; its chart RBAC can manage
certificate Secrets cluster-wide. Its ClusterIssuer reads the signer from
`fleet-pki`. A fail-closed native ValidatingAdmissionPolicy rejects Certificate
and CertificateRequest references to `fleet-local-ca` outside `fleet-edge`.
Only administrators may alter that policy, issuer, controller, or namespace
RBAC. The webhook is a private ClusterIP endpoint. This profile does not claim
egress isolation or a tested fleet-pki webhook NetworkPolicy.

Traefik has **no Secret permission** in `ory`, `fleet-recall`, or `fleet-pki`.
Its Gateway provider watches only `fleet-edge`. Its custom ClusterRole reads
Namespaces/GatewayClasses; the namespace Role reads edge objects and leaf TLS
Secrets. Apply impersonates the edge ServiceAccount and checks denial of
get/list/watch Secrets in each private namespace before starting the edge.
The impersonation includes all three standard ServiceAccount groups so that
group-bound permissions are included in these negative checks.

Cross-provider HTTPRoute references, such as `hydra@file`, select fixed file
provider services using the supported Traefik Gateway extension. The upstreams
are the four public application Services. The Kubernetes CRD and Ingress
providers are disabled; Traefik's bundled CRDs are not installed. This avoids
granting the edge controller access to Ory database credentials or Recall grant
keys merely to route to public services. Route/config writers in `fleet-edge`
remain privileged administrators.

Only HTTPS8443 is exposed by the edge Service. Ping9000 and metrics9100 are
private; the separate policy profile limits metrics to Prometheus. Access logs
are disabled so authorization query strings and bearer headers are not logged.
The dashboard/API and forwarded-header trust from arbitrary clients are disabled.
Hydra admin, Kratos admin, application health/metrics, and arbitrary root paths
are absent from `routes.yaml`. UI paths and Kratos browser paths keep their
original paths on the same `login.fleet.test` origin; no prefix rewrite is used.

## Renewal and recovery

cert-manager issues a 90-day leaf for the three fixed DNS names and renews it
30 days before expiry, rotating its private key. Traefik watches that edge TLS
Secret. The root and intermediate do not renew automatically. Preparation rejects
a CA with fewer than 180 days remaining; operators must monitor CA expiry and
perform an explicit overlap/rotation ceremony before automatic leaf renewal
would outlive the issuer. Changing a CA Secret alone does **not** reissue leaves.
CA renewal and live leaf-rotation proof belong to the lifecycle qualification.

Preserve the existing CA pins, root/intermediate keys, leaf state, Ory secrets,
Recall keys, and workload backup when restoring. Do not rerun an initialization
with a different state directory and distribute its root as though it were the
existing profile. The cutover backup and rollback helper own application/DNS
restoration; this installer intentionally does not delete retained resources.

Workstation-only checks:

```sh
python3 -m unittest discover -s deploy/local/https/gateway -p 'test_*.py'
```

## Pinned upstream references

- [Traefik Helm chart 41.6.0](https://github.com/traefik/traefik-helm-chart/releases/tag/v41.6.0),
  using Traefik v3.7.13; chart archive digest is recorded in `versions.json`.
- [Gateway API standard v1.6.2](https://github.com/kubernetes-sigs/gateway-api/releases/tag/v1.6.2).
- [Traefik Gateway API configuration](https://doc.traefik.io/traefik/reference/routing-configuration/kubernetes/gateway-api/)
  and the pinned [cross-provider implementation](https://github.com/traefik/traefik/blob/v3.7.13/pkg/provider/kubernetes/gateway/httproute.go).
- The pinned [Gateway client watches](https://github.com/traefik/traefik/blob/v3.7.13/pkg/provider/kubernetes/gateway/client.go)
  explain why application namespaces cannot be included in the edge watch set.
- [cert-manager v1.21.2 release](https://github.com/cert-manager/cert-manager/releases/tag/v1.21.2),
  [Helm installation](https://cert-manager.io/docs/installation/helm/), and
  [CA issuer limitations and rotation](https://cert-manager.io/docs/configuration/ca/).
