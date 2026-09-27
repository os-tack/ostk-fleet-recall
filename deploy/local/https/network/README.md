# Local HTTPS ingress boundaries

These policies isolate incoming pod traffic in `fleet-recall`, `ory`, and
`fleet-edge`. They deliberately do not restrict egress. DNS, authenticated
Kubernetes issuer discovery, Helm controllers, worker source fetches, and sandbox
provider traffic therefore retain their existing outbound behavior. They are
not an exfiltration boundary or a substitute for application credentials.

The TLS edge is identified by namespace **and** the stable pod label
`fleet-recall.dev/component=https-edge`. It can enter only Recall's MCP port,
Hydra/Kratos public ports, and the login UI. Ory admin ports admit only their
named UI/identity/controller peers. Database and embedding admission uses exact
workload labels; enrollment Jobs carry `app: enrollment`. Namespace membership
alone does not grant access. Anyone allowed to create or relabel pods in these
trusted namespaces can impersonate a label, so RBAC remains part of the boundary.

Prometheus retains its existing Recall/embed `9100` and demo/webhook `9091`
scrapes. The worker textfile travels through host storage to node-exporter;
there is no new worker listener. Edge metrics `9100` are admitted only from
Prometheus, but adding a scrape target is a separate telemetry configuration.
Cockroach's web console is not made accessible to arbitrary pods.

Existing demo/webhook operator-local forwards remain usable through the trusted
node. Explicit in-namespace clients may use `fleet-recall.dev/client=publication`
or `fleet-recall.dev/client=webhook` respectively. Neither service is routed
through the public HTTPS edge in this milestone.

NetworkPolicy does not enforce URL paths, and node-origin / hostNetwork behavior
depends on the CNI. Remove or convert the old Recall and Ory NodePorts during
cutover; in particular, Hydra's former admin NodePort must not remain reachable.
Keep database/demo/webhook forwards loopback-only. Do not interpret successful
`kubectl port-forward` as a NetworkPolicy allow test. The cluster's kube-router
must actually enforce these policies; an API object alone is not proof.
See the [Kubernetes NetworkPolicy semantics](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

After applying in the authorized cutover, test TCP from ordinary, non-hostNetwork
pods: edge-labelled pods may reach public app ports but not Ory admin, SQL,
embedding or metrics; unrelated pods may reach edge `8443` but none of those
private listeners; the real UI, Recall, worker, enrollment, and Prometheus must
retain their listed dependencies. Use real workload probes or tightly controlled
temporary test identities; do not permanently grant test labels to untrusted pods.

The `fleet-pki` certificate controller namespace is separate. Its API-server
webhook and signing-key RBAC need their own controller policy; these manifests
do not claim to isolate that privileged namespace.
