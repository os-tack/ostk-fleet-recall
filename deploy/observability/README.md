# Local monitoring and Grafana dashboards

The local k0s stack collects application metrics, container resource usage,
node health, Kubernetes object state, pod logs, and Kubernetes events. Six
linked Grafana dashboards are provisioned from versioned JSON; no plugins or
manual dashboard setup are required.

## Install on the local k0s VM

After `deploy/local/bootstrap.sh up`, run:

```sh
deploy/local/bootstrap.sh phase observability
export KUBECONFIG="$PWD/deploy/local/.state/kubeconfig"
deploy/observability/install-k0s.sh forward
```

Open <http://127.0.0.1:3000>. The username is `admin`. Retrieve the generated
password locally (do not paste it into logs, tickets, or source control):

```sh
kubectl -n fleet-observability get secret fleet-grafana-admin \
  -o jsonpath='{.data.password}' | base64 --decode
```

Keep the `forward` command running in a terminal while using Grafana. Restart
it after closing that terminal, restarting the app that launched it, or a
Grafana pod replacement. A stopped forward makes the local URL unreachable
even when monitoring is healthy. The normal local `bootstrap.sh up` does not
remove the monitoring namespace; use `install-k0s.sh verify` to check the
stack independently of the browser connection.

From a separate worktree, set `KUBECONFIG` to the original checkout's
`deploy/local/.state/kubeconfig`, then run `deploy/observability/install-k0s.sh
up` directly. The installer requires an explicit kubeconfig and exactly one
k0s node because storage lives on that VM. Rerunning `up` updates manifests
and provisioning while preserving the existing admin credential and data.
`render` prints the public configuration for review without contacting the
cluster; it intentionally omits the generated admin Secret.

The monitoring namespace is `fleet-observability`. Grafana is reached only by
loopback port forwarding; Prometheus and Loki have ClusterIP services. No
Ingress or NodePort is created. Network policies limit access to monitoring
pods, while node exporter uses the private node network to observe the host.

## Dashboard guide

| Dashboard | Questions it answers |
|---|---|
| [Overview](grafana/dashboards/fleet-overview.json) | Are targets up? Are requests failing or slowing? Are dependencies and worker snapshots healthy? |
| [Requests](grafana/dashboards/fleet-mcp.json) | Which MCP operations or HTTP routes fail? How do p50/p95/p99 and latency distributions change with load? |
| [Dependencies](grafana/dashboards/fleet-dependencies.json) | Are database retries amplifying work? Is local embedding or its provider slow or failing? |
| [Workers](grafana/dashboards/fleet-workers.json) | Is the snapshot fresh, did that run succeed, and which step or source failed? How much work did it finish? |
| [Kubernetes](grafana/dashboards/fleet-kubernetes.json) | Are nodes and workloads ready? Which containers restart, run out of memory, throttle, or approach limits? Are CronJobs keeping schedule? |
| [Logs & Events](grafana/dashboards/fleet-logs.json) | What did this pod log? Which structured operations failed? Which Kubernetes warnings explain scheduling or startup trouble? |

Start in Overview, follow Requests/Dependencies for application issues, or
Kubernetes for resource and scheduling issues. Kubernetes pod tables link to
matching logs. Dashboard navigation preserves the time range and compatible
filters. Prometheus and Loki datasource selectors allow reuse in another
Grafana installation. Panels include scope and interpretation notes.

Missing data stays missing. A quiet histogram cannot produce a meaningful
latency percentile, a container without a memory limit has no utilization-of-
limit ratio, and a stopped target is not zero traffic. Worker freshness and
last-run success are separate: a fresh failed run is still a failure. The
worker dashboard reads completed-run counters directly; applying `rate()` to
these replacement snapshots would invent throughput.

## Collection and storage

| Component | Input / purpose | Persistence |
|---|---|---|
| Prometheus | Annotated Fleet pods, kubelet/cAdvisor through the verified API proxy, kube-state-metrics, node exporter, API server | VM hostPath; 3 days or 3 GB of TSDB blocks |
| kube-state-metrics | Read-only Kubernetes object state: readiness, restarts, limits, Jobs and CronJobs | None |
| node exporter | VM CPU, RAM, filesystems, network, plus the worker textfile directory | Worker snapshot on VM hostPath |
| Alloy | Kubernetes pod-log API and namespace events; sends to Loki | VM hostPath for collector positions |
| Loki | Original log lines and Kubernetes events | Single-node filesystem store; 48-hour retention |
| Grafana | Provisioned dashboards and datasources | VM hostPath for its database |

Storage is under `/var/lib/fleet-recall/observability/` inside the Lima VM.
Pod replacement and VM stop/start preserve it; deleting the VM loses it.
HostPaths are deliberately limited to this single-node local deployment and
are not a production storage or availability design. Retention is asynchronous;
WAL, indexes, and temporary files use space beyond Prometheus's block-size
limit. Loki has time retention, not a hard filesystem quota. Watch the node
filesystem panel and adjust retention/resources for the actual log volume.

Alloy collects only `fleet-recall`, `ory`, `localstack`, `kube-system`, and
`fleet-observability`. Change the namespace allowlists and their RBAC together
to add another namespace. Stream labels are `cluster`, `deployment`,
`namespace`, `pod`, `container`, `app`, and `node`; Kubernetes events use their
own stream job. Request IDs and user/content fields are not stream labels.
The log dashboard parses Fleet's nested JSON fields at query time and also
shows ordinary non-JSON logs. The event collector exposes Kubernetes event
`type`, `reason`, and `msg` fields in JSON.

Collection is operational telemetry, not an audit ledger: Kubernetes rotates
pod logs and expires events, and outages can lose entries despite persisted
collector positions. Existing application/dependency logs can include sensitive
diagnostics; structured operation events add only bounded operational fields.
Access to Grafana or Loki grants access to collected raw logs. Keep this local
stack private and apply your own redaction policy before extending collection.

## Application integration

The local demo and ingress pod templates expose a **pod-only** `metrics` port
9091 and opt into the `fleet-recall` scrape job with
`prometheus.io/scrape: "true"`. Their public Services expose only the application
port. The worker writes `/metrics/worker.prom` atomically to a dedicated VM
directory shared with node exporter as UID 10001; the file stays mode 0600.
The CronJob forbids overlap. One collector directory represents exactly one
scheduled worker identity.

Source changes take effect after rebuilding and deploying an image containing
the telemetry code (`bootstrap.sh phase images`, then `phase recall`, with
the normal local state/model configuration). Installing monitoring alone does
not replace application images. Infrastructure and raw log panels work with
the existing images; application and structured-event panels need the new
binary and actual traffic. The current stdio writer is an exec target, not a
persistent metrics listener; `kubectl exec` streams are also separate from
the container's main-process log stream. A host-launched remote MCP process runs
`serve --http` outside Kubernetes discovery and pod-log collection.
Its `http_mcp` and nested `mcp` metrics need an explicit Prometheus target
reachable from the monitoring pod; host JSON stderr needs separate log
shipping. See [remote-plane telemetry](../../docs/REMOTE_PLANE.md) for launcher
configuration. The M4 HTTPS profile deploys Recall in an annotated pod with the
same named metrics port, scrape annotation and metrics environment as the other services.
Do not put a fixed listener in shared configuration used by concurrent CLI
processes.

Prometheus uses `deployment="local-k0s"` and `cluster="k0s"`. The Kubernetes
Deployment object's name is normalized to `workload_deployment` to avoid a
label collision. The `fleet-worker-textfile` job keeps only Fleet snapshots
and textfile scrape errors; the ordinary `node-exporter` job excludes Fleet
snapshot metrics so service-rate queries cannot accidentally include them.

## Verification and changes

```sh
deploy/observability/install-k0s.sh verify
python3 deploy/observability/validate_dashboards.py \
  --rules-output /tmp/fleet-dashboard-rules.json
promtool check rules /tmp/fleet-dashboard-rules.json
promtool test rules deploy/observability/alerts.test.yml
promtool test rules deploy/observability/k0s-alerts.test.yml
promtool test rules deploy/observability/remote-alerts.test.yml
```

For live query validation, forward the private services in separate terminals:

```sh
kubectl -n fleet-observability port-forward service/prometheus 9090:9090
kubectl -n fleet-observability port-forward service/loki 3100:3100
python3 deploy/observability/validate_dashboards.py \
  --prometheus-url http://127.0.0.1:9090 --loki-url http://127.0.0.1:3100
  # Add --require-k0s-targets to require every expected infrastructure scrape job.
```

The validator checks panel layout, datasource/variable wiring, snapshot
semantics, and every panel query. Live checks report accepted queries and
data availability without printing log contents. Installer `verify` also
checks all six provisioned dashboards, both datasource plugins/connections,
all ten required scrape jobs, and that pod logs and events have arrived within
Loki's 48-hour retention window. It opens temporary loopback forwards and
keeps the admin credential in memory. This catches datasource failures that
pod readiness alone cannot detect. Prometheus `/targets` should
show the infrastructure targets up. Application targets appear only when the
annotated pods are deployed. Grafana's Kubernetes and Logs dashboards should
then show the live node, workloads, pod logs, and events. Alert evaluation is
included for application errors, worker freshness/failures, infrastructure
scrape coverage, node pressure/readiness, low disk space, crash loops, recent
OOM restarts, and overdue CronJobs. Thresholds are starting points in
[`alerts.yml`](alerts.yml) and [`k0s-alerts.yml`](k0s-alerts.yml).
**Notification delivery is not configured**. Connect Prometheus to
an Alertmanager and configure receivers before relying on paging.

For the installed M4 HTTPS profile, use `FLEET_OBSERVABILITY_REMOTE=true` with
`install-k0s.sh render`, `up`, and `verify`. This enables the separate
[`remote-alerts.yml`](remote-alerts.yml) pack, private Traefik and cert-manager
scrapes, read-only Pod discovery in their existing namespaces, and a private
once-per-minute dependency probe. The probe uses the existing public
`fleet-oidc-ca` ConfigMap and writes its own atomic node-exporter textfile.
It mounts no credentials. Its Python runtime defaults to the already imported
`ostk-sandbox:m4-20260927b`; override `FLEET_OBSERVABILITY_PROBE_IMAGE` with an
imported image containing `/usr/bin/python3` if the local release changes.
Images are never pulled automatically. The default
base profile does not require those namespaces. Keep using the flag on later
updates: selecting the base profile explicitly removes remote scrapes/rules
from the generated ConfigMaps and suspends the retained probe CronJob. It does
not delete the retained discovery RoleBindings, probe snapshots or application
data.

Overview includes a remote lifecycle section for core readiness, probe age,
HTTP response classes/denials, spool quota/I/O refusals, worker age versus its
computed budget, loaded/managed leaf expiry, and backing filesystem byte/inode
capacity. Remote verification requires the new gauges/counters and certificate
series, all three fresh successful dependency probes, and healthy scrape jobs.
Issuer discovery and JWKS use the canonical verified HTTPS path. The tokenless
embedding check verifies transport and the authentication guard; observed
authenticated descriptor/inference failures have a separate alert. Rebuild and deploy the M4.3 application
image before enabling that verification. See the
[thresholds and response guidance](../../docs/TELEMETRY.md#remote-https-lifecycle-alerts).

Edit the dashboard JSON in Git and rerun the installer. Grafana reloads the
files; datasource and alert-rule changes trigger a content-based rollout.
Provisioned dashboards are read-only in the UI to prevent unnoticed drift.
For an existing Grafana, import the JSON files or mount `grafana/dashboards`
at `/var/lib/grafana/dashboards` and use the two `grafana/provisioning` files.
Set `FLEET_PROMETHEUS_URL` and `FLEET_LOKI_URL` in that Grafana process to URLs
reachable from its network, and select the appropriate datasources.

## Existing Prometheus installations

The top-level `prometheus.yml` and `alerts.yml` connect existing Prometheus and node exporter installations to
Fleet Recall's private metrics endpoint and scheduled-worker snapshots. They
do not deploy a monitoring stack or configure alert delivery on their own.

1. Enable `FLEET_RECALL_METRICS_LISTEN=127.0.0.1:9091` on the long-running
   Fleet process. Keep its normal database/model configuration.
2. Prepare the worker snapshot directory. Run node exporter with
   `--collector.textfile.directory=/var/lib/fleet-recall-metrics` and give it
   access to the worker's `0600` snapshot files. Set
   `FLEET_RECALL_METRICS_TEXTFILE=/var/lib/fleet-recall-metrics/worker.prom`
   on the scheduled `worker --once` command.
3. Copy or merge `prometheus.yml` into the existing scrape configuration and
   `alerts.yml` into the configured rule directory. Adjust private target
   addresses and coarse deployment/role labels. The example assumes the
   processes share one host/network namespace; container loopback points to
   that container, not the application host.
4. The shared worker rule assumes a five-minute schedule: two missed ticks
   plus the last measured runtime (minimum one minute), followed by a one-minute
   hold. Legacy snapshots without duration use 15 minutes. Adjust the 600-second
   cadence constant for other schedules. Tune request latency and
   error-rate thresholds with observed traffic. Connect these rules to the
   deployment's existing Alertmanager and notification routing.

Validate with the installed Prometheus tools before reloading:

```sh
cd deploy/observability
promtool check config prometheus.yml
promtool check rules alerts.yml
promtool test rules alerts.test.yml
```

Rule tests exercise worker failure-to-success replacement, stale and missing
snapshots, a snapshot from the wrong command, alert hold times, and the live
MCP error-rate threshold and traffic floor.

Inspect a live endpoint from an authorized scraper host:

```sh
curl --fail http://127.0.0.1:9091/metrics
```

The live `fleet-recall` scrape job supports `rate()`/`increase()` across
process counter resets. The `fleet-worker-textfile` job publishes one
completed invocation; its counter values must be read directly. The recording
rule `fleet_recall_worker_last_run_failed` provides a last-run gauge (0/1).
It is absent when no terminal worker process observation exists, which has a
separate alert. A fresh failed run still updates snapshot freshness.

Use exactly one Fleet snapshot identity per node-exporter endpoint/collector
directory. Multiple `.prom` filenames do not distinguish duplicate metric
series. Separate independently scheduled workers into separate collector
endpoints, and do not let other CLI commands overwrite the worker snapshot.

Metrics listeners have no authentication or TLS. Keep them private; a
non-loopback bind requires `FLEET_RECALL_METRICS_ALLOW_NON_LOOPBACK=true` and
an appropriate network/proxy boundary. The examples contain no credentials
and should not be exposed through the public application.

See [the operator guide](../../docs/TELEMETRY.md) for the event schema, metric
coverage, PromQL, privacy constraints, and response runbook.
