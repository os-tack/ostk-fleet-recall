# Operating telemetry

Fleet Recall emits structured JSON events to stderr and exposes optional
Prometheus metrics. These observations describe process health and work; they
are separate from the governed evidence, measurement, and audit ledgers.

## Enable collection

| Setting | Default | Effect |
| --- | --- | --- |
| `FLEET_RECALL_LOG_FORMAT` | `json` | `json` or `text`; both write to stderr. |
| `RUST_LOG` | `ostk_fleet_recall=info` | Filters tracing events. Completion events require `info`. |
| `FLEET_RECALL_METRICS_LISTEN` | unset | Optional private HTTP listener, for example `127.0.0.1:9091`. |
| `FLEET_RECALL_METRICS_ALLOW_NON_LOOPBACK` | `false` | Must be `true` to bind a non-loopback metrics address. |
| `FLEET_RECALL_METRICS_TEXTFILE` | unset | Destination `.prom` file replaced atomically when the command finishes. |

For a long-running MCP server, with its normal database and model configuration:

```sh
FLEET_RECALL_METRICS_LISTEN=127.0.0.1:9091 \
  ostk-fleet-recall serve
```

The same setting works with `serve --http 127.0.0.1:8080`. The local
`deploy/local/bin/serve-remote.sh` launcher explicitly passes the optional
metrics listen/non-loopback settings to HTTP serving and defaults stderr
events to JSON. It passes a log-format override to enrollment too, but does
not pass the service listener or worker textfile destination to enrollment.

Scrape `http://127.0.0.1:9091/metrics`. The metrics listener is separate from
the application listener, has no authentication or TLS, and exposes only the
metrics route. For cross-host scrapes, bind a private address, set the explicit
non-loopback opt-in, and restrict access with the deployment's network policy
or authenticated proxy. Never publish it through a public application route.
Each process needs its own listener address/port.

MCP protocol frames and CLI reports stay on stdout. Capture stderr with the
deployment's log collector. For local troubleshooting, use
`FLEET_RECALL_LOG_FORMAT=text`; use JSON in log pipelines. Raising `RUST_LOG`
to debug can enable existing dependency and SQL diagnostics; the payload-free
operational event schema below does not sanitize every pre-existing log line.

See [the runnable scrape and alert examples](../deploy/observability/README.md).

## Metrics and events

Metric names and labels:

| Metric | Type | Labels / meaning |
| --- | --- | --- |
| `fleet_recall_operations_total` | Counter | `component`, `operation`, `outcome`; one terminal observation per operation. |
| `fleet_recall_operation_duration_seconds` | Histogram | `component`, `operation`; wall time, including failures and cancellations. |
| `fleet_recall_operations_in_flight` | Gauge | `component`, `operation`; active operations. |
| `fleet_recall_units_total` | Counter | `component`, `operation`, `unit`; numeric progress and response classes. |
| `fleet_recall_build_info` | Gauge | `version`; value `1`. |
| `fleet_recall_process_start_time_seconds` | Gauge | Unix time when the process telemetry registry initialized. |
| `fleet_recall_process_uptime_seconds` | Gauge | Seconds since registry initialization. |
| `fleet_recall_snapshot_time_seconds` | Gauge | Unix time the textfile snapshot was written; textfile export only. |
| `fleet_recall_ready` | Gauge | HTTP remote runtime only: `1` after a fresh successful bounded database check, otherwise `0`, including startup, stale observations and probe failure. |
| `fleet_recall_readiness_last_check_timestamp_seconds` | Gauge | Unix time of the last completed readiness check; zero before any check completes. No dependency URL or database identity is exported. |

Histograms expose `_bucket`, `_sum`, and `_count` series. Finite buckets are
0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60,
and 300 seconds, followed by `+Inf`.

The bounded outcome vocabulary is `success`, `error`, `refused`, `invalid`,
`timeout`, `cancelled`, `skipped`, and `degraded`. Not every operation uses
every outcome. An abandoned future records `cancelled` and releases its
in-flight gauge. A timeout or cancellation does not prove that a mutation
rolled back: follow its receipt/idempotency contract before retrying.

Instrumented boundaries:

| Component | Operations | What it measures |
| --- | --- | --- |
| `process` | CLI command names, including `serve`, `demo`, `ingress`, `worker`, `collect`, `health`, `migrate`, `ingest`, `model_digest`, `enroll` | Command lifetime and exit outcome after logging initialization, including metrics configuration and listener startup failures. Both stdio and HTTP serving use `serve`. |
| `mcp` | `recall.<action>`, `remember.<action>`, protocol categories | Dispatch, refusals, tool failures, malformed frames, and request deadlines. Tool action names are from the closed service enums. |
| `http_mcp` | `mcp`, `resource_metadata`, `grant`, `revoke`, `auth_aws`, `transcript`, `health`, `readiness`, `other` | Remote HTTP latency/outcome and response classes, including requests rejected before MCP dispatch. Grant IDs, transcript identities and query strings never become labels. |
| `runtime` | `readiness` | Bounded core database check outcome and duration. Embedding or issuer outages do not themselves remove lexical service readiness. |
| `transcript` | `receive` | Fixed units `quota_rejected` and `io_errors`, initialized to zero at receiver startup. Quota includes file bytes, scope bytes and file count. I/O includes permission, lock and storage errors. No scope, source, path or raw error is exported. |
| `http_demo` | `index`, `health`, `status`, `recall`, `other` | HTTP latency/outcome and `responses_1xx` through `responses_5xx` units. |
| `http_ingress` | `ingress`, `other` | Push ingress HTTP latency/outcome and response classes. |
| `database` | `health_check`, `serializable_transaction` | Health checks and transactions using the shared serializable retry helper. This is not a timer for every SQL statement. |
| `embedding` | `local_batch`, `embed` | Local batch encoding and validated projection embeddings. Units are `texts` and `embeddings`, respectively. |
| `worker` | `command`, `tick` | Startup/configuration, tick execution, and writing the report; tick failures remain errors even when a report is returned successfully. |
| `worker_step` | `transcript`, `git`, `ci`, `collect`, `bodies`, `lexical`, `dense` | Individual step outcomes and duration; unselected steps are `skipped`. |
| `worker_source` | `transcript`, `git`, `ci`, `collector` | Aggregated numeric source counters and `sources_ok`, `sources_unchanged`, `sources_failed` units; no source identities. |

Protocol fallback operations are fixed categories such as `protocol.unknown`,
`protocol.parse`, `protocol.invalid`, `tools.call.unknown`, `recall.unknown`,
`remember.unknown`, `frame.oversize`, `frame.invalid_utf8`, and `notification`.
Notifications record `skipped`; tool-shaped notifications do not execute.
HTTP 401/403/429 map to `refused`, 408/504 to `timeout`, other 4xx to `invalid`,
and other 5xx to `error`.

Modern discovery uses `mcp/server.discover`; protocol version and header
validation failures are `invalid`. Requests rejected by the HTTP layer before
dispatch have only an `http_mcp` observation. A dispatch deadline records one
`mcp` timeout; its existing JSON-RPC error maps to HTTP 500 and therefore an
`http_mcp` error. Authentication, grant, and AWS exchange deadlines return 503
and likewise record an HTTP error; body-read deadlines return 408 and record
an HTTP timeout. This preserves the wire contract and separates protocol
outcomes from HTTP status. Do not sum MCP and HTTP counters for total requests.

For `database/serializable_transaction`, `attempts` counts attempts including
the first; `retries_body` and `retries_commit` count retries after backoff;
`retries_exhausted` counts serialization failures that exhausted the policy.
Worker units include `appended`, `replayed`, `quarantined`, `dead_lettered`,
`retry_exhausted`, `rows_indexed`, `events_projected`, `turns_redacted`, and
`items_refused`. Step and source totals describe different levels of work:
do not sum across these components to calculate throughput. All worker unit
names pass an explicit code-owned allowlist.

Each completed operation emits an `info` JSON tracing event. Its `fields`
object includes:

```json
{
  "event": "operation.completed",
  "event_version": 1,
  "component": "mcp",
  "operation": "recall.search",
  "outcome": "success",
  "duration_seconds": 0.021
}
```

Tracing also supplies the timestamp, level, target, and operation span with a
generated `operation_id`. Use the span ID to correlate observations within
the process; it is never a metric label or an externally propagated trace ID.
Lifecycle events include `process.started`, `telemetry.exporter.started`,
`telemetry.exporter.failed`, and `telemetry.export.failed`.

## Scheduled workers

Short-lived `worker --once` processes should write a snapshot for the
Prometheus node exporter textfile collector. Prepare an existing writable
directory, run the collector with `--collector.textfile.directory` pointing
there, and configure the scheduled command:

```sh
FLEET_RECALL_METRICS_TEXTFILE=/var/lib/fleet-recall-metrics/worker.prom \
  ostk-fleet-recall worker --once --sources /etc/fleet-recall/sources.json
```

The node exporter must be able to read the file. Snapshots are created with
mode `0600` on Unix, so use the same effective user or an explicitly approved
privileged collector. Directory creation and collector installation are
deployment responsibilities. Each successful publication replaces the previous
file; readers see either the previous complete snapshot or the new one.

Use one Fleet Recall snapshot identity per node-exporter endpoint/collector
directory. Multiple Fleet `.prom` files expose duplicate unlabeled build,
snapshot, and operation series; filenames do not namespace those series. Use
separate collector endpoints for independent worker schedules. Keep other
commands from overwriting the worker's snapshot, and prevent overlapping
scheduled worker runs.

Snapshots are attempted after command success and failure, once the telemetry
runtime has initialized. Metrics setup failures emit a terminal process error
event but cannot publish a snapshot. A CLI parse failure, invalid telemetry configuration,
exporter startup failure, kill, crash, or snapshot write failure may leave an
old file or no file. A fresh snapshot proves a terminal publication, not a
successful tick. Monitor both freshness and the process outcome.

All counters restart with each process. A worker snapshot represents one
invocation; **never use `rate()` or `increase()` on its counters**. The sample
rules derive `fleet_recall_worker_last_run_failed` as a gauge: `1` for the
last published `process/worker` error and `0` for its success. They separately
alert for a stale/missing worker snapshot, unreadable textfiles, and an
unreachable collector. Tune the default 15-minute freshness limit to the
schedule plus the longest expected run and collection delay.

## Useful PromQL

These live-process queries use the example `fleet-recall` scrape job. Add
deployment/role filters when operating multiple targets.

Request error fraction by MCP operation (missing error series become zero):

```promql
(
  sum by (job, instance, operation) (
    rate(fleet_recall_operations_total{job="fleet-recall", component="mcp", operation=~"recall\\..*|remember\\..*", outcome=~"error|timeout|cancelled"}[5m])
  )
  or
  0 * sum by (job, instance, operation) (
    rate(fleet_recall_operations_total{job="fleet-recall", component="mcp", operation=~"recall\\..*|remember\\..*"}[5m])
  )
)
/
clamp_min(sum by (job, instance, operation) (
  rate(fleet_recall_operations_total{job="fleet-recall", component="mcp", operation=~"recall\\..*|remember\\..*"}[5m])
), 0.000001)
```

95th percentile wall time, including unsuccessful calls:

```promql
histogram_quantile(0.95, sum by (le, job, instance, operation) (
  rate(fleet_recall_operation_duration_seconds_bucket{job="fleet-recall", component="mcp", operation=~"recall\\..*|remember\\..*"}[5m])
))
```

Serialization retries per second and retries exhausted in the last 5 minutes:

```promql
sum by (job, instance, unit) (
  rate(fleet_recall_units_total{job="fleet-recall", component="database", operation="serializable_transaction", unit=~"retries_body|retries_commit"}[5m])
)
```

```promql
sum by (job, instance) (
  increase(fleet_recall_units_total{job="fleet-recall", component="database", operation="serializable_transaction", unit="retries_exhausted"}[5m])
)
```

Age of the last worker snapshot, and its recorded failure gauge:

```promql
time() - fleet_recall_snapshot_time_seconds{job="fleet-worker-textfile"}
```

```promql
fleet_recall_worker_last_run_failed{job="fleet-worker-textfile"}
```

Live counters reset at process restart; Prometheus `rate()` handles a reset
between observed samples. Events before the first scrape and very short-lived
processes may be missed by scraping. Use events/textfiles for those cases.
Histograms and in-flight counts describe nested operations, so summing every
component does not produce a request count or process utilization measure.

An observed operation initializes zero counters for every outcome, and the
transaction helper initializes its retry counters before work. This lets a
later first failure be compared with a previously scraped zero baseline.

## Response runbook

1. **Target down:** verify the process, metrics bind address, firewall/proxy,
   and scraper network namespace. An available metrics endpoint is not a
   database readiness check; inspect `health_check` and application health too.
2. **MCP errors or latency:** compare the operation's error, timeout, refused,
   and invalid outcomes; inspect JSON completion events by operation and time.
   Compare database transaction and embedding duration. Follow the existing
   mutation receipt rules when a client timed out.
3. **Serialization retries/exhaustion:** inspect concurrent writers and
   transaction contention. Check CockroachDB operational diagnostics; avoid
   automatically increasing retries to hide persistent contention.
4. **Worker failure:** read the last process event and the protected stdout
   tick report. Inspect the failing step and bounded unit counts for held,
   dead-lettered, refused, or unindexable work. The report contains the detailed
   source context deliberately absent from telemetry.
5. **Worker stale/missing snapshot:** verify scheduler execution, overlapping
   jobs, destination permissions, collector readability, clock agreement,
   `node_textfile_scrape_error`, and telemetry export failure events. A failed
   export can leave a previously healthy snapshot visible.

### Remote HTTPS lifecycle alerts

The M4 local profile adds `remote-alerts.yml` and a lifecycle section to the
existing Overview dashboard. Enable it explicitly when installing or updating
the HTTPS deployment's monitoring:

```sh
FLEET_OBSERVABILITY_REMOTE=true \
KUBECONFIG=deploy/local/.state/kubeconfig \
  deploy/observability/install-k0s.sh up
```

Use the same flag for `render` and `verify`. The default remains the base stack
without HTTPS dependencies. Switching back to `false` removes the remote
scrapes/rules from their ConfigMaps; it does not delete retained pod-discovery
RoleBindings. Both profiles retain the existing dashboards and infrastructure
alerts. Remote mode requires the `fleet-edge` and `fleet-pki` namespaces and an
application image containing the readiness and spool instruments.

| Signal | Evaluation and response |
| --- | --- |
| Core readiness | Failed or missing readiness for one minute; inspect bounded database checks. `/healthz` remains listener liveness. A healthy metrics scrape alone is insufficient. |
| HTTP failures | More than 5% 5xx, at least five errors in five minutes, sustained two minutes. Separate gateway and Recall alerts locate Ory/edge versus application failures. HTTP 200 tool errors remain covered by MCP alerts. |
| Denials | More than 20% 401/403/429 and at least twenty denials in five minutes, sustained five minutes. Expected OAuth challenges and explicit negative tests can contribute; this is operational diagnosis, not proof of attack. |
| Worker freshness | Two missed five-minute ticks (600 seconds), plus the last measured process runtime, with a 60-second minimum and a one-minute alert hold. Legacy snapshots without duration use 900 seconds. Fresh failed runs still fire the separate last-run failure alert. Missing snapshots/collector failures remain separate. |
| Spool refusal | Any increase in quota or I/O refusals over five minutes. Inspect configured per-file/per-scope/file-count limits separately from storage exhaustion. Counters begin at zero, and a missing quota counter has its own alert. |
| Storage capacity | Existing node alert below 10% available bytes and a new alert below 10% free inodes, each for ten minutes. The spool's hostPath shares VM storage; the PV's declared 2 GiB is not an enforced filesystem quota. No per-tenant usage is exported. |
| Certificate expiry | Managed leaf below fourteen days for five minutes; gateway-loaded leaf below seven days for five minutes is critical. Missing certificate metrics alert independently. Automatic renewal is configured thirty days before expiry. These gauges do not verify network trust, every SNI name, or root/intermediate lifetime. |
| Dependency reachability | Fixed, tokenless issuer discovery/JWKS and embedding-listener checks every minute; a failed probe holds one minute. Snapshots older than three minutes or over thirty seconds in the future hold one minute; absent samples have a separate two-minute alert. Authenticated embedding client errors alert separately. |

The private `remote-dependency-probe` CronJob reuses the imported sandbox image
as a Python runtime with its entrypoint overridden. It mounts only the public
CA ConfigMap, the fixed probe script, and the existing node-exporter textfile
directory. It mounts no tokens or Secrets and has no Kubernetes API access.
HTTPS requests verify the canonical issuer, host certificate and exact fixed
JWKS URL; redirects are refused, each request has an eight-second deadline and
responses are limited to 64 KiB. Refused/reset connections retry at one-second
intervals within that same total deadline, covering observed transient
connection refusals during fresh-Pod startup. TLS, HTTP status and schema
errors are never retried.
The embedding check expects an unauthenticated
401 from the protected internal descriptor endpoint. This proves transport and
the authentication guard, not descriptor agreement or successful inference;
the separate embedding-client alert covers observed authenticated failures.
Only the three fixed target categories, health, duration and completion time
are exported. Failed checks still publish a fresh snapshot atomically without
overwriting the worker snapshot. Ory Deployment readiness alone does not prove
the canonical HTTPS path works.

Worker duration and freshness budget are exposed as recording rules
`fleet_recall_worker_last_run_duration_seconds` and
`fleet_recall_worker_snapshot_max_age_seconds`. They read completed snapshots
directly. The existing Workers dashboard's configurable static freshness
threshold remains a triage view; the Overview lifecycle panel shows the actual
duration-aware alert budget. Recalibrate the cadence constant if the CronJob
schedule changes. An active or deliberately suspended worker does not silence
freshness alerts automatically; use an explicit maintenance silence if a
notification system is added.

Private pod discovery adds get/list/watch **Pods only** in the edge and PKI
namespaces. It adds no Secret access. Only fixed gateway request/certificate
metrics and certificate-controller status/expiry/renewal metrics are ingested;
no HTTP headers, request paths, users, prompts or transcript contents are
metric labels. The gateway metrics port stays subject to its Prometheus-only
ingress policy. PKI controller metrics remain private ClusterIP/pod traffic;
the existing privileged PKI namespace is not claimed to have ingress isolation.
See [Traefik metrics](https://doc.traefik.io/traefik/reference/install-configuration/observability/metrics/)
and [cert-manager metrics](https://cert-manager.io/docs/devops-tips/prometheus-metrics/).

Run `promtool test rules deploy/observability/remote-alerts.test.yml` alongside
the existing rule tests. Fixtures exercise alert hold times, recovery,
readiness/target/certificate absence, HTTP traffic floors and exact ratio
boundaries, initial spool refusal, byte/inode pressure, and the measured worker
duration allowance. This proves evaluation; it does not prove that an external
receiver delivered a notification. Alertmanager/paging remains unconfigured.
Live installer verification additionally requires healthy new scrape jobs,
ready Recall, initialized spool counters, unexpired managed/loaded leaf
metrics and fresh successful samples for all three fixed dependency probes
before reporting success.

The example alert thresholds are starting points, not established service
objectives. Configure an Alertmanager/notification route in the existing
monitoring system before relying on alerts; these examples do not deploy one.

## Privacy and boundaries

For the local k0s deployment, the [monitoring stack and dashboard guide](../deploy/observability/README.md)
adds Grafana, Prometheus, Loki, Alloy, node exporter, and kube-state-metrics.
It covers container resources, cluster state, pod logs and Kubernetes events,
and explains activation, retention, and the distinction between live service
counters and completed-worker snapshots.

The Mac process started by `deploy/local/bin/serve-remote.sh` is outside that
pod discovery and API log collection. Its optional loopback metrics endpoint
and stderr require a separately configured private host scrape/forwarding
path and host log collection. A VM or pod's loopback is not the Mac's loopback.
See [remote HTTP operation](REMOTE_PLANE.md#operational-visibility); enabling
the host listener alone does not add its data to the k0s dashboards.

New operational metrics and completion events contain only code-owned
categories, numeric measurements, build version, and generated operation IDs
in spans. They exclude query/body text, credentials, headers, cookies,
environment values, tenant/project/agent identities, source paths and IDs,
URLs, database values, and free-form error messages. Unknown routes, methods,
and actions collapse to fixed fallback categories. Cardinality therefore
does not grow with corpus size or caller-supplied identifiers.

Metrics are local to a process; they are not a durable audit trail, do not
authenticate a mutation, and are not automatically stored in the governed
telemetry evidence contracts. No external SaaS export or distributed tracing
collector is configured. Attach coarse deployment/role labels at scrape time,
protect collected logs and metrics, and choose retention in the monitoring
system. Existing CLI reports and diagnostic logs retain their existing data
contracts; do not treat them as sanitized telemetry exports.
