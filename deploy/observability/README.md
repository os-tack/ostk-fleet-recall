# Prometheus examples

These files connect existing Prometheus and node exporter installations to
Fleet Recall's private metrics endpoint and scheduled-worker snapshots. They
do not deploy a monitoring stack or configure alert delivery.

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
4. Set the worker freshness threshold to the schedule interval plus the
   longest acceptable runtime and collection delay. Tune request latency and
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
