#!/usr/bin/env python3
"""Verify local k0s dashboards, datasource plugins, scrapes, and log ingestion.

Requires an explicit KUBECONFIG. Creates only temporary loopback port-forwards;
credentials stay in memory and output contains counts or a fixed failing check.
The log counts cover Loki's 48-hour retention window, including quiet clusters.
"""

import base64
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

NAMESPACE = "fleet-observability"
DASHBOARDS = ("overview", "mcp", "workers", "dependencies", "kubernetes", "logs")
JOBS = ("kubernetes-nodes", "kubernetes-cadvisor", "kube-state-metrics", "node-exporter",
        "kubernetes-apiserver", "fleet-worker-textfile", "prometheus", "loki", "alloy", "grafana")
SERVICES = {"grafana": 3000, "prometheus": 9090, "loki": 3100}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        return None  # Never forward Grafana authorization to a redirected URL.


def verify():
    kubeconfig = os.environ.get("KUBECONFIG")
    if not kubeconfig:
        print("Set KUBECONFIG explicitly before verifying the local k0s stack.", file=sys.stderr)
        return 1
    command = ["kubectl", "--kubeconfig", kubeconfig, "-n", NAMESPACE]
    deadline = time.monotonic() + 90
    processes, forwards = [], {}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    stage, authorization = "admin credential", None

    def remaining(maximum=10):
        timeout = min(maximum, deadline - time.monotonic())
        if timeout <= 0:
            raise TimeoutError()
        return timeout

    def forward(service):
        existing = forwards.get(service)
        if existing and existing[0].poll() is None:
            return existing[1]
        # ubs:ignore python.lifecycle.popen_handle -- registered below; finally terminates and waits for every owned process.
        process = subprocess.Popen(
            command + ["port-forward", "--address", "127.0.0.1", "service/" + service,
                       ":" + str(SERVICES[service])],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace",
        )
        processes.append(process)
        ready = queue.Queue()

        def drain():
            found = False
            for line in process.stdout:
                match = re.search(r"Forwarding from 127\.0\.0\.1:(\d+) ->", line)
                if match and not found:
                    ready.put(int(match.group(1)))
                    found = True
            if not found:
                ready.put(None)

        threading.Thread(target=drain, daemon=True).start()
        port = ready.get(timeout=remaining(10))
        if port is None:
            raise ConnectionError()
        url = "http://127.0.0.1:" + str(port)
        forwards[service] = (process, url)
        return url

    def request(base, path, auth=None):
        # Disable proxies and redirects, and construct every URL ourselves.
        assert urllib.parse.urlsplit(base).hostname == "127.0.0.1"
        headers = {"Authorization": auth} if auth else {}
        with opener.open(urllib.request.Request(base + path, headers=headers),
                         timeout=remaining()) as response:
            try:
                return json.load(response)
            except json.JSONDecodeError as error:
                raise ValueError("Backend did not return JSON") from error

    def query(base, path, expression):
        result = request(base, path + "?" + urllib.parse.urlencode({"query": expression}))
        if result.get("status") != "success":
            raise ValueError()
        return result["data"]["result"]

    try:
        while time.monotonic() < deadline:
            try:
                if authorization is None:
                    stage = "admin credential"
                    result = subprocess.run(command + ["get", "secret", "fleet-grafana-admin", "-o", "json"],
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=remaining())
                    data = json.loads(result.stdout)["data"]
                    credential = base64.b64decode(data["user"], validate=True) + b":" + base64.b64decode(data["password"], validate=True)
                    authorization = "Basic " + base64.b64encode(credential).decode("ascii")
                urls = {}
                for service in SERVICES:
                    stage = service + " port-forward"
                    urls[service] = forward(service)
                for name in DASHBOARDS:
                    stage = "dashboard fleet-" + name
                    dashboard = request(urls["grafana"], "/api/dashboards/uid/fleet-" + name, authorization)
                    if dashboard["dashboard"]["uid"] != "fleet-" + name or not dashboard["meta"].get("provisioned"):
                        raise ValueError()
                for name in ("prometheus", "loki"):
                    stage = "datasource fleet-" + name
                    health = request(urls["grafana"], "/api/datasources/uid/fleet-" + name + "/health", authorization)
                    if health.get("status") != "OK":
                        raise ValueError()
                stage = "required Prometheus scrape jobs"
                expression = 'up{cluster="k0s",deployment="local-k0s",job=~"' + "|".join(JOBS) + '"}'
                samples = query(urls["prometheus"], "/api/v1/query", expression)
                jobs = {job: [] for job in JOBS}
                for sample in samples:
                    jobs[sample["metric"]["job"]].append(float(sample["value"][1]))
                if not all(values and all(value == 1 for value in values) for values in jobs.values()):
                    raise ValueError()
                counts = {}
                for name in ("kubernetes-pods", "kubernetes-events"):
                    stage = name + " ingestion"
                    expression = 'sum(count_over_time({cluster="k0s",deployment="local-k0s",job="' + name + '"}[48h]))'
                    samples = query(urls["loki"], "/loki/api/v1/query", expression)
                    count = sum(float(sample["value"][1]) for sample in samples)
                    if not count > 0:
                        raise ValueError()
                    counts[name] = int(count)
                print(json.dumps({"dashboards": len(DASHBOARDS), "healthy_datasources": 2,
                                  "up_jobs": len(jobs), "log_entries_48h": counts}))
                return 0
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, queue.Empty):
                time.sleep(max(0, min(2, deadline - time.monotonic())))
        print(json.dumps({"verification": "failed", "check": stage}), file=sys.stderr)
        return 1
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


if __name__ == "__main__":
    sys.exit(verify())
