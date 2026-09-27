#!/usr/bin/env python3
"""Check dashboard structure and optionally validate queries against live backends.

Write expanded PromQL as a rule file for `promtool check rules` using
--rules-output PATH. Live checks report counts, never log or event contents.
"""

import argparse
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request


def expand(expression):
    replacements = {
        "__rate_interval": "5m", "__range": "1h", "__interval": "1m",
        "snapshot_max_age": "900", "search": '""',
    }
    pattern = r"\$\{([A-Za-z_]\w*)(?::\w+)?\}|\$([A-Za-z_]\w*)"
    return re.sub(pattern, lambda m: replacements.get(m[1] or m[2], ".*"), expression)


def backend_check(base, kind, expression):
    now = int(time.time())
    if kind == "loki":
        endpoint = "/loki/api/v1/query_range"
        params = {"query": expression, "start": str((now - 600) * 10**9),
                  "end": str(now * 10**9), "step": "60", "limit": "1"}
    else:
        endpoint = "/api/v1/query"
        params = {"query": expression, "time": str(now)}
    url = base.rstrip("/") + endpoint + "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        raise ValueError(f"{kind} rejected query: {error.read().decode()[:1500]}") from error
    if payload.get("status") != "success":
        raise ValueError(f"{kind} query failed: {payload.get('error', 'unknown error')}")
    return bool(payload.get("data", {}).get("result"))


def validate(args):
    root = Path(__file__).parent / "grafana" / "dashboards"
    expected = {"fleet-overview", "fleet-mcp", "fleet-dependencies", "fleet-workers",
                "fleet-kubernetes", "fleet-logs"}
    seen = set()
    rules = []
    live_count = nonempty = query_count = 0
    for path in sorted(root.glob("*.json")):
        try:
            dashboard = json.loads(path.read_text())
        except json.JSONDecodeError as error:
            raise ValueError(f"Invalid dashboard JSON: {path}") from error
        uid = dashboard["uid"]
        assert uid not in seen, f"duplicate dashboard UID: {uid}"
        seen.add(uid)
        assert dashboard["schemaVersion"] >= 39, path
        variables = {v["name"] for v in dashboard["templating"]["list"]}
        links = dashboard.get("links", [])
        assert {link["url"].split("/")[-1] for link in links} == expected - {uid}, uid
        assert all(link.get("includeVars") and link.get("keepTime") for link in links), uid
        for variable in dashboard["templating"]["list"]:
            if variable["type"] != "query":
                continue
            query = variable["query"]
            query = query["query"] if isinstance(query, dict) else query
            match = re.fullmatch(r"label_values\((.*),\s*\w+\)", query)
            assert match, f"{uid}: unsupported query-variable syntax: {query}"
            selector = expand(match[1])
            kind = variable["datasource"]["type"]
            if kind == "prometheus":
                rules.append({"record": f"dashboard_check_{len(rules)}", "expr": selector})
            base = args.prometheus_url if kind == "prometheus" else args.loki_url
            if base:
                nonempty += backend_check(base, kind, selector)
                live_count += 1
        panels = dashboard["panels"]
        ids = set()
        occupied = set()
        for panel in panels:
            assert panel["id"] not in ids, f"{uid}: duplicate panel ID"
            ids.add(panel["id"])
            grid = panel["gridPos"]
            assert 0 <= grid["x"] < 24 and 0 < grid["w"] <= 24 - grid["x"], panel["title"]
            assert grid["y"] >= 0 and grid["h"] > 0, panel["title"]
            cells = {(x, y) for x in range(grid["x"], grid["x"] + grid["w"])
                     for y in range(grid["y"], grid["y"] + grid["h"])}
            assert not cells & occupied, f"{uid}: overlapping panel {panel['title']}"
            occupied |= cells
            for target in panel.get("targets", []):
                expression = target.get("expr")
                if not expression:
                    continue
                query_count += 1
                datasource = target.get("datasource", panel.get("datasource", {}))
                kind = datasource.get("type")
                assert kind in {"prometheus", "loki"}, f"{uid}: unknown datasource"
                assert kind in variables, f"{uid}: missing datasource variable"
                assert datasource["uid"] in {"$" + kind, "${" + kind + "}"}, (uid, datasource)
                for match in re.finditer(r"\$\{(\w+)(?::\w+)?\}|\$(\w+)", expression):
                    variable = match[1] or match[2]
                    assert variable.startswith("__") or variable in variables, (uid, variable)
                if uid == "fleet-workers" or "fleet-worker-textfile" in expression:
                    assert not re.search(r"\b(?:rate|irate|increase|sum_over_time)\s*\(", expression), expression
                assert not re.search(r"\bvector\s*\(\s*0\s*\)", expression), f"{uid}: masks missing data"
                if kind == "loki" and not expression.lstrip().startswith("{"):
                    assert "operation_id=" not in expression and "duration_seconds=" not in expression, expression
                expanded = expand(expression)
                if kind == "prometheus":
                    rules.append({"record": f"dashboard_check_{len(rules)}", "expr": expanded})
                base = args.prometheus_url if kind == "prometheus" else args.loki_url
                if base:
                    try:
                        nonempty += backend_check(base, kind, expanded)
                    except ValueError as error:
                        raise ValueError(f"{uid} / {panel['title']}: {error}") from error
                    live_count += 1
        print(f"{uid}: {len(panels)} panels validated")
    assert seen == expected, f"dashboard set differs: {seen ^ expected}"
    if args.rules_output:
        Path(args.rules_output).write_text(json.dumps({"groups": [{"name": "dashboard-checks", "rules": rules}]}, indent=2) + "\n")
    print(f"{len(seen)} dashboards; {query_count} queries; {len(rules)} PromQL expressions")
    if live_count:
        print(f"Live queries: {live_count} accepted; {nonempty} currently return data")
    if args.require_k0s_targets:
        assert args.prometheus_url, "--require-k0s-targets requires --prometheus-url"
        for job in ["node-exporter", "kube-state-metrics", "kubernetes-nodes", "kubernetes-cadvisor", "kubernetes-apiserver", "fleet-worker-textfile", "prometheus", "loki", "alloy", "grafana"]:
            healthy = backend_check(args.prometheus_url, "prometheus", f'up{{job="{job}",cluster="k0s"}} == 1')
            assert healthy, f"no healthy k0s target for {job}"
            print(f"Healthy scrape job: {job}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-output")
    parser.add_argument("--prometheus-url")
    parser.add_argument("--loki-url")
    parser.add_argument("--require-k0s-targets", action="store_true")
    validate(parser.parse_args())
