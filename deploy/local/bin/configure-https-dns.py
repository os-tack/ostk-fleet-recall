#!/usr/bin/env python3
"""Map canonical Fleet names to the HTTPS gateway inside k0s.

Retains the existing Corefile and changes only an explicitly marked server
block. Run after the edge Service exists. Host DNS and Docker host-gateway
mapping are separate; none of these mappings changes the OAuth issuer.
"""

import argparse
import ipaddress
import json
import os
import subprocess
import time
from pathlib import Path

BEGIN = "# BEGIN fleet-recall HTTPS split DNS\n"
END = "# END fleet-recall HTTPS split DNS\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--service", default="fleet-edge")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    state = args.state.resolve(strict=True)
    kube = ["kubectl", "--kubeconfig", str(state / "kubeconfig"), "--request-timeout=30s"]

    def get(namespace, kind, name):
        return json.loads(subprocess.check_output(
            kube + ["-n", namespace, "get", kind, name, "-o", "json"], timeout=40))

    service = get("fleet-edge", "service", args.service)
    address = str(ipaddress.IPv4Address(service["spec"]["clusterIP"]))
    if not any(port["port"] == 8443 for port in service["spec"]["ports"]):
        parser.error("edge Service must expose canonical port 8443")
    config = get("kube-system", "configmap", "coredns")
    original = config["data"]["Corefile"]
    body = original
    if BEGIN in body or END in body:
        if body.count(BEGIN) != 1 or body.count(END) != 1 or body.index(BEGIN) > body.index(END):
            parser.error("malformed managed DNS block")
        prefix, tail = body.split(BEGIN)
        _, suffix = tail.split(END)
        body = prefix + suffix
    if "fleet.test" in body:
        parser.error("an unmanaged fleet.test DNS configuration already exists")
    block = (BEGIN + "fleet.test:53 {\n    errors\n    hosts {\n        " + address
             + " recall.fleet.test auth.fleet.test login.fleet.test\n"
             + "        ttl 30\n        no_reverse\n    }\n    cache 30\n}\n" + END)
    desired = body + block
    if desired == original:
        print("Fleet split DNS already points to " + address)
        return
    backup = state / ("coredns-before-https-" + time.strftime("%Y%m%dT%H%M%S") + ".json")
    with backup.open("x") as target:
        json.dump(config, target, indent=2)
    if args.apply:
        patch = [
            {"op": "test", "path": "/metadata/resourceVersion", "value": config["metadata"]["resourceVersion"]},
            {"op": "replace", "path": "/data/Corefile", "value": desired},
        ]
        subprocess.run(kube + ["-n", "kube-system", "patch", "configmap", "coredns", "--type=json", "-p", json.dumps(patch)], check=True, timeout=40)
        print("Applied Fleet split DNS to " + address + "; allow CoreDNS reload and verify from a pod.")
    else:
        print(block, end="")
        print("Prepared only; use --apply to install. Backup: " + str(backup))


if __name__ == "__main__":
    main()
