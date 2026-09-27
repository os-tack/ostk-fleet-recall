#!/usr/bin/env python3
"""Add only the single-Mac HTTPS forward to an existing, stopped Lima VM.

Does not recreate the VM, alter mounts, or touch its disks. Stop/drain workloads
before stopping the VM; keep all administrative forwards loopback-bound.
"""

import argparse
import json
import shutil
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm", default="k0s")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    records = [json.loads(line) for line in subprocess.check_output(
        ["limactl", "list", "--json"], text=True, timeout=30).splitlines()]
    matches = [record for record in records if record["name"] == args.vm]
    if len(matches) != 1:
        parser.error("expected one existing VM")
    record = matches[0]
    forwards = record["config"]["portForwards"]
    configured = False
    for forward in forwards:
        if forward.get("hostIP", "127.0.0.1") != "127.0.0.1":
            parser.error("single-Mac profile requires existing forwards to remain loopback-bound")
        if forward.get("hostPort") == 8443 or forward.get("guestPort") == 30443:
            if (forward.get("hostPort"), forward.get("guestPort"), forward.get("static")) == (8443, 30443, True):
                if configured:
                    parser.error("duplicate HTTPS port forward")
                configured = True
            else:
                parser.error("existing conflicting HTTPS port forward")
    if configured:
        print("Single-Mac HTTPS forward is already configured.")
        return
    if not args.apply:
        print("Will add 127.0.0.1:8443 -> guest NodePort30443; retain all other VM settings.")
        print("Stop the VM, then rerun with --apply and start it again.")
        return
    if record["status"] != "Stopped":
        parser.error("stop the VM before applying the configuration change")
    state = args.state.resolve(strict=True)
    source = Path(record["dir"]) / "lima.yaml"
    backup = state / ("lima-before-https-" + time.strftime("%Y%m%dT%H%M%S") + ".yaml")
    if backup.exists():
        parser.error("backup path already exists")
    shutil.copy2(source, backup)
    expression = '.portForwards += [{"guestPort":30443,"hostIP":"127.0.0.1","hostPort":8443,"static":true}]'
    subprocess.run(["limactl", "edit", args.vm, "--tty=false", "--set", expression], check=True, timeout=60)
    print("HTTPS forward configured. Prior config: " + str(backup))


if __name__ == "__main__":
    main()
