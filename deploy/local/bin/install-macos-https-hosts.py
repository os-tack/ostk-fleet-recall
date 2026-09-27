#!/usr/bin/env python3
"""Install the single-Mac HTTPS name mapping; run with sudo after review.

Only the three local Fleet names are added. Existing conflicting entries fail
closed. A dated copy of /etc/hosts is retained before the first change. Docker
uses the launcher's host-gateway mapping and k0s uses split DNS separately.
"""

import argparse
import ipaddress
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

NAMES = ("recall.fleet.test", "auth.fleet.test", "login.fleet.test")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("this helper is only for macOS")
    hosts = Path("/etc/hosts")
    if hosts.is_symlink() or not hosts.is_file():
        parser.error("/etc/hosts must be a regular file")
    original = hosts.read_text()
    found = set()
    for line in original.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        matches = set(fields[1:]) & set(NAMES)
        if matches:
            if ipaddress.ip_address(fields[0]) != ipaddress.ip_address("127.0.0.1"):
                parser.error("existing Fleet hostname has a conflicting address")
            found.update(matches)
    missing = [name for name in NAMES if name not in found]
    if not missing:
        print("Fleet single-Mac hostname mappings already installed.")
        return
    addition = "\n# Fleet Recall single-Mac HTTPS (M4)\n127.0.0.1 " + " ".join(missing) + "\n"
    if not args.apply:
        print("Will append to /etc/hosts after retaining a dated backup:")
        print(addition, end="")
        print("Run this helper with sudo and --apply to install.")
        return
    if os.geteuid() != 0:
        parser.error("--apply requires sudo to update /etc/hosts")
    backup = hosts.with_name("hosts.fleet-before-" + time.strftime("%Y%m%dT%H%M%S"))
    with backup.open("x") as target:
        target.write(original)
    shutil.copystat(hosts, backup)
    with hosts.open("a") as target:
        target.write(addition)
        target.flush()
        os.fsync(target.fileno())
    subprocess.run(["/usr/bin/dscacheutil", "-flushcache"], check=True, timeout=30)
    print("Installed Fleet single-Mac hostname mappings; backup: " + str(backup))


if __name__ == "__main__":
    main()
