#!/usr/bin/env python3
"""Pass only the per-agent Recall token to the stdio-to-HTTP shim."""
import os
from urllib.parse import urlsplit


def main():
    url = os.environ["FLEET_RECALL_URL"]
    args = ["ostk-fleet-recall", "shim", "--url", url]
    # This URL was explicitly supplied to launch up for a private container route.
    if urlsplit(url).scheme == "http":
        args.append("--allow-http")
    os.execve("/usr/local/bin/ostk-fleet-recall", args, {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "FLEET_RECALL_TOKEN": os.environ["FLEET_RECALL_TOKEN"],
    })


if __name__ == "__main__":
    main()
