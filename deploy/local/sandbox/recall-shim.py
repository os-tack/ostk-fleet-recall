#!/usr/bin/env python3
"""Pass only the per-agent Recall token to the stdio-to-HTTP shim."""
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit


def command(environment):
    url = environment["FLEET_RECALL_URL"]
    args = ["ostk-fleet-recall", "shim", "--url", url]
    allow_http = environment.get("FLEET_RECALL_ALLOW_HTTP")
    if allow_http not in (None, "true", "false"):
        raise ValueError("invalid Recall HTTP opt-in")
    if urlsplit(url).scheme == "http" and allow_http != "true":
        raise ValueError("Recall HTTP requires explicit development opt-in")
    if allow_http == "true":
        args.append("--allow-http")
    if "FLEET_RECALL_CA_PATH" in environment:
        ca_path = environment["FLEET_RECALL_CA_PATH"]
        if not ca_path or not Path(ca_path).is_absolute():
            raise ValueError("invalid Recall CA path")
        args += ["--ca-path", ca_path]
    return args, {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "FLEET_RECALL_TOKEN": environment["FLEET_RECALL_TOKEN"],
    }


def main():
    args, environment = command(os.environ)
    os.execve("/usr/local/bin/ostk-fleet-recall", args, environment)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError):
        print("Recall shim configuration failed; details withheld", file=sys.stderr)
        sys.exit(1)
