#!/usr/bin/env python3
"""Run one bounded, isolated harness. Provider credentials never enter transcripts."""
import base64
import json
import os
from pathlib import Path
import signal
import subprocess
import sys


def private_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream)


def configure(home, transcripts, env):
    """Only transcript subdirectories are shared with the shipper."""
    work = home / "work"
    work.mkdir(mode=0o700)
    codex = home / ".codex"
    claude = home / ".claude"
    codex.mkdir(mode=0o700)
    claude.mkdir(mode=0o700)
    for target, link in [(transcripts / "codex", codex / "sessions"),
                         (transcripts / "claude", claude / "projects")]:
        target.mkdir(mode=0o750)
        link.symlink_to(target, target_is_directory=True)
    auth = env.pop("FLEET_SANDBOX_CODEX_AUTH_B64", None)
    if auth:
        value = json.loads(base64.b64decode(auth, validate=True))
        if not isinstance(value, dict):
            raise ValueError("invalid Codex auth object")
        private_json(codex / "auth.json", value)
    env["CODEX_HOME"] = str(codex)
    env["CLAUDE_CONFIG_DIR"] = str(claude)
    # Fresh home has no inherited hooks, plugins, skills or other MCP servers.
    (codex / "config.toml").write_text(
        'cli_auth_credentials_store = "file"\n'
        'approval_policy = "never"\n'
        '[mcp_servers.recall]\n'
        'command = "/usr/local/bin/recall-shim"\n'
        'env_vars = ["FLEET_RECALL_TOKEN", "FLEET_RECALL_URL"]\n'
        'required = true\n', encoding="utf-8")
    private_json(work / ".mcp.json", {"mcpServers": {"recall": {
        "command": "/usr/local/bin/recall-shim", "args": [],
        "env": {"FLEET_RECALL_TOKEN": "${FLEET_RECALL_TOKEN}",
                "FLEET_RECALL_URL": "${FLEET_RECALL_URL}"},
    }}})
    return work


def harness_argv(harness, task, model, work):
    if harness == "synthetic":
        return ["/opt/fleet-sandbox/synthetic.py"]
    if harness == "codex":
        args = ["codex", "exec", "--skip-git-repo-check", "--sandbox", "read-only",
                "--color", "never", "--json", "--ignore-rules", "--cd", str(work)]
        if model:
            args += ["--model", model]
        return args + ["--", task]
    if harness == "claude":
        return ["claude", "-p", "--bare", "--model", model or "claude-haiku-4-5",
                "--max-turns", "5", "--max-budget-usd", "2", "--tools", "",
                "--allowedTools", "mcp__recall__recall", "mcp__recall__remember",
                "--strict-mcp-config", "--mcp-config", str(work / ".mcp.json"),
                "--output-format", "json", "--", task]
    raise ValueError("unknown sandbox harness")


def run():
    os.umask(0o077)
    allowed = {"FLEET_RECALL_TOKEN", "FLEET_RECALL_URL", "FLEET_SANDBOX_HARNESS",
               "FLEET_SANDBOX_INSTANCE", "FLEET_SANDBOX_TASK_B64", "FLEET_SANDBOX_MODEL",
               "FLEET_SANDBOX_TIMEOUT_SECONDS", "FLEET_SANDBOX_CODEX_AUTH_B64"}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    harness = env.get("FLEET_SANDBOX_HARNESS", "synthetic")
    provider = {"codex": "CODEX_API_KEY", "claude": "ANTHROPIC_API_KEY"}.get(harness)
    if provider and provider in os.environ:
        env[provider] = os.environ[provider]
    env.update(PATH="/usr/local/bin:/usr/bin:/bin", HOME="/home/sandbox", LANG="C.UTF-8")
    home = Path(env["HOME"])
    work = configure(home, Path("/transcripts"), env)
    task = base64.b64decode(env.pop("FLEET_SANDBOX_TASK_B64", ""), validate=True).decode("utf-8")
    deadline = int(env.pop("FLEET_SANDBOX_TIMEOUT_SECONDS", "300"))
    if not 1 <= deadline <= 3600:
        raise ValueError("invalid sandbox deadline")
    args = harness_argv(harness, task, env.pop("FLEET_SANDBOX_MODEL", None), work)
    # Provider logs can contain credentials or prompt text. Keep them in the
    # private home, not Docker logs or the transcript volume.
    with (home / "harness.log").open("xb") as log:
        child = subprocess.Popen(args, cwd=work, env=env, stdout=log, stderr=log,
                                 stdin=subprocess.DEVNULL, start_new_session=True)

        def stop(_signum, _frame):
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        try:
            code = child.wait(timeout=deadline)
        except subprocess.TimeoutExpired:
            stop(None, None)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            code = 124
    print(json.dumps({"harness": harness, "exit_code": code,
                      "instance": env.get("FLEET_SANDBOX_INSTANCE"),
                      "transcripts": "/transcripts"}), flush=True)
    return code


if __name__ == "__main__":
    try:
        sys.exit(run())
    except (OSError, ValueError, KeyError):
        print("sandbox configuration failed; details withheld to protect credentials", file=sys.stderr)
        sys.exit(1)
