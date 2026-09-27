#!/usr/bin/env python3
"""Run one bounded, isolated harness. Provider credentials never enter transcripts."""
import base64
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

RECALL_ENVIRONMENT = ("FLEET_RECALL_TOKEN", "FLEET_RECALL_URL",
                      "FLEET_RECALL_CA_PATH", "FLEET_RECALL_ALLOW_HTTP")


def harness_environment(source):
    """Keep Recall trust settings separate from provider keys and trust stores."""
    allowed = {*RECALL_ENVIRONMENT, "FLEET_SANDBOX_HARNESS",
               "FLEET_SANDBOX_INSTANCE", "FLEET_SANDBOX_TASK_B64", "FLEET_SANDBOX_MODEL",
               "FLEET_SANDBOX_TIMEOUT_SECONDS", "FLEET_SANDBOX_CODEX_AUTH_B64",
               "FLEET_SANDBOX_START_BEFORE_UNIX"}
    env = {key: value for key, value in source.items() if key in allowed}
    if env.get("FLEET_RECALL_ALLOW_HTTP") not in (None, "true", "false"):
        raise ValueError("invalid Recall HTTP opt-in")
    harness = env.get("FLEET_SANDBOX_HARNESS", "synthetic")
    provider = {"codex": "CODEX_API_KEY", "claude": "ANTHROPIC_API_KEY"}.get(harness)
    if provider and provider in source:
        env[provider] = source[provider]
    env.update(PATH="/usr/local/bin:/usr/bin:/bin", HOME="/home/sandbox", LANG="C.UTF-8")
    return env


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
    recall_keys = [key for key in RECALL_ENVIRONMENT if key in env]
    # Fresh home has no inherited hooks, plugins, skills or other MCP servers.
    (codex / "config.toml").write_text(
        'cli_auth_credentials_store = "file"\n'
        'approval_policy = "never"\n'
        '[mcp_servers.recall]\n'
        'command = "/usr/local/bin/recall-shim"\n'
        f'env_vars = {json.dumps(recall_keys)}\n'
        'required = true\n'
        'enabled_tools = ["recall", "remember"]\n'
        'default_tools_approval_mode = "prompt"\n'
        # Selecting this harness authorizes the scoped Recall read/write tools.
        # Keep that permission separate from shell execution and other servers.
        '[mcp_servers.recall.tools.recall]\n'
        'approval_mode = "approve"\n'
        '[mcp_servers.recall.tools.remember]\n'
        'approval_mode = "approve"\n', encoding="utf-8")
    private_json(work / ".mcp.json", {"mcpServers": {"recall": {
        "command": "/usr/local/bin/recall-shim", "args": [],
        "env": {key: "${" + key + "}" for key in recall_keys},
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


def start_harness(args, work, env, log):
    """Recheck the grant-derived deadline after scheduling and setup delays."""
    raw = env.pop("FLEET_SANDBOX_START_BEFORE_UNIX", None)
    if raw is not None:
        if (not isinstance(raw, str) or not 1 <= len(raw) <= 12 or not raw.isascii()
                or not raw.isdecimal() or raw.startswith("0") or int(raw) > 253402300799):
            raise ValueError("invalid sandbox startup deadline")
        if time.time() >= int(raw):
            raise ValueError("sandbox startup deadline has passed")
    # Older launchers did not supply a deadline. New launchers always do.
    # Consume the control value here so the provider and its MCP children never
    # inherit it. Keep this check immediately adjacent to process creation.
    return subprocess.Popen(args, cwd=work, env=env, stdout=log, stderr=log,
                            stdin=subprocess.DEVNULL, start_new_session=True)


def run():
    os.umask(0o077)
    env = harness_environment(os.environ)
    harness = env.get("FLEET_SANDBOX_HARNESS", "synthetic")
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
        child = start_harness(args, work, env, log)

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
