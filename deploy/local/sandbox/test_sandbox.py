"""No-provider checks for the sandbox's configuration and argument boundary."""
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("sandbox_entry", Path(__file__).with_name("entrypoint.py"))
ENTRY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENTRY)


class SandboxTests(unittest.TestCase):
    def test_only_transcript_subdirectories_are_shared(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            transcripts = Path(directory) / "transcripts"
            home.mkdir()
            transcripts.mkdir()
            env = {"FLEET_RECALL_TOKEN": "agent-token", "FLEET_RECALL_URL": "http://recall/mcp",
                   "FLEET_SANDBOX_CODEX_AUTH_B64": base64.b64encode(b'{"tokens":{"access_token":"provider-token"}}').decode()}
            work = ENTRY.configure(home, transcripts, env)
            self.assertNotIn("FLEET_SANDBOX_CODEX_AUTH_B64", env)
            self.assertEqual((home / ".codex/sessions").resolve(), (transcripts / "codex").resolve())
            self.assertEqual((home / ".claude/projects").resolve(), (transcripts / "claude").resolve())
            self.assertEqual(list(transcripts.rglob("*.json")), [])
            self.assertIn("provider-token", (home / ".codex/auth.json").read_text())
            self.assertNotIn("provider-token", (home / ".codex/config.toml").read_text())
            self.assertNotIn("agent-token", (work / ".mcp.json").read_text())
            config = json.loads((work / ".mcp.json").read_text())
            self.assertEqual(list(config["mcpServers"]), ["recall"])

    def test_tasks_stay_single_argv_values_and_cannot_add_flags(self):
        task = "--model injected; $(touch /tmp/never)\nsecond line"
        for harness in ["codex", "claude"]:
            args = ENTRY.harness_argv(harness, task, None, Path("/home/sandbox/work"))
            self.assertEqual(args[-2:], ["--", task])
            self.assertNotIn("sh", args)
            self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", args)
            self.assertNotIn("--dangerously-skip-permissions", args)
        claude = ENTRY.harness_argv("claude", "task", None, Path("/work"))
        self.assertIn("--max-turns", claude)
        self.assertIn("--strict-mcp-config", claude)
        self.assertIn("--bare", claude)

    def test_unknown_harness_fails_closed(self):
        with self.assertRaises(ValueError):
            ENTRY.harness_argv("bash", "task", None, Path("/work"))


if __name__ == "__main__":
    unittest.main()
