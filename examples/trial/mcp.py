"""Drive `ostk-fleet-recall serve` over stdio JSON-RPC, one process per agent.

Every request and response is appended to $T/transcripts/<agent>.jsonl so the
run can be re-checked.
"""

import json
import os
import subprocess
import sys
import time

T = os.environ["T"]
os.makedirs(f"{T}/transcripts", exist_ok=True)


class Serve:
    def __init__(self, agent, extra_env=None, drop_env=()):
        env = dict(os.environ)
        env["FLEET_RECALL_DATABASE_URL"] = os.environ["WRITER_URL"]
        env.pop("FLEET_RECALL_PUBLICATION_DATABASE_URL", None)
        env["FLEET_RECALL_AGENT"] = agent
        for name in drop_env:
            env.pop(name, None)
        env.update(extra_env or {})
        self.agent = agent
        self.stderr = open(f"{T}/transcripts/serve-{agent}.stderr.log", "ab")
        self.transcript = open(f"{T}/transcripts/{agent}.jsonl", "a")
        self.proc = subprocess.Popen(
            [os.environ["FLEET_RECALL_BIN"], "serve"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            env=env,
            cwd=os.environ["REPO"],
        )
        self.next_id = 1
        init = self.request(
            "initialize",
            {"protocolVersion": "2025-06-18", "capabilities": {},
             "clientInfo": {"name": "trial", "version": "1.0.0"}},
        )
        assert "result" in init, init
        self.notify("notifications/initialized", {})

    def send(self, message):
        self.transcript.write(json.dumps({"dir": "->", "t": time.time(), "msg": message}) + "\n")
        self.transcript.flush()
        self.proc.stdin.write((json.dumps(message) + "\n").encode())
        self.proc.stdin.flush()

    def notify(self, method, params):
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def request(self, method, params):
        request_id = self.next_id
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(f"serve({self.agent}) closed stdout; exit={self.proc.poll()}")
            response = json.loads(line)
            self.transcript.write(json.dumps({"dir": "<-", "t": time.time(), "msg": response}) + "\n")
            self.transcript.flush()
            if response.get("id") == request_id:
                return response

    def call(self, tool, arguments):
        response = self.request("tools/call", {"name": tool, "arguments": arguments})
        if "error" in response:
            return {"error": response["error"]}
        result = response["result"]
        sc = result.get("structuredContent") or {}
        return {
            "is_error": result.get("isError", False),
            "data": sc.get("data"),
            "structured": sc,
            "text": [c.get("text") for c in result.get("content", [])],
        }

    def recall(self, **arguments):
        return self.call("recall", arguments)

    def remember(self, **arguments):
        return self.call("remember", arguments)

    def close(self):
        self.proc.stdin.close()
        code = self.proc.wait(timeout=60)
        self.stderr.close()
        self.transcript.close()
        return code


def dump(path, value):
    with open(path, "w") as f:
        json.dump(value, f, indent=1, sort_keys=True)


def show(label, value, limit=4000):
    print(f"== {label}")
    print(json.dumps(value, indent=1, sort_keys=True)[:limit])
    sys.stdout.flush()
