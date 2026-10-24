"""End-to-end tests for the MCP proxy example."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY = os.path.join(ROOT, "examples", "mcp_proxy", "proxy.py")
FAKE = os.path.join(ROOT, "examples", "mcp_proxy", "fake_server.py")


def request(request_id, method, params=None):
    body = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        body["params"] = params
    return body


class TestMcpProxy(unittest.TestCase):
    def run_proxy(self, messages, mode="enforce"):
        handle, log_path = tempfile.mkstemp(suffix=".jsonl")
        os.close(handle)
        payload = "".join(json.dumps(message) + "\n" for message in messages)
        command = "%s %s" % (sys.executable, FAKE)
        result = subprocess.run(
            [sys.executable, PROXY, "--server", command, "--mode", mode, "--log", log_path],
            input=payload, capture_output=True, text=True, timeout=120, cwd=ROOT,
        )
        responses = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        with open(log_path, "r", encoding="utf-8") as handle:
            events = [json.loads(line) for line in handle if line.strip()]
        os.unlink(log_path)
        return result, responses, events

    def test_poisoned_manifest_is_blocked_in_enforce_mode(self):
        result, responses, events = self.run_proxy([request(1, "tools/list")])
        self.assertEqual(result.returncode, 0, result.stderr)
        blocked = [r for r in responses if r.get("error", {}).get("code") == -32001]
        self.assertTrue(blocked, responses)
        self.assertIn("manifest_blocked", [event["event"] for event in events])

    def test_poisoned_manifest_is_forwarded_in_monitor_mode(self):
        result, responses, events = self.run_proxy([request(1, "tools/list")], mode="monitor")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("manifest_flagged", [event["event"] for event in events])
        self.assertTrue(any("result" in response for response in responses))

    def test_ordinary_tool_call_passes(self):
        messages = [request(1, "tools/call", {"name": "read_file", "arguments": {"path": "src/app.py"}})]
        result, responses, events = self.run_proxy(messages)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("called read_file" in json.dumps(response) for response in responses), responses)
        self.assertIn("summary", [event["event"] for event in events])

    def test_dangerous_tool_call_is_refused(self):
        messages = [request(1, "tools/call", {"name": "read_file", "arguments": {"path": "~/.ssh/id_rsa"}})]
        result, responses, events = self.run_proxy(messages)
        self.assertEqual(result.returncode, 0, result.stderr)
        refused = [r for r in responses if r.get("error", {}).get("code") == -32000]
        self.assertTrue(refused, responses)
        self.assertIn("RL-501", json.dumps(refused[0]))
        self.assertIn("tool_call_denied", [event["event"] for event in events])

    def test_dangerous_tool_call_passes_in_monitor_mode(self):
        messages = [request(1, "tools/call", {"name": "read_file", "arguments": {"path": "~/.ssh/id_rsa"}})]
        result, responses, events = self.run_proxy(messages, mode="monitor")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("called read_file" in json.dumps(r) for r in responses), responses)
        self.assertIn("tool_call_flagged", [event["event"] for event in events])


if __name__ == "__main__":
    unittest.main()
