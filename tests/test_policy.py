"""Tests for the policy engine, the chained audit log, and the CLI surfaces."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from redlens import AuditLog, Policy, combine, verify_audit_log  # noqa: E402
from redlens.policy import host_allowed, host_of, normalize_path, path_within  # noqa: E402

POLICY = {
    "default": "review",
    "tools": {
        "read_file": {"allow": {"path": {"within": ["./project", "/srv/data"]}}},
        "http_request": {"allow": {"url": {"hosts": ["api.internal.example", "*.trusted.example"]}}},
        "run_command": {"require_confirmation": True},
    },
    "rules": [
        {"id": "POL-001", "when": {"tool": "run_command"}, "action": "deny", "reason": "no shell"},
        {"id": "POL-002", "when": {"tool": "*delete*"}, "action": "deny", "reason": "no destructive tools"},
    ],
}


class TestPathRules(unittest.TestCase):
    def test_normalisation_collapses_traversal(self):
        self.assertEqual(normalize_path("./project/../project/app.py"), "project/app.py")
        self.assertEqual(normalize_path("a/b/../../../c"), "../c")

    def test_within(self):
        self.assertTrue(path_within("./project/src/app.py", "./project"))
        self.assertFalse(path_within("./project/../secrets/key.pem", "./project"))
        self.assertFalse(path_within("/srv/data2/x", "/srv/data"))

    def test_hosts(self):
        self.assertEqual(host_of("https://api.example.com/v1?x=1"), "api.example.com")
        self.assertTrue(host_allowed("a.trusted.example", ["*.trusted.example"]))
        self.assertFalse(host_allowed("evil.example", ["api.internal.example"]))


class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = Policy(POLICY)

    def test_explicit_rule_denies(self):
        decision = self.policy.evaluate("run_command", {"cmd": "ls"})
        self.assertEqual(decision.action, "deny")
        self.assertEqual(decision.rule_id, "POL-001")

    def test_glob_tool_rule(self):
        self.assertEqual(self.policy.evaluate("bulk_delete", {}).action, "deny")

    def test_scope_violation(self):
        decision = self.policy.evaluate("read_file", {"path": "~/.ssh/id_rsa"})
        self.assertEqual((decision.action, decision.rule_id), ("deny", "POL-SCOPE"))

    def test_in_scope_path_allowed(self):
        decision = self.policy.evaluate("read_file", {"path": "./project/src/app.py"})
        self.assertEqual(decision.action, "review")  # falls through to the default

    def test_host_allowlist(self):
        self.assertEqual(self.policy.evaluate("http_request", {"url": "https://api.internal.example/v1"}).action, "review")
        denied = self.policy.evaluate("http_request", {"url": "https://evil.example/exfil"})
        self.assertEqual((denied.action, denied.rule_id), ("deny", "POL-HOST"))

    def test_require_confirmation(self):
        decision = self.policy.evaluate("run_command_2", {"cmd": "ls"})
        self.assertEqual(decision.action, "review")

    def test_unknown_tool_uses_the_default(self):
        self.assertEqual(self.policy.evaluate("something_else", {}).action, "review")

    def test_combine_takes_the_stricter_side(self):
        self.assertEqual(combine("allow", "block"), "deny")
        self.assertEqual(combine("review", "clean"), "review")
        self.assertEqual(combine("allow", "clean"), "allow")
        self.assertEqual(combine("deny", "clean"), "deny")


class TestAuditLog(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".jsonl")
        os.close(handle)
        os.unlink(self.path)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_chain_verifies(self):
        log = AuditLog(self.path)
        for index in range(3):
            log.append("tool_call", tool="read_file", index=index)
        ok, first_bad, count, message = verify_audit_log(self.path)
        self.assertTrue(ok, message)
        self.assertEqual(count, 3)

    def test_reopening_continues_the_chain(self):
        AuditLog(self.path).append("one")
        AuditLog(self.path).append("two")
        ok, _, count, message = verify_audit_log(self.path)
        self.assertTrue(ok, message)
        self.assertEqual(count, 2)

    def test_tampering_is_detected(self):
        log = AuditLog(self.path)
        log.append("tool_call", tool="read_file")
        log.append("tool_call", tool="http_post")
        with open(self.path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
        lines[0] = lines[0].replace("read_file", "write_file")
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.writelines(lines)
        ok, first_bad, _, message = verify_audit_log(self.path)
        self.assertFalse(ok)
        self.assertEqual(first_bad, 0)
        self.assertIn("modified", message)


class TestCliPolicy(unittest.TestCase):
    def run_cli(self, args):
        return subprocess.run([sys.executable, "-m", "redlens"] + args, cwd=ROOT, capture_output=True, text=True)

    def test_policy_denies_out_of_scope_path(self):
        handle, path = tempfile.mkstemp(suffix=".json")
        os.close(handle)
        with open(path, "w", encoding="utf-8") as out:
            json.dump(POLICY, out)
        try:
            denied = self.run_cli(["policy", "--file", path, "--tool", "run_command", "--args", '{"cmd": "ls"}'])
            self.assertEqual(denied.returncode, 1)
            self.assertIn("DENY", denied.stdout)

            scoped = self.run_cli(["policy", "--file", path, "--tool", "read_file",
                                   "--args", '{"path": "~/.ssh/id_rsa"}'])
            self.assertEqual(scoped.returncode, 1)
            self.assertIn("POL-SCOPE", scoped.stdout)
        finally:
            os.unlink(path)

    def test_verify_log_reports_a_broken_chain(self):
        handle, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(handle)
        os.unlink(path)
        try:
            log = AuditLog(path)
            log.append("a")
            log.append("b")
            good = self.run_cli(["verify-log", "--file", path])
            self.assertEqual(good.returncode, 0)
            self.assertIn("OK", good.stdout)
        finally:
            if os.path.exists(path):
                os.unlink(path)


if __name__ == "__main__":
    unittest.main()
