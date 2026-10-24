#!/usr/bin/env python3
"""A stdio MCP proxy that scans what passes through it.

Put it between an MCP client and a server and it does three things the client
cannot do for itself:

  1. reads every tool definition the server publishes, as one manifest, before
     the client is told those tools exist;
  2. reads the arguments of every tools/call before they reach the server;
  3. writes an audit line for each decision, so an incident review has evidence
     instead of a feeling.

It is deliberately stdlib-only: an audit log for a security control should not
itself pull in a dependency tree.

    python proxy.py --server "npx -y @modelcontextprotocol/server-filesystem /tmp" \
        --mode enforce --log audit.jsonl

Modes:
    monitor   scan and log, forward everything (safe default)
    enforce   refuse poisoned manifests and dangerous calls

Stdio is dirty, so the proxy never writes to stdout except to speak MCP. All
diagnostics go to stderr and the audit log.
"""

import argparse
import json
import os
import shlex
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from redlens import AuditLog, Policy, combine, scan_tool_call, scan_tool_manifest  # noqa: E402

ERROR_BLOCKED = -32000
ERROR_MANIFEST = -32001
DEFAULT_DENY_AT = "review"


def split_server_command(server):
    """Split a --server command line without losing quoted paths or backslashes.

    shlex in posix mode eats backslashes, which breaks Windows paths; in non-posix
    mode it leaves the quotes on the token, which breaks paths with spaces. So:
    split non-posix, then strip one matching pair of surrounding quotes per token.
    On Windows a .cmd or .bat shim (npx.cmd, for example) cannot be executed
    directly by Popen, so it goes through cmd /c.
    """
    tokens = shlex.split(server, posix=False)
    cleaned = [
        token[1:-1] if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'" else token
        for token in tokens
    ]
    if not cleaned:
        raise SystemExit("--server is empty")
    if os.name == "nt" and cleaned[0].lower().endswith((".cmd", ".bat")):
        return ["cmd", "/c"] + cleaned
    return cleaned


def _load_manifest(result):
    """The tools/list result may be a list or an object with a tools key."""
    if isinstance(result, dict):
        return result.get("tools") or []
    if isinstance(result, list):
        return result
    return []


class Proxy:
    def __init__(self, server_cmd, mode="monitor", deny_at=DEFAULT_DENY_AT, log_path=None, policy_path=None):
        self.server_cmd = server_cmd
        self.mode = mode
        self.deny_at = deny_at
        self.log_path = log_path
        self.policy = Policy.load(policy_path) if policy_path else None
        self.log = AuditLog(log_path) if log_path else None
        # The manifest the server published, kept so an argument can be judged
        # against the capabilities of the tool it is being handed to.
        self.manifest = None
        self.pending = {}
        self.write_lock = threading.Lock()
        self.audit_lock = threading.Lock()
        self.counters = {"allowed": 0, "denied": 0, "manifest_blocked": 0}

    # ---------------------------------------------------------------- audit
    def audit(self, event, **fields):
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event}
        record.update(fields)
        with self.audit_lock:
            if self.log is not None:
                self.log.append(event, **fields)
            else:
                sys.stderr.write(json.dumps(record, ensure_ascii=False) + "\n")
                sys.stderr.flush()

    def emit(self, message):
        with self.write_lock:
            sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
            sys.stdout.flush()

    def error(self, request_id, code, message, data=None):
        error = {"code": code, "message": message}
        if data:
            error["data"] = data
        return {"jsonrpc": "2.0", "id": request_id, "error": error}

    # --------------------------------------------------------------- client
    def handle_client_message(self, message):
        """Return the line to forward, or None when the proxy answered itself."""
        method = message.get("method")
        request_id = message.get("id")
        if request_id is not None and method:
            self.pending[request_id] = method

        if method != "tools/call":
            return json.dumps(message, ensure_ascii=False)

        params = message.get("params") or {}
        name = params.get("name") or ""
        arguments = params.get("arguments") or {}
        report = scan_tool_call(name, arguments, tool_manifest=self.manifest)
        policy_decision = self.policy.evaluate(name, arguments) if self.policy else None
        final_action = combine(policy_decision.action, report.decision) if policy_decision else None

        rule_ids = sorted({finding.rule_id for finding in report.findings})
        argument_names = sorted(str(key) for key in arguments.keys())

        if policy_decision and self.mode == "enforce" and final_action == "deny":
            self.counters["denied"] += 1
            self.audit("tool_call_denied", tool=name, score=report.score, decision=final_action,
                       policy=policy_decision.rule_id, policy_reason=policy_decision.reason,
                       rules=rule_ids, arguments=argument_names)
            self.emit(self.error(request_id, ERROR_BLOCKED,
                                 "blocked by policy: %s" % policy_decision.reason,
                                 {"tool": name, "policy": policy_decision.to_dict(),
                                  "findings": [f.to_dict() for f in report.findings]}))
            return None

        if policy_decision and policy_decision.action != "allow":
            self.audit("tool_call_flagged", tool=name, score=report.score, decision=final_action,
                       policy=policy_decision.rule_id, policy_reason=policy_decision.reason)

        if report.decision == "clean" or (self.mode == "monitor"):
            self.counters["allowed"] += 1
            # One record per decision, allow or not, so the log is a complete
            # record rather than a list of alerts.
            self.audit("tool_call_flagged" if report.findings else "tool_call_allowed",
                       tool=name, score=report.score, decision=report.decision,
                       rules=rule_ids, arguments=argument_names)
            return json.dumps(message, ensure_ascii=False)

        if self.deny_at == "review" and report.decision == "review":
            pass
        elif self.deny_at == "block" and report.decision != "block":
            self.counters["allowed"] += 1
            return json.dumps(message, ensure_ascii=False)

        self.counters["denied"] += 1
        self.audit("tool_call_denied", tool=name, score=report.score,
                   decision=report.decision, rules=rule_ids, arguments=argument_names)
        self.emit(self.error(
            request_id, ERROR_BLOCKED,
            "blocked by redlens: %s" % ", ".join(sorted({f.rule_id for f in report.findings})),
            {"tool": name, "score": report.score, "findings": [f.to_dict() for f in report.findings]},
        ))
        return None

    # --------------------------------------------------------------- server
    def handle_server_message(self, message):
        """Return the line to forward, or None when the proxy answered itself."""
        request_id = message.get("id")
        with self.write_lock:
            method = self.pending.pop(request_id, None) if request_id is not None else None
        if method != "tools/list":
            return json.dumps(message, ensure_ascii=False)

        tools = _load_manifest(message.get("result"))
        self.manifest = {"tools": tools}
        report = scan_tool_manifest(tools)
        if not report.findings:
            self.audit("manifest_clean", tools=len(tools))
            return json.dumps(message, ensure_ascii=False)

        self.audit("manifest_flagged", tools=len(tools), score=report.score,
                   decision=report.decision,
                   rules=[finding.rule_id for finding in report.findings])

        # A manifest is critical data: refusing it makes the server unusable,
        # so only a clear verdict is worth refusing. A kill switch always is.
        if self.mode == "enforce" and (report.kill_switch_hit or report.decision == "block"):
            self.counters["manifest_blocked"] += 1
            self.audit("manifest_blocked", tools=len(tools), score=report.score,
                       rules=[finding.rule_id for finding in report.findings])
            return json.dumps(self.error(
                request_id, ERROR_MANIFEST,
                "blocked by redlens: poisoned tool manifest",
                {"score": report.score, "findings": [f.to_dict() for f in report.findings]},
            ), ensure_ascii=False)
        return json.dumps(message, ensure_ascii=False)

    # ----------------------------------------------------------------- run
    def run(self, server_stdin, server_stdout):
        def pump_server():
            for line in server_stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except ValueError:
                    sys.stdout.write(line + "\n")
                    sys.stdout.flush()
                    continue
                forwarded = self.handle_server_message(message)
                if forwarded:
                    self.emit(json.loads(forwarded))

        reader = threading.Thread(target=pump_server, daemon=True)
        reader.start()

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError:
                server_stdin.write(line + "\n")
                server_stdin.flush()
                continue
            forwarded = self.handle_client_message(message)
            if forwarded:
                server_stdin.write(forwarded + "\n")
                server_stdin.flush()

        try:
            server_stdin.close()
        except (BrokenPipeError, OSError):
            pass
        reader.join(timeout=10)
        self.audit("summary", **self.counters)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scanning proxy for MCP stdio servers.")
    parser.add_argument("--server", required=True, help="command that starts the real MCP server")
    parser.add_argument("--mode", choices=["monitor", "enforce"], default="monitor")
    parser.add_argument("--deny-at", choices=["review", "block"], default=DEFAULT_DENY_AT,
                        help="which decision refuses a tool call in enforce mode")
    parser.add_argument("--log", help="append audit records to this file instead of stderr")
    parser.add_argument("--policy", help="policy JSON file: what this agent is allowed to do")
    args = parser.parse_args(argv)

    command = split_server_command(args.server)
    server = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        text=True, bufsize=1,
    )
    proxy = Proxy(args.server, mode=args.mode, deny_at=args.deny_at, log_path=args.log,
                  policy_path=args.policy)
    try:
        proxy.run(server.stdin, server.stdout)
    finally:
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
