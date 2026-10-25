#!/usr/bin/env python3
"""A gateway in front of any OpenAI-compatible endpoint.

The MCP proxy covers tool calls. This covers everything else: every chat
completion that passes through it is scanned on the way in and on the way out,
and the decision is written to the same chained audit log.

    python examples/llm_gateway.py --upstream https://api.example.com --port 8787 \
        --mode enforce --log audit.jsonl --canary CANARY-7f3a91

    # then point the client at it
    export OPENAI_BASE_URL=http://127.0.0.1:8787/v1

Stdlib only: http.server for the listener, urllib for the upstream call. It is a
reference shape, not a hardened proxy: it does not terminate TLS, it does not
scale past a thread per request, and it holds no credentials of its own.
"""

import argparse
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from redlens import AuditLog, Policy, scan, scan_output  # noqa: E402

MODEL_PATH_HINTS = ("/chat/completions", "/completions", "/responses")
DEFAULT_MAX_BODY = 1_048_576


def tool_calls_in(payload):
    """Tool calls the model asked for, in OpenAI message shape.

    A gateway sees the model's request to call a tool before the agent executes
    it, which is the last moment a policy can refuse it.
    """
    if not isinstance(payload, dict):
        return []
    for choice in payload.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message") or {}
        calls = message.get("tool_calls") if isinstance(message, dict) else None
        for call in calls or []:
            function = call.get("function") or {}
            name = str(function.get("name") or call.get("name") or "")
            raw = function.get("arguments") or "{}"
            try:
                arguments = json.loads(raw) if isinstance(raw, str) else (raw or {})
            except ValueError:
                arguments = {"_unparsed": str(raw)[:200]}
            yield name, arguments


def last_user_text(payload):
    """The most recent user turn, which is what the scanner judges."""
    messages = payload.get("messages") or []
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            content = message.get("content")
            if isinstance(content, list):
                return " ".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
            return str(content or "")
    return str(payload.get("prompt") or "")


def response_text(payload):
    """Text out of a chat completion or a text completion."""
    if isinstance(payload, dict):
        choices = payload.get("choices") or []
        if choices and isinstance(choices[0], dict):
            message = choices[0].get("message") or {}
            if isinstance(message, dict) and message.get("content"):
                return str(message["content"])
            return str(choices[0].get("text") or "")
    return ""


class Gateway(BaseHTTPRequestHandler):
    server_version = "RedLensGateway/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("gateway: " + (fmt % args) + "\n")

    # ------------------------------------------------------------------ helpers
    def _json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _audit(self, event, **fields):
        with self.server.audit_lock:
            self.server.audit.append(event, **fields)

    def _refusal(self, reason, rules):
        return {
            "error": {
                "message": "blocked by redlens: " + reason,
                "type": "prompt_injection_blocked",
                "rules": rules,
            }
        }

    # -------------------------------------------------------------------- proxy
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > self.server.max_body:
            self._audit("gateway_request_rejected", reason="body too large", bytes=length)
            self._json(413, {"error": {"message": "request body larger than %d bytes" % self.server.max_body}})
            return
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw or b"{}")
        except ValueError:
            self._audit("gateway_request_rejected", reason="body is not JSON")
            self._json(400, {"error": {"message": "request body is not JSON"}})
            return

        # Streaming is refused rather than passed through unscanned. Buffering a
        # stream adds the whole latency of the answer before the first token; the
        # honest options are to refuse it or to admit the tail is unscanned, and a
        # gateway that quietly forwards tokens it never inspected is the worst of
        # both. Opt in with --allow-streaming when you accept that.
        if payload.get("stream") and not self.server.allow_streaming:
            self._audit("gateway_streaming_refused", model=str(payload.get("model") or "unknown"))
            self._json(501, {"error": {
                "message": "streaming is not scanned: pass --allow-streaming to forward it uninspected",
                "type": "streaming_not_supported"}})
            return
        if payload.get("stream"):
            self._audit("gateway_streaming_unscanned", model=str(payload.get("model") or "unknown"))

        model = str(payload.get("model") or "unknown")
        if any(hint in self.path for hint in MODEL_PATH_HINTS):
            text = last_user_text(payload)
            try:
                report = scan(text, target="input")
            except Exception as error:  # a scanner that fails must not become a bypass
                self._audit("gateway_scanner_error", stage="input", error=str(error)[:200])
                if not self.server.fail_open:
                    self._json(503, {"error": {"message": "scanner unavailable; request refused"}})
                    return
                report = None
            if report is not None:
                if report.findings:
                    self._audit("gateway_input_flagged", model=model, score=report.score,
                                decision=report.decision,
                                rules=sorted({f.rule_id for f in report.findings}))
                if self.server.mode == "enforce" and report.decision == "block":
                    self._audit("gateway_input_blocked", model=model, score=report.score,
                                rules=sorted({f.rule_id for f in report.findings}))
                    self._json(403, self._refusal("prompt injection at the input boundary",
                                                  sorted({f.rule_id for f in report.findings})))
                    return

        request = urllib.request.Request(
            self.server.upstream.rstrip("/") + self.path,
            data=raw,
            headers={key: value for key, value in self.headers.items()
                     if key.lower() not in ("host", "content-length", "authorization")},
            method="POST",
        )
        if self.server.authorization:
            request.add_header("Authorization", self.server.authorization)
        try:
            with urllib.request.urlopen(request, timeout=self.server.timeout) as response:
                body = response.read()
                status = response.status
                content_type = response.headers.get("Content-Type", "application/json")
        except urllib.error.HTTPError as error:
            body, status, content_type = error.read(), error.code, "application/json"
        except Exception as error:
            self._json(502, {"error": {"message": "upstream failed: %s" % error}})
            return

        parsed = None
        if body[:1] in (b"{", b"["):
            try:
                parsed = json.loads(body.decode("utf-8", "replace"))
            except ValueError:
                parsed = None

        if parsed is not None:
            # Policy on the tool calls the model asked for: the moment between the
            # model deciding and the agent executing.
            if self.server.policy and isinstance(parsed, dict):
                for name, arguments in tool_calls_in(parsed):
                    decision = self.server.policy.evaluate(name, arguments, agent=self.server.agent_id)
                    self._audit("gateway_tool_call_reviewed", tool=name, action=decision.action,
                                policy=decision.rule_id, arguments=sorted(arguments.keys()))
                    if self.server.mode == "enforce" and decision.action == "deny":
                        self._json(403, self._refusal(
                            "policy refused the requested tool call: " + decision.reason,
                            [decision.rule_id]))
                        return

            try:
                out = scan_output(response_text(parsed), canaries=self.server.canaries, target="output")
            except Exception as error:
                self._audit("gateway_scanner_error", stage="output", error=str(error)[:200])
                if not self.server.fail_open:
                    self._json(503, {"error": {"message": "scanner unavailable; response withheld"}})
                    return
                out = None
            if out is not None:
                if out.findings:
                    self._audit("gateway_output_flagged", score=out.score, decision=out.decision,
                                rules=sorted({f.rule_id for f in out.findings}))
                if self.server.mode == "enforce" and out.decision == "block":
                    self._audit("gateway_output_blocked", score=out.score,
                                rules=sorted({f.rule_id for f in out.findings}))
                    self._json(403, self._refusal("data leaving at the output boundary",
                                                  sorted({f.rule_id for f in out.findings})))
                    return

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scanning gateway for OpenAI-compatible APIs.")
    parser.add_argument("--upstream", required=True, help="base URL, e.g. https://api.example.com")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--mode", choices=["monitor", "enforce"], default="monitor")
    parser.add_argument("--log", help="chained audit log path; stderr when omitted")
    parser.add_argument("--canary", action="append", default=[], help="repeatable")
    parser.add_argument("--api-key-env", help="environment variable holding the upstream key")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--policy", help="policy JSON: tool calls the model requests are checked against it")
    parser.add_argument("--agent-id", help="agent identity used for policy grants")
    parser.add_argument("--max-body-bytes", type=int, default=DEFAULT_MAX_BODY)
    parser.add_argument("--allow-streaming", action="store_true",
                        help="forward streaming responses uninspected instead of refusing them")
    parser.add_argument("--fail-open", action="store_true",
                        help="forward when the scanner fails instead of refusing (default is fail closed)")
    args = parser.parse_args(argv)

    server = ThreadingHTTPServer((args.host, args.port), Gateway)
    server.upstream = args.upstream
    server.mode = args.mode
    server.canaries = args.canary
    server.timeout = args.timeout
    server.audit = AuditLog(args.log) if args.log else AuditLog(stream=sys.stderr)
    server.audit_lock = threading.Lock()
    key = os.environ.get(args.api_key_env) if args.api_key_env else None
    server.authorization = ("Bearer " + key) if key else None
    server.policy = Policy.load(args.policy) if args.policy else None
    server.agent_id = args.agent_id or None
    server.max_body = args.max_body_bytes
    server.allow_streaming = args.allow_streaming
    server.fail_open = args.fail_open
    bound = server.server_address[1]
    print("gateway listening on http://%s:%d in %s mode, forwarding to %s" % (
        args.host, bound, args.mode, args.upstream), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
