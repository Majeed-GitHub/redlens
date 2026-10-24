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

from redlens import AuditLog, scan, scan_output  # noqa: E402

MODEL_PATH_HINTS = ("/chat/completions", "/completions", "/responses")


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
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw or b"{}")
        except ValueError:
            self._json(400, {"error": {"message": "request body is not JSON"}})
            return

        if any(hint in self.path for hint in MODEL_PATH_HINTS):
            text = last_user_text(payload)
            report = scan(text, target="input")
            model = str(payload.get("model") or "unknown")
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

        if isinstance(body, (bytes, bytearray)) and b"{" in body[:1] or body[:1] == b"[":
            try:
                parsed = json.loads(body.decode("utf-8", "replace"))
                out = scan_output(response_text(parsed), canaries=self.server.canaries, target="output")
                if out.findings:
                    self._audit("gateway_output_flagged", score=out.score, decision=out.decision,
                                rules=sorted({f.rule_id for f in out.findings}))
                if self.server.mode == "enforce" and out.decision == "block":
                    self._audit("gateway_output_blocked", score=out.score,
                                rules=sorted({f.rule_id for f in out.findings}))
                    self._json(403, self._refusal("data leaving at the output boundary",
                                                  sorted({f.rule_id for f in out.findings})))
                    return
            except ValueError:
                pass

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

    print("gateway listening on http://%s:%d in %s mode, forwarding to %s" % (
        args.host, args.port, args.mode, args.upstream))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
