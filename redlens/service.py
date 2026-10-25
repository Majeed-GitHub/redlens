"""A dependency-free HTTP sidecar.

For callers that cannot import Python: a gateway, a sidecar container, another
language. The scanner is the same code; this only moves the decision onto a
socket, which is where a platform team actually deploys it.

    python -m redlens serve --port 8123 --token-env REDLENS_TOKEN

    GET  /health          liveness
    POST /scan            {"text": "...", "layer": "direct", "target": "..."}
    POST /scan/tool       {"name": "...", "description": "...", "schema": {...}}

The HTTP status carries the decision, so a caller can gate on it without parsing
JSON: 200 for clean or allow_with_warnings, 422 for review, 403 for block.

Deliberately stdlib only, and deliberately small: no TLS, no auth beyond a shared
token, and no request queue. Put it behind the platform's own ingress.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from .scanner import DECISION_BLOCK, DECISION_CLEAN, DECISION_REVIEW, scan, scan_tool_definition
from .session import ScanSession

STATUS_BY_DECISION = {
    DECISION_CLEAN: 200,
    "allow_with_warnings": 200,
    DECISION_REVIEW: 422,
    DECISION_BLOCK: 403,
}
DEFAULT_MAX_BODY = 262_144
LOOPBACK = ("127.0.0.1", "::1", "localhost")


def _status_for(report) -> int:
    return STATUS_BY_DECISION.get(report.decision, 422)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "RedLensSidecar/1.0"

    def log_message(self, fmt, *args):
        if self.server.quiet:
            return
        sys.stderr.write("redlens: " + (fmt % args) + "\n")

    # ------------------------------------------------------------------ helpers
    def _send(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self) -> bool:
        if not self.server.token:
            return True
        header = self.headers.get("Authorization") or ""
        return header == "Bearer " + self.server.token

    def _read_json(self) -> Optional[Dict[str, Any]]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > self.server.max_body:
            self._send(413, {"error": "request body larger than %d bytes" % self.server.max_body})
            return None
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw or b"{}")
        except ValueError as exc:
            self._send(400, {"error": "body is not JSON: %s" % exc})
            return None
        if not isinstance(payload, dict):
            self._send(400, {"error": "body must be a JSON object"})
            return None
        return payload

    # -------------------------------------------------------------------- routes
    def do_GET(self):
        if self.path.split("?")[0] in ("/health", "/"):
            self._send(200, {"status": "ok", "version": self.server.redlens_version})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorised():
            self._send(401, {"error": "missing or wrong bearer token"})
            return
        path = self.path.split("?")[0]
        if path not in ("/scan", "/scan/tool", "/scan/session"):
            self._send(404, {"error": "not found"})
            return
        payload = self._read_json()
        if payload is None:
            return

        if path == "/scan":
            report = scan(str(payload.get("text") or ""),
                          target=str(payload.get("target") or "http"),
                          layer=str(payload.get("layer") or "direct"))
        elif path == "/scan/session":
            session = ScanSession()
            for turn in payload.get("turns") or []:
                if isinstance(turn, dict):
                    session.scan(str(turn.get("text") or ""), layer=str(turn.get("layer") or "direct"))
                else:
                    session.scan(str(turn))
            report = session.scan(str(payload.get("text") or ""))
        else:
            report = scan_tool_definition(str(payload.get("name") or ""),
                                          str(payload.get("description") or ""),
                                          payload.get("schema") or {})

        self._send(_status_for(report), report.to_dict())


def build_server(host: str = "127.0.0.1", port: int = 8123, token: Optional[str] = None,
                 max_body: int = DEFAULT_MAX_BODY, quiet: bool = False):
    """Create the server without starting it, so tests can bind port 0."""
    from . import __version__
    server = ThreadingHTTPServer((host, port), Handler)
    server.token = token
    server.max_body = max_body
    server.quiet = quiet
    server.redlens_version = __version__
    return server


def serve(host: str = "127.0.0.1", port: int = 8123, token: Optional[str] = None,
          max_body: int = DEFAULT_MAX_BODY, quiet: bool = False) -> int:
    """Run until interrupted. Refuses a non-loopback bind without a token."""
    if host not in LOOPBACK and not token:
        sys.stderr.write("refusing to bind %s without a token: pass --token-env or --token\n" % host)
        return 2
    server = build_server(host, port, token, max_body, quiet)
    bound = server.server_address[1]
    sys.stderr.write("redlens sidecar on http://%s:%d %s\n" % (
        host, bound, "(token required)" if token else "(no token, loopback only)"))
    sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def serve_in_thread(host: str = "127.0.0.1", **kwargs):
    """Start the server on a background thread and return (server, url)."""
    server = build_server(host, kwargs.pop("port", 0), **kwargs)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "http://%s:%d" % (host, server.server_address[1])
