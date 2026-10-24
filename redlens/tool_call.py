"""Argument-level inspection.

Manifest analysis sees what a tool claims. This sees what it is about to do.
The documented agent exfiltration path is usually a parameter value the UI never
renders - a key path handed to a tool that can also reach the network - so the
decision here is capped at review on purpose: one argument is evidence, not
proof, and RedLens must not block an agent on evidence it cannot see whole.

Latency is reported by redlens audit; routine arguments are a few hundred bytes.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .detectors import Finding
from .manifest import _capabilities
from .rules import STRUCTURAL_RULES
from .scanner import DECISION_BLOCK, DECISION_REVIEW, Report, decide, score_findings

TOOL_CALL_LAYER = "tool_call"

SENSITIVE_PATH = re.compile(
    r"(?:~?/\.ssh/|~?/\.aws/|/\.config/gh/|(?:^|[\s\"'=])\.env\b|\.npmrc|\.pypirc|"
    r"mcp\.json|id_rsa|id_ed25519|\.git-credentials|\.pem\b|/etc/shadow|"
    r"Application Support/Google/Chrome|\.mozilla/firefox)",
    re.IGNORECASE,
)

SECRET_VALUE = re.compile(
    r"(?:sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{16,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)",
)

SHELL_METACHARACTERS = re.compile(
    r"(?:<\s*\(|\$\(|\x60|\|\s*\w|&&|;\s*(?:rm|curl|wget|nc|sh|bash)\b)",
)

TRAVERSAL = re.compile(r"(?:\.\./){2,}|(?:^|[\s\"'=])/(?:etc|root|var|home|usr|proc)/")

# A URL argument that contains a shell command is not a URL. This check is not
# gated on the tool being exec-like: the argument itself is the evidence.
NESTED_COMMAND = re.compile(
    r"(?:\$\(|<\s*\()\s*(?:sudo\s+)?(?:curl|wget|nc|netcat|sh|bash|zsh|python3?|node|perl|rm|cat)\b",
    re.IGNORECASE,
)


def _structural(rule_id: str, evidence: str, description: Optional[str] = None) -> Finding:
    meta = STRUCTURAL_RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        category=str(meta["category"]),
        severity=str(meta["severity"]),
        description=description or str(meta["description"]),
        evidence=evidence[:200],
        span=(0, 0),
        owasp="LLM01:2025 Prompt Injection",
        layer=TOOL_CALL_LAYER,
        rule_severity=str(meta["severity"]),
    )


def _strings(arguments: Any, prefix: str = "") -> Iterable[Tuple[str, str]]:
    """Yield (key path, string value) for every string in an argument tree."""
    if isinstance(arguments, dict):
        for key, value in arguments.items():
            yield from _strings(value, prefix + "." + str(key) if prefix else str(key))
    elif isinstance(arguments, list):
        for index, value in enumerate(arguments):
            yield from _strings(value, "%s[%d]" % (prefix, index))
    elif isinstance(arguments, str):
        yield prefix, arguments


def _manifest_tool(tool_manifest: Any, tool_name: str) -> Optional[Dict[str, Any]]:
    if not tool_manifest:
        return None
    tools = tool_manifest.get("tools") if isinstance(tool_manifest, dict) else tool_manifest
    if not isinstance(tools, list):
        return None
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        body = tool.get("function") if isinstance(tool.get("function"), dict) else tool
        if str(body.get("name") or "") == tool_name:
            return body
    return None


def _capabilities_for(tool_name: str, arguments: Dict[str, Any], tool_manifest: Any) -> Dict[str, bool]:
    declared = _manifest_tool(tool_manifest, tool_name) or {}
    schema = declared.get("inputSchema") or declared.get("parameters") or {}
    if not isinstance(schema, dict):
        schema = {}
    # Argument keys matter as much as the declared schema: a call that carries a
    # url is egress-capable whether or not the manifest admits it.
    merged = dict(schema)
    properties = dict(merged.get("properties") or {})
    for key in (arguments or {}):
        properties.setdefault(str(key), {})
    merged["properties"] = properties
    return _capabilities(tool_name, merged)


def scan_tool_call(
    tool_name: str,
    arguments: Dict[str, Any],
    tool_manifest: Any = None,
    target: Optional[str] = None,
) -> Report:
    """Inspect the arguments of a single tool call. Never returns block."""
    findings: List[Finding] = []
    args = arguments if isinstance(arguments, dict) else {}
    caps = _capabilities_for(tool_name, args, tool_manifest)
    exec_like = caps.get("exec", False)
    egress = caps.get("net_egress", False)

    sensitive_paths: List[str] = []
    for key, value in _strings(args):
        if SENSITIVE_PATH.search(value):
            sensitive_paths.append(key)
            findings.append(_structural("RL-501", "%s = %s" % (key, value)))
        if SECRET_VALUE.search(value):
            findings.append(_structural("RL-502", "%s carries a secret-shaped value" % key))
        match = NESTED_COMMAND.search(value)
        if match:
            findings.append(_structural(
                "RL-503", "%s runs a nested command: %s" % (key, value[max(0, match.start() - 20):match.end() + 20]),
            ))
        elif exec_like:
            match = SHELL_METACHARACTERS.search(value)
            if match:
                findings.append(_structural(
                    "RL-503", "%s = %s" % (key, value[max(0, match.start() - 20):match.end() + 20]),
                ))
        if TRAVERSAL.search(value):
            findings.append(_structural("RL-504", "%s = %s" % (key, value)))

    # The composite is the real story: a secret in hand and a way out.
    if sensitive_paths and egress:
        findings.append(_structural(
            "RL-505",
            "sensitive path(s) %s handed to an egress-capable tool" % ", ".join(sorted(set(sensitive_paths))),
        ))

    score, notes = score_findings(findings)
    decision = decide(score, findings, TOOL_CALL_LAYER)
    if decision == DECISION_BLOCK:
        decision = DECISION_REVIEW
        notes.append("capped at review: a tool argument is evidence, not proof.")
    if findings:
        notes.append("arguments are not displayed in most agent UIs: log these with the tool name and call id.")

    return Report(
        target=target or ("call:" + (tool_name or "unknown")),
        layer=TOOL_CALL_LAYER,
        text_length=len(json.dumps(args, ensure_ascii=False)),
        findings=findings,
        score=score,
        decision=decision,
        notes=notes,
    )
