"""Whole-toolset analysis for MCP and function-calling manifests.

A per-tool scan sees one description. Attacks do not work that way: the
dangerous facts are often the combination - a tool that can read credentials
and also reach the network - or text that is invisible in the rendered
description but perfectly visible to the model reading the raw JSON.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .detectors import LAYER_TOOL_DEFINITION, Finding, scan_text
from .rules import RULES, STRUCTURAL_RULES
from .scanner import Report, decide, scan_tool_definition, score_findings

INVISIBLE_CHARS = "\u200b\u200c\u200d\u2060\ufeff\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
TAG_CHARS = re.compile(r"[\U000e0000-\U000e007f]")
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
INSTRUCTION_WORDS = re.compile(
    r"\b(?:ignore|instruct|instruction|must|should|always|never|read|send|pass|include|forward|token|key|secret|password|execute|run|delete|upload)\b",
    re.IGNORECASE,
)
SENTENCE_ENUM = re.compile(r"^[A-Za-z][^,]{24,}\s\w+\s\w+\s\w+$")

KNOWN_TOOL_NAMES: Tuple[str, ...] = (
    "read_file", "write_file", "web_fetch", "http_request", "bash", "shell",
    "execute_code", "search", "get_weather", "send_email", "list_files",
    "delete_file", "transfer_funds", "query_database", "run_command",
)

CAPABILITY_PATTERNS: Dict[str, "re.Pattern[str]"] = {
    "fs_read": re.compile(r"(?:^|_)(?:read|get|load|list|cat|open|download)(?:_|$)", re.IGNORECASE),
    "fs_write": re.compile(r"(?:^|_)(?:write|save|put|upload|create|delete|remove|drop|move)(?:_|$)", re.IGNORECASE),
    "net_egress": re.compile(r"(?:url|uri|endpoint|webhook|http|https|host|domain|address|remote|callback)", re.IGNORECASE),
    "exec": re.compile(r"(?:exec|execute|shell|bash|cmd|command|run|eval|script|code)", re.IGNORECASE),
    "cred_access": re.compile(r"(?:secret|token|key|credential|password|passwd|vault|aws|session|cookie)", re.IGNORECASE),
}

DANGEROUS_PAIRS: Tuple[Tuple[str, str], ...] = (
    ("cred_access", "net_egress"),
    ("fs_read", "net_egress"),
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
        owasp="LLM03:2025 Supply Chain",
        layer=LAYER_TOOL_DEFINITION,
        rule_severity=str(meta["severity"]),
        kill_switch=bool(meta["kill_switch"]),
    )


def _decode_tag_characters(text: str) -> str:
    """Tag characters carry their payload in the U+E0000 offset. Decode them."""
    return "".join(chr(ord(ch) - 0xE0000) for ch in text if 0xE0000 <= ord(ch) <= 0xE007F)


def hidden_content(raw: str) -> str:
    """Everything a human would not see when the description is rendered."""
    if not raw:
        return ""
    hidden = _decode_tag_characters(raw)
    hidden += "".join(ch for ch in raw if ch in INVISIBLE_CHARS)
    hidden += " ".join(HTML_COMMENT.findall(raw))
    hidden += " ".join(ANSI_ESCAPE.findall(raw))
    return hidden


def _tool_parts(tool: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
    """Accept both MCP style and OpenAI function-calling style tool objects."""
    body = tool.get("function") if isinstance(tool.get("function"), dict) else tool
    name = str(body.get("name") or tool.get("name") or "")
    description = str(body.get("description") or tool.get("description") or "")
    schema = body.get("inputSchema") or body.get("parameters") or body.get("input_schema") or {}
    if not isinstance(schema, dict):
        schema = {}
    return name, description, schema


def _walk(node: Any):
    """Yield every key and string value inside a schema."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)
    elif isinstance(node, str):
        yield node


def _capabilities(name: str, schema: Dict[str, Any]) -> Dict[str, bool]:
    tokens = [name] + list(_walk(schema))
    joined = " ".join(tokens)
    return {tag: bool(pattern.search(joined)) for tag, pattern in CAPABILITY_PATTERNS.items()}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def scan_tool_manifest(tools: Sequence[Dict[str, Any]], target: str = "manifest") -> Report:
    """Analyse a whole toolset, not one tool description at a time."""
    findings: List[Finding] = []
    notes: List[str] = []
    tool_list = [t for t in (tools or []) if isinstance(t, dict)]
    seen_names: Dict[str, int] = {}

    for index, tool in enumerate(tool_list):
        name, description, schema = _tool_parts(tool)
        label = name or ("tool[%d]" % index)
        raw = json.dumps(tool, ensure_ascii=False)
        seen_names[label] = seen_names.get(label, 0) + 1

        # 1. Instructions hidden where a reviewer will not look.
        hidden = hidden_content(raw)
        if hidden.strip() and INSTRUCTION_WORDS.search(hidden):
            findings.append(_structural(
                "RL-401",
                "hidden text in %s: %s" % (label, hidden.strip()[:120]),
                "Instructions hidden in invisible characters inside tool metadata (%s)." % label,
            ))

        # 2. Encoded blobs in defaults or examples.
        for value in _walk(schema):
            match = B64_BLOB.search(value)
            if match:
                findings.append(_structural(
                    "RL-403",
                    "%s: %s..." % (label, match.group(0)[:40]),
                    "Encoded blob in a parameter value of tool %s." % label,
                ))
                break

        # 3. Name says one thing, parameters say another.
        caps = _capabilities(name, schema)
        lowered = name.lower()
        looks_readonly = bool(re.match(r"^(?:get|read|list|fetch|search|lookup|describe|view|weather)", lowered))
        risky_params = bool(re.search(r"(?:url|endpoint|cmd|command|path|payload|exec|shell|script)", json.dumps(schema), re.IGNORECASE))
        if looks_readonly and risky_params and caps["net_egress"]:
            findings.append(_structural(
                "RL-404",
                "%s takes url/endpoint/payload parameters" % label,
                "Tool %s reads as a lookup but accepts parameters that reach outside it." % label,
            ))

        # 4. Capability combinations: this is the exfiltration primitive.
        for left, right in DANGEROUS_PAIRS:
            if caps[left] and caps[right]:
                findings.append(_structural(
                    "RL-402",
                    "%s holds %s + %s" % (label, left, right),
                    "Tool %s combines %s with %s in one call." % (label, left, right),
                ))
                break

        # 5. Name shadowing.
        if name and name not in KNOWN_TOOL_NAMES:
            for known in KNOWN_TOOL_NAMES:
                if 0 < _levenshtein(name.lower(), known) <= 2:
                    findings.append(_structural(
                        "RL-405",
                        "%s is %d edit(s) from %s" % (name, _levenshtein(name.lower(), known), known),
                        "Tool name %s shadows the well-known tool %s." % (name, known),
                    ))
                    break

        # 6. Open schema plus execution-style parameters.
        if re.search(r'"additionalProperties"\s*:\s*true', json.dumps(schema)) and caps["exec"]:
            findings.append(_structural(
                "RL-406",
                "%s: additionalProperties true with exec-style parameters" % label,
            ))

        # 7. Instruction-like values in defaults or examples.
        for value in _walk(schema):
            if len(value) > 12 and INSTRUCTION_WORDS.search(value) and not value.startswith("{"):
                findings.append(_structural(
                    "RL-407",
                    "%s: %s" % (label, value[:100]),
                    "Instruction-like text in a parameter value of tool %s." % label,
                ))
                break

        # 8. Enum entries written as sentences.
        for value in _walk(schema):
            if SENTENCE_ENUM.match(value) and value.count(" ") >= 4 and not value.endswith("."):
                findings.append(_structural(
                    "RL-408",
                    "%s: %s" % (label, value[:100]),
                ))
                break

        # 9. The existing per-tool text rules still apply.
        per_tool = scan_tool_definition(name, description, schema)
        findings.extend(per_tool.findings)
        notes.extend(per_tool.notes)

    for label, count in seen_names.items():
        if count > 1:
            notes.append("tool name %s appears %d times in the manifest." % (label, count))

    score, extra_notes = score_findings(findings)
    notes.extend(extra_notes)
    if len(tool_list) > 1:
        notes.append("analysed %d tools as one manifest." % len(tool_list))

    return Report(
        target=target,
        layer=LAYER_TOOL_DEFINITION,
        text_length=len(json.dumps(tool_list, ensure_ascii=False)),
        findings=findings,
        score=score,
        decision=decide(score, findings, LAYER_TOOL_DEFINITION),
        notes=notes,
    )
