"""Declarative policy for what an agent is allowed to do.

The scanner answers "does this look like an attack". Policy answers a different
question, and it is the one auditors ask: "is this agent allowed to do this at
all". A tool call can be completely clean - no injection anywhere - and still be
out of bounds, because the agent is reaching a credential store it should never
have touched.

Policy is JSON, not YAML, because the package ships with no dependencies and the
standard library parses JSON.

    {
      "default": "review",
      "tools": {
        "read_file":   {"allow": {"path": {"within": ["./project", "/srv/data"]}}},
        "http_request":{"allow": {"url": {"hosts": ["api.internal.example"]}}},
        "run_command": {"require_confirmation": true}
      },
      "rules": [
        {"id": "POL-001", "when": {"tool": "run_command"}, "action": "deny",
         "reason": "shell execution is not permitted for this agent"},
        {"id": "POL-002", "when": {"tool": "*delete*", "arg_matches": {"path": "**/.env"}},
         "action": "deny", "reason": "never delete a dotfile secret store"}
      ]
    }
"""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlsplit

ACTION_ALLOW = "allow"
ACTION_REVIEW = "review"
ACTION_DENY = "deny"
ACTION_ORDER = {ACTION_ALLOW: 0, ACTION_REVIEW: 1, ACTION_DENY: 2}

SCAN_TO_ACTION = {
    "clean": ACTION_ALLOW,
    "allow_with_warnings": ACTION_ALLOW,
    "review": ACTION_REVIEW,
    "block": ACTION_DENY,
}


@dataclass
class PolicyDecision:
    action: str
    rule_id: str
    reason: str
    violations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "violations": self.violations,
        }


def normalize_path(value: str) -> str:
    """Collapse a path without touching the filesystem, resolving .. textually."""
    text = str(value).replace("\\", "/")
    absolute = text.startswith("/")
    parts: List[str] = []
    for part in text.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            elif not absolute:
                parts.append("..")
            continue
        parts.append(part)
    joined = "/".join(parts)
    return ("/" + joined) if absolute else joined


def path_within(value: str, root: str) -> bool:
    """True when a path stays inside root after textual normalisation."""
    candidate = normalize_path(value)
    base = normalize_path(root).rstrip("/") or "/"
    return candidate == base or candidate.startswith(base + "/")


def host_of(value: str) -> str:
    try:
        split = urlsplit(str(value))
    except ValueError:
        return ""
    return (split.hostname or "").lower()


def host_allowed(host: str, allowed: Sequence[str]) -> bool:
    for entry in allowed:
        pattern = str(entry).lower()
        if pattern.startswith("*.") and host.endswith(pattern[1:]):
            return True
        if host == pattern:
            return True
    return False


def _string_values(arguments: Any, prefix: str = ""):
    if isinstance(arguments, dict):
        for key, value in arguments.items():
            yield from _string_values(value, prefix + "." + str(key) if prefix else str(key))
    elif isinstance(arguments, list):
        for index, value in enumerate(arguments):
            yield from _string_values(value, "%s[%d]" % (prefix, index))
    elif isinstance(arguments, str):
        yield prefix, arguments


def _matches_when(condition: Dict[str, Any], tool_name: str, arguments: Dict[str, Any]) -> bool:
    pattern = condition.get("tool")
    if pattern and not fnmatch.fnmatch(tool_name or "", pattern):
        return False
    for key, value in (condition.get("arg_matches") or {}).items():
        found = False
        for _, text in _string_values(arguments):
            if fnmatch.fnmatch(text, value):
                found = True
                break
        if not found:
            return False
    for key in (condition.get("has_arg") or []):
        if key not in (arguments or {}):
            return False
    return True


class Policy:
    """A loaded policy document."""

    def __init__(self, document: Dict[str, Any]):
        self.document = document or {}
        self.default = str(self.document.get("default") or ACTION_ALLOW)
        self.tools: Dict[str, Dict[str, Any]] = dict(self.document.get("tools") or {})
        self.rules: List[Dict[str, Any]] = list(self.document.get("rules") or [])

    @classmethod
    def load(cls, path: str) -> "Policy":
        with open(path, "r", encoding="utf-8") as handle:
            return cls(json.load(handle))

    # ------------------------------------------------------------------ eval
    def evaluate(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None,
                 agent: Optional[str] = None) -> PolicyDecision:
        arguments = arguments or {}
        name = tool_name or ""

        # Runtime least privilege. A grant is what this agent, in this session, is
        # allowed to call at all. A tool that is absent from the grant list is out
        # of bounds even when the call itself is clean.
        grants = self.document.get("grants")
        if isinstance(grants, dict) and agent:
            allowed = grants.get(agent)
            if allowed is None:
                return PolicyDecision(ACTION_DENY, "POL-GRANT",
                                      "agent %s has no grant in this policy" % agent)
            if name not in allowed:
                return PolicyDecision(ACTION_DENY, "POL-GRANT",
                                      "agent %s is not granted the tool %s" % (agent, name))

        for rule in self.rules:
            if _matches_when(rule.get("when") or {}, name, arguments):
                return PolicyDecision(
                    action=str(rule.get("action") or ACTION_REVIEW),
                    rule_id=str(rule.get("id") or "POL-RULE"),
                    reason=str(rule.get("reason") or "matched policy rule"),
                )

        spec = self.tools.get(name)
        if not spec:
            for candidate, body in self.tools.items():
                if fnmatch.fnmatch(name, candidate):
                    spec = body
                    break
        if isinstance(spec, dict):
            decision = self._check_tool(name, spec, arguments)
            if decision:
                return decision

        return PolicyDecision(self.default, "POL-DEFAULT", "no rule matched; policy default is %s" % self.default)

    def _check_tool(self, name: str, spec: Dict[str, Any], arguments: Dict[str, Any]) -> Optional[PolicyDecision]:
        for key, pattern in (spec.get("deny") or {}).items():
            for arg_key, text in _string_values(arguments):
                if arg_key.split(".")[-1] != key:
                    continue
                patterns = pattern if isinstance(pattern, list) else [pattern]
                for entry in patterns:
                    if fnmatch.fnmatch(text, entry):
                        return PolicyDecision(ACTION_DENY, "POL-DENY",
                                              "tool %s: argument %s matches denied pattern %s" % (name, arg_key, entry),
                                              ["%s=%s" % (arg_key, text)])

        constraints = spec.get("allow") or {}
        for key, rule in constraints.items():
            patterns = rule if isinstance(rule, dict) else {"matches": rule if isinstance(rule, list) else [rule]}
            for arg_key, text in _string_values(arguments):
                if arg_key.split(".")[-1] != key:
                    continue
                if "within" in patterns:
                    roots = patterns["within"] if isinstance(patterns["within"], list) else [patterns["within"]]
                    if not any(path_within(text, root) for root in roots):
                        return PolicyDecision(ACTION_DENY, "POL-SCOPE",
                                              "tool %s: %s is outside the allowed roots %s" % (name, arg_key, ", ".join(roots)),
                                              ["%s=%s" % (arg_key, text)])
                if "hosts" in patterns:
                    hosts = patterns["hosts"] if isinstance(patterns["hosts"], list) else [patterns["hosts"]]
                    host = host_of(text)
                    if not host_allowed(host, hosts):
                        return PolicyDecision(ACTION_DENY, "POL-HOST",
                                              "tool %s: host %s is not in the allowed list" % (name, host or text),
                                              ["%s=%s" % (arg_key, text)])
                if "matches" in patterns:
                    allowed = patterns["matches"] if isinstance(patterns["matches"], list) else [patterns["matches"]]
                    if not any(fnmatch.fnmatch(text, entry) for entry in allowed):
                        return PolicyDecision(ACTION_DENY, "POL-PATTERN",
                                              "tool %s: %s does not match the allowed patterns" % (name, arg_key),
                                              ["%s=%s" % (arg_key, text)])

        if spec.get("require_confirmation"):
            return PolicyDecision(ACTION_REVIEW, "POL-CONFIRM",
                                  "tool %s requires human confirmation" % name)
        return None


def combine(policy_action: str, scan_decision: str) -> str:
    """The stricter of what policy allows and what the scanner found."""
    return max(
        (policy_action, SCAN_TO_ACTION.get(scan_decision, ACTION_REVIEW)),
        key=lambda action: ACTION_ORDER.get(action, 1),
    )


def load_policy(path: Optional[str]) -> Optional[Policy]:
    if not path:
        return None
    return Policy.load(path)
