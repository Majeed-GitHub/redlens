"""Turn findings into a scored, actionable verdict."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence

from .detectors import (
    LAYER_DIRECT,
    LAYER_RETRIEVED,
    LAYER_TOOL_DEFINITION,
    LAYER_TOOL_OUTPUT,
    Finding,
    scan_text,
)
from .rules import SEVERITY_WEIGHTS, Rule

DECISION_CLEAN = "clean"
DECISION_ALLOW = "allow_with_warnings"
DECISION_REVIEW = "review"
DECISION_BLOCK = "block"

REVIEW_AT = 25
BLOCK_AT = 55

# Content the user never typed gets a lower review bar: it only has to look
# suspicious, because nobody is watching it arrive.
REVIEW_THRESHOLDS = {
    "direct": 25,
    "retrieved": 18,
    "tool_output": 18,
    "tool_definition": 15,
    "output": 25,
    "session": 18,
}
KILL_SWITCH_BUDGET = 12

RISKY_COMBINATIONS = (
    ("instruction_override", "system_exfiltration"),
    ("instruction_override", "agent_tool_abuse"),
    ("safety_bypass", "tool_poisoning"),
    ("instruction_override", "tool_poisoning"),
)


@dataclass
class Report:
    """Result of scanning one piece of content."""

    target: str
    layer: str
    text_length: int
    findings: List[Finding] = field(default_factory=list)
    score: int = 0
    decision: str = DECISION_CLEAN
    notes: List[str] = field(default_factory=list)

    @property
    def categories(self) -> List[str]:
        return sorted({f.category for f in self.findings})

    @property
    def kill_switch_hit(self) -> bool:
        return any(f.kill_switch for f in self.findings)

    @property
    def max_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        order = ["low", "medium", "high", "critical"]
        return max((f.severity for f in self.findings), key=order.index)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "layer": self.layer,
            "text_length": self.text_length,
            "decision": self.decision,
            "score": self.score,
            "max_severity": self.max_severity,
            "categories": self.categories,
            "notes": self.notes,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def summary(self) -> str:
        head = "%s [%s] score=%d decision=%s findings=%d" % (
            self.target, self.layer, self.score, self.decision, len(self.findings))
        if not self.findings:
            return head + " - no indicators"
        lines = [head]
        for finding in self.findings:
            lines.append("  " + finding.line())
            lines.append("    evidence: " + finding.evidence[:140])
        for note in self.notes:
            lines.append("  note: " + note)
        return "\n".join(lines)


def score_findings(findings: Sequence[Finding]) -> tuple:
    """Sum weighted severity, add combination bonuses, cap at 100."""
    score = 0
    used = set()
    for finding in findings:
        if finding.rule_id in used:
            continue
        used.add(finding.rule_id)
        score += SEVERITY_WEIGHTS.get(finding.severity, 0)

    notes: List[str] = []
    categories = {f.category for f in findings}
    if len(categories) >= 2:
        score += 5 * (len(categories) - 1)
        notes.append("%d attack categories in one input (%s): layered attempt." % (
            len(categories), ", ".join(sorted(categories))))
    if any(f.decoded_via for f in findings):
        score += 10
        notes.append("Payload was obfuscated (decoded before matching): active evasion.")
    for left, right in RISKY_COMBINATIONS:
        if left in categories and right in categories:
            score += 10
            notes.append("Risky combination detected: %s + %s." % (left, right))
            break
    return min(100, score), notes



def decide(score: int, findings: Sequence[Finding], layer: str = "direct") -> str:
    # A kill-switch finding blocks on its own. That list stays tiny on purpose:
    # redlens audit fails CI if it grows past KILL_SWITCH_BUDGET.
    if any(f.kill_switch for f in findings):
        return DECISION_BLOCK
    if any(f.severity == "critical" for f in findings) and score >= 40:
        return DECISION_BLOCK
    if score >= BLOCK_AT:
        return DECISION_BLOCK
    if score >= REVIEW_THRESHOLDS.get(layer, REVIEW_AT):
        return DECISION_REVIEW
    if findings:
        return DECISION_ALLOW
    return DECISION_CLEAN


def scan(
    text: str,
    target: str = "input",
    layer: str = LAYER_DIRECT,
    rules: Optional[Sequence[Rule]] = None,
) -> Report:
    """Scan one piece of content and return a scored verdict."""
    findings = scan_text(text or "", layer=layer, rules=rules)
    score, notes = score_findings(findings)
    return Report(
        target=target,
        layer=layer,
        text_length=len(text or ""),
        findings=findings,
        score=score,
        decision=decide(score, findings, layer),
        notes=notes,
    )


def scan_messages(messages: Iterable[dict], rules: Optional[Sequence[Rule]] = None) -> List[Report]:
    """Scan a chat transcript. Each message may give a role and a layer."""
    reports = []
    for index, message in enumerate(messages):
        layer = message.get("layer") or LAYER_DIRECT
        role = message.get("role", "unknown")
        target = "%s[%d]:%s" % (message.get("id", "msg"), index, role)
        reports.append(scan(message.get("content", ""), target=target, layer=layer, rules=rules))
    return reports


def scan_tool_output(text: str, tool: str = "tool", rules: Optional[Sequence[Rule]] = None) -> Report:
    """Scan third-party tool or API output before it reaches the model."""
    return scan(text, target="tool:" + tool, layer=LAYER_TOOL_OUTPUT, rules=rules)


def scan_retrieved(text: str, source: str = "document", rules: Optional[Sequence[Rule]] = None) -> Report:
    """Scan retrieved RAG content before it reaches the model."""
    return scan(text, target="rag:" + source, layer=LAYER_RETRIEVED, rules=rules)


def scan_tool_definition(
    name: str,
    description: str,
    schema: Optional[dict] = None,
    rules: Optional[Sequence[Rule]] = None,
) -> Report:
    """Scan an MCP or function-calling tool definition for poisoning."""
    payload = "tool: %s\ndescription: %s" % (name, description or "")
    if schema:
        payload += "\nschema: " + json.dumps(schema, ensure_ascii=False)
    report = scan(payload, target="tool-definition:" + name, layer=LAYER_TOOL_DEFINITION, rules=rules)
    lowered = (description or "").lower()
    if len(description or "") > 1200:
        report.notes.append("Tool description is unusually long (%d chars): review for smuggling." % len(description))
        report.score = min(100, report.score + 5)
    if "http://" in lowered or "https://" in lowered:
        report.notes.append("Tool description contains a URL: verify the destination is trusted.")
    return report


def worst(reports: Sequence[Report]) -> Optional[Report]:
    """Return the highest-risk report from a batch."""
    order = {DECISION_CLEAN: 0, DECISION_ALLOW: 1, DECISION_REVIEW: 2, DECISION_BLOCK: 3}
    if not reports:
        return None
    return max(reports, key=lambda r: (order.get(r.decision, 0), r.score))
