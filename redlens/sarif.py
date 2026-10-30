"""SARIF 2.1.0 export.

A scanner that only prints text is a demo. SARIF is the format GitHub Code
Scanning, Azure DevOps and most CI security tabs consume: findings arrive on a
pull request as annotations instead of scrolling past in a log. This module is
the adapter, and it stays free of policy - a finding's severity maps to a SARIF
level, the rule's description becomes the message, and the offset range becomes
a line and column so the annotation points at the sentence that fired.

Two deliberate choices:

- Rule metadata comes from the rule pack, so a consumer can read what RL-210
  means without opening this repository. A finding whose rule id is unknown
  (a caller passed custom rules) still emits with a minimal descriptor: hiding
  a real detection because its metadata is missing would be the worse failure.
- Fingerprints hash (rule id, normalised evidence), so one finding keeps one
  identity across runs. GitHub Code Scanning uses that identity to match an
  alert and to decide when it has been fixed.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional, Sequence, Tuple

from .detectors import Finding
from .identity import annotate
from .rules import CCI_SIGNALS, OUTPUT_RULES, RULES, STRUCTURAL_RULES, Rule
from .scanner import Report

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Majeed-GitHub/redlens"

_LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _rule_table() -> Dict[str, Rule]:
    """Regex rules carry their own metadata."""
    table: Dict[str, Rule] = {}
    for rule in list(RULES) + list(CCI_SIGNALS) + list(OUTPUT_RULES):
        table.setdefault(rule.id, rule)
    return table


"""(Fingerprints come from redlens.identity: they are positional, because the
evidence window a detector produces shifts with the surrounding document.)"""


def _uri(target: str, base_dir: Optional[str]) -> str:
    path = target or "input"
    if base_dir:
        try:
            relative = os.path.relpath(path, base_dir)
            if not relative.startswith(".."):
                path = relative
        except (ValueError, OSError):
            pass
    return path.replace("\\", "/")


def _region(text: Optional[str], span: Tuple[int, int]) -> Optional[Dict[str, int]]:
    """Line/column region for a byte range, when the range still fits text.

    Findings are sometimes matched against a decoded variant (base64, hidden
    unicode) whose offsets mean nothing in the original document. In that case
    the caller gets a location without a region rather than a wrong line.
    """
    if not text:
        return None
    start, end = span
    if start < 0 or end <= start or end > len(text):
        return None
    line = text.count("\n", 0, start) + 1
    column = start - (text.rfind("\n", 0, start) + 1) + 1
    end_line = text.count("\n", 0, end) + 1
    end_column = end - (text.rfind("\n", 0, end) + 1) + 1
    return {
        "startLine": line,
        "startColumn": column,
        "endLine": end_line,
        "endColumn": end_column,
    }


def _structural_descriptor(meta: Dict[str, object], rule_id: str) -> Dict[str, object]:
    """Structural findings (session, output, manifest, tool-call) describe
    themselves in STRUCTURAL_RULES rather than as a Rule object."""
    severity = str(meta.get("severity", "high"))
    descriptor: Dict[str, object] = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": str(meta.get("description", rule_id))},
        "defaultConfiguration": {"level": _LEVELS.get(severity, "warning")},
        "helpUri": INFORMATION_URI,
        "properties": {
            "category": meta.get("category", ""),
            "severity": severity,
            "source": "structural",
            "killSwitch": bool(meta.get("kill_switch")),
        },
    }
    if meta.get("rationale"):
        descriptor["fullDescription"] = {"text": str(meta["rationale"])}
    return descriptor


def rule_descriptor(rule: Optional[Rule], rule_id: str,
                    structural: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    if rule is None and structural is not None:
        return _structural_descriptor(structural, rule_id)
    if rule is None:
        return {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": "RedLens rule " + rule_id},
        }
    descriptor: Dict[str, object] = {
        "id": rule.id,
        "name": rule.id,
        "shortDescription": {"text": rule.description},
        "defaultConfiguration": {"level": _LEVELS.get(rule.severity, "warning")},
        "helpUri": INFORMATION_URI,
    }
    if rule.rationale:
        descriptor["fullDescription"] = {"text": rule.rationale}
    properties: Dict[str, object] = {
        "category": rule.category,
        "severity": rule.severity,
        "source": rule.source,
    }
    if rule.owasp:
        properties["owasp"] = rule.owasp
    if rule.atlas:
        properties["atlas"] = rule.atlas
    if rule.kill_switch:
        properties["killSwitch"] = True
    if rule.ttl:
        properties["ttl"] = rule.ttl
    descriptor["properties"] = properties
    return descriptor


def _result(report: Report, finding: Finding, text: Optional[str], identity: str,
            base_dir: Optional[str], rule_index: Dict[str, int]) -> Dict[str, object]:
    level = "error" if finding.kill_switch else _LEVELS.get(finding.severity, "warning")
    message = finding.description or finding.rule_id
    evidence = " ".join((finding.evidence or "").split())[:200]
    if evidence:
        message = "%s Evidence: %s" % (message, evidence)
    physical: Dict[str, object] = {"artifactLocation": {"uri": _uri(report.target, base_dir)}}
    region = _region(text, finding.span)
    if region:
        physical["region"] = region
    properties: Dict[str, object] = {
        "decision": report.decision,
        "score": report.score,
        "layer": finding.layer or report.layer,
        "category": finding.category,
        "severity": finding.severity,
        "killSwitch": bool(finding.kill_switch),
    }
    if finding.rule_severity:
        properties["ruleSeverity"] = finding.rule_severity
    if finding.owasp:
        properties["owasp"] = finding.owasp
    if finding.decoded_via:
        properties["decodedVia"] = finding.decoded_via
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index.get(finding.rule_id, 0),
        "level": level,
        "message": {"text": message},
        "locations": [{"physicalLocation": physical}],
        "partialFingerprints": {"redlensPosition/v1": identity},
        "properties": properties,
    }


def build_sarif(entries: Sequence[Tuple[Report, str]], tool_version: str = "",
                base_dir: Optional[str] = None) -> Dict[str, object]:
    """Build one SARIF log from (report, scanned text) pairs."""
    table = _rule_table()
    annotated = annotate(entries)
    used: List[str] = []
    seen = set()
    for _, _, finding, _ in annotated:
        if finding.rule_id not in seen:
            seen.add(finding.rule_id)
            used.append(finding.rule_id)

    rule_index = {rule_id: index for index, rule_id in enumerate(used)}
    rules = [
        rule_descriptor(table.get(rule_id), rule_id, STRUCTURAL_RULES.get(rule_id))
        for rule_id in used
    ]
    results = [
        _result(report, finding, text, identity, base_dir, rule_index)
        for report, text, finding, identity in annotated
    ]
    run: Dict[str, object] = {
        "tool": {
            "driver": {
                "name": "redlens",
                "informationUri": INFORMATION_URI,
                "version": tool_version or "unknown",
                "rules": rules,
            }
        },
        "invocations": [{"executionSuccessful": True}],
        "results": results,
    }
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def to_sarif_json(entries: Sequence[Tuple[Report, str]], tool_version: str = "",
                  base_dir: Optional[str] = None, indent: int = 2) -> str:
    return json.dumps(build_sarif(entries, tool_version, base_dir), indent=indent)
