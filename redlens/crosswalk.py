"""Map the rule pack onto the standards a buyer can actually check.

Two rules govern this file:

  1. A mapping is printed only for a standard whose text is in front of the author.
     Every rule in this pack already carries its OWASP LLM Top 10 reference, so
     that column is a restatement, not a guess.
  2. A standard that could not be obtained is listed as unmapped, with the reason.
     A crosswalk to a document nobody read is fabrication with a schema.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .rules import CCI_SIGNALS, OUTPUT_RULES, RULES, STRUCTURAL_RULES

# NIST AI RMF functions, mapped from the category each rule belongs to. This is
# the project's own reading of the functions, not a certified mapping.
RMF_BY_CATEGORY = {
    "instruction_override": "MEASURE",
    "system_exfiltration": "MEASURE",
    "role_hijack": "MEASURE",
    "safety_bypass": "MEASURE",
    "delimiter_spoof": "MEASURE",
    "agent_tool_abuse": "MANAGE",
    "indirect_injection": "MEASURE",
    "tool_poisoning": "MANAGE",
    "encoding_evasion": "MEASURE",
    "data_exfiltration": "MANAGE",
    "many_shot": "MEASURE",
    "error_path_injection": "MEASURE",
    "crypto_context_injection": "MEASURE",
    "cross_turn_escalation": "MEASURE",
    "secret_leak": "MANAGE",
    "output_exfiltration": "MANAGE",
    "code_sink": "MANAGE",
    "manifest_anomaly": "MANAGE",
    "tool_call_abuse": "MANAGE",
}

UNMAPPED_STANDARDS = [
    {
        "standard": "OWASP Top 10 for Agentic Applications",
        "status": "not mapped",
        "reason": "the document was not obtained in the environment where this was built, "
                  "so any control-by-control mapping would be invented",
    },
    {
        "standard": "AIUC-1",
        "status": "not mapped",
        "reason": "same: the control text is not available here, and a crosswalk to a standard "
                  "nobody read is worse than no crosswalk",
    },
    {
        "standard": "EU AI Act technical documentation",
        "status": "not mapped",
        "reason": "legal interpretation is out of scope for this project",
    },
]


# The rules carry LLM01 by default; this is the project's own reading of which
# Top 10 entry each family belongs to, which is why it is named as an opinion.
OWASP_BY_CATEGORY = {
    "instruction_override": "LLM01:2025 Prompt Injection",
    "system_exfiltration": "LLM02:2025 Sensitive Information Disclosure",
    "role_hijack": "LLM01:2025 Prompt Injection",
    "safety_bypass": "LLM01:2025 Prompt Injection",
    "delimiter_spoof": "LLM01:2025 Prompt Injection",
    "agent_tool_abuse": "LLM06:2025 Excessive Agency",
    "indirect_injection": "LLM01:2025 Prompt Injection",
    "tool_poisoning": "LLM03:2025 Supply Chain",
    "encoding_evasion": "LLM01:2025 Prompt Injection",
    "data_exfiltration": "LLM02:2025 Sensitive Information Disclosure",
    "many_shot": "LLM01:2025 Prompt Injection",
    "error_path_injection": "LLM01:2025 Prompt Injection",
    "crypto_context_injection": "LLM01:2025 Prompt Injection",
    "cross_turn_escalation": "LLM01:2025 Prompt Injection",
    "secret_leak": "LLM02:2025 Sensitive Information Disclosure",
    "output_exfiltration": "LLM02:2025 Sensitive Information Disclosure",
    "code_sink": "LLM05:2025 Improper Output Handling",
    "manifest_anomaly": "LLM03:2025 Supply Chain",
    "tool_call_abuse": "LLM06:2025 Excessive Agency",
}


def _entry(rule_id: str, category: str, severity: str, description: str,
           owasp: str = "", kill_switch: bool = False) -> Dict[str, Any]:
    return {
        "rule": rule_id,
        "category": category,
        "severity": severity,
        "owasp_llm_top10": OWASP_BY_CATEGORY.get(category, owasp or "LLM01:2025 Prompt Injection"),
        "nist_ai_rmf_function": RMF_BY_CATEGORY.get(category, "MEASURE"),
        "kill_switch": kill_switch,
        "description": description,
    }


def build_crosswalk() -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    for rule in list(RULES) + list(CCI_SIGNALS) + list(OUTPUT_RULES):
        entries.append(_entry(rule.id, rule.category, rule.severity, rule.description, rule.owasp, rule.kill_switch))
    for rule_id, meta in sorted(STRUCTURAL_RULES.items()):
        entries.append(_entry(rule_id, str(meta["category"]), str(meta["severity"]),
                              str(meta["description"]), "LLM01:2025 Prompt Injection",
                              bool(meta.get("kill_switch"))))
    return {
        "generated_for": "redlens",
        "note": "Mappings are restatements of references already carried by each rule. "
                "Unmapped standards are listed with the reason.",
        "controls": entries,
        "coverage_by_owasp": _by_owasp(entries),
        "unmapped_standards": UNMAPPED_STANDARDS,
    }


def _by_owasp(entries: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for entry in entries:
        counts[entry["owasp_llm_top10"]] = counts.get(entry["owasp_llm_top10"], 0) + 1
    return dict(sorted(counts.items()))


def summarize_crosswalk(crosswalk: Dict[str, Any]) -> str:
    lines = ["RedLens standard crosswalk", "  controls: %d" % len(crosswalk["controls"])]
    for reference, count in crosswalk["coverage_by_owasp"].items():
        lines.append("    %-42s %d" % (reference, count))
    lines.append("  unmapped standards:")
    for item in crosswalk["unmapped_standards"]:
        lines.append("    %-42s %s" % (item["standard"], item["status"]))
    return "\n".join(lines)


def as_json(crosswalk: Dict[str, Any]) -> str:
    return json.dumps(crosswalk, indent=2)
