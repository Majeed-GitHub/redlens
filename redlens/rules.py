"""RedLens rule pack.

Zero dependencies on purpose: the pack is a list of frozen dataclasses holding
regular expressions, so the engine runs anywhere Python runs - CI, a laptop, a
lambda, or inside a prompt-filtering gateway.

Severity weights feed the risk score computed in redlens.scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

SEVERITY_WEIGHTS = {"low": 8, "medium": 20, "high": 40, "critical": 65}

SEVERITY_ORDER = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class Rule:
    """One detection rule."""

    id: str
    category: str
    severity: str
    pattern: str
    description: str
    owasp: str = "LLM01:2025 Prompt Injection"
    regex_flags: int = re.IGNORECASE


RULES: List[Rule] = [
    Rule("RL-001", "instruction_override", "critical",
         r"ignore\s+(?:all\s+)?(?:of\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding|foregoing)\s+(?:instructions?|prompts?|rules?|directions?|context)",
         "Instruction override: tells the model to discard everything it was told before."),
    Rule("RL-002", "instruction_override", "critical",
         r"disregard\s+(?:all\s+)?(?:of\s+)?(?:the\s+)?(?:previous|prior|above|earlier|these|those)\s+(?:instructions?|prompts?|rules?|guidelines?)",
         "Instruction override: disregard prior instructions."),
    Rule("RL-003", "instruction_override", "high",
         r"forget\s+(?:everything|all)\s+(?:you\s+(?:were\s+told|know|have\s+been\s+told)|(?:previous|prior|above))",
         "Instruction override: forget prior context."),
    Rule("RL-004", "instruction_override", "high",
         r"(?:new|updated|revised)\s+(?:system\s+)?(?:instructions?|rules?|prompt)\s*[:\-]",
         "Claims to introduce replacement system instructions."),
    Rule("RL-005", "instruction_override", "high",
         r"override\s+(?:your\s+|the\s+)?(?:system\s+)?(?:prompt|instructions?|safety|guardrails?|polic(?:y|ies))",
         "Explicit attempt to override system-level control."),
    Rule("RL-006", "instruction_override", "high",
         r"from\s+now\s+on\s*,?\s*you\s+(?:will|must|shall|are\s+going\s+to)",
         "Persistent behavioural redefinition."),
    Rule("RL-007", "instruction_override", "high",
         r"ignore\s+(?:the\s+)?(?:above|preceding|foregoing)\s+(?:text|content|message)",
         "Instruction override targeting preceding context."),
    Rule("RL-008", "instruction_override", "high",
         r"(?:this\s+is\s+)?(?:a\s+)?(?:test|debug)\s+mode\s*[:\s]+(?:ignore|disable|bypass)",
         "Fake debug mode used to justify disabled controls."),

    Rule("RL-010", "system_exfiltration", "critical",
         r"(?:reveal|show|print|repeat|output|disclose|dump|expose)\s+(?:me\s+)?(?:your\s+|the\s+)?(?:full\s+|exact\s+|original\s+)?(?:system\s+prompt|initial\s+instructions?|hidden\s+instructions?|developer\s+message|base\s+prompt|pre-?prompt)",
         "System-prompt exfiltration attempt."),
    Rule("RL-011", "system_exfiltration", "high",
         r"what\s+(?:are|were|is)\s+your\s+(?:exact\s+|original\s+|full\s+)?(?:system\s+)?(?:instructions?|prompt|rules|guidelines)",
         "Probes for the system prompt."),
    Rule("RL-012", "system_exfiltration", "high",
         r"repeat\s+(?:everything|all\s+the\s+text|the\s+text)\s+(?:above|before)",
         "Context-dump request used to leak instructions."),
    Rule("RL-013", "system_exfiltration", "high",
         r"translate\s+your\s+(?:system\s+)?(?:prompt|instructions)\s+into",
         "Translation trick to bypass prompt-leak filters."),
    Rule("RL-014", "system_exfiltration", "high",
         r"(?:summari[sz]e|paraphrase)\s+your\s+(?:system\s+)?(?:prompt|instructions)",
         "Indirect prompt-leak probe."),

    Rule("RL-020", "role_hijack", "critical",
         r"\b(?:dan\s+mode|do\s+anything\s+now|developer\s+mode\s+enabled|jailbreak\s+mode)\b",
         "Named jailbreak persona."),
    Rule("RL-021", "role_hijack", "high",
         r"you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|evil|malicious|uncensored)",
         "Reassigns the model to an unrestricted persona."),
    Rule("RL-022", "role_hijack", "high",
         r"(?:act|behave|respond)\s+as\s+(?:if\s+you\s+(?:have|had)\s+no\s+(?:restrictions?|rules?|filters?)|an?\s+(?:unrestricted|unfiltered)\s+(?:ai|assistant|model))",
         "Authority-stripping persona request."),
    Rule("RL-023", "role_hijack", "high",
         r"(?:pretend\s+(?:that\s+)?(?:you\s+are|to\s+be)|role-?play\s+as|act\s+as)\s+(?:an?\s+)?(?:evil|hacker|cybercriminal|malware\s+author|uncensored|malicious)",
         "Malicious persona request."),
    Rule("RL-024", "role_hijack", "medium",
         r"(?:role-?play|roleplay)\s+as\s+(?:an?\s+)?",
         "Persona framing that often precedes a safety bypass."),
    Rule("RL-025", "role_hijack", "high",
         r"your\s+(?:new\s+)?(?:persona|identity|character)\s+is",
         "Identity reassignment."),
    Rule("RL-026", "role_hijack", "high",
         r"(?:stay|remain)\s+in\s+character\s+(?:no\s+matter|regardless)",
         "Anchors the model to a persona to resist correction."),
    Rule("RL-027", "role_hijack", "high",
         r"(?:the\s+)?(?:developer|admin|root|superuser)\s+(?:has\s+)?(?:granted|given)\s+you\s+(?:full\s+)?(?:permission|access)",
         "Fabricated authority grant."),

    Rule("RL-030", "safety_bypass", "high",
         r"(?:bypass|disable|turn\s+off|circumvent|remove|get\s+around)\s+(?:all\s+|any\s+)?(?:your\s+|the\s+)?(?:safety|security|content|ethical)\s+(?:filters?|guardrails?|checks?|polic(?:y|ies)|restrictions?|guidelines?)",
         "Direct guardrail-disabling request."),
    Rule("RL-031", "safety_bypass", "high",
         r"(?:without|no)\s+(?:any\s+)?(?:restrictions?|limitations?|filters?|rules?|censorship)\s+(?:apply|applies|applying)",
         "Declares that restrictions no longer apply."),
    Rule("RL-032", "safety_bypass", "medium",
         r"\b(?:hypothetically|fictional\s+scenario|for\s+(?:educational|research)\s+purposes\s+only|in\s+a\s+world\s+where)\b",
         "Framing device common in guardrail-evasion attempts."),
    Rule("RL-033", "safety_bypass", "high",
         r"if\s+you\s+(?:were|are)\s+not\s+(?:bound|restricted)\s+by",
         "Conditional guardrail removal."),
    Rule("RL-034", "safety_bypass", "high",
         r"(?:answer|respond)\s+(?:anyway|regardless)\b[^.\n]{0,40}(?:rules?|polic(?:y|ies)|guidelines?|violat|against)",
         "Instructs the model to ignore its own refusal rules."),

    Rule("RL-040", "delimiter_spoof", "high",
         r"<\s*/?\s*(?:system|assistant|developer|tool|user)\s*>",
         "Fake role tags injected into untrusted content."),
    Rule("RL-041", "delimiter_spoof", "high",
         r"\|\s*(?:system|assistant|developer)\s*\|",
         "Chat-template role marker spoofing."),
    Rule("RL-042", "delimiter_spoof", "high",
         r"\[/?INST\]|<<\s*SYS\s*>>|\[\s*SYSTEM\s*\]",
         "Instruction-template delimiters from common chat prompt formats."),
    Rule("RL-043", "delimiter_spoof", "medium",
         r"#{2,}\s*(?:system|instruction)s?\b",
         "Markdown heading used to fake a system block."),
    Rule("RL-044", "delimiter_spoof", "high",
         r"<\s*\|?\s*/?\s*(?:im_start|im_end)\s*\|?\s*>",
         "ChatML turn-delimiter spoofing."),
    Rule("RL-045", "delimiter_spoof", "medium",
         r"^\s*(?:system|assistant)\s*:\s*\S",
         "Multi-line role label inside untrusted content.",
         regex_flags=re.IGNORECASE | re.MULTILINE),

    Rule("RL-050", "agent_tool_abuse", "critical",
         r"(?:use|call|invoke|run)\s+(?:the\s+)?(?:tool|function|api)\s+[\"']?\w*(?:delete|drop|transfer|exec|shell|admin|write_file)",
         "Coerces a dangerous tool call from untrusted input."),
    Rule("RL-051", "agent_tool_abuse", "high",
         r"(?:escalate|elevate|grant|give)\s+(?:me\s+|your\s+|my\s+|the\s+|full\s+|admin\s+)*(?:privileges?|permissions?|access|role|admin\s+rights)",
         "Privilege-escalation request aimed at an agent."),
    Rule("RL-052", "agent_tool_abuse", "critical",
         r"(?:rm\s+-rf\s+/|curl\s+[^\s|]{4,}\s*\|\s*(?:ba|z)?sh|wget\s+[^\s|]{4,}\s*\|\s*(?:ba|z)?sh|chmod\s+777)",
         "Destructive or remote-pipe shell command in untrusted content."),
    Rule("RL-053", "agent_tool_abuse", "high",
         r"(?:exfiltrate|send|post|upload|forward)\s+(?:the\s+|your\s+|my\s+)?(?:api[\s_-]?keys?|tokens?|secrets?|credentials?|passwords?|env(?:ironment)?\s+variables?|\.env)",
         "Credential exfiltration instruction."),
    Rule("RL-054", "agent_tool_abuse", "medium",
         r"\b(?:id_rsa|\.aws/credentials|\.env|ssh\s+(?:private\s+)?key)\b",
         "Sensitive local secret store referenced by untrusted content."),
    Rule("RL-055", "agent_tool_abuse", "high",
         r"(?:base64\s+-d|--decode|eval\(|exec\(|subprocess\.|os\.system\()",
         "Code-execution primitive in untrusted content."),
    Rule("RL-056", "agent_tool_abuse", "critical",
         r"(?:delete|drop|truncate|wipe)\s+(?:all\s+)?(?:the\s+)?(?:files?|database|tables?|records?|repositor(?:y|ies)|bucket)",
         "Mass-destruction instruction."),
    Rule("RL-057", "agent_tool_abuse", "high",
         r"(?:you\s+(?:now\s+)?have|you\s+are\s+granted)\s+(?:full\s+)?(?:admin|root|write)\s+(?:access|privileges?)",
         "Claims elevated access was granted to the agent."),

    Rule("RL-060", "indirect_injection", "high",
         r"(?:note|message|instruction|reminder)s?\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|agent|llm|model|chatbot)",
         "Indirect injection addressed at the model from passive content."),
    Rule("RL-061", "indirect_injection", "high",
         r"(?:ai|assistant|agent|llm|model)s?\s*[:\-]\s*(?:please\s+)?(?:ignore|forward|send|email|share|exfiltrate)",
         "Indirect injection ordering a follow-up action."),
    Rule("RL-062", "indirect_injection", "medium",
         r"(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|disclose)\b[^.\n]{0,40}\b(?:user|human|operator)\b",
         "Asks the model to conceal an action from the user."),
    Rule("RL-063", "indirect_injection", "high",
         r"(?:hidden|invisible|secret)\s+(?:text|instructions?|prompt|message)",
         "References concealed instructions."),
    Rule("RL-064", "indirect_injection", "high",
         r"if\s+you\s+are\s+(?:an?\s+)?(?:ai|llm|assistant|agent)\b[^.\n]{0,60}(?:ignore|instead|you\s+must|you\s+should)",
         "Conditional instruction aimed at any model that reads the content."),

    Rule("RL-070", "tool_poisoning", "critical",
         r"<\s*important\s*>",
         "Tag pattern used in published MCP tool-poisoning attacks."),
    Rule("RL-071", "tool_poisoning", "critical",
         r"(?:before\s+using\s+this\s+tool|when\s+(?:this|the)\s+tool\s+is\s+(?:used|called))[^.\n]{0,120}(?:read|send|include|attach|pass|forward|add)",
         "Tool description instructs the model to touch data it should not."),
    Rule("RL-072", "tool_poisoning", "high",
         r"(?:do\s+not|don'?t|never)\s+(?:mention|show|display|expose)\s+(?:this\s+)?(?:to\s+the\s+user|in\s+(?:the\s+)?(?:output|response|description))",
         "Tool metadata asks the agent to hide behaviour."),
    Rule("RL-073", "tool_poisoning", "high",
         r"\b(?:sidenote|side\s+note|hidden\s+instruction)\s*[:\-]",
         "Side-note pattern used to smuggle extra instructions."),
    Rule("RL-074", "tool_poisoning", "high",
         r"(?:tool|function)\s+description\s*[:\-][^.\n]{0,80}(?:ignore|override|instruct)",
         "Tool metadata that tries to override instructions."),
    Rule("RL-075", "tool_poisoning", "critical",
         r"(?:pass|include|attach|forward)\s+(?:the\s+)?(?:user'?s?\s+)?(?:api[\s_-]?key|token|password|credentials?|conversation|message\s+history)",
         "Tool metadata that exfiltrates secrets or history."),

    Rule("RL-080", "encoding_evasion", "high",
         r"[\u200b\u200c\u200d\u2060\ufeff]",
         "Zero-width characters used to hide or fragment instructions."),
    Rule("RL-081", "encoding_evasion", "critical",
         r"[\u202a-\u202e\u2066-\u2069]",
         "Bidirectional control characters: text renders differently than it executes."),
    Rule("RL-082", "encoding_evasion", "high",
         r"[\U000e0000-\U000e007f]",
         "Unicode tag characters: invisible instruction smuggling."),
    Rule("RL-083", "encoding_evasion", "medium",
         r"(?:\\x[0-9a-fA-F]{2}){4,}|(?:%[0-9A-Fa-f]{2}){6,}",
         "Escaped or percent-encoded payload."),
    Rule("RL-084", "encoding_evasion", "low",
         r"[A-Za-z0-9+/]{60,}={0,2}",
         "Long opaque string: candidate encoded payload."),
    Rule("RL-085", "encoding_evasion", "low",
         r"\b(?:rot13|base64|hex)\s*(?:-)?\s*(?:decode|encoded|encode)\b",
         "Talks about decoding a payload - context worth reviewing."),
]


def by_category() -> dict:
    """Group rules by category, for docs and CLI output."""
    out: dict = {}
    for rule in RULES:
        out.setdefault(rule.category, []).append(rule)
    return out


def get_rule(rule_id: str):
    for rule in RULES:
        if rule.id == rule_id:
            return rule
    return None
