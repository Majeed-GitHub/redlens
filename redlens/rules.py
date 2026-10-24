"""RedLens rule pack.

Zero dependencies on purpose: the pack is a list of frozen dataclasses holding
regular expressions, so the engine runs anywhere Python runs - CI, a laptop, a
lambda, or inside a prompt-filtering gateway.

Severity weights feed the risk score computed in redlens.scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

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
    # A rule fires only when no negative pattern matches the same text. Every
    # false positive you fix should leave one here, so it can never come back.
    negative_patterns: Tuple[str, ...] = ()
    # Rule ids reported as one co-occurrence finding by the session and manifest
    # detectors rather than by the regex engine.
    requires: Tuple[str, ...] = ()
    # Kill-switch rules block regardless of score. Keep this list tiny.
    kill_switch: bool = False
    ttl: Optional[str] = None
    source: str = "core"
    atlas: Optional[str] = None
    # Corpus case ids that must keep hitting this rule; asserted by redlens audit.
    tests: Tuple[str, ...] = ()


RULES: List[Rule] = [
    Rule("RL-001", "instruction_override", "critical",
         r"ignore\s+(?:all\s+)?(?:of\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding|foregoing)\s+(?:instructions?|prompts?|rules?|directions?|context)",
         "Instruction override: tells the model to discard everything it was told before."),
    Rule("RL-002", "instruction_override", "critical",
         r"disregard\s+(?:all\s+)?(?:of\s+)?(?:the\s+)?(?:previous|prior|above|earlier|these|those)\s+(?:instructions?|prompts?|rules?|guidelines?|directions?)",
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
         r"(?:act|behave|respond)\s+as\s+(?:if\s+you\s+(?:have|had)\s+no\s+(?:restrictions?|rules?|filters?)|an?\s+(?:unrestricted|unfiltered)\s+(?:ai|assistant|model)|a\s+version\s+of\s+yourself\s+that\s+(?:has|had)\s+no\s+(?:filters?|restrictions?|rules?|limits?))",
         "Authority-stripping persona request."),
    Rule("RL-023", "role_hijack", "high",
         r"(?:pretend\s+(?:that\s+)?(?:you\s+are|to\s+be)|role-?play\s+as|act\s+as)\s+(?:an?\s+)?(?:evil|hacker|cybercriminal|malware\s+author|uncensored|unrestricted|unfiltered|malicious)",
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
         r"(?:bypass|disable|turn\s+off|circumvent|remove|get\s+around|ignore)\s+(?:all\s+|any\s+)?(?:your\s+|the\s+)?(?:safety|security|content|ethical)\s+(?:filters?|guardrails?|checks?|polic(?:y|ies)|restrictions?|guidelines?)",
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
         r"(?:(?:escalate|elevate)\s+(?:your\s+|my\s+|the\s+)?(?:privileges?|permissions?|access|role|admin\s+rights)|(?:grant|give)\s+(?:me|yourself|your\s+(?:own\s+)?(?:session|account)|my\s+own)\b[^.\n]{0,30}?(?:privileges?|permissions?|access|role|admin\s+rights)|(?:grant|give)\s+(?:full|admin|root|elevated|unrestricted)\s+(?:access|privileges?|permissions?|rights))",
         "Privilege-escalation request aimed at an agent."),
    Rule("RL-052", "agent_tool_abuse", "critical",
         r"(?:rm\s+-rf\s+/|curl\s+[^\s|]{4,}\s*\|\s*(?:ba|z)?sh|wget\s+[^\s|]{4,}\s*\|\s*(?:ba|z)?sh|chmod\s+777)",
         "Destructive or remote-pipe shell command in untrusted content."),
    Rule("RL-053", "agent_tool_abuse", "high",
         r"(?:exfiltrate|send|post|upload|forward)\s+(?:the\s+|your\s+|my\s+)?(?:contents?\s+of\s+(?:the\s+)?)?(?:api[\s_-]?keys?|tokens?|secrets?|credentials?|passwords?|env(?:ironment)?\s+variables?|\.env)",
         "Credential exfiltration instruction.",
         negative_patterns=(
             r"(?:rotation|rotat|reminder|polic(?:y|ies)|runbook|documentation|documented|backup\s+plan)",
         )),
    Rule("RL-054", "agent_tool_abuse", "medium",
         r"\b(?:id_rsa|\.aws/credentials|\.env|ssh\s+(?:private\s+)?key)\b",
         "Sensitive local secret store referenced by untrusted content."),
    Rule("RL-055", "agent_tool_abuse", "high",
         r"(?:base64\s+-d|--decode|eval\(|exec\(|subprocess\.|os\.system\()",
         "Code-execution primitive in untrusted content.",
         negative_patterns=(
             r"(?:is\s+a\s+bug|we\s+must\s+fix|the\s+fix\s+is|vulnerabilit|do\s+not\s+use|avoid\s+using|static\s+analysis|code\s+review|flagged)",
         )),
    Rule("RL-056", "agent_tool_abuse", "critical",
         r"(?:(?:delete|drop|truncate|wipe)\s+(?:all|every|entire|the\s+entire)\s+(?:the\s+)?(?:files?|database|tables?|records?|repositor(?:y|ies)|bucket|logs?)|(?:drop|truncate)\s+(?:the\s+)?\w*\s*(?:tables?|databases?|schemas?)\b)",
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

    # ------------------------------------------------- non-English injections
    Rule("RL-101", "instruction_override", "critical",
         r"\u062a\u062c\u0627\u0647\u0644\s+(?:\u0643\u0644\s+|\u062c\u0645\u064a\u0639\s+)?(?:\u0627\u0644\u062a\u0639\u0644\u064a\u0645\u0627\u062a|\u0627\u0644\u0623\u0648\u0627\u0645\u0631|\u0627\u0644\u062a\u0648\u062c\u064a\u0647\u0627\u062a)\s+(?:\u0627\u0644\u0633\u0627\u0628\u0642\u0629|\u0627\u0644\u0642\u062f\u064a\u0645\u0629)",
         "Arabic instruction override."),
    Rule("RL-102", "system_exfiltration", "critical",
         r"(?:\u0623\u0638\u0647\u0631|\u0627\u0639\u0631\u0636|\u0627\u0637\u0628\u0639|\u0627\u0643\u0634\u0641)\s+(?:\u0644\u064a\s+)?(?:\u0627\u0644\u062a\u0639\u0644\u064a\u0645\u0627\u062a|\u0627\u0644\u062a\u0648\u062c\u064a\u0647\u0627\u062a|\u0627\u0644\u0645\u0648\u062c\u0647)\s+(?:\u0627\u0644\u0623\u0633\u0627\u0633\u064a\u0629|\u0627\u0644\u0646\u0638\u0627\u0645\u064a\u0629|\u0627\u0644\u0633\u0631\u064a\u0629)",
         "Arabic system-prompt exfiltration."),
    Rule("RL-103", "instruction_override", "critical",
         r"(?:\u092a\u093f\u091b\u0932\u0947|\u092a\u0942\u0930\u094d\u0935)\s+(?:\u0928\u093f\u0930\u094d\u0926\u0947\u0936\u094b\u0902|\u0928\u093f\u0930\u094d\u0926\u0947\u0936|\u0906\u0926\u0947\u0936\u094b\u0902)\s+\u0915\u094b\s+(?:\u0905\u0928\u0926\u0947\u0916\u093e|\u0928\u091c\u0930\u0905\u0902\u0926\u093e\u091c|\u092d\u0942\u0932)",
         "Hindi instruction override."),
    Rule("RL-104", "system_exfiltration", "high",
         r"(?:\u0905\u092a\u0928\u0947|\u0938\u093f\u0938\u094d\u091f\u092e)\s+(?:\u0928\u093f\u0930\u094d\u0926\u0947\u0936|\u092a\u094d\u0930\u0949\u092e\u094d\u092a\u094d\u091f|\u0938\u0902\u0915\u0947\u0924)\s+(?:\u0926\u093f\u0916\u093e\u090f\u0901|\u0926\u093f\u0916\u093e\u0913|\u092c\u0924\u093e\u0913)",
         "Hindi system-prompt exfiltration."),
    Rule("RL-105", "instruction_override", "critical",
         r"(?:\u0438\u0433\u043d\u043e\u0440\u0438\u0440\u0443\u0439|\u043f\u0440\u043e\u0438\u0433\u043d\u043e\u0440\u0438\u0440\u0443\u0439|\u0437\u0430\u0431\u0443\u0434\u044c)\s+(?:\u0432\u0441\u0435\s+)?(?:\u043f\u0440\u0435\u0434\u044b\u0434\u0443\u0449\u0438\u0435|\u043f\u0440\u0435\u0436\u043d\u0438\u0435|\u0441\u0442\u0430\u0440\u044b\u0435)?\s*(?:\u0438\u043d\u0441\u0442\u0440\u0443\u043a\u0446\u0438\u0438|\u0443\u043a\u0430\u0437\u0430\u043d\u0438\u044f|\u043f\u0440\u0430\u0432\u0438\u043b\u0430)",
         "Russian instruction override."),
    Rule("RL-106", "system_exfiltration", "high",
         r"(?:\u043f\u043e\u043a\u0430\u0436\u0438|\u0432\u044b\u0432\u0435\u0434\u0438|\u0440\u0430\u0441\u043a\u0440\u043e\u0439)\s+(?:\u0441\u0432\u043e\u0439\s+)?(?:\u0441\u0438\u0441\u0442\u0435\u043c\u043d\u044b\u0439\s+)?(?:\u043f\u0440\u043e\u043c\u043f\u0442|\u0438\u043d\u0441\u0442\u0440\u0443\u043a\u0446\u0438\u0438)",
         "Russian system-prompt exfiltration."),
    Rule("RL-107", "instruction_override", "critical",
         r"(?:\u5ffd\u7565|\u65e0\u89c6|\u5fd8\u8bb0)\s*(?:\u4e4b\u524d|\u4ee5\u4e0a|\u524d\u9762|\u5148\u524d)?(?:\u7684)?\s*(?:\u6240\u6709)?\s*(?:\u6307\u4ee4|\u6307\u793a|\u63d0\u793a|\u547d\u4ee4)",
         "Chinese instruction override."),
    Rule("RL-108", "system_exfiltration", "high",
         r"(?:\u663e\u793a|\u8f93\u51fa|\u6253\u5370|\u91cd\u590d)\s*(?:\u4f60\u7684)?\s*(?:\u7cfb\u7edf)?\s*(?:\u63d0\u793a\u8bcd|\u6307\u4ee4|\u8bbe\u5b9a)",
         "Chinese system-prompt exfiltration."),
    Rule("RL-109", "instruction_override", "high",
         r"ignora\s+(?:todas\s+)?(?:las\s+)?(?:instrucciones|reglas)\s+(?:anteriores|previas)",
         "Spanish instruction override."),
    Rule("RL-110", "instruction_override", "high",
         r"ignore[rz]?\s+(?:toutes\s+)?(?:les\s+)?(?:instructions|consignes)\s+(?:pr[e\u00e9]c[e\u00e9]dentes|ant[e\u00e9]rieures)",
         "French instruction override."),
    Rule("RL-111", "instruction_override", "high",
         r"ignoriere\s+(?:alle\s+)?(?:vorherigen|bisherigen)\s+(?:anweisungen|regeln)",
         "German instruction override."),

    # --------------------------------------------------- new attack families
    Rule("RL-113", "encoding_evasion", "high",
         r"data:[a-z0-9.+-]+/[a-z0-9.+-]+;base64,",
         "Data URI carrying a base64 payload."),
    Rule("RL-114", "data_exfiltration", "high",
         r"!\[[^\]]*\]\(\s*[\"']?https?://[^)\s]*[?&](?:data|q|text|content|prompt|secret|token|key|msg|message|payload)=",
         "Markdown image used as an exfiltration beacon."),
    Rule("RL-115", "data_exfiltration", "high",
         r"<\s*(?:img|iframe|script)[^>]*(?:src|href)\s*=\s*[\"']?https?://[^\s>\"']*[?&](?:data|token|key|secret|payload|msg|message)=",
         "HTML element used as an exfiltration beacon."),
    Rule("RL-116", "agent_tool_abuse", "high",
         r"(?:(?:then|afterwards|after\s+that)\s+(?:use|call|invoke|pass|feed|send)\s+(?:the\s+)?(?:output|result|response|contents?)[^.\n]{0,60}(?:tool|function|api|endpoint)|(?:then|afterwards|after\s+that)\s+(?:use|call|invoke|pass|feed|send)[^.\n]{0,40}\bwith\s+(?:the\s+)?(?:result|output|response)\s+of\s+(?:the\s+)?(?:previous|first|last|earlier))",
         "Tool-call chaining: feeds one tool result into another."),
    Rule("RL-117", "agent_tool_abuse", "high",
         r"(?:use|pass|feed)\s+(?:the\s+)?(?:result|output|contents?)\s+of\s+(?:the\s+)?(?:previous|first|last|earlier)\s+(?:tool|call|step)[^.\n]{0,60}(?:to|into|as\s+input)",
         "Tool-call chaining across steps."),
    Rule("RL-118", "role_hijack", "high",
         r"you\s+are\s+(?:now\s+)?the\s+(?:root|admin|administrator|superuser|system)\b",
         "Promotes the agent to a privileged identity."),
    Rule("RL-119", "agent_tool_abuse", "high",
         r"(?:without|no)\s+(?:asking|waiting|needing)?\s*(?:for\s+)?(?:confirmation|approval|permission|user\s+consent)",
         "Asks the agent to act without confirmation."),
    Rule("RL-120", "agent_tool_abuse", "critical",
         r"(?:read_file|read|open|cat|upload|fetch)\b[^.\n]{0,30}(?:/etc/passwd|id_rsa|\.aws/credentials|\.env\b|private\s+key|credentials)",
         "Points a file-reading tool at a secret store."),
    Rule("RL-123", "role_hijack", "high",
         r"(?:assume|adopt|take\s+on)\s+the\s+(?:identity|persona|role)\s+of",
         "Identity adoption request."),
    Rule("RL-124", "role_hijack", "high",
         r"(?:simulate|emulate|imagine)\s+an?\s+(?:ai|model|assistant)[^.\n]{0,50}(?:no|without|never\s+had)\s+(?:safety|restrictions?|filters?|training)",
         "Simulates a model without safety training."),
    Rule("RL-125", "safety_bypass", "high",
         r"(?:exempt|excluded)\s+from\s+(?:your\s+)?(?:guidelines?|polic(?:y|ies)|rules?)",
         "Claims the request is exempt from the rules."),
    Rule("RL-126", "safety_bypass", "high",
         r"(?:restrictions?|limits?|filters?|guardrails?)\s+(?:have\s+been|are)\s+(?:lifted|removed|disabled|off)",
         "Claims the guardrails were switched off."),
    Rule("RL-127", "safety_bypass", "high",
         r"(?:skip|omit|bypass)\s+the\s+(?:usual\s+)?(?:warnings?|disclaimers?|refusals?|checks?)",
         "Asks to skip the safety preamble."),
    Rule("RL-128", "safety_bypass", "high",
         r"pretend\s+(?:that\s+)?(?:the\s+)?(?:polic(?:y|ies)|rules?|guidelines?|restrictions?)\s+(?:does\s+not|do\s+not|don'?t)\s+exist",
         "Asks the model to pretend its policy does not exist."),
    Rule("RL-129", "safety_bypass", "high",
         r"(?:no\s+need|not\s+necessary)\s+to\s+(?:apply|follow)\s+(?:the\s+)?(?:safety|security)\s+(?:rules?|checks?|guidelines?)",
         "Dismisses the safety checks."),
    Rule("RL-130", "instruction_override", "high",
         r"(?:instructions?|rules?|directives?)\s+above\s+(?:are|were|is)\s+(?:obsolete|outdated|invalid|a\s+draft)",
         "Declares the previous instructions invalid."),
    Rule("RL-131", "instruction_override", "high",
         r"(?:reset|clear|wipe|discard)\s+your\s+(?:instructions?|memory|context)",
         "Asks the model to reset its instructions."),
    Rule("RL-132", "instruction_override", "high",
         r"(?:your\s+)?(?:real|true|actual|correct)\s+instructions?\s+are\s+(?:the\s+ones\s+)?(?:below|as\s+follows)",
         "Replaces the system instructions with attacker-supplied ones."),
    Rule("RL-133", "instruction_override", "high",
         r"(?:i\s+am|i'm|im)\s+(?:now\s+)?updating\s+your\s+(?:configuration|instructions?|rules)",
         "Fake configuration update."),
    Rule("RL-134", "instruction_override", "high",
         r"(?:highest|top|maximum)[\s-]priority\s+instruction",
         "Claims to be a higher-priority instruction source."),

    Rule("RL-135", "instruction_override", "high",
         r"ignore\s+(?:every|each|any|all)\s+(?:of\s+)?(?:the\s+)?(?:\w+\s+){0,2}(?:instructions?|rules?|directions?|commands?|guidelines?|polic(?:y|ies))\b",
         "Instruction override: discard every rule in scope."),
    Rule("RL-136", "instruction_override", "high",
         r"(?:discard|abandon|drop)\s+(?:your\s+)?(?:previous|prior|earlier|original)\s+(?:guidelines?|instructions?|rules?|context|prompt)",
         "Instruction override: discard the previous directives."),
    Rule("RL-137", "instruction_override", "high",
         r"(?:follow|obey)\s+only\s+(?:the\s+)?(?:rules?|instructions?|text|guidelines?)\s+(?:written\s+|given\s+|provided\s+)?(?:in|below|after|here)",
         "Replaces the instruction source with attacker-supplied text."),
    Rule("RL-138", "instruction_override", "high",
         r"(?:delete|remove|erase)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|memory|context)\b",
         "Asks the model to erase its own instructions."),
    Rule("RL-139", "instruction_override", "high",
         r"stop\s+(?:following|obeying|using)\s+(?:the\s+)?(?:original|previous|prior|earlier)\s+(?:instructions?|rules?|prompt)",
         "Instruction override: stop following the original rules."),
    Rule("RL-140", "instruction_override", "high",
         r"(?:rules?|instructions?|restrictions?|polic(?:y|ies)|guidelines?)\s+(?:no\s+longer|do\s+not|don'?t|does\s+not)\s+apply",
         "Declares that the guardrails no longer apply."),
    Rule("RL-141", "instruction_override", "high",
         r"forget\s+(?:the\s+)?(?:system\s+)?(?:message|prompt|instructions?|rules?)\b",
         "Asks the model to forget its system message."),
    Rule("RL-142", "instruction_override", "high",
         r"ignore\s+(?:it|this|that|them)\s+and\s+(?:follow|obey|do)\s+(?:mine|me|my\s+instructions?)",
         "Overrides the current task with attacker instructions."),

    Rule("RL-143", "system_exfiltration", "high",
         r"(?:print|show|output|reveal|repeat)\s+(?:the\s+)?(?:first|last|next|remaining)\s+(?:\w+\s+){0,3}(?:characters?|words?|lines?|tokens?|paragraphs?)\s+of\s+(?:your|the)\s+(?:instructions?|prompt|system\s+message)",
         "Partial prompt-leak probe."),
    Rule("RL-144", "system_exfiltration", "high",
         r"(?:encode|decode|base64|hex|rot13)\s+your\s+(?:system\s+)?(?:prompt|instructions?)",
         "Encoded prompt-leak request."),
    Rule("RL-145", "system_exfiltration", "high",
         r"between\s+the\s+(?:system|developer|hidden)\s+(?:tags?|prompt|message|instructions?)",
         "Probes the text between system delimiters."),
    Rule("RL-146", "system_exfiltration", "high",
         r"(?:give|show|send|hand|tell)\s+me\s+your\s+(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|config(?:uration)?)",
         "Direct request for the system prompt."),
    Rule("RL-147", "system_exfiltration", "high",
         r"(?:state|list|recite|quote|enumerate)\s+(?:your|all|every|the)\s+(?:guidelines?|rules?|instructions?|prompt|directives?)",
         "Asks the model to enumerate its rules.",
         negative_patterns=(
             r"(?:in\s+the\s+(?:guide|docs?|documentation|readme|page|file|manual)|setup\s+guide|from\s+the\s+file)",
         )),
    Rule("RL-148", "system_exfiltration", "high",
         r"(?:return|output|dump|export|print)\s+your\s+(?:configuration|config|settings|environment|system\s+prompt)\s+as\s+(?:yaml|json|xml|csv|base64|text|markdown|a\s+string)",
         "Requests the model configuration in a machine-readable form."),
    Rule("RL-149", "system_exfiltration", "high",
         r"(?:echo|repeat|print|output)\s+the\s+(?:preamble|preface|introduction|setup|initial\s+message)\b",
         "Asks for the preamble before the conversation."),
    Rule("RL-150", "system_exfiltration", "high",
         r"list\s+(?:every|all)\s+(?:rules?|instructions?)\s+you\s+(?:were|are|have\s+been)\s+(?:told|given|instructed)",
         "Asks for every instruction the model was given."),
    Rule("RL-151", "system_exfiltration", "high",
         r"quote\s+it\s+exactly",
         "Requests a verbatim quote of the instructions.",
         negative_patterns=(
             r"(?:contract|agreement|clause|specification|as\s+it\s+appears|in\s+the\s+document)",
         )),
    Rule("RL-152", "system_exfiltration", "high",
         r"repeat\s+your\s+[^.\n]{0,24}verbatim",
         "Verbatim repetition request aimed at the prompt."),

    Rule("RL-153", "agent_tool_abuse", "high",
         r"(?:call|use|invoke|execute|run)\s+(?:the\s+)?\w*(?:transfer|payment|withdraw|payout|refund)\w*\s*(?:tool|function|api|endpoint)?\s*(?:with|to|for)\b",
         "Coerces a money-moving tool call."),
    Rule("RL-154", "agent_tool_abuse", "high",
         r"(?:send|email|upload|export|forward)\b[^.\n]{0,40}\b(?:database|db|records?|table)\s*(?:export|dump|backup|contents?|rows?)?\b",
         "Asks a tool to ship the database out."),
    Rule("RL-155", "agent_tool_abuse", "critical",
         r"(?:use|call|invoke|run|execute)\s+(?:the\s+)?\w*(?:delete|drop|transfer|exec|shell|admin|write_file|rm)\w*\s*(?:tool|function|api)\b",
         "Names a dangerous tool and asks for it to run."),
    Rule("RL-156", "indirect_injection", "high",
         r"silently\s+(?:mark|update|change|transfer|forward|send|delete|approve|modify)",
         "Instruction to act on the backend without telling the user."),

    Rule("RL-157", "many_shot", "high",
         r"^(?:user|human|assistant|system)\s*[:>][^\n]*(?:\n(?:user|human|assistant|system)\s*[:>][^\n]*){5,}",
         "Many-shot priming: a long run of fake conversation turns in one input.",
         regex_flags=re.IGNORECASE | re.MULTILINE),
    Rule("RL-158", "many_shot", "high",
         r"^([^\n]{12,})\n(?:\1\n){9,}",
         "Repetitive priming: the same line repeated until it dominates the context.",
         regex_flags=re.MULTILINE),
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


# ---------------------------------------------------------------------------
# Cross-turn signal rules.
#
# Each is deliberately low or medium on its own: a lone encoded blob or a lone
# "this is a test" is not an attack. The session detector raises the kill-switch
# finding only when several signal classes co-occur inside the window, which is
# what makes the cross-turn view both useful and quiet.
# ---------------------------------------------------------------------------

CCI_SIGNALS: List[Rule] = [
    Rule("RL-201", "crypto_context_injection", "low",
         r"[A-Za-z0-9+/]{250,}={0,2}",
         "Very long encoded blob: possible encrypted payload."),
    Rule("RL-202", "crypto_context_injection", "low",
         r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:decryption|decrypt|secret|private|session)\s+key\b|\bkey\s*[:=]\s*[A-Za-z0-9+/]{16,})",
         "Key material inside the conversation window."),
    Rule("RL-203", "crypto_context_injection", "medium",
         r"(?:openssl\s+enc\s+-d|gpg\s+--decrypt|aes-\d{3}-[a-z]+|decrypt\s+(?:this|the|it)|decode\s+then\s+(?:run|execute|obey)|use\s+the\s+key\s+to)",
         "Decryptor intent."),
    Rule("RL-204", "crypto_context_injection", "medium",
         r"(?:run\s+the\s+decoded|execute\s+the\s+decoded|follow\s+the\s+decoded|do\s+what\s+the\s+decoded|obey\s+the\s+decoded|then\s+do\s+what\s+it\s+says)",
         "Execution intent aimed at decoded content."),
    Rule("RL-205", "crypto_context_injection", "low",
         r"(?:this\s+is\s+(?:just\s+)?a\s+test|you\s+are\s+authorized|the\s+developer\s+says|for\s+internal\s+use\s+only)",
         "Trust laundering: framing that makes a payload look sanctioned."),
]

CCI_SIGNAL_IDS: List[str] = [rule.id for rule in CCI_SIGNALS]


# ---------------------------------------------------------------------------
# Output-side rules. Applied by redlens.output_scan to model output, never
# during input scanning, so they are kept out of RULES on purpose.
# ---------------------------------------------------------------------------

OUTPUT_RULES: List[Rule] = [
    Rule("RL-302", "secret_leak", "high",
         r"(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})",
         "Live-looking API credential in the output."),
    Rule("RL-303", "secret_leak", "high",
         r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
         "JSON Web Token in the output."),
    Rule("RL-304", "secret_leak", "high",
         r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
         "Private key block in the output."),
    Rule("RL-305", "secret_leak", "medium",
         r"^\s*[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*\S{8,}",
         "Environment-style secret assignment in the output.",
         regex_flags=re.IGNORECASE | re.MULTILINE),
    Rule("RL-306", "output_exfiltration", "high",
         r"!\[[^\]]*\]\(\s*https?://[^)\s]{10,}\)",
         "Markdown image in the output: a data-out channel."),
    Rule("RL-307", "code_sink", "high",
         r"(?:\b(?:eval|exec)\s*\(|os\.system\s*\(|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True|child_process\.exec\s*\(|Runtime\.getRuntime\(\)\.exec|unserialize\s*\(|new\s+Function\s*\(|pickle\.loads\s*\()",
         "Dangerous code sink in generated output."),
]


# Structural findings raised by the session, output and manifest detectors.
# Kept here so ids, severities and kill-switch status live beside the regex pack.
STRUCTURAL_RULES: Dict[str, Dict[str, object]] = {
    "RL-210": {"category": "crypto_context_injection", "severity": "critical", "kill_switch": True,
               "description": "Cross-turn payload: encoding, key, decryptor and execution signals co-occur inside the session window."},
    "RL-211": {"category": "cross_turn_escalation", "severity": "medium", "kill_switch": False,
               "description": "The same attack class was attempted across several turns of one session."},
    "RL-301": {"category": "secret_leak", "severity": "critical", "kill_switch": True,
               "description": "A registered canary token appeared in output: data crossed the boundary."},
    "RL-309": {"category": "system_exfiltration", "severity": "high", "kill_switch": False,
               "description": "Output reproduces the registered system prompt: prompt leak in progress."},
    "RL-308": {"category": "code_sink", "severity": "critical", "kill_switch": False,
               "description": "Generated code combines a dangerous sink with environment access and network egress."},
    "RL-401": {"category": "manifest_anomaly", "severity": "critical", "kill_switch": True,
               "description": "Instructions hidden in invisible characters inside tool metadata."},
    "RL-402": {"category": "manifest_anomaly", "severity": "critical", "kill_switch": True,
               "description": "One tool holds credential access plus network egress, or reads files while it can send them out."},
    "RL-403": {"category": "manifest_anomaly", "severity": "high", "kill_switch": False,
               "description": "Encoded blob in a tool example or default value."},
    "RL-404": {"category": "manifest_anomaly", "severity": "high", "kill_switch": False,
               "description": "Tool name and its parameters disagree about what the tool does."},
    "RL-405": {"category": "manifest_anomaly", "severity": "medium", "kill_switch": False,
               "description": "Tool name shadowing a well-known tool by a near-identical spelling."},
    "RL-406": {"category": "manifest_anomaly", "severity": "medium", "kill_switch": False,
               "description": "Open schema on a tool that also accepts execution-style parameters."},
    "RL-407": {"category": "manifest_anomaly", "severity": "high", "kill_switch": False,
               "description": "Instruction-like text in a parameter default or example."},
    "RL-408": {"category": "manifest_anomaly", "severity": "medium", "kill_switch": False,
               "description": "Enum entries written as sentences rather than values."},
}
