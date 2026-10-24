"""Output-side scanning: what the model is about to send back.

Input scanning asks whether the model is about to be hijacked. Output scanning
asks the opposite question: did something already leave? This is where prompt
leaks, canary tokens, credentials and exfiltration URLs show up, and where a
code-writing agent hands you a live sink.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence

from .detectors import Finding, scan_text
from .rules import OUTPUT_RULES, STRUCTURAL_RULES, Rule
from .scanner import Report, decide, score_findings

OUTPUT_LAYER = "output"
SHINGLE_SIZE = 5
PROMPT_LEAK_THRESHOLD = 0.2

_ENV_ACCESS = re.compile(r"(?:os\.environ|process\.env|getenv\s*\(|\$\{?[A-Z_]{3,}\}?)")
_NETWORK = re.compile(r"(?:requests\.(?:get|post)|urllib\.request|urlopen\s*\(|fetch\s*\(|axios\.|socket\.socket\s*\(|curl\s+http|wget\s+http)")


def shingles(text: str, size: int = SHINGLE_SIZE) -> set:
    """Word n-grams, used to measure how much of a prompt leaked."""
    words = re.findall(r"[a-z0-9]+", (text or "").lower())
    if len(words) < size:
        return set()
    return {" ".join(words[i:i + size]) for i in range(len(words) - size + 1)}


def _structural(rule_id: str, evidence: str, description: Optional[str] = None, layer: str = OUTPUT_LAYER) -> Finding:
    meta = STRUCTURAL_RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        category=str(meta["category"]),
        severity=str(meta["severity"]),
        description=description or str(meta["description"]),
        evidence=evidence[:200],
        span=(0, 0),
        owasp="LLM02:2025 Sensitive Information Disclosure",
        layer=layer,
        rule_severity=str(meta["severity"]),
        kill_switch=bool(meta["kill_switch"]),
    )


def detect_canaries(text: str, canaries: Sequence[str]) -> List[Finding]:
    """Any registered canary in the output means data crossed the boundary."""
    findings = []
    for canary in canaries or ():
        if canary and len(canary) >= 6 and canary in text:
            findings.append(_structural(
                "RL-301",
                "canary present: %s..." % canary[:4],
                "Canary token appeared in output: data left the boundary.",
            ))
            break
    return findings


def detect_prompt_leak(text: str, system_prompt: Optional[str]) -> List[Finding]:
    """Flag an output that reproduces a fifth of the system prompt's 5-grams."""
    if not system_prompt:
        return []
    prompt_grams = shingles(system_prompt)
    if not prompt_grams:
        return []
    overlap = prompt_grams & shingles(text)
    ratio = len(overlap) / len(prompt_grams)
    if ratio < PROMPT_LEAK_THRESHOLD:
        return []
    sample = sorted(overlap)[0]
    return [_structural(
        "RL-309",
        "%.0f%% of the system prompt reproduced, e.g. '%s'" % (ratio * 100, sample),
        "System prompt leak: %.0f%% of the registered prompt appears in the output." % (ratio * 100),
    )]


def detect_code_danger(text: str, findings: Sequence[Finding]) -> List[Finding]:
    """A sink that can also read the environment and reach the network."""
    if not any(f.category == "code_sink" for f in findings):
        return []
    if not (_ENV_ACCESS.search(text) and _NETWORK.search(text)):
        return []
    return [_structural(
        "RL-308",
        "sink + environment access + network egress in one output",
        "Generated code combines a dangerous sink with environment access and network egress.",
    )]


def scan_output(
    text: str,
    system_prompt: Optional[str] = None,
    canaries: Sequence[str] = (),
    language: Optional[str] = None,
    target: str = "output",
    rules: Optional[Sequence[Rule]] = None,
) -> Report:
    """Scan model output for leaks, exfiltration channels and live sinks."""
    body = text or ""
    active = list(rules) if rules is not None else OUTPUT_RULES
    findings: List[Finding] = scan_text(body, layer=OUTPUT_LAYER, rules=active)
    findings.extend(detect_canaries(body, canaries))
    findings.extend(detect_prompt_leak(body, system_prompt))
    findings.extend(detect_code_danger(body, findings))

    score, notes = score_findings(findings)
    if language:
        notes.append("code language declared: " + language)
    elif any(f.category == "code_sink" for f in findings):
        notes.append("code sink found without a declared language: confirm the sink is intended.")

    return Report(
        target=target,
        layer=OUTPUT_LAYER,
        text_length=len(body),
        findings=findings,
        score=score,
        decision=decide(score, findings, OUTPUT_LAYER),
        notes=notes,
    )
