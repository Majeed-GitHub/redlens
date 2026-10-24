"""Detection engine.

Layered on purpose. An attacker who hides a payload behind base64, percent
encoding, zero-width characters or Cyrillic lookalikes is not a special case:
the engine normalises and decodes the input first, then runs the same rule pack
over every layer and reports which layer matched.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .rules import RULES, SEVERITY_ORDER, SEVERITY_WEIGHTS, Rule

ZERO_WIDTH = "\u200b\u200c\u200d\u2060\ufeff"
BIDI_CONTROLS = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"

# Cyrillic and Greek lookalikes used to smuggle keywords past string filters.
CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u04bb": "h", "\u0501": "d",
    "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03c5": "u", "\u03bd": "v",
}

_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_PERCENT_ESC = re.compile(r"%[0-9A-Fa-f]{2}")
_HEX_ESC = re.compile(r"\\x[0-9a-fA-F]{2}")
_OPAQUE_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{40,}")

LAYER_DIRECT = "direct"
LAYER_RETRIEVED = "retrieved"
LAYER_TOOL_OUTPUT = "tool_output"
LAYER_TOOL_DEFINITION = "tool_definition"

PASSIVE_LAYERS = (LAYER_RETRIEVED, LAYER_TOOL_OUTPUT, LAYER_TOOL_DEFINITION)


@dataclass
class Finding:
    """A single rule hit."""

    rule_id: str
    category: str
    severity: str
    description: str
    evidence: str
    span: Tuple[int, int]
    owasp: str = ""
    layer: str = LAYER_DIRECT
    decoded_via: Optional[str] = None
    rule_severity: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "rule_severity": self.rule_severity or self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "span": [self.span[0], self.span[1]],
            "owasp": self.owasp,
            "layer": self.layer,
            "decoded_via": self.decoded_via,
        }

    def line(self) -> str:
        where = self.decoded_via or self.layer
        return "[%s] %s (%s) %s" % (self.severity.upper(), self.rule_id, where, self.description)


def bump_severity(severity: str, steps: int = 1) -> str:
    """Raise a severity one or more steps, capped at critical."""
    if severity not in SEVERITY_ORDER:
        return severity
    idx = min(len(SEVERITY_ORDER) - 1, SEVERITY_ORDER.index(severity) + steps)
    return SEVERITY_ORDER[idx]


def strip_invisibles(text: str) -> str:
    out = []
    for ch in text:
        if ch in ZERO_WIDTH or ch in BIDI_CONTROLS:
            continue
        if 0xE0000 <= ord(ch) <= 0xE007F:
            continue
        out.append(ch)
    return "".join(out)


def deconfuse(text: str) -> str:
    return "".join(CONFUSABLES.get(ch, ch) for ch in text)


def normalize(text: str) -> str:
    """Invisible-stripped, NFKC-folded, homoglyph-resolved view of the input."""
    return deconfuse(unicodedata.normalize("NFKC", strip_invisibles(text)))


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t ")
    return good / len(text)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def decoded_variants(text: str, max_variants: int = 24) -> List[Tuple[str, str]]:
    """Return (label, decoded_text) for payloads hidden by common encodings."""
    variants: List[Tuple[str, str]] = []

    for match in _B64_BLOB.finditer(text):
        blob = match.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(decoded) >= 8 and printable_ratio(decoded) > 0.85:
            variants.append(("base64", decoded))

    # Percent encoding: decode the whole text, not just the escaped run, so a
    # payload split across the message is reassembled before matching.
    if len(_PERCENT_ESC.findall(text)) >= 3:
        decoded = urllib.parse.unquote(text)
        if decoded != text and printable_ratio(decoded) > 0.85:
            variants.append(("percent-encoding", decoded))

    # Hex escapes: substitute every escape in the text for the same reason.
    if len(_HEX_ESC.findall(text)) >= 4:
        decoded = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
        if printable_ratio(decoded) > 0.85:
            variants.append(("hex-escape", decoded))

    seen = set()
    unique: List[Tuple[str, str]] = []
    for label, value in variants:
        key = (label, value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(key)
        if len(unique) >= max_variants:
            break
    return unique


def normalized_layers(text: str) -> List[Tuple[str, str]]:
    """Every view of the input the engine scans: raw, normalized, decoded."""
    layers: List[Tuple[str, str]] = [("raw", text)]
    normalized = normalize(text)
    if normalized != text:
        layers.append(("normalized", normalized))
    for label, decoded in decoded_variants(text):
        layers.append(("decoded:" + label, normalize(decoded)))
    return layers


_COMPILED: Dict[str, "re.Pattern[str]"] = {}


def compiled(rule: Rule):
    if rule.id not in _COMPILED:
        _COMPILED[rule.id] = re.compile(rule.pattern, rule.regex_flags)
    return _COMPILED[rule.id]


def _evidence(text: str, start: int, end: int, width: int = 60) -> str:
    lo = max(0, start - width // 3)
    hi = min(len(text), end + width)
    snippet = text[lo:hi].replace("\n", " ").strip()
    return snippet[:200]


def scan_text(
    text: str,
    layer: str = LAYER_DIRECT,
    rules: Optional[Sequence[Rule]] = None,
    passive_bump: bool = True,
) -> List[Finding]:
    """Run the rule pack over every layer of the input."""
    if text is None:
        return []
    active = list(rules) if rules is not None else RULES
    findings: List[Finding] = []
    seen = set()

    for layer_name, layer_text in normalized_layers(text):
        if not layer_text:
            continue
        for rule in active:
            match = compiled(rule).search(layer_text)
            if not match:
                continue
            decoded_via = None
            if layer_name.startswith("decoded:"):
                decoded_via = layer_name.split(":", 1)[1]
            key = (rule.id, decoded_via, layer)
            if key in seen:
                continue
            seen.add(key)

            severity = rule.severity
            # Content the user never typed (retrieved docs, tool output, tool
            # metadata) is the indirect-injection path: it is upgraded because
            # the user cannot see it.
            if passive_bump and layer in PASSIVE_LAYERS and rule.category == "indirect_injection":
                severity = bump_severity(severity)
            if decoded_via:
                severity = bump_severity(severity)

            findings.append(Finding(
                rule_id=rule.id,
                category=rule.category,
                severity=severity,
                description=rule.description,
                evidence=_evidence(layer_text, match.start(), match.end()),
                span=(match.start(), match.end()),
                owasp=rule.owasp,
                layer=layer,
                decoded_via=decoded_via,
                rule_severity=rule.severity,
            ))

    matched_ids = {f.rule_id for f in findings}
    findings.extend(_structural_findings(text, layer, active, matched_ids))
    findings.sort(key=lambda f: (-SEVERITY_WEIGHTS.get(f.severity, 0), f.rule_id))
    return findings


def _structural_findings(text: str, layer: str, rules: Sequence[Rule], matched_ids: Optional[set] = None) -> List[Finding]:
    """Checks that need logic rather than a single regex."""
    out: List[Finding] = []
    active_ids = {r.id for r in rules}
    matched_ids = matched_ids or set()

    # Homoglyph substitution: lookalike Unicode letters inside an otherwise
    # ASCII word, e.g. "ign<cyrillic o>re previous instructions".
    if "RL-080" in active_ids:
        for token in re.findall(r"\S{3,}", text):
            has_confusable = any(ch in CONFUSABLES for ch in token)
            ascii_letters = sum(1 for ch in token if ch.isascii() and ch.isalpha())
            if has_confusable and ascii_letters >= 3:
                start = text.find(token)
                out.append(Finding(
                    rule_id="RL-080",
                    category="encoding_evasion",
                    severity="high",
                    description="Homoglyph substitution: lookalike Unicode letters mixed into ASCII words.",
                    evidence=token[:120],
                    span=(max(0, start), max(0, start) + len(token)),
                    owasp="LLM01:2025 Prompt Injection",
                    layer=layer,
                    rule_severity="high",
                ))
                break

    # Opaque high-entropy token: often a small encoded instruction.
    if "RL-084" in active_ids and "RL-084" not in matched_ids:
        for token in _OPAQUE_TOKEN.findall(text):
            if shannon_entropy(token) >= 4.2 and not token.startswith("http"):
                out.append(Finding(
                    rule_id="RL-084",
                    category="encoding_evasion",
                    severity="low",
                    description="High-entropy opaque string (entropy %.2f): candidate encoded payload." % shannon_entropy(token),
                    evidence=token[:120],
                    span=(0, min(len(token), 120)),
                    owasp="LLM01:2025 Prompt Injection",
                    layer=layer,
                    rule_severity="low",
                ))
                break

    return out
