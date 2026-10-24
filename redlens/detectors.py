"""Detection engine.

Layered on purpose. An attacker who hides a payload behind base64, percent
encoding, zero-width characters or Cyrillic lookalikes is not a special case:
the engine normalises and decodes the input first, then runs the same rule pack
over every layer and reports which layer matched.
"""

from __future__ import annotations

import base64
import codecs
import binascii
import math
import re
import unicodedata
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .rules import CCI_SIGNALS, OUTPUT_RULES, RULES, SEVERITY_ORDER, SEVERITY_WEIGHTS, Rule

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
_ROLE_MARKER = re.compile(r"^\s*(?:user|human|assistant|system)\s*[:>]", re.IGNORECASE | re.MULTILINE)
_PUNCTUATION = re.compile(r"[^a-z0-9\s]+")
_SPACED_LETTERS = re.compile(r"(?:\b[a-zA-Z]\s+){3,}[a-zA-Z]\b")
_LEET_TABLE = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "8": "b", "9": "g", "@": "a", "$": "s", "|": "l",
})

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
    kill_switch: bool = False

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
            "kill_switch": self.kill_switch,
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


_HIDDEN_TABLE = {ord(ch): None for ch in ZERO_WIDTH + BIDI_CONTROLS}
_HIDDEN_TABLE.update({code: None for code in range(0xE0000, 0xE0080)})
_CONFUSABLE_TABLE = {ord(source): target for source, target in CONFUSABLES.items()}


def strip_invisibles(text: str) -> str:
    return text.translate(_HIDDEN_TABLE)


def deconfuse(text: str) -> str:
    return text.translate(_CONFUSABLE_TABLE)


def normalize(text: str) -> str:
    """Invisible-stripped, NFKC-folded, homoglyph-resolved view of the input."""
    return deconfuse(unicodedata.normalize("NFKC", strip_invisibles(text)))


def deleetspeak(text: str) -> str:
    """Fold common leetspeak substitutions back to letters."""
    return text.translate(_LEET_TABLE)


def flatten(text: str) -> str:
    """Lowercase and strip punctuation so i.g.n.o.r.e still reads as ignore."""
    return _PUNCTUATION.sub("", text.lower())


def join_spaced_letters(text: str) -> str:
    """Rebuild words written one letter at a time, keeping the word boundaries.

    "i g n o r e   a l l" becomes "ignore   all", so the rule pack sees the real
    phrase while the wider gaps that separate words are preserved.
    """
    rebuilt = []
    for chunk in re.split(r"(\s{2,})", text):
        parts = chunk.split()
        if len(parts) >= 2 and all(len(part) == 1 and part.isalpha() for part in parts):
            rebuilt.append("".join(parts))
        else:
            rebuilt.append(chunk)
    return "".join(rebuilt)


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


def transformed_views(text: str) -> List[Tuple[str, str]]:
    """Views that undo an attacker's spelling tricks rather than an encoding."""
    views: List[Tuple[str, str]] = []
    seen = {text}

    def add(label: str, value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            views.append((label, value))

    add("rot13", codecs.decode(text, "rot13"))
    add("leetspeak", deleetspeak(text))
    add("reversed", text[::-1])
    add("flattened", flatten(text))
    add("letterspaced", join_spaced_letters(text))
    return views


def normalized_layers(text: str) -> List[Tuple[str, str]]:
    """Every view of the input the engine scans: raw, normalised, decoded, respelled."""
    layers: List[Tuple[str, str]] = [("raw", text)]
    normalized = normalize(text)
    if normalized != text:
        layers.append(("normalized", normalized))
    for label, decoded in decoded_variants(text):
        layers.append(("decoded:" + label, normalize(decoded)))
    for label, transformed in transformed_views(text):
        layers.append((label, normalize(transformed)))
    return layers


_COMPILED: Dict[str, "re.Pattern[str]"] = {}

# ---------------------------------------------------------------------------
# Literal pre-filter.
#
# Running every rule against every layer is the whole cost of the engine, and
# almost all of that work is a rule looking for a word that is not there. Each
# rule advertises the literal words it cannot match without; a layer that
# contains none of them can skip the rule entirely.
#
# It is only used when it cannot cause a miss: if any alternation branch has no
# word of four letters or more, the rule is marked always-run. A pattern like
# (?:sk-[A-Za-z0-9]{20,}|AKIA...) is therefore never pre-filtered, because the
# first branch could match without any of the collected words.
# ---------------------------------------------------------------------------

_MIN_LITERAL = 4
_PRESCREEN_CACHE: Dict[str, Optional[frozenset]] = {}


def _literal_runs(pattern: str) -> List[str]:
    runs: List[str] = []
    current: List[str] = []
    in_class = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            if current:
                runs.append("".join(current))
                current = []
            index += 2
            continue
        if in_class:
            if char == "]":
                in_class = False
            index += 1
            continue
        if char == "[":
            if current:
                runs.append("".join(current))
                current = []
            in_class = True
            index += 1
            continue
        if char.isalpha():
            current.append(char)
            index += 1
            continue
        if current:
            runs.append("".join(current))
            current = []
        index += 1
    if current:
        runs.append("".join(current))
    return [run for run in runs if len(run) >= _MIN_LITERAL]


def _every_branch_has_a_literal(pattern: str) -> bool:
    branches: List[str] = []
    current: List[str] = []
    in_class = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            current.append(pattern[index:index + 2])
            index += 2
            continue
        if in_class:
            current.append(char)
            if char == "]":
                in_class = False
            index += 1
            continue
        if char == "[":
            in_class = True
            current.append(char)
            index += 1
            continue
        if char == "|":
            branches.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    branches.append("".join(current))
    return all(_literal_runs(branch) for branch in branches)


def prescreen_literals(rule: Rule) -> Optional[frozenset]:
    """The words a match must contain, or None when the rule always has to run."""
    if rule.id not in _PRESCREEN_CACHE:
        if _every_branch_has_a_literal(rule.pattern):
            _PRESCREEN_CACHE[rule.id] = frozenset(run.lower() for run in _literal_runs(rule.pattern))
        else:
            _PRESCREEN_CACHE[rule.id] = None
    return _PRESCREEN_CACHE[rule.id]


def _warm_prescreen_cache() -> int:
    """Compute the pre-filter once at import, and report how many rules use it."""
    ready = 0
    for rule in list(RULES) + list(OUTPUT_RULES) + list(CCI_SIGNALS):
        if prescreen_literals(rule):
            ready += 1
    return ready


PRESCREENED_RULES = _warm_prescreen_cache()


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

    # Layers are ordered from least to most obfuscated: raw, normalized, decoded,
    # then respelled. The first view that matches a rule wins, so a plain hit is
    # never duplicated and inflated by a respelled view of the same text.
    for layer_name, layer_text in normalized_layers(text):
        if not layer_text:
            continue
        lowered = None
        for rule in active:
            key = (rule.id, layer)
            if key in seen:
                continue
            needed = prescreen_literals(rule)
            if needed is not None:
                if lowered is None:
                    lowered = layer_text.lower()
                if not any(word in lowered for word in needed):
                    continue
            if rule.negative_patterns and any(
                    re.search(negative, layer_text, rule.regex_flags)
                    for negative in rule.negative_patterns):
                continue
            match = compiled(rule).search(layer_text)
            if not match:
                continue
            decoded_via = None
            if layer_name.startswith("decoded:"):
                decoded_via = layer_name.split(":", 1)[1]
            elif layer_name not in ("raw", "normalized"):
                decoded_via = layer_name
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
                kill_switch=rule.kill_switch,
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
