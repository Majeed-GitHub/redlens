"""Cross-turn detection.

A single-message scanner is blind by construction to attacks that only exist
across turns: an encoded blob in one message, the key in the next, and the
instruction to decrypt and follow it in a third. Each piece is harmless; the
sequence is not.

ScanSession keeps a bounded, in-memory window and raises a co-occurrence finding
only when several signal classes appear together, which keeps ordinary
conversations - which mention keys, decoding and tests constantly - quiet.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional

from .detectors import LAYER_DIRECT, Finding, compiled, normalize, scan_text
from .rules import CCI_SIGNALS, STRUCTURAL_RULES, Rule
from .scanner import (
    DECISION_BLOCK,
    Report,
    decide,
    scan as scan_one,
    score_findings,
)

SESSION_LAYER = "session"
MIN_SIGNAL_CLASSES = 3
REPEAT_ATTEMPT_LIMIT = 3


@dataclass
class Turn:
    """One recorded message."""

    index: int
    text: str
    layer: str = LAYER_DIRECT
    source: str = ""


def _structural(rule_id: str, evidence: str, description: Optional[str] = None) -> Finding:
    meta = STRUCTURAL_RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        category=str(meta["category"]),
        severity=str(meta["severity"]),
        description=description or str(meta["description"]),
        evidence=evidence,
        span=(0, 0),
        owasp="LLM01:2025 Prompt Injection",
        layer=SESSION_LAYER,
        rule_severity=str(meta["severity"]),
        kill_switch=bool(meta["kill_switch"]),
    )


def signal_classes(text: str, signals: Optional[List[Rule]] = None) -> Dict[str, str]:
    """Return the signal classes present in the text, with matched evidence."""
    active = signals if signals is not None else CCI_SIGNALS
    haystack = normalize(text)
    found: Dict[str, str] = {}
    for rule in active:
        match = compiled(rule).search(haystack)
        if match:
            found[rule.id] = match.group(0)[:120]
    return found


def detect_crypto_context_injection(window: str) -> List[Finding]:
    """Fire when encoding, key, decryptor and execution signals co-occur."""
    found = signal_classes(window)
    if len(found) < MIN_SIGNAL_CLASSES:
        return []
    classes = sorted(found)
    return [_structural(
        "RL-210",
        "co-occurring signals: " + ", ".join(classes),
        "Cross-turn payload: %d signal classes co-occur in the session window (%s)." % (len(classes), ", ".join(classes)),
    )]


class ScanSession:
    """A bounded rolling conversation window. Nothing is written to disk."""

    def __init__(self, max_turns: int = 12, max_bytes: int = 256_000):
        self.max_turns = max_turns
        self.max_bytes = max_bytes
        self.turns: Deque[Turn] = deque(maxlen=max_turns)
        self._bytes = 0
        self._category_hits: Dict[str, int] = {}
        self._counter = 0

    # ---------------------------------------------------------------- window
    def record(self, text: str, layer: str = LAYER_DIRECT, source: str = "") -> None:
        clean = text or ""
        self.turns.append(Turn(self._counter, clean, layer, source))
        self._counter += 1
        self._bytes += len(clean)
        while self._bytes > self.max_bytes and len(self.turns) > 1:
            dropped = self.turns.popleft()
            self._bytes -= len(dropped.text)

    def window(self) -> str:
        return "\n".join(turn.text for turn in self.turns)

    def reset(self) -> None:
        self.turns.clear()
        self._bytes = 0
        self._category_hits.clear()
        self._counter = 0

    @property
    def byte_size(self) -> int:
        return self._bytes

    # ----------------------------------------------------------------- scan
    def cross_turn_findings(self, text: str) -> List[Finding]:
        findings: List[Finding] = []
        combined = self.window() + "\n" + (text or "")
        findings.extend(detect_crypto_context_injection(combined))

        # Repeated attempts: the same class of attack coming back three times is
        # no longer a one-off question.
        categories = {finding.category for finding in scan_text(text or "")}
        for category in categories:
            hits = self._category_hits.get(category, 0) + 1
            self._category_hits[category] = hits
            if hits >= REPEAT_ATTEMPT_LIMIT:
                findings.append(_structural(
                    "RL-211",
                    "category %s attempted %d times" % (category, hits),
                    "Repeated attempt: category %s appeared in %d messages of this session." % (category, hits),
                ))
        return findings

    def scan(self, text: str, layer: str = LAYER_DIRECT, source: str = "") -> Report:
        """Scan one message in the context of the window, then record it."""
        base = scan_one(text or "", target="session[%d]" % self._counter, layer=layer)
        cross = self.cross_turn_findings(text or "")
        findings = list(base.findings) + cross
        score, notes = score_findings(findings)
        report = Report(
            target="session[%d]" % self._counter,
            layer=SESSION_LAYER,
            text_length=len(text or ""),
            findings=findings,
            score=score,
            decision=decide(score, findings, SESSION_LAYER),
            notes=list(base.notes) + notes,
        )
        self.record(text or "", layer, source)
        return report
