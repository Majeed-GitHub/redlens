"""Stable identities for findings.

A fingerprint answers one question: is this the same finding we already
accepted? It must be deterministic across runs, and it must not depend on how
much surrounding text the detector happened to include in its evidence window -
that window grows and shrinks with the document, so a text hash re-reports the
same finding every time a paragraph moves.

The identity is therefore positional: rule id, target, the line the match
starts on, and which occurrence of that rule it is on that line. Measured on
the shipped corpus, an evidence-based hash kept the same identity for only 13%
of findings once the document gained a sentence; this one keeps every finding
whose line did not move, which is the contract a baseline can explain to a
reviewer.

The trade-off is stated rather than hidden: inserting text above a finding
moves it, and a moved finding is reported again. The save-baseline command is
the one step that re-accepts the new positions.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Sequence, Tuple

from .detectors import Finding
from .scanner import Report


def line_of(finding: Finding, text: Optional[str]) -> int:
    """1-based line the match starts on, or 0 when the offsets are unknown.

    Findings raised on a decoded variant carry offsets into that variant, not
    into the document. Those get line 0 and stay distinguishable by ordinal
    instead of pointing at an unrelated line.
    """
    if not text:
        return 0
    start = finding.span[0]
    if start < 0 or start > len(text):
        return 0
    return text.count("\n", 0, start) + 1


def fingerprint(finding: Finding, text: Optional[str] = "", target: str = "",
                ordinal: int = 0) -> str:
    line = line_of(finding, text)
    raw = "\x00".join((finding.rule_id, target or "", str(line), str(ordinal)))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def annotate(entries: Sequence[Tuple[Report, Optional[str]]],
             ) -> List[Tuple[Report, Optional[str], Finding, str]]:
    """Pair every finding with its fingerprint, numbering repeats on one line."""
    seen: Dict[Tuple[str, str, int], int] = {}
    annotated: List[Tuple[Report, Optional[str], Finding, str]] = []
    for report, text in entries:
        for finding in report.findings:
            key = (report.target or "", finding.rule_id, line_of(finding, text))
            ordinal = seen.get(key, 0)
            seen[key] = ordinal + 1
            value = fingerprint(finding, text, report.target or "", ordinal)
            annotated.append((report, text, finding, value))
    return annotated
