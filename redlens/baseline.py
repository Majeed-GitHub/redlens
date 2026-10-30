"""Baseline: adopt the scanner on a codebase that already has findings.

Nobody turns on a scanner that reports fifty pre-existing problems on day one
and blocks the build; they turn it off instead. A baseline records the
fingerprint of every finding that exists today, so the next run reports only
what is new. This is the difference between a demo and a control you can roll
out to a team that already has debt.

The file is deliberately boring JSON - reviewable in a pull request, diffable in
git, no timestamps inside the fingerprint set.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .detectors import Finding
from .identity import annotate, fingerprint as finding_fingerprint
from .scanner import Report, decide, score_findings

BASELINE_VERSION = 1
BASELINE_KIND = "redlens-baseline"


def collect_fingerprints(entries: Sequence[Tuple[Report, Optional[str]]]) -> List[str]:
    """Fingerprints for every finding in the given (report, text) pairs."""
    seen: Set[str] = set()
    for _, _, _, value in annotate(entries):
        seen.add(value)
    return sorted(seen)


def write_baseline(path: str, entries: Sequence[Tuple[Report, Optional[str]]],
                   tool_version: str = "") -> int:
    """Record every current finding. Returns how many fingerprints were written."""
    fingerprints = collect_fingerprints(entries)
    payload: Dict[str, object] = {
        "kind": BASELINE_KIND,
        "version": BASELINE_VERSION,
        "toolVersion": tool_version or "unknown",
        "fingerprints": fingerprints,
    }
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return len(fingerprints)


def load_baseline(path: str) -> Set[str]:
    """Read a baseline file. Raises ValueError for anything that is not one."""
    if not os.path.exists(path):
        raise ValueError("baseline not found: %s" % path)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("baseline is unreadable: %s" % exc)
    if not isinstance(payload, dict):
        raise ValueError("baseline is not a JSON object: %s" % path)
    if payload.get("kind") != BASELINE_KIND:
        raise ValueError("baseline is not a RedLens baseline: %s" % path)
    entries = payload.get("fingerprints")
    if not isinstance(entries, list):
        raise ValueError("baseline has no fingerprint list: %s" % path)
    return {str(entry) for entry in entries}


def suppress(report: Report, fingerprints: Set[str], text: Optional[str] = "") -> Tuple[Report, int]:
    """Drop findings already in the baseline and rescore what is left.

    Rescoring matters: the decision has to reflect the findings that remain, or
    a suppressed finding would keep a clean scan failing CI forever.
    """
    annotated = annotate([(report, text)])
    known: List[Finding] = []
    remaining: List[Finding] = []
    for _, _, finding, value in annotated:
        if value in fingerprints:
            known.append(finding)
        else:
            remaining.append(finding)
    if not known:
        return report, 0
    score, notes = score_findings(remaining)
    decision = decide(score, remaining, report.layer)
    notes = list(notes) + ["%d finding(s) suppressed by baseline." % len(known)]
    return (
        Report(
            target=report.target,
            layer=report.layer,
            text_length=report.text_length,
            findings=remaining,
            score=score,
            decision=decision,
            notes=notes,
        ),
        len(known),
    )
