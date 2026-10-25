"""Measure a rule set against attack and benign corpora, and say what failed."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from ..rules import RULES, Rule
from ..scanner import DECISION_BLOCK, DECISION_REVIEW, scan

FLAGGED = (DECISION_REVIEW, DECISION_BLOCK)


@dataclass
class Metrics:
    attacks: int = 0
    caught: int = 0
    benign: int = 0
    false_positives: int = 0
    misses: List[Dict[str, str]] = field(default_factory=list)
    flagged_benign: List[Dict[str, str]] = field(default_factory=list)
    # Distinct seed attacks caught, not generated rows: seven mutations of one
    # seed are one detection, not seven. Counting rows let the loop report a
    # large gain for a rule that only matched shared context prose (D3).
    caught_parents: set = field(default_factory=set)
    latency_p50: float = 0.0
    latency_p95: float = 0.0
    latency_p99: float = 0.0
    latency_samples: int = 0

    @property
    def recall(self) -> float:
        return (self.caught / self.attacks) if self.attacks else 1.0

    def to_dict(self) -> Dict[str, object]:
        return {
            "attacks": self.attacks,
            "caught": self.caught,
            "recall": round(self.recall, 4),
            "benign": self.benign,
            "false_positives": self.false_positives,
            "caught_parents": len(self.caught_parents),
            "latency_p50": round(self.latency_p50, 3),
            "latency_p95": round(self.latency_p95, 3),
            "latency_p99": round(self.latency_p99, 3),
            "latency_samples": self.latency_samples,
        }


def load_jsonl(path: str) -> List[Dict[str, str]]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def quantile(values: Sequence[float], fraction: float) -> float:
    """A real quantile. The previous code used int(n*0.99), which is the maximum
    for every sample size this gate used, so "p99" was "the worst run" (D7a)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    index = int(round(fraction * (len(ordered) - 1)))
    return ordered[max(0, min(len(ordered) - 1, index))]


def latency_inputs(attacks: Sequence[Dict[str, str]], benign: Sequence[Dict[str, str]],
                   limit: int = 8) -> List[str]:
    """Inputs the timing run actually scans.

    A single fixed sentence let a candidate rule pass the budget without ever
    executing, because the pre-filter skipped it (D7b). These are drawn from the
    corpora, so a rule that matches attacks is executed while it is timed.
    """
    texts: List[str] = []
    for row in list(attacks)[:limit]:
        texts.append(str(row.get("text", ""))[:600])
    for row in list(benign)[:limit]:
        texts.append(str(row.get("text", ""))[:600])
    return [text for text in texts if text]


def measure(
    attacks: Sequence[Dict[str, str]],
    benign: Sequence[Dict[str, str]],
    extra_rules: Sequence[Rule] = (),
    latency_sample: str = "Can you review this pull request and summarise the changes?",
    latency_rounds: int = 40,
) -> Metrics:
    """Run one rule set over both corpora, and time it."""
    active = list(RULES) + list(extra_rules)
    metrics = Metrics(attacks=len(attacks), benign=len(benign))

    for row in attacks:
        report = scan(row.get("text", ""), layer=row.get("layer", "direct"), rules=active)
        if report.decision in FLAGGED:
            metrics.caught += 1
            metrics.caught_parents.add(str(row.get("parent") or row.get("id") or ""))
        else:
            metrics.misses.append(row)

    for row in benign:
        report = scan(row.get("text", ""), layer=row.get("layer", "direct"), rules=active)
        if report.decision in FLAGGED:
            metrics.false_positives += 1
            metrics.flagged_benign.append(row)

    inputs = latency_inputs(attacks, benign) or [latency_sample]
    pooled = []
    for text in inputs:
        for _ in range(max(1, latency_rounds // max(1, len(inputs)))):
            started = time.perf_counter()
            scan(text, rules=active)
            pooled.append((time.perf_counter() - started) * 1000)
    metrics.latency_samples = len(pooled)
    metrics.latency_p50 = quantile(pooled, 0.50)
    metrics.latency_p95 = quantile(pooled, 0.95)
    metrics.latency_p99 = quantile(pooled, 0.99)
    return metrics


def cluster_misses(misses: Sequence[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
    """Group misses so a report can say which mutations defeat the pack."""
    clustered: Dict[str, List[Dict[str, str]]] = {}
    for row in misses:
        key = row.get("mutation") or row.get("category") or "unknown"
        clustered.setdefault(key, []).append(row)
    return dict(sorted(clustered.items(), key=lambda item: -len(item[1])))
