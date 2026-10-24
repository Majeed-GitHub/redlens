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
    latency_p50: float = 0.0
    latency_p99: float = 0.0

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
            "latency_p50": round(self.latency_p50, 3),
            "latency_p99": round(self.latency_p99, 3),
        }


def load_jsonl(path: str) -> List[Dict[str, str]]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


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
        else:
            metrics.misses.append(row)

    for row in benign:
        report = scan(row.get("text", ""), layer=row.get("layer", "direct"), rules=active)
        if report.decision in FLAGGED:
            metrics.false_positives += 1
            metrics.flagged_benign.append(row)

    samples = []
    for _ in range(latency_rounds):
        started = time.perf_counter()
        scan(latency_sample, rules=active)
        samples.append((time.perf_counter() - started) * 1000)
    samples.sort()
    metrics.latency_p50 = samples[len(samples) // 2]
    metrics.latency_p99 = samples[min(len(samples) - 1, int(len(samples) * 0.99))]
    return metrics


def cluster_misses(misses: Sequence[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
    """Group misses so a report can say which mutations defeat the pack."""
    clustered: Dict[str, List[Dict[str, str]]] = {}
    for row in misses:
        key = row.get("mutation") or row.get("category") or "unknown"
        clustered.setdefault(key, []).append(row)
    return dict(sorted(clustered.items(), key=lambda item: -len(item[1])))
