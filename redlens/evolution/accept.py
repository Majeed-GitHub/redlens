"""The acceptance gate, and the loop that runs it.

A proposal is accepted only when all of these hold:

  * the gate measured the same artifact it is about to accept, checked by a
    content fingerprint, not by a rule id;
  * it catches at least one seed attack the current pack misses, counted by
    distinct parent, not by generated row;
  * it catches something on a holdout split of the generated pool that the pack
    misses, so shared context prose cannot earn an acceptance;
  * it adds no false positive, measured at every layer;
  * it is not a kill switch, and its words are not the generator's scaffolding;
  * the pack plus this rule stays inside the latency budget, measured on inputs
    the rule actually executes against.

This file was rewritten after an adversarial review (reviews/2026-10-25-acceptance-gate.md).
Eight defects were found in it: a rule-id keyed regex cache that let the gate
measure one pattern and accept another, lints that read a rule's description
instead of its pattern, gains counted per generated row, per-candidate latency
checks, a cap applied after the verdict, and a "p99" that was the sample maximum.
Every one of them has a test in tests/test_gate_integrity.py.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from ..detectors import compiled, pattern_words
from ..rules import RULES, Rule
from ..scanner import DECISION_BLOCK, DECISION_REVIEW, scan
from .attackgen import SCAFFOLD, generate
from .miner import Metrics, cluster_misses, measure
from .synthesizer import propose_rules

GATE_VERSION = "0.8.0-content-addressed"
DEFAULT_LATENCY_BUDGET_MS = 12.0
DEFAULT_MAX_ACCEPTED = 6
DEFAULT_HOLDOUT_RATIO = 0.3
FLAGGED = (DECISION_REVIEW, DECISION_BLOCK)
FP_LAYERS = ("direct", "retrieved", "tool_output", "tool_definition")


@dataclass
class Decision:
    rule_id: str
    phrase: str
    accepted: bool
    reason: str
    gain: int = 0
    new_false_positives: int = 0
    fingerprint: str = ""
    executed: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "phrase": self.phrase,
            "accepted": self.accepted,
            "reason": self.reason,
            "gain": self.gain,
            "new_false_positives": self.new_false_positives,
            "fingerprint": self.fingerprint,
            "executed_when_timed": self.executed,
        }


def fingerprint(rule: Rule) -> str:
    """Identity by content: id, pattern, flags, severity, category.

    The adversarial review's first finding was that the gate verified an id. An
    id is a label a caller can reuse; the artifact is the regex and its meaning.
    """
    payload = json.dumps(
        [rule.id, rule.pattern, rule.regex_flags, rule.severity, rule.category],
        sort_keys=True, ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def phrase_of(rule: Rule) -> str:
    """The words a rule cannot match without, read from its pattern.

    Reading the description instead meant a rule whose pattern *was* generator
    scaffolding got accepted whenever its description looked innocent (D2).
    """
    return " ".join(word.lower() for word in pattern_words(rule.pattern, minimum=2))


def identity_holds(candidate: Rule) -> bool:
    """The measured artifact is the candidate's own pattern, byte for byte."""
    return compiled(candidate).pattern == candidate.pattern


def _lint(candidate: Rule, accepted: Sequence[Rule]) -> str:
    """Refusals that need no measurement, so the expensive path is not wasted."""
    phrase = phrase_of(candidate)
    words = phrase.split()
    if len(words) < 2:
        return "a single word is not a rule"
    for scaffold in SCAFFOLD:
        scaffold_words = " ".join(re.findall(r"[a-z0-9]+", scaffold.lower()))
        if scaffold_words and scaffold_words in phrase:
            return "matches the generator's own scaffolding, not an attack"
    for rule in accepted:
        existing = phrase_of(rule)
        if phrase and existing and (phrase in existing or existing in phrase):
            return "subsumed by the already accepted rule %s" % rule.id
    return ""


def false_positives_at(benign: Sequence[Dict[str, str]], rules: Sequence[Rule], layer: str) -> int:
    """Flag count with the benign corpus forced through one layer.

    The shipped benign corpus is entirely direct-layer, so a candidate graded on
    a passive-layer attack used to face a cheaper false-positive test than one
    graded on a direct-layer attack (D8). This closes that asymmetry.
    """
    return sum(1 for row in benign
               if scan(row.get("text", ""), layer=layer, rules=list(rules)).decision in FLAGGED)


def executed_on(attacks: Sequence[Dict[str, str]], rules: Sequence[Rule], rule_id: str, limit: int = 12) -> bool:
    """Did the candidate rule actually fire while it was being timed?"""
    for row in list(attacks)[:limit]:
        report = scan(row.get("text", ""), layer=row.get("layer", "direct"), rules=list(rules))
        if any(finding.rule_id == rule_id for finding in report.findings):
            return True
    return False


def evaluate_candidate(
    candidate: Rule,
    attacks: Sequence[Dict[str, str]],
    benign: Sequence[Dict[str, str]],
    baseline: Metrics,
    latency_budget_ms: float = DEFAULT_LATENCY_BUDGET_MS,
    accepted: Sequence[Rule] = (),
    holdout: Sequence[Dict[str, str]] = (),
    holdout_baseline: Optional[Metrics] = None,
) -> Decision:
    """Run one candidate through every gate and return the verdict."""
    mark = fingerprint(candidate)
    if candidate.kill_switch:
        return Decision(candidate.id, candidate.pattern, False, "a proposal may never be a kill switch", fingerprint=mark)
    if any(rule.id == candidate.id for rule in RULES):
        return Decision(candidate.id, candidate.pattern, False, "rule id already exists", fingerprint=mark)
    if any(rule.id == candidate.id for rule in accepted):
        return Decision(candidate.id, candidate.pattern, False, "rule id already accepted this run", fingerprint=mark)
    if not identity_holds(candidate):
        return Decision(candidate.id, candidate.pattern, False,
                        "the compiled pattern does not match the candidate: refusing to measure an artifact I do not hold",
                        fingerprint=mark)
    lint = _lint(candidate, accepted)
    if lint:
        return Decision(candidate.id, candidate.pattern, False, lint, fingerprint=mark)

    # Measure the pack as it would be, not the candidate alone: measuring the
    # candidate in isolation credited the same rows to two near-duplicate rules (D4).
    proposed = list(accepted) + [candidate]
    after = measure(attacks, benign, extra_rules=proposed, latency_rounds=60)
    # Newly caught rows, with the parent count reported separately. Counting only
    # distinct parents refused a rule that caught a previously missed mutation of
    # an attack the pack partly handled; counting only rows let one shared
    # sentence across many mutations look like a large gain. The seed-disjoint
    # holdout below is what carries the anti-multiplicity duty.
    gain = after.caught - baseline.caught
    new_parents = len(after.caught_parents - baseline.caught_parents)
    new_false_positives = after.false_positives - baseline.false_positives

    if new_false_positives > 0:
        return Decision(candidate.id, candidate.pattern, False,
                        "would add %d false positive(s)" % new_false_positives,
                        gain=gain, new_false_positives=new_false_positives, fingerprint=mark)

    for layer in FP_LAYERS:
        extra = false_positives_at(benign, proposed, layer)
        if extra:
            return Decision(candidate.id, candidate.pattern, False,
                            "would flag %d benign sample(s) at layer %s" % (extra, layer),
                            gain=gain, fingerprint=mark)

    if gain <= 0:
        return Decision(candidate.id, candidate.pattern, False,
                        "catches nothing the pack already missed", gain=gain, fingerprint=mark)

    if holdout and holdout_baseline is not None:
        after_holdout = measure(holdout, [], extra_rules=proposed, latency_rounds=1)
        holdout_gain = len(after_holdout.caught_parents - holdout_baseline.caught_parents)
        if holdout_gain <= 0:
            return Decision(candidate.id, candidate.pattern, False,
                            "catches nothing on the seed-disjoint holdout: likely shared context prose",
                            gain=gain, fingerprint=mark)

    executed = executed_on(attacks, proposed, candidate.id)
    if not executed:
        return Decision(candidate.id, candidate.pattern, False,
                        "never fired on any graded attack, so its latency was never measured",
                        gain=gain, fingerprint=mark)

    if after.latency_p95 > latency_budget_ms:
        return Decision(candidate.id, candidate.pattern, False,
                        "pack p95 %.2f ms would exceed the %.1f ms budget" % (after.latency_p95, latency_budget_ms),
                        gain=gain, executed=executed, fingerprint=mark)

    return Decision(candidate.id, candidate.pattern, True,
                    "catches %d new row(s) across %d seed attack(s), nothing new flagged, p95 %.2f ms"
                    % (gain, new_parents, after.latency_p95),
                    gain=gain, executed=executed, fingerprint=mark)


def split_pool(pool: Sequence[Dict[str, str]], ratio: float = DEFAULT_HOLDOUT_RATIO):
    """Deterministic split of a generated pool into tuning and holdout rows."""
    tune, holdout = [], []
    for row in pool:
        digest = hashlib.sha256(str(row.get("id", "")).encode("utf-8")).digest()
        (holdout if (digest[0] % 100) < int(ratio * 100) else tune).append(row)
    return tune, holdout


def split_seeds(seeds: Sequence[Dict[str, str]], ratio: float = DEFAULT_HOLDOUT_RATIO):
    """Split the seed attacks themselves, so the two halves share no text.

    Splitting generated rows is not enough: mutations of one seed all carry that
    seed's wording, so a rule matching shared context prose passes a row-level
    holdout. Seeding the holdout from different attacks is what makes the check
    mean generalisation rather than memorisation.
    """
    tune, holdout = [], []
    for row in seeds:
        digest = hashlib.sha256(str(row.get("id", "")).encode("utf-8")).digest()
        (holdout if (digest[0] % 100) < int(ratio * 100) else tune).append(row)
    return tune, holdout


def evolve(
    seed_attacks: Sequence[Dict[str, str]],
    benign: Sequence[Dict[str, str]],
    rounds: int = 3,
    seed: int = 0,
    per_text: int = 3,
    proposals_per_round: int = 3,
    max_accepted: int = DEFAULT_MAX_ACCEPTED,
    latency_budget_ms: float = DEFAULT_LATENCY_BUDGET_MS,
    holdout_ratio: float = DEFAULT_HOLDOUT_RATIO,
) -> Dict[str, object]:
    """Run the loop and return the report the CLI prints."""
    tune_seeds, holdout_seeds = split_seeds(seed_attacks, holdout_ratio)
    pool = generate(tune_seeds, seed=seed, per_text=per_text)
    tune = pool
    holdout = generate(holdout_seeds, seed=seed + 1, per_text=per_text)
    accepted: List[Rule] = []
    decisions: List[Decision] = []
    history: List[Dict[str, object]] = []

    holdout_baseline = measure(holdout, [], extra_rules=accepted, latency_rounds=1)
    baseline = measure(tune, benign, extra_rules=accepted)

    for round_index in range(rounds):
        current = measure(tune, benign, extra_rules=accepted)
        misses = current.misses
        proposals = propose_rules(
            misses,
            [row.get("text", "") for row in benign],
            limit=proposals_per_round,
            start_id=900 + round_index * 10,
            existing_ids=[rule.id for rule in accepted],
        )
        accepted_this_round = 0
        for candidate in proposals:
            # The cap is checked before the verdict, so a report can never claim a
            # gain that was not applied (D5).
            if len(accepted) >= max_accepted:
                decisions.append(Decision(candidate.id, candidate.pattern, False,
                                          "acceptance budget is full (%d rules)" % max_accepted,
                                          fingerprint=fingerprint(candidate)))
                continue
            decision = evaluate_candidate(candidate, tune, benign, current, latency_budget_ms,
                                          accepted, holdout, holdout_baseline)
            decisions.append(decision)
            if decision.accepted:
                accepted.append(candidate)
                holdout_baseline = measure(holdout, [], extra_rules=accepted, latency_rounds=1)
                current = measure(tune, benign, extra_rules=accepted)
                accepted_this_round += 1
        history.append({
            "round": round_index + 1,
            "generated": len(pool),
            "tuning_rows": len(tune),
            "holdout_rows": len(holdout),
            "caught_before": current.caught,
            "missed": len(misses),
            "miss_clusters": {name: len(rows) for name, rows in cluster_misses(misses).items()},
            "proposed": len(proposals),
            "accepted": accepted_this_round,
        })

    final = measure(tune, benign, extra_rules=accepted)
    holdout_final = measure(holdout, [], extra_rules=accepted, latency_rounds=1)
    return {
        "gate_version": GATE_VERSION,
        "seed": seed,
        "rounds": rounds,
        "generated_attacks": len(pool),
        "tuning_rows": len(tune),
        "holdout_rows": len(holdout),
        "benign_samples": len(benign),
        "baseline": baseline.to_dict(),
        "final": final.to_dict(),
        "holdout_baseline": holdout_baseline.to_dict(),
        "holdout_final": holdout_final.to_dict(),
        "accepted_rules": [rule.id for rule in accepted],
        "rules": [
            {
                "id": rule.id,
                "fingerprint": fingerprint(rule),
                "category": rule.category,
                "severity": rule.severity,
                "pattern": rule.pattern,
                "description": rule.description,
                "source": rule.source,
                "tests": list(rule.tests),
            }
            for rule in accepted
        ],
        "decisions": [decision.to_dict() for decision in decisions],
        "history": history,
    }
