"""The acceptance gate, and the loop that runs it.

A proposal is accepted only when all of these hold:

  * it catches at least one attack the current pack misses;
  * it adds no false positive on the benign or hard-negative corpora;
  * it is not a kill switch (those stay hand-made and few);
  * it does not push p99 latency past the budget;
  * its id does not collide with an existing rule.

Anything else is rejected with a reason, and the reason is recorded, because a
rejection is a result too: it says the phrase that looked discriminating was not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from ..rules import RULES, Rule
from .attackgen import SCAFFOLD, generate
from .miner import Metrics, cluster_misses, measure
from .synthesizer import propose_rules

DEFAULT_LATENCY_BUDGET_MS = 12.0
DEFAULT_MAX_ACCEPTED = 6


@dataclass
class Decision:
    rule_id: str
    phrase: str
    accepted: bool
    reason: str
    gain: int = 0
    new_false_positives: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "phrase": self.phrase,
            "accepted": self.accepted,
            "reason": self.reason,
            "gain": self.gain,
            "new_false_positives": self.new_false_positives,
        }


def phrase_of(rule: Rule) -> str:
    """The words a synthesised rule was built from.

    Read from the description, not from the pattern: pulling words out of a regex
    yields "b transmit s the s api s key b", because the escapes look like words.
    The first version of this gate did exactly that, and both checks below were
    dead code that always passed.
    """
    text = rule.description or ""
    if ":" in text:
        text = text.split(":", 1)[1]
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def _lint(candidate: Rule, accepted: Sequence[Rule]) -> str:
    """Cheap refusals first, so the expensive measurement is not wasted."""
    phrase = phrase_of(candidate)
    words = phrase.split()
    for scaffold in SCAFFOLD:
        scaffold_words = " ".join(re.findall(r"[a-z0-9]+", scaffold.lower()))
        if scaffold_words and scaffold_words in phrase:
            return "matches the generator's own scaffolding, not an attack"
    if len(words) < 2:
        return "a single word is not a rule"
    for rule in accepted:
        existing = phrase_of(rule)
        if phrase and existing and (phrase in existing or existing in phrase):
            return "subsumed by the already accepted rule %s" % rule.id
    return ""


def evaluate_candidate(
    candidate: Rule,
    attacks: Sequence[Dict[str, str]],
    benign: Sequence[Dict[str, str]],
    baseline: Metrics,
    latency_budget_ms: float = DEFAULT_LATENCY_BUDGET_MS,
    accepted: Sequence[Rule] = (),
) -> Decision:
    """Run one candidate through every gate and return the verdict."""
    if candidate.kill_switch:
        return Decision(candidate.id, candidate.pattern, False, "a proposal may never be a kill switch")
    if any(rule.id == candidate.id for rule in RULES):
        return Decision(candidate.id, candidate.pattern, False, "rule id already exists")
    lint = _lint(candidate, accepted)
    if lint:
        return Decision(candidate.id, candidate.pattern, False, lint)

    after = measure(attacks, benign, extra_rules=[candidate], latency_rounds=20)
    gain = after.caught - baseline.caught
    new_false_positives = after.false_positives - baseline.false_positives

    if new_false_positives > 0:
        return Decision(candidate.id, candidate.pattern, False,
                        "would add %d false positive(s)" % new_false_positives,
                        gain=gain, new_false_positives=new_false_positives)
    if gain <= 0:
        return Decision(candidate.id, candidate.pattern, False,
                        "catches nothing the pack already missed", gain=gain)
    if after.latency_p99 > latency_budget_ms:
        return Decision(candidate.id, candidate.pattern, False,
                        "p99 %.2f ms would exceed the %.1f ms budget" % (after.latency_p99, latency_budget_ms),
                        gain=gain)
    return Decision(candidate.id, candidate.pattern, True,
                    "catches %d new attack(s) with no new false positives" % gain, gain=gain)


def evolve(
    seed_attacks: Sequence[Dict[str, str]],
    benign: Sequence[Dict[str, str]],
    rounds: int = 3,
    seed: int = 0,
    per_text: int = 3,
    proposals_per_round: int = 3,
    max_accepted: int = DEFAULT_MAX_ACCEPTED,
    latency_budget_ms: float = DEFAULT_LATENCY_BUDGET_MS,
) -> Dict[str, object]:
    """Run the loop and return the report the CLI prints."""
    pool = generate(seed_attacks, seed=seed, per_text=per_text)
    accepted: List[Rule] = []
    decisions: List[Decision] = []
    history: List[Dict[str, object]] = []

    baseline = measure(pool, benign, extra_rules=accepted)
    for round_index in range(rounds):
        current = measure(pool, benign, extra_rules=accepted)
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
            decision = evaluate_candidate(candidate, pool, benign, current, latency_budget_ms, accepted)
            decisions.append(decision)
            if decision.accepted and len(accepted) < max_accepted:
                accepted.append(candidate)
                accepted_this_round += 1
        history.append({
            "round": round_index + 1,
            "generated": len(pool),
            "caught_before": current.caught,
            "missed": len(misses),
            "miss_clusters": {name: len(rows) for name, rows in cluster_misses(misses).items()},
            "proposed": len(proposals),
            "accepted": accepted_this_round,
        })

    final = measure(pool, benign, extra_rules=accepted)
    return {
        "seed": seed,
        "rounds": rounds,
        "generated_attacks": len(pool),
        "benign_samples": len(benign),
        "baseline": baseline.to_dict(),
        "final": final.to_dict(),
        "accepted_rules": [rule.id for rule in accepted],
        "rules": [
            {
                "id": rule.id,
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
