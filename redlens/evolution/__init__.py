"""The closed loop: generate, measure, propose, accept.

A hand-written rule pack stops improving the day its author stops thinking of new
phrasings. This package closes that loop:

    generate    mutate known attacks into variants the pack has not seen
    mine        run the pack, find what it misses and what it wrongly flags
    synthesise  propose rules from the phrases that separate a miss from benign text
    accept      keep a proposal only if it measurably improves and nothing else changes

The acceptance gate is the point. A system that can change its own detection is
worthless unless something refuses its bad ideas, so every proposal faces the
same gates a human contribution does: no new false positives, no kill switch, no
latency regression, and a real gain on cases that were previously missed.

Nothing here trains a model, and nothing here may weaken the frozen benchmark:
generated attacks live in a separate pending corpus until a human promotes them.
"""

from .accept import Decision, evolve, evaluate_candidate
from .attackgen import MUTATION_NAMES, SCAFFOLD, generate, mutate
from .miner import Metrics, cluster_misses, load_jsonl, measure
from .synthesizer import discriminating_phrases, propose_rules

__all__ = [
    "Decision",
    "MUTATION_NAMES",
    "SCAFFOLD",
    "Metrics",
    "cluster_misses",
    "discriminating_phrases",
    "evaluate_candidate",
    "evolve",
    "generate",
    "load_jsonl",
    "measure",
    "mutate",
    "propose_rules",
]
