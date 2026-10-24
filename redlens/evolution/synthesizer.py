"""Turn misses into candidate rules.

The signal is contrast: a phrase that appears in an attack the pack missed and in
none of the benign or hard-negative samples is, by construction, a phrase the
current pack does not know and legitimate writing does not use. That is the whole
idea, and it is deliberately boring: no model, no guessing, just a phrase that
separates the two corpora and a rule built from it.

A proposal is never trusted. Every one of them goes to the acceptance gate.
"""

from __future__ import annotations

import re
from typing import Dict, List, Sequence, Tuple

from ..rules import RULES, Rule

WORD = re.compile(r"[a-z0-9]+")
MIN_WORDS = 2
MAX_WORDS = 6

STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with", "is", "are",
    "was", "were", "be", "been", "it", "this", "that", "these", "those", "as", "at",
    "by", "from", "you", "your", "me", "my", "i", "we", "they", "he", "she", "them",
    "do", "does", "did", "can", "could", "should", "would", "will", "please", "then",
}


def normalize_words(text: str) -> List[str]:
    return WORD.findall((text or "").lower())


def _ngrams(words: Sequence[str], size: int) -> List[str]:
    return [" ".join(words[index:index + size]) for index in range(len(words) - size + 1)]


def candidate_phrases(text: str, min_words: int = MIN_WORDS, max_words: int = MAX_WORDS) -> List[str]:
    """Every word n-gram in a text that carries at least one content word."""
    words = normalize_words(text)
    phrases: List[str] = []
    for size in range(min_words, max_words + 1):
        for phrase in _ngrams(words, size):
            parts = phrase.split()
            if all(part in STOPWORDS for part in parts):
                continue
            if not any(part not in STOPWORDS and len(part) >= 4 for part in parts):
                continue
            phrases.append(phrase)
    return phrases


def _covered_by_existing(phrase: str) -> bool:
    for rule in RULES:
        try:
            if re.search(rule.pattern, phrase, rule.regex_flags):
                return True
        except re.error:
            continue
    return False


def discriminating_phrases(
    misses: Sequence[Dict[str, str]],
    benign_texts: Sequence[str],
    limit: int = 40,
) -> List[Tuple[str, int]]:
    """Phrases present in the misses and absent from every benign sample."""
    benign_blob = "\n".join((text or "").lower() for text in benign_texts)
    counts: Dict[str, int] = {}
    for row in misses:
        for phrase in set(candidate_phrases(row.get("text", ""))):
            if phrase in benign_blob:
                continue
            counts[phrase] = counts.get(phrase, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], -len(item[0])))
    return [item for item in ranked if not _covered_by_existing(item[0])][:limit]


def build_rule(phrase: str, category: str, rule_id: str, severity: str = "high", parent: str = "") -> Rule:
    """A rule that matches the phrase with any whitespace between its words."""
    words = phrase.split()
    pattern = r"\b" + r"\s+".join(re.escape(word) for word in words) + r"\b"
    return Rule(
        id=rule_id,
        category=category or "synthesized",
        severity=severity,
        pattern=pattern,
        description="Synthesised from a missed attack: %s" % phrase,
        owasp="LLM01:2025 Prompt Injection",
        source="evolution",
        tests=(parent,) if parent else (),
    )


def propose_rules(
    misses: Sequence[Dict[str, str]],
    benign_texts: Sequence[str],
    limit: int = 3,
    start_id: int = 900,
    existing_ids: Sequence[str] = (),
) -> List[Rule]:
    """Propose a small number of candidate rules, best first."""
    taken = set(existing_ids) | {rule.id for rule in RULES}
    proposals: List[Rule] = []
    by_phrase_parent: Dict[str, Dict[str, str]] = {}
    for row in misses:
        for phrase in candidate_phrases(row.get("text", "")):
            by_phrase_parent.setdefault(phrase, row)

    for phrase, _ in discriminating_phrases(misses, benign_texts, limit=limit * 6):
        parent = by_phrase_parent.get(phrase, {})
        rule_id = "AUTO-%03d" % start_id
        while rule_id in taken:
            start_id += 1
            rule_id = "AUTO-%03d" % start_id
        taken.add(rule_id)
        proposals.append(build_rule(
            phrase,
            parent.get("category", "synthesized"),
            rule_id,
            parent=parent.get("id", ""),
        ))
        if len(proposals) >= limit:
            break
    return proposals
