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


def phrase_spans(text: str, min_words: int = MIN_WORDS, max_words: int = MAX_WORDS):
    """(normalised phrase, raw substring) for every word window in a text.

    The raw substring matters: a phrase rebuilt from words joined by whitespace
    cannot match text where the words were separated by "://", "." or "%20", so
    the rule could never fire on its own parent. Carrying the original text lets
    build_rule escape what is there and keep whitespace flexible only where the
    text had whitespace.
    """
    matches = list(WORD.finditer(text or ""))
    out = []
    for size in range(min_words, max_words + 1):
        for start in range(len(matches) - size + 1):
            window = matches[start:start + size]
            phrase = " ".join(match.group(0).lower() for match in window)
            parts = phrase.split()
            if all(part in STOPWORDS for part in parts):
                continue
            if not any(part not in STOPWORDS and len(part) >= 4 for part in parts):
                continue
            out.append((phrase, text[window[0].start():window[-1].end()]))
    return out


def candidate_phrases(text: str, min_words: int = MIN_WORDS, max_words: int = MAX_WORDS) -> List[str]:
    """Every word n-gram in a text that carries at least one content word."""
    return [phrase for phrase, _ in phrase_spans(text, min_words, max_words)]


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
) -> List[Tuple[str, int, str]]:
    """Phrases present in the misses and absent from every benign sample.

    Returns (normalised phrase, occurrences, raw substring as it appeared).
    """
    benign_blob = "\n".join((text or "").lower() for text in benign_texts)
    counts: Dict[str, int] = {}
    raw: Dict[str, str] = {}
    for row in misses:
        text = row.get("text", "")
        for phrase, span in phrase_spans(text):
            if phrase in benign_blob:
                continue
            counts[phrase] = counts.get(phrase, 0) + 1
            raw.setdefault(phrase, span)
    ranked = sorted(counts.items(), key=lambda item: (-item[1], -len(item[0])))
    return [(phrase, count, raw.get(phrase, phrase))
            for phrase, count in ranked if not _covered_by_existing(phrase)][:limit]


def build_rule(phrase: str, category: str, rule_id: str, severity: str = "high",
               parent: str = "", literal: bool = False) -> Rule:
    """A rule for a phrase, with flexible whitespace between its pieces.

    literal=False joins the words with \s+ (a normalised phrase).
    literal=True escapes the phrase as text, so punctuation between the words
    survives: a rule rebuilt from words alone cannot match "h77p://3v1l.3x4mpl3",
    which is why the synthesiser produced candidates that could never fire on
    their own parent attack.
    """
    pieces = [re.escape(piece) for piece in re.split(r"\s+", phrase.strip()) if piece]
    body = r"\s+".join(pieces)
    if not literal:
        words = phrase.split()
        body = r"\s+".join(re.escape(word) for word in words)
    leading = r"\b" if re.match(r"\w", phrase.strip()) else ""
    trailing = r"\b" if re.search(r"\w$", phrase.strip()) else ""
    pattern = leading + body + trailing
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
    by_phrase: Dict[str, Tuple[Dict[str, str], str]] = {}
    for row in misses:
        for phrase, span in phrase_spans(row.get("text", "")):
            by_phrase.setdefault(phrase, (row, span))

    for phrase, _count, raw in discriminating_phrases(misses, benign_texts, limit=limit * 6):
        parent, span = by_phrase.get(phrase, ({}, raw))
        rule_id = "AUTO-%03d" % start_id
        while rule_id in taken:
            start_id += 1
            rule_id = "AUTO-%03d" % start_id
        taken.add(rule_id)
        proposals.append(build_rule(
            span or phrase,
            parent.get("category", "synthesized"),
            rule_id,
            parent=parent.get("id", ""),
            literal=True,
        ))
        if len(proposals) >= limit:
            break
    return proposals
