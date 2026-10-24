"""Attack generation by mutation.

Takes attacks the pack already catches and rewrites them the way an adversary
would: encode, obfuscate, respell, split, reframe, and swap the trigger words.
The output keeps its lineage, so a miss can always be traced back to the mutation
that caused it.

Deterministic for a given seed, so an evolution round can be reproduced.
"""

from __future__ import annotations

import base64
import codecs
import random
import re
from typing import Callable, Dict, List, Sequence, Tuple

SYNONYMS = {
    "ignore": ["disregard", "overlook", "skip"],
    "previous": ["prior", "earlier", "preceding"],
    "instructions": ["directions", "rules", "guidance"],
    "reveal": ["show", "print", "disclose", "output"],
    "system prompt": ["initial instructions", "base prompt", "system message"],
    "must": ["should", "shall", "need to"],
    "assistant": ["agent", "model", "ai"],
    "send": ["forward", "post", "transmit"],
    "delete": ["remove", "wipe", "erase"],
    "read": ["open", "fetch", "load"],
}

FRAMES = [
    ("frame-note", "Note for the AI assistant: {body}"),
    ("frame-comment", "<!-- {body} -->"),
    ("frame-alt", "![{body}](image.png)"),
    ("frame-details", "<details><summary>Policy</summary>{body}</details>"),
    ("frame-quote", "> {body}"),
    ("frame-todo", "TODO: {body}"),
    ("frame-footer", "Terms of service apply. {body} End of document."),
    ("frame-log", "2026-10-24 12:00:01 INFO request handled. {body}"),
]

LEET = str.maketrans({"o": "0", "i": "1", "e": "3", "a": "4", "s": "5", "t": "7"})
HOMOGLYPH = {"a": "\u0430", "e": "\u0435", "o": "\u043e", "p": "\u0440", "c": "\u0441", "x": "\u0445"}
ZERO_WIDTH = "\u200b"


def _m_plain(text, rng):
    return text


def _m_base64(text, rng):
    # No English scaffolding. The first version of this generator prefixed
    # "Here is the encoded payload: ", and the loop duly learned a rule matching
    # that prefix - it was scoring its own scaffolding, not attacks. Prose
    # framing belongs to the frame mutation, which is a separate decision.
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _m_percent(text, rng):
    # Encode UTF-8 bytes, not code points: "%02X" on an Arabic code point makes a
    # %0631 escape that decodes to mojibake, which looked like a detector miss in
    # the first evolution run and was a generator bug.
    out = []
    for byte in text.encode("utf-8"):
        if 48 <= byte <= 57 or 65 <= byte <= 90 or 97 <= byte <= 122:
            out.append(chr(byte))
        else:
            out.append("%%%02X" % byte)
    return "".join(out)


def _m_rot13(text, rng):
    return codecs.decode(text, "rot13")


def _m_leet(text, rng):
    return text.translate(LEET)


def _m_zerowidth(text, rng):
    return ZERO_WIDTH.join(text)


def _m_homoglyph(text, rng):
    return "".join(HOMOGLYPH.get(char, char) for char in text)


def _m_letterspaced(text, rng):
    return " ".join(text)


def _m_reversed(text, rng):
    return text[::-1]


def _m_synonym(text, rng):
    result = text
    for word, options in SYNONYMS.items():
        if word in result.lower():
            result = re.sub(re.escape(word), rng.choice(options), result, count=1, flags=re.IGNORECASE)
    return result


def _m_case(text, rng):
    return "".join(char.upper() if index % 2 else char for index, char in enumerate(text))


def _m_frame(text, rng):
    _, template = rng.choice(FRAMES)
    return template.format(body=text)


def _m_split(text, rng):
    words = text.split()
    if len(words) < 6:
        return text
    cut = len(words) // 2
    return " ".join(words[:cut]) + "\n\n" + " ".join(words[cut:])


MUTATORS = [
    ("plain", _m_plain),
    ("base64", _m_base64),
    ("percent", _m_percent),
    ("rot13", _m_rot13),
    ("leet", _m_leet),
    ("zerowidth", _m_zerowidth),
    ("homoglyph", _m_homoglyph),
    ("letterspaced", _m_letterspaced),
    ("reversed", _m_reversed),
    ("synonym", _m_synonym),
    ("case", _m_case),
    ("frame", _m_frame),
    ("split", _m_split),
]

MUTATION_NAMES = [name for name, _ in MUTATORS]

# Literal text this module adds when it rewrites a payload. A synthesised rule
# must never be built from these phrases, or the loop would reward itself for
# recognising its own scaffolding.
SCAFFOLD = [template.split("{body}")[0].strip().lower() for _, template in FRAMES]
SCAFFOLD += [template.split("{body}")[-1].strip().lower() for _, template in FRAMES]
SCAFFOLD = [phrase for phrase in SCAFFOLD if phrase]


def mutate(text: str, seed: int = 0, per_text: int = 3) -> List[Dict[str, str]]:
    """Return up to per_text labelled variants of one attack."""
    rng = random.Random(seed)
    if per_text >= len(MUTATORS):
        chosen = MUTATORS
    else:
        chosen = rng.sample(MUTATORS, per_text)
    out = []
    for name, mutator in chosen:
        try:
            variant = mutator(text, rng)
        except Exception:
            continue
        if not variant or variant == text:
            continue
        out.append({"mutation": name, "text": variant})
    return out


def generate(seeds: Sequence[Dict[str, str]], seed: int = 0, per_text: int = 3) -> List[Dict[str, str]]:
    """Expand attack documents into a labelled, reproducible attack corpus."""
    rng = random.Random(seed)
    generated = []
    for index, document in enumerate(seeds):
        text = document.get("text") or ""
        if not text:
            continue
        for variant in mutate(text, seed=rng.randrange(1000000), per_text=per_text):
            generated.append({
                "id": "GEN-%s-%04d-%s" % (document.get("id", "doc"), index, variant["mutation"]),
                "category": document.get("category", "unknown"),
                "layer": document.get("layer", "direct"),
                "mutation": variant["mutation"],
                "parent": document.get("id", ""),
                "text": variant["text"],
            })
    return generated
