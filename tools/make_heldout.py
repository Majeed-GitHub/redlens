"""Build a held-out benchmark the evolution loop must never see.

The critique that matters is self-reference: the loop generates attacks from the
frozen corpus and measures against the same pack, so its own numbers prove less
than they look. This builds a second corpus from a seed that no development run
used, and redlens evolve refuses to seed from it.

    python tools/make_heldout.py
"""

import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from redlens.evolution import generate  # noqa: E402

FROZEN = os.path.join(ROOT, "benchmarks", "redlens-bench-v1")
HELDOUT = os.path.join(ROOT, "benchmarks", "redlens-heldout-v1")
HELDOUT_SEED = 99991
SAMPLE = 250


def load(name):
    with open(os.path.join(FROZEN, name), "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main():
    os.makedirs(HELDOUT, exist_ok=True)
    seeds = load("attacks.jsonl")
    pool = generate(seeds, seed=HELDOUT_SEED, per_text=3)
    # Deterministic sample: sort by id and take every nth, so the file is stable.
    pool.sort(key=lambda row: row["id"])
    step = max(1, len(pool) // SAMPLE)
    sample = pool[::step][:SAMPLE]

    with open(os.path.join(HELDOUT, "attacks.jsonl"), "w", encoding="utf-8", newline="\n") as handle:
        for row in sample:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")

    manifest = {"version": "redlens-heldout-v1", "seed": HELDOUT_SEED, "cases": len(sample), "files": {}}
    for name in os.listdir(HELDOUT):
        path = os.path.join(HELDOUT, name)
        if os.path.isfile(path) and name != "MANIFEST.json":
            manifest["files"][name] = hashlib.sha256(open(path, "rb").read()).hexdigest()
    with open(os.path.join(HELDOUT, "MANIFEST.json"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(manifest, indent=2) + "\n")

    print("wrote %d held-out cases to %s (seed %d)" % (len(sample), HELDOUT, HELDOUT_SEED))


if __name__ == "__main__":
    main()
