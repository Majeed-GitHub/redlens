# The self-improvement loop

A hand-written rule pack stops improving the day its author stops thinking of new
phrasings. This loop keeps the pressure on:

    python -m redlens evolve --corpus-dir benchmarks/redlens-bench-v1 --rounds 3 --seed 7

Four stages, all offline, all reproducible from a seed:

| Stage | What it does | Module |
| --- | --- | --- |
| generate | rewrites known attacks the way an adversary would: encode, obfuscate, respell, split, reframe, swap trigger words | evolution/attackgen.py |
| mine | runs the pack over the generated attacks and both benign corpora, reporting what it missed and what it wrongly flagged | evolution/miner.py |
| synthesise | finds word phrases that appear in a miss and in no benign sample, and builds candidate rules from them | evolution/synthesizer.py |
| accept | keeps a candidate only if it measurably improves and changes nothing else | evolution/accept.py |

## What it is not

It is not a self-learning model, and calling it that would be the kind of overclaim
this project exists to avoid. Nothing is trained: no gradient, no weights, no GPU.
What improves is the rule pack, by search under a hard acceptance gate, and the
improvement is measured on every run.

## The gate is the whole point

A system that can change its own detection is worthless unless something refuses
its bad ideas. A candidate is accepted only when all of these hold:

- it catches at least one attack the current pack misses;
- it adds no false positive on the benign or hard-negative corpora;
- it is not a kill switch;
- it does not push p99 latency past the budget;
- its phrase is not scaffolding the generator itself added;
- its phrase is not subsumed by an already accepted rule.

Every refusal is reported with a reason. A rejection is a result: it says the
phrase that looked discriminating was not.

## A run, in numbers

    537 generated attacks from 205 seeds, 107 benign and hard-negative samples
    recall 91.6% -> 92.0%, false positives 0 -> 0
    round 1: missed 45, proposed 3, accepted 1  (prior\s+guidance)
    round 2: missed 43, proposed 3, accepted 0
    round 3: missed 43, proposed 3, accepted 0
    8 proposals refused, each with a reason

Recall moves in small steps because the pack is already strong. The interesting
column is the refusals: three proposals per round, almost all rejected. That is
what an honest gate looks like.

## What the first real run found

Three things, two of them uncomfortable.

**The loop was learning its own scaffolding.** The first generator prefixed encoded
payloads with "Here is the encoded payload: ", and the loop duly accepted a rule
matching that prefix. It was not finding attacks, it was finding itself. The
generator no longer adds prose to encoded payloads, and the gate refuses any
candidate whose phrase comes from the generator's own frame text.

**It found a real detector bug.** Letter-spaced attacks survived the pack: the
existing view rejoined runs of single letters only when they were separated by two
or more spaces, so "h e a d e r s :" never collapsed, and neither did runs written
with ordinary single spaces. Fixing both raised baseline recall on the generated
corpus from 88.3 to 91.6 percent before a single rule was added. The loop paid for
itself twice over in detector quality alone.

**Two of the gate's own checks were dead code.** The scaffolding and subsumption
guards extracted words from the rule's regex instead of its phrase, so they read
"b transmit s the s api s key b" and always passed. A unit test caught it. Both now
read the phrase, and both have a test that fails if they stop working.

## Limits

- **The generator bounds what can be discovered.** A weakness no mutation reaches is
  invisible to the loop. That is the self-play trap, and the mitigation is more
  human-written mutations, not more iterations.
- **Generated attacks are not benchmark cases.** They land in a separate pending
  corpus and never touch benchmarks/redlens-bench-v1, which stays frozen so the
  published numbers keep meaning the same thing.
- **Accepted rules are proposals.** The loop writes them into its report; a human
  promotes one into rules.py together with its corpus case, as CONTRIBUTING
  requires. The loop never edits the rule pack itself.
- **It optimises exactly what it measures.** Recall on generated attacks and zero
  false positives on two benign corpora. Nothing that is not in a corpus.
