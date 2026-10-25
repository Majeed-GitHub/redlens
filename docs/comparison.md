# Comparison with open-source guardrails

**Status: no head-to-head result exists, and this file says why.**

An acquirer or an enterprise buyer will ask "how do you compare to X". The honest
answer today is that the comparison has not been run, because the alternatives
could not be installed and run in the environment this project was built in. That
is recorded here rather than filled in with an estimate.

## What was checked, and what it showed

Both mainstream open-source options were probed for installability:

| Project | Installable here | Why not |
| --- | --- | --- |
| llm-guard (0.3.16) | no | pulls torch>=2.4 and transformers==4.51.3: a multi-gigabyte install, plus model downloads at first use |
| rebuff (0.1.1) | no | requires an OpenAI API key and pinecone-client: it is not a local detector at all |

Those are the actual dependency lists from the distributions, not opinions about
them. Nothing here says either project detects worse than RedLens; that has not
been measured, and a row without a measurement is a guess with a table around it.

What the probe does show is the shape of the trade-off: the alternatives are
hundreds of megabytes before they detect anything, need a network at run time, and
in one case need a hosted vector database. RedLens is a standard-library import
that runs in an air-gapped container. That difference is measurable without
running either of them, and it is the reason the zero-dependency constraint
exists.

## The protocol for anyone who wants to run it

    git clone https://github.com/Majeed-GitHub/redlens
    cd redlens
    python -m redlens eval --corpus-dir benchmarks/redlens-bench-v1

For a fair comparison, run both tools on the same frozen corpus and report:

| Field | RedLens 0.8.2 | your tool |
| --- | --- | --- |
| recall on attacks.jsonl | 205/205 (measured) | |
| false positives on benign.jsonl + benign_hard.jsonl | 0/107 (measured) | |
| p50 latency, 59-byte message | 0.9 ms (measured) | |
| p50 latency, 4 KB document | 33 ms (measured) | |
| runtime dependencies | 0 (measured) | |
| network egress at run time | none (by construction) | |
| held-out recall, benchmarks/redlens-heldout-v1 | 234/250 = 93.6% (measured) | |

Submit a pull request with the row filled and the exact command, hardware and
Python version. A blank row is better than an estimated one, and a row that shows
RedLens losing is welcome: the reliability score of this project is its ability to
publish unflattering numbers, and evaluating my own scanner against a competitor
is exactly the situation where that discipline has to hold.
