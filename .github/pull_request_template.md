## What this changes

One sentence. One concern per pull request.

## Rule changes

If this adds or changes a rule, every box must be checked.

- [ ] An attack case in benchmarks/redlens-bench-v1/attacks.jsonl hits the rule
- [ ] A hard negative in benchmarks/redlens-bench-v1/benign_hard.jsonl does not, with a sentence proving why it cannot
- [ ] A unit test asserts both directions
- [ ] CHANGELOG has a line

## Kill switches

If this adds a kill switch, answer all three.

- The narrowest substring that defines this attack: _
- The legitimate input that contains that substring: _
- How many benign corpus cases contain it (must be 0): _

## Gate output

Paste the tail of all three, run from the repository root.

    python -m unittest discover -s tests -t .
    python -m redlens eval --corpus-dir benchmarks/redlens-bench-v1
    python -m redlens audit

## Negative results

If this adds a component, state its measured delta from tools/ablations.py. A delta of zero is
a valid answer and belongs in docs/technical-report.md.
