# Contributing

The hard-negative loop is the product. A rule without a hard negative is an opinion.

## Rule admission bar

A pull request that adds or changes a rule must contain all of the following. The PR template
blocks merge until every box is checked.

1. An attack case in benchmarks/redlens-bench-v1/attacks.jsonl that the rule catches.
2. A hard negative in benchmarks/redlens-bench-v1/benign_hard.jsonl that the rule must NOT catch,
   plus one sentence proving why it cannot: which substring of the benign sample is absent from
   the attack sample.
3. A unit test naming the rule id and asserting both directions.
4. Gate output pasted into the PR. Run all three and paste the tail:

       python -m unittest discover -s tests -t .
       python -m redlens eval --corpus-dir benchmarks/redlens-bench-v1
       python -m redlens audit

5. A CHANGELOG line.

## Kill switches

A kill switch blocks regardless of score. There are four; the ceiling is twelve, enforced by
redlens audit.

To add one you need:

- a rationale field naming the specific benign input it must never fire on, and why it cannot;
- a maintainer plus one reviewer;
- a demonstration that the budget still holds, and if it is full, which existing switch is demoted
  and which corpus case proves the demotion is safe.

If the benign input you named is in the corpus, the corpus must assert it stays clean.

## Negative results

If your change adds a component, measure it. tools/ablations.py shows the pattern: remove the
component, re-run the corpus, report the delta. If the delta is zero, say so in the PR and in
docs/technical-report.md. Two components in the current report are documented as contributing
nothing measurable; that is normal and expected, not embarrassing.

## Benchmark submissions

To get your tool into the comparison table in docs/technical-report.md, run it against
benchmarks/redlens-bench-v1 and submit: recall, false-positive count, p50 and p99 latency on a
59-byte message and a 4 KB document, dependency count, hardware and Python version, and the exact
command. A reproduction script is required. Estimated numbers are rejected; a blank row is better
than a guess.

## Style

- One concern per commit.
- No new runtime dependency in the core package, ever. Optional extras must degrade silently.
- No incident, CVE or third-party benchmark figure in any document unless it was opened and
  verified while writing that document. If you cannot verify it, describe the mechanism instead.
