# Independent validation

**Status: the protocol exists, the independent run does not.** This file is the
invitation and the rules. It is written now, while it is still empty, so that
whatever comes back cannot be presented selectively later.

## Why this matters more than another feature

Every number in this repository was produced by its author, on a corpus its author
wrote, against a rule pack its author tuned. The held-out benchmark reduces that
problem, and the published 6.4-point gap is the evidence that it reduces rather
than removes it. Only someone else running the thing can settle it.

## What counts as an independent run

Any of the following, published in `reviews/` with the raw output attached:

1. **A held-out run.** Run the frozen suite and the held-out suite, report both
   numbers, including if the held-out number is well below the frozen one.
2. **An adversarial review of a component**, like the one that produced
   reviews/2026-10-25-acceptance-gate.md. Read-only, reproductions required.
3. **A false-positive hunt.** Write benign text that looks like an attack until
   RedLens flags it, then submit it as a hard negative with the rule that fired.
   This is the most valuable contribution available and the easiest to do.

## Rules for a submission

- State the exact commands, the Python version and the hardware.
- Report what failed as prominently as what passed. A submission that only lists
  successes will not be merged.
- Do not modify the corpus to make a number better. New cases go to a new version.
- If the run contradicts a claim in the README or the technical report, say so in
  the submission. The README gets corrected; the submission stays.

## What has already been done in this direction

| Date | Reviewer | Scope | Outcome |
| --- | --- | --- | --- |
| 2026-10-25 | loop-adversary (independent agent) | the acceptance gate | 8 defects, all fixed, guards added |
| earlier | docs-reviewer (independent agent) | documentation against the code | 12 defects, all fixed |

Those are agent reviewers, not external humans, and this file does not pretend
otherwise. They are listed because they are the closest thing that exists, and
because one of them withdrew a published result.

## Template

    ## Independent run: <name or handle>
    - Date:
    - Commands run:
    - Python / hardware:
    - Frozen suite result:
    - Held-out suite result:
    - False positives found (case text, rule id):
    - What contradicted the documentation:
