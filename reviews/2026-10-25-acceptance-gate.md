# Review: the acceptance gate (2026-10-25)

**Reviewer:** loop-adversary, an independent agent given one instruction: break the gate.
**Scope:** redlens/evolution/accept.py and its measurement path. Review only; no project file edited.
**Verdict published as:** gate demoted to experimental, improvements marked unreproduced.

## Findings

| # | Defect | Status | Guard |
| --- | --- | --- | --- |
| D1 | Compiled and pre-filter caches keyed by rule id, so the gate could measure one pattern and accept another | fixed | caches keyed by (id, pattern, flags); fingerprint over the artifact; tests/test_gate_integrity.py::TestD1 |
| D2 | Scaffolding and subsumption lints read the rule description, not its pattern | fixed | phrase_of() reads literal words from the pattern; TestD2 |
| D3 | "Gain" counted generated rows, so one shared context line across many mutations looked like a large gain | fixed | gain counts rows and reports distinct parents; a seed-disjoint holdout must also gain; TestD3 |
| D4 | Gains double-counted inside a round; near-duplicate rules accepted | fixed | the pack plus the candidate is measured; refusals on zero new catches; TestD4 |
| D5 | max_accepted applied after the verdict, so reports claimed gains that were never applied | fixed | the cap is checked before the verdict; TestD5 |
| D6 | Latency gated per candidate, never for the accepted set | fixed | the measured set is accepted + candidate; TestD6 |
| D7 | "p99" was the sample maximum, on one fixed input, and a rule could be timed without ever executing | fixed | real quantile, pooled inputs drawn from the corpora, execution required; TestD7 |
| D8 | Verdict depended on the corpus layer field; benign rows are all direct | partly fixed | false positives are checked at every layer; TestD8 |

## What the reviewer could not break

- No rule that adds false positives on the two shipped benign corpora was accepted.
- The kill-switch refusal, the id-collision refusal and the single-word refusal held.
- No acceptance was provably caused by timing noise alone; the two that came close were D6 and D7b.

## Correction to the published numbers

The v0.6.0 release claimed one accepted rule and recall moving from 91.6 to 92.0 percent. **That
claim is not reproduced under the corrected gate and is marked as such in the README and the
changelog.** The corrected run on the same corpus reports zero accepted rules.

Two further defects were found while fixing the eight above, both in code the reviewer pointed at:

1. The synthesiser rebuilt a phrase's words joined by whitespace, so a phrase whose original text
   contained "://", "." or "%20" could never match its own parent attack.
2. The literal-word extractor read a \\u062a escape as the text "062a", so a rule written with
   escapes appeared to require a string that never occurs, and the pre-filter skipped it.

## Honest outcome

With the corrected gate, the loop accepts nothing on the frozen corpus. Its holdout requirement
demands that a synthesised phrase catch attacks it was not derived from, and phrase-level synthesis
rarely does. That is a negative result about the synthesiser, not about the gate, and it is
published as one.
