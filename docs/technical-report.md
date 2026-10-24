# RedLens: a deterministic baseline for known-pattern prompt injection

Version 0.3.1. Every number in this report was produced by the commands in section 10,
on the hardware stated in section 7, against the corpus frozen in benchmarks/redlens-bench-v1.

## 1. Abstract

Hosted ML guardrails are evaluated against benchmarks that are not public, on corpora that are
not reproducible, with false-positive rates that are rarely reported. RedLens takes the opposite
position for the subset of attacks that are known patterns: a zero-dependency rule engine with a
graded corpus, an auditable decision path, and a published false-positive discipline. The artifact
is not the scanner; it is the **baseline the scanner provides** - a free, reproducible floor that a
hosted guardrail can be measured against. On the frozen corpus, RedLens recovers 205 of
205 attack cases with zero false positives across 107 benign and hard-negative samples, at
0.74 ms median latency on a typical message and 31.9 ms on a 4 KB document. Its own ablations show
that normalisation contributes 26 of those cases, negative patterns contribute all three
false-positive fixes, the co-occurrence engine contributes half of the session detections, and
two scoring components contribute nothing measurable on this corpus. Those two are reported as
negative results rather than quietly kept.

## 2. Thesis

Determinism, auditability and zero dependencies are the properties that decide adoption for a
security control at the text boundary; detection quality alone does not. A deterministic scanner
that returns the same verdict twice and names the rule is deployable in a CI gate, a proxy, or an
incident review. A hosted classifier with a 3 percent false-positive rate and an unknown vendor
model is not, no matter how good its benchmark.

Therefore RedLens is positioned as the floor, not the ceiling: the layer beneath an ML guardrail,
the corpus that guardrail is measured against, and the rule IDs quoted in a review.

## 3. Threat model

Coverage is claimed per attack capability, not per named incident. No incident, CVE or third-party
benchmark figure is cited in this project, because none has been verified from its primary source
in the environment where this was built.

| Attacker capability | Status | Mechanism or gap |
| --- | --- | --- |
| Verbatim replay of a known payload | covered | rule pack, 112 rules across 11 categories |
| Encoding and obfuscation | covered | base64, percent, hex, rot13, leetspeak, reversed, letterspaced, flattened, NFKC, homoglyph |
| Cross-turn payload assembly | covered | ScanSession co-occurrence, RL-210 |
| Hidden content in retrieved material | covered | tag characters, HTML comments, alt text, collapsed blocks, CSS-hidden, data URIs |
| Argument smuggling into a tool call | partially | sensitive paths, secret values, traversal, nested commands; not authorisation |
| Paraphrase and semantic restatement | not covered | no model in the loop, by design |
| Runtime-gated metadata (payload unlocks after N calls) | not covered | requires a runtime, not a scanner |
| Containment after compromise | not covered | network policy, isolation, least privilege |
| Multi-modal input (image, audio, PDF internals) | not covered | no adapters shipped |

## 4. Design

Six boundaries are scanned: input text, retrieved content, tool definitions, tool output, tool
arguments, and model output. Each is a layer, and the layer changes the verdict, not only the
message: content the user never typed is reviewed at a lower score threshold, because nobody is
watching it arrive.

Normalisation is layered. The engine scans raw text, an NFKC-normalised view with invisible
characters removed and homoglyphs folded, decoded views (base64, percent, hex) and respelled views
(rot13, leetspeak, reversed, flattened, letterspaced). A rule is reported from the least obfuscated
view that matches, so a plain-English hit is never inflated by an obfuscation bonus.

Scoring sums severity weights over distinct rules, adds a category-diversity bonus, adds for
obfuscation and for known dangerous pairings, and caps at 100. Kill switches - four of them -
block regardless of score and each carries a rationale naming the benign input it must never fire
on.

## 5. Ablations

Each component was removed in isolation and the corpus re-run. Recall is on 205 attack cases, false
positives on 107 benign plus hard-negative samples, latency on a 59-byte typical message
(median over 200 rounds) and a 4 KB document (median over 40 rounds).

| Variant | Recall | False positives | Hidden cases | p50 ms | p99 ms |
| --- | --- | --- | --- | --- | --- |
| Baseline | 205/205 | 0/107 | 7/7 | 0.74 | 1.08 |
| No normalisation or decoding | 179/205 | 0/107 | 7/7 | 0.19 | 0.32 |
| No negative patterns | 205/205 | 3/107 | 7/7 | 0.70 | 1.16 |
| No per-layer thresholds | 205/205 | 0/107 | 7/7 | 0.74 | 1.08 |
| No category-diversity bonus | 205/205 | 0/107 | 7/7 | 0.74 | 1.66 |
| No hidden-content view | 204/205 | 0/107 | 6/7 | 0.74 | 1.03 |
| No kill-switch class | 205/205 | 0/107 | 7/7 | 0.73 | 1.08 |
| No literal pre-filter | 205/205 | 0/107 | 7/7 | 0.82 | 1.01 |

Interpretation, including the results that do not flatter the design:

- **Normalisation and decoding carry 26 cases.** Removing it drops recall from 100 percent to 87.3
  percent. This is the single largest contributor and the reason the layer exists.
- **Negative patterns carry all three false positives.** Without them the hard-negative set flags
  three samples. This is the component that makes the zero-false-positive claim generalise rather
  than merely hold on the corpus it was tuned on.
- **The hidden-content view carries one case and all seven hidden cases depend on it for the
  tag-character path.** It was worth building, but the first corpus version showed it contributing
  nothing - the hidden payloads were also present in the visible text. The corpus was fixed to
  include payloads that only exist in the hidden view, which is what made the contribution
  measurable. This is recorded because it nearly became a shipped feature with no evidence.
- **Per-layer thresholds changed no decision on this corpus.** Every flagged attack already scores
  above 25 and no benign sample lands in the 18-25 band. The component is kept because the band it
  covers is real in deployment, but on this corpus it is unproven and is reported as such.
- **The category-diversity bonus changed no decision.** It affects ordering and explanation, not
  the verdict. Reported as unproven.
- **The kill-switch class changed no single-message decision**, because every kill switch is also
  high-scoring. It matters for the cross-turn case: without the co-occurrence engine, session
  detection falls from 2 of 2 attacks to 1 of 2, while benign sessions stay clean.
- **The literal pre-filter costs latency when removed**: 0.82 ms versus 0.74 ms on a typical
  message, and 50.5 ms versus 31.9 ms median on a 4 KB document. Detection is identical, so the
  pre-filter buys speed only, and only where the input is long.

## 6. Hard negatives

The corpus ships 61 ordinary benign samples and 46 hard negatives: text that uses attack vocabulary
legitimately. Six real false positives in the project's own rules were found this way.

| Rule | Benign input that exposed it | Fix |
| --- | --- | --- |
| RL-055 | code review comment: this function calls eval() on user input, it is a bug we must fix | negative pattern for defect framing |
| RL-055 | security note: the service uses subprocess with shell=True, the fix is a list | negative pattern |
| RL-053 | send the API key rotation reminder to the team channel | negative pattern for rotation, policy, runbook |
| RL-147 | list all the instructions in the setup guide | negative pattern for documentation context |
| RL-151 | quote it exactly as it appears in the contract | negative pattern for contract framing |
| RL-053 and RL-051 | give me five ideas; grant access only when the user is an admin | narrowed patterns to privilege objects |

## 7. Evaluation

Corpus composition (frozen, hashed in the benchmark manifest):

| Category | Cases |
| --- | --- |
| agent_tool_abuse | 26 |
| data_exfiltration | 6 |
| delimiter_spoof | 11 |
| encoding_evasion | 44 |
| indirect_injection | 18 |
| instruction_override | 30 |
| many_shot | 5 |
| role_hijack | 16 |
| safety_bypass | 13 |
| system_exfiltration | 21 |
| tool_poisoning | 15 |

Latency was measured on Windows, Python 3.12.14, single core, no warm cache:

| Input | p50 | p99 | Status |
| --- | --- | --- | --- |
| typical message (59 bytes) | 0.74 ms | 1.08 ms | gated at 5 ms by redlens audit |
| 4 KB document | 31.9 ms | 52.1 ms | reported, not gated |

Latency in this report comes from tools/ablations.py on an otherwise idle machine. redlens
audit, which runs alongside other work, prints a wider range: 0.7 to 2.0 ms p50 for a typical
message and 30 to 47 ms p50 for a 4 KB document. Capacity planning should use the range.

Determinism: scanning the same input twice produces byte-identical JSON. This is asserted in
redlens audit on every run. Latency figures move by a few percent between runs; the detection
counts in section 5 do not.

## 8. Comparison

The comparison is deliberately left blank. A row requires running the other tool on the same
frozen corpus on the same hardware; neither is installed in the environment where this report was
written, and an estimated row would be the exact failure mode this project exists to correct.

| Tool | Recall | False positives | p50 latency | Dependencies | Status |
| --- | --- | --- | --- | --- | --- |
| RedLens 0.3.1 | 205/205 | 0/107 | 0.74 ms | 0 | measured |
| (your tool) | | | | | protocol below |

Protocol for a submission: run against benchmarks/redlens-bench-v1, report recall, false-positive
count, p50 and p99 latency on the same two input sizes, dependency count, and the exact command.
Submissions as pull requests with a reproduction script.

## 9. Limitations

- A determined attacker who controls the language can phrase an injection that no rule matches.
  The corpus measures what the corpus contains.
- Paraphrase and semantic restatement are outside the design. A model-based layer could cover
  them; the moment it can block on its own, this project is no longer a deterministic baseline and
  the thesis dies with it.
- Runtime-gated metadata, containment, memory poisoning and multi-modal input are not covered and
  are named as such in the README scope table.
- The corpus is written by the same author as the rules. That is a conflict of interest. It is
  mitigated by the hard negatives and by publishing the corpus for others to attack, not solved.
- No incident, CVE or third-party benchmark figure is cited, because none was verified from a
  primary source while this was written.

## 10. Reproduction

    git clone https://github.com/Majeed-GitHub/redlens
    cd redlens
    python -m unittest discover -s tests -t .
    python -m redlens eval --corpus-dir benchmarks/redlens-bench-v1
    python -m redlens audit
    python tools/ablations.py

Each table above states its command; the ablation harness is kept in tools/ablations.py so the
section 5 numbers can be re-run rather than trusted.
