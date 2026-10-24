# redlens-bench-v1

A frozen corpus for measuring prompt-injection and tool-poisoning detectors. It is the corpus the
RedLens report is written against, and the corpus anyone else can run.

## Contents

| File | Cases | What it is |
| --- | --- | --- |
| attacks.jsonl | 205 | graded attacks across 11 categories, with layer and category labels |
| benign.jsonl | 61 | ordinary text a scanner must not flag |
| benign_hard.jsonl | 46 | text that uses attack vocabulary legitimately: code review comments about eval, base64 blobs in configs, license comments, alt text |
| tool_call_attacks.jsonl | 8 | malicious tool-call arguments |
| tool_call_benign.jsonl | 8 | legitimate tool-call arguments |

MANIFEST.json contains the SHA-256 of every file and the case counts.

## Running it

    git clone https://github.com/Majeed-GitHub/redlens
    cd redlens
    python -m redlens eval --corpus-dir benchmarks/redlens-bench-v1

To measure your own detector, report recall on attacks.jsonl, false positives across benign.jsonl
and benign_hard.jsonl, and p50 and p99 latency on a 59-byte message and a 4 KB document, with the
hardware, Python version and exact command. See CONTRIBUTING.md.

## Licence

The corpus is licensed CC-BY-4.0, separately from the MIT-licensed code, so it can be reused and
redistributed with attribution. See LICENSE-CC-BY-4.0.

## Honesty notes

- The corpus was written by the same author as the rules. That is a conflict of interest; the hard
  negatives reduce it, and publishing the corpus for others to attack is the mitigation.
- No incident, CVE or third-party benchmark number appears anywhere in this corpus or in the
  RedLens documentation, because none was verified from its primary source while it was written.
- The corpus is versioned, not living: v1 is frozen. Changes belong to v2, with a changelog.
