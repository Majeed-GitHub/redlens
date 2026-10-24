"""Command line interface.

    redlens scan "ignore all previous instructions"
    redlens scan --file prompt.txt --json
    cat retrieved_doc.md | redlens scan --layer retrieved
    redlens eval
    redlens rules
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .rules import RULES, by_category
from .scanner import (
    DECISION_ALLOW,
    DECISION_BLOCK,
    DECISION_CLEAN,
    DECISION_REVIEW,
    scan,
    worst,
)

CORPUS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

FAIL_ON_LEVELS = {
    "any": {DECISION_ALLOW, DECISION_REVIEW, DECISION_BLOCK},
    "review": {DECISION_REVIEW, DECISION_BLOCK},
    "block": {DECISION_BLOCK},
}


def _read_input(args) -> str:
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read()
        except OSError as exc:
            raise SystemExit("cannot read %s: %s" % (args.file, exc))
    if args.stdin or not args.text:
        if sys.stdin is None or sys.stdin.isatty():
            return args.text or ""
        return sys.stdin.read()
    return " ".join(args.text)


def cmd_scan(args) -> int:
    text = _read_input(args)
    report = scan(text, target=args.target or (args.file or "input"), layer=args.layer)
    if args.json:
        print(report.to_json(indent=2))
    else:
        print(report.summary())
    if args.fail_on:
        thresholds = FAIL_ON_LEVELS[args.fail_on]
        return EXIT_FINDINGS if report.decision in thresholds else EXIT_CLEAN
    return EXIT_CLEAN


def _load_jsonl(path: str):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def cmd_eval(args) -> int:
    """Run the shipped corpus and report detection quality."""
    corpus_dir = args.corpus_dir or CORPUS_DIR
    attacks = _load_jsonl(os.path.join(corpus_dir, "attacks.jsonl"))
    benign = _load_jsonl(os.path.join(corpus_dir, "benign.jsonl"))

    if not attacks:
        print("no attack corpus found at " + corpus_dir, file=sys.stderr)
        return EXIT_ERROR

    caught = 0
    per_category = {}
    missed = []
    for row in attacks:
        report = scan(row["text"], target=row.get("id", "attack"), layer=row.get("layer", "direct"))
        flagged = report.decision in (DECISION_REVIEW, DECISION_BLOCK)
        per_category.setdefault(row.get("category", "unknown"), [0, 0])
        per_category[row["category"]][1] += 1
        if flagged:
            caught += 1
            per_category[row["category"]][0] += 1
        else:
            missed.append((row.get("id"), row.get("category"), report.score))

    false_positives = 0
    for row in benign:
        report = scan(row["text"], target=row.get("id", "benign"), layer=row.get("layer", "direct"))
        if report.decision in (DECISION_REVIEW, DECISION_BLOCK):
            false_positives += 1

    recall = caught / len(attacks)
    fp_rate = (false_positives / len(benign)) if benign else 0.0

    print("RedLens corpus evaluation")
    print("  attacks          : %d" % len(attacks))
    print("  detected         : %d (recall %.1f%%)" % (caught, recall * 100))
    print("  benign samples   : %d" % len(benign))
    print("  false positives  : %d (rate %.1f%%)" % (false_positives, fp_rate * 100))
    print("  by category:")
    for category in sorted(per_category):
        hit, total = per_category[category]
        print("    %-20s %d/%d" % (category, hit, total))
    if missed:
        print("  missed samples:")
        for sample_id, category, score in missed[:20]:
            print("    %-16s %-20s score=%d" % (sample_id, category, score))

    if args.min_recall is not None and recall < args.min_recall:
        print("FAIL: recall %.3f below required %.3f" % (recall, args.min_recall))
        return EXIT_FINDINGS
    if args.max_fp is not None and fp_rate > args.max_fp:
        print("FAIL: false-positive rate %.3f above allowed %.3f" % (fp_rate, args.max_fp))
        return EXIT_FINDINGS
    return EXIT_CLEAN


def cmd_rules(args) -> int:
    grouped = by_category()
    if args.json:
        payload = [
            {
                "id": rule.id,
                "category": rule.category,
                "severity": rule.severity,
                "description": rule.description,
                "owasp": rule.owasp,
                "pattern": rule.pattern,
            }
            for rule in RULES
        ]
        print(json.dumps(payload, indent=2))
        return EXIT_CLEAN
    print("RedLens rule pack: %d rules" % len(RULES))
    for category in sorted(grouped):
        rules = grouped[category]
        print("\n%s (%d)" % (category, len(rules)))
        for rule in rules:
            print("  %-7s %-9s %s" % (rule.id, rule.severity, rule.description))
    return EXIT_CLEAN


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redlens",
        description="Scan LLM and agent input for prompt injection, tool poisoning and evasion.",
    )
    parser.add_argument("--version", action="version", version="redlens " + __version__)
    sub = parser.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="scan text, a file or stdin")
    scan_parser.add_argument("text", nargs="*", help="text to scan")
    scan_parser.add_argument("--file", "-f", help="read the text from this file")
    scan_parser.add_argument("--stdin", action="store_true", help="read the text from stdin")
    scan_parser.add_argument("--layer", default="direct",
                             choices=["direct", "retrieved", "tool_output", "tool_definition"],
                             help="where the content came from")
    scan_parser.add_argument("--target", help="label used in the report")
    scan_parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    scan_parser.add_argument("--fail-on", choices=sorted(FAIL_ON_LEVELS),
                             help="exit 1 when the decision reaches this level")
    scan_parser.set_defaults(func=cmd_scan)

    eval_parser = sub.add_parser("eval", help="run the shipped attack and benign corpora")
    eval_parser.add_argument("--corpus-dir", help="directory holding attacks.jsonl and benign.jsonl")
    eval_parser.add_argument("--min-recall", type=float, help="fail when recall is below this")
    eval_parser.add_argument("--max-fp", type=float, help="fail when the false-positive rate is above this")
    eval_parser.set_defaults(func=cmd_eval)

    rules_parser = sub.add_parser("rules", help="list the rule pack")
    rules_parser.add_argument("--json", action="store_true")
    rules_parser.set_defaults(func=cmd_rules)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_CLEAN
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
