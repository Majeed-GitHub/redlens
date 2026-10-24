# Changelog

All notable changes. One line per change, in the commit that made it.

## 0.4.0 - deployable, not just importable

- examples/mcp_proxy: a stdlib-only stdio proxy that scans every tool manifest
  and every tool call passing through it, in monitor or enforce mode, writing a
  JSON audit line per decision. Replaces a poisoned manifest with a JSON-RPC
  error rather than handing it to the client.
- action/action.yml: a composite GitHub Action that installs RedLens from the
  repository, verifies it against the frozen corpus, and scans a manifest. Ships
  this way because a composite action needs no workflow scope to publish.
- .pre-commit-hooks.yaml: manifest and prompt hooks.
- docs/integration.md: where to place the check on five boundaries, what each
  costs, and the audit line each should emit.
- examples/openai_agents_guardrail.py and examples/langchain_guard.py.
- 5 end-to-end proxy tests driving a fake server with one honest and one
  poisoned tool.

## 0.3.0 - tool-call arguments, hidden content, and a written scope

- Add scan_tool_call: inspects the arguments of a single call for secret paths,
  secret-shaped values, traversal, nested shell commands, and secret plus egress.
  Decision is capped at review by design.
- Add hidden-content extraction for passive layers: HTML comments, markdown
  reference definitions and alt text, collapsed blocks, CSS-hidden spans, data
  URIs. Findings from hidden regions are upgraded one severity step and carry a
  readable layer suffix.
- Add --explain-hidden to print exactly what the extractor saw.
- Add a Scope and non-goals section to the README, with a layer coverage table,
  and enforce it in redlens audit.
- Every kill switch now carries a rationale naming the benign input it may never
  fire on; audit fails without one.
- Add 5 retrieved-layer corpus cases and 4 hard negatives for hidden content.

## 0.2.0 - cross-turn sessions, output scanning, manifest analysis

- ScanSession with the crypto-context co-occurrence kill switch (RL-210).
- scan_output: canaries, credentials, JWT, private keys, markdown-image
  exfiltration, code sinks, sink plus environment plus network, prompt leaks.
- scan_tool_manifest: invisible instruction smuggling, capability combinations,
  schema abuse, name shadowing.
- Rule schema gains negative_patterns, requires, kill_switch, ttl, source,
  atlas, tests.
- Per-layer review thresholds, category-diversity bonus, kill-switch class.
- 42 hard negatives; six real false positives found and fixed.
- audit: precision, kill-switch budget, determinism, latency.
- Literal pre-filter for 63 of 112 rules.

## 0.1.0 - first release

- 112 rules across 11 categories; layered decoding and respelled views.
- 198 attack cases, 61 benign; 100 percent recall, 0 false positives.
- CLI: scan, eval, rules.
