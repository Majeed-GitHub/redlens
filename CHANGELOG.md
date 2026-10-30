# Changelog

All notable changes. One line per change, in the commit that made it.

## 0.9.0 - the release that makes a team able to adopt it

- redlens/sarif.py: SARIF 2.1.0 export. Findings become review annotations in
  GitHub Code Scanning, Azure DevOps and any CI that reads SARIF, instead of
  scrollback. Rule metadata comes from the rule pack (regex rules and the
  structural ones alike), severity maps to a SARIF level, the offset becomes a
  line and column, and the fingerprint rides along as a partialFingerprint.
- redlens/identity.py: finding identity, and an honest one. The first design
  hashed the evidence window; measured against the shipped corpus it kept only
  13% of findings' identities once a sentence was added around them, because
  the window grows with the surrounding text. Identity is now positional -
  rule, target, line, occurrence - so anything whose line did not move keeps
  its identity. The trade-off is documented instead of hidden: text inserted
  above a finding makes it new again.
- redlens/baseline.py: baseline suppression. Nobody enables a scanner that
  reports fifty pre-existing findings and blocks the build, so --save-baseline
  records what exists today and --baseline reports only what is new. The
  verdict is rescored after suppression, so a suppressed finding cannot keep
  a clean scan failing forever.
- redlens ci: scan a whole tree in one call and gate the build. Deterministic
  file discovery, dependency and cache directories skipped, a per-file size
  cap, one SARIF log for the tree, relative paths under the working directory,
  and one exit code.
- action/action.yml: the composite action now scans a path and can emit SARIF,
  so wiring a repository takes one step instead of a script.
- Version honesty fixed: __init__.py and pyproject.toml said 0.8.2 while
  v0.8.3 and v0.8.4 had been tagged, so 'redlens --version' and every SARIF
  log from those releases carried the wrong version. tests/test_hygiene.py now
  fails if the package, the metadata and the changelog disagree.
- 270 tests.

## 0.8.4 - the warning a stranger saw first

- redlens/evolution/synthesizer.py: the build_rule docstring was not raw and
  contained \s+, so Python 3.12 emitted a SyntaxWarning on import and a future
  version will make it an error.
- tests/test_hygiene.py: every module is compiled in memory with SyntaxWarning
  promoted, so the next one fails the suite.
- CI runs the same compileall gate before the test suite, so the warning
  breaks the build here instead of scrolling past a cloner's terminal.

## 0.8.3 - CI, and the integration recipes

- .github/workflows/ci.yml: tests on Python 3.9, 3.11, 3.12 and 3.13, plus the
  corpus evaluation, the latency and determinism audit, and the rule-pack
  export.
- docs/integration.md, docs/validation.md and docs/bedrock-runbook.md: the
  recipes for LangChain, the OpenAI Agents SDK and pre-commit; the protocol an
  outside tester runs; and the two-command Bedrock evaluation.

## 0.8.2 - the HTTP sidecar, which task-2 had been claiming for days

- redlens/service.py: a stdlib HTTP sidecar for callers that cannot import
  Python. GET /health, POST /scan, POST /scan/tool, POST /scan/session. The HTTP
  status carries the decision: 200 clean or allow_with_warnings, 422 review, 403
  block, so a caller can gate without parsing JSON.
- redlens serve runs it. A non-loopback bind without a token is refused rather
  than warned about; bodies are size-capped; /health needs no token and nothing
  else does.
- tests/test_service.py: 15 tests over a live socket, covering the status codes,
  the layer effect on the verdict, both tool and session endpoints, the auth
  split, the body cap and the non-loopback guard.
- Task board corrected: task-2 was marked in progress for days while no one was
  working it and the file did not exist. It is finished here. task-3 is marked
  completed because the harness repo it described does exist and is green.
- 225 tests.

## 0.8.1 - the gateway enforces, and the test that proves it

- examples/llm_gateway.py is hardened: streaming responses are refused rather
  than forwarded uninspected (opt in with --allow-streaming and the log records
  that the stream was unscanned), request bodies are size-capped, and a scanner
  failure fails closed by default instead of silently forwarding.
- The gateway now loads a policy and checks the tool calls the model asks for
  before the agent can execute them, so POL-GRANT applies at the gateway and not
  only in the library. Records carry rule ids and argument names, never values.
- Policy semantics fixed: a grant is an allowlist. Previously a granted tool fell
  through to the document default, so a policy with default: deny refused every
  tool the agent had been granted. Per-tool constraints still apply.
- tests/test_gateway.py: 15 end-to-end tests driving the real handler against a
  mock upstream, asserting that a blocked request never reaches the model, a
  canary-bearing response never reaches the client, an ungranted tool call is
  refused with POL-GRANT, streaming is a 501, the body cap is a 413, a failing
  scanner is a 503, and the audit chain verifies afterwards.
- 208 tests.

## 0.8.0 - the gate is content-addressed, and its old number is withdrawn

- The acceptance gate verifies the artifact, not the id: regex and pre-filter
  caches are keyed by (id, pattern, flags), every decision records a content
  fingerprint, and the gate refuses to measure a rule whose compiled pattern is
  not the one it holds.
- Eight defects found by an independent adversarial review are fixed, each with a
  regression test in tests/test_gate_integrity.py: measuring a different regex,
  lints reading the description, row-counted gains, double-counted gains, a cap
  applied after the verdict, per-candidate latency, p99 as the sample maximum,
  and layer-dependent verdicts.
- Latency is a real quantile over inputs drawn from the corpora, and a candidate
  that never fires is refused instead of timed at zero cost.
- Gains require a second, seed-disjoint holdout, so a rule matching shared
  context prose is refused.
- Fixed while fixing the above: phrase patterns rebuilt with whitespace could
  never match text containing punctuation, and the literal extractor read a
  unicode escape as literal hex text, which made the pre-filter skip the
  multilingual rules entirely.
- Withdrawn as unreproduced: the v0.6.0 claim of one accepted rule and recall
  moving 91.6 to 92.0 percent. Under the corrected gate the loop accepts nothing
  on the frozen corpus; the corrected run is published beside the old claim.
- 193 tests.

## 0.7.0 - runtime controls, and a held-out number

- Error-path injection is its own passive layer (error_output) with rules RL-601
  to RL-605: instructions in error text, recovery steps that smuggle a command,
  retry payloads, suggested debug affordances, and stack traces carrying orders.
- Manifest drift: redlens manifest --baseline reports a tool that appeared
  (RL-409) and a tool that gained a capability (RL-410).
- redlens agbom: a CycloneDX-shaped agent bill of materials with per-tool hashes
  and a capability inventory.
- Runtime least privilege: policy grants name the tools an agent may call at all,
  and an ungranted tool is refused with POL-GRANT even when the call is clean.
- redlens crosswalk: every rule mapped to its OWASP LLM Top 10 entry and NIST AI
  RMF function. OWASP Agentic and AIUC-1 are declared not mapped, with the reason,
  because neither document could be obtained.
- redlens log --format cef: SIEM export that verifies the hash chain first and
  refuses to emit an edited log without --force.
- examples/llm_gateway.py: a stdlib gateway in front of any OpenAI-compatible
  endpoint, scanning the request and the response.
- benchmarks/redlens-heldout-v1: 250 mutated attacks from a seed no development
  run used. redlens evolve refuses to seed from it. Measured recall on it is 93.6
  percent, against 100 percent on the tuned corpus.
- 169 tests.

## 0.6.0 - the closed loop

- redlens/evolution: generate attacks by mutation, measure the pack against them,
  synthesise candidate rules from phrases that separate a miss from benign text,
  and accept a candidate only when it catches something new without adding a false
  positive, staying inside the latency budget, being a kill switch, leaking the
  generator's own scaffolding, or duplicating an accepted rule.
- redlens evolve: runs the loop from the frozen corpus, prints before and after,
  and writes the full report, refusals included, as JSON.
- First real run: 537 generated attacks from 205 seeds, recall 91.6 to 92.0
  percent, zero false positives before and after, one rule accepted and eight
  proposals refused with reasons.
- The run exposed a detector gap: letter-spaced words with punctuation were never
  rejoined, which cost 22 of the 537 generated attacks. Fixed, and baseline recall
  rose from 88.3 to 91.6 percent before any rule was added.
- The same run exposed two dead checks in the gate: the scaffolding and
  subsumption guards parsed the rule regex instead of its phrase, so they always
  passed. Both fixed, with the unit test that caught it.
- The generator no longer prefixes prose to encoded payloads, because the loop
  learned that prefix instead of an attack.
- 146 tests.

## 0.5.0 - policy and a tamper-evident record

- redlens/policy.py: a JSON policy for what an agent is allowed to do - path roots,
  host allowlists, required confirmation, tool globs - evaluated before a call
  runs, and combined with the scanner so the stricter answer wins.
- redlens/audit_log.py: a hash-chained audit log. Every record commits to the
  previous one, so editing any earlier line is reported at its sequence number.
  redlens verify-log walks the chain.
- The MCP proxy takes --policy, keeps the manifest it read and hands it to the
  argument scanner (so a secret path given to an egress-capable tool is caught),
  and writes one record per decision with rule ids and argument names, never
  argument values.
- redlens eval now measures the tool-call corpus too.
- Fixes from an independent docs review: the proxy command works on Windows
  (cmd /c for .cmd shims, quote-safe splitting), the audit latency gate is a
  12 ms regression budget rather than a flaky 5 ms, and every stale number,
  example and claim in the README, integration guide and proxy guide was
  corrected against real output.

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
- Literal pre-filter for 57 of the 112 input rules.

## 0.1.0 - first release

- 112 rules across 11 categories; layered decoding and respelled views.
- 198 attack cases, 61 benign; 100 percent recall, 0 false positives.
- CLI: scan, eval, rules.
