# Integration

Where to put the check, what it costs, and what it does not protect you from.
Every recipe names the audit line it should produce.

## 1. Plain Python gate

    from redlens import scan, scan_output

    report = scan(user_message, layer="direct")
    if report.decision == "block":
        log.warning("prompt_injection_blocked rules=%s", sorted(f.rule_id for f in report.findings))
        return refusal()
    if report.decision == "review":
        log.info("prompt_injection_review rules=%s", sorted(f.rule_id for f in report.findings))

    answer = call_model(user_message)
    out = scan_output(answer, system_prompt=SYSTEM_PROMPT, canaries=CANARIES)
    if out.decision == "block":
        log.warning("output_blocked rules=%s", sorted(f.rule_id for f in out.findings))
        return refusal()

Latency, from tools/ablations.py: 0.75 ms p50 on a 59-byte message, 31.9 ms p50 on a 4 KB
document. redlens audit reports a run-to-run range of 0.7-2.0 ms and 30-47 ms respectively,
because the machine is not idle. Use the range for capacity planning, not the single figure.
Does not protect: authorised-tool misuse, containment, model semantics.
Audit line: decision, score, rule ids and argument names. Never the argument values: a security
log should not become the place secrets are collected.

## 2. MCP proxy

    # offline, using the server this repository ships:
    python examples/mcp_proxy/proxy.py --server "python examples/mcp_proxy/fake_server.py" \
        --mode monitor --log audit.jsonl

    # a real server: on Windows npx is npx.cmd, which the proxy launches through cmd /c
    python examples/mcp_proxy/proxy.py --server "npx -y @modelcontextprotocol/server-filesystem /tmp" \
        --mode enforce --log audit.jsonl

Start in monitor for a week, read the log, then switch to enforce.
Latency: one scan per tool call and one per manifest.
Audit line: one JSON object per decision, including allowed ones, with rule ids and argument
names only. The records are hash-chained, so redlens verify-log detects edits after the fact.

## 3. GitHub Action

    - uses: Majeed-GitHub/redlens/action@main
      with:
        manifest: mcp/tools.json
        fail-on: block

The composite action installs RedLens from the repository, runs its own test
suite and audit, then scans the manifest you point it at. It ships as a composite
action rather than a workflow because a composite action does not need the
workflow scope on the publishing token.

## 4. pre-commit

    repos:
      - repo: https://github.com/Majeed-GitHub/redlens
        rev: v0.4.0
        hooks:
          - id: redlens-manifest
          - id: redlens-prompts

The hooks use language: system, so install RedLens into the environment
pre-commit runs in:

    python -m pip install git+https://github.com/Majeed-GitHub/redlens

## 5. Retrieval boundary

    from redlens import scan_retrieved
    report = scan_retrieved(chunk, source="policy.pdf#p12")

Retrieved content is reviewed at a lower threshold, 18 rather than 25, and
indirect-injection findings are upgraded one step, because the user never sees
that text arrive.

## Order matters

Scan in this order and stop at the first block:

1. tool arguments, before the call executes (scan_tool_call, plus a policy check)
2. retrieved chunks, before they enter the context (scan_retrieved)
3. tool definitions, before the client registers them (scan_tool_manifest)
4. tool output, before it is treated as fact (scan_tool_output)
5. the user message, before the model sees it (scan)
6. the model output, before the user sees it (scan_output)

Items 1 to 4 are the ones most teams skip, and they are the boundaries where
nobody is watching.

Where a tool call is subject to a policy, check both and take the stricter
answer: redlens policy reports what the agent is allowed to do, and the scanner
reports what the text is trying to do. A clean call can still be out of bounds.
