# The platform layer

Everything here exists because a scanner alone is not a control. Each piece is
stdlib only, testable offline, and honest about what it does not do.

## Error-path injection

The error handling loop is a trust boundary nobody watches. A tool that fails can
return an instruction, and the agent reading the failure is more likely to comply
than at any other moment.

    from redlens import scan
    report = scan(tool_error_message, layer="error_output")

error_output is a passive layer: indirect-injection findings are upgraded one
step, and the review threshold drops, because the text arrived from a system the
user never sees. New rules RL-601 to RL-605 cover instructions in error text,
recovery steps that smuggle a command, retry guidance with an embedded payload,
suggested debug affordances, and instructions hidden in a stack trace.

## Manifest drift

A toolset is a moving target: a server that only read files last week can add
network egress this week, and nobody notices.

    python -m redlens manifest --file tools.json --baseline tools.last-week.json

RL-409 reports a tool that was not there before, RL-410 reports a tool that gained
a capability, and the notes cover description growth and removed tools.

## Agent bill of materials

    python -m redlens agbom --file tools.json --agent support-agent --out agbom.json

CycloneDX-shaped JSON: every tool, the capabilities it holds, a hash per tool for
change detection, and a serial number derived from the toolset, so two agents can
be compared and a difference can be reviewed. Risky tools, those holding
credential access, network egress, execution or file write, are counted in the
metadata.

## Runtime least privilege

A grant is what an agent may call at all, independently of whether a call is clean:

    {
      "default": "allow",
      "grants": {"support-agent": ["get_weather", "read_file"]},
      "tools": {"read_file": {"allow": {"path": {"within": ["./project"]}}}}
    }

An agent with no grant entry is refused entirely, and a tool absent from its grant
is refused with POL-GRANT. A clean call outside the grant is still out of bounds,
which is the difference between scanning and least privilege.

## Standards crosswalk

    python -m redlens crosswalk --out crosswalk.json

Every rule mapped to the OWASP LLM Top 10 entry its family belongs to, the NIST AI
RMF function it serves, and its severity. The mapping is the project's own reading
and is labelled as such.

Two standards are deliberately **not mapped**: the OWASP Top 10 for Agentic
Applications and AIUC-1. Neither document was obtained while this was written, and
a control-by-control crosswalk to a standard nobody read is fabrication with a
schema. The file says so, in the file.

## SIEM export

    python -m redlens log --file audit.jsonl --format cef

CEF or JSONL. The export verifies the hash chain first and refuses to emit a log
that fails, unless asked with --force, because a forensic export that quietly
includes an edited record is worse than no export.

## Gateway for non-MCP model calls

The MCP proxy covers tool calls. examples/llm_gateway.py covers everything else: a
stdlib HTTP gateway in front of any OpenAI-compatible endpoint that scans the last
user turn on the way in, scans the model's answer on the way out, and writes the
same chained records.

    python examples/llm_gateway.py --upstream https://api.example.com --port 8787 --mode monitor --log audit.jsonl

It is a reference shape: no TLS termination, a thread per request, and no
credentials of its own.

## Held-out benchmark

The most serious critique of this project is self-reference: the evolution loop
generates attacks from the frozen corpus and measures against the pack that was
tuned on it. So there is a second corpus, built from a seed no development run
used:

    python tools/make_heldout.py
    python -m redlens eval --corpus-dir benchmarks/redlens-heldout-v1

250 cases, never seeded into redlens evolve, which refuses that directory by name.
The measured recall on it is **93.6 percent**, against 100 percent on the frozen
corpus the pack was tuned on. That gap is the honest measure of generalisation,
and it is the number to quote.

## What is not here, and cannot be

- **Kernel or eBPF sandboxing, immutable runtime boundaries.** Out of reach from
  a Python package, and on Windows there is no eBPF. Network egress policy,
  container isolation and least-privilege credentials belong to the platform, not
  to the text boundary. Saying otherwise would be the overclaim this project
  exists to avoid.
- **A SOC dashboard and policy management plane.** Not built: it is a product, not
  a library, and it needs a front end, storage and authentication.
- **Third-party validation.** Cannot be manufactured from inside the project. The
  protocol for submitting results is in CONTRIBUTING.md; the submissions have to
  come from other people.
- **Comparisons against hosted guardrails.** They cannot be run offline, and
  estimated numbers are not allowed here. The table in the technical report stays
  blank until someone runs one.
