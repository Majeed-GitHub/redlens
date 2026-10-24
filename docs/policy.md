# Policy and the audit trail

The scanner answers "does this look like an attack". Policy answers the question
an auditor actually asks: "was this agent allowed to do that at all". A tool call
can be perfectly clean - no injection anywhere in the text - and still be out of
bounds, because the agent is reaching a credential store it should never touch.

RedLens ships both, and takes the stricter answer.

## The policy document

JSON rather than YAML, because the package carries no dependencies and the
standard library parses JSON.

    {
      "version": 1,
      "default": "review",
      "tools": {
        "read_file":    {"allow": {"path": {"within": ["./project", "/srv/data"]}}},
        "http_request": {"allow": {"url": {"hosts": ["api.internal.example", "*.trusted.example"]}}},
        "run_command":  {"require_confirmation": true}
      },
      "rules": [
        {"id": "POL-001", "when": {"tool": "run_command"}, "action": "deny",
         "reason": "shell execution is not permitted for this agent"},
        {"id": "POL-002", "when": {"tool": "*delete*"}, "action": "deny",
         "reason": "destructive tools are not permitted for this agent"}
      ]
    }

Evaluation order, first match wins:

1. the rules list, in order: tool globs and argument-glob conditions;
2. the per-tool allow constraints: within (path roots), hosts (host allowlist),
   matches (argument glob);
3. the per-tool deny constraints;
4. require_confirmation, which answers review;
5. the document default.

Path containment is textual: a path is normalised, .. is resolved without touching
the filesystem, and the result must sit inside the declared root. A path that
escapes the root by any amount is denied, not silently clamped.

## Combining policy with the scanner

    from redlens import Policy, combine, scan_tool_call

    policy = Policy.load("policy.json")
    report = scan_tool_call(tool_name, arguments, tool_manifest=manifest)
    action = combine(policy.evaluate(tool_name, arguments).action, report.decision)

    # allow < review < deny
    if action == "deny":
        refuse()

Policy says what the agent may do; the scanner says what the text is trying to
do. Scanning alone misses the clean call that is out of scope. Policy alone misses
the in-scope call that has been hijacked.

## The audit trail

    from redlens import AuditLog, verify_audit_log

    log = AuditLog("audit.jsonl")
    log.append("tool_call_denied", tool="read_file", rules=["RL-501"], arguments=["path"])

Every record commits to the hash of the one before it, so changing any earlier
line breaks every line after it and verification fails at that record's sequence
number:

    python -m redlens verify-log --file audit.jsonl

What belongs in a record: the event, the tool, the decision, the score, the rule
ids, and the argument names. What must never belong in it: argument values. The
scanner's evidence strings can contain a credential or a key path, and an audit
log is long-lived, widely readable, and shipped to ticketing systems.

## Limits, stated plainly

- This is tamper *evidence*, not tamper proofing. It makes silent edits loud.
- **Deleting the final line cannot be detected**, because nothing follows it.
  If that matters, anchor the last hash somewhere else: a ticket, a git commit,
  a signature. Everything before the anchor is still protected.
- Policy is not authorisation. It sees the arguments of a call, not the intent
  behind it, and it cannot tell whether the user consented to the tool being
  available at all. Pair it with an approval flow for anything destructive.
- A policy that is wrong is worse than no policy: it produces confident denials.
  Start in the proxy's monitor mode, read the log for a week, then enforce.
