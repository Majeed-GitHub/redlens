# Scanning MCP proxy

A drop-in stdio proxy that scans an MCP server's tool definitions and every tool
call before either reaches the client or the server. Stdlib only.

## Why a proxy and not a library call

A client library has to remember to call the scanner. A proxy cannot forget: the
process is the control. That is also the deployment shape a platform team can
actually ship, because it needs no changes to the agent.

## Use it

    # offline, against the server this repository ships:
    python examples/mcp_proxy/proxy.py \
        --server "python examples/mcp_proxy/fake_server.py" \
        --mode monitor \
        --log audit.jsonl

    # a real server. On Windows npx resolves to npx.cmd, and the proxy launches
    # .cmd shims through cmd /c, so the quoting below works as written:
    python examples/mcp_proxy/proxy.py \
        --server "npx -y @modelcontextprotocol/server-filesystem /tmp" \
        --mode enforce \
        --log audit.jsonl

In an MCP client config, replace the server command with the proxy:

    {
      "mcpServers": {
        "filesystem": {
          "command": "python",
          "args": [
            "C:/path/to/redlens/examples/mcp_proxy/proxy.py",
            "--server", "npx -y @modelcontextprotocol/server-filesystem /tmp",
            "--mode", "enforce",
            "--log", "audit.jsonl"
          ]
        }
      }
    }

## Modes

| Mode | Behaviour | Use it when |
| --- | --- | --- |
| monitor | scans, logs, forwards everything | first week, while you learn what your servers actually do |
| enforce | refuses poisoned manifests and calls at or above --deny-at | once the audit log is quiet |

The default is monitor on purpose: a security control that blocks on day one,
before anyone has read its findings, gets removed on day two.

## What it checks

- **tools/list responses**: the whole manifest at once. Invisible instructions,
  capability combinations, schema abuse, name shadowing. In enforce mode a
  manifest that trips a kill switch, or that scores a block decision, is replaced
  with a JSON-RPC error, so the client never receives the poisoned tools. Anything
  weaker is logged and forwarded: refusing a whole server on a single medium
  finding is how a control gets uninstalled.
- **tools/call requests**: the arguments. Secret paths, secret-shaped values,
  traversal, nested shell commands, and a secret path handed to a tool with
  network egress.
- Every decision appends one JSON line to the audit log, including the allowed ones, so the log
  is a complete record rather than a list of alerts. A record carries the timestamp, event, tool
  name, score, decision, the rule ids that fired, and the argument names involved. It never
  carries argument values: the log must not become the place secrets are collected, and the
  scanner's own evidence strings can contain them. Records are hash-chained, so redlens verify-log
  reports the exact position of any later edit.

## The audit line is the point

An incident review needs a record of what the agent was told and what it tried.
The proxy writes that record even in monitor mode, where nothing is refused:

    {"seq":7,"ts":"2026-10-24T18:02:11Z","event":"tool_call_flagged","tool":"read_file",
     "score":40,"decision":"review","rules":["RL-501"],"arguments":["path"],
     "prev":"...","hash":"..."}

Check the log for tampering after an incident:

    python -m redlens verify-log --file audit.jsonl

## Limits

The proxy sees what crosses stdio. It does not see a server that talks to the
network directly, does not sandbox the server process, and cannot stop a server
from doing something before it answers. It is the text boundary, not containment.

## Test it

    python -m unittest tests.test_mcp_proxy -v

The test drives the proxy against a fake server that publishes one honest tool
and one poisoned tool, and asserts both the forwarded and refused paths.
