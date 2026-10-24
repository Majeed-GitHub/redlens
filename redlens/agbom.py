"""Agent bill of materials.

An SBOM says which packages you ship. An AgBOM says which capabilities your agent
has: every tool it can call, what that tool can touch, and a hash of the manifest
it came from, so two agents can be compared and a change can be reviewed.

Emitted as CycloneDX-shaped JSON because an AgBOM nobody's tooling can read is a
document, not an artifact.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Sequence

from .manifest import _capabilities, _tool_parts

AGBOM_VERSION = "1.0"
RISKY = ("cred_access", "net_egress", "exec", "fs_write")


def _digest(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def build_agbom(tools: Sequence[Dict[str, Any]], agent: str = "unnamed-agent", server: str = "unknown") -> Dict[str, Any]:
    """Turn a tool manifest into a capability inventory the agent can be held to."""
    components: List[Dict[str, Any]] = []
    risky: List[str] = []

    for tool in tools or []:
        if not isinstance(tool, dict):
            continue
        name, description, schema = _tool_parts(tool)
        capabilities = _capabilities(name, schema)
        held = sorted(tag for tag, present in capabilities.items() if present)
        if any(tag in RISKY for tag in held):
            risky.append(name)
        components.append({
            "type": "machine-learning-model",
            "name": name,
            "description": description[:500],
            "properties": [{"name": "redlens:capability:" + tag, "value": "true"} for tag in held]
                          + [{"name": "redlens:tool-hash", "value": _digest({"name": name, "description": description, "schema": schema})}],
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + _digest({"agent": agent, "server": server, "tools": components})[:32],
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "component": {"type": "application", "name": agent},
            "properties": [
                {"name": "redlens:agbom-version", "value": AGBOM_VERSION},
                {"name": "redlens:server", "value": server},
                {"name": "redlens:tool-count", "value": str(len(components))},
                {"name": "redlens:risky-tool-count", "value": str(len(risky))},
            ],
        },
        "components": components,
        "dependencies": [{"ref": agent, "dependsOn": [component["name"] for component in components]}],
    }


def summarize(bom: Dict[str, Any]) -> str:
    properties = {entry["name"]: entry["value"] for entry in bom["metadata"]["properties"]}
    lines = [
        "AgBOM for %s" % bom["metadata"]["component"]["name"],
        "  server        : %s" % properties.get("redlens:server", "unknown"),
        "  tools         : %s" % properties.get("redlens:tool-count", "0"),
        "  risky tools   : %s" % properties.get("redlens:risky-tool-count", "0"),
        "  serial        : %s" % bom["serialNumber"],
    ]
    for component in bom["components"]:
        held = [entry["name"].split(":")[-1] for entry in component["properties"]
                if entry["name"].startswith("redlens:capability:")]
        lines.append("  %-18s %s" % (component["name"], ", ".join(held) or "no notable capability"))
    return "\n".join(lines)
