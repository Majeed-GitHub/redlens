"""RedLens - prompt-injection and agent-tool security scanner."""

from .detectors import Finding, normalized_layers, scan_text
from .rules import RULES, SEVERITY_WEIGHTS, Rule
from .scanner import (
    Report,
    scan,
    scan_messages,
    scan_retrieved,
    scan_tool_definition,
    scan_tool_output,
)

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "Report",
    "Rule",
    "RULES",
    "SEVERITY_WEIGHTS",
    "scan",
    "scan_messages",
    "scan_retrieved",
    "scan_text",
    "scan_tool_definition",
    "scan_tool_output",
    "normalized_layers",
    "__version__",
]
