"""RedLens - prompt-injection and agent-tool security scanner."""

from .detectors import Finding, normalized_layers, scan_text
from .manifest import scan_tool_manifest
from .output_scan import scan_output
from .rules import (
    CCI_SIGNALS,
    OUTPUT_RULES,
    RULES,
    SEVERITY_WEIGHTS,
    STRUCTURAL_RULES,
    Rule,
)
from .scanner import (
    Report,
    scan,
    scan_messages,
    scan_retrieved,
    scan_tool_definition,
    scan_tool_output,
)
from .session import ScanSession, detect_crypto_context_injection
from .tool_call import scan_tool_call

__version__ = "0.3.1"

__all__ = [
    "CCI_SIGNALS",
    "Finding",
    "OUTPUT_RULES",
    "RULES",
    "Rule",
    "SEVERITY_WEIGHTS",
    "STRUCTURAL_RULES",
    "Report",
    "ScanSession",
    "detect_crypto_context_injection",
    "normalized_layers",
    "scan",
    "scan_messages",
    "scan_output",
    "scan_retrieved",
    "scan_text",
    "scan_tool_definition",
    "scan_tool_call",
    "scan_tool_manifest",
    "scan_tool_output",
    "__version__",
]
