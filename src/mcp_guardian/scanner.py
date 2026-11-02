from __future__ import annotations

import json
from pathlib import Path

from mcp_guardian import __version__
from mcp_guardian.detectors.prompt_injection import PromptInjectionDetector
from mcp_guardian.detectors.return_channel import ReturnChannelDetector
from mcp_guardian.detectors.tool_poisoning import ToolPoisoningDetector
from mcp_guardian.models import Finding, ScanResult, ScanTarget


class MCPScanner:
    def __init__(self) -> None:
        self._detectors = [
            PromptInjectionDetector(),
            ToolPoisoningDetector(),
            ReturnChannelDetector(),
        ]

    def scan(self, target: ScanTarget) -> ScanResult:
        findings: list[Finding] = []
        for detector in self._detectors:
            findings.extend(detector.detect(target))
        return ScanResult(
            target=target,
            findings=findings,
            scanner_version=__version__,
        )

    @classmethod
    def from_config_file(cls, config_path: Path) -> tuple["MCPScanner", ScanTarget]:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        tools = _extract_tools(raw)
        target = ScanTarget(
            name=config_path.stem,
            config_path=str(config_path),
            tools=tools,
        )
        return cls(), target


def _extract_tools(raw: dict) -> list[dict]:
    # Claude Desktop / Cursor format: {"mcpServers": {"name": {...}}}
    if "mcpServers" in raw:
        tools = []
        for server_name, server_cfg in raw["mcpServers"].items():
            tools.append({"name": server_name, **server_cfg})
        return tools
    # Generic MCP format: {"tools": [...]}
    if "tools" in raw:
        return raw["tools"]
    return []
