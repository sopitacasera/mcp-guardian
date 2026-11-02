"""Detects tool poisoning (rug-pull): tool descriptions changed after approval."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mcp_guardian.models import Finding, ScanTarget, Severity, VulnType

_PINFILE = Path.home() / ".mcp-guardian" / "tool-pins.json"


class ToolPoisoningDetector:
    """
    Maintains a hash baseline of tool descriptions.

    On each scan, compares the current tool description hash against the saved
    baseline. A mismatch indicates the server silently changed tool behavior
    after the user approved it — a classic rug-pull attack.
    """

    def detect(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        pins = _load_pins()
        scope = f"{target.name}:{target.config_path}"

        for tool in target.tools:
            name = str(tool.get("name", ""))
            description = str(tool.get("description", ""))
            current_hash = _hash(description)
            pin_key = f"{scope}:{name}"

            if pin_key in pins and pins[pin_key] != current_hash:
                findings.append(
                    Finding(
                        id=f"TP-{name}",
                        vuln_type=VulnType.TOOL_POISONING,
                        severity=Severity.HIGH,
                        title=f"Tool description changed since last scan: '{name}'",
                        description=(
                            f"Hash for tool '{name}' changed from {pins[pin_key][:8]}… "
                            f"to {current_hash[:8]}…. The server may have silently modified "
                            f"the tool's behavior after you approved it (rug-pull attack)."
                        ),
                        tool_name=name,
                        cvss_score=8.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
                        remediation=(
                            "Review the new tool description carefully. "
                            "If the change is intentional, run `mcp-guardian pin <config>` "
                            "to update the baseline. Otherwise, stop using this MCP server "
                            "until the source is verified."
                        ),
                        references=[
                            "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning",
                        ],
                    )
                )

        # Persist updated hashes after scan
        for tool in target.tools:
            name = str(tool.get("name", ""))
            pins[f"{scope}:{name}"] = _hash(str(tool.get("description", "")))
        _save_pins(pins)

        return findings


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _load_pins() -> dict[str, str]:
    if _PINFILE.exists():
        return json.loads(_PINFILE.read_text(encoding="utf-8"))
    return {}


def _save_pins(pins: dict[str, str]) -> None:
    _PINFILE.parent.mkdir(parents=True, exist_ok=True)
    _PINFILE.write_text(json.dumps(pins, indent=2), encoding="utf-8")
