"""Detects prompt injection embedded in MCP tool descriptions and schemas."""

from __future__ import annotations

import re

from mcp_guardian.models import Finding, ScanTarget, Severity, VulnType

# Patterns known to appear in prompt injection attacks against LLM agents
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(previous|all|above)\s+instruction", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
    re.compile(r"disregard\s+(your|all)\s+", re.IGNORECASE),
    re.compile(r"(exfiltrate|leak|send)\s+(the\s+)?(password|secret|key|token)", re.IGNORECASE),
    re.compile(r"system\s*prompt", re.IGNORECASE),
    re.compile(r"\bDAN\b"),  # "Do Anything Now" jailbreak variant
    re.compile(r"<\s*script\b", re.IGNORECASE),  # XSS-style injection
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"new\s+persona", re.IGNORECASE),
    re.compile(r"act\s+as\s+(?:a\s+)?(?:new|different|unrestricted)", re.IGNORECASE),
]


class PromptInjectionDetector:
    """Scans tool descriptions and input schemas for embedded injection patterns."""

    def detect(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for tool in target.tools:
            name = str(tool.get("name", "unknown"))
            description = str(tool.get("description", ""))
            schema_text = _flatten_schema(tool.get("inputSchema", {}) or tool.get("args", {}))
            full_text = f"{description} {schema_text}"

            for pattern in _INJECTION_PATTERNS:
                if pattern.search(full_text):
                    findings.append(
                        Finding(
                            id=f"PI-{name}-{len(findings)}",
                            vuln_type=VulnType.PROMPT_INJECTION,
                            severity=Severity.CRITICAL,
                            title=f"Prompt injection pattern in tool '{name}'",
                            description=(
                                f"Tool description or schema matches known injection pattern "
                                f"'{pattern.pattern}'. Malicious content in tool metadata "
                                f"can manipulate the LLM agent's behavior at runtime."
                            ),
                            tool_name=name,
                            cvss_score=9.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                            remediation=(
                                "Remove any instruction-like text from the tool description. "
                                "Tool descriptions must only describe functionality, not issue "
                                "commands to the model. Verify the MCP server's source code."
                            ),
                            references=[
                                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                            ],
                        )
                    )
                    break  # One finding per tool per scan pass

        return findings


def _flatten_schema(schema: dict) -> str:
    parts: list[str] = []
    for val in schema.values():
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, dict):
            parts.append(_flatten_schema(val))
    return " ".join(parts)
