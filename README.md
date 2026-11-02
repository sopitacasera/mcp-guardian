# mcp-guardian

> Framework-agnostic MCP server security scanner. Audit-grade reports. No vendor lock-in.

[![CI](https://github.com/sopitacasera/mcp-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/sopitacasera/mcp-guardian/actions)
[![PyPI version](https://badge.fury.io/py/mcp-guardian.svg)](https://badge.fury.io/py/mcp-guardian)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/sopitacasera/mcp-guardian/branch/main/graph/badge.svg)](https://codecov.io/gh/sopitacasera/mcp-guardian)

**mcp-guardian** is an open-source security scanner for MCP (Model Context Protocol) servers. It detects prompt injection, tool poisoning, and **return channel vulnerabilities** — the three attack vectors that security research identifies as the core risks in AI agent deployments in 2026.

Unlike Promptfoo (acquired by OpenAI) or MCP-Scan (acquired by Snyk), mcp-guardian is **permanently vendor-neutral** and works with any MCP client or LLM provider.

---

## Why mcp-guardian

| Capability | Promptfoo | MCP-Scan | mcp-guardian |
|---|:---:|:---:|:---:|
| Vendor-neutral | ⚠ OpenAI-owned | ⚠ Snyk-owned | ✅ independent |
| Scans return channel | ❌ | ❌ | ✅ |
| Audit-grade reports (CVSS) | ❌ | ❌ | ✅ |
| Python SDK | ❌ | ❌ | ✅ |
| Framework-agnostic | ❌ | Claude/Cursor/Windsurf only | ✅ any MCP client |

---

## Installation

```bash
pip install mcp-guardian
```

Run without installing:

```bash
uvx mcp-guardian scan ~/.config/claude/claude_desktop_config.json
```

---

## Quick start

```bash
# Scan a Claude Desktop config
mcp-guardian scan ~/.config/claude/claude_desktop_config.json

# Generate an HTML audit report
mcp-guardian scan config.json --html report.html --output report.json

# CI mode — exits with code 1 on any CRITICAL or HIGH finding
mcp-guardian scan config.json --fail-on high
```

---

## What it detects

### 1. Prompt injection
Scans tool descriptions and input schemas for patterns associated with known injection attacks: jailbreaks, instruction overrides, credential exfiltration commands, XSS-style markup.

### 2. Tool poisoning
Maintains a SHA-256 hash baseline of tool descriptions. Flags any server that silently modifies a tool's description after the user approved it — the *rug-pull* attack.

### 3. Return channel vulnerabilities *(unique to mcp-guardian)*
Analyzes tool configuration flags and tool types for indicators of unsafe output handling. Tools like `fetch`, `browse`, and `read_file` that return external content to the LLM without filtering are flagged — the attack vector all other scanners miss.

---

## Python SDK

```python
from mcp_guardian.scanner import MCPScanner
from mcp_guardian.models import ScanTarget

target = ScanTarget(
    name="my-server",
    tools=[
        {"name": "fetch", "description": "Fetch a URL and return its content."},
        {"name": "get_weather", "description": "Get current weather for a city."},
    ],
)

scanner = MCPScanner()
result = scanner.scan(target)

print(f"Passed: {result.passed}")
for finding in result.findings:
    print(f"[{finding.severity.upper()}] {finding.title} — CVSS {finding.cvss_score:.1f}")
```

---

## GitHub Actions integration

```yaml
- name: Scan MCP configuration
  run: |
    pip install mcp-guardian
    mcp-guardian scan .cursor/mcp.json --fail-on high
```

---

## Supported config formats

| Format | Path |
|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Cursor | `.cursor/mcp.json` |
| Generic MCP | Any JSON with `{"tools": [...]}` |

---

## Development

```bash
git clone https://github.com/sopitacasera/mcp-guardian
cd mcp-guardian
pip install -e ".[dev]"
pre-commit install
pytest
```

---

## Security

Please report vulnerabilities privately via [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions welcome.

## License

[Apache 2.0](LICENSE)
