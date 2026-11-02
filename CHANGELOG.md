# Changelog

All notable changes to mcp-guardian are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

## [0.1.0] — 2026-11-01

### Added
- `PromptInjectionDetector`: scans tool descriptions and input schemas for known injection patterns
- `ToolPoisoningDetector`: SHA-256 hash baseline to detect rug-pull attacks
- `ReturnChannelDetector`: flags unsafe output handling and high-risk tool types (fetch, browse, read_file, etc.)
- `MCPScanner`: orchestrates all detectors and returns a structured `ScanResult`
- `mcp-guardian scan` CLI command with `--output` (JSON) and `--html` report flags
- `--fail-on` flag for CI integration (exits 1 on severity threshold)
- `JsonReporter` and `HtmlReporter` with CVSS scores and remediation guidance
- Support for Claude Desktop, Cursor, and generic MCP config formats
- `pyproject.toml` with hatch build backend
- GitHub Actions CI: lint (ruff), security scan (bandit), test matrix (Python 3.11, 3.12), typecheck (mypy)
- GitHub Actions publish workflow (PyPI trusted publishing via OIDC)
- Pre-commit hooks: ruff, bandit, trailing-whitespace, check-yaml, check-toml
- Hypothesis property tests: scanner handles arbitrary inputs without crashing

[Unreleased]: https://github.com/sopitacasera/mcp-guardian/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sopitacasera/mcp-guardian/releases/tag/v0.1.0
