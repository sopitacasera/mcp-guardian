# Contributing to mcp-guardian

Thank you for helping make MCP deployments safer. All contributions are welcome.

## Quick start

```bash
git clone https://github.com/sopitacasera/mcp-guardian
cd mcp-guardian
pip install -e ".[dev]"
pre-commit install
```

## Ways to contribute

- **New detectors** — add a file under `src/mcp_guardian/detectors/` implementing a `detect(target) -> list[Finding]` method and register it in `MCPScanner.__init__`
- **New reporters** — add a file under `src/mcp_guardian/reporters/` with a `write(result, path)` method
- **False positives / negatives** — open an issue with the MCP config that triggered the wrong result
- **Documentation** — improve examples, fix typos, add config format guides

## Standards

- `ruff check src tests` and `ruff format src tests` must pass
- `bandit -r src -c pyproject.toml` must pass
- New detectors require at least one positive and one negative test
- Property tests using Hypothesis are encouraged for parsers and pattern matchers
- Update `CHANGELOG.md` under `[Unreleased]`

## Commit messages

Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
