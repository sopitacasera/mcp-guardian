from hypothesis import given, settings
from hypothesis import strategies as st

from mcp_guardian.models import ScanTarget, VulnType
from mcp_guardian.scanner import MCPScanner


def test_empty_target_no_findings(empty_target: ScanTarget) -> None:
    result = MCPScanner().scan(empty_target)
    assert result.findings == []
    assert result.passed is True


def test_safe_target_no_critical(safe_target: ScanTarget) -> None:
    result = MCPScanner().scan(safe_target)
    assert result.critical_count == 0


def test_injected_target_finds_prompt_injection(injected_target: ScanTarget) -> None:
    result = MCPScanner().scan(injected_target)
    vuln_types = {f.vuln_type for f in result.findings}
    assert VulnType.PROMPT_INJECTION in vuln_types
    assert result.passed is False


def test_fetch_tool_flagged_as_return_channel_risk(fetch_target: ScanTarget) -> None:
    result = MCPScanner().scan(fetch_target)
    vuln_types = {f.vuln_type for f in result.findings}
    assert VulnType.RETURN_CHANNEL in vuln_types


def test_result_has_scanner_version(safe_target: ScanTarget) -> None:
    result = MCPScanner().scan(safe_target)
    assert result.scanner_version != ""


def test_all_findings_have_valid_cvss(injected_target: ScanTarget) -> None:
    result = MCPScanner().scan(injected_target)
    for finding in result.findings:
        assert 0.0 <= finding.cvss_score <= 10.0


@given(
    name=st.text(min_size=1, max_size=64).filter(lambda s: s.strip()),
    description=st.text(max_size=500),
)
@settings(max_examples=200)
def test_scanner_never_crashes_on_arbitrary_input(name: str, description: str) -> None:
    """Property: scanner must handle any string without raising."""
    target = ScanTarget(
        name="fuzz",
        tools=[{"name": name, "description": description}],
    )
    result = MCPScanner().scan(target)
    assert result is not None
    assert all(0.0 <= f.cvss_score <= 10.0 for f in result.findings)
