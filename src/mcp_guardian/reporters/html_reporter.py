from __future__ import annotations

from pathlib import Path

from mcp_guardian.models import ScanResult, Severity

_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#f85149",
    Severity.HIGH: "#f0883e",
    Severity.MEDIUM: "#d29922",
    Severity.LOW: "#58a6ff",
    Severity.INFO: "#8b949e",
}


class HtmlReporter:
    def write(self, result: ScanResult, path: Path) -> None:
        path.write_text(_render(result), encoding="utf-8")


def _render(result: ScanResult) -> str:
    findings_html = ""
    for f in sorted(result.findings, key=lambda x: x.cvss_score, reverse=True):
        c = _COLORS.get(f.severity, "#8b949e")
        refs = "".join(f'<a href="{r}" target="_blank">{r}</a><br>' for r in f.references)
        findings_html += f"""
    <div class="finding">
      <div class="fh">
        <span class="badge" style="background:{c}20;color:{c};border:1px solid {c}40">{f.severity.upper()}</span>
        <h3>{f.title}</h3>
        <span class="cvss">CVSS {f.cvss_score:.1f}</span>
      </div>
      <p>{f.description}</p>
      <div class="remed"><strong>Remediation:</strong> {f.remediation}</div>
      {f'<div class="refs">{refs}</div>' if f.references else ""}
    </div>"""

    verdict = "PASS" if result.passed else "FAIL"
    vc = "#3fb950" if result.passed else "#f85149"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mcp-guardian — {result.target.name}</title>
<style>
  *{{box-sizing:border-box}}
  body{{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:2rem;max-width:900px;margin:0 auto;padding:2rem 1rem}}
  h1{{color:#f0f6fc;font-size:1.4rem;margin:0 0 .25rem}}
  .meta{{color:#8b949e;font-size:.85rem;margin-bottom:2rem}}
  .summary{{display:flex;flex-wrap:wrap;gap:.75rem;margin-bottom:2rem}}
  .stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:.75rem 1.25rem;text-align:center;min-width:80px}}
  .num{{font-size:1.75rem;font-weight:700;line-height:1}}
  .finding{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;margin-bottom:.75rem}}
  .fh{{display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem;flex-wrap:wrap}}
  .fh h3{{margin:0;font-size:.95rem;color:#f0f6fc;flex:1}}
  .badge{{font-size:.7rem;font-weight:700;padding:.2rem .5rem;border-radius:4px;white-space:nowrap}}
  .cvss{{font-size:.85rem;color:#8b949e;white-space:nowrap}}
  p{{margin:.5rem 0;font-size:.875rem;line-height:1.6}}
  .remed{{background:#0d1117;border-left:3px solid #3fb950;padding:.6rem .875rem;font-size:.85rem;border-radius:0 4px 4px 0;margin-top:.75rem}}
  .refs{{margin-top:.5rem;font-size:.8rem}} .refs a{{color:#58a6ff}}
</style>
</head>
<body>
<h1>mcp-guardian security report</h1>
<div class="meta">Target: <strong>{result.target.name}</strong> &middot; {result.scanned_at.strftime("%Y-%m-%d %H:%M UTC")} &middot; v{result.scanner_version}</div>
<div class="summary">
  <div class="stat"><div class="num" style="color:{vc}">{verdict}</div><div style="font-size:.8rem;color:#8b949e">verdict</div></div>
  <div class="stat"><div class="num" style="color:#f85149">{result.critical_count}</div><div style="font-size:.8rem;color:#8b949e">critical</div></div>
  <div class="stat"><div class="num" style="color:#f0883e">{result.high_count}</div><div style="font-size:.8rem;color:#8b949e">high</div></div>
  <div class="stat"><div class="num">{len(result.findings)}</div><div style="font-size:.8rem;color:#8b949e">total</div></div>
</div>
{findings_html or '<p style="color:#3fb950">&#10003; No vulnerabilities detected.</p>'}
</body>
</html>"""
