from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from mcp_guardian.models import Severity
from mcp_guardian.scanner import MCPScanner

app = typer.Typer(
    name="mcp-guardian",
    help="Framework-agnostic MCP server security scanner.",
    no_args_is_help=True,
)
console = Console()

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "[bold red]",
    Severity.HIGH: "[red]",
    Severity.MEDIUM: "[yellow]",
    Severity.LOW: "[cyan]",
    Severity.INFO: "[dim]",
}

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@app.command()
def scan(
    config: Path = typer.Argument(..., help="Path to MCP config file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON report"),
    html: Optional[Path] = typer.Option(None, "--html", help="Write HTML report"),
    fail_on: Severity = typer.Option(
        Severity.HIGH, "--fail-on", help="Exit 1 if any finding >= this severity"
    ),
) -> None:
    """Scan an MCP config file for security vulnerabilities."""
    if not config.exists():
        console.print(f"[red]Error:[/red] File not found: {config}")
        raise typer.Exit(1)

    scanner, target = MCPScanner.from_config_file(config)

    with console.status(f"Scanning [bold]{target.name}[/bold]..."):
        result = scanner.scan(target)

    table = Table(title=f"Scan — {target.name}", box=box.ROUNDED)
    table.add_column("Severity", style="bold")
    table.add_column("Type")
    table.add_column("Title")
    table.add_column("CVSS", justify="right")

    for finding in sorted(result.findings, key=lambda f: f.cvss_score, reverse=True):
        style = _SEVERITY_STYLES.get(finding.severity, "")
        table.add_row(
            f"{style}{finding.severity.upper()}[/]",
            finding.vuln_type.value,
            finding.title,
            f"{finding.cvss_score:.1f}",
        )

    console.print(table)
    console.print(
        f"\nFound [bold]{len(result.findings)}[/bold] issues — "
        f"[red]{result.critical_count} critical[/red], "
        f"[yellow]{result.high_count} high[/yellow]"
    )

    if output:
        from mcp_guardian.reporters.json_reporter import JsonReporter

        JsonReporter().write(result, output)
        console.print(f"JSON report → [green]{output}[/green]")

    if html:
        from mcp_guardian.reporters.html_reporter import HtmlReporter

        HtmlReporter().write(result, html)
        console.print(f"HTML report → [green]{html}[/green]")

    fail_index = _SEVERITY_ORDER.index(fail_on)
    worst = min(
        (_SEVERITY_ORDER.index(f.severity) for f in result.findings),
        default=len(_SEVERITY_ORDER),
    )
    if worst <= fail_index:
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Print mcp-guardian version."""
    from mcp_guardian import __version__

    console.print(f"mcp-guardian [bold]{__version__}[/bold]")
