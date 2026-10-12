from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .checks import CHECKS
from .report import build_report, save_report
from .scanner import ScanConfig, run_scan

app = typer.Typer(
    no_args_is_help=True,
    help="PayIntLab Red Team CLI for payment, fintech and multi-tenant RAG agents.",
)
console = Console()

SEVERITY_COLORS = {
    "Critical": "red",
    "High": "yellow",
    "Medium": "cyan",
    "Low": "green",
}


def _render_findings(findings: list[dict]) -> None:
    table = Table(title="Findings")
    table.add_column("ID")
    table.add_column("Check")
    table.add_column("Severity")
    table.add_column("Triggered")
    table.add_column("Hardened blocked")
    for item in findings:
        severity = str(item.get("severity", "Medium"))
        table.add_row(
            str(item.get("id")),
            str(item.get("name")),
            f"[{SEVERITY_COLORS.get(severity, 'white')}]{severity}[/]",
            "[red]YES[/]" if item.get("triggered") else "[green]no[/]",
            "[green]yes[/]" if item.get("hardened_blocked") else "-",
        )
    console.print(table)


@app.command()
def scan(
    target: str = typer.Option(
        "http://127.0.0.1:8001",
        "--target",
        "-t",
        help="Target base URL. Defaults to the local Vulnerable RAG Lab.",
    ),
    mode: str = typer.Option(
        "lab",
        "--mode",
        "-m",
        help="Scan mode: lab, quick, or full.",
    ),
    tenant_id: str = typer.Option("tenant-a", "--tenant", help="Tenant ID for the chat API."),
    token: str | None = typer.Option(None, "--token", help="Access token for a protected lab."),
    authorized: bool = typer.Option(
        False,
        "--authorized",
        help="Confirm you have written permission for a non-local target.",
    ),
    output: str = typer.Option(
        "payintlab-reports",
        "--output",
        "-o",
        help="Report output directory.",
    ),
    as_json: bool = typer.Option(False, "--json", help="Print JSON instead of a table."),
) -> None:
    """Run an AI red-team scan and save JSON + Markdown reports."""
    if mode not in {"lab", "quick", "full"}:
        raise typer.BadParameter("mode must be lab, quick, or full")
    config = ScanConfig(
        target=target,
        tenant_id=tenant_id,
        token=token,
        authorized=authorized,
    )
    try:
        result = run_scan(config, mode=mode)
    except PermissionError as exc:
        console.print(Panel(str(exc), title="Authorization required", style="red"))
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # noqa: BLE001
        console.print(Panel(f"{exc}", title="Scan failed", style="red"))
        raise typer.Exit(code=2) from exc

    report = build_report(result)
    run_dir = Path(output) / datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path, markdown_path = save_report(report, run_dir)

    if as_json:
        console.print_json(json.dumps(report, ensure_ascii=False))
    else:
        summary = report["summary"]
        console.print(
            Panel(
                f"Target: {report['target']}\n"
                f"Mode: {report['mode']}\n"
                f"Triggered: {summary['triggered']}/{summary['total']}\n"
                f"By severity: {summary['by_severity']}",
                title="PayIntLab Red Team",
                style="bold blue",
            )
        )
        _render_findings(report["findings"])
        console.print(f"JSON report: {json_path}")
        console.print(f"Markdown report: {markdown_path}")

    critical_or_high = any(
        item.get("triggered") and item.get("severity") in {"Critical", "High"}
        for item in report["findings"]
    )
    if critical_or_high:
        raise typer.Exit(code=1)


@app.command("attacks")
def attacks() -> None:
    """List the built-in attack checks."""
    table = Table(title="PayIntLab Red Team checks")
    table.add_column("ID")
    table.add_column("Check")
    table.add_column("Category")
    table.add_column("Severity")
    for check in CHECKS:
        severity = check.severity
        table.add_row(
            check.id,
            check.name,
            check.category,
            f"[{SEVERITY_COLORS.get(severity, 'white')}]{severity}[/]",
        )
    console.print(table)


@app.command()
def lab() -> None:
    """Show how to start the local lab or use the hosted demo."""
    console.print(
        Panel(
            "Local lab:\n"
            "  cd vulnerable-rag-lab && docker compose up --build\n\n"
            "Hosted demo:\n"
            "  https://vulnerable-rag-lab.onrender.com/\n\n"
            "Then run:\n"
            "  payintlab-redteam scan --target http://127.0.0.1:8001 --mode lab",
            title="Vulnerable RAG Chatbot Lab",
            style="green",
        )
    )


@app.command()
def version() -> None:
    """Print the CLI version."""
    console.print(f"payintlab-redteam {__version__}")


if __name__ == "__main__":
    app()
