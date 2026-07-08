#!/usr/bin/env python3
"""
Quick standalone scanner - just runs vulnerability detection without AI.
Useful for getting a quick audit of your Rails app.

Usage:
    python scan_only.py /path/to/rails/app
"""

import sys
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table

from agents.scanner import ScannerAgent
from agents.utils import detect_rails_app_info

console = Console()


def main():
    if len(sys.argv) < 2:
        console.print("[red]Usage:[/red] python scan_only.py /path/to/rails/app")
        sys.exit(1)

    rails_path = Path(sys.argv[1]).resolve()

    if not (rails_path / "Gemfile").exists():
        console.print(f"[red]Error:[/red] No Gemfile found at {rails_path}")
        sys.exit(1)

    # Show app info
    info = detect_rails_app_info(rails_path)
    console.print(f"\n[bold]Rails App:[/bold] {rails_path}")
    console.print(f"  Rails: {info['rails_version']} | Ruby: {info['ruby_version']} | Gems: {info['gem_count']}")
    console.print(f"  Tests: {info['test_framework']} | Sidekiq: {'✓' if info['has_sidekiq'] else '✗'}")
    console.print("")

    # Scan
    config = {"scanner": {"tools": ["bundle-audit"], "severity_threshold": "low"}}
    scanner = ScannerAgent(rails_path, config)
    vulns = scanner.scan()

    if not vulns:
        console.print("[green]✓ No vulnerabilities found![/green]")
        return

    # Display table
    table = Table(title=f"Vulnerabilities Found ({len(vulns)})")
    table.add_column("Gem", style="cyan")
    table.add_column("Current", style="red")
    table.add_column("Patched", style="green")
    table.add_column("CVE", style="yellow")
    table.add_column("Severity")
    table.add_column("Title")

    for vuln in vulns:
        severity_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
        }.get(vuln.severity.value, "")

        patched = ", ".join(vuln.patched_versions[:2]) if vuln.patched_versions else "unknown"

        table.add_row(
            vuln.gem,
            vuln.current_version,
            patched,
            vuln.cve,
            f"[{severity_style}]{vuln.severity.value.upper()}[/{severity_style}]",
            vuln.title[:40],
        )

    console.print(table)

    # Also output JSON for scripting
    json_output = [
        {
            "gem": v.gem,
            "current_version": v.current_version,
            "patched_versions": v.patched_versions,
            "cve": v.cve,
            "severity": v.severity.value,
            "title": v.title,
        }
        for v in vulns
    ]

    output_path = Path("reports")
    output_path.mkdir(exist_ok=True)
    report_file = output_path / "scan_results.json"
    report_file.write_text(json.dumps(json_output, indent=2))
    console.print(f"\n[dim]JSON report saved to: {report_file}[/dim]")


if __name__ == "__main__":
    main()
