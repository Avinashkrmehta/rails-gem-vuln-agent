#!/usr/bin/env python3
"""
Rails Gem Vulnerability Agent - Main Entry Point

Orchestrates the full vulnerability detection, analysis, fix, and PR workflow.
"""

import click
import logging
import sys
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.logging import RichHandler

from agents.orchestrator import VulnerabilityOrchestrator
from config_loader import load_config

load_dotenv()
console = Console()


def setup_logging(level: str) -> None:
    """Configure rich logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@click.command()
@click.option(
    "--rails-app",
    type=click.Path(exists=True),
    required=True,
    help="Path to the Rails application root directory.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Scan only, do not apply fixes.",
)
@click.option(
    "--gem",
    type=str,
    default=None,
    help="Fix a specific gem only.",
)
@click.option(
    "--max-retries",
    type=int,
    default=None,
    help="Override max retry attempts from config.",
)
@click.option(
    "--config",
    type=click.Path(exists=True),
    default="config.yaml",
    help="Path to config file.",
)
@click.option(
    "--create-pr",
    is_flag=True,
    default=False,
    help="Create a GitHub/Bitbucket PR after successful fix.",
)
@click.option(
    "--jira-ticket",
    type=str,
    default=None,
    help="Jira ticket ID for branch name and commit message (e.g., EP-1234).",
)
@click.option(
    "--mock-llm",
    is_flag=True,
    default=False,
    help="Use mock LLM responses (no API key needed, for testing).",
)
def main(
    rails_app: str,
    dry_run: bool,
    gem: str | None,
    max_retries: int | None,
    config: str,
    create_pr: bool,
    jira_ticket: str | None,
    mock_llm: bool,
) -> None:
    """Rails Gem Vulnerability Agent - Detect, analyze, and fix gem vulnerabilities."""

    cfg = load_config(config)
    setup_logging(cfg.get("log_level", "INFO"))
    logger = logging.getLogger("vuln-agent")

    rails_path = Path(rails_app).resolve()

    # Validate it's a Rails app
    if not (rails_path / "Gemfile").exists():
        console.print("[red]Error:[/red] No Gemfile found. Is this a Rails app?")
        sys.exit(1)

    if not (rails_path / "Gemfile.lock").exists():
        console.print("[red]Error:[/red] No Gemfile.lock found. Run 'bundle install' first.")
        sys.exit(1)

    console.print(f"\n[bold blue]Rails Gem Vulnerability Agent[/bold blue]")
    console.print(f"Target: {rails_path}")
    console.print(f"Mode: {'Dry Run (scan only)' if dry_run else 'Full Fix'}")
    if mock_llm:
        console.print(f"LLM: [yellow]MOCK (no API key required)[/yellow]")
    if gem:
        console.print(f"Target gem: {gem}")
    if jira_ticket:
        console.print(f"Jira ticket: {jira_ticket}")
    console.print("")

    if max_retries is not None:
        cfg["retry"]["max_attempts"] = max_retries

    orchestrator = VulnerabilityOrchestrator(
        rails_app_path=rails_path,
        config=cfg,
        dry_run=dry_run,
        target_gem=gem,
        create_pr=create_pr,
        mock_llm=mock_llm,
        jira_ticket=jira_ticket,
    )

    try:
        results = orchestrator.run()
        _print_summary(results)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        sys.exit(1)
    except Exception as e:
        logger.exception("Agent failed")
        console.print(f"\n[red]Agent failed:[/red] {e}")
        sys.exit(1)


def _print_summary(results: dict) -> None:
    """Print a summary of the agent run."""
    console.print("\n[bold]═══ Summary ═══[/bold]\n")

    vulns = results.get("vulnerabilities_found", 0)
    fixed = results.get("vulnerabilities_fixed", 0)
    failed = results.get("vulnerabilities_failed", 0)
    skipped = results.get("vulnerabilities_skipped", 0)

    console.print(f"  Vulnerabilities found:   {vulns}")
    console.print(f"  Successfully fixed:      [green]{fixed}[/green]")
    console.print(f"  Failed to fix:           [red]{failed}[/red]")
    console.print(f"  Skipped (dry run/manual):[yellow]{skipped}[/yellow]")

    if results.get("pr_url"):
        console.print(f"\n  Pull Request: [link]{results['pr_url']}[/link]")

    if results.get("report_path"):
        console.print(f"  Full report:  {results['report_path']}")

    console.print("")


if __name__ == "__main__":
    main()
