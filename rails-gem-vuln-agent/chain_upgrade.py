#!/usr/bin/env python3
"""
Multi-repo dependency chain upgrade tool.

Handles upgrades where internal gems (csxgit) pin transitive dependencies.
Detects the chain, builds an upgrade plan, and executes it in order.

Usage:
    python chain_upgrade.py --rails-app ../collector_app --gem faraday --version 2.15.0
    python chain_upgrade.py --rails-app ../lx-edcast --gem faraday --version 2.15.0 --dry-run
"""

import click
import logging
import sys
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.logging import RichHandler

from agents.dependency_chain import DependencyChainResolver
from config_loader import load_config

load_dotenv()
console = Console()


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@click.command()
@click.option("--rails-app", type=click.Path(exists=True), required=True,
              help="Path to the downstream Rails app.")
@click.option("--gem", type=str, required=True,
              help="Target gem to upgrade (e.g., faraday).")
@click.option("--version", type=str, required=True,
              help="Target version to upgrade to.")
@click.option("--workspace", type=click.Path(exists=True), default=None,
              help="Workspace root containing all repos (default: parent of rails-app).")
@click.option("--dry-run", is_flag=True, default=False,
              help="Show plan without executing.")
@click.option("--config", type=click.Path(exists=True), default="config.yaml")
def main(rails_app, gem, version, workspace, dry_run, config):
    """Multi-repo dependency chain upgrade for internal gems."""

    cfg = load_config(config)
    setup_logging(cfg.get("log_level", "INFO"))

    rails_path = Path(rails_app).resolve()
    workspace_root = Path(workspace).resolve() if workspace else rails_path.parent

    console.print(f"\n[bold blue]Dependency Chain Upgrade[/bold blue]")
    console.print(f"App: {rails_path.name}")
    console.print(f"Target: {gem} → {version}")
    console.print(f"Workspace: {workspace_root}")
    console.print(f"Mode: {'DRY RUN' if dry_run else 'EXECUTE'}\n")

    resolver = DependencyChainResolver(
        rails_app_path=rails_path,
        workspace_root=workspace_root,
        config=cfg,
    )

    # Step 1: Detect internal gems
    console.print("[bold]Step 1:[/bold] Detecting internal gems (csxgit)...")
    internal_gems = resolver.detect_internal_gems()

    if not internal_gems:
        console.print("  No internal gems found in Gemfile.")
        console.print(f"  You can upgrade {gem} directly with:")
        console.print(f"    python main.py --rails-app {rails_app} --gem {gem}")
        return

    # Show internal gems table
    table = Table(title="Internal Gems (csxgit)")
    table.add_column("Gem")
    table.add_column("Repo")
    table.add_column("Tag")
    table.add_column("Local?")
    table.add_column(f"Pins {gem}?")

    for ig in internal_gems:
        pins = ig.constrains.get(gem, "")
        table.add_row(
            ig.name,
            ig.repo_path,
            ig.current_tag,
            "✓" if ig.local_path else "✗",
            pins or "—",
        )
    console.print(table)

    # Step 2: Find blocking gems
    console.print(f"\n[bold]Step 2:[/bold] Finding gems that block {gem} {version}...")
    blocking = resolver.find_blocking_gems(gem, version, internal_gems)

    if not blocking:
        console.print(f"  [green]No internal gems block {gem} {version}![/green]")
        console.print(f"  You can upgrade directly:")
        console.print(f"    python main.py --rails-app {rails_app} --gem {gem}")
        return

    console.print(f"  Found {len(blocking)} blocking gem(s):")
    for bg in blocking:
        console.print(f"    • {bg.name} pins {gem} to '{bg.constrains[gem]}'")
        if not bg.local_path:
            console.print(f"      [yellow]⚠ No local checkout found![/yellow]")
            console.print(f"      Clone it: git clone git@bitbucket.csod.com:{bg.repo_path}.git")

    # Step 3: Build upgrade plan
    console.print(f"\n[bold]Step 3:[/bold] Building upgrade plan...")
    plan = resolver.build_upgrade_plan(gem, version, blocking)

    console.print("\n[bold]Upgrade Plan:[/bold]")
    for i, step in enumerate(plan, 1):
        action = step["action"]
        repo = step["repo"]
        if action == "bump_dependency":
            console.print(
                f"  {i}. [{repo}] Update gemspec: "
                f"{step['gem']} '{step['from']}' → '{step['to']}' "
                f"(tag: {step['new_tag']})"
            )
        elif action == "update_tag":
            console.print(
                f"  {i}. [{repo}] Update Gemfile: "
                f"{step['gem']} tag '{step['from']}' → '{step['to']}'"
            )
        elif action == "bundle_update":
            console.print(f"  {i}. [{repo}] bundle update {step['gem']}")

    # Step 4: Execute (or dry run)
    if dry_run:
        console.print("\n[yellow]DRY RUN — no changes made.[/yellow]")
        console.print("\nTo execute:")
        console.print(f"  python chain_upgrade.py --rails-app {rails_app} --gem {gem} --version {version}")
        return

    # Check all local paths exist
    missing = [bg for bg in blocking if not bg.local_path]
    if missing:
        console.print(f"\n[red]Cannot execute:[/red] Missing local checkouts:")
        for m in missing:
            console.print(f"  git clone git@bitbucket.csod.com:{m.repo_path}.git {workspace_root}/{m.repo_path.split('/')[-1]}")
        sys.exit(1)

    console.print(f"\n[bold]Step 4:[/bold] Executing plan...")
    results = resolver.execute_plan(plan, dry_run=False)

    # Summary
    success_count = sum(1 for r in results if r["success"])
    console.print(f"\n[bold]Results:[/bold] {success_count}/{len(results)} steps succeeded")

    if all(r["success"] for r in results):
        console.print("[green]✓ All steps completed![/green]")
        console.print("\n[bold]Next steps:[/bold]")
        console.print("  1. cd into each internal gem repo, commit, tag, and push:")
        for bg in blocking:
            new_tag = resolver._increment_tag(bg.current_tag)
            console.print(f"     cd {bg.local_path}")
            console.print(f"     git add . && git commit -m 'EP-XXXX: Bump {gem} constraint'")
            console.print(f"     git tag {new_tag} && git push origin {new_tag}")
        console.print(f"  2. Then run the full agent on {rails_path.name}:")
        console.print(f"     python main.py --rails-app {rails_app} --gem {gem} --create-pr --jira-ticket EP-XXXX")
    else:
        console.print("[red]✗ Some steps failed. Check logs above.[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
