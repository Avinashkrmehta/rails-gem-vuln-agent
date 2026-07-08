"""Dependency Chain Resolver

Handles multi-repo gem upgrades where custom internal gems
(pinned via csxgit/git tags in Gemfile) constrain transitive
dependencies in the downstream app.

Example scenario:
  collector_app/Gemfile:
    gem 'ecl_client', csxgit: 'ent-lx/ecl_client', tag: 'v0.1.4'

  ecl_client/ecl_client.gemspec:
    spec.add_dependency "faraday", "2.14.3"

  To upgrade faraday in collector_app:
    1. Bump faraday in ecl_client.gemspec → v0.1.5
    2. Update collector_app/Gemfile tag → v0.1.5
    3. bundle update faraday in collector_app
"""

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .llm_client import create_llm_client
from .shell_runner import run_ruby_command

logger = logging.getLogger("vuln-agent.dependency-chain")


@dataclass
class InternalGem:
    """An internal gem hosted on Bitbucket (csxgit)."""

    name: str                   # ecl_client
    repo_path: str              # ent-lx/ecl_client
    current_tag: str            # v0.1.4
    local_path: Optional[Path] = None  # /Users/.../bitbucket/ecl_client
    gemspec_path: Optional[Path] = None
    constrains: dict = field(default_factory=dict)  # {faraday: "2.14.3"}


@dataclass
class DependencyChain:
    """A chain of upgrades needed across repos."""

    target_gem: str             # faraday
    target_version: str         # 2.15.0
    blocking_gems: list[InternalGem] = field(default_factory=list)
    upgrade_order: list[dict] = field(default_factory=list)


class DependencyChainResolver:
    """Detects and resolves multi-repo dependency chains."""

    def __init__(
        self,
        rails_app_path: Path,
        workspace_root: Path,
        config: dict,
        llm_client=None,
    ):
        self.rails_app_path = rails_app_path
        self.workspace_root = workspace_root  # e.g., /Users/.../bitbucket
        self.config = config
        self.llm = llm_client

    def detect_internal_gems(self) -> list[InternalGem]:
        """Parse Gemfile for all csxgit/git-sourced internal gems."""
        gemfile = self.rails_app_path / "Gemfile"
        content = gemfile.read_text()
        internal_gems = []

        # Match: gem 'name', csxgit: 'ent-lx/repo', tag: 'v1.0.0'
        # Each match must be on a single line
        pattern = re.compile(
            r"""gem\s+['"](\w[\w-]*)['"].*?csxgit:\s*['"]([^'"]+)['"]"""
            r"""(?:.*?tag:\s*['"]([^'"]+)['"])?"""
        )

        for match in pattern.finditer(content):
            gem_name = match.group(1)
            repo_path = match.group(2)
            tag = match.group(3) or "HEAD"

            # Try to find local checkout
            # repo_path is like "ent-lx/ecl_client" → look for ecl_client folder
            repo_name = repo_path.split("/")[-1]
            local_path = self.workspace_root / repo_name

            gem = InternalGem(
                name=gem_name,
                repo_path=repo_path,
                current_tag=tag,
                local_path=local_path if local_path.exists() else None,
            )

            # If local checkout exists, find gemspec and extract dependencies
            if gem.local_path:
                gem.gemspec_path = self._find_gemspec(gem.local_path, gem_name)
                if gem.gemspec_path:
                    gem.constrains = self._extract_dependencies(gem.gemspec_path)

            internal_gems.append(gem)

        logger.info(f"Found {len(internal_gems)} internal gems in Gemfile")
        return internal_gems

    def find_blocking_gems(
        self, target_gem: str, target_version: str, internal_gems: list[InternalGem]
    ) -> list[InternalGem]:
        """Find internal gems that constrain the target gem's version."""
        blocking = []

        for gem in internal_gems:
            if target_gem in gem.constrains:
                constraint = gem.constrains[target_gem]
                if self._version_blocked(constraint, target_version):
                    logger.info(
                        f"  {gem.name} pins {target_gem} to '{constraint}' "
                        f"(blocks upgrade to {target_version})"
                    )
                    blocking.append(gem)

        return blocking

    def build_upgrade_plan(
        self, target_gem: str, target_version: str, blocking_gems: list[InternalGem]
    ) -> list[dict]:
        """Build an ordered upgrade plan across repos.

        Returns a list of steps like:
        [
          {"repo": "ecl_client", "action": "bump_dependency",
           "gem": "faraday", "from": "2.14.3", "to": "~> 2.15",
           "file": "ecl_client.gemspec", "new_tag": "v0.1.5"},
          {"repo": "collector_app", "action": "update_tag",
           "gem": "ecl_client", "from": "v0.1.4", "to": "v0.1.5"},
          {"repo": "collector_app", "action": "bundle_update",
           "gem": "faraday"}
        ]
        """
        steps = []

        for blocking_gem in blocking_gems:
            current_constraint = blocking_gem.constrains.get(target_gem, "")
            new_constraint = f"~> {target_version.rsplit('.', 1)[0]}"

            # Step 1: Update the internal gem's gemspec
            new_tag = self._increment_tag(blocking_gem.current_tag)
            steps.append({
                "repo": blocking_gem.name,
                "repo_path": blocking_gem.repo_path,
                "local_path": str(blocking_gem.local_path) if blocking_gem.local_path else None,
                "action": "bump_dependency",
                "gem": target_gem,
                "from": current_constraint,
                "to": new_constraint,
                "file": str(blocking_gem.gemspec_path) if blocking_gem.gemspec_path else None,
                "new_tag": new_tag,
            })

            # Step 2: Update the downstream app's Gemfile tag
            steps.append({
                "repo": self.rails_app_path.name,
                "action": "update_tag",
                "gem": blocking_gem.name,
                "from": blocking_gem.current_tag,
                "to": new_tag,
            })

        # Step 3: Bundle update the target gem in the app
        steps.append({
            "repo": self.rails_app_path.name,
            "action": "bundle_update",
            "gem": target_gem,
        })

        return steps

    def execute_plan(self, steps: list[dict], dry_run: bool = False) -> list[dict]:
        """Execute the upgrade plan.

        Returns results for each step.
        """
        results = []

        for i, step in enumerate(steps, 1):
            logger.info(f"\n  Step {i}/{len(steps)}: [{step['repo']}] {step['action']} {step.get('gem', '')}")

            if dry_run:
                logger.info(f"    [DRY RUN] Would: {json.dumps(step, indent=2, default=str)}")
                results.append({"step": step, "success": True, "dry_run": True})
                continue

            if step["action"] == "bump_dependency":
                success = self._execute_bump_dependency(step)
            elif step["action"] == "update_tag":
                success = self._execute_update_tag(step)
            elif step["action"] == "bundle_update":
                success = self._execute_bundle_update(step)
            else:
                logger.warning(f"    Unknown action: {step['action']}")
                success = False

            results.append({"step": step, "success": success})

            if not success:
                logger.error(f"    Step failed. Stopping chain.")
                break

        return results

    # ── Execution methods ──

    def _execute_bump_dependency(self, step: dict) -> bool:
        """Bump a dependency version in a gemspec file."""
        gemspec_path = step.get("file")
        if not gemspec_path or not Path(gemspec_path).exists():
            logger.error(f"    Gemspec not found: {gemspec_path}")
            return False

        gemspec = Path(gemspec_path)
        content = gemspec.read_text()
        gem_name = step["gem"]
        new_constraint = step["to"]

        # Match patterns like:
        #   spec.add_dependency "faraday", "2.14.3"
        #   spec.add_dependency 'faraday', '~> 2.14'
        #   spec.add_runtime_dependency "faraday", ">= 1.0"
        pattern = re.compile(
            rf"""(add_(?:runtime_)?dependency\s+['"]){gem_name}(['"],\s*['"])([^'"]+)(['"])"""
        )

        if pattern.search(content):
            new_content = pattern.sub(rf"\g<1>{gem_name}\g<2>{new_constraint}\g<4>", content)
            gemspec.write_text(new_content)
            logger.info(f"    ✓ Updated {gemspec.name}: {gem_name} → '{new_constraint}'")
            return True
        else:
            logger.error(f"    Could not find {gem_name} dependency in {gemspec.name}")
            return False

    def _execute_update_tag(self, step: dict) -> bool:
        """Update a csxgit gem's tag in the downstream Gemfile."""
        gemfile = self.rails_app_path / "Gemfile"
        content = gemfile.read_text()
        gem_name = step["gem"]
        old_tag = step["from"]
        new_tag = step["to"]

        # Match: gem 'ecl_client', csxgit: 'ent-lx/ecl_client', tag: 'v0.1.4'
        pattern = re.compile(
            rf"""(gem\s+['"]){gem_name}(['"].*?tag:\s*['"]){re.escape(old_tag)}(['"])"""
        )

        if pattern.search(content):
            new_content = pattern.sub(rf"\g<1>{gem_name}\g<2>{new_tag}\g<3>", content)
            gemfile.write_text(new_content)
            logger.info(f"    ✓ Updated Gemfile: {gem_name} tag → {new_tag}")
            return True
        else:
            logger.error(f"    Could not find {gem_name} with tag '{old_tag}' in Gemfile")
            return False

    def _execute_bundle_update(self, step: dict) -> bool:
        """Run bundle update for the target gem."""
        gem_name = step["gem"]
        result = run_ruby_command(
            ["bundle", "update", gem_name],
            cwd=self.rails_app_path,
            timeout=300,
        )
        if result.returncode == 0:
            logger.info(f"    ✓ bundle update {gem_name} succeeded")
            return True
        else:
            logger.error(f"    ✗ bundle update {gem_name} failed: {result.stderr[:200]}")
            return False

    # ── Helper methods ──

    def _find_gemspec(self, gem_path: Path, gem_name: str) -> Optional[Path]:
        """Find the gemspec file in a gem's directory."""
        # Try exact name match first
        exact = gem_path / f"{gem_name}.gemspec"
        if exact.exists():
            return exact

        # Try any .gemspec
        gemspecs = list(gem_path.glob("*.gemspec"))
        if gemspecs:
            return gemspecs[0]

        return None

    def _extract_dependencies(self, gemspec_path: Path) -> dict[str, str]:
        """Extract dependency constraints from a gemspec."""
        content = gemspec_path.read_text()
        deps = {}

        # Match: spec.add_dependency "gem_name", "version"
        # Match: spec.add_runtime_dependency 'gem_name', '~> 1.0'
        pattern = re.compile(
            r"""add_(?:runtime_)?dependency\s+['"](\w[\w-]*)['"](?:,\s*['"]([^'"]+)['"])?"""
        )

        for match in pattern.finditer(content):
            dep_name = match.group(1)
            constraint = match.group(2) or "*"
            deps[dep_name] = constraint

        return deps

    def _version_blocked(self, constraint: str, target_version: str) -> bool:
        """Check if a constraint blocks the target version.

        Simple heuristic — exact pins and pessimistic constraints.
        """
        constraint = constraint.strip()

        # Exact pin: "2.14.3" blocks "2.15.0"
        if re.match(r"^\d+\.\d+\.\d+$", constraint):
            return constraint != target_version

        # Pessimistic: "~> 2.14" allows 2.14.x but not 2.15.x
        pessimistic = re.match(r"~>\s*(\d+)\.(\d+)", constraint)
        if pessimistic:
            major, minor = int(pessimistic.group(1)), int(pessimistic.group(2))
            target_parts = target_version.split(".")
            target_major = int(target_parts[0])
            target_minor = int(target_parts[1]) if len(target_parts) > 1 else 0

            if target_major != major:
                return True
            # ~> 2.14 allows 2.14.x, 2.15.x etc (up to next major)
            # ~> 2.14.0 allows 2.14.x only
            if len(constraint.split(".")) == 3:
                return target_minor != minor
            return False

        # >= or > constraints generally don't block
        if constraint.startswith(">=") or constraint.startswith(">"):
            return False

        return False

    def _increment_tag(self, tag: str) -> str:
        """Increment a version tag: v0.1.4 → v0.1.5"""
        match = re.match(r"(v?)(\d+)\.(\d+)\.(\d+)(.*)", tag)
        if match:
            prefix = match.group(1)
            major = int(match.group(2))
            minor = int(match.group(3))
            patch = int(match.group(4)) + 1
            suffix = match.group(5)
            return f"{prefix}{major}.{minor}.{patch}{suffix}"
        return f"{tag}-updated"
