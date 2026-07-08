"""Agent 3: Gem Updater

Updates the Gemfile and runs bundle update for the target gem.
"""

import logging
import re
import subprocess
from pathlib import Path

from .models import AnalysisResult
from .shell_runner import run_ruby_command

logger = logging.getLogger("vuln-agent.updater")


class UpdaterAgent:
    """Updates gem versions in Gemfile and Gemfile.lock."""

    def __init__(self, rails_app_path: Path, config: dict):
        self.rails_app_path = rails_app_path
        self.config = config.get("updater", {})
        self.strategy = self.config.get("strategy", "minimum")
        self.pin_in_gemfile = self.config.get("pin_in_gemfile", True)

    def update(self, analysis: AnalysisResult) -> dict:
        """Update a gem based on the analysis result.

        Returns:
            dict with keys: success (bool), changes (list[str]), error (str)
        """
        gem_name = analysis.vulnerability.gem
        target_version = analysis.recommended_version
        current_version = analysis.vulnerability.current_version

        logger.info(f"Updating {gem_name}: {current_version} → {target_version}")

        changes: list[str] = []

        # Step 1: Update Gemfile if the gem is directly specified
        if self.pin_in_gemfile:
            gemfile_updated = self._update_gemfile(gem_name, target_version)
            if gemfile_updated:
                changes.append(f"Updated Gemfile: gem '{gem_name}' version constraint")

        # Step 2: Run bundle update for the specific gem
        success, output = self._run_bundle_update(gem_name)

        if not success:
            # Try with --conservative flag for minimal changes
            logger.info(f"Retrying with --conservative flag...")
            success, output = self._run_bundle_update_conservative(gem_name)

        if success:
            changes.append(f"Updated Gemfile.lock: {gem_name} → {target_version}")
            return {"success": True, "changes": changes, "error": ""}
        else:
            return {"success": False, "changes": changes, "error": output}

    def _update_gemfile(self, gem_name: str, target_version: str) -> bool:
        """Update the gem version constraint in Gemfile."""
        gemfile_path = self.rails_app_path / "Gemfile"
        content = gemfile_path.read_text()

        # Pattern to match gem declaration
        # Handles: gem 'name', '~> x.y' / gem "name", ">= x.y" / gem 'name'
        pattern = rf"""(gem\s+['"]){gem_name}(['"])\s*,\s*['"][^'"]*['"]"""
        replacement_version = self._compute_version_constraint(target_version)

        if re.search(pattern, content):
            new_content = re.sub(
                pattern,
                rf"""\g<1>{gem_name}\g<2>, '{replacement_version}'""",
                content,
            )
            gemfile_path.write_text(new_content)
            logger.info(f"  Updated Gemfile constraint: {gem_name} → {replacement_version}")
            return True

        # Check if gem is listed without version constraint
        pattern_no_version = rf"""(gem\s+['"]){gem_name}(['"])\s*$"""
        if re.search(pattern_no_version, content, re.MULTILINE):
            new_content = re.sub(
                pattern_no_version,
                rf"""\g<1>{gem_name}\g<2>, '{replacement_version}'""",
                content,
                flags=re.MULTILINE,
            )
            gemfile_path.write_text(new_content)
            logger.info(f"  Added version constraint to Gemfile: {gem_name} → {replacement_version}")
            return True

        logger.info(f"  {gem_name} not found directly in Gemfile (transitive dependency)")
        return False

    def _compute_version_constraint(self, target_version: str) -> str:
        """Compute an appropriate version constraint.

        For strategy 'minimum': use '>= x.y.z'
        For strategy 'latest': use '~> x.y' (pessimistic)
        """
        parts = target_version.split(".")

        if self.strategy == "minimum":
            return f">= {target_version}"
        else:
            # Pessimistic constraint: ~> major.minor
            if len(parts) >= 2:
                return f"~> {parts[0]}.{parts[1]}"
            return f"~> {target_version}"

    def _run_bundle_update(self, gem_name: str) -> tuple[bool, str]:
        """Run bundle update for a specific gem."""
        result = run_ruby_command(
            ["bundle", "update", gem_name],
            cwd=self.rails_app_path,
            timeout=300,
        )

        if result.returncode == 0:
            logger.info(f"  bundle update {gem_name} succeeded")
            return True, result.stdout
        else:
            error = result.stderr or result.stdout
            logger.warning(f"  bundle update {gem_name} failed: {error[:200]}")
            return False, error

    def _run_bundle_update_conservative(self, gem_name: str) -> tuple[bool, str]:
        """Run bundle update with --conservative for minimal dependency changes."""
        result = run_ruby_command(
            ["bundle", "update", gem_name, "--conservative"],
            cwd=self.rails_app_path,
            timeout=300,
        )

        if result.returncode == 0:
            logger.info(f"  bundle update {gem_name} --conservative succeeded")
            return True, result.stdout
        else:
            error = result.stderr or result.stdout
            logger.warning(f"  bundle update {gem_name} --conservative failed: {error[:200]}")
            return False, error
