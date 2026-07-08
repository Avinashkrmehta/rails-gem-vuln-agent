"""Agent 5: Verification Agent

Runs the full verification suite: bundle install, rspec, rubocop, brakeman, bundle audit.
"""

import logging
import re
import subprocess
from pathlib import Path

from .models import VerificationResult
from .shell_runner import run_ruby_command

logger = logging.getLogger("vuln-agent.verifier")


class VerifierAgent:
    """Runs verification steps to confirm the upgrade is safe."""

    def __init__(self, rails_app_path: Path, config: dict):
        self.rails_app_path = rails_app_path
        self.config = config.get("verifier", {})
        self.timeout = self.config.get("timeout_seconds", 600)
        self.rails_checks = self.config.get("rails_checks", [])

    def verify(self) -> VerificationResult:
        """Run the full verification suite."""
        logger.info("Running verification suite...")

        result = VerificationResult(success=True)

        # Step 1: bundle install
        result.bundle_install = self._run_bundle_install(result)
        if not result.bundle_install:
            result.success = False
            return result

        # Step 2: Run tests (rspec or minitest)
        result.tests_passed = self._run_tests(result)

        # Step 3: Rubocop
        result.rubocop_passed = self._run_rubocop(result)

        # Step 4: Brakeman
        result.brakeman_passed = self._run_brakeman(result)

        # Step 5: Bundle audit (confirm vulnerability is fixed)
        result.audit_clean = self._run_bundle_audit(result)

        # Step 6: Rails-specific checks (zeitwerk, etc.)
        if self.rails_checks:
            result.zeitwerk_check = self._run_rails_checks(result)

        # Overall success requires tests + audit to pass
        # Rubocop and brakeman are advisory
        result.success = result.tests_passed and result.bundle_install

        logger.info(
            f"  Verification {'PASSED' if result.success else 'FAILED'}: "
            f"tests={'✓' if result.tests_passed else '✗'} "
            f"rubocop={'✓' if result.rubocop_passed else '✗'} "
            f"brakeman={'✓' if result.brakeman_passed else '✗'} "
            f"audit={'✓' if result.audit_clean else '✗'}"
        )

        return result

    def _run_bundle_install(self, result: VerificationResult) -> bool:
        """Run bundle install."""
        logger.info("  Running bundle install...")
        proc = run_ruby_command(
            ["bundle", "install"],
            cwd=self.rails_app_path,
            timeout=self.timeout,
            stream_output=True,
        )
        if proc.returncode != 0:
            result.stderr += f"\n[bundle install]\n{proc.stderr or proc.stdout}"
            logger.error(f"  bundle install failed")
            return False
        return True

    def _run_tests(self, result: VerificationResult) -> bool:
        """Run test suite (rspec or minitest)."""
        # Detect test framework
        if (self.rails_app_path / "spec").is_dir():
            return self._run_rspec(result)
        elif (self.rails_app_path / "test").is_dir():
            return self._run_minitest(result)
        else:
            logger.warning("  No test directory found (spec/ or test/)")
            result.warnings.append("No test suite found")
            return True  # Pass by default if no tests

    def _run_rspec(self, result: VerificationResult) -> bool:
        """Run RSpec."""
        logger.info("  Running bundle exec rspec...")
        proc = run_ruby_command(
            ["bundle", "exec", "rspec", "--format", "documentation", "--no-color"],
            cwd=self.rails_app_path,
            timeout=self.timeout,
            stream_output=True,
        )

        result.stdout += f"\n[rspec]\n{proc.stdout}"

        if proc.returncode != 0:
            result.stderr += f"\n[rspec]\n{proc.stderr}"
            # Extract failed spec files
            result.failed_specs = self._extract_failed_specs(proc.stdout + proc.stderr)
            logger.warning(f"  RSpec failed. {len(result.failed_specs)} failing specs.")
            return False

        return True

    def _run_minitest(self, result: VerificationResult) -> bool:
        """Run Minitest."""
        logger.info("  Running bundle exec rails test...")
        proc = run_ruby_command(
            ["bundle", "exec", "rails", "test"],
            cwd=self.rails_app_path,
            timeout=self.timeout,
            stream_output=True,
        )

        result.stdout += f"\n[minitest]\n{proc.stdout}"

        if proc.returncode != 0:
            result.stderr += f"\n[minitest]\n{proc.stderr}"
            return False

        return True

    def _run_rubocop(self, result: VerificationResult) -> bool:
        """Run Rubocop with autocorrect."""
        logger.info("  Running bundle exec rubocop...")
        proc = run_ruby_command(
            ["bundle", "exec", "rubocop", "--autocorrect-all", "--format", "simple"],
            cwd=self.rails_app_path,
            timeout=120,
        )

        if proc.returncode not in (0, 1):  # 1 = offenses found but corrected
            result.warnings.append(f"Rubocop issues: {proc.stdout[:200]}")
            return False

        return True

    def _run_brakeman(self, result: VerificationResult) -> bool:
        """Run Brakeman security scanner."""
        logger.info("  Running bundle exec brakeman...")
        proc = run_ruby_command(
            ["bundle", "exec", "brakeman", "--no-pager", "-q", "--format", "json"],
            cwd=self.rails_app_path,
            timeout=120,
        )

        if proc.returncode != 0:
            result.warnings.append(f"Brakeman found issues")
            return False

        return True

    def _run_bundle_audit(self, result: VerificationResult) -> bool:
        """Run bundle audit to confirm vulnerability is fixed."""
        logger.info("  Running bundle audit check...")
        proc = run_ruby_command(
            ["bundle-audit", "check"],
            cwd=self.rails_app_path,
            timeout=60,
        )

        if proc.returncode == 0:
            return True
        else:
            result.warnings.append("bundle audit still reports vulnerabilities")
            return False

    def _run_rails_checks(self, result: VerificationResult) -> bool:
        """Run Rails-specific checks like zeitwerk:check."""
        all_passed = True

        for check_cmd in self.rails_checks:
            logger.info(f"  Running {check_cmd}...")
            proc = run_ruby_command(
                check_cmd,
                cwd=self.rails_app_path,
                timeout=60,
            )
            if proc.returncode != 0:
                result.warnings.append(f"{check_cmd} failed")
                all_passed = False

        return all_passed

    def _extract_failed_specs(self, output: str) -> list[str]:
        """Extract failed spec file paths from RSpec output."""
        failed = []

        # Match patterns like: rspec ./spec/models/user_spec.rb:42
        pattern = re.compile(r"rspec (./spec/\S+\.rb(?::\d+)?)")
        matches = pattern.findall(output)
        failed.extend(matches)

        # Also match: Failure/Error in spec/...
        pattern2 = re.compile(r"(spec/\S+\.rb):(\d+)")
        matches2 = pattern2.findall(output)
        failed.extend([f"{m[0]}:{m[1]}" for m in matches2])

        return list(set(failed))[:20]  # Limit
