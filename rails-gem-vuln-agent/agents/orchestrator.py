"""Orchestrator - Coordinates all agents in the vulnerability fix pipeline.

Flow:
  Scanner → Analyzer → Updater → Fixer → Verifier → (Retry) → PR Creator
"""

import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from .analyzer import AnalyzerAgent
from .fixer import FixerAgent
from .models import (
    AnalysisResult,
    FixResult,
    FixStatus,
    RiskLevel,
    VerificationResult,
    Vulnerability,
)
from .pr_creator import PRCreatorAgent
from .scanner import ScannerAgent
from .updater import UpdaterAgent
from .verifier import VerifierAgent

logger = logging.getLogger("vuln-agent.orchestrator")


class VulnerabilityOrchestrator:
    """Orchestrates the full vulnerability detection and fix pipeline."""

    def __init__(
        self,
        rails_app_path: Path,
        config: dict,
        dry_run: bool = False,
        target_gem: Optional[str] = None,
        create_pr: bool = False,
        mock_llm: bool = False,
        jira_ticket: Optional[str] = None,
    ):
        self.rails_app_path = rails_app_path
        self.config = config
        self.dry_run = dry_run
        self.target_gem = target_gem
        self.create_pr = create_pr
        self.jira_ticket = jira_ticket
        self.max_retries = config.get("retry", {}).get("max_attempts", 3)
        self.rollback_on_failure = config.get("retry", {}).get("rollback_on_failure", True)

        # Create LLM client (real or mock)
        from .llm_client import create_llm_client

        llm_client = create_llm_client(config.get("llm", {}), mock=mock_llm)

        # Initialize agents
        self.scanner = ScannerAgent(rails_app_path, config)
        self.analyzer = AnalyzerAgent(rails_app_path, config, llm_client=llm_client)
        self.updater = UpdaterAgent(rails_app_path, config)
        self.fixer = FixerAgent(rails_app_path, config, llm_client=llm_client)
        self.verifier = VerifierAgent(rails_app_path, config)
        self.pr_creator = PRCreatorAgent(rails_app_path, config, jira_ticket=jira_ticket)

    def run(self) -> dict:
        """Run the full pipeline and return summary results."""
        results = {
            "vulnerabilities_found": 0,
            "vulnerabilities_fixed": 0,
            "vulnerabilities_failed": 0,
            "vulnerabilities_skipped": 0,
            "pr_url": None,
            "report_path": None,
            "details": [],
        }

        # ── Step 1: Scan ──
        logger.info("═══ Step 1: Scanning for vulnerabilities ═══")
        vulnerabilities = self.scanner.scan()
        results["vulnerabilities_found"] = len(vulnerabilities)

        if not vulnerabilities:
            logger.info("No vulnerabilities found. All clear!")
            return results

        # Filter to target gem if specified
        if self.target_gem:
            vulnerabilities = [v for v in vulnerabilities if v.gem == self.target_gem]
            if not vulnerabilities:
                logger.warning(f"No vulnerabilities found for gem: {self.target_gem}")
                return results

        logger.info(f"Found {len(vulnerabilities)} vulnerabilities to process")

        # ── Process each vulnerability ──
        for i, vuln in enumerate(vulnerabilities, 1):
            logger.info(f"\n{'═' * 60}")
            logger.info(f"Processing [{i}/{len(vulnerabilities)}]: {vuln.gem} ({vuln.cve})")
            logger.info(f"{'═' * 60}")

            fix_result = self._process_vulnerability(vuln)
            results["details"].append(fix_result)

            if fix_result.status == FixStatus.SUCCESS:
                results["vulnerabilities_fixed"] += 1
            elif fix_result.status == FixStatus.SKIPPED:
                results["vulnerabilities_skipped"] += 1
            else:
                results["vulnerabilities_failed"] += 1

        # ── Create PR if all fixes succeeded ──
        if self.create_pr and results["vulnerabilities_fixed"] > 0:
            # Use the last successful analysis/fix for PR
            successful = [d for d in results["details"] if d.status == FixStatus.SUCCESS]
            if successful:
                pr_url = self._create_combined_pr(successful, results)
                results["pr_url"] = pr_url

        # ── Generate report ──
        report_path = self._generate_report(results)
        results["report_path"] = str(report_path)

        return results

    def _process_vulnerability(self, vuln: Vulnerability) -> FixResult:
        """Process a single vulnerability through the full pipeline."""
        fix_result = FixResult(vulnerability=vuln)

        # ── Step 2: Analyze ──
        logger.info("  ── Analyzing...")
        analysis = self.analyzer.analyze(vuln)

        # Check if safe to auto-upgrade
        if not analysis.safe_to_auto_upgrade:
            logger.warning(
                f"  ⚠ {vuln.gem} is NOT safe for auto-upgrade "
                f"(risk: {analysis.risk_level.value}, score: {analysis.risk_score:.2f})"
            )
            if analysis.risk_level == RiskLevel.HIGH and not self.target_gem:
                logger.warning("  Skipping high-risk upgrade. Use --gem flag to force.")
                fix_result.status = FixStatus.SKIPPED
                fix_result.error_message = "High risk - manual review required"
                return fix_result

        if self.dry_run:
            logger.info("  [DRY RUN] Would upgrade, skipping actual changes.")
            fix_result.status = FixStatus.SKIPPED
            return fix_result

        # Save git state for potential rollback
        original_state = self._save_git_state()

        # ── Step 3: Update gem ──
        logger.info("  ── Updating gem...")
        update_result = self.updater.update(analysis)

        if not update_result["success"]:
            logger.error(f"  ✗ Failed to update {vuln.gem}: {update_result['error'][:200]}")
            fix_result.status = FixStatus.FAILED
            fix_result.error_message = update_result["error"]
            self._rollback(original_state)
            return fix_result

        fix_result.gemfile_changes = update_result["changes"]

        # ── Step 4: Fix breaking changes (proactive) ──
        if analysis.requires_code_changes:
            logger.info("  ── Fixing breaking changes...")
            code_fixes = self.fixer.fix_breaking_changes(analysis)
            fix_result.code_changes = [f.get("description", "") for f in code_fixes]

        # ── Step 5: Verify ──
        logger.info("  ── Verifying...")
        verification = self.verifier.verify()

        # ── Step 6: Retry loop if tests fail ──
        attempts = 1
        while not verification.success and attempts < self.max_retries:
            attempts += 1
            logger.info(f"  ── Retry attempt {attempts}/{self.max_retries}...")

            # Get the fixer to try to fix based on test output
            retry_fixes = self.fixer.fix_from_test_failure(
                analysis=analysis,
                test_output=verification.stdout + verification.stderr,
                failed_specs=verification.failed_specs,
            )

            if not retry_fixes:
                logger.warning("  No fixes generated, stopping retry.")
                break

            fix_result.code_changes.extend([f.get("description", "") for f in retry_fixes])

            # Re-verify
            verification = self.verifier.verify()

        fix_result.attempts = attempts
        fix_result.verification_output = verification.stdout[:500]

        if verification.success:
            logger.info(f"  ✓ {vuln.gem} upgraded successfully!")
            fix_result.status = FixStatus.SUCCESS
        else:
            logger.error(f"  ✗ {vuln.gem} upgrade failed after {attempts} attempts")
            fix_result.status = FixStatus.FAILED
            fix_result.error_message = verification.stderr[:500]

            if self.rollback_on_failure:
                logger.info("  Rolling back changes...")
                self._rollback(original_state)
                fix_result.status = FixStatus.ROLLED_BACK

        return fix_result

    def _create_combined_pr(self, successful_fixes: list[FixResult], results: dict) -> Optional[str]:
        """Create a single PR for all successful fixes."""
        # Use the first fix's analysis for the PR (simplified)
        # In a real implementation, you'd combine all analyses
        first_fix = successful_fixes[0]

        # Re-run analysis for PR metadata (could cache this)
        analysis = self.analyzer.analyze(first_fix.vulnerability)
        verification = VerificationResult(
            success=True,
            tests_passed=True,
            rubocop_passed=True,
            brakeman_passed=True,
            audit_clean=True,
        )

        return self.pr_creator.create_pr(analysis, first_fix, verification)

    def _save_git_state(self) -> str:
        """Save current git state for rollback."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.rails_app_path,
                capture_output=True,
                text=True,
            )
            return result.stdout.strip()
        except Exception:
            return ""

    def _rollback(self, commit_hash: str) -> None:
        """Rollback to a previous git state."""
        if not commit_hash:
            return

        try:
            subprocess.run(
                ["git", "checkout", "--", "."],
                cwd=self.rails_app_path,
                capture_output=True,
            )
            subprocess.run(
                ["git", "clean", "-fd"],
                cwd=self.rails_app_path,
                capture_output=True,
            )
            logger.info("  Rolled back to previous state.")
        except Exception as e:
            logger.error(f"  Rollback failed: {e}")

    def _generate_report(self, results: dict) -> Path:
        """Generate a JSON report of the agent run."""
        reports_dir = Path(__file__).parent.parent / "reports"
        reports_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = reports_dir / f"vuln_report_{timestamp}.json"

        # Serialize results (handle dataclass objects)
        serializable = {
            "timestamp": datetime.now().isoformat(),
            "rails_app": str(self.rails_app_path),
            "vulnerabilities_found": results["vulnerabilities_found"],
            "vulnerabilities_fixed": results["vulnerabilities_fixed"],
            "vulnerabilities_failed": results["vulnerabilities_failed"],
            "vulnerabilities_skipped": results["vulnerabilities_skipped"],
            "pr_url": results.get("pr_url"),
            "details": [],
        }

        for fix_result in results.get("details", []):
            serializable["details"].append({
                "gem": fix_result.vulnerability.gem,
                "cve": fix_result.vulnerability.cve,
                "status": fix_result.status.value,
                "attempts": fix_result.attempts,
                "gemfile_changes": fix_result.gemfile_changes,
                "code_changes": fix_result.code_changes,
                "error": fix_result.error_message,
            })

        report_path.write_text(json.dumps(serializable, indent=2))
        logger.info(f"Report saved to: {report_path}")

        return report_path
