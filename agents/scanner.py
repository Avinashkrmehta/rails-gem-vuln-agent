"""Agent 1: Vulnerability Scanner

Detects vulnerabilities using bundle-audit and osv-scanner.
"""

import json
import logging
import re
import subprocess
from pathlib import Path

from .models import Severity, Vulnerability
from .shell_runner import run_ruby_command

logger = logging.getLogger("vuln-agent.scanner")


class ScannerAgent:
    """Scans a Rails application for gem vulnerabilities."""

    def __init__(self, rails_app_path: Path, config: dict):
        self.rails_app_path = rails_app_path
        self.config = config.get("scanner", {})
        self.tools = self.config.get("tools", ["bundle-audit"])
        self.severity_threshold = self.config.get("severity_threshold", "medium")

    def scan(self) -> list[Vulnerability]:
        """Run all configured scanners and return deduplicated vulnerabilities."""
        vulnerabilities: list[Vulnerability] = []
        any_scanner_ran = False

        if "bundle-audit" in self.tools:
            results = self._run_bundle_audit()
            if results is not None:
                any_scanner_ran = True
                vulnerabilities.extend(results)

        if "osv-scanner" in self.tools:
            results = self._run_osv_scanner()
            if results is not None:
                any_scanner_ran = True
                vulnerabilities.extend(results)

        if not any_scanner_ran:
            raise RuntimeError(
                "No vulnerability scanners could run. Install at least one:\n"
                "  gem install bundler-audit\n"
                "  OR install osv-scanner (https://github.com/google/osv-scanner)"
            )

        # Deduplicate by CVE
        seen_cves: set[str] = set()
        unique_vulns: list[Vulnerability] = []
        for vuln in vulnerabilities:
            if vuln.cve not in seen_cves:
                seen_cves.add(vuln.cve)
                unique_vulns.append(vuln)

        # Filter by severity threshold
        filtered = self._filter_by_severity(unique_vulns)

        logger.info(f"Found {len(filtered)} vulnerabilities above threshold '{self.severity_threshold}'")
        return filtered

    def _run_bundle_audit(self) -> list[Vulnerability] | None:
        """Run bundle-audit and parse output. Returns None if tool unavailable."""
        logger.info("Running bundle-audit check --update...")

        # First check if bundle-audit is available (via login shell for RVM)
        check = run_ruby_command(
            ["bundle-audit", "--version"],
            cwd=self.rails_app_path,
            timeout=30,
        )

        if check.returncode != 0:
            # Try alternative: bundle exec bundle-audit
            check = run_ruby_command(
                ["bundle", "exec", "bundle-audit", "--version"],
                cwd=self.rails_app_path,
                timeout=30,
            )
            if check.returncode == 0:
                self._audit_cmd_prefix = "bundle exec bundle-audit"
            else:
                logger.error("bundle-audit not found. Install with: gem install bundler-audit")
                return None
        else:
            self._audit_cmd_prefix = "bundle-audit"

        try:
            # Update the advisory database
            run_ruby_command(
                f"{self._audit_cmd_prefix} update",
                cwd=self.rails_app_path,
                timeout=120,
            )

            # Run the audit with JSON format
            result = run_ruby_command(
                f"{self._audit_cmd_prefix} check --format json",
                cwd=self.rails_app_path,
                timeout=120,
            )

            # bundle-audit returns exit code 0 if no vulnerabilities
            if result.returncode == 0:
                logger.info("bundle-audit: No vulnerabilities found.")
                return []

            return self._parse_bundle_audit_json(result.stdout)

        except Exception as e:
            logger.error(f"bundle-audit failed: {e}")
            # Try text-based fallback
            return self._run_bundle_audit_text()

    def _run_bundle_audit_text(self) -> list[Vulnerability] | None:
        """Fallback: run bundle-audit with text output and parse it."""
        cmd_prefix = getattr(self, "_audit_cmd_prefix", "bundle-audit")
        try:
            result = run_ruby_command(
                f"{cmd_prefix} check --update",
                cwd=self.rails_app_path,
                timeout=120,
            )

            return self._parse_bundle_audit_text(result.stdout + result.stderr)
        except Exception as e:
            logger.error(f"bundle-audit text fallback failed: {e}")
            return None

    def _parse_bundle_audit_json(self, output: str) -> list[Vulnerability]:
        """Parse JSON output from bundle-audit."""
        vulnerabilities = []

        try:
            data = json.loads(output)
            results = data.get("results", [])

            for item in results:
                advisory = item.get("advisory", {})
                gem_info = item.get("gem", {})

                vuln = Vulnerability(
                    gem=gem_info.get("name", "unknown"),
                    current_version=gem_info.get("version", "0.0.0"),
                    patched_versions=advisory.get("patched_versions", []),
                    cve=advisory.get("cve", advisory.get("id", "UNKNOWN")),
                    title=advisory.get("title", ""),
                    severity=self._map_severity(advisory.get("criticality", "medium")),
                    advisory_url=advisory.get("url", ""),
                    description=advisory.get("description", ""),
                )
                vulnerabilities.append(vuln)

        except json.JSONDecodeError:
            logger.warning("Failed to parse bundle-audit JSON, falling back to text parsing")
            return self._parse_bundle_audit_text(output)

        return vulnerabilities

    def _parse_bundle_audit_text(self, output: str) -> list[Vulnerability]:
        """Parse text output from bundle-audit."""
        vulnerabilities = []
        current_block: dict = {}

        for line in output.split("\n"):
            line = line.strip()

            if line.startswith("Name:"):
                current_block["gem"] = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                current_block["current_version"] = line.split(":", 1)[1].strip()
            elif line.startswith("CVE:"):
                current_block["cve"] = line.split(":", 1)[1].strip()
            elif line.startswith("Advisory:"):
                cve_or_id = line.split(":", 1)[1].strip()
                if "cve" not in current_block:
                    current_block["cve"] = cve_or_id
            elif line.startswith("Criticality:"):
                current_block["severity"] = line.split(":", 1)[1].strip().lower()
            elif line.startswith("Title:"):
                current_block["title"] = line.split(":", 1)[1].strip()
            elif line.startswith("URL:"):
                current_block["advisory_url"] = line.split(":", 1)[1].strip()
            elif line.startswith("Solution:"):
                solution = line.split(":", 1)[1].strip()
                # Extract patched versions from solution text
                versions = re.findall(r"[\d]+\.[\d]+\.[\d]+[\w.]*", solution)
                current_block["patched_versions"] = versions

            # End of a vulnerability block
            if line == "" and current_block.get("gem"):
                vuln = Vulnerability(
                    gem=current_block.get("gem", ""),
                    current_version=current_block.get("current_version", ""),
                    patched_versions=current_block.get("patched_versions", []),
                    cve=current_block.get("cve", "UNKNOWN"),
                    title=current_block.get("title", ""),
                    severity=self._map_severity(current_block.get("severity", "medium")),
                    advisory_url=current_block.get("advisory_url", ""),
                )
                vulnerabilities.append(vuln)
                current_block = {}

        # Handle last block
        if current_block.get("gem"):
            vuln = Vulnerability(
                gem=current_block.get("gem", ""),
                current_version=current_block.get("current_version", ""),
                patched_versions=current_block.get("patched_versions", []),
                cve=current_block.get("cve", "UNKNOWN"),
                title=current_block.get("title", ""),
                severity=self._map_severity(current_block.get("severity", "medium")),
                advisory_url=current_block.get("advisory_url", ""),
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _run_osv_scanner(self) -> list[Vulnerability] | None:
        """Run osv-scanner and parse output."""
        logger.info("Running osv-scanner...")

        try:
            result = subprocess.run(
                ["osv-scanner", "--lockfile", "Gemfile.lock", "--format", "json"],
                cwd=self.rails_app_path,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                logger.info("osv-scanner: No vulnerabilities found.")
                return []

            return self._parse_osv_output(result.stdout)

        except FileNotFoundError:
            logger.warning("osv-scanner not found. Skipping.")
            return None
        except subprocess.TimeoutExpired:
            logger.error("osv-scanner timed out")
            return []

    def _parse_osv_output(self, output: str) -> list[Vulnerability]:
        """Parse osv-scanner JSON output."""
        vulnerabilities = []

        try:
            data = json.loads(output)
            results = data.get("results", [])

            for result in results:
                packages = result.get("packages", [])
                for pkg in packages:
                    pkg_info = pkg.get("package", {})
                    if pkg_info.get("ecosystem") != "RubyGems":
                        continue

                    for vuln_data in pkg.get("vulnerabilities", []):
                        aliases = vuln_data.get("aliases", [])
                        cve = next((a for a in aliases if a.startswith("CVE-")), aliases[0] if aliases else "UNKNOWN")

                        # Extract fix versions
                        fix_versions = []
                        for affected in vuln_data.get("affected", []):
                            for rng in affected.get("ranges", []):
                                for event in rng.get("events", []):
                                    if "fixed" in event:
                                        fix_versions.append(event["fixed"])

                        vuln = Vulnerability(
                            gem=pkg_info.get("name", ""),
                            current_version=pkg_info.get("version", ""),
                            patched_versions=fix_versions,
                            cve=cve,
                            title=vuln_data.get("summary", ""),
                            severity=self._osv_severity(vuln_data),
                            description=vuln_data.get("details", ""),
                        )
                        vulnerabilities.append(vuln)

        except json.JSONDecodeError:
            logger.error("Failed to parse osv-scanner JSON output")

        return vulnerabilities

    def _osv_severity(self, vuln_data: dict) -> Severity:
        """Extract severity from OSV vulnerability data."""
        severity_list = vuln_data.get("severity", [])
        for sev in severity_list:
            score = sev.get("score", "")
            # CVSS score to severity
            try:
                # Extract numeric score from CVSS vector if present
                if "CVSS" in sev.get("type", ""):
                    # Simple heuristic based on score ranges
                    score_val = float(score) if score.replace(".", "").isdigit() else 5.0
                    if score_val >= 9.0:
                        return Severity.CRITICAL
                    elif score_val >= 7.0:
                        return Severity.HIGH
                    elif score_val >= 4.0:
                        return Severity.MEDIUM
                    else:
                        return Severity.LOW
            except (ValueError, TypeError):
                pass

        return Severity.MEDIUM

    def _map_severity(self, severity_str: str | None) -> Severity:
        """Map a severity string to Severity enum."""
        if not severity_str:
            return Severity.MEDIUM
        mapping = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }
        return mapping.get(severity_str.lower(), Severity.MEDIUM)

    def _filter_by_severity(self, vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
        """Filter vulnerabilities by configured severity threshold."""
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        threshold_idx = severity_order.index(self._map_severity(self.severity_threshold))

        return [v for v in vulnerabilities if severity_order.index(v.severity) >= threshold_idx]
