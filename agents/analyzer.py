"""Agent 2: AI Analyzer

Analyzes vulnerabilities using LLM to determine upgrade path,
breaking changes, Rails compatibility, and risk level.
"""

import json
import logging
import re
import subprocess
from pathlib import Path

from .llm_client import LLMClient
from .models import AnalysisResult, RiskLevel, Vulnerability

logger = logging.getLogger("vuln-agent.analyzer")

ANALYSIS_SYSTEM_PROMPT = """You are a senior Ruby on Rails security engineer specializing in gem dependency management.
Your job is to analyze a vulnerable gem and provide a detailed upgrade plan.

You must consider:
1. The current Rails version and its compatibility with the target gem version.
2. Breaking changes between the current and recommended version.
3. Whether code changes are required in the application.
4. The risk level of the upgrade (low/medium/high).

Always respond in valid JSON format with this structure:
{
  "recommended_version": "x.y.z",
  "breaking_changes": ["list of breaking changes"],
  "migration_steps": ["step 1", "step 2"],
  "rails_compatibility": "Compatible with Rails X.Y",
  "risk_level": "low|medium|high",
  "risk_score": 0.0-1.0,
  "changelog_summary": "Brief summary of important changes",
  "requires_code_changes": true/false,
  "code_change_description": "Description of code changes needed",
  "safe_to_auto_upgrade": true/false
}
"""


class AnalyzerAgent:
    """Analyzes vulnerabilities and determines upgrade strategy."""

    def __init__(self, rails_app_path: Path, config: dict, llm_client=None):
        self.rails_app_path = rails_app_path
        self.config = config.get("analyzer", {})
        self.llm = llm_client or LLMClient(config.get("llm", {}))
        self.risk_config = config.get("risk_scoring", {})

    def analyze(self, vulnerability: Vulnerability) -> AnalysisResult:
        """Analyze a vulnerability and produce an upgrade plan."""
        logger.info(f"Analyzing {vulnerability.gem} {vulnerability.current_version} (CVE: {vulnerability.cve})")

        # Gather context
        context = self._gather_context(vulnerability)

        # Ask LLM for analysis
        user_message = self._build_prompt(vulnerability, context)
        response = self.llm.chat(
            system_prompt=ANALYSIS_SYSTEM_PROMPT,
            user_message=user_message,
            json_mode=True,
        )

        # Parse response
        analysis = self._parse_response(vulnerability, response)
        logger.info(
            f"  → Recommended: {analysis.recommended_version}, "
            f"Risk: {analysis.risk_level.value}, "
            f"Auto-safe: {analysis.safe_to_auto_upgrade}"
        )

        return analysis

    def _gather_context(self, vulnerability: Vulnerability) -> dict:
        """Gather contextual information about the Rails app and gem."""
        context = {
            "rails_version": self._detect_rails_version(),
            "ruby_version": self._detect_ruby_version(),
            "gemfile_entry": self._get_gemfile_entry(vulnerability.gem),
            "dependent_gems": self._get_dependent_gems(vulnerability.gem),
        }
        return context

    def _detect_rails_version(self) -> str:
        """Detect the Rails version from Gemfile.lock."""
        lockfile = self.rails_app_path / "Gemfile.lock"
        try:
            content = lockfile.read_text()
            match = re.search(r"rails \((\d+\.\d+\.\d+)\)", content)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "unknown"

    def _detect_ruby_version(self) -> str:
        """Detect Ruby version."""
        ruby_version_file = self.rails_app_path / ".ruby-version"
        if ruby_version_file.exists():
            return ruby_version_file.read_text().strip()

        try:
            result = subprocess.run(
                ["ruby", "-v"],
                cwd=self.rails_app_path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            match = re.search(r"ruby (\d+\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "unknown"

    def _get_gemfile_entry(self, gem_name: str) -> str:
        """Get the current Gemfile entry for the gem."""
        gemfile = self.rails_app_path / "Gemfile"
        try:
            for line in gemfile.read_text().splitlines():
                if re.search(rf"""gem\s+['"]({gem_name})['"]""", line):
                    return line.strip()
        except Exception:
            pass
        return ""

    def _get_dependent_gems(self, gem_name: str) -> list[str]:
        """Find gems that depend on the target gem."""
        lockfile = self.rails_app_path / "Gemfile.lock"
        dependents = []
        try:
            content = lockfile.read_text()
            # Simple heuristic: look for gems that list this gem as a dependency
            in_specs = False
            current_gem = ""
            for line in content.splitlines():
                if line.strip() == "specs:":
                    in_specs = True
                    continue
                if in_specs:
                    # Top-level gem (4 spaces indent)
                    match = re.match(r"    (\S+) \(", line)
                    if match:
                        current_gem = match.group(1)
                        continue
                    # Dependency (6+ spaces indent)
                    dep_match = re.match(r"      (\S+)", line)
                    if dep_match and dep_match.group(1) == gem_name:
                        dependents.append(current_gem)
        except Exception:
            pass
        return dependents[:10]  # Limit to top 10

    def _build_prompt(self, vulnerability: Vulnerability, context: dict) -> str:
        """Build the analysis prompt for the LLM."""
        patched = ", ".join(vulnerability.patched_versions) if vulnerability.patched_versions else "unknown"

        prompt = f"""Analyze this gem vulnerability and provide an upgrade plan:

## Vulnerability Details
- Gem: {vulnerability.gem}
- Current Version: {vulnerability.current_version}
- Patched Versions: {patched}
- CVE: {vulnerability.cve}
- Severity: {vulnerability.severity.value}
- Title: {vulnerability.title}
- Description: {vulnerability.description[:500] if vulnerability.description else 'N/A'}

## Application Context
- Rails Version: {context['rails_version']}
- Ruby Version: {context['ruby_version']}
- Current Gemfile Entry: {context['gemfile_entry'] or 'Not directly in Gemfile (transitive dependency)'}
- Gems depending on {vulnerability.gem}: {', '.join(context['dependent_gems']) or 'None found'}

## Instructions
1. Recommend the minimum safe version that fixes this CVE.
2. List any breaking changes between current and recommended version.
3. Determine if this upgrade requires application code changes.
4. Assess Rails compatibility.
5. Provide a risk score (0.0 = trivial, 1.0 = extremely risky).
6. Determine if this is safe for automated upgrade (no manual intervention needed).

Respond with valid JSON only.
"""
        return prompt

    def _parse_response(self, vulnerability: Vulnerability, response: str) -> AnalysisResult:
        """Parse the LLM response into an AnalysisResult."""
        try:
            # Try to extract JSON from the response
            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = json.loads(response)

            risk_level_str = data.get("risk_level", "medium").lower()
            risk_level = RiskLevel(risk_level_str) if risk_level_str in ["low", "medium", "high"] else RiskLevel.MEDIUM

            return AnalysisResult(
                vulnerability=vulnerability,
                recommended_version=data.get("recommended_version", ""),
                breaking_changes=data.get("breaking_changes", []),
                migration_steps=data.get("migration_steps", []),
                rails_compatibility=data.get("rails_compatibility", ""),
                risk_level=risk_level,
                risk_score=float(data.get("risk_score", 0.5)),
                changelog_summary=data.get("changelog_summary", ""),
                requires_code_changes=data.get("requires_code_changes", False),
                code_change_description=data.get("code_change_description", ""),
                safe_to_auto_upgrade=data.get("safe_to_auto_upgrade", True),
            )

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            # Return a conservative default
            return AnalysisResult(
                vulnerability=vulnerability,
                recommended_version=vulnerability.patched_versions[0] if vulnerability.patched_versions else "",
                risk_level=RiskLevel.HIGH,
                risk_score=0.8,
                safe_to_auto_upgrade=False,
            )
