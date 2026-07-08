"""Agent 4: Code Fixer

Uses LLM to automatically fix application code that breaks
after a gem upgrade (API changes, deprecations, etc.)
"""

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

from .llm_client import LLMClient
from .models import AnalysisResult

logger = logging.getLogger("vuln-agent.fixer")

FIXER_SYSTEM_PROMPT = """You are a senior Ruby on Rails engineer fixing code broken by a gem upgrade.

Given:
- The gem that was upgraded
- The breaking changes
- The error/failure output
- The relevant source code

You must produce a JSON response with the exact file modifications needed:

{
  "fixes": [
    {
      "file": "relative/path/to/file.rb",
      "description": "What this fix does",
      "search": "exact text to find (multiline ok)",
      "replace": "replacement text"
    }
  ],
  "explanation": "Summary of all changes made"
}

Rules:
1. The "search" field must match EXACTLY what's in the file (whitespace matters).
2. Each fix should be minimal and focused.
3. Prefer updating to the new API over workarounds.
4. If Sidekiq::Worker → Sidekiq::Job, update includes accordingly.
5. If ActiveRecord API changes, update queries.
6. Preserve existing functionality and test behavior.
7. Only fix what's actually broken - don't refactor unrelated code.
"""


class FixerAgent:
    """Fixes application code broken by gem upgrades."""

    def __init__(self, rails_app_path: Path, config: dict, llm_client=None):
        self.rails_app_path = rails_app_path
        self.llm = llm_client or LLMClient(config.get("llm", {}))

    def fix_breaking_changes(self, analysis: AnalysisResult) -> list[dict]:
        """Proactively fix known breaking changes before running tests.

        Returns list of applied fixes.
        """
        if not analysis.requires_code_changes:
            logger.info("  No code changes required for this upgrade.")
            return []

        logger.info(f"  Fixing breaking changes for {analysis.vulnerability.gem}...")

        # Search codebase for patterns that need fixing
        affected_files = self._find_affected_files(analysis)

        if not affected_files:
            logger.info("  No affected files found in codebase.")
            return []

        # Ask LLM to generate fixes
        fixes = self._generate_fixes(analysis, affected_files)

        # Apply fixes
        applied = self._apply_fixes(fixes)
        return applied

    def fix_from_test_failure(
        self,
        analysis: AnalysisResult,
        test_output: str,
        failed_specs: list[str],
    ) -> list[dict]:
        """Fix code based on test failure output.

        Returns list of applied fixes.
        """
        logger.info(f"  Attempting to fix test failures for {analysis.vulnerability.gem}...")

        # Get relevant source code context
        relevant_code = self._get_failure_context(test_output, failed_specs)

        # Ask LLM to generate fixes
        fixes = self._generate_fixes_from_failure(analysis, test_output, relevant_code)

        # Apply fixes
        applied = self._apply_fixes(fixes)
        return applied

    def _find_affected_files(self, analysis: AnalysisResult) -> dict[str, str]:
        """Find files that may need changes based on the gem upgrade."""
        gem_name = analysis.vulnerability.gem
        affected_files: dict[str, str] = {}

        # Common patterns to search for based on gem name
        search_patterns = self._get_search_patterns(gem_name, analysis)

        for pattern in search_patterns:
            try:
                result = subprocess.run(
                    ["grep", "-rl", pattern, "--include=*.rb", "--include=*.rake", "."],
                    cwd=self.rails_app_path,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                for filepath in result.stdout.strip().splitlines():
                    if filepath and not filepath.startswith("./vendor/"):
                        full_path = self.rails_app_path / filepath.lstrip("./")
                        if full_path.exists():
                            affected_files[filepath] = full_path.read_text()
            except Exception as e:
                logger.debug(f"  grep for '{pattern}' failed: {e}")

        return affected_files

    def _get_search_patterns(self, gem_name: str, analysis: AnalysisResult) -> list[str]:
        """Get code patterns to search for based on gem and breaking changes."""
        patterns = []

        # Known gem-specific patterns
        gem_patterns = {
            "sidekiq": ["Sidekiq::Worker", "Sidekiq::Testing", "sidekiq_options"],
            "nokogiri": ["Nokogiri::XML", "Nokogiri::HTML", "Nokogiri::Slop"],
            "devise": ["Devise.setup", "devise_for", "current_user"],
            "rails": ["ActiveRecord::Base", "ApplicationRecord", "ActiveSupport"],
            "puma": ["Puma::Server", "puma.rb"],
            "redis": ["Redis.new", "Redis.current", "redis"],
            "faraday": ["Faraday.new", "Faraday::Connection"],
            "rspec": ["RSpec.describe", "RSpec.configure"],
            "pundit": ["Pundit", "authorize", "policy"],
            "cancancan": ["CanCan", "can?", "authorize!"],
        }

        if gem_name in gem_patterns:
            patterns.extend(gem_patterns[gem_name])
        else:
            # Generic: search for the gem's module name
            module_name = gem_name.replace("-", "::").title().replace("_", "")
            patterns.append(module_name)

        # Add patterns from breaking changes description
        for change in analysis.breaking_changes:
            # Extract class/method names from breaking change descriptions
            matches = re.findall(r"`([A-Z]\w+(?:::\w+)*)`", change)
            patterns.extend(matches)

        return list(set(patterns))

    def _generate_fixes(self, analysis: AnalysisResult, affected_files: dict[str, str]) -> list[dict]:
        """Ask LLM to generate code fixes for breaking changes."""
        # Truncate file contents to avoid token limits
        truncated_files = {}
        for filepath, content in affected_files.items():
            if len(content) > 3000:
                truncated_files[filepath] = content[:3000] + "\n... (truncated)"
            else:
                truncated_files[filepath] = content

        files_context = "\n\n".join(
            f"### {path}\n```ruby\n{content}\n```" for path, content in truncated_files.items()
        )

        user_message = f"""A gem was upgraded and code changes are needed:

## Upgrade Details
- Gem: {analysis.vulnerability.gem}
- From: {analysis.vulnerability.current_version}
- To: {analysis.recommended_version}

## Breaking Changes
{chr(10).join(f'- {change}' for change in analysis.breaking_changes)}

## Code Change Needed
{analysis.code_change_description}

## Affected Files
{files_context}

Generate the minimal JSON fixes to update these files for the new gem version.
"""

        response = self.llm.chat(
            system_prompt=FIXER_SYSTEM_PROMPT,
            user_message=user_message,
            json_mode=True,
        )

        return self._parse_fix_response(response)

    def _generate_fixes_from_failure(
        self,
        analysis: AnalysisResult,
        test_output: str,
        relevant_code: dict[str, str],
    ) -> list[dict]:
        """Generate fixes based on test failure output."""
        # Truncate test output
        if len(test_output) > 2000:
            test_output = test_output[:2000] + "\n... (truncated)"

        files_context = "\n\n".join(
            f"### {path}\n```ruby\n{content}\n```" for path, content in relevant_code.items()
        )

        user_message = f"""Tests failed after upgrading a gem. Fix the code:

## Upgrade Details
- Gem: {analysis.vulnerability.gem}
- From: {analysis.vulnerability.current_version}
- To: {analysis.recommended_version}

## Test Failure Output
```
{test_output}
```

## Relevant Source Code
{files_context}

Analyze the test failures and generate JSON fixes. Focus on the actual error, not test expectations
unless the gem's behavior intentionally changed.
"""

        response = self.llm.chat(
            system_prompt=FIXER_SYSTEM_PROMPT,
            user_message=user_message,
            json_mode=True,
        )

        return self._parse_fix_response(response)

    def _parse_fix_response(self, response: str) -> list[dict]:
        """Parse the LLM fix response."""
        try:
            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = json.loads(response)

            return data.get("fixes", [])

        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"  Failed to parse fix response: {e}")
            return []

    def _apply_fixes(self, fixes: list[dict]) -> list[dict]:
        """Apply fixes to files. Returns list of successfully applied fixes."""
        applied = []

        for fix in fixes:
            filepath = fix.get("file", "")
            search = fix.get("search", "")
            replace = fix.get("replace", "")

            if not filepath or not search:
                continue

            full_path = self.rails_app_path / filepath.lstrip("./")

            if not full_path.exists():
                logger.warning(f"  File not found: {filepath}")
                continue

            try:
                content = full_path.read_text()

                if search in content:
                    new_content = content.replace(search, replace, 1)
                    full_path.write_text(new_content)
                    logger.info(f"  ✓ Applied fix: {fix.get('description', filepath)}")
                    applied.append(fix)
                else:
                    logger.warning(f"  ✗ Pattern not found in {filepath}: {search[:60]}...")

            except Exception as e:
                logger.error(f"  ✗ Failed to apply fix to {filepath}: {e}")

        return applied

    def _get_failure_context(self, test_output: str, failed_specs: list[str]) -> dict[str, str]:
        """Extract relevant source files from test failure output."""
        relevant_files: dict[str, str] = {}

        # Extract file paths from error output
        file_pattern = re.compile(r"(?:./)?(\S+\.rb):(\d+)")
        matches = file_pattern.findall(test_output)

        for filepath, line_no in matches:
            if filepath.startswith("vendor/") or filepath.startswith("spec/"):
                continue

            full_path = self.rails_app_path / filepath
            if full_path.exists() and filepath not in relevant_files:
                try:
                    content = full_path.read_text()
                    if len(content) > 5000:
                        # Extract context around the error line
                        lines = content.splitlines()
                        line_idx = int(line_no) - 1
                        start = max(0, line_idx - 10)
                        end = min(len(lines), line_idx + 20)
                        content = "\n".join(lines[start:end])
                    relevant_files[filepath] = content
                except Exception:
                    pass

        # Also include failed spec files
        for spec_file in failed_specs[:5]:
            full_path = self.rails_app_path / spec_file
            if full_path.exists() and spec_file not in relevant_files:
                try:
                    relevant_files[spec_file] = full_path.read_text()[:3000]
                except Exception:
                    pass

        return relevant_files
