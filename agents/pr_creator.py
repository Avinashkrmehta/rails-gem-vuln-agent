"""Agent 7: Pull Request Creator

Creates a pull request on GitHub or Bitbucket with a detailed
explanation of the security fix, changes made, and validation results.

Supports:
- GitHub (via `gh` CLI or REST API)
- Bitbucket Cloud (via REST API)
"""

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Optional

import requests

from .models import AnalysisResult, FixResult, VerificationResult

logger = logging.getLogger("vuln-agent.pr-creator")


class PRCreatorAgent:
    """Creates a pull request for the security fix (GitHub or Bitbucket)."""

    def __init__(self, rails_app_path: Path, config: dict, jira_ticket: Optional[str] = None):
        self.rails_app_path = rails_app_path
        self.config = config.get("pr", {})
        self.branch_pattern = self.config.get("branch_pattern", "security/fix-{gem}-{cve}")
        self.labels = self.config.get("labels", ["security", "automated"])
        self.reviewers = self.config.get("reviewers", [])
        self.jira_ticket = jira_ticket or os.environ.get("JIRA_TICKET_PREFIX", "").strip()

        # Detect platform
        self.platform = self._detect_platform()

    def _detect_platform(self) -> str:
        """Detect whether repo is on GitHub or Bitbucket.

        Priority:
        1. Explicit GIT_PLATFORM env var
        2. BITBUCKET_SERVER_URL or BITBUCKET_WORKSPACE being set → bitbucket
        3. GITHUB_TOKEN and GITHUB_REPO_OWNER being set → github
        4. Parse git remote URL
        """
        explicit = os.environ.get("GIT_PLATFORM", "").lower()
        if explicit in ("github", "bitbucket"):
            return explicit

        if os.environ.get("BITBUCKET_SERVER_URL") or os.environ.get("BITBUCKET_WORKSPACE"):
            return "bitbucket"

        if os.environ.get("GITHUB_TOKEN", "").strip() and os.environ.get("GITHUB_REPO_OWNER", "").strip():
            return "github"

        # Try to detect from git remote
        try:
            result = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                cwd=self.rails_app_path,
                capture_output=True,
                text=True,
            )
            remote_url = result.stdout.strip().lower()
            if "bitbucket" in remote_url:
                return "bitbucket"
            elif "github" in remote_url:
                return "github"
        except Exception:
            pass

        return "github"  # default

    def create_pr(
        self,
        analysis: AnalysisResult,
        fix_result: FixResult,
        verification: VerificationResult,
    ) -> Optional[str]:
        """Create a pull request.

        Returns the PR URL or None if creation failed.
        """
        vuln = analysis.vulnerability

        # Generate branch name with Jira ticket
        cve_slug = (vuln.cve or "unknown").lower().replace("-", "")
        if self.jira_ticket:
            branch_name = f"{self.jira_ticket}/fix-{vuln.gem}-{cve_slug}"
        else:
            branch_name = self.branch_pattern.format(gem=vuln.gem, cve=cve_slug)

        logger.info(f"Creating PR on branch: {branch_name} (platform: {self.platform})")

        # Step 1: Create and switch to branch
        if not self._create_branch(branch_name):
            return None

        # Step 2: Commit changes (with Jira ticket in message)
        if self.jira_ticket:
            commit_msg = (
                f"{self.jira_ticket}: fix(security): Upgrade {vuln.gem} to "
                f"{analysis.recommended_version}\n\n"
                f"Fixes {vuln.cve}"
            )
        else:
            commit_msg = (
                f"fix(security): Upgrade {vuln.gem} to {analysis.recommended_version}\n\n"
                f"Fixes {vuln.cve}"
            )
        if not self._commit_changes(commit_msg):
            return None

        # Step 3: Push branch
        if not self._push_branch(branch_name):
            return None

        # Step 4: Create PR on the appropriate platform
        pr_body = self._generate_pr_body(analysis, fix_result, verification)
        pr_title = f"{self.jira_ticket + ': ' if self.jira_ticket else ''}Fix: Upgrade {vuln.gem} to {analysis.recommended_version} ({vuln.cve})"

        if self.platform == "bitbucket":
            return self._create_bitbucket_pr(branch_name, pr_title, pr_body)
        else:
            return self._create_github_pr(branch_name, pr_title, pr_body)

    # ── Git operations ──

    def _create_branch(self, branch_name: str) -> bool:
        """Create and checkout a new git branch."""
        try:
            # Detect default branch
            default_branch = self._get_default_branch()

            subprocess.run(
                ["git", "checkout", default_branch],
                cwd=self.rails_app_path,
                capture_output=True,
                text=True,
            )

            # Create new branch
            result = subprocess.run(
                ["git", "checkout", "-b", branch_name],
                cwd=self.rails_app_path,
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                # Branch might already exist
                subprocess.run(
                    ["git", "checkout", branch_name],
                    cwd=self.rails_app_path,
                    capture_output=True,
                    text=True,
                )

            return True
        except Exception as e:
            logger.error(f"Failed to create branch: {e}")
            return False

    def _get_default_branch(self) -> str:
        """Detect the default branch (main or master)."""
        result = subprocess.run(
            ["git", "branch", "--list", "main"],
            cwd=self.rails_app_path,
            capture_output=True,
            text=True,
        )
        if "main" in result.stdout:
            return "main"
        return "master"

    def _commit_changes(self, message: str) -> bool:
        """Stage and commit all changes."""
        try:
            subprocess.run(
                ["git", "add", "Gemfile", "Gemfile.lock"],
                cwd=self.rails_app_path,
                capture_output=True,
            )

            subprocess.run(
                ["git", "add", "-A"],
                cwd=self.rails_app_path,
                capture_output=True,
            )

            result = subprocess.run(
                ["git", "commit", "-m", message],
                cwd=self.rails_app_path,
                capture_output=True,
                text=True,
            )

            return result.returncode == 0
        except Exception as e:
            logger.error(f"Failed to commit: {e}")
            return False

    def _push_branch(self, branch_name: str) -> bool:
        """Push the branch to origin."""
        try:
            result = subprocess.run(
                ["git", "push", "-u", "origin", branch_name],
                cwd=self.rails_app_path,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                logger.error(f"Failed to push: {result.stderr}")
                return False
            return True
        except Exception as e:
            logger.error(f"Failed to push: {e}")
            return False

    # ── GitHub PR Creation ──

    def _create_github_pr(self, branch: str, title: str, body: str) -> Optional[str]:
        """Create PR on GitHub using `gh` CLI or REST API."""
        # Try gh CLI first
        pr_url = self._create_github_pr_cli(branch, title, body)
        if pr_url:
            return pr_url

        # Fallback to REST API
        return self._create_github_pr_api(branch, title, body)

    def _create_github_pr_cli(self, branch: str, title: str, body: str) -> Optional[str]:
        """Create PR using GitHub CLI (gh)."""
        try:
            cmd = [
                "gh", "pr", "create",
                "--title", title,
                "--body", body,
                "--head", branch,
            ]

            for label in self.labels:
                cmd.extend(["--label", label])

            for reviewer in self.reviewers:
                cmd.extend(["--reviewer", reviewer])

            result = subprocess.run(
                cmd,
                cwd=self.rails_app_path,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                pr_url = result.stdout.strip()
                logger.info(f"  PR created (gh CLI): {pr_url}")
                return pr_url
            else:
                logger.warning(f"  gh CLI failed: {result.stderr[:100]}")
                return None

        except FileNotFoundError:
            logger.info("  gh CLI not found, trying REST API...")
            return None
        except Exception as e:
            logger.warning(f"  gh CLI error: {e}")
            return None

    def _create_github_pr_api(self, branch: str, title: str, body: str) -> Optional[str]:
        """Create PR using GitHub REST API."""
        token = os.environ.get("GITHUB_TOKEN", "").strip()
        owner = os.environ.get("GITHUB_REPO_OWNER", "").strip()
        repo = os.environ.get("GITHUB_REPO_NAME", "").strip()

        if not all([token, owner, repo]):
            logger.error(
                "  Cannot create GitHub PR: missing GITHUB_TOKEN, "
                "GITHUB_REPO_OWNER, or GITHUB_REPO_NAME"
            )
            return None

        url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        payload = {
            "title": title,
            "body": body,
            "head": branch,
            "base": self._get_default_branch(),
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=15)
            if response.status_code == 201:
                pr_url = response.json()["html_url"]
                logger.info(f"  PR created (GitHub API): {pr_url}")
                return pr_url
            else:
                logger.error(f"  GitHub API error ({response.status_code}): {response.text[:200]}")
                return None
        except Exception as e:
            logger.error(f"  GitHub API failed: {e}")
            return None

    # ── Bitbucket PR Creation ──

    def _create_bitbucket_pr(self, branch: str, title: str, body: str) -> Optional[str]:
        """Create PR on Bitbucket (Cloud or Server).

        Auto-detects Cloud vs Server based on BITBUCKET_SERVER_URL.

        For Bitbucket Server (self-hosted):
        - BITBUCKET_SERVER_URL (e.g., https://bitbucket.csod.com)
        - BITBUCKET_TOKEN (Personal Access Token)
        - BITBUCKET_PROJECT (project key, e.g., ent-lx)
        - BITBUCKET_REPO_SLUG (repo name)

        For Bitbucket Cloud:
        - BITBUCKET_USERNAME
        - BITBUCKET_APP_PASSWORD
        - BITBUCKET_WORKSPACE
        - BITBUCKET_REPO_SLUG
        """
        server_url = os.environ.get("BITBUCKET_SERVER_URL", "").strip()

        if server_url:
            return self._create_bitbucket_server_pr(branch, title, body)
        else:
            return self._create_bitbucket_cloud_pr(branch, title, body)

    def _create_bitbucket_server_pr(self, branch: str, title: str, body: str) -> Optional[str]:
        """Create PR on Bitbucket Server (self-hosted, e.g., bitbucket.csod.com)."""
        server_url = os.environ.get("BITBUCKET_SERVER_URL", "").strip().rstrip("/")
        token = os.environ.get("BITBUCKET_TOKEN", "").strip()
        project = os.environ.get("BITBUCKET_PROJECT", "").strip()
        repo_slug = os.environ.get("BITBUCKET_REPO_SLUG", "").strip()

        if not all([server_url, token, project, repo_slug]):
            logger.error(
                "  Cannot create Bitbucket Server PR. Set these env vars:\n"
                "    BITBUCKET_SERVER_URL - e.g., https://bitbucket.csod.com\n"
                "    BITBUCKET_TOKEN - Personal Access Token\n"
                "    BITBUCKET_PROJECT - project key (e.g., ent-lx)\n"
                "    BITBUCKET_REPO_SLUG - repository slug (e.g., hrms_app)"
            )
            return None

        # Bitbucket Server REST API 1.0
        url = (
            f"{server_url}/rest/api/1.0/projects/{project}/repos/{repo_slug}/pull-requests"
        )

        payload = {
            "title": title,
            "description": body,
            "fromRef": {
                "id": f"refs/heads/{branch}",
            },
            "toRef": {
                "id": f"refs/heads/{self._get_default_branch()}",
            },
        }

        # Add reviewers if configured
        if self.reviewers:
            payload["reviewers"] = [{"user": {"name": r}} for r in self.reviewers]

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=15)

            if response.status_code in (200, 201):
                pr_data = response.json()
                pr_id = pr_data.get("id")
                pr_url = (
                    f"{server_url}/projects/{project}/repos/{repo_slug}"
                    f"/pull-requests/{pr_id}"
                )
                logger.info(f"  PR created (Bitbucket Server): {pr_url}")
                return pr_url
            else:
                logger.error(
                    f"  Bitbucket Server API error ({response.status_code}): "
                    f"{response.text[:200]}"
                )
                return None

        except Exception as e:
            logger.error(f"  Bitbucket Server API failed: {e}")
            return None

    def _create_bitbucket_cloud_pr(self, branch: str, title: str, body: str) -> Optional[str]:
        """Create PR on Bitbucket Cloud (bitbucket.org)."""
        username = os.environ.get("BITBUCKET_USERNAME", os.environ.get("BITBUCKET_USER", "")).strip()
        app_password = os.environ.get("BITBUCKET_APP_PASSWORD", "").strip()
        workspace = os.environ.get("BITBUCKET_WORKSPACE", "").strip()
        repo_slug = os.environ.get("BITBUCKET_REPO_SLUG", "").strip()

        if not all([username, app_password, workspace, repo_slug]):
            logger.error(
                "  Cannot create Bitbucket Cloud PR. Set these env vars:\n"
                "    BITBUCKET_USERNAME - your Bitbucket username\n"
                "    BITBUCKET_APP_PASSWORD - app password\n"
                "    BITBUCKET_WORKSPACE - workspace/org slug\n"
                "    BITBUCKET_REPO_SLUG - repository slug"
            )
            return None

        url = (
            f"https://api.bitbucket.org/2.0/repositories/"
            f"{workspace}/{repo_slug}/pullrequests"
        )

        payload = {
            "title": title,
            "description": body,
            "source": {
                "branch": {"name": branch},
            },
            "destination": {
                "branch": {"name": self._get_default_branch()},
            },
            "close_source_branch": True,
        }

        if self.reviewers:
            payload["reviewers"] = [{"username": r} for r in self.reviewers]

        try:
            response = requests.post(
                url,
                auth=(username, app_password),
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=15,
            )

            if response.status_code == 201:
                pr_data = response.json()
                pr_url = pr_data["links"]["html"]["href"]
                logger.info(f"  PR created (Bitbucket Cloud): {pr_url}")
                return pr_url
            else:
                logger.error(
                    f"  Bitbucket Cloud API error ({response.status_code}): "
                    f"{response.text[:200]}"
                )
                return None

        except Exception as e:
            logger.error(f"  Bitbucket Cloud API failed: {e}")
            return None

    # ── PR Body Generation ──

    def _generate_pr_body(
        self,
        analysis: AnalysisResult,
        fix_result: FixResult,
        verification: VerificationResult,
    ) -> str:
        """Generate a detailed PR description."""
        vuln = analysis.vulnerability

        # Changes section
        changes = []
        for change in fix_result.gemfile_changes:
            changes.append(f"- {change}")
        for change in fix_result.code_changes:
            changes.append(f"- {change}")

        changes_str = "\n".join(changes) if changes else "- Updated Gemfile.lock"

        # Validation section
        validations = []
        validations.append(f"{'✓' if verification.tests_passed else '✗'} Tests passed")
        validations.append(f"{'✓' if verification.rubocop_passed else '✗'} Rubocop passed")
        validations.append(f"{'✓' if verification.brakeman_passed else '✗'} Brakeman passed")
        validations.append(f"{'✓' if verification.audit_clean else '✗'} Bundle Audit clean")

        # Breaking changes
        breaking = ""
        if analysis.breaking_changes:
            breaking = "\n## Breaking Changes Addressed\n"
            for change in analysis.breaking_changes:
                breaking += f"- {change}\n"

        body = f"""## Security Fix: Upgrade {vuln.gem} to {analysis.recommended_version}

### Vulnerability
| Field | Value |
|-------|-------|
| CVE | {vuln.cve} |
| Gem | {vuln.gem} |
| Previous Version | {vuln.current_version} |
| Fixed Version | {analysis.recommended_version} |
| Severity | {vuln.severity.value.upper()} |
| Risk Level | {analysis.risk_level.value} |

### Reason
{vuln.title}

{vuln.description[:300] if vuln.description else ''}

### Changes
{changes_str}
{breaking}
### Validation Results
{chr(10).join(validations)}

### Risk Assessment
- **Risk Score:** {analysis.risk_score:.1f}/1.0
- **Rails Compatibility:** {analysis.rails_compatibility}
- **Changelog Summary:** {analysis.changelog_summary}

### Notes
- This PR was automatically generated by the Rails Gem Vulnerability Agent.
- Fix attempts: {fix_result.attempts}
- Please review the changes before merging.
"""
        return body
