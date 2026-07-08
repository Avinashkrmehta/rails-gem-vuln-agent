"""Utility functions for the vulnerability agent."""

import re
import subprocess
from pathlib import Path
from typing import Optional


def parse_semver(version: str) -> tuple[int, int, int]:
    """Parse a semantic version string into (major, minor, patch)."""
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if match:
        return int(match.group(1)), int(match.group(2)), int(match.group(3))
    return (0, 0, 0)


def is_major_bump(current: str, target: str) -> bool:
    """Check if upgrading from current to target is a major version bump."""
    curr = parse_semver(current)
    tgt = parse_semver(target)
    return tgt[0] > curr[0]


def is_minor_bump(current: str, target: str) -> bool:
    """Check if upgrading is a minor version bump."""
    curr = parse_semver(current)
    tgt = parse_semver(target)
    return tgt[0] == curr[0] and tgt[1] > curr[1]


def get_gem_version_from_lockfile(gem_name: str, rails_app_path: Path) -> Optional[str]:
    """Extract a gem's current version from Gemfile.lock."""
    lockfile = rails_app_path / "Gemfile.lock"
    if not lockfile.exists():
        return None

    content = lockfile.read_text()
    pattern = rf"^\s+{re.escape(gem_name)}\s+\((\S+)\)"
    match = re.search(pattern, content, re.MULTILINE)
    if match:
        return match.group(1)
    return None


def get_installed_gems(rails_app_path: Path) -> dict[str, str]:
    """Get all installed gems and their versions from Gemfile.lock."""
    lockfile = rails_app_path / "Gemfile.lock"
    if not lockfile.exists():
        return {}

    gems = {}
    content = lockfile.read_text()
    pattern = re.compile(r"^\s{4}(\S+)\s+\((\S+)\)", re.MULTILINE)

    for match in pattern.finditer(content):
        gems[match.group(1)] = match.group(2)

    return gems


def run_command(
    cmd: list[str],
    cwd: Path,
    timeout: int = 60,
) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def detect_rails_app_info(rails_app_path: Path) -> dict:
    """Detect key information about a Rails application."""
    info = {
        "rails_version": "unknown",
        "ruby_version": "unknown",
        "test_framework": "unknown",
        "has_rubocop": False,
        "has_brakeman": False,
        "has_sidekiq": False,
        "gem_count": 0,
    }

    # Rails version
    lockfile = rails_app_path / "Gemfile.lock"
    if lockfile.exists():
        content = lockfile.read_text()
        match = re.search(r"rails \((\d+\.\d+\.\d+)\)", content)
        if match:
            info["rails_version"] = match.group(1)

        # Count gems
        info["gem_count"] = len(re.findall(r"^\s{4}\S+ \(\S+\)", content, re.MULTILINE))

        # Check for specific gems
        info["has_sidekiq"] = "sidekiq" in content
        info["has_rubocop"] = "rubocop" in content
        info["has_brakeman"] = "brakeman" in content

    # Ruby version
    ruby_version_file = rails_app_path / ".ruby-version"
    if ruby_version_file.exists():
        info["ruby_version"] = ruby_version_file.read_text().strip()

    # Test framework
    if (rails_app_path / "spec").is_dir():
        info["test_framework"] = "rspec"
    elif (rails_app_path / "test").is_dir():
        info["test_framework"] = "minitest"

    return info
