"""Shell runner that respects RVM/rbenv/asdf Ruby version managers.

When Python's subprocess runs commands, it doesn't load the shell profile
(~/.zshrc, ~/.bash_profile), so Ruby version managers like RVM don't activate.
This results in the wrong Ruby version being used.

This module wraps commands to run through a login shell so that RVM/rbenv/asdf
are properly initialized and .ruby-version is respected.
"""

import logging
import os
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger("vuln-agent.shell")


def run_ruby_command(
    cmd: list[str] | str,
    cwd: Path,
    timeout: int = 300,
    env: dict | None = None,
    stream_output: bool = False,
) -> subprocess.CompletedProcess:
    """Run a Ruby/Bundler command through a login shell.

    This ensures RVM/rbenv/asdf are loaded and .ruby-version is respected.

    Args:
        cmd: Command as list or string
        cwd: Working directory (the Rails app root)
        timeout: Timeout in seconds
        env: Additional environment variables
        stream_output: If True, stream stdout/stderr to console in real-time

    Returns:
        CompletedProcess with stdout, stderr, returncode
    """
    # Build the command string
    if isinstance(cmd, list):
        # Escape arguments for shell
        cmd_str = " ".join(_shell_escape(c) for c in cmd)
    else:
        cmd_str = cmd

    # Wrap in a login shell invocation
    # -l = login shell (loads ~/.zshrc or ~/.bash_profile which initializes RVM)
    # -c = execute command
    shell = os.environ.get("SHELL", "/bin/zsh")
    wrapped_cmd = [shell, "-l", "-c", f"cd {_shell_escape(str(cwd))} && {cmd_str}"]

    logger.debug(f"Running: {cmd_str} (in {cwd})")

    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    try:
        if stream_output:
            return _run_streaming(wrapped_cmd, timeout, merged_env)
        else:
            result = subprocess.run(
                wrapped_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=merged_env,
            )
            return result
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            args=wrapped_cmd,
            returncode=-1,
            stdout="",
            stderr=f"Command timed out after {timeout}s",
        )
    except Exception as e:
        return subprocess.CompletedProcess(
            args=wrapped_cmd,
            returncode=-1,
            stdout="",
            stderr=str(e),
        )


def _run_streaming(
    cmd: list[str],
    timeout: int,
    env: dict,
) -> subprocess.CompletedProcess:
    """Run command while streaming output to console and capturing it."""
    stdout_lines = []
    stderr_lines = []

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # Merge stderr into stdout for unified streaming
        text=True,
        env=env,
        bufsize=1,  # Line-buffered
    )

    try:
        for line in iter(proc.stdout.readline, ""):
            line_stripped = line.rstrip("\n")
            stdout_lines.append(line)
            # Print to console in real-time
            print(f"    │ {line_stripped}")

        proc.wait(timeout=timeout)

    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=-1,
            stdout="".join(stdout_lines),
            stderr=f"Command timed out after {timeout}s",
        )

    return subprocess.CompletedProcess(
        args=cmd,
        returncode=proc.returncode,
        stdout="".join(stdout_lines),
        stderr="",  # merged into stdout
    )


def _shell_escape(s: str) -> str:
    """Escape a string for safe shell usage."""
    # If it contains spaces or special chars, wrap in single quotes
    if any(c in s for c in " \t'\"\\$`!#&|;(){}[]<>?*~"):
        # Escape single quotes within the string
        return "'" + s.replace("'", "'\"'\"'") + "'"
    return s
