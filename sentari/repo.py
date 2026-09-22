# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Shallow-clone a source repository for static review (--code-review URL).

Enables the "add a repo for deeper analysis" step: a GitHub, GitLab, or
Bitbucket URL is cloned into a temporary directory, scanned with SAST, and
removed afterwards. Cloning uses the system git, so private repos work through
whatever credentials git already has (SSH keys, a credential helper, or a token
in the URL). Nothing is written outside the temporary directory.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")


def is_repo_url(value: str) -> bool:
    """True if the string looks like a git remote rather than a local path."""
    v = value.strip()
    if v.startswith(("http://", "https://", "git://", "ssh://", "git@")):
        return True
    if v.endswith(".git"):
        return True
    return any(h in v for h in _HOSTS)


def available() -> bool:
    return shutil.which("git") is not None


def clone(url: str, timeout: int = 300) -> tuple[str | None, str | None]:
    """Shallow-clone ``url`` into a fresh temp dir.

    Returns (path, error). On success path is the clone directory and error is
    None; the caller owns the directory and should pass it to :func:`cleanup`.
    """
    if not available():
        return None, "git not installed (needed to clone a repository)"
    dest = tempfile.mkdtemp(prefix="sentari-repo-")
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, dest],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        cleanup(dest)
        return None, f"git clone timed out after {timeout}s"
    except Exception as e:  # pragma: no cover - defensive
        cleanup(dest)
        return None, f"git clone failed: {type(e).__name__}: {e}"
    if proc.returncode != 0:
        cleanup(dest)
        return None, f"git clone failed: {proc.stderr.strip()[:300]}"
    return dest, None


def cleanup(path: str | None) -> None:
    if path and Path(path).exists():
        shutil.rmtree(path, ignore_errors=True)


def label(url: str) -> str:
    """A short, host-safe label for the repo (used as the scan target name)."""
    name = url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name or "repository"
