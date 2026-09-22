# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Propose concrete code fixes as diffs, applied only by explicit user action.

For findings that map to a source location, this asks the AI for a minimal
unified diff that fixes the root cause, validates that the diff actually applies,
and writes it to a patch file. It never edits code on its own. A separate,
explicitly confirmed step applies the validated patches into the working tree
(uncommitted) so a human can review with `git diff` and decide. Nothing here
commits or merges.

The loop this supports, borrowed from disciplined engineering practice: propose,
let a human review and apply, then re-test to prove the fix landed.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

APPLY_CONFIRM = "APPLY THESE PATCHES TO MY WORKING TREE"


def _location_file(location: str, repo: Path) -> tuple[Path | None, int | None]:
    """Parse a 'path:line' finding location into a real file under repo."""
    if not location:
        return None, None
    path, _, line = location.partition(":")
    line_no = int(line) if line.isdigit() else None
    candidate = (repo / path).resolve()
    # path-traversal guard: the file must stay inside the repo
    try:
        candidate.relative_to(repo.resolve())
    except ValueError:
        return None, None
    return (candidate, line_no) if candidate.is_file() else (None, None)


def _context(file: Path, line: int | None, radius: int = 25) -> str:
    try:
        lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if line is None:
        return "\n".join(lines[:radius * 2])
    lo, hi = max(0, line - radius), min(len(lines), line + radius)
    return "\n".join(f"{i+1}: {lines[i]}" for i in range(lo, hi))


def validates(diff: str, repo: Path) -> bool:
    """True if the diff applies cleanly to repo (checked, not applied)."""
    if not diff.strip():
        return False
    r = subprocess.run(["git", "-C", str(repo), "apply", "--check", "-"],
                       input=diff, text=True, capture_output=True)
    return r.returncode == 0


def propose(results, repo_dir: str, provider, max_patches: int = 20) -> list[dict]:
    """Return proposed patches: {finding, file, rationale, diff}. AI-generated,
    each validated to apply. Findings without a source location are skipped."""
    repo = Path(repo_dir)
    out: list[dict] = []
    findings = [f for r in results for f in r.findings]
    for f in findings:
        if len(out) >= max_patches:
            break
        file, line = _location_file(getattr(f, "location", "") or "", repo)
        if file is None:
            continue
        rel = file.relative_to(repo.resolve())
        ctx = _context(file, line)
        if not ctx:
            continue
        system = ("You are a security engineer. Produce a MINIMAL unified diff that "
                  "fixes the described vulnerability at its root cause. Output ONLY the "
                  "diff, starting with '--- a/<path>' and '+++ b/<path>', using the exact "
                  "path given. No prose, no code fences.")
        user = (f"File: {rel}\nFinding: {f.title}\n{f.description}\n"
                f"Recommended fix: {getattr(f, 'recommendation', '') or 'n/a'}\n\n"
                f"Code around the finding (line-numbered):\n{ctx}")
        try:
            diff = provider.complete(system, user, max_tokens=1200)
        except Exception:
            continue
        diff = diff.strip()
        if diff.startswith("```"):
            diff = diff.strip("`")
            diff = diff.split("\n", 1)[1] if "\n" in diff else diff
        # a unified diff must end with a newline for `git apply` to accept it
        diff = diff.rstrip("\n") + "\n"
        if validates(diff, repo):
            out.append({"finding": f.title, "file": str(rel),
                        "rationale": getattr(f, "recommendation", "") or f.description,
                        "diff": diff})
    return out


def combined_patch(patches: list[dict]) -> str:
    """One patch file for all proposed diffs, with a header per finding."""
    parts = []
    for p in patches:
        parts.append(f"# Fix: {p['finding']} ({p['file']})\n{p['diff']}")
    return "\n".join(parts)


def apply(patches: list[dict], repo_dir: str) -> tuple[list[str], list[str]]:
    """Apply validated patches into the working tree (uncommitted). Returns
    (applied files, failed files). Only call after explicit user confirmation."""
    repo = Path(repo_dir)
    applied, failed = [], []
    for p in patches:
        r = subprocess.run(["git", "-C", str(repo), "apply", "-"],
                           input=p["diff"], text=True, capture_output=True)
        (applied if r.returncode == 0 else failed).append(p["file"])
    return applied, failed
