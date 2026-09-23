# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""PR security review: run SAST only on the files a change touches.

For CI on a pull request, scanning the whole repo every time is noisy; this
reviews just the changed files between a base and a head ref with semgrep, maps
the results to evidence-backed findings, and can post a summary comment on the PR
with `gh`. Same evidence-first rule: a finding is a real semgrep match on a real
changed line. Works on a local checkout or a cloned repo URL.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field

from . import sast
from .runner import resolve_tool

_CODE_EXT = (".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php", ".java",
             ".c", ".cpp", ".cs", ".rs", ".kt", ".scala", ".sh", ".mjs", ".cjs")


@dataclass
class PRReview:
    repo: str
    base: str
    head: str
    changed: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    note: str = ""
    error: str | None = None


def _git(repo_dir: str, *args, timeout: int = 60) -> tuple[int, str, str]:
    git = resolve_tool("git")
    if not git:
        return 127, "", "git not installed"
    try:
        p = subprocess.run([git, "-C", repo_dir, *args], capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:  # pragma: no cover - defensive
        return 1, "", f"{type(e).__name__}: {e}"


def changed_files(repo_dir: str, base: str, head: str = "HEAD") -> tuple[list[str], str | None]:
    rc, out, err = _git(repo_dir, "diff", "--name-only", f"{base}...{head}")
    if rc != 0:
        # fall back to a two-dot diff if the merge-base form fails
        rc, out, err = _git(repo_dir, "diff", "--name-only", base, head)
    if rc != 0:
        return [], err.strip() or f"git diff failed (base={base}, head={head})"
    files = [ln.strip() for ln in out.splitlines() if ln.strip().endswith(_CODE_EXT)]
    return files, None


def review(repo_dir: str, base: str, head: str = "HEAD", timeout: int = 600) -> PRReview:
    r = PRReview(repo=repo_dir, base=base, head=head)
    files, err = changed_files(repo_dir, base, head)
    if err:
        r.error = err
        return r
    r.changed = files
    if not files:
        r.note = "No changed code files between base and head; nothing to review."
        return r
    semgrep = resolve_tool("semgrep")
    if not semgrep:
        r.error = 'semgrep not installed (pip install "sentari[sast]")'
        return r
    try:
        p = subprocess.run(
            [semgrep, "--config", "auto", "--json", "--quiet", "--", *files],
            cwd=repo_dir, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        r.error = f"semgrep timed out after {timeout}s"
        return r
    results = sast.parse_semgrep(p.stdout)
    for res in results:
        r.findings.append({
            "check_id": res["check_id"], "severity": res["severity"],
            "path": res["path"], "line": res["line"], "message": res["message"],
            "cwe": res["cwe"], "owasp": res["owasp"],
        })
    r.note = f"semgrep reviewed {len(files)} changed file(s), {len(r.findings)} finding(s)."
    return r


def comment_body(r: PRReview) -> str:
    lines = ["## Sentari PR security review", ""]
    if r.error:
        lines.append(f"Review could not complete: {r.error}")
        return "\n".join(lines)
    lines.append(f"Reviewed **{len(r.changed)}** changed code file(s); "
                 f"**{len(r.findings)}** finding(s).")
    if not r.findings:
        lines.append("\nNo new SAST findings on the changed files. ✅")
        return "\n".join(lines)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    lines.append("\n| Severity | Rule | Location |")
    lines.append("|---|---|---|")
    for f in sorted(r.findings, key=lambda x: order.get(x["severity"], 4)):
        loc = f"{f['path']}:{f['line']}" if f["line"] else f["path"]
        lines.append(f"| {f['severity'].upper()} | `{f['check_id']}` | `{loc}` |")
    lines.append("\nEach finding is a real semgrep match on a changed line.")
    return "\n".join(lines)


def post_comment(pr: str, body: str, repo_slug: str | None = None) -> tuple[bool, str]:
    gh = resolve_tool("gh")
    if not gh:
        return False, "gh CLI not installed; cannot post the PR comment"
    cmd = [gh, "pr", "comment", str(pr), "--body", body]
    if repo_slug:
        cmd += ["--repo", repo_slug]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as e:  # pragma: no cover - defensive
        return False, f"{type(e).__name__}: {e}"
    if p.returncode != 0:
        return False, p.stderr.strip()[:200]
    return True, "comment posted"
