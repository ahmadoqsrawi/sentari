# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Preflight: report which external tools are present before a scan runs.

A phase quietly degrades to zero findings when its tool is missing (that is by
design, no fabrication), but on a hand-run box or a worker with a minimal PATH a
missing scanner is easy to miss. Preflight makes it explicit: it lists every
optional tool, whether it was found (searching PATH and known install dirs), and
what it is for, so "0 findings" is never confused with "tool not installed".
"""
from __future__ import annotations

from dataclasses import dataclass

from .runner import resolve_tool

# (tool, what it powers). None of these are required: the stdlib core runs
# without them, but each one it finds adds coverage.
TOOLS: list[tuple[str, str]] = [
    ("nmap", "recon: service/version detection"),
    ("naabu", "recon: fast port scan"),
    ("httpx", "recon: fast HTTP probe"),
    ("subfinder", "OSINT: subdomain enumeration"),
    ("nuclei", "vuln: template scanning (CVSS)"),
    ("sqlmap", "vuln: SQL injection (gated)"),
    ("gobuster", "scanning: content discovery"),
    ("ffuf", "scanning: content discovery (alt)"),
    ("semgrep", "SAST / code review (--sast, --code-review)"),
    ("git", "code review from a git URL"),
    ("dig", "domain verification (DNS TXT)"),
    ("prowler", "cloud audit (--cloud-audit)"),
    ("mitmdump", "proxy capture (--proxy)"),
    ("docker", "sandbox / PoC / interactive shell"),
]


@dataclass
class ToolStatus:
    name: str
    purpose: str
    path: str | None

    @property
    def present(self) -> bool:
        return self.path is not None


def _playwright() -> ToolStatus:
    try:
        import importlib
        importlib.import_module("playwright.sync_api")
        return ToolStatus("playwright", "browser DAST / login recording (--browser)", "installed")
    except Exception:
        return ToolStatus("playwright", "browser DAST / login recording (--browser)", None)


def check() -> list[ToolStatus]:
    rows = [ToolStatus(name, purpose, resolve_tool(name)) for name, purpose in TOOLS]
    rows.append(_playwright())
    return rows


def missing(rows: list[ToolStatus] | None = None) -> list[str]:
    rows = rows or check()
    return [r.name for r in rows if not r.present]


def summary_line(rows: list[ToolStatus] | None = None) -> str:
    rows = rows or check()
    have = sum(1 for r in rows if r.present)
    miss = [r.name for r in rows if not r.present]
    line = f"environment: {have}/{len(rows)} optional tools available"
    if miss:
        line += f"; missing: {', '.join(miss)} (those checks report 0, not a clean result)"
    return line


def render(rows: list[ToolStatus] | None = None) -> str:
    rows = rows or check()
    width = max(len(r.name) for r in rows)
    out = ["Sentari preflight - external tool availability", "-" * 60]
    for r in rows:
        mark = "OK " if r.present else "-- "
        loc = f"  ({r.path})" if r.path and r.path != "installed" else ""
        out.append(f"  [{mark}] {r.name.ljust(width)}  {r.purpose}{loc}")
    miss = [r.name for r in rows if not r.present]
    out.append("-" * 60)
    out.append(summary_line(rows))
    if miss:
        out.append("Install the missing ones to widen coverage; the core still runs without them.")
    return "\n".join(out)


def as_dict(rows: list[ToolStatus] | None = None) -> dict:
    rows = rows or check()
    return {
        "tools": {r.name: {"present": r.present, "purpose": r.purpose,
                           "path": r.path} for r in rows},
        "missing": [r.name for r in rows if not r.present],
    }
