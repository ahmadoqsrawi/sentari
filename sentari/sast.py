# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Static analysis (SAST) via semgrep.

Runs semgrep over a source tree and maps its results to findings. This is the
static counterpart to the dynamic phases: it reads code, it does not touch the
running target. Optional and graceful: without semgrep installed, the phase says
so and adds nothing. It reports what semgrep found; it invents no findings.
"""
from __future__ import annotations

import json

# semgrep severities -> Sentari severity names
SEV_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low", "INVENTORY": "info"}


def parse_semgrep(stdout: str) -> list[dict]:
    """Parse `semgrep --json` output into a list of result dicts."""
    try:
        data = json.loads(stdout)
    except ValueError:
        return []
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {}) or {}
        start = r.get("start", {}) or {}
        out.append({
            "check_id": r.get("check_id", "semgrep"),
            "path": r.get("path", ""),
            "line": start.get("line", 0),
            "severity": SEV_MAP.get(str(extra.get("severity", "INFO")).upper(), "low"),
            "message": (extra.get("message") or "").strip(),
            "cwe": _cwe(extra),
            "owasp": _owasp(extra),
        })
    return out


def _cwe(extra: dict) -> list[str]:
    md = extra.get("metadata", {}) or {}
    cwe = md.get("cwe") or []
    return [cwe] if isinstance(cwe, str) else list(cwe)


def _owasp(extra: dict) -> list[str]:
    md = extra.get("metadata", {}) or {}
    owasp = md.get("owasp") or []
    return [owasp] if isinstance(owasp, str) else list(owasp)
