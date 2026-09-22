# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Heuristic candidate flagging.

Scans the evidence for patterns that often indicate a problem worth a human
look, such as stack traces or verbose framework errors, and tags the related
finding as a candidate for manual review. This is the honest version of the
"novel issue" idea: it never claims a vulnerability, never says "zero-day," and
creates no findings. It only points a person at evidence worth reading.
"""
from __future__ import annotations

import re

from .models import PhaseResult

_PATTERNS = [
    ("stack trace", re.compile(
        r"Traceback \(most recent call last\)|"
        r"at [\w.$]+\([\w]+\.java:\d+\)|"
        r"System\.\w+Exception|ORA-\d{5}|SQLSTATE\[|SQLException|"
        r"Fatal error:|Warning: .+ on line \d+", re.I)),
    ("verbose framework error", re.compile(
        r"Werkzeug Debugger|Django.*DEBUG|NoMethodError|undefined method|"
        r"Whoops, looks like something went wrong", re.I)),
]


def apply(results: list[PhaseResult]) -> int:
    """Tag findings whose evidence contains an error/leak pattern. Returns count."""
    evidence = {e.id: e for r in results for e in r.evidence}
    flagged = 0
    for r in results:
        for f in r.findings:
            if not f.evidence_ids or "candidate" in (f.metadata or {}):
                continue
            ev = evidence.get(f.evidence_ids[0])
            if not ev:
                continue
            for label, rx in _PATTERNS:
                if rx.search(ev.stdout):
                    f.metadata = {**(f.metadata or {}),
                                  "candidate": f"{label} present in the response; worth manual "
                                               f"review (not a confirmed vulnerability)"}
                    flagged += 1
                    break
    return flagged
