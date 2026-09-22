"""Phase 6: Retest.

Compares a fresh scan against a baseline produced by an earlier run's --json
output, and classifies every issue as fixed / still-present / new. Matching uses
a stable semantic signature (phase, title, location) rather than the random
per-run finding id, so the same issue lines up across runs.

Like everything in Sentari, the current-state side is real: retest re-runs the
phases and diffs actual results: it never assumes an issue is fixed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .models import Finding


def _sig_finding(f: Finding) -> tuple[str, str, str]:
    return (f.phase, f.title, f.location or "")


def _sig_dict(d: dict) -> tuple[str, str, str]:
    return (d.get("phase", ""), d.get("title", ""), d.get("location") or "")


@dataclass
class RetestResult:
    fixed: list[dict]              # in baseline, gone now
    still_present: list[Finding]   # in both
    new: list[Finding]             # only now
    baseline_count: int
    current_count: int


def load_baseline(path: str) -> list[dict]:
    """Read findings from a prior `--json` report (a list of phase dicts)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    # accept both shapes: a bare list of phase dicts, or {"results": [...]}
    phases = data["results"] if isinstance(data, dict) else data
    findings: list[dict] = []
    for phase in phases:
        findings.extend(phase.get("findings", []))
    return findings


def compare(baseline: list[dict], current: list[Finding]) -> RetestResult:
    base = {_sig_dict(d): d for d in baseline}
    cur = {_sig_finding(f): f for f in current}
    fixed = [d for s, d in base.items() if s not in cur]
    still = [f for s, f in cur.items() if s in base]
    new = [f for s, f in cur.items() if s not in base]
    return RetestResult(fixed, still, new, len(baseline), len(current))


def render(rr: RetestResult, baseline_path: str) -> str:
    lines = ["", "=" * 70, f"RETEST vs baseline: {baseline_path}", "=" * 70,
             f"baseline findings: {rr.baseline_count} | current findings: {rr.current_count}",
             f"  fixed:         {len(rr.fixed)}",
             f"  still present: {len(rr.still_present)}",
             f"  new:           {len(rr.new)}"]
    if rr.fixed:
        lines.append("\n-- FIXED (in baseline, no longer detected) --")
        for d in rr.fixed:
            lines.append(f"  [{d.get('severity','?').upper():4}] {d.get('title')}  {d.get('location') or ''}")
    if rr.still_present:
        lines.append("\n-- STILL PRESENT --")
        for f in sorted(rr.still_present, key=lambda x: -x.severity.rank):
            lines.append(f"  [{f.severity.value.upper():4}] {f.title}  {f.location or ''}")
    if rr.new:
        lines.append("\n-- NEW (not in baseline) --")
        for f in sorted(rr.new, key=lambda x: -x.severity.rank):
            lines.append(f"  [{f.severity.value.upper():4}] {f.title}  {f.location or ''}")
    return "\n".join(lines)


def to_dict(rr: RetestResult) -> dict:
    return {
        "baseline_count": rr.baseline_count,
        "current_count": rr.current_count,
        "fixed": rr.fixed,
        "still_present": [{"phase": f.phase, "title": f.title, "location": f.location,
                           "severity": f.severity.value} for f in rr.still_present],
        "new": [{"phase": f.phase, "title": f.title, "location": f.location,
                 "severity": f.severity.value} for f in rr.new],
    }
