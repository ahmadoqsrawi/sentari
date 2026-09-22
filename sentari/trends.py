# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Trend analysis over stored runs.

Summarizes how findings change across the runs in the store (counts by severity
per run, oldest to newest). Reads real stored runs; it does not extrapolate.
"""
from __future__ import annotations

_SEVS = ["critical", "high", "medium", "low", "info"]


def trend_rows(runs: dict[str, dict]) -> list[dict]:
    rows = []
    for rid in sorted(runs):
        findings = [f for r in runs[rid].get("results", []) for f in r.get("findings", [])]
        counts = {s: 0 for s in _SEVS}
        for f in findings:
            counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
        rows.append({"run": rid, "total": len(findings), **counts})
    return rows


def render(rows: list[dict]) -> str:
    if not rows:
        return "No stored runs to trend."
    head = f"{'run':32} {'total':>6} " + " ".join(f"{s[:4]:>5}" for s in _SEVS)
    lines = [head, "-" * len(head)]
    for r in rows:
        lines.append(f"{r['run'][:32]:32} {r['total']:>6} "
                     + " ".join(f"{r[s]:>5}" for s in _SEVS))
    return "\n".join(lines)
