# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Cross-asset correlation.

Given a set of stored runs, finds the same issue across more than one target, so
a systemic problem (a header missing everywhere, one CVE on many hosts) stands
out. It groups the real findings that were recorded; it invents nothing.
"""
from __future__ import annotations

from collections import defaultdict


def correlate(runs: dict[str, dict]) -> list[dict]:
    targets_by_sig: dict[tuple, set] = defaultdict(set)
    severity_by_sig: dict[tuple, str] = {}
    for run in runs.values():
        for r in run.get("results", []):
            for f in r.get("findings", []):
                sig = (f.get("title", ""),)
                tgt = f.get("target") or f.get("location") or "?"
                targets_by_sig[sig].add(tgt)
                severity_by_sig[sig] = f.get("severity", "info")
    out = [{"finding": sig[0], "severity": severity_by_sig[sig], "targets": sorted(ts)}
           for sig, ts in targets_by_sig.items() if len(ts) > 1]
    out.sort(key=lambda x: -len(x["targets"]))
    return out
