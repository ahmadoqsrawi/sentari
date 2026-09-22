# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Anomaly flagging.

Highlights findings whose evidence looks unusual relative to the rest of the
run, so a human knows where to look first. This is a prioritization aid, not a
detector: it never asserts a vulnerability, never claims a zero-day, and never
creates a finding. It only tags existing, evidence-backed findings with a note
that says "worth manual review".
"""
from __future__ import annotations

import statistics
from collections import Counter

from .models import PhaseResult


def apply(results: list[PhaseResult]) -> int:
    """Tag outlier findings with metadata['anomaly']. Returns how many were tagged."""
    evidence = {e.id: e for r in results for e in r.evidence}
    findings = [f for r in results for f in r.findings]
    if not findings:
        return 0

    # response-size outliers, using median + MAD as the threshold
    sized = []
    for f in findings:
        ev = evidence.get(f.evidence_ids[0]) if f.evidence_ids else None
        sized.append((f, len(ev.stdout) if ev else 0))
    sizes = [s for _, s in sized]
    flagged = 0
    if len(sizes) >= 4:
        med = statistics.median(sizes)
        mad = statistics.median([abs(s - med) for s in sizes]) or 1
        for f, size in sized:
            if size > med + 6 * mad and size > 500:
                f.metadata = {**(f.metadata or {}),
                              "anomaly": f"response is unusually large ({size} bytes vs "
                                         f"median {int(med)}); worth manual review"}
                flagged += 1

    # rare HTTP status codes for this target
    statuses = [(f, (f.metadata or {}).get("status")) for f in findings]
    counts = Counter(s for _, s in statuses if s is not None)
    if sum(counts.values()) > 3:
        for f, s in statuses:
            if s is not None and counts[s] == 1 and "anomaly" not in (f.metadata or {}):
                f.metadata = {**(f.metadata or {}),
                              "anomaly": f"uncommon HTTP status {s} for this target; "
                                         f"worth manual review"}
                flagged += 1
    return flagged
