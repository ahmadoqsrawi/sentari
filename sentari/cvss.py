# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""CVSS v3.1 base-score scoring.

Computes a base score from a CVSS v3.1 vector string, and maps a score to a
severity band. Used to attach scores to findings that carry a vector or a score
(for example, from nuclei template metadata). Pure arithmetic on real inputs; it
scores what a tool reported and does not invent severity.
"""
from __future__ import annotations

import math
from typing import Optional

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def _roundup(x: float) -> float:
    # CVSS "roundup": ceiling to one decimal place
    return math.ceil(x * 10) / 10.0


def compute_base_score(vector: str) -> Optional[float]:
    """CVSS v3.x vector -> base score (0.0-10.0), or None if unparseable."""
    if not vector:
        return None
    parts = dict(p.split(":", 1) for p in vector.strip().split("/") if ":" in p)
    try:
        scope_changed = parts.get("S") == "C"
        av = _AV[parts["AV"]]
        ac = _AC[parts["AC"]]
        ui = _UI[parts["UI"]]
        pr = (_PR_C if scope_changed else _PR_U)[parts["PR"]]
        c, i, a = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    return _roundup(min(raw, 10.0))


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def from_nuclei_info(info: dict) -> dict:
    """Extract CVSS data from a nuclei finding's info block, if present.
    Returns {score?, vector?, cve?} with whatever was available."""
    out: dict = {}
    classification = (info or {}).get("classification") or {}
    vector = classification.get("cvss-metrics")
    score = classification.get("cvss-score")
    cve = classification.get("cve-id")
    if vector:
        out["vector"] = vector
        computed = compute_base_score(vector)
        if computed is not None:
            out["score"] = computed
    if score and "score" not in out:
        try:
            out["score"] = float(score)
        except (TypeError, ValueError):
            pass
    if cve:
        out["cve"] = cve if isinstance(cve, list) else [cve]
    return out
