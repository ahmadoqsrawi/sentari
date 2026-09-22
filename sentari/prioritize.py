"""Business-impact scoring and a risk matrix.

Both are transparent, rule-based ratings over the real findings:

* business impact weights a finding's CVSS (or severity) by how critical the
  asset is (operator-supplied), and
* the risk matrix places each finding on a likelihood x impact grid, where
  likelihood is raised when a CVE is known-exploited (CISA KEV).

These are prioritization aids derived from the findings, not new findings and
not predictions.
"""
from __future__ import annotations

from collections import defaultdict

from .models import PhaseResult

_ASSET_WEIGHT = {"low": 0.6, "medium": 1.0, "high": 1.4, "critical": 1.8}
_LEVELS = ["low", "medium", "high", "critical"]


def _score(f) -> float:
    cvss = (f.metadata or {}).get("cvss") or {}
    if cvss.get("score") is not None:
        return float(cvss["score"])
    return f.severity.rank * 2.5  # 0..10 from severity when no CVSS


def _band(score: float) -> str:
    return ("critical" if score >= 9 else "high" if score >= 7
            else "medium" if score >= 4 else "low")


def apply_business_impact(results: list[PhaseResult], asset_value: str = "medium") -> None:
    w = _ASSET_WEIGHT.get(asset_value, 1.0)
    for r in results:
        for f in r.findings:
            score = min(_score(f) * w, 10.0)
            f.metadata = {**(f.metadata or {}),
                          "business_impact": {"asset_value": asset_value,
                                              "impact": _band(score), "score": round(score, 1)}}


def _likelihood(f) -> str:
    if (f.metadata or {}).get("known_exploited"):
        return "critical"
    return "high" if f.severity.rank >= 3 else "medium" if f.severity.rank == 2 else "low"


def _impact(f) -> str:
    return "high" if f.severity.rank >= 3 else "medium" if f.severity.rank == 2 else "low"


def apply_risk(results: list[PhaseResult]) -> None:
    for r in results:
        for f in r.findings:
            f.metadata = {**(f.metadata or {}),
                          "risk": {"likelihood": _likelihood(f), "impact": _impact(f)}}


def risk_matrix(results: list[PhaseResult]) -> str:
    cells: dict[tuple, int] = defaultdict(int)
    for r in results:
        for f in r.findings:
            risk = (f.metadata or {}).get("risk")
            if risk:
                cells[(risk["likelihood"], risk["impact"])] += 1
    if not any(cells.values()):
        return ""
    lines = ["", "RISK MATRIX (likelihood x impact)", "  L\\I     low  medium  high"]
    for lk in ["critical", "high", "medium", "low"]:
        row = f"  {lk:8}"
        for im in ["low", "medium", "high"]:
            row += f"{cells.get((lk, im), 0):>5}   "
        lines.append(row.rstrip())
    return "\n".join(lines)
