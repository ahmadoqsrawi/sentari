"""Prometheus metrics from the stored runs.

Emits the standard Prometheus text format so a scrape job can chart real scan
activity: how many runs are stored and how many findings by severity. The
numbers come from the run store, so they reflect actual scans, not estimates.
"""
from __future__ import annotations

_SEVS = ["critical", "high", "medium", "low", "info"]


def render_metrics(runs: dict[str, dict]) -> str:
    findings_by_sev = {s: 0 for s in _SEVS}
    findings_total = 0
    for run in runs.values():
        for r in run.get("results", []):
            for f in r.get("findings", []):
                findings_total += 1
                sev = f.get("severity", "info")
                findings_by_sev[sev] = findings_by_sev.get(sev, 0) + 1

    lines = [
        "# HELP sentari_scans_total Number of stored scan runs.",
        "# TYPE sentari_scans_total gauge",
        f"sentari_scans_total {len(runs)}",
        "# HELP sentari_findings_total Findings across stored runs, by severity.",
        "# TYPE sentari_findings_total gauge",
    ]
    for sev in _SEVS:
        lines.append(f'sentari_findings_total{{severity="{sev}"}} {findings_by_sev[sev]}')
    lines += [
        "# HELP sentari_findings_all Total findings across all stored runs.",
        "# TYPE sentari_findings_all gauge",
        f"sentari_findings_all {findings_total}",
    ]
    return "\n".join(lines) + "\n"
