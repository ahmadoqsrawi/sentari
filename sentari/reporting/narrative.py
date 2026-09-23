# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Narrative report: an executive-readable Markdown assessment.

Composes a report in the shape a client expects (executive summary, methodology,
technical analysis, recommendations, retest guidance) entirely from the run's
real data: the confirmed/reported findings, the coverage map, and the gaps.
Nothing is invented. If a grounded AI summary is supplied it is used verbatim for
the executive prose; otherwise a deterministic summary is written from the counts.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .. import confidence as _conf
from ..models import PhaseResult, Severity

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _all(results):
    return [f for r in results for f in r.findings]


def _sev(f):
    return f.severity.value if isinstance(f.severity, Severity) else str(f.severity)


def render_markdown(results: list[PhaseResult], target: str, coverage_map: dict,
                    analysis: dict | None = None) -> str:
    findings = _all(results)
    c = _conf.counts(results)
    n_conf = sum(c["confirmed"].values())
    n_rep = sum(c["reported"].values())
    conf_findings = [f for f in findings
                     if (f.metadata or {}).get("confidence") == "confirmed"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    out: list[str] = []
    out.append(f"# Security Assessment Report\n")
    out.append(f"**Target:** `{target}`  ")
    out.append(f"**Generated:** {now}  ")
    out.append(f"**Tool:** Sentari (evidence-first: every finding is backed by a real command)\n")

    # Executive summary
    out.append("## Executive summary\n")
    if analysis and analysis.get("summary"):
        out.append(analysis["summary"].strip() + "\n")
    if conf_findings:
        top = sorted(conf_findings, key=lambda f: -Severity(_sev(f)).rank)[:5]
        out.append(f"The assessment **confirmed {n_conf} issue(s)** through a real "
                   f"observed effect (payload execution or an out-of-band callback). "
                   f"A further {n_rep} candidate(s) were reported by scanners and need "
                   f"verification before they are treated as real.\n")
        out.append("Confirmed issues, highest severity first:\n")
        for f in top:
            out.append(f"- **[{_sev(f).upper()}] {f.title}** - {f.description[:160]}")
        out.append("")
    else:
        out.append(f"**No vulnerability was confirmed** through a real observed effect on "
                   f"the tested surface. {n_rep} candidate(s) were reported by scanners "
                   f"(unverified) and are listed below for review; on inspection these are "
                   f"typically configuration or hardening items rather than exploitable "
                   f"vulnerabilities.\n")

    # Methodology (from coverage)
    out.append("## Methodology\n")
    out.append("Sentari ran an evidence-grounded assessment; a finding exists only when a "
               "real command produced evidence for it. Surfaces reviewed:\n")
    for s in coverage_map.get("surfaces", []):
        out.append(f"- {s['surface']} - {s['detail']}")
    out.append("")

    # Confirmed findings detail
    if conf_findings:
        out.append("## Confirmed findings\n")
        for f in sorted(conf_findings, key=lambda f: -Severity(_sev(f)).rank):
            out.append(f"### [{_sev(f).upper()}] {f.title}")
            if f.location:
                out.append(f"- **Location:** `{f.location}`")
            out.append(f"- **Detail:** {f.description}")
            if f.recommendation:
                out.append(f"- **Fix:** {f.recommendation}")
            out.append("")

    # Reported / unverified candidates (grouped, concise)
    reported = [f for f in findings
                if (f.metadata or {}).get("confidence") != "confirmed"
                and _sev(f) in ("critical", "high", "medium", "low")]
    if reported:
        out.append("## Reported candidates (unverified - verify before trusting)\n")
        for f in sorted(reported, key=lambda f: -Severity(_sev(f)).rank):
            loc = f" (`{f.location}`)" if f.location else ""
            out.append(f"- **[{_sev(f).upper()}]** {f.title}{loc}")
        out.append("")

    # Recommendations (deduped from findings + generic)
    out.append("## Recommendations\n")
    recs = []
    seen = set()
    for f in sorted(findings, key=lambda f: -Severity(_sev(f)).rank):
        rec = (f.recommendation or "").strip()
        if rec and rec not in seen:
            seen.add(rec)
            recs.append(rec)
    for rec in recs[:12]:
        out.append(f"- {rec}")
    if not recs:
        out.append("- No specific remediation required from the confirmed results; "
                   "maintain current controls.")
    out.append("")

    # Coverage gaps / retest guidance
    gaps = coverage_map.get("gaps", [])
    out.append("## Coverage gaps and retest guidance\n")
    if gaps:
        out.append("The following surfaces were not fully exercised in this run and are "
                   "the priority for a follow-up assessment:\n")
        for g in gaps:
            out.append(f"- **{g['surface']}** - {g['reason']}")
    else:
        out.append("No significant coverage gaps: the selected phases exercised the "
                   "reachable surface.")
    out.append("")
    return "\n".join(out)
