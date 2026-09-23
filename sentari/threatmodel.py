# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Threat-model-driven assessors: plan the assessment as skill-scoped roles.

Instead of one flat scan, `--threat-model` frames the run as a set of named
assessors, each with a skill set and the real phases it owns (an Auth & API
assessor, an Authorization/IDOR assessor, an Injection assessor, a Framework/SPA
assessor, and so on). Sentari runs those phases through the same evidence-first
engine, then attributes the results back to each assessor and reports what each
one covered and concluded. It is honest orchestration over the real phases, not
a swarm of fake agents; for LLM-driven agents use --agent / --graph.
"""
from __future__ import annotations

from .models import PhaseResult

# Each assessor: the phases it owns, the option flags it needs enabled, its
# skills (for the report), and an optional prerequisite that, if unmet, becomes
# a coverage gap rather than a silent skip.
ASSESSORS: list[dict] = [
    {"name": "Recon & Perimeter Mapper",
     "skills": ["asset_discovery", "dns", "http_fingerprint"],
     "phases": ["osint", "recon", "scanning"], "enable": {}},
    {"name": "Known-Vulnerability Assessor",
     "skills": ["nuclei", "cve", "sqli"],
     "phases": ["vuln"], "enable": {}},
    {"name": "Auth & API Assessor",
     "skills": ["authentication_jwt", "api_security", "rate_limiting"],
     "phases": ["api"], "enable": {"api_tests": True}},
    {"name": "Authorization Assessor",
     "skills": ["idor", "broken_function_level_authorization"],
     "phases": ["access-control"], "enable": {"access_control": True},
     "needs": ("identities", "no test-user credentials supplied")},
    {"name": "Injection Assessor",
     "skills": ["ssrf", "xxe", "command_injection", "ssti", "nosqli"],
     "phases": ["injection"], "enable": {"injection": True}},
    {"name": "Framework/SPA Assessor",
     "skills": ["nextjs", "open_redirect", "host_header", "image_ssrf"],
     "phases": ["framework"], "enable": {"framework": True}},
    {"name": "Client-side Assessor",
     "skills": ["xss", "dom", "clickjacking", "csrf"],
     "phases": ["browser"], "enable": {"browser": True}},
    {"name": "Verification Assessor",
     "skills": ["proof", "read_only_confirmation"],
     "phases": ["verification"], "enable": {}},
]


def enabled_options(options: dict | None = None) -> dict:
    """Merge every assessor's enable-flags into the run options."""
    opts = dict(options or {})
    for a in ASSESSORS:
        for k, v in a["enable"].items():
            opts.setdefault(k, v)
    return opts


def all_phases() -> set[str]:
    return {p for a in ASSESSORS for p in a["phases"]}


def attribute(results: list[PhaseResult], options: dict | None = None) -> dict:
    """Attribute run results to each assessor; return the threat-model report."""
    options = options or {}
    by_phase = {r.phase: r for r in results}
    agents = []
    gaps = []
    for a in ASSESSORS:
        findings = []
        ran_any = False
        for p in a["phases"]:
            r = by_phase.get(p)
            if r is not None:
                ran_any = True
                findings.extend(r.findings)
        confirmed = sum(1 for f in findings
                        if (f.metadata or {}).get("confidence") == "confirmed")
        reported = len(findings) - confirmed
        need = a.get("needs")
        unmet = bool(need and not options.get(need[0]))
        if unmet:
            gaps.append({"assessor": a["name"], "reason": need[1]})
        status = ("completed" if ran_any else "not_run")
        if ran_any and unmet:
            status = "completed_with_gap"
        agents.append({
            "name": a["name"], "skills": a["skills"], "phases": a["phases"],
            "status": status, "confirmed": confirmed, "reported": reported,
        })
    return {
        "assessors": agents,
        "gaps": gaps,
        "summary": {
            "assessors": len(agents),
            "completed": sum(1 for x in agents if x["status"].startswith("completed")),
            "confirmed_findings": sum(x["confirmed"] for x in agents),
        },
    }


def render(tm: dict) -> str:
    lines = ["-" * 70, "THREAT MODEL (assessors)", "-" * 70]
    s = tm["summary"]
    lines.append(f"assessors: {s['assessors']}  completed: {s['completed']}  "
                 f"confirmed findings: {s['confirmed_findings']}")
    for a in tm["assessors"]:
        lines.append(f"  [{a['status']:>18}] {a['name']}  "
                     f"(confirmed {a['confirmed']}, reported {a['reported']})")
        lines.append(f"                       skills: {', '.join(a['skills'])}")
    if tm["gaps"]:
        lines.append("\nAssessor gaps:")
        for g in tm["gaps"]:
            lines.append(f"  - {g['assessor']}: {g['reason']}")
    return "\n".join(lines)
