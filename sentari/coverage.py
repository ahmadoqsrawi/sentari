# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Coverage: report what was tested and what was not, not just what was found.

A findings list alone cannot tell "0 findings because we tested thoroughly and
the target is clean" apart from "0 findings because we barely tested". This
builds a coverage map from a run: every surface Sentari reviewed with an outcome
(no issue / needs follow-up / issue), plus the gaps, the surfaces it could not
reach and why (a phase not enabled, a tool missing, no credentials for
authenticated flows). It turns an empty report into an honest one.
"""
from __future__ import annotations

from .models import PhaseResult

# outcomes
NO_ISSUE = "no_issue"
NEEDS_FOLLOW_UP = "needs_follow_up"
ISSUE = "issue"
ERROR = "error"
NOT_TESTED = "not_tested"

# phase -> (human label, flag that enables it when off by default)
_PHASES: dict[str, tuple[str, str | None]] = {
    "osint": ("OSINT / passive perimeter enumeration", None),
    "recon": ("Reconnaissance: DNS, ports, services", None),
    "scanning": ("HTTP security headers, TLS, content discovery", None),
    "sast": ("Static code analysis (source review)", "--sast / --code-review"),
    "cloud-audit": ("Cloud configuration audit", "--cloud-audit"),
    "vuln": ("Known-vulnerability templates (nuclei) and SQLi", None),
    "api": ("API security and JWT", "--api-tests"),
    "access-control": ("Broken access control / IDOR", "--access-control"),
    "injection": ("Injection & logic (SSRF/XXE/cmdi/SSTI/NoSQLi)", "--injection"),
    "framework": ("Framework/SPA (open redirect, Next.js image SSRF, host-header)", "--framework"),
    "workflow": ("Business-logic workflow", "--workflow"),
    "proxy": ("Captured-traffic analysis", "--proxy-ingest"),
    "browser": ("Client-side DAST (XSS, prototype pollution, clickjacking)", "--browser"),
    "verification": ("Read-only confirmation of findings", None),
}


def _outcome(r: PhaseResult) -> tuple[str, str]:
    if r.error:
        return ERROR, r.error
    confirmed = [f for f in r.findings
                 if (f.metadata or {}).get("confidence") == "confirmed"]
    reported = [f for f in r.findings
                if (f.metadata or {}).get("confidence") != "confirmed"]
    if confirmed:
        return ISSUE, f"{len(confirmed)} confirmed finding(s)"
    if reported:
        return NEEDS_FOLLOW_UP, f"{len(reported)} unverified candidate(s) to review"
    # ran clean: was the tool even present?
    missing = [t for t, ok in (r.tools_available or {}).items() if not ok]
    if missing and not r.findings:
        return NO_ISSUE, f"no issue found (note: {', '.join(missing)} not installed)"
    return NO_ISSUE, "no issue found"


def build(results: list[PhaseResult], options: dict | None = None,
          agent_mode: bool = False) -> dict:
    """Build the coverage map from a completed run."""
    options = options or {}
    ran = {r.phase: r for r in results}
    surfaces: list[dict] = []
    gaps: list[dict] = []

    # An agent run records everything under one "agent" phase, so surface-level
    # coverage cannot be derived per phase; report it honestly rather than wrongly.
    if agent_mode or (set(ran) == {"agent"}):
        r = ran.get("agent")
        outcome, detail = _outcome(r) if r else (NOT_TESTED, "no result")
        surfaces.append({"surface": "Agent-driven assessment", "phase": "agent",
                         "outcome": outcome, "detail": detail})
    else:
        for phase, (label, flag) in _PHASES.items():
            if phase in ran:
                outcome, detail = _outcome(ran[phase])
                surfaces.append({"surface": label, "phase": phase,
                                 "outcome": outcome, "detail": detail})
            else:
                reason = (f"not run (enable with {flag})" if flag
                          else "not run (not in the selected phases)")
                gaps.append({"surface": label, "phase": phase, "reason": reason})

    # Cross-cutting gap: authenticated authorization needs credentials.
    if not options.get("identities"):
        gaps.append({"surface": "Authenticated authorization (role- and object-level)",
                     "phase": "access-control",
                     "reason": "not tested: no test-user credentials supplied "
                               "(add --identity or record a login)"})

    # Cross-cutting gap: OOB confirmation for an external target needs a public host.
    if options.get("injection") and str(options.get("oob_host", "127.0.0.1")) in (
            "127.0.0.1", "localhost"):
        gaps.append({"surface": "Out-of-band injection confirmation (SSRF/XXE/cmdi)",
                     "phase": "injection",
                     "reason": "OOB host is localhost: callbacks from an external "
                               "target cannot arrive (use --oob-host auto)"})

    outcomes: dict[str, int] = {}
    for s in surfaces:
        outcomes[s["outcome"]] = outcomes.get(s["outcome"], 0) + 1
    summary = {
        "surfaces_reviewed": len(surfaces),
        "outcomes": outcomes,
        "gaps": len(gaps),
    }
    return {"summary": summary, "surfaces": surfaces, "gaps": gaps}


def render(cov: dict) -> str:
    s = cov["summary"]
    lines = ["-" * 70, "COVERAGE (what was tested)", "-" * 70]
    oc = s["outcomes"]
    lines.append(f"surfaces reviewed: {s['surfaces_reviewed']}  "
                 f"(no issue: {oc.get(NO_ISSUE, 0)}, needs follow-up: "
                 f"{oc.get(NEEDS_FOLLOW_UP, 0)}, issue: {oc.get(ISSUE, 0)}, "
                 f"error: {oc.get(ERROR, 0)})   gaps: {s['gaps']}")
    for surf in cov["surfaces"]:
        mark = {NO_ISSUE: "clean", NEEDS_FOLLOW_UP: "review", ISSUE: "ISSUE",
                ERROR: "error"}.get(surf["outcome"], surf["outcome"])
        lines.append(f"  [{mark:>6}] {surf['surface']}  ({surf['detail']})")
    if cov["gaps"]:
        lines.append("\nGaps (not tested):")
        for g in cov["gaps"]:
            lines.append(f"  - {g['surface']}: {g['reason']}")
    return "\n".join(lines)
