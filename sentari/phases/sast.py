# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Phase 2 (static): SAST over a source tree with semgrep.

Runs only when a path is given with --sast. It scans code, not the live target,
and records semgrep's own output as evidence for each finding. Off by default;
without semgrep installed it reports that and adds nothing.
"""
from __future__ import annotations

from ..models import Finding, PhaseResult, Severity
from .base import Phase, PhaseContext

_SEV = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW,
        "info": Severity.INFO}


class SASTPhase(Phase):
    name = "sast"
    number = 2
    description = "Static analysis (SAST) over a source tree with semgrep (--sast PATH)"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        path = ctx.options.get("sast_path")
        if not path:
            return
        result.tools_available = {"semgrep": ctx.runner.available("semgrep")}
        if not result.tools_available["semgrep"]:
            result.notes.append("semgrep not installed: skipping SAST (no fabrication). "
                                "pip install semgrep")
            return
        from .. import sast
        config = ctx.options.get("sast_config", "auto")
        ev = ctx.runner.run(["semgrep", "--config", config, "--json", "--quiet", path],
                            tool="semgrep", timeout=max(ctx.runner.default_timeout, 600))
        results = sast.parse_semgrep(ev.stdout)
        for r in results:
            loc = f"{r['path']}:{r['line']}" if r["line"] else r["path"]
            refs = [f"CWE {c}" for c in r["cwe"]] + list(r["owasp"])
            result.findings.append(Finding(
                title=f"{r['check_id']}", severity=_SEV.get(r["severity"], Severity.LOW),
                description=(r["message"] or f"semgrep rule {r['check_id']} matched.").strip(),
                evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=loc,
                references=refs, metadata={"source": "semgrep", "check_id": r["check_id"]}))
        if results:
            result.notes.append(f"semgrep reported {len(results)} result(s).")
        elif ev.returncode not in (0,):
            result.notes.append(f"semgrep exited {ev.returncode}: {ev.stderr[:200]}")
        else:
            result.notes.append("semgrep found nothing.")
