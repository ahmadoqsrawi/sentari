"""Phase 2 (cloud): misconfiguration audit with Prowler.

Runs only when --cloud-audit PROVIDER is given. It audits your own cloud account
configuration and records Prowler's failed checks as findings. Off by default;
without Prowler installed it reports that and adds nothing.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from ..models import Finding, PhaseResult, Severity
from .base import Phase, PhaseContext

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
        "low": Severity.LOW, "info": Severity.INFO}


class CloudAuditPhase(Phase):
    name = "cloud-audit"
    number = 2
    description = "Cloud misconfiguration audit with Prowler (--cloud-audit aws|azure|gcp)"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        provider = ctx.options.get("cloud_audit")
        if not provider:
            return
        result.tools_available = {"prowler": ctx.runner.available("prowler")}
        if not result.tools_available["prowler"]:
            result.notes.append("prowler not installed: skipping cloud audit (no fabrication). "
                                "pip install prowler")
            return
        from .. import cloudaudit
        with tempfile.TemporaryDirectory() as tmp:
            ev = ctx.runner.run(
                ["prowler", provider, "--output-formats", "json", "--output-directory", tmp,
                 "--output-filename", "sentari"],
                tool="prowler", timeout=max(ctx.runner.default_timeout, 1800))
            payload = ev.stdout
            # Prowler writes the JSON to a file; prefer that over stdout.
            files = sorted(Path(tmp).glob("*.json"))
            if files:
                try:
                    payload = files[-1].read_text(encoding="utf-8")
                except OSError:
                    pass
        results = cloudaudit.parse_prowler(payload)
        for r in results:
            loc = " / ".join(x for x in (r["region"], r["resource"]) if x) or provider
            result.findings.append(Finding(
                title=f"{r['title']}", severity=_SEV.get(r["severity"], Severity.MEDIUM),
                description=(r["detail"] or f"Prowler check {r['check_id']} failed.").strip(),
                evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=loc,
                metadata={"source": "prowler", "check_id": r["check_id"],
                          "service": r["service"], "provider": provider}))
        if results:
            result.notes.append(f"prowler reported {len(results)} failed check(s).")
        elif ev.returncode not in (0,):
            result.notes.append(f"prowler exited {ev.returncode}: {ev.stderr[:200]}")
        else:
            result.notes.append("prowler found no failed checks.")
