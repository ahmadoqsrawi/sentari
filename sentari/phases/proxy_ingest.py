# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Phase 3 (proxy): ingest captured HTTP traffic.

Runs only when --proxy-ingest FILE is given. It reads a capture produced by the
Sentari mitmproxy addon (JSONL) or a browser HAR export and turns provable issues
in the real traffic into findings. It analyzes what was captured; it sends nothing.
"""
from __future__ import annotations

from ..models import Finding, PhaseResult, Severity
from .base import Phase, PhaseContext

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
        "low": Severity.LOW, "info": Severity.INFO}


class ProxyIngestPhase(Phase):
    name = "proxy"
    number = 3
    description = "Ingest captured HTTP traffic (mitmproxy JSONL or HAR) via --proxy-ingest"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        path = ctx.options.get("proxy_ingest")
        if not path:
            return
        from .. import proxy
        try:
            issues = proxy.analyze_flows(path)
        except OSError as e:
            result.notes.append(f"Proxy ingest: could not read {path}: {e}")
            return
        for iss in issues:
            ev = ctx.runner.record_internal(["proxy-flow", iss["location"]], 0,
                                            f"{iss['issue']}: {iss['detail']}")
            result.findings.append(Finding(
                title=iss["issue"], severity=_SEV.get(iss["severity"], Severity.INFO),
                description=f"{iss['detail']} (from captured traffic).",
                evidence_ids=[ev.id], target=ctx.target, phase=self.name,
                location=iss["location"], metadata={"source": "proxy-capture"}))
        result.notes.append(f"Proxy ingest: analyzed capture, {len(issues)} issue(s).")
