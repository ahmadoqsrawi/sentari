# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Assessment engine: the single code path that runs the phases.

Both the CLI and the (optional) Celery worker call `run_assessment`, so a scan
behaves identically whether run locally or dispatched to a distributed worker.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .authorization import AuditLog, Scope, authorize
from .models import PhaseResult
from .phases import PHASES, PhaseContext
from .runner import ToolRunner


def run_assessment(
    target: str,
    scope: Scope,
    authorized: bool,
    audit: AuditLog,
    *,
    safe_mode: bool = True,
    phases: Optional[set[str]] = None,
    timeout: int = 120,
    dry_run: bool = False,
    options: Optional[dict] = None,
    apply_compliance: bool = True,
    apply_anomaly: bool = True,
    apply_heuristics: bool = True,
    apply_threatintel: bool = True,
    asset_value: str = "medium",
) -> list[PhaseResult]:
    """Authorize the target, run the selected phases in order, tag compliance.
    Raises AuthorizationError if the target is not authorized/in scope."""
    from . import events
    authorize(target, scope, authorized, audit)
    events.emit("run_start", "engine", target)

    ctx = PhaseContext(target=target, runner=ToolRunner(timeout, dry_run),
                       safe_mode=safe_mode, options=options or {})
    results: list[PhaseResult] = []
    for cls in sorted(PHASES, key=lambda c: c.number):
        if phases is not None and cls.name not in phases:
            continue
        audit.record("phase.start", target=target, phase=cls.name)
        events.emit("phase_start", cls.name, cls.description)
        ctx.runner = ToolRunner(timeout, dry_run)
        result = cls().run(ctx)
        ctx.shared.setdefault("prior_findings", []).extend(result.findings)
        for f in result.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            events.emit("finding", cls.name, f.title, severity=sev,
                        location=f.location or "")
        audit.record("phase.done", target=target, phase=cls.name,
                     findings=len(result.findings), error=result.error)
        events.emit("phase_done", cls.name,
                    f"{len(result.findings)} finding(s)"
                    + (f"; error: {result.error}" if result.error else ""),
                    findings=len(result.findings), error=bool(result.error))
        results.append(result)

    # Gated exploitation runs only with safe mode off and an explicit, confirmed
    # request. It is not in the default phase list, so it never runs by accident.
    # Optional Docker sandbox: the gated offensive tools run inside a disposable
    # container instead of on the host. It isolates where commands run; it does
    # not change reporting or loosen any gate.
    sbx = None
    sbx_cfg = (options or {}).get("sandbox")
    if not safe_mode and sbx_cfg:
        from .sandbox import Sandbox
        sbx = Sandbox(**sbx_cfg) if isinstance(sbx_cfg, dict) else Sandbox()

    if not safe_mode and (options or {}).get("exploit"):
        from .phases.exploit import ExploitPhase
        ctx.runner = ToolRunner(timeout, dry_run, sandbox=sbx)
        results.append(ExploitPhase().run(ctx))

    # Gated post-exploitation (lateral movement, AD collection). Same gates as
    # exploitation: never runs by accident and never in safe mode.
    if not safe_mode and (options or {}).get("postexploit"):
        from .phases.postexploit import PostExploitPhase
        ctx.runner = ToolRunner(timeout, dry_run, sandbox=sbx)
        results.append(PostExploitPhase().run(ctx))

    if apply_compliance:
        from . import compliance
        compliance.apply(results)
    if apply_anomaly:
        from . import anomaly
        anomaly.apply(results)
    if apply_heuristics:
        from . import heuristics
        heuristics.apply(results)
    if apply_threatintel:
        from . import threatintel
        threatintel.apply(results)

    # Tag every finding confirmed vs reported/unverified (always on) so proven
    # issues lead and scanner candidates never dominate the headline.
    from . import confidence
    confidence.apply(results)

    # Prioritization aids (always on): weight by asset value, tag likelihood x
    # impact. These rate the real findings; they never add findings.
    from . import prioritize
    prioritize.apply_business_impact(results, asset_value)
    prioritize.apply_risk(results)
    events.emit("run_done", "engine",
                f"{sum(len(r.findings) for r in results)} finding(s) total")
    return results


def payload_from_results(results: list[PhaseResult], analysis_dict: Optional[dict] = None) -> dict:
    payload = {"results": [r.to_dict() for r in results]}
    if analysis_dict is not None:
        payload["ai_analysis"] = analysis_dict
    return payload
