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
) -> list[PhaseResult]:
    """Authorize the target, run the selected phases in order, tag compliance.
    Raises AuthorizationError if the target is not authorized/in scope."""
    authorize(target, scope, authorized, audit)

    ctx = PhaseContext(target=target, runner=ToolRunner(timeout, dry_run),
                       safe_mode=safe_mode, options=options or {})
    results: list[PhaseResult] = []
    for cls in sorted(PHASES, key=lambda c: c.number):
        if phases is not None and cls.name not in phases:
            continue
        audit.record("phase.start", target=target, phase=cls.name)
        ctx.runner = ToolRunner(timeout, dry_run)
        result = cls().run(ctx)
        ctx.shared.setdefault("prior_findings", []).extend(result.findings)
        audit.record("phase.done", target=target, phase=cls.name,
                     findings=len(result.findings), error=result.error)
        results.append(result)

    if apply_compliance:
        from . import compliance
        compliance.apply(results)
    if apply_anomaly:
        from . import anomaly
        anomaly.apply(results)
    return results


def payload_from_results(results: list[PhaseResult], analysis_dict: Optional[dict] = None) -> dict:
    payload = {"results": [r.to_dict() for r in results]}
    if analysis_dict is not None:
        payload["ai_analysis"] = analysis_dict
    return payload
