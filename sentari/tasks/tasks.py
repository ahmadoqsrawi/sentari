"""Celery task wrapping the shared assessment engine.

The task runs the exact same `run_assessment` code path as the CLI, so a scan
dispatched to a distributed worker behaves identically to a local one. When a
DB DSN is provided, the completed run is persisted for the dashboard/retest.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..authorization import AuditLog, Scope
from ..engine import payload_from_results, run_assessment
from .app import HAVE_CELERY, app


def run_assessment_sync(
    target: str,
    scope_items: list[str],
    authorized: bool,
    options: Optional[dict] = None,
    safe_mode: bool = True,
    db: Optional[str] = None,
    audit_log: str = "sentari-audit.log",
) -> dict:
    audit = AuditLog(Path(audit_log))
    scope = Scope.from_items(scope_items)
    results = run_assessment(target, scope, authorized, audit,
                             safe_mode=safe_mode, options=options or {})
    payload = payload_from_results(results)
    if db:
        from ..db import RunStore
        store = RunStore(db)
        try:
            payload["run_id"] = store.save_run(target, payload)
        finally:
            store.close()
    return payload


# Register as a Celery task only when Celery is available.
run_assessment_task = (
    app.task(name="sentari.run_assessment")(run_assessment_sync) if HAVE_CELERY else None
)
