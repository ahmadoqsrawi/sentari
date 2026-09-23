# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
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


def scheduled_retest_sync() -> dict:
    """Run the target from the schedule env vars, persist it, and diff against the
    previous stored run. Driven by SENTARI_SCHEDULE_TARGET / _SCOPE / _DB."""
    import os
    target = os.getenv("SENTARI_SCHEDULE_TARGET")
    if not target:
        return {"error": "SENTARI_SCHEDULE_TARGET not set"}
    scope = [s for s in (os.getenv("SENTARI_SCHEDULE_SCOPE") or target).split(",") if s]
    db = os.getenv("SENTARI_SCHEDULE_DB")
    from ..retest import findings_from_payload, delta_dicts
    prev = None
    if db:
        from ..db import RunStore
        store = RunStore(db)
        try:
            prev = store.latest_for_target(target)
        finally:
            store.close()
    payload = run_assessment_sync(target, scope, True, db=db)
    result = {"run_id": payload.get("run_id")}
    if prev:
        result["delta"] = {k: len(v) for k, v in
                           delta_dicts(findings_from_payload(prev),
                                       findings_from_payload(payload)).items()}
    return result


def run_platform_scan_sync(scan_id: str, target: str, scope_items: list,
                           authorized: bool, options: Optional[dict], safe_mode: bool,
                           mode: Optional[str], db_path: str) -> dict:
    """Worker-side execution of a platform scan: run the engine and persist the
    status/result to the platform store at db_path (shared with the API)."""
    from ..platform.api import execute_scan
    from ..platform.store import PlatformStore
    store = PlatformStore(db_path)
    try:
        execute_scan(store, scan_id, target, scope_items, authorized,
                     options or {}, safe_mode, mode)
    finally:
        store.close()
    return {"scan_id": scan_id}


# Register as Celery tasks only when Celery is available.
run_assessment_task = (
    app.task(name="sentari.run_assessment")(run_assessment_sync) if HAVE_CELERY else None
)
scheduled_retest_task = (
    app.task(name="sentari.scheduled_retest")(scheduled_retest_sync) if HAVE_CELERY else None
)
run_platform_scan_task = (
    app.task(name="sentari.run_platform_scan")(run_platform_scan_sync) if HAVE_CELERY else None
)
