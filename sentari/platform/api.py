# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Stdlib HTTP API for the multi-tenant platform.

Endpoints (all /api/scans routes need `Authorization: Bearer <token>`):

  GET  /api/health         - liveness, no auth
  POST /api/scans          - start a scan (tenant-scoped); requires authorized=true
  GET  /api/scans          - list the caller's scans
  GET  /api/scans/{id}     - the caller's scan status + report

Routing/auth live in the pure ``dispatch`` function so they are testable without
sockets. Scans run in a bounded thread pool through the same evidence-first
engine; a scan is refused unless it carries scope and an authorization
attestation, exactly like the CLI.
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .store import PlatformStore

_MODE_PHASES = {
    "quick": {"osint", "recon", "scanning"},
    "standard": {"osint", "recon", "scanning", "vuln", "api"},
}


def _run_scan(store: PlatformStore, scan_id: str, target: str, scope_items: list,
              authorized: bool, options: dict, safe_mode: bool, mode: str | None) -> None:
    from ..authorization import AuditLog, AuthorizationError, Scope
    from ..engine import run_assessment
    from .. import coverage as _coverage
    store.update_scan(scan_id, status="running", started_at=time.time())
    try:
        opts = dict(options or {})
        phases = None
        if mode in _MODE_PHASES:
            phases = _MODE_PHASES[mode]
            if mode == "standard":
                opts["api_tests"] = True
        elif mode == "deep":
            opts.update({"api_tests": True, "injection": True, "framework": True,
                         "browser": True})
        audit = AuditLog(Path("sentari-audit.log"))
        scope = Scope.from_items(scope_items, exclude=opts.get("exclude"))
        results = run_assessment(target, scope, authorized, audit,
                                 safe_mode=safe_mode, phases=phases, options=opts)
        payload = {"results": [r.to_dict() for r in results],
                   "coverage": _coverage.build(results, opts)}
        findings = sum(len(r.findings) for r in results)
        confirmed = sum(1 for r in results for f in r.findings
                        if (f.metadata or {}).get("confidence") == "confirmed")
        store.update_scan(scan_id, status="done", finished_at=time.time(),
                          findings=findings, confirmed=confirmed,
                          payload_json=json.dumps(payload))
    except AuthorizationError as e:
        store.update_scan(scan_id, status="refused", finished_at=time.time(), error=str(e))
    except Exception as e:  # pragma: no cover - defensive
        store.update_scan(scan_id, status="failed", finished_at=time.time(),
                          error=f"{type(e).__name__}: {e}")


def make_submit(store: PlatformStore, executor: ThreadPoolExecutor):
    def submit(user_id, scan_id, target, scope, authorized, options, safe_mode, mode):
        executor.submit(_run_scan, store, scan_id, target, scope, authorized,
                        options, safe_mode, mode)
    return submit


def dispatch(method: str, path: str, token: str | None, body: dict | None,
             store: PlatformStore, submit) -> tuple[int, dict]:
    """Pure request handler: returns (http_status, json_body)."""
    if method == "GET" and path == "/api/health":
        return 200, {"status": "ok", "service": "sentari"}
    if not path.startswith("/api/"):
        return 404, {"error": "not found"}

    user = store.user_by_token(token or "")
    if user is None:
        return 401, {"error": "invalid or missing API token"}

    if path == "/api/scans":
        if method == "GET":
            return 200, {"scans": store.list_scans(user.id)}
        if method == "POST":
            body = body or {}
            target = body.get("target")
            if not target:
                return 400, {"error": "target is required"}
            if not body.get("authorized"):
                return 400, {"error": "authorized attestation required: set authorized=true; "
                                      "you must have explicit written permission to test the target"}
            scope = body.get("scope") or [target]
            options = body.get("options") or {}
            if body.get("exclude"):
                options["exclude"] = body["exclude"]
            mode = body.get("mode")
            safe_mode = not body.get("no_safe_mode", False)
            sid = store.create_scan(user.id, target, mode)
            submit(user.id, sid, target, scope, True, options, safe_mode, mode)
            return 202, {"id": sid, "status": "queued"}
        return 405, {"error": "method not allowed"}

    if path.startswith("/api/scans/"):
        sid = path[len("/api/scans/"):].strip("/")
        if method == "GET":
            scan = store.get_scan(user.id, sid)
            return (200, scan) if scan else (404, {"error": "not found"})
        return 405, {"error": "method not allowed"}

    return 404, {"error": "not found"}


def make_handler(store: PlatformStore, submit):
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _token(self):
            h = self.headers.get("Authorization", "")
            return h[7:].strip() if h.lower().startswith("bearer ") else None

        def _reply(self, code, obj):
            data = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            code, resp = dispatch("GET", self.path, self._token(), None, store, submit)
            self._reply(code, resp)

        def do_POST(self):
            try:
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n) or b"{}") if n else {}
            except (ValueError, json.JSONDecodeError):
                self._reply(400, {"error": "invalid JSON body"})
                return
            code, resp = dispatch("POST", self.path, self._token(), body, store, submit)
            self._reply(code, resp)

    return _Handler


def serve_api(db: str = "sentari-platform.db", host: str = "127.0.0.1",
              port: int = 8700, workers: int = 4) -> None:
    store = PlatformStore(db)
    executor = ThreadPoolExecutor(max_workers=workers)
    submit = make_submit(store, executor)
    httpd = ThreadingHTTPServer((host, port), make_handler(store, submit))
    print(f"Sentari platform API on http://{host}:{port}  (db={db})")
    print("Auth: Authorization: Bearer <token>. Create users with: sentari api-user add <email>")
    if host not in ("127.0.0.1", "localhost"):
        print("WARNING: bound to a public interface. Put it behind TLS/a reverse proxy "
              "and restrict access; tokens are bearer credentials.")
    print("Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        executor.shutdown(wait=False)
        store.close()
