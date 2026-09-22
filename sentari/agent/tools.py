# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""The agent's toolbox.

A fixed set of actions the model may call. The dispatcher runs each one through
the real ToolRunner, so every call leaves evidence. Hard limits that keep an
autonomous model safe:

  * The host is fixed at construction. No tool can point at another host.
  * Arguments are validated; unknown tools and bad args return an error string
    to the model rather than doing anything.
  * `record_finding` requires an evidence_id that a previous tool actually
    produced. A finding with no real evidence behind it is refused.
  * Intrusive tools (sqlmap) run only when safe mode is off.
"""
from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.request

from ..concurrency import pmap
from ..models import Finding, Severity
from ..parsers.nmap import parse_nmap_xml
from ..phases.recon import DEFAULT_PORTS, WEB_PORTS, _hostname

# Tool descriptions handed to the model (kept short; the loop renders them).
TOOL_SPECS = [
    {"name": "dns_lookup", "args": {}, "desc": "Resolve the target host to IP addresses."},
    {"name": "port_scan", "args": {}, "desc": "TCP connect scan of common ports."},
    {"name": "http_get", "args": {"path": "string", "port": "int (optional)"},
     "desc": "GET a path on the target. Returns status, server, missing security headers, and an evidence_id."},
    {"name": "run_nuclei", "args": {"severity": "csv string (optional)"},
     "desc": "Run nuclei templates against discovered web ports (if nuclei is installed)."},
    {"name": "run_sqlmap", "args": {"path": "string"},
     "desc": "Test a path for SQL injection. Only works when safe mode is off."},
    {"name": "record_finding",
     "args": {"evidence_id": "string (required)", "severity": "info|low|medium|high|critical",
              "title": "string", "description": "string", "location": "string (optional)",
              "recommendation": "string (optional)"},
     "desc": "Record a finding. REQUIRES an evidence_id returned by a previous tool."},
    {"name": "run_phase",
     "args": {"phase": "one of: osint, recon, scanning, sast, vuln, api, access-control, "
                       "injection, browser, verification",
              "options": "object (optional): extra options like {\"sqlmap_url\": \"...\"}"},
     "desc": "Run a full assessment phase against the target with its real engine. Findings "
             "come back evidence-backed. Run recon first so later phases see open ports. "
             "injection and browser send active payloads and run only when safe mode is off."},
    {"name": "finish", "args": {"summary": "string"}, "desc": "End the assessment."},
]

_SEV = {s.value: s for s in Severity}


class ToolDispatcher:
    def __init__(self, runner, target: str, safe_mode: bool, options: dict | None = None) -> None:
        self.r = runner
        self.target = target
        self.host = _hostname(target)
        self.safe_mode = safe_mode
        self.options = dict(options or {})
        self.shared: dict = {}          # persists across run_phase calls (open_ports, ips, ...)
        self.findings: list[Finding] = []
        self.open_ports: list[int] = []

    def dispatch(self, name: str, args: dict) -> str:
        fn = getattr(self, f"_{name}", None)
        if fn is None:
            return f"error: unknown tool {name!r}"
        try:
            return fn(args or {})
        except Exception as e:  # never let a tool crash the loop
            return f"error: {type(e).__name__}: {e}"

    def _evidence_ids(self) -> set[str]:
        return {e.id for e in self.r.evidence}

    # --- tools ---
    def _dns_lookup(self, args: dict) -> str:
        t0 = time.monotonic()
        try:
            ips = sorted({i[4][0] for i in socket.getaddrinfo(self.host, None)})
            rc, out = 0, "\n".join(ips)
        except OSError as e:
            ips, rc, out = [], 1, str(e)
        ev = self.r.record_internal(["dns-resolve", self.host], rc, out,
                                    duration_sec=round(time.monotonic() - t0, 3))
        if ips:
            self.findings.append(Finding(
                title="DNS resolution", severity=Severity.INFO,
                description=f"{self.host} resolves to: {', '.join(ips)}",
                evidence_ids=[ev.id], target=self.target, phase="agent", location=self.host))
        return f"{self.host} -> {ips or 'no answer'} (evidence_id={ev.id})"

    def _port_scan(self, args: dict) -> str:
        def check(port: int):
            t0 = time.monotonic()
            try:
                with socket.create_connection((self.host, port), timeout=2):
                    ok = True
            except (socket.timeout, ConnectionRefusedError, OSError):
                ok = False
            return port, ok, round(time.monotonic() - t0, 3)

        opened = []
        for port, ok, dur in pmap(check, DEFAULT_PORTS, workers=32):
            if ok:
                opened.append(port)
                ev = self.r.record_internal(["tcp-connect", f"{self.host}:{port}"], 0,
                                            f"port {port}/tcp open", duration_sec=dur)
                self.findings.append(Finding(
                    title=f"Open port {port}/tcp", severity=Severity.INFO,
                    description=f"TCP port {port} is open on {self.host}.",
                    evidence_ids=[ev.id], target=self.target, phase="agent",
                    location=f"{port}/tcp"))
        self.open_ports = sorted(opened)
        return f"open ports: {self.open_ports or 'none found'}"

    def _http_get(self, args: dict) -> str:
        path = str(args.get("path", "/")) or "/"
        if not path.startswith("/"):
            path = "/" + path
        port = int(args.get("port") or (self.open_ports[0] if self.open_ports else 80))
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{self.host}:{port}{path}"
        t0 = time.monotonic()
        sslctx = ssl.create_default_context()
        sslctx.check_hostname = False
        sslctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Sentari/0.2"})
        try:
            with urllib.request.urlopen(req, timeout=8, context=sslctx) as resp:
                status = resp.status
                headers = {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            status = e.code
            headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        except Exception as e:
            ev = self.r.record_internal(["http-get", url], 1, "", str(e),
                                        round(time.monotonic() - t0, 3))
            return f"{url} unreachable: {e} (evidence_id={ev.id})"
        sec = ["content-security-policy", "strict-transport-security", "x-frame-options",
               "x-content-type-options", "referrer-policy", "permissions-policy"]
        missing = [h for h in sec if h not in headers]
        dump = f"HTTP {status}\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
        ev = self.r.record_internal(["http-get", url], 0, dump,
                                    duration_sec=round(time.monotonic() - t0, 3))
        return (f"HTTP {status} for {url}; server={headers.get('server','?')}; "
                f"missing_security_headers={missing}; evidence_id={ev.id}")

    def _run_nuclei(self, args: dict) -> str:
        if not self.r.available("nuclei"):
            return "nuclei not installed; skipped (nothing fabricated)"
        urls = [f"{'https' if p in (443, 8443) else 'http'}://{self.host}:{p}"
                for p in (self.open_ports or [80]) if p in WEB_PORTS] or [f"http://{self.host}"]
        cmd = ["nuclei", "-jsonl", "-silent", "-no-color"]
        for u in urls:
            cmd += ["-u", u]
        if self.safe_mode:
            cmd += ["-etags", "dos,intrusive,fuzz"]
        sev = str(args.get("severity", "")).strip()
        if sev:
            cmd += ["-severity", sev]
        ev = self.r.run(cmd, tool="nuclei", timeout=900)
        n = 0
        for line in ev.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info", {}) or {}
            self.findings.append(Finding(
                title=f"{info.get('name', obj.get('template-id', 'nuclei'))}",
                severity=_SEV.get(str(info.get("severity", "info")).lower(), Severity.INFO),
                description=(info.get("description") or "nuclei match").strip(),
                evidence_ids=[ev.id], target=self.target, phase="agent",
                location=obj.get("matched-at", "")))
            n += 1
        return f"nuclei matched {n} template(s) (evidence_id={ev.id})"

    def _run_sqlmap(self, args: dict) -> str:
        if self.safe_mode:
            return "sqlmap skipped: safe mode is on (re-run with --no-safe-mode to enable)"
        if not self.r.available("sqlmap"):
            return "sqlmap not installed; skipped"
        path = str(args.get("path", "/"))
        if not path.startswith("/"):
            path = "/" + path
        port = self.open_ports[0] if self.open_ports else 80
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{self.host}:{port}{path}"
        ev = self.r.run(["sqlmap", "-u", url, "--batch", "--level", "1", "--risk", "1",
                         "--disable-coloring", "--flush-session"], tool="sqlmap", timeout=600)
        out = ev.stdout.lower()
        if "is vulnerable" in out or "identified the following injection point" in out:
            self.findings.append(Finding(
                title="SQL injection confirmed by sqlmap", severity=Severity.CRITICAL,
                description=f"sqlmap confirmed an injectable parameter at {url}.",
                evidence_ids=[ev.id], target=self.target, phase="agent", location=url,
                recommendation="Use parameterized queries / an ORM."))
            return f"sqlmap: injection confirmed (evidence_id={ev.id})"
        return f"sqlmap: no injection confirmed (evidence_id={ev.id})"

    def _record_finding(self, args: dict) -> str:
        eid = str(args.get("evidence_id", "")).strip()
        if eid not in self._evidence_ids():
            return (f"error: unknown evidence_id {eid!r}. A finding must cite an evidence_id "
                    "returned by a previous tool. Nothing recorded.")
        sev = _SEV.get(str(args.get("severity", "info")).lower(), Severity.INFO)
        title = str(args.get("title", "")).strip()
        if not title:
            return "error: title is required. Nothing recorded."
        f = Finding(
            title=title, severity=sev,
            description=str(args.get("description", "")).strip() or title,
            evidence_ids=[eid], target=self.target, phase="agent",
            location=args.get("location"), recommendation=args.get("recommendation"),
            metadata={"authored_by": "agent"})
        self.findings.append(f)
        return f"recorded finding {f.id}: [{sev.value}] {title}"

    # auto-enable each phase's own gate so the model just names the phase
    _PHASE_GATE = {"injection": "injection", "browser": "browser", "api": "api_tests",
                   "access-control": "access_control"}

    def _run_phase(self, args: dict) -> str:
        """Run a real assessment phase; its findings come back evidence-backed."""
        from ..phases import PHASES, PhaseContext
        name = str(args.get("phase", "")).strip()
        by_name = {c.name: c for c in PHASES}
        cls = by_name.get(name)
        if cls is None:
            return f"error: unknown phase {name!r}. Valid: {', '.join(sorted(by_name))}"
        opts = {**self.options, **(args.get("options") or {})}
        gate = self._PHASE_GATE.get(name)
        if gate:
            opts[gate] = True
        ctx = PhaseContext(target=self.target, runner=self.r, safe_mode=self.safe_mode,
                           options=opts, shared=self.shared)
        before = len(self.findings)
        res = cls().run(ctx)
        self.findings.extend(res.findings)
        if name == "recon":  # keep open ports for the granular tools too
            self.open_ports = sorted(self.shared.get("open_ports", self.open_ports))
        new = res.findings
        sev_counts = {}
        for f in new:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
        summary = ", ".join(f"{v} {k}" for k, v in sev_counts.items()) or "no findings"
        notes = "; ".join(res.notes[-3:]) if res.notes else ""
        out = f"phase {name}: {len(new)} finding(s) ({summary})."
        if notes:
            out += f" notes: {notes}"
        if res.error:
            out += f" ERROR: {res.error}"
        return out
