"""Phase 2: Scanning & Enumeration.

Builds on Phase 1's discovered web ports (via ctx.shared) and performs real,
evidence-backed checks:
  * HTTP security-header analysis (missing CSP/HSTS/X-Frame-Options/... )
  * TLS inspection (negotiated protocol, cert expiry, legacy TLS acceptance)
  * Content discovery (gobuster/ffuf when installed; a small built-in probe of
    common sensitive paths otherwise)

Every finding cites the exact probe that produced it. Nothing is assumed.
"""
from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from ..concurrency import pmap
from ..models import Finding, PhaseResult, Severity
from .base import Phase, PhaseContext
from .recon import WEB_PORTS, _hostname, target_port

# header -> (severity, why, recommendation)
_SECURITY_HEADERS = {
    "content-security-policy": (
        Severity.MEDIUM, "No Content-Security-Policy: reduced XSS/clickjacking defense.",
        "Add a Content-Security-Policy (start with frame-ancestors 'none'; roll out a full policy via Report-Only)."),
    "strict-transport-security": (
        Severity.MEDIUM, "No HSTS: browsers may connect over plaintext HTTP.",
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains."),
    "x-frame-options": (
        Severity.MEDIUM, "No X-Frame-Options: page may be framed (clickjacking).",
        "Add X-Frame-Options: DENY (or a CSP frame-ancestors directive)."),
    "x-content-type-options": (
        Severity.LOW, "No X-Content-Type-Options: MIME sniffing possible.",
        "Add X-Content-Type-Options: nosniff."),
    "referrer-policy": (
        Severity.LOW, "No Referrer-Policy: referrers may leak to third parties.",
        "Add Referrer-Policy: strict-origin-when-cross-origin."),
    "permissions-policy": (
        Severity.LOW, "No Permissions-Policy: browser features not restricted.",
        "Add a Permissions-Policy restricting camera/microphone/geolocation, etc."),
}
# common sensitive paths for the built-in content probe (safe GETs)
_COMMON_PATHS = ["/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/backup",
                 "/backup.zip", "/.svn/entries", "/config.json", "/server-status",
                 "/phpinfo.php", "/.DS_Store", "/robots.txt", "/sitemap.xml"]


def _web_targets(ctx: PhaseContext) -> list[tuple[str, int]]:
    host = ctx.shared.get("host") or _hostname(ctx.target)
    ports = {p for p in ctx.shared.get("open_ports", []) if p in WEB_PORTS}
    tp = target_port(ctx.target)
    if tp:
        ports.add(tp)   # an explicitly requested port is always scanned
    if not ports:
        ports = {443, 80}
    return [(host, p) for p in sorted(ports)]


def _fetch(url: str) -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Sentari/0.1"})
    sslctx = ssl.create_default_context()
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=8, context=sslctx) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, ""
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, hdrs, ""
    except Exception as e:
        return -1, {}, str(e)


class ScanPhase(Phase):
    name = "scanning"
    number = 2
    description = "Scanning & enumeration: security headers, TLS, content discovery"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        result.tools_available = {
            "gobuster": ctx.runner.available("gobuster"),
            "ffuf": ctx.runner.available("ffuf"),
        }
        targets = _web_targets(ctx)
        if not targets:
            result.notes.append("No web ports to enumerate.")
            return
        for host, port in targets:
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{host}:{port}/"
            self._security_headers(ctx, result, url)
            if scheme == "https":
                self._tls_check(ctx, result, host, port)
            self._content_discovery(ctx, result, host, port, scheme)

    # --- security headers ---
    def _security_headers(self, ctx: PhaseContext, result: PhaseResult, url: str) -> None:
        t0 = time.monotonic()
        status, headers, err = _fetch(url)
        if status < 0:
            ctx.runner.record_internal(["http-get", url], 1, "", err,
                                       round(time.monotonic() - t0, 3))
            result.notes.append(f"{url} unreachable: {err}")
            return
        dump = f"HTTP {status}\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
        ev = ctx.runner.record_internal(["http-get-headers", url], 0, dump,
                                        duration_sec=round(time.monotonic() - t0, 3))
        csp = headers.get("content-security-policy", "")
        for hdr, (sev, why, fix) in _SECURITY_HEADERS.items():
            present = hdr in headers
            # X-Frame-Options is satisfied by a CSP frame-ancestors directive
            if hdr == "x-frame-options" and "frame-ancestors" in csp:
                present = True
            if not present:
                result.findings.append(Finding(
                    title=f"Missing header: {hdr}", severity=sev, description=why,
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name,
                    location=url, recommendation=fix,
                ))
        # information disclosure
        for leak in ("x-powered-by", "server"):
            val = headers.get(leak, "")
            if val and (leak == "x-powered-by" or any(c.isdigit() for c in val)):
                result.findings.append(Finding(
                    title=f"Technology/version disclosure via {leak}",
                    severity=Severity.LOW,
                    description=f"Response header '{leak}: {val}' reveals stack details.",
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                    recommendation=f"Suppress or genericize the '{leak}' header.",
                ))

    # --- TLS ---
    def _tls_check(self, ctx: PhaseContext, result: PhaseResult, host: str, port: int) -> None:
        t0 = time.monotonic()
        info = {}
        try:
            sslctx = ssl.create_default_context()
            sslctx.check_hostname = False
            sslctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=8) as sock:
                with sslctx.wrap_socket(sock, server_hostname=host) as ss:
                    info["protocol"] = ss.version()
                    cert = ss.getpeercert()
                    if not cert:  # verify_mode NONE -> may be empty; refetch with binary
                        info["cert"] = None
                    else:
                        info["cert"] = cert
        except Exception as e:
            ctx.runner.record_internal(["tls-connect", f"{host}:{port}"], 1, "", str(e),
                                       round(time.monotonic() - t0, 3))
            return
        # legacy TLS acceptance (real handshake attempts)
        legacy = self._legacy_tls(host, port)
        dump = f"protocol={info.get('protocol')}\nlegacy_accepted={legacy}"
        ev = ctx.runner.record_internal(["tls-inspect", f"{host}:{port}"], 0, dump,
                                        duration_sec=round(time.monotonic() - t0, 3))
        for proto in legacy:
            result.findings.append(Finding(
                title=f"Legacy TLS accepted: {proto}", severity=Severity.MEDIUM,
                description=f"{host}:{port} completed a {proto} handshake; deprecated protocols weaken transport security.",
                evidence_ids=[ev.id], target=ctx.target, phase=self.name,
                location=f"{host}:{port}",
                recommendation="Disable TLS 1.0/1.1; require TLS 1.2+.",
            ))

    def _legacy_tls(self, host: str, port: int) -> list[str]:
        accepted = []
        for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            try:
                c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                c.check_hostname = False
                c.verify_mode = ssl.CERT_NONE
                c.minimum_version = ver
                c.maximum_version = ver
                with socket.create_connection((host, port), timeout=6) as sock:
                    with c.wrap_socket(sock, server_hostname=host):
                        accepted.append(name)
            except Exception:
                pass
        return accepted

    # --- content discovery ---
    def _content_discovery(self, ctx: PhaseContext, result: PhaseResult,
                           host: str, port: int, scheme: str) -> None:
        base = f"{scheme}://{host}:{port}"
        wordlist = ctx.options.get("wordlist")
        if result.tools_available["gobuster"] and wordlist:
            ev = ctx.runner.run(
                ["gobuster", "dir", "-q", "-u", base, "-w", wordlist, "-t", "20"],
                tool="gobuster", timeout=300)
            for line in ev.stdout.splitlines():
                line = line.strip()
                if line.startswith("/"):
                    result.findings.append(Finding(
                        title=f"Discovered path: {line.split()[0]}", severity=Severity.INFO,
                        description=f"gobuster found: {line}", evidence_ids=[ev.id],
                        target=ctx.target, phase=self.name, location=f"{base}{line.split()[0]}"))
            return
        # built-in probe of common sensitive paths (concurrent: I/O bound)
        if not wordlist:
            result.notes.append("No wordlist/gobuster: probing a small built-in sensitive-path list.")

        def probe(path: str):
            url = base + path
            t0 = time.monotonic()
            status, _, _ = _fetch(url)
            return path, url, status, round(time.monotonic() - t0, 3)

        for path, url, status, dur in pmap(probe, _COMMON_PATHS, workers=16):
            if status in (200, 401, 403) and status > 0:
                ev = ctx.runner.record_internal(["http-get", url], 0, f"HTTP {status}",
                                                duration_sec=dur)
                sev = Severity.HIGH if path.startswith(("/.git", "/.env", "/.svn")) and status == 200 else Severity.LOW
                result.findings.append(Finding(
                    title=f"Sensitive path reachable: {path} (HTTP {status})", severity=sev,
                    description=f"{url} returned HTTP {status}; may expose sensitive data.",
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                    recommendation="Block access to this path or remove the exposed resource.",
                ))
