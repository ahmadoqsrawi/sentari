"""Phase 1: Reconnaissance.

Goal: establish what actually exists at the target: resolved IPs, reachable
TCP ports, service/version banners, and basic web fingerprint: every item
backed by a real probe.

Works with zero external tools installed (built-in DNS + TCP-connect + HTTP
probes), and enriches with nmap service/version detection when nmap is present.
"""
from __future__ import annotations

import socket
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from ..concurrency import pmap
from ..models import Finding, PhaseResult, Severity
from ..parsers.nmap import parse_nmap_xml
from .base import Phase, PhaseContext

# Common ports probed by the built-in scanner when nmap is unavailable.
DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                 1433, 2049, 3000, 3001, 3306, 3389, 5432, 6379, 8000,
                 8080, 8443, 9200, 27017]
WEB_PORTS = {80, 443, 3000, 3001, 8000, 8080, 8443}


def _hostname(target: str) -> str:
    """Accept bare host, host:port, or a URL; return the hostname."""
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0].split(":")[0]


class ReconPhase(Phase):
    name = "recon"
    number = 1
    description = "Reconnaissance: DNS resolution, port/service discovery, web fingerprint"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        host = _hostname(ctx.target)
        result.tools_available = {"nmap": ctx.runner.available("nmap")}

        ips = self._resolve(ctx, result, host)
        if not ips:
            result.notes.append(f"Could not resolve {host}; continuing best-effort.")

        if result.tools_available["nmap"]:
            open_ports = self._nmap(ctx, result, host)
        else:
            result.notes.append("nmap not installed: using built-in TCP connect scan.")
            open_ports = self._builtin_portscan(ctx, result, host)

        # store for later phases
        ctx.shared["host"] = host
        ctx.shared["ips"] = ips
        ctx.shared["open_ports"] = open_ports

        for port in sorted(p for p in open_ports if p in WEB_PORTS):
            self._web_fingerprint(ctx, result, host, port)

    # --- DNS ---
    def _resolve(self, ctx: PhaseContext, result: PhaseResult, host: str) -> list[str]:
        t0 = time.monotonic()
        try:
            ips = sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
            rc, out = 0, "\n".join(ips)
        except OSError as e:
            ips, rc, out = [], 1, str(e)
        ev = ctx.runner.record_internal(
            ["dns-resolve", host], rc, out, duration_sec=round(time.monotonic() - t0, 3),
        )
        if ips:
            result.findings.append(Finding(
                title="DNS resolution", severity=Severity.INFO,
                description=f"{host} resolves to: {', '.join(ips)}",
                evidence_ids=[ev.id], target=ctx.target, phase=self.name,
                location=host, metadata={"ips": ips},
            ))
        return ips

    # --- built-in TCP connect scan ---
    def _builtin_portscan(self, ctx: PhaseContext, result: PhaseResult, host: str) -> list[int]:
        ports = ctx.options.get("ports", DEFAULT_PORTS)

        def check(port: int) -> tuple[int, bool, float]:
            t0 = time.monotonic()
            try:
                with socket.create_connection((host, port), timeout=2):
                    is_open = True
            except (socket.timeout, ConnectionRefusedError, OSError):
                is_open = False
            return port, is_open, round(time.monotonic() - t0, 3)

        # probe all ports concurrently (I/O-bound); record results sequentially
        open_ports: list[int] = []
        for port, is_open, dur in pmap(check, ports, workers=32):
            if is_open:
                open_ports.append(port)
                ev = ctx.runner.record_internal(
                    ["tcp-connect", f"{host}:{port}"], 0, f"port {port}/tcp open",
                    duration_sec=dur,
                )
                result.findings.append(Finding(
                    title=f"Open port {port}/tcp", severity=Severity.INFO,
                    description=f"TCP port {port} is open on {host}.",
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name,
                    location=f"{port}/tcp",
                ))
        return sorted(open_ports)

    # --- nmap service/version enrichment ---
    def _nmap(self, ctx: PhaseContext, result: PhaseResult, host: str) -> list[int]:
        args = ["-Pn", "-sV", "-oX", "-"]
        if not ctx.safe_mode:
            args.insert(1, "-sC")  # default scripts only outside safe mode
        ev = ctx.runner.run(["nmap", *args, host], tool="nmap", timeout=300)
        services = parse_nmap_xml(ev.stdout)
        open_ports: list[int] = []
        for s in services:
            if s.state != "open":
                continue
            open_ports.append(s.port)
            result.findings.append(Finding(
                title=f"Open port {s.port}/{s.protocol}: {s.label()}",
                severity=Severity.INFO,
                description=f"nmap reports {s.port}/{s.protocol} open: {s.label()}.",
                evidence_ids=[ev.id], target=ctx.target, phase=self.name,
                location=f"{s.port}/{s.protocol}",
                metadata={"service": s.service, "product": s.product, "version": s.version},
            ))
        if not services and ev.returncode != 0:
            result.notes.append(f"nmap exited {ev.returncode}: {ev.stderr[:200]}")
        return open_ports

    # --- web fingerprint (built-in HTTP HEAD/GET) ---
    def _web_fingerprint(self, ctx: PhaseContext, result: PhaseResult, host: str, port: int) -> None:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}/"
        t0 = time.monotonic()
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Sentari/0.1"})
        try:
            import ssl
            ctxssl = ssl.create_default_context()
            ctxssl.check_hostname = False
            ctxssl.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=6, context=ctxssl) as resp:
                status = resp.status
                headers = dict(resp.headers.items())
        except urllib.error.HTTPError as e:
            status, headers = e.code, dict(e.headers.items()) if e.headers else {}
        except Exception as e:
            ctx.runner.record_internal(["http-get", url], 1, "", str(e),
                                       round(time.monotonic() - t0, 3))
            return

        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        body = f"HTTP {status}\nServer: {server}\nX-Powered-By: {powered}"
        ev = ctx.runner.record_internal(["http-get", url], 0, body,
                                        duration_sec=round(time.monotonic() - t0, 3))
        desc = f"{url} responded HTTP {status}."
        if server:
            desc += f" Server: {server}."
        if powered:
            desc += f" X-Powered-By: {powered}."
        result.findings.append(Finding(
            title=f"Web service on {port}/tcp", severity=Severity.INFO,
            description=desc, evidence_ids=[ev.id], target=ctx.target, phase=self.name,
            location=url, metadata={"status": status, "server": server, "x_powered_by": powered},
        ))
