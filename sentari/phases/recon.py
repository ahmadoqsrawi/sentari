"""Phase 1: Reconnaissance.

Goal: establish what actually exists at the target: resolved IPs, reachable
TCP ports, service/version banners, and basic web fingerprint: every item
backed by a real probe.

Works with zero external tools installed (built-in DNS + TCP-connect + HTTP
probes), and enriches with nmap service/version detection when nmap is present.
"""
from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from typing import Optional
from urllib.parse import urlparse

from ..classify import classify
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


def target_port(target: str) -> Optional[int]:
    """Return the explicit port in the target (URL or host:port), or None."""
    if "://" in target:
        u = urlparse(target)
        return u.port or (443 if u.scheme == "https" else 80)
    hostpart = target.split("/")[0]
    if hostpart.count(":") == 1:
        _, _, p = hostpart.partition(":")
        if p.isdigit():
            return int(p)
    return None


class ReconPhase(Phase):
    name = "recon"
    number = 1
    description = "Reconnaissance: DNS resolution, port/service discovery, web fingerprint"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        host = _hostname(ctx.target)
        result.tools_available = {t: ctx.runner.available(t)
                                  for t in ("nmap", "naabu", "masscan", "httpx")}

        ips = self._resolve(ctx, result, host)
        if not ips:
            result.notes.append(f"Could not resolve {host}; continuing best-effort.")

        if result.tools_available["nmap"]:
            open_ports = self._nmap(ctx, result, host)
        elif result.tools_available["naabu"]:
            result.notes.append("using naabu for port discovery.")
            open_ports = self._naabu(ctx, result, host)
        elif result.tools_available["masscan"] and not ctx.safe_mode:
            result.notes.append("using masscan for port discovery.")
            open_ports = self._masscan(ctx, result, host)
        else:
            result.notes.append("using built-in TCP connect scan.")
            open_ports = self._builtin_portscan(ctx, result, host)

        # store for later phases
        ctx.shared["host"] = host
        ctx.shared["ips"] = ips
        ctx.shared["open_ports"] = open_ports

        self._ingest_api_spec(ctx, result)

        tp = target_port(ctx.target)
        fp_ports = sorted(p for p in open_ports if p in WEB_PORTS or p == tp)
        for port in fp_ports:
            if result.tools_available.get("httpx"):
                self._httpx_fingerprint(ctx, result, host, port)
            else:
                self._web_fingerprint(ctx, result, host, port)

    # --- API spec ingestion (OpenAPI / Swagger / Postman) ---
    def _ingest_api_spec(self, ctx: PhaseContext, result: PhaseResult) -> None:
        src = ctx.options.get("openapi")
        if not src:
            return
        from .. import openapi
        spec, err = openapi.load_spec(src)
        if err:
            result.notes.append(f"API spec: {err}")
            return
        endpoints = openapi.extract_endpoints(spec, ctx.options.get("openapi_base_url"))
        if not endpoints:
            result.notes.append("API spec: no endpoints found.")
            return
        ctx.shared["api_endpoints"] = endpoints
        ev = ctx.runner.record_internal(["openapi-ingest", src], 0, "\n".join(endpoints))
        result.findings.append(Finding(
            title=f"API endpoints from spec: {len(endpoints)}", severity=Severity.INFO,
            description="Ingested from the API spec: " + ", ".join(endpoints[:20])
                        + (" ..." if len(endpoints) > 20 else ""),
            evidence_ids=[ev.id], target=ctx.target, phase=self.name,
            location=src, metadata={"endpoints": endpoints,
                                    "hosts": sorted(openapi.hosts_of(endpoints))}))
        result.notes.append(f"API spec: ingested {len(endpoints)} endpoint(s) as scan targets.")

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
        ports = list(ctx.options.get("ports", DEFAULT_PORTS))
        tp = target_port(ctx.target)
        if tp and tp not in ports:
            ports.append(tp)  # always probe the explicitly requested port

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
                    location=f"{port}/tcp", metadata={"service_class": classify(port)},
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
                metadata={"service": s.service, "product": s.product, "version": s.version,
                          "service_class": classify(s.port, s.service)},
            ))
        if not services and ev.returncode != 0:
            result.notes.append(f"nmap exited {ev.returncode}: {ev.stderr[:200]}")
        return open_ports

    # --- masscan fast port discovery (needs root; gated by safe mode) ---
    def _masscan(self, ctx: PhaseContext, result: PhaseResult, host: str) -> list[int]:
        ev = ctx.runner.run(["masscan", host, "-p1-65535", "--rate", "1000"],
                            tool="masscan", timeout=600)
        import re as _re
        ports = sorted({int(m) for m in _re.findall(r"port (\d+)/tcp", ev.stdout)})
        for port in ports:
            result.findings.append(Finding(
                title=f"Open port {port}/tcp", severity=Severity.INFO,
                description=f"masscan reports {port}/tcp open on {host}.",
                evidence_ids=[ev.id], target=ctx.target, phase=self.name,
                location=f"{port}/tcp", metadata={"service_class": classify(port)}))
        if not ports and ev.returncode != 0:
            result.notes.append(f"masscan exited {ev.returncode} (needs root): {ev.stderr[:120]}")
        return ports

    # --- naabu fast port discovery ---
    def _naabu(self, ctx: PhaseContext, result: PhaseResult, host: str) -> list[int]:
        ev = ctx.runner.run(["naabu", "-host", host, "-silent"], tool="naabu", timeout=300)
        ports: list[int] = []
        for line in ev.stdout.splitlines():
            line = line.strip()
            tail = line.rsplit(":", 1)[-1] if ":" in line else ""
            if tail.isdigit():
                port = int(tail)
                ports.append(port)
                result.findings.append(Finding(
                    title=f"Open port {port}/tcp", severity=Severity.INFO,
                    description=f"naabu reports {port}/tcp open on {host}.",
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name,
                    location=f"{port}/tcp", metadata={"service_class": classify(port)}))
        return sorted(set(ports))

    # --- httpx web fingerprint ---
    def _httpx_fingerprint(self, ctx: PhaseContext, result: PhaseResult, host: str, port: int) -> None:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}"
        ev = ctx.runner.run(["httpx", "-u", url, "-silent", "-json", "-title",
                             "-tech-detect", "-status-code"], tool="httpx", timeout=60)
        obj = {}
        for line in ev.stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
        status = obj.get("status_code") or obj.get("status-code")
        tech = obj.get("tech") or obj.get("technologies") or []
        title = obj.get("title", "")
        desc = f"{url} responded HTTP {status}."
        if title:
            desc += f" Title: {title}."
        if tech:
            desc += f" Tech: {', '.join(tech) if isinstance(tech, list) else tech}."
        result.findings.append(Finding(
            title=f"Web service on {port}/tcp", severity=Severity.INFO,
            description=desc, evidence_ids=[ev.id], target=ctx.target, phase=self.name,
            location=url, metadata={"status": status, "tech": tech, "title": title}))

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
