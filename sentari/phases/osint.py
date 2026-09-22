"""Phase 0: OSINT.

Passive intelligence gathering before the active phases: subdomain enumeration
(subfinder, amass passive, theHarvester) and host lookups via the Shodan API.
Everything is optional: a tool that is not installed, or a missing SHODAN_API_KEY,
is reported and skipped. Discovered assets are recorded as informational findings
so the operator can decide what to bring into scope; Sentari does not scan them
automatically.
"""
from __future__ import annotations

import json
import re
import socket
import time
import urllib.request

from ..models import Finding, PhaseResult, Severity
from .base import Phase, PhaseContext
from .recon import _hostname

_HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)


class OSINTPhase(Phase):
    name = "osint"
    number = 0
    description = "OSINT: passive subdomain enumeration and Shodan host lookup"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        host = _hostname(ctx.target)
        result.tools_available = {t: ctx.runner.available(t)
                                  for t in ("subfinder", "amass", "theHarvester")}

        is_ip = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", host))
        subs: set[str] = set()

        if not is_ip:
            subs |= self._subfinder(ctx, result, host)
            subs |= self._amass(ctx, result, host)
            subs |= self._theharvester(ctx, result, host)
            if subs:
                ev = ctx.runner.record_internal(["osint-subdomains", host], 0,
                                                "\n".join(sorted(subs)))
                result.findings.append(Finding(
                    title=f"Subdomains discovered: {len(subs)}", severity=Severity.INFO,
                    description="Passive enumeration found: " + ", ".join(sorted(subs)[:25])
                                + (" ..." if len(subs) > 25 else ""),
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name,
                    location=host, metadata={"subdomains": sorted(subs)}))
                ctx.shared.setdefault("subdomains", []).extend(sorted(subs))
        else:
            result.notes.append("Target is an IP; skipping subdomain enumeration.")

        self._shodan(ctx, result, host)

    def _lines(self, ev_stdout: str) -> set[str]:
        return {m.group(0).lower() for line in ev_stdout.splitlines()
                for m in [_HOST_RE.search(line)] if m}

    def _subfinder(self, ctx, result, host) -> set[str]:
        if not ctx.runner.available("subfinder"):
            return set()
        ev = ctx.runner.run(["subfinder", "-d", host, "-silent"], tool="subfinder", timeout=180)
        return {ln.strip().lower() for ln in ev.stdout.splitlines() if ln.strip()}

    def _amass(self, ctx, result, host) -> set[str]:
        if not ctx.runner.available("amass"):
            return set()
        ev = ctx.runner.run(["amass", "enum", "-passive", "-d", host], tool="amass", timeout=300)
        return self._lines(ev.stdout)

    def _theharvester(self, ctx, result, host) -> set[str]:
        if not ctx.runner.available("theHarvester"):
            return set()
        ev = ctx.runner.run(["theHarvester", "-d", host, "-b", "bing,duckduckgo"],
                            tool="theHarvester", timeout=300)
        return {s for s in self._lines(ev.stdout) if s.endswith(host)}

    def _shodan(self, ctx, result, host) -> None:
        import os
        key = os.getenv("SHODAN_API_KEY")
        if not key:
            result.notes.append("No SHODAN_API_KEY; skipping Shodan lookup.")
            return
        try:
            ip = socket.gethostbyname(host)
        except OSError as e:
            result.notes.append(f"Could not resolve {host} for Shodan: {e}")
            return
        t0 = time.monotonic()
        url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception as e:
            ctx.runner.record_internal(["shodan-host", ip], 1, "", str(e),
                                       round(time.monotonic() - t0, 3))
            result.notes.append(f"Shodan lookup failed: {e}")
            return
        ports = data.get("ports", [])
        # redact the key from any echoed URL; store only the JSON body
        ev = ctx.runner.record_internal(["shodan-host", ip], 0, json.dumps(data)[:4000],
                                        duration_sec=round(time.monotonic() - t0, 3))
        result.findings.append(Finding(
            title=f"Shodan: {ip} exposes {len(ports)} port(s)", severity=Severity.INFO,
            description=f"Shodan reports open ports {ports} for {ip}; "
                        f"org={data.get('org','?')}.",
            evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=ip,
            metadata={"shodan_ports": ports}))
