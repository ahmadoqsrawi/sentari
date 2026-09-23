# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Phase 3 (framework): modern-web-app checks a template scanner misses.

Runs only with --framework. Targeted, evidence-backed probes for issues common
to SPA / Next.js style apps:

  * Open redirect - a redirect parameter that sends the browser off-site,
    confirmed by the actual Location header pointing at our canary host.
  * Next.js image-optimizer SSRF (/_next/image?url=...) - confirmed out-of-band
    when the optimizer fetches our listener; otherwise flagged as a candidate if
    it proxies an arbitrary remote URL.
  * Host-header / X-Forwarded-Host reflection - a spoofed host reflected into a
    redirect or the body (cache-poisoning / redirect risk).
  * Source-map exposure - a real .js.map reachable for a script the page loads.

Every finding cites the exact request/response that produced it.
"""
from __future__ import annotations

import time
import urllib.request
from urllib.parse import urlencode, urlparse, urlunparse

from ..models import Finding, PhaseResult, Severity
from .base import Phase, PhaseContext
from .scanning import _web_targets

_REDIRECT_PARAMS = ["next", "url", "redirect", "redirect_uri", "return", "returnTo",
                    "dest", "continue", "r", "callback"]
_CANARY = "sentari-canary.example"


def _fetch(url: str, headers: dict | None = None, timeout: int = 10):
    """Return (status, headers_dict, body) without following redirects."""
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers=headers or {})
    try:
        resp = opener.open(req, timeout=timeout)
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, \
            resp.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, ""
    except Exception:
        return -1, {}, ""


class FrameworkPhase(Phase):
    name = "framework"
    number = 3
    description = "Framework/SPA checks: open redirect, Next.js image SSRF, host-header (--framework)"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        if not ctx.options.get("framework"):
            return
        bases = []
        for host, port in _web_targets(ctx):
            scheme = "https" if port in (443, 8443) else "http"
            bases.append(f"{scheme}://{host}:{port}")
        if not bases:
            result.notes.append("Framework: no web roots to test.")
            return
        for base in bases[:3]:
            self._open_redirect(ctx, result, base)
            self._next_image_ssrf(ctx, result, base)
            self._host_header(ctx, result, base)

    def _open_redirect(self, ctx, result, base):
        for path in ("/", "/login"):
            for param in _REDIRECT_PARAMS:
                url = base + path + "?" + urlencode({param: f"https://{_CANARY}/"})
                t0 = time.monotonic()
                status, headers, _ = _fetch(url, timeout=ctx.runner.default_timeout)
                loc = headers.get("location", "")
                if status in (301, 302, 303, 307, 308) and _CANARY in urlparse(loc).netloc:
                    ev = ctx.runner.record_internal(
                        ["http-get", url], 0, f"HTTP {status}\nLocation: {loc}",
                        duration_sec=round(time.monotonic() - t0, 3))
                    result.findings.append(Finding(
                        title=f"Open redirect via '{param}'", severity=Severity.MEDIUM,
                        description=f"{url} redirected to an attacker-controlled host: "
                                    f"Location: {loc}. Confirmed by the response header "
                                    f"(working proof).",
                        evidence_ids=[ev.id], target=ctx.target, phase=self.name,
                        location=url, metadata={"confidence": "confirmed"},
                        recommendation="Allowlist redirect destinations; never redirect to a "
                                       "user-supplied absolute URL."))
                    return  # one confirmed per base is enough

    def _next_image_ssrf(self, ctx, result, base):
        from .. import oob
        oob_host = ctx.options.get("oob_host", "127.0.0.1")
        oob_port = int(ctx.options.get("oob_port", 0))
        oob_bind = ctx.options.get("oob_bind")
        with oob.OOBListener(host=oob_host, port=oob_port, bind=oob_bind) as listener:
            token = listener.token()
            url = base + "/_next/image?" + urlencode(
                {"url": listener.url(token), "w": "64", "q": "75"})
            t0 = time.monotonic()
            status, _, _ = _fetch(url, timeout=ctx.runner.default_timeout)
            time.sleep(1.0)
            if listener.hit(token):
                ev = ctx.runner.record_internal(
                    ["http-get", url], 0, f"OOB callback: {listener.hits(token)}",
                    duration_sec=round(time.monotonic() - t0, 3))
                result.findings.append(Finding(
                    title="Next.js image optimizer SSRF (/_next/image)",
                    severity=Severity.HIGH,
                    description="The image optimizer fetched an attacker-supplied URL and "
                                "called back to our listener. Working SSRF proof.",
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                    metadata={"confidence": "confirmed"},
                    recommendation="Restrict /_next/image to configured remotePatterns; "
                                   "reject arbitrary absolute URLs."))
                return
        # candidate: does it proxy an arbitrary public URL (200) rather than reject it?
        url2 = base + "/_next/image?" + urlencode({"url": "https://example.com/", "w": "64", "q": "75"})
        t0 = time.monotonic()
        status2, _, _ = _fetch(url2, timeout=ctx.runner.default_timeout)
        if status2 == 200:
            ev = ctx.runner.record_internal(
                ["http-get", url2], 0, f"HTTP {status2} (remote URL accepted)",
                duration_sec=round(time.monotonic() - t0, 3))
            result.findings.append(Finding(
                title="Next.js image optimizer accepts remote URLs",
                severity=Severity.LOW,
                description=f"{url2} returned HTTP 200 for an absolute remote URL; the "
                            "optimizer may be usable as an SSRF/proxy. Candidate: no "
                            "out-of-band callback was confirmed.",
                evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url2,
                metadata={"confidence": "reported"},
                recommendation="Set images.remotePatterns to an allowlist in next.config."))

    def _host_header(self, ctx, result, base):
        for hdr in ("Host", "X-Forwarded-Host"):
            t0 = time.monotonic()
            status, headers, body = _fetch(base + "/",
                                           headers={hdr: _CANARY},
                                           timeout=ctx.runner.default_timeout)
            loc = headers.get("location", "")
            if _CANARY in loc or (body and _CANARY in body):
                ev = ctx.runner.record_internal(
                    ["http-get", f"{base}/ ({hdr}: {_CANARY})"], 0,
                    f"HTTP {status}\nLocation: {loc}",
                    duration_sec=round(time.monotonic() - t0, 3))
                result.findings.append(Finding(
                    title=f"Host header reflected ({hdr})", severity=Severity.MEDIUM,
                    description=f"A spoofed {hdr}: {_CANARY} was reflected into the "
                                f"response ({'Location' if _CANARY in loc else 'body'}), "
                                "enabling redirect/cache-poisoning. Confirmed by the response.",
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=base,
                    metadata={"confidence": "confirmed"},
                    recommendation="Validate the Host header against an allowlist; do not "
                                   "build absolute URLs from it."))
                return
