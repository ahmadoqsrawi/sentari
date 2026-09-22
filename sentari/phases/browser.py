# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Phase 3 (client-side): headless-browser DAST.

Runs only when requested with --browser. Drives a real headless browser against
the discovered web URLs (and any API endpoints) to find client-side issues,
confirming reflected XSS by actual execution rather than by reflection alone.
Off by default; every finding carries the browser observation as evidence.
"""
from __future__ import annotations

from ..models import Finding, PhaseResult, Severity
from .base import Phase, PhaseContext
from .scanning import _web_targets

_SEV = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW,
        "info": Severity.INFO}


def _urls(ctx: PhaseContext) -> list[str]:
    out = []
    for host, port in _web_targets(ctx):
        scheme = "https" if port in (443, 8443) else "http"
        out.append(f"{scheme}://{host}:{port}")
    for u in ctx.shared.get("api_endpoints", []):
        if u not in out:
            out.append(u)
    return out


class BrowserPhase(Phase):
    name = "browser"
    number = 3
    description = "Client-side DAST: headless-browser reflected-XSS and DOM checks (--browser)"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        if not ctx.options.get("browser"):
            return
        from .. import browser
        result.tools_available = {"playwright": browser.available()}
        urls = _urls(ctx)
        if not urls:
            result.notes.append("Browser DAST: no web URLs to test.")
            return
        checks, err = browser.run_checks(urls, timeout=max(ctx.runner.default_timeout, 15),
                                         active=not ctx.safe_mode,
                                         extra_headers=ctx.options.get("extra_headers"))
        if err:
            result.notes.append(f"Browser DAST: {err}")
        for c in checks:
            if c["type"] in ("browser-error",):
                result.notes.append(f"{c['url']}: {c['detail']}")
                continue
            ev = ctx.runner.record_internal(["browser-check", c["type"], c["url"]], 0,
                                            c["evidence"])
            _confirmed_titles = {
                "reflected-xss": "Reflected XSS confirmed (browser execution)",
                "dom-xss": "DOM-based XSS confirmed (browser execution)",
                "stored-xss": "Stored XSS confirmed (browser execution)",
                "prototype-pollution": "Client-side prototype pollution confirmed",
            }
            title = (_confirmed_titles.get(c["type"]) if c["confirmed"]
                     else None) or c["type"].replace("-", " ").title()
            result.findings.append(Finding(
                title=title, severity=_SEV.get(c["severity"], Severity.INFO),
                description=c["detail"], evidence_ids=[ev.id], target=ctx.target,
                phase=self.name, location=c["url"],
                recommendation=_fix(c["type"]),
                metadata={"browser_check": c["type"], "confirmed": c["confirmed"]}))
        if not err:
            result.notes.append(f"Browser DAST checked {min(len(urls), 10)} URL(s).")


def _fix(ctype: str) -> str:
    return {
        "reflected-xss": "Contextually encode output; add a strict Content-Security-Policy.",
        "reflected-input": "Encode reflected input; validate and escape on output.",
        "password-over-http": "Serve the login over HTTPS only; add HSTS.",
        "mixed-content": "Load all subresources over HTTPS; set upgrade-insecure-requests.",
        "dom-xss": "Avoid writing untrusted location data into HTML sinks; sanitize and use safe APIs.",
        "stored-xss": "Encode stored user input on output; apply a strict Content-Security-Policy.",
        "prototype-pollution": "Reject __proto__/constructor keys when merging untrusted input.",
        "clickjacking": "Set X-Frame-Options: DENY or a CSP frame-ancestors policy.",
        "csrf": "Add per-request anti-CSRF tokens and SameSite cookies on state-changing forms.",
    }.get(ctype, "")
