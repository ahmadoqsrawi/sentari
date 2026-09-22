# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Phase 3 (access control): broken-access-control / IDOR testing.

Runs only when --access-control is given with at least one --identity. It
requests the protected URLs (from --ac-url or the ingested API endpoints) as each
identity and anonymously, then reports resources that are unprotected or served
to the wrong user. It sends ordinary GETs with the supplied credentials.
"""
from __future__ import annotations

from ..models import Finding, PhaseResult, Severity
from .base import Phase, PhaseContext
from .scanning import _web_targets

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
        "low": Severity.LOW, "info": Severity.INFO}


def _urls(ctx: PhaseContext) -> list[str]:
    urls = list(ctx.options.get("ac_urls", []))
    urls += [u for u in ctx.shared.get("api_endpoints", []) if u not in urls]
    if urls:
        return urls
    out = []
    for host, port in _web_targets(ctx):
        scheme = "https" if port in (443, 8443) else "http"
        out.append(f"{scheme}://{host}:{port}")
    return out


class AccessControlPhase(Phase):
    name = "access-control"
    number = 3
    description = "Broken access control / IDOR: compare identities (--access-control)"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        identities = ctx.options.get("identities")
        if not ctx.options.get("access_control") or not identities:
            if ctx.options.get("access_control") and not identities:
                result.notes.append("Access control: no --identity supplied; skipping.")
            return
        from .. import accesscontrol
        urls = _urls(ctx)[:25]
        if not urls:
            result.notes.append("Access control: no URLs to test.")
            return
        samples = accesscontrol.collect(urls, identities,
                                        timeout=max(ctx.runner.default_timeout, 10))
        issues = accesscontrol.analyze(samples)
        for iss in issues:
            ev = ctx.runner.record_internal(
                ["access-control", iss["location"]], 0,
                f"{iss['issue']}: {iss['detail']}\nidentities: {', '.join(iss['identities'])}")
            result.findings.append(Finding(
                title=iss["issue"], severity=_SEV.get(iss["severity"], Severity.HIGH),
                description=iss["detail"], evidence_ids=[ev.id], target=ctx.target,
                phase=self.name, location=iss["location"],
                recommendation="Enforce authorization on every request and scope objects to "
                               "their owner (check the session, not just authentication).",
                metadata={"candidate": "broken access control",
                          "identities": iss["identities"]}))
        result.notes.append(f"Access control: tested {len(urls)} URL(s) as "
                            f"{len(identities)} identity/identities, {len(issues)} issue(s).")
