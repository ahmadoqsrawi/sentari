"""Phase 3 (API): read-only API-security checks.

Runs only when requested with --api-tests. It exercises the endpoints ingested
from an API spec (or the discovered web roots) with safe, non-mutating requests
and reports what the responses actually show:

  * JWTs seen in responses/cookies (or supplied with --jwt) are audited offline.
  * Rate limiting: a bounded burst; if nothing throttles, that is noted.
  * Auth exposure: an endpoint that returns data with no credentials is flagged
    as a candidate for manual review (not asserted as a vulnerability).
  * State-changing HTTP methods advertised via OPTIONS.

It sends only GET and OPTIONS, so it changes no server state. Mass-assignment
and other mutation tests are intentionally out of scope for this safe phase.
"""
from __future__ import annotations

import re
import time
import urllib.request

from ..concurrency import pmap
from ..models import Finding, PhaseResult, Severity
from .base import Phase, PhaseContext
from .scanning import _web_targets

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
        "low": Severity.LOW, "info": Severity.INFO}


def _endpoints(ctx: PhaseContext) -> list[str]:
    eps = list(ctx.shared.get("api_endpoints", []))
    if eps:
        return eps
    out = []
    for host, port in _web_targets(ctx):
        scheme = "https" if port in (443, 8443) else "http"
        out.append(f"{scheme}://{host}:{port}")
    return out


def _fetch(url: str, method: str = "GET", timeout: int = 10):
    import ssl
    sslctx = ssl.create_default_context()
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": "Sentari/0.7"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=sslctx) as resp:
            return resp.status, dict(resp.headers.items()), resp.read(4096)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()) if e.headers else {}, b""
    except Exception:
        return None, {}, b""


class APITestPhase(Phase):
    name = "api"
    number = 3
    description = "API security: JWT audit, rate-limit and auth-exposure checks (--api-tests)"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        if not ctx.options.get("api_tests") and not ctx.options.get("jwt"):
            return
        # A JWT supplied directly is audited even without endpoints.
        supplied = ctx.options.get("jwt")
        if supplied:
            self._audit_jwt(ctx, result, supplied, "supplied via --jwt")
        if not ctx.options.get("api_tests"):
            return

        endpoints = _endpoints(ctx)
        if not endpoints:
            result.notes.append("API tests: no endpoints to test.")
            return
        endpoints = endpoints[:25]

        self._auth_and_jwt(ctx, result, endpoints)
        self._rate_limit(ctx, result, endpoints[0])
        self._methods(ctx, result, endpoints[0])
        result.notes.append(f"API tests ran against {len(endpoints)} endpoint(s).")

    def _auth_and_jwt(self, ctx, result, endpoints):
        def probe(url):
            return (url, *_fetch(url))
        seen_tokens: set[str] = set()
        for url, status, headers, body in pmap(probe, endpoints, workers=8):
            if status is None:
                continue
            text = body.decode("utf-8", "replace")
            blob = text + " " + " ".join(headers.get(h, "") for h in
                                         ("Set-Cookie", "Authorization"))
            for tok in _JWT_RE.findall(blob):
                if tok not in seen_tokens:
                    seen_tokens.add(tok)
                    self._audit_jwt(ctx, result, tok, f"observed at {url}")
            if status == 200 and body:
                ev = ctx.runner.record_internal(["api-get", url], 0,
                                                f"HTTP {status}, {len(body)} bytes, no auth sent")
                result.findings.append(Finding(
                    title="Endpoint responds without authentication",
                    severity=Severity.LOW,
                    description=f"{url} returned HTTP 200 with a body and no credentials. "
                                "Confirm whether it should require authentication.",
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                    metadata={"candidate": "unauthenticated access", "status": status}))

    def _audit_jwt(self, ctx, result, token, where):
        from .. import jwt_audit
        wordlist = ctx.options.get("jwt_wordlist")
        issues = jwt_audit.audit(token, wordlist)
        redacted = token[:12] + "..." + token[-6:]
        for iss in issues:
            if iss["severity"] == "info":
                result.notes.append(f"JWT ({where}): {iss['issue']} - {iss['detail']}")
                continue
            ev = ctx.runner.record_internal(["jwt-audit", redacted], 0,
                                            f"{iss['issue']}: {iss['detail']}")
            result.findings.append(Finding(
                title=f"JWT weakness: {iss['issue']}", severity=_SEV[iss["severity"]],
                description=f"{iss['detail']} ({where}).",
                evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=where,
                recommendation="Use a strong signing secret/RS256, reject alg=none, set exp, "
                               "and keep sensitive data out of the payload.",
                metadata={"jwt_issue": iss["issue"]}))

    def _rate_limit(self, ctx, result, url, burst: int = 15):
        t0 = time.monotonic()
        statuses = [s for s, _, _ in
                    (r[1:] for r in pmap(lambda i: (i, *_fetch(url)), list(range(burst)), workers=burst))]
        throttled = sum(1 for s in statuses if s == 429)
        body = f"sent {burst} requests to {url}; status counts: " + \
               ", ".join(f"{s}:{statuses.count(s)}" for s in sorted(set(statuses), key=lambda x: (x is None, x)))
        ev = ctx.runner.record_internal(["api-rate-burst", url], 0, body,
                                        duration_sec=round(time.monotonic() - t0, 3))
        if throttled == 0 and any(s == 200 for s in statuses):
            result.findings.append(Finding(
                title="No rate limiting observed", severity=Severity.LOW,
                description=f"{burst} rapid requests to {url} returned no 429/throttling. "
                            "The endpoint may lack rate limiting (candidate for review).",
                evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                metadata={"candidate": "missing rate limiting", "burst": burst}))
        else:
            result.notes.append(f"Rate-limit check on {url}: {throttled}/{burst} throttled.")

    def _methods(self, ctx, result, url):
        status, headers, _ = _fetch(url, method="OPTIONS")
        allow = headers.get("Allow") or headers.get("Access-Control-Allow-Methods") or ""
        risky = [m for m in ("PUT", "DELETE", "PATCH") if m in allow.upper()]
        if allow:
            ev = ctx.runner.record_internal(["api-options", url], 0, f"Allow: {allow}")
            if risky:
                result.findings.append(Finding(
                    title=f"State-changing methods advertised: {', '.join(risky)}",
                    severity=Severity.INFO,
                    description=f"OPTIONS on {url} advertises {allow}. Confirm these "
                                "methods enforce authorization.",
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                    metadata={"allow": allow}))
