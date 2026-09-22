# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Phase 3 (injection & logic): SSRF, XXE, NoSQLi, mass assignment, race.

Runs only with --injection. SSRF and XXE are confirmed out-of-band: Sentari
injects a URL that points at its own listener and reports only if the target
actually calls back. NoSQLi and mass assignment are differential candidates.
The race check fires concurrent requests at an operator-named URL.

Active, mutating tests (XXE, mass assignment) run only outside safe mode, since
they POST data. SSRF and NoSQLi use GET parameters. Findings stay evidence-backed.
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..concurrency import pmap
from ..models import Finding, PhaseResult, Severity
from .base import Phase, PhaseContext
from .scanning import _web_targets


def _fetch(url, method="GET", headers=None, data=None, timeout=10):
    sslctx = ssl.create_default_context()
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, method=method, data=body,
                                 headers={"User-Agent": "Sentari/0.10", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=sslctx) as resp:
            return resp.status, resp.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(4000).decode("utf-8", "replace") if hasattr(e, "read") else "")
    except Exception:
        return 0, ""


def _set_cookies(url, timeout=10) -> list[str]:
    """Return the Set-Cookie header values from a GET of url (best-effort)."""
    sslctx = ssl.create_default_context()
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Sentari/0.11"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=sslctx) as resp:
            return resp.headers.get_all("Set-Cookie") or []
    except Exception:
        return []


def _with_param(url, key, value):
    p = urlparse(url)
    q = dict(parse_qsl(p.query))
    q[key] = value
    return urlunparse(p._replace(query=urlencode(q)))


class InjectionPhase(Phase):
    name = "injection"
    number = 3
    description = "SSRF/XXE (OOB-confirmed), NoSQLi, mass assignment, race (--injection)"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        opts = ctx.options
        if not (opts.get("injection") or opts.get("race_url") or opts.get("session_fixation")):
            return
        # injection fires many requests, so cap each to a short timeout regardless
        # of the global --timeout; a WAF/tarpit must not stall the whole phase.
        timeout = int(opts.get("injection_timeout", 8))

        if opts.get("session_fixation"):
            self._session_fixation(ctx, result, opts["session_fixation"], timeout)
        if opts.get("race_url"):
            self._race(ctx, result, opts["race_url"],
                       int(opts.get("race_count", 20)), timeout)
        if not opts.get("injection"):
            return

        # cap endpoints so injection does not flood a live target; override with
        # options["injection_max_urls"] when a wider sweep is wanted.
        max_urls = int(opts.get("injection_max_urls", 8))
        urls = self._urls(ctx)[:max_urls]
        from .. import oob
        oob_host = opts.get("oob_host", "127.0.0.1")
        with oob.OOBListener(host=oob_host) as listener:
            self._ssrf(ctx, result, urls, listener, timeout)
            self._cmdi(ctx, result, urls, listener, timeout)
            if not ctx.safe_mode:
                self._xxe(ctx, result, urls, listener, timeout)

        self._ssti(ctx, result, urls, timeout)
        self._nosqli(ctx, result, urls, timeout)
        self._deserial(ctx, result, urls, timeout)
        if not ctx.safe_mode:
            self._mass_assignment(ctx, result, urls, timeout)

    def _urls(self, ctx):
        urls = list(ctx.shared.get("api_endpoints", []))
        for host, port in _web_targets(ctx):
            scheme = "https" if port in (443, 8443) else "http"
            u = f"{scheme}://{host}:{port}"
            if u not in urls:
                urls.append(u)
        return urls

    # --- SSRF: inject an OOB URL into likely params; confirm by callback ---
    def _ssrf(self, ctx, result, urls, listener, timeout):
        from .. import injection
        tokens = {}
        # existing params plus the most common SSRF sinks, not all 24 on every URL
        for url in urls:
            existing = list(dict(parse_qsl(urlparse(url).query)))
            ssrf_params = list(dict.fromkeys(existing + injection.SSRF_PARAMS[:8]))
            for param in ssrf_params:
                token = listener.token()
                target = _with_param(url, param, listener.url(token))
                _fetch(target, timeout=timeout)
                tokens[token] = (url, param)
        time.sleep(3)  # give the target time to call back
        for token, (url, param) in tokens.items():
            if listener.hit(token):
                ev = ctx.runner.record_internal(
                    ["ssrf-oob", url, param], 0,
                    f"Server fetched our OOB URL via param '{param}'. "
                    f"callbacks: {listener.hits(token)}")
                result.findings.append(Finding(
                    title="SSRF confirmed (out-of-band callback)", severity=Severity.HIGH,
                    description=f"Injecting an OOB URL into '{param}' on {url} made the server "
                                "call back to our listener. This is a working SSRF proof.",
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                    recommendation="Validate and allowlist outbound URLs; block internal ranges.",
                    metadata={"param": param, "ssrf": True}))

    # --- XXE: POST an XML external entity; confirm by callback (gated) ---
    def _xxe(self, ctx, result, urls, listener, timeout):
        from .. import injection
        for url in urls:
            token = listener.token()
            payload = injection.xxe_payload(listener.url(token))
            _fetch(url, method="POST", headers={"Content-Type": "application/xml"},
                   data=payload, timeout=timeout)
            time.sleep(2)
            if listener.hit(token):
                ev = ctx.runner.record_internal(
                    ["xxe-oob", url], 0, f"XML external entity triggered a callback: "
                    f"{listener.hits(token)}")
                result.findings.append(Finding(
                    title="XXE confirmed (out-of-band callback)", severity=Severity.HIGH,
                    description=f"An XML external entity POSTed to {url} made the server call "
                                "back to our listener. This is a working XXE proof.",
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                    recommendation="Disable external entity resolution in the XML parser.",
                    metadata={"xxe": True}))

    # --- Command injection: inject shell payloads; confirm by callback ---
    def _cmdi(self, ctx, result, urls, listener, timeout):
        from .. import injection
        for url in urls:
            existing = list(dict(parse_qsl(urlparse(url).query)))
            params = injection.candidate_params(existing)
            token_map = {}
            for param in params:
                token = listener.token()
                for payload in injection.cmdi_payloads(listener.url(token)):
                    _fetch(_with_param(url, param, payload), timeout=timeout)
                token_map[token] = param
            time.sleep(2)
            for token, param in token_map.items():
                if listener.hit(token):
                    ev = ctx.runner.record_internal(
                        ["cmdi-oob", url, param], 0,
                        f"Command injection callback via '{param}': {listener.hits(token)}")
                    result.findings.append(Finding(
                        title="OS command injection confirmed (out-of-band callback)",
                        severity=Severity.CRITICAL,
                        description=f"A shell payload in '{param}' on {url} made the server call "
                                    "back to our listener. This is a working command-injection proof.",
                        evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                        recommendation="Never pass user input to a shell; use argument arrays and allowlists.",
                        metadata={"param": param, "cmdi": True}))
                    break

    # --- SSTI: template math (7*7) evaluated in the response ---
    def _ssti(self, ctx, result, urls, timeout):
        from .. import injection
        for url in urls:
            existing = list(dict(parse_qsl(urlparse(url).query)))
            for param in injection.candidate_params(existing):
                marker = "ssti" + str(abs(hash((url, param))) % 100000)
                hit = False
                for payload in injection.ssti_payloads(marker):
                    status, body = _fetch(_with_param(url, param, payload), timeout=timeout)
                    if marker + "49" in body:
                        hit = True
                        ev = ctx.runner.record_internal(
                            ["ssti", url, param], 0,
                            f"payload {payload!r} -> response contained {marker}49 (7*7 evaluated)")
                        result.findings.append(Finding(
                            title="Server-side template injection confirmed", severity=Severity.HIGH,
                            description=f"A template expression in '{param}' on {url} was evaluated "
                                        f"(7*7 became 49). Working SSTI proof.",
                            evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                            recommendation="Do not render user input as a template; sandbox the engine.",
                            metadata={"param": param, "ssti": True}))
                        break
                if hit:
                    break

    # --- Insecure deserialization: serialized blobs in client-controllable inputs ---
    def _deserial(self, ctx, result, urls, timeout):
        from .. import deserial
        for url in urls:
            issues = deserial.scan(url, {})  # serialized blob in a URL parameter
            issues += deserial.scan_setcookie(url, _set_cookies(url, timeout))  # or in a cookie
            for iss in issues:
                ev = ctx.runner.record_internal(["deserial", url], 0,
                                                f"{iss['detail']} ({iss['where']})")
                result.findings.append(Finding(
                    title="Serialized object in client-controllable input", severity=Severity.MEDIUM,
                    description=iss["detail"] + " Confirm the app does not deserialize it unsafely.",
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                    metadata={"candidate": "insecure deserialization", "format": iss["format"]}))

    # --- NoSQLi: differential operator injection on existing params ---
    def _nosqli(self, ctx, result, urls, timeout):
        from .. import injection
        for url in urls:
            params = dict(parse_qsl(urlparse(url).query))
            if not params:
                continue
            name = next(iter(params))
            base = _fetch(_with_param(url, name, "sentari_baseline_val"), timeout=timeout)
            for suffix, val in injection.nosqli_variants():
                inj_url = _with_param(url, name + suffix, val)
                inj = _fetch(inj_url, timeout=timeout)
                if injection.behavior_changed(base, inj):
                    ev = ctx.runner.record_internal(
                        ["nosqli", inj_url], 0,
                        f"baseline {base[0]}/{len(base[1])}B vs injected {inj[0]}/{len(inj[1])}B")
                    result.findings.append(Finding(
                        title="Possible NoSQL injection (differential)", severity=Severity.MEDIUM,
                        description=f"Injecting a Mongo-style operator ({name}{suffix}) into {url} "
                                    "changed the response. Confirm manually.",
                        evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                        metadata={"candidate": "nosqli", "param": name}))
                    break

    # --- mass assignment: POST extra sensitive fields, look for acceptance (gated) ---
    def _mass_assignment(self, ctx, result, urls, timeout):
        from .. import injection
        for url in urls:
            body = json.dumps(injection.MASS_ASSIGN_FIELDS)
            status, resp = _fetch(url, method="POST",
                                  headers={"Content-Type": "application/json"},
                                  data=body, timeout=timeout)
            echoed = [k for k in injection.MASS_ASSIGN_FIELDS if k in resp]
            if status in (200, 201) and echoed:
                ev = ctx.runner.record_internal(
                    ["mass-assign", url], 0,
                    f"POST accepted (HTTP {status}); response echoes: {', '.join(echoed)}")
                result.findings.append(Finding(
                    title="Possible mass assignment", severity=Severity.MEDIUM,
                    description=f"{url} accepted a POST with privileged fields and its response "
                                f"reflects {', '.join(echoed)}. Confirm these are not bound.",
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                    metadata={"candidate": "mass assignment", "fields": echoed}))

    # --- session fixation ---
    def _session_fixation(self, ctx, result, cfg, timeout):
        from .. import sessionfix
        issue, ev_text = sessionfix.check(
            cfg["login_url"], cfg.get("login_data", ""), cfg.get("cookie_name"), timeout)
        ev = ctx.runner.record_internal(["session-fixation", cfg["login_url"]], 0, ev_text)
        if issue:
            result.findings.append(Finding(
                title=issue["issue"], severity=Severity.HIGH, description=issue["detail"],
                evidence_ids=[ev.id], target=ctx.target, phase=self.name,
                location=cfg["login_url"],
                recommendation="Regenerate the session id on authentication and privilege change.",
                metadata={"session_fixation": True}))
        else:
            result.notes.append(f"Session fixation: {ev_text}")

    # --- race condition harness ---
    def _race(self, ctx, result, url, count, timeout):
        method = "POST" if ctx.options.get("race_post") else "GET"
        t0 = time.monotonic()
        results = pmap(lambda i: _fetch(url, method=method, timeout=timeout),
                       list(range(count)), workers=count)
        statuses = [s for s, _ in results]
        ok = sum(1 for s in statuses if s in (200, 201))
        dist = ", ".join(f"{s}:{statuses.count(s)}" for s in sorted(set(statuses)))
        ev = ctx.runner.record_internal(["race", url], 0,
                                        f"{count} concurrent {method}s; statuses: {dist}",
                                        duration_sec=round(time.monotonic() - t0, 3))
        if ok > 1:
            result.findings.append(Finding(
                title="Race condition candidate: multiple concurrent successes",
                severity=Severity.MEDIUM,
                description=f"{ok} of {count} concurrent {method}s to {url} succeeded. If this "
                            "endpoint should act once (redeem, transfer), that is a race candidate.",
                evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                metadata={"candidate": "race condition", "successes": ok, "count": count}))
        else:
            result.notes.append(f"Race check on {url}: {ok}/{count} succeeded (statuses {dist}).")
