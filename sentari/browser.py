# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Headless-browser client-side checks (DAST), grounded in what the browser does.

Drives a real headless browser (Playwright) against authorized URLs to find
client-side issues a template scanner misses:

  * Reflected XSS, confirmed by execution. A unique payload sets a JavaScript
    marker; the finding is only "confirmed" when the browser reports the marker
    was actually set, which is a working proof, not a reflection guess.
  * Password fields served over plain HTTP.
  * Mixed content (an HTTPS page loading HTTP subresources).

It needs Playwright and its browser (pip install "sentari[browser]" and
`playwright install chromium`). Without them it reports that and adds nothing.
It sends crafted requests, so it runs only when explicitly requested (--browser).
"""
from __future__ import annotations

import importlib
import uuid
from typing import Optional
from urllib.parse import urlencode, urlparse, urlunparse


def available() -> bool:
    try:
        importlib.import_module("playwright.sync_api")
        return True
    except Exception:
        return False


def _with_param(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = (p.query + "&" if p.query else "") + urlencode({key: value})
    return urlunparse(p._replace(query=q))


def run_checks(urls: list[str], timeout: int = 15, limit: int = 10, active: bool = False
               ) -> tuple[list[dict], Optional[str]]:
    """Return (checks, error). Each check: url, type, detail, severity, confirmed, evidence.

    When `active` is set (outside safe mode), also submit a payload through forms
    and re-load the page to detect stored XSS. This writes data to the app."""
    if not available():
        return [], "Playwright not installed (pip install \"sentari[browser]\" && playwright install chromium)"
    from playwright.sync_api import sync_playwright
    checks: list[dict] = []
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True)
            except Exception as e:
                return [], f"could not launch browser (run `playwright install chromium`): {e}"
            ctx = browser.new_context(ignore_https_errors=True)
            for url in urls[:limit]:
                checks.extend(_probe_url(ctx, url, timeout))
                if active:
                    checks.extend(_stored_xss(ctx, url, timeout))
            browser.close()
    except Exception as e:
        return checks, f"browser session error: {type(e).__name__}: {e}"
    return checks, None


def _stored_xss(ctx, url: str, timeout: int) -> list[dict]:
    """Submit an XSS payload through a form, reload, and check for execution."""
    marker = "stx" + uuid.uuid4().hex[:10]
    payload = f'<img src=x onerror="window.__stx=\'{marker}\'">'
    page = ctx.new_page()
    try:
        page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
        filled = page.evaluate(
            """(p) => {
                for (const f of document.forms) {
                    let any = false;
                    for (const e of f.elements) {
                        const t = (e.type || '').toLowerCase();
                        if (e.tagName === 'TEXTAREA' || t === 'text' || t === 'search' || t === '') {
                            e.value = p; any = true;
                        }
                    }
                    if (any) { f.submit(); return true; }
                }
                return false;
            }""", payload)
        if not filled:
            return []
        page.wait_for_timeout(500)
        # revisit the original page; a stored payload renders again there
        page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
        page.wait_for_timeout(400)
        if page.evaluate("window.__stx || null") == marker:
            return [_ck(url, "stored-xss", "high", True,
                        "A payload submitted through a form executed when the page was "
                        "reloaded (stored XSS). Working PoC.",
                        f"{url}\n[executed after resubmit] window.__stx == {marker}")]
    except Exception:
        pass
    finally:
        page.close()
    return []


def _probe_url(ctx, url: str, timeout: int) -> list[dict]:
    out: list[dict] = []
    marker = "sx" + uuid.uuid4().hex[:10]
    payload = f'"><img src=x onerror="window.__sx=\'{marker}\'">'
    test_url = _with_param(url, "sentari_xss", payload)
    page = ctx.new_page()
    console: list[str] = []
    page.on("console", lambda m: console.append(f"{m.type}: {m.text}"[:200]))
    try:
        resp = page.goto(test_url, timeout=timeout * 1000, wait_until="domcontentloaded")
        try:
            hit = page.evaluate("window.__sx || null")
        except Exception:
            hit = None
        content = page.content()
        if hit == marker:
            out.append(_ck(url, "reflected-xss", "high", True,
                           "Payload executed in the browser (JS marker set). Working PoC.",
                           test_url + f"\n[executed] window.__sx == {marker}"))
        elif payload in content:
            out.append(_ck(url, "reflected-input", "medium", False,
                           "Input reflected unescaped in the response (not confirmed executing).",
                           test_url + "\n[reflected raw payload in DOM]"))
        headers = {}
        try:
            headers = resp.headers if resp else {}
        except Exception:
            headers = {}
        # insecure password field / mixed content, from the real DOM
        out.extend(_dom_checks(page, url, console))
        out.extend(_clickjacking(headers, url))
        out.extend(_csrf(page, url))
        out.extend(_dom_xss(ctx, url, timeout))
        out.extend(_proto_pollution(ctx, url, timeout))
    except Exception as e:
        out.append(_ck(url, "browser-error", "info", False, f"navigation failed: {e}", test_url))
    finally:
        page.close()
    return out


def _clickjacking(headers: dict, url: str) -> list[dict]:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    xfo = h.get("x-frame-options", "")
    csp = h.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        return [_ck(url, "clickjacking", "medium", False,
                    "No X-Frame-Options and no CSP frame-ancestors: the page can be framed "
                    "(clickjacking candidate).",
                    f"{url}\nX-Frame-Options: (absent)\nCSP frame-ancestors: (absent)")]
    return []


def _csrf(page, url: str) -> list[dict]:
    """Flag state-changing forms with no anti-CSRF token."""
    try:
        forms = page.evaluate(
            """() => Array.from(document.forms).map(f => ({
                method: (f.method || 'get').toLowerCase(),
                fields: Array.from(f.elements).map(e => (e.name||'').toLowerCase())
            }))""")
    except Exception:
        return []
    out = []
    for f in forms or []:
        if f.get("method") == "post":
            names = f.get("fields", [])
            has_token = any(("csrf" in n or "token" in n or "authenticity" in n) for n in names)
            if not has_token:
                out.append(_ck(url, "csrf", "medium", False,
                               "A POST form has no anti-CSRF token field (candidate).",
                               f"{url}\nform fields: {', '.join(names) or '(none)'}"))
                break
    return out


def _dom_xss(ctx, url: str, timeout: int) -> list[dict]:
    """DOM-based XSS via the URL fragment (never sent to the server)."""
    import uuid as _uuid
    marker = "dx" + _uuid.uuid4().hex[:10]
    frag = f'#"><img src=x onerror="window.__dx=\'{marker}\'">'
    page = ctx.new_page()
    try:
        page.goto(url + frag, timeout=timeout * 1000, wait_until="domcontentloaded")
        page.wait_for_timeout(300)
        hit = page.evaluate("window.__dx || null")
        if hit == marker:
            return [_ck(url, "dom-xss", "high", True,
                        "Fragment payload executed via a client-side sink (DOM XSS). "
                        "The fragment is never sent to the server, so this is client-side.",
                        url + frag + f"\n[executed] window.__dx == {marker}")]
    except Exception:
        pass
    finally:
        page.close()
    return []


def _proto_pollution(ctx, url: str, timeout: int) -> list[dict]:
    """Client-side prototype pollution via a crafted query string."""
    marker = "pp" + uuid.uuid4().hex[:8]
    test = _with_param(url, "__proto__[sentari_pp]", marker)
    page = ctx.new_page()
    try:
        page.goto(test, timeout=timeout * 1000, wait_until="domcontentloaded")
        page.wait_for_timeout(300)
        polluted = page.evaluate("({}).sentari_pp || null")
        if polluted == marker:
            return [_ck(url, "prototype-pollution", "high", True,
                        "A query parameter polluted Object.prototype (client-side prototype "
                        "pollution). Confirmed by reading the polluted property.",
                        test + f"\n[confirmed] ({{}}).sentari_pp == {marker}")]
    except Exception:
        pass
    finally:
        page.close()
    return []


def _dom_checks(page, url: str, console: list[str]) -> list[dict]:
    out = []
    is_http = urlparse(url).scheme == "http"
    try:
        pw_fields = page.query_selector_all("input[type=password]")
    except Exception:
        pw_fields = []
    if is_http and pw_fields:
        out.append(_ck(url, "password-over-http", "high", True,
                       f"{len(pw_fields)} password field(s) served over plain HTTP.",
                       f"{url}\ninput[type=password] count = {len(pw_fields)}"))
    mixed = [c for c in console if "mixed content" in c.lower()]
    if mixed:
        out.append(_ck(url, "mixed-content", "medium", True,
                       "Browser reported mixed content on an HTTPS page.",
                       "\n".join(mixed[:5])))
    return out


def _ck(url, ctype, severity, confirmed, detail, evidence) -> dict:
    return {"url": url, "type": ctype, "severity": severity, "confirmed": confirmed,
            "detail": detail, "evidence": evidence}
