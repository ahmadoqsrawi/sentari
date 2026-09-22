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


def run_checks(urls: list[str], timeout: int = 15, limit: int = 10
               ) -> tuple[list[dict], Optional[str]]:
    """Return (checks, error). Each check: url, type, detail, severity, confirmed, evidence."""
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
            browser.close()
    except Exception as e:
        return checks, f"browser session error: {type(e).__name__}: {e}"
    return checks, None


def _probe_url(ctx, url: str, timeout: int) -> list[dict]:
    out: list[dict] = []
    marker = "sx" + uuid.uuid4().hex[:10]
    payload = f'"><img src=x onerror="window.__sx=\'{marker}\'">'
    test_url = _with_param(url, "sentari_xss", payload)
    page = ctx.new_page()
    console: list[str] = []
    page.on("console", lambda m: console.append(f"{m.type}: {m.text}"[:200]))
    try:
        page.goto(test_url, timeout=timeout * 1000, wait_until="domcontentloaded")
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
        # insecure password field / mixed content, from the real DOM
        out.extend(_dom_checks(page, url, console))
    except Exception as e:
        out.append(_ck(url, "browser-error", "info", False, f"navigation failed: {e}", test_url))
    finally:
        page.close()
    return out


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
