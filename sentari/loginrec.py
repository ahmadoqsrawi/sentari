# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Record a login through a real browser and capture the authenticated session.

The wizard's Access step needs an authenticated session to test what a
logged-in user can reach. This drives a headless browser (Playwright) through a
login form, verifies the sign-in actually succeeded, and captures the resulting
cookies as a ``Cookie`` header that becomes a test identity or a global header.

"Verified" is grounded, not assumed: the sign-in counts only when a real signal
says so, either a caller-supplied success string appearing on the page, or the
password field disappearing together with the URL leaving the login page. A
screenshot and the post-login response are saved as evidence. Without Playwright
installed it degrades honestly and records nothing.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


def available() -> bool:
    try:
        importlib.import_module("playwright.sync_api")
        return True
    except Exception:
        return False


@dataclass
class LoginRecording:
    url: str
    verified: bool = False
    cookies: list[dict] = field(default_factory=list)
    cookie_header: str = ""
    screenshot: str | None = None
    response: str | None = None
    detail: str = ""
    error: str | None = None


def _cookie_header(cookies: list[dict]) -> str:
    return "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name"))


def record_login(url: str, username: str, password: str, *,
                 user_field: str | None = None, pass_field: str | None = None,
                 submit: str | None = None, success_text: str | None = None,
                 timeout: int = 30, artifacts_dir: str | None = None,
                 extra_headers: dict | None = None) -> LoginRecording:
    """Sign in at ``url`` and capture the session. See module docstring."""
    rec = LoginRecording(url=url)
    if not available():
        rec.error = ('Playwright not installed (pip install "sentari[browser]" '
                     "&& playwright install chromium)")
        return rec
    from playwright.sync_api import sync_playwright

    out = Path(artifacts_dir or "sentari-login")
    out.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True)
            except Exception as e:
                rec.error = f"could not launch browser (run `playwright install chromium`): {e}"
                return rec
            ctx = browser.new_context(ignore_https_errors=True,
                                      extra_http_headers=extra_headers or {})
            page = ctx.new_page()
            page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")

            # Fill the username/password fields (explicit selectors win; else
            # the first e-mail/text input and the first password input).
            if user_field:
                page.fill(user_field, username)
            else:
                page.fill("input[type=email], input[type=text], input[name*=user i], "
                          "input[name*=email i]", username)
            pass_sel = pass_field or "input[type=password]"
            page.fill(pass_sel, password)

            had_password = page.locator("input[type=password]").count() > 0
            login_host = urlparse(url).path

            if submit:
                page.click(submit)
            else:
                # Prefer a submit control; fall back to Enter in the password box.
                btn = page.locator("button[type=submit], input[type=submit], "
                                   "button:has-text('log in'), button:has-text('sign in')")
                if btn.count() > 0:
                    btn.first.click()
                else:
                    page.press(pass_sel, "Enter")

            try:
                page.wait_for_load_state("networkidle", timeout=timeout * 1000)
            except Exception:
                page.wait_for_timeout(1500)

            # Grounded verification.
            body = ""
            try:
                body = page.content()
            except Exception:
                body = ""
            if success_text:
                rec.verified = success_text in body
                rec.detail = (f"success text {success_text!r} present"
                              if rec.verified else f"success text {success_text!r} not found")
            else:
                still_has_pass = page.locator("input[type=password]").count() > 0
                moved = urlparse(page.url).path != login_host
                rec.verified = had_password and not still_has_pass and moved
                rec.detail = (f"password field gone and URL moved to {page.url}"
                              if rec.verified
                              else "no clear success signal (pass a success text to confirm)")

            rec.cookies = ctx.cookies()
            rec.cookie_header = _cookie_header(rec.cookies)

            shot = out / "login.png"
            try:
                page.screenshot(path=str(shot))
                rec.screenshot = str(shot)
            except Exception:
                pass
            resp = out / "login-response.html"
            try:
                resp.write_text(body, encoding="utf-8")
                rec.response = str(resp)
            except Exception:
                pass
            browser.close()
    except Exception as e:
        rec.error = f"login recording failed: {type(e).__name__}: {e}"
    return rec
