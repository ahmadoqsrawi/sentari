# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Session-fixation check.

A well-behaved app issues a new session identifier when a user authenticates. If
the identifier a user held before login is still valid afterwards, an attacker
who planted that identifier can ride the authenticated session. This checks that
by reading the session cookie before and after an operator-supplied login and
comparing them. It uses the credentials you provide; it does not guess passwords.
"""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from typing import Optional


def _sslctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _request(url, method="GET", headers=None, data=None, timeout=15):
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, method=method, data=body,
                                 headers={"User-Agent": "Sentari/0.11", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_sslctx()) as resp:
            return resp.status, resp.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:
        return e.code, (e.headers.get_all("Set-Cookie") if e.headers else []) or []
    except Exception:
        return 0, []


def _session_value(set_cookies: list[str], name: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Return (cookie_name, value). If name is None, pick the first session-like cookie."""
    for sc in set_cookies:
        jar = SimpleCookie()
        try:
            jar.load(sc)
        except Exception:
            continue
        for k, morsel in jar.items():
            if name and k.lower() != name.lower():
                continue
            if name or "sess" in k.lower() or k.lower() in ("sid", "phpsessid", "jsessionid"):
                return k, morsel.value
    return None, None


def check(login_url: str, login_data: str, cookie_name: Optional[str] = None,
          timeout: int = 15) -> tuple[Optional[dict], str]:
    """Return (issue, evidence_text). issue is None when no fixation is found."""
    pre_status, pre_cookies = _request(login_url, timeout=timeout)
    name, pre_val = _session_value(pre_cookies, cookie_name)
    if not pre_val:
        return None, "No pre-login session cookie was set; cannot assess fixation."

    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "Cookie": f"{name}={pre_val}"}
    post_status, post_cookies = _request(login_url, method="POST", headers=headers,
                                         data=login_data, timeout=timeout)
    _, post_val = _session_value(post_cookies, name)

    ev = (f"pre-login {name}={pre_val[:8]}... (HTTP {pre_status}); "
          f"post-login {name}={(post_val or '(unchanged)')[:8]}... (HTTP {post_status})")
    if post_val is None:
        # server did not reissue the cookie: the old one remains valid
        return ({"issue": "Session not rotated on login (session fixation)",
                 "detail": f"The '{name}' cookie was not reissued after authentication, so a "
                           "pre-set session id stays valid (session fixation)."}, ev)
    if post_val == pre_val:
        return ({"issue": "Session not rotated on login (session fixation)",
                 "detail": f"The '{name}' cookie is unchanged after authentication, so a "
                           "pre-set session id stays valid (session fixation)."}, ev)
    return None, ev
