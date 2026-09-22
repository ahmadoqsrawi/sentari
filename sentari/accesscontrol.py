# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Broken access control / IDOR testing by comparing identities.

Given the same protected URLs requested as several identities (and anonymously),
this compares the real responses and reports two provable patterns:

  * Missing authentication: an anonymous request gets the same substantive
    content an authenticated user gets.
  * Horizontal access (IDOR): two different users get the same private resource,
    while anonymous access is refused, so the resource is protected but not
    scoped to its owner.

It only reports when the responses actually match and the resource is otherwise
non-trivial, to keep false positives down. It sends ordinary GETs with the
credentials you supply; it changes nothing.
"""
from __future__ import annotations

import difflib
import ssl
import urllib.error
import urllib.request

ANON = "anonymous"
_MIN_LEN = 200        # ignore tiny/empty bodies (error pages, redirects)
_SIMILAR = 0.95       # how alike two bodies must be to count as "the same resource"


def fetch(url: str, headers: dict[str, str], timeout: int = 10) -> tuple[int, str]:
    sslctx = ssl.create_default_context()
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "Sentari/0.9", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=sslctx) as resp:
            return resp.status, resp.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read(4000).decode("utf-8", "replace") if hasattr(e, "read") else ""
        return e.code, body
    except Exception:
        return 0, ""


def _similar(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:8000], b[:8000]).ratio()


def analyze(samples: dict[str, dict[str, tuple[int, str]]]) -> list[dict]:
    """samples: {url: {identity_name: (status, body)}}, including the ANON name.

    Returns issues: {issue, severity, detail, location, identities}."""
    issues: list[dict] = []
    for url, per_id in samples.items():
        anon_status, anon_body = per_id.get(ANON, (0, ""))
        users = {k: v for k, v in per_id.items() if k != ANON}

        # Missing authentication: anon sees an authenticated user's content.
        for name, (status, body) in users.items():
            if (status == 200 and anon_status == 200 and len(body) >= _MIN_LEN
                    and _similar(body, anon_body) >= _SIMILAR):
                issues.append({
                    "issue": "Resource accessible without authentication",
                    "severity": "high",
                    "detail": f"{url} returns the same content anonymously as it does for "
                              f"'{name}'. The resource is not access-controlled.",
                    "location": url, "identities": [ANON, name]})
                break  # one is enough per URL

        # Horizontal access / IDOR: two users get the same private resource while
        # anonymous access is refused (so it IS protected, just not scoped).
        anon_blocked = anon_status in (401, 403) or anon_status in (301, 302) or anon_status == 0 \
            or len(anon_body) < _MIN_LEN
        names = list(users)
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                s1, b1 = users[names[i]]
                s2, b2 = users[names[j]]
                if (anon_blocked and s1 == 200 and s2 == 200
                        and len(b1) >= _MIN_LEN and _similar(b1, b2) >= _SIMILAR):
                    issues.append({
                        "issue": "Possible IDOR: same resource served to different users",
                        "severity": "high",
                        "detail": f"{url} returns near-identical private content to both "
                                  f"'{names[i]}' and '{names[j]}' while anonymous access is "
                                  "refused. Confirm the resource should be owner-scoped.",
                        "location": url, "identities": [names[i], names[j]]})
    return issues


def collect(urls: list[str], identities: list[dict], timeout: int = 10
            ) -> dict[str, dict[str, tuple[int, str]]]:
    """Fetch each URL as every identity plus anonymously. identities: [{name, headers}]."""
    samples: dict[str, dict[str, tuple[int, str]]] = {}
    for url in urls:
        per_id = {ANON: fetch(url, {}, timeout)}
        for ident in identities:
            per_id[ident["name"]] = fetch(url, ident.get("headers", {}), timeout)
        samples[url] = per_id
    return samples
