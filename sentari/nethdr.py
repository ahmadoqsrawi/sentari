# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Global custom HTTP headers, applied to every request in a run.

Sentari has no single HTTP layer: phases open URLs with urllib in ~17 places.
Rather than thread a headers argument through all of them, we install a urllib
opener whose default headers are added to every ``urlopen`` call that does not
already set them (an identity's Cookie, for example, is left untouched). This is
how API keys, JWTs, session cookies, and WAF-bypass tokens ride along with every
request. The browser phase (Playwright) receives the same headers separately.

HTTP header names are case-insensitive by RFC 7230, so urllib's capitalization
of default header names does not change how a compliant server reads them.
"""
from __future__ import annotations

import urllib.request

USER_AGENT = "sentari"

_INSTALLED: dict[str, str] = {}


def parse_header(spec: str) -> tuple[str, str]:
    """Parse a 'Name: Value' header spec. Raises ValueError on a malformed one."""
    name, sep, value = spec.partition(":")
    if not sep or not name.strip():
        raise ValueError(f"bad header {spec!r}: want 'Name: Value'")
    return name.strip(), value.strip()


def parse_headers(specs: list[str]) -> dict[str, str]:
    """Parse repeated 'Name: Value' specs into a dict (later wins on a repeat)."""
    out: dict[str, str] = {}
    for spec in specs:
        name, value = parse_header(spec)
        out[name] = value
    return out


def install(headers: dict[str, str]) -> None:
    """Install a process-wide urllib opener that adds these headers to every
    request. Passing an empty dict still sets our User-Agent."""
    global _INSTALLED
    _INSTALLED = dict(headers)
    opener = urllib.request.build_opener()
    opener.addheaders = [("User-Agent", USER_AGENT)] + list(headers.items())
    urllib.request.install_opener(opener)


def current() -> dict[str, str]:
    """The headers installed for this run (empty if none)."""
    return dict(_INSTALLED)
