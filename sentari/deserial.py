"""Insecure-deserialization surface detection.

Flags serialized objects carried in client-controllable inputs (URL parameters
and cookies), which is the classic entry point for deserialization attacks. It
recognizes the well-known formats by signature; it does not build or fire a
deserialization gadget (that needs a target-specific chain and is destructive).
It reports where a serialized blob is exposed so the operator can check whether
the app deserializes it unsafely.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

# (format name, predicate over the raw value)
_PHP = re.compile(r'^[aOsb]:\d+:[{"]')       # PHP serialize(): a:/ O:8:"..." / s:5:"..."


def detect(value: str) -> str | None:
    """Return the serialized format detected in a value, or None."""
    if not value or len(value) < 6:
        return None
    v = value.strip()
    if v.startswith("rO0AB"):                 # base64 of Java 0xACED0005
        return "java"
    if v.startswith("\xac\xed") or v.startswith("aced0005"):
        return "java"
    if v.startswith("BAh"):                    # base64 of Ruby Marshal 0x0408
        return "ruby-marshal"
    if v.startswith(("gAS", "gAJ", "gAN", "gAR")):  # base64 of Python pickle 0x80
        return "python-pickle"
    if _PHP.match(v):
        return "php"
    return None


def scan(url: str, cookies: dict[str, str]) -> list[dict]:
    """Scan a URL's query params and the given cookies for serialized blobs."""
    issues = []
    for name, value in parse_qsl(urlparse(url).query):
        fmt = detect(value)
        if fmt:
            issues.append({"format": fmt, "where": f"param {name}",
                           "detail": f"A {fmt} serialized object is carried in the '{name}' "
                                     "parameter."})
    for name, value in (cookies or {}).items():
        fmt = detect(value)
        if fmt:
            issues.append({"format": fmt, "where": f"cookie {name}",
                           "detail": f"A {fmt} serialized object is carried in the '{name}' cookie."})
    return issues


def scan_setcookie(url: str, set_cookie_values: list[str]) -> list[dict]:
    """Scan Set-Cookie header values (the app round-tripping a serialized cookie)."""
    cookies = {}
    for sc in set_cookie_values or []:
        first = sc.split(";", 1)[0]
        if "=" in first:
            k, _, v = first.partition("=")
            cookies[k.strip()] = v.strip()
    return scan(url, cookies)
