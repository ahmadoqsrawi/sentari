# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Service classification (rule-based).

Groups a discovered service into a category (web, database, mail, remote-access,
cache, dns, and so on) from its port and service name. This is a deterministic
lookup, not machine learning; it labels what a scan found, it does not predict.
"""
from __future__ import annotations

from typing import Optional

_BY_PORT = {
    21: "file-transfer", 22: "remote-access", 23: "remote-access", 25: "mail",
    53: "dns", 80: "web", 110: "mail", 143: "mail", 389: "directory",
    443: "web", 465: "mail", 587: "mail", 636: "directory", 993: "mail",
    995: "mail", 1433: "database", 1521: "database", 2049: "file-share",
    3000: "web", 3001: "web", 3306: "database", 3389: "remote-access",
    5432: "database", 5900: "remote-access", 6379: "cache", 8000: "web",
    8080: "web", 8443: "web", 9200: "search", 11211: "cache", 27017: "database",
}
_BY_KEYWORD = {
    "http": "web", "ssh": "remote-access", "smtp": "mail", "imap": "mail",
    "pop3": "mail", "mysql": "database", "postgres": "database", "redis": "cache",
    "mongo": "database", "ldap": "directory", "dns": "dns", "ftp": "file-transfer",
    "rdp": "remote-access", "vnc": "remote-access", "elastic": "search",
}


def classify(port: Optional[int] = None, service: Optional[str] = None) -> str:
    if service:
        s = service.lower()
        for kw, cat in _BY_KEYWORD.items():
            if kw in s:
                return cat
    if port in _BY_PORT:
        return _BY_PORT[port]
    return "unknown"
