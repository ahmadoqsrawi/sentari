"""Authorization gate + audit log.

Sentari runs real offensive tools, so scope enforcement is not optional and is
never a decorative string: a target is refused unless it matches the
operator-declared scope, and the operator must explicitly attest authorization.
Every run is written to an append-only audit log.
"""
from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


class AuthorizationError(Exception):
    pass


@dataclass
class Scope:
    """Allowlist of what may be tested. Empty scope authorizes nothing."""
    hosts: set[str] = field(default_factory=set)      # exact hostnames
    cidrs: list[ipaddress._BaseNetwork] = field(default_factory=list)

    @classmethod
    def from_items(cls, items: list[str]) -> "Scope":
        hosts: set[str] = set()
        cidrs: list[ipaddress._BaseNetwork] = []
        for raw in items:
            item = raw.strip()
            if not item:
                continue
            try:
                cidrs.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                hosts.add(item.lower())
        return cls(hosts=hosts, cidrs=cidrs)

    def contains(self, target: str) -> bool:
        t = host_only(target).lower()
        if t in self.hosts:
            return True
        # direct IP match against CIDRs
        try:
            ip = ipaddress.ip_address(t)
            return any(ip in net for net in self.cidrs)
        except ValueError:
            pass
        # resolve hostname and check every resolved IP against CIDRs
        if self.cidrs:
            for ip in _resolve_all(t):
                if any(ipaddress.ip_address(ip) in net for net in self.cidrs):
                    return True
        return False

    def is_empty(self) -> bool:
        return not self.hosts and not self.cidrs


def host_only(target: str) -> str:
    """Extract the hostname from a bare host, host:port, or URL. Leaves IPv6
    literals (multiple colons) intact."""
    t = target.strip()
    if "://" in t:
        from urllib.parse import urlparse
        return urlparse(t).hostname or t
    t = t.split("/")[0]
    # strip a single trailing :port (but not IPv6, which has multiple colons)
    if t.count(":") == 1:
        host, _, port = t.partition(":")
        if port.isdigit():
            return host
    return t


def _resolve_all(host: str) -> list[str]:
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except OSError:
        return []


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, **fields) -> None:
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def authorize(target: str, scope: Scope, authorized: bool, audit: AuditLog) -> None:
    """Raise AuthorizationError unless the target is in scope AND the operator
    has attested authorization. Both conditions are logged."""
    if scope.is_empty():
        audit.record("authorize.denied", target=target, reason="empty_scope")
        raise AuthorizationError(
            "No scope defined. Declare authorized targets with --scope before scanning."
        )
    if not authorized:
        audit.record("authorize.denied", target=target, reason="no_attestation")
        raise AuthorizationError(
            "Authorization not attested. Pass --authorized to confirm you have "
            "explicit written permission to test this target."
        )
    if not scope.contains(target):
        audit.record("authorize.denied", target=target, reason="out_of_scope")
        raise AuthorizationError(
            f"Target {target!r} is not within the declared scope. Refusing to run."
        )
    audit.record("authorize.granted", target=target)
