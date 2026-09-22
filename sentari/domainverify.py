# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Prove control of a domain via a DNS TXT record before an external scan.

This is an honest, Cloudflare-style ownership check: Sentari issues a token, the
operator publishes it as a ``sentari-verify=<token>`` TXT record on the domain
(in Cloudflare or any DNS provider), and a second run confirms the record
resolves. Only someone who controls the domain's DNS can add it, so a passing
check is real evidence of control, not an attestation.

Issued tokens are stored per-domain under ~/.sentari/verify.json so the same
token is checked on the follow-up run. TXT lookups use the system ``dig`` or
``nslookup``; without either, the check degrades honestly and says so.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

PREFIX = "sentari-verify="


def _store_path() -> Path:
    base = Path(os.environ.get("SENTARI_HOME", Path.home() / ".sentari"))
    return base / "verify.json"


def _load_store() -> dict:
    p = _store_path()
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_store(data: dict) -> None:
    p = _store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def token_for(domain: str) -> str:
    """Return the token for ``domain``, issuing and persisting one if needed."""
    domain = domain.strip().lower()
    store = _load_store()
    if domain not in store:
        store[domain] = secrets.token_hex(16)
        _save_store(store)
    return store[domain]


def _resolver() -> list[str] | None:
    if shutil.which("dig"):
        return ["dig", "+short", "TXT"]
    if shutil.which("nslookup"):
        return ["nslookup", "-type=TXT"]
    return None


def txt_records(domain: str, timeout: int = 15) -> tuple[list[str], str | None]:
    """Return (records, error). Records are unquoted TXT strings."""
    resolver = _resolver()
    if not resolver:
        return [], "no DNS resolver found (install dnsutils for `dig`, or bind-tools)"
    cmd = (resolver + [domain]) if resolver[0] == "dig" else [resolver[0], resolver[1], domain]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [], f"DNS lookup timed out after {timeout}s"
    except Exception as e:  # pragma: no cover - defensive
        return [], f"DNS lookup failed: {type(e).__name__}: {e}"
    records = re.findall(r'"([^"]*)"', proc.stdout)
    if not records:  # dig +short may print unquoted lines
        records = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    return records, None


@dataclass
class VerifyResult:
    domain: str
    token: str
    verified: bool
    records: list[str]
    error: str | None = None


def verify(domain: str, timeout: int = 15) -> VerifyResult:
    """Check whether the domain publishes this run's ownership token."""
    domain = domain.strip().lower()
    token = token_for(domain)
    records, err = txt_records(domain, timeout=timeout)
    wanted = PREFIX + token
    verified = any(wanted in r for r in records)
    return VerifyResult(domain=domain, token=token, verified=verified,
                        records=records, error=err)


def instructions(domain: str, token: str) -> str:
    return (f"To prove control of {domain}, add this DNS TXT record "
            f"(in Cloudflare or your DNS provider):\n\n"
            f"    Type:  TXT\n"
            f"    Name:  {domain}   (or @ for the apex)\n"
            f"    Value: {PREFIX}{token}\n\n"
            f"DNS can take a few minutes to propagate. Then re-run:\n"
            f"    sentari --verify-domain {domain}")
