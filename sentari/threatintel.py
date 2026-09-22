# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Threat-intel correlation via the CISA Known Exploited Vulnerabilities catalog.

Correlates the CVEs on findings against CISA KEV (a public, authoritative list of
vulnerabilities known to be exploited in the wild). A match means a real exploit
is known to exist and is being used, which is genuine exploit-availability
signal, not a guess. The catalog is fetched over HTTPS and cached locally; if it
cannot be fetched, correlation is skipped with a note rather than invented.
"""
from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path
from typing import Optional

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CACHE = Path.home() / ".sentari" / "kev.json"
_MAX_AGE = 24 * 3600  # refresh daily


def load_kev(offline_ok: bool = True) -> Optional[set[str]]:
    """Return the set of KEV CVE ids, or None if unavailable."""
    if _CACHE.exists() and (time.time() - _CACHE.stat().st_mtime) < _MAX_AGE:
        try:
            return _parse(json.loads(_CACHE.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
    try:
        with urllib.request.urlopen(_KEV_URL, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        _CACHE.parent.mkdir(parents=True, exist_ok=True)
        _CACHE.write_text(json.dumps(data), encoding="utf-8")
        return _parse(data)
    except Exception:
        if offline_ok and _CACHE.exists():
            try:
                return _parse(json.loads(_CACHE.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                return None
        return None


def _parse(data: dict) -> set[str]:
    return {v.get("cveID", "").upper() for v in data.get("vulnerabilities", []) if v.get("cveID")}


def _cves(finding) -> list[str]:
    cvss = (finding.metadata or {}).get("cvss") or {}
    cves = cvss.get("cve") or []
    return [c.upper() for c in (cves if isinstance(cves, list) else [cves])]


def apply(results) -> int:
    """Tag findings whose CVE is in KEV as known-exploited. Returns count."""
    kev = load_kev()
    if not kev:
        for r in results:
            r.notes.append("Threat-intel: CISA KEV unavailable; correlation skipped.")
            break
        return 0
    flagged = 0
    for r in results:
        for f in r.findings:
            hits = [c for c in _cves(f) if c in kev]
            if hits:
                f.metadata = {**(f.metadata or {}),
                              "known_exploited": True, "kev_cves": hits}
                flagged += 1
    return flagged
