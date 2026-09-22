# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""OpenVAS / Greenbone (GVM) connector.

Pulls results from a Greenbone instance through python-gvm and maps them to
findings. It is optional: without python-gvm installed or the GVM_* environment
set, it returns nothing with a note. It reports what GVM found; it does not
generate results.

Env: GVM_HOST, GVM_PORT (default 9390), GVM_USER, GVM_PASS.
"""
from __future__ import annotations

import importlib
import os
from typing import Optional

_SEV = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low")]


def _band(score: float) -> str:
    for threshold, name in _SEV:
        if score >= threshold:
            return name
    return "info"


def fetch_results(target_ip: str) -> tuple[list[dict], Optional[str]]:
    """Return (results, error). Each result: {name, severity, host, cvss, oid}."""
    gvm = importlib.import_module("gvm") if _available() else None
    if gvm is None:
        return [], "python-gvm not installed (pip install python-gvm)"
    host = os.getenv("GVM_HOST")
    user = os.getenv("GVM_USER")
    pw = os.getenv("GVM_PASS")
    if not (host and user and pw):
        return [], "set GVM_HOST / GVM_USER / GVM_PASS"
    try:
        from gvm.connections import TLSConnection
        from gvm.protocols.gmp import Gmp
        conn = TLSConnection(hostname=host, port=int(os.getenv("GVM_PORT", "9390")))
        results = []
        with Gmp(connection=conn) as gmp:
            gmp.authenticate(user, pw)
            resp = gmp.get_results(filter_string=f"host={target_ip} rows=1000")
            for r in resp.findall("result"):
                name = r.findtext("name") or "GVM result"
                sev = float(r.findtext("severity") or 0)
                oid = (r.find("nvt").get("oid") if r.find("nvt") is not None else "")
                results.append({"name": name, "severity": _band(sev), "cvss": sev,
                                "host": r.findtext("host") or target_ip, "oid": oid})
        return results, None
    except Exception as e:
        return [], f"GVM query failed: {type(e).__name__}: {e}"


def _available() -> bool:
    try:
        importlib.import_module("gvm")
        return True
    except Exception:
        return False
