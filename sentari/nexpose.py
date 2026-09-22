"""Rapid7 Nexpose / InsightVM connector.

Pulls vulnerability results for a host from a Nexpose/InsightVM console through
its REST API (v3) and maps them to findings. It is optional and graceful: without
the NEXPOSE_* environment set it returns nothing with a note. It reports what the
console found; it does not generate results.

Env: NEXPOSE_HOST, NEXPOSE_PORT (default 3780), NEXPOSE_USER, NEXPOSE_PASS.
Set NEXPOSE_VERIFY_TLS=1 to require a valid certificate (default: allow the
self-signed cert consoles ship with, since these are internal hosts).
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.request
from typing import Optional

# Nexpose severity is 1..10 (per-vuln "riskScore"/"severityScore"); map to bands.
_SEV = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low")]
_MAX_DETAIL = 200  # bound the per-vulnerability detail lookups


def _band(score: float) -> str:
    for threshold, name in _SEV:
        if score >= threshold:
            return name
    return "info"


def _ctx() -> ssl.SSLContext:
    c = ssl.create_default_context()
    if os.getenv("NEXPOSE_VERIFY_TLS", "") not in ("1", "true", "yes"):
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
    return c


def fetch_results(target_ip: str) -> tuple[list[dict], Optional[str]]:
    """Return (results, error). Each result: {name, severity, host, cvss, id}."""
    host = os.getenv("NEXPOSE_HOST")
    user = os.getenv("NEXPOSE_USER")
    pw = os.getenv("NEXPOSE_PASS")
    if not (host and user and pw):
        return [], "set NEXPOSE_HOST / NEXPOSE_USER / NEXPOSE_PASS"
    base = f"https://{host}:{os.getenv('NEXPOSE_PORT', '3780')}/api/3"
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    ctx = _ctx()

    def call(path: str, method: str = "GET", body: Optional[dict] = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method,
                                     headers={"Authorization": f"Basic {auth}",
                                              "Content-Type": "application/json",
                                              "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8", "replace") or "{}")

    try:
        search = call("/assets/search?size=1", "POST",
                      {"match": "all",
                       "filters": [{"field": "ip-address", "operator": "is",
                                    "value": target_ip}]})
        assets = search.get("resources") or []
        if not assets:
            return [], f"no asset in Nexpose matches {target_ip}"
        asset_id = assets[0].get("id")
        vulns = call(f"/assets/{asset_id}/vulnerabilities?size=500").get("resources") or []
        results = []
        for v in vulns[:_MAX_DETAIL]:
            vid = v.get("id")
            if not vid:
                continue
            try:
                d = call(f"/vulnerabilities/{vid}")
            except Exception:
                d = {}
            cvss = (((d.get("cvss") or {}).get("v3") or {}).get("score")
                    or ((d.get("cvss") or {}).get("v2") or {}).get("score") or 0)
            cvss = float(cvss or 0)
            results.append({"id": vid, "name": d.get("title") or vid,
                            "severity": _band(cvss or (d.get("riskScore", 0) / 100)),
                            "cvss": cvss, "host": target_ip})
        return results, None
    except Exception as e:
        return [], f"Nexpose query failed: {type(e).__name__}: {e}"
