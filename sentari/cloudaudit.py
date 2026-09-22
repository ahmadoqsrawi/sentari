# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Cloud misconfiguration auditing via Prowler.

Runs Prowler against a cloud account and maps its FAILed checks to findings.
This audits configuration in your own account (using your normal cloud
credentials); it does not attack anything. Optional and graceful: without
Prowler installed it reports that and adds nothing. It reports what Prowler
found; it invents no findings.
"""
from __future__ import annotations

import json

# Prowler severities -> Sentari severity names.
SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium",
           "low": "low", "informational": "info", "info": "info"}


def _get(d: dict, *keys, default=""):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def parse_prowler(stdout: str) -> list[dict]:
    """Parse Prowler JSON output into failed-check dicts. Accepts a list, or a
    dict with a 'findings' list, and both Prowler's native and OCSF-ish keys."""
    try:
        data = json.loads(stdout)
    except ValueError:
        return []
    if isinstance(data, dict):
        data = data.get("findings") or data.get("results") or []
    out = []
    for item in data:
        if not isinstance(item, dict):
            continue
        status = str(_get(item, "Status", "status", "status_code")).upper()
        if status not in ("FAIL", "FAILED"):
            continue
        sev = str(_get(item, "Severity", "severity", default="medium")).lower()
        # OCSF nests severity under finding_info sometimes; keep it best-effort.
        out.append({
            "check_id": _get(item, "CheckID", "check_id", "check_title", default="prowler"),
            "title": _get(item, "CheckTitle", "check_title", "title", default="Prowler check"),
            "severity": SEV_MAP.get(sev, "medium"),
            "detail": _get(item, "StatusExtended", "status_extended", "status_detail",
                           "risk_details", default=""),
            "resource": _get(item, "ResourceId", "resource_id", "resource_uid",
                             "resource", default=""),
            "region": _get(item, "Region", "region", default=""),
            "service": _get(item, "ServiceName", "service_name", "service", default=""),
        })
    return out
