# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""SARIF 2.1.0 export, so findings drop into GitHub code scanning, CI, and IDEs.

Each finding becomes a SARIF result: severity maps to a SARIF level, the finding
location (a URL or file:line) becomes the result location, and the confidence tag
(confirmed vs reported) and CWE/OWASP references ride along in properties, so a
consumer can filter proven issues from scanner candidates.
"""
from __future__ import annotations

import json

from ..models import PhaseResult, Severity

_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
    Severity.LOW: "note", Severity.INFO: "note",
}
_SECURITY_SEVERITY = {  # GitHub code-scanning numeric severity
    Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0", Severity.INFO: "1.0",
}


def _location(loc: str | None) -> dict:
    if not loc:
        return {}
    return {"physicalLocation": {"artifactLocation": {"uri": loc}}}


def render_sarif(results: list[PhaseResult], target: str) -> str:
    rules: dict[str, dict] = {}
    sarif_results: list[dict] = []
    for r in results:
        for f in r.findings:
            sev = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
            rule_id = (f.metadata or {}).get("check_id") or f"sentari/{f.phase}/{_slug(f.title)}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": _slug(f.title),
                    "shortDescription": {"text": f.title[:120]},
                    "properties": {
                        "tags": ["security", f.phase],
                        "security-severity": _SECURITY_SEVERITY[sev],
                    },
                }
            md = f.metadata or {}
            res = {
                "ruleId": rule_id,
                "level": _LEVEL[sev],
                "message": {"text": f.description or f.title},
                "properties": {
                    "severity": sev.value,
                    "confidence": md.get("confidence", "reported"),
                    "phase": f.phase,
                    "evidence_ids": f.evidence_ids,
                    "references": f.references,
                },
            }
            loc = _location(f.location)
            if loc:
                res["locations"] = [loc]
            sarif_results.append(res)

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Sentari",
                "informationUri": "https://github.com/ahmadoqsrawi/sentari",
                "rules": list(rules.values()),
            }},
            "properties": {"target": target},
            "results": sarif_results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _slug(text: str) -> str:
    keep = "".join(c.lower() if c.isalnum() else "-" for c in text)[:60]
    return "-".join(p for p in keep.split("-") if p) or "finding"
