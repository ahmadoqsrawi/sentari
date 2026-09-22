# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Business-logic workflow testing (operator-defined).

Business-logic flaws cannot be found generically, so this replays a sequence of
requests the operator describes and checks the app against the operator's own
expectations. Two honest signals:

  * a step marked `should_fail` that instead succeeds (step-skipping, workflow or
    authorization bypass, price/quantity tampering the app should reject), and
  * a step whose status does not match its declared `expect_status`.

Values can be captured from one response and substituted into later steps with
{{var}}. It replays real requests and compares real responses; it asserts nothing
the operator did not describe.

Spec (JSON):
  {"vars": {...},
   "steps": [{"name": "...", "method": "POST", "url": "...", "headers": {...},
              "data": "...", "expect_status": 200, "should_fail": false,
              "capture": {"token": "\"token\":\"([^\"]+)\""}}]}
"""
from __future__ import annotations

import json
import re
from typing import Callable

_VAR = re.compile(r"\{\{(\w+)\}\}")


def load_spec(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _subst(text, vars: dict) -> str:
    if not isinstance(text, str):
        return text
    return _VAR.sub(lambda m: str(vars.get(m.group(1), m.group(0))), text)


def run(spec: dict, fetch: Callable[[str, str, dict, str], tuple[int, str]]
        ) -> tuple[list[dict], list[dict]]:
    """Return (issues, trace). fetch(url, method, headers, data) -> (status, body)."""
    vars = dict(spec.get("vars", {}))
    issues: list[dict] = []
    trace: list[dict] = []
    for step in spec.get("steps", []):
        name = step.get("name", step.get("url", "step"))
        url = _subst(step.get("url", ""), vars)
        method = step.get("method", "GET").upper()
        headers = {k: _subst(v, vars) for k, v in (step.get("headers") or {}).items()}
        data = _subst(step["data"], vars) if step.get("data") is not None else None

        status, body = fetch(url, method, headers, data)
        trace.append({"step": name, "status": status, "url": url})

        for var, pat in (step.get("capture") or {}).items():
            m = re.search(pat, body)
            if m:
                vars[var] = m.group(1) if m.groups() else m.group(0)

        exp = step.get("expect_status")
        if step.get("should_fail") and 200 <= status < 300:
            issues.append({
                "issue": "Business-logic / workflow bypass",
                "severity": "high",
                "detail": f"Step '{name}' succeeded (HTTP {status}) when it was expected to "
                          "fail. The app accepted an action it should have rejected.",
                "step": name, "url": url, "status": status})
        elif exp is not None and status != exp:
            issues.append({
                "issue": "Unexpected workflow behavior",
                "severity": "medium",
                "detail": f"Step '{name}' returned HTTP {status}, expected {exp}.",
                "step": name, "url": url, "status": status})
    return issues, trace
