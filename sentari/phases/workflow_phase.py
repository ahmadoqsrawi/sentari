"""Phase 3 (business logic): replay an operator-defined workflow.

Runs only when --workflow FILE is given. It replays the described request
sequence and reports steps that succeeded when they should have failed
(step-skipping, workflow/authorization bypass, price or quantity tampering) or
that returned an unexpected status. Findings are backed by the real responses.
"""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request

from ..models import Finding, PhaseResult, Severity
from .base import Phase, PhaseContext

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
        "low": Severity.LOW, "info": Severity.INFO}


def _fetch(url, method="GET", headers=None, data=None, timeout=15):
    sslctx = ssl.create_default_context()
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, method=method, data=body,
                                 headers={"User-Agent": "Sentari/0.11", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=sslctx) as resp:
            return resp.status, resp.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(4000).decode("utf-8", "replace") if hasattr(e, "read") else "")
    except Exception:
        return 0, ""


class WorkflowPhase(Phase):
    name = "workflow"
    number = 3
    description = "Business-logic workflow testing from a spec (--workflow FILE)"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        path = ctx.options.get("workflow_spec")
        if not path:
            return
        from .. import workflow
        try:
            spec = workflow.load_spec(path)
        except (OSError, ValueError) as e:
            result.notes.append(f"Workflow: could not read spec {path}: {e}")
            return
        timeout = max(ctx.runner.default_timeout, 15)
        issues, trace = workflow.run(spec, lambda u, m, h, d: _fetch(u, m, h, d, timeout))
        for iss in issues:
            ev = ctx.runner.record_internal(
                ["workflow-step", iss["step"], iss["url"]], 0,
                f"{iss['detail']} (HTTP {iss['status']})")
            result.findings.append(Finding(
                title=iss["issue"], severity=_SEV.get(iss["severity"], Severity.MEDIUM),
                description=iss["detail"], evidence_ids=[ev.id], target=ctx.target,
                phase=self.name, location=iss["url"],
                metadata={"candidate": "business logic", "step": iss["step"]}))
        result.notes.append(f"Workflow: ran {len(trace)} step(s), {len(issues)} issue(s).")
