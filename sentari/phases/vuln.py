"""Phase 3: Vulnerability Assessment.

Runs real detection engines against the discovered web surface and reports only
confirmed matches, each carrying the tool's own output as evidence:

  * nuclei : thousands of maintained detection templates (the centerpiece).
  * sqlmap : SQL-injection testing, GATED: only runs outside safe mode or when
              an explicit injectable URL is supplied. Low risk/level, --batch.

If a tool is not installed, Sentari says so and adds nothing: it never invents a
vulnerability to fill the gap.
"""
from __future__ import annotations

import json

from ..models import Finding, PhaseResult, Severity
from .base import Phase, PhaseContext
from .scanning import _web_targets

_NUCLEI_SEV = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
    "low": Severity.LOW, "info": Severity.INFO, "unknown": Severity.INFO,
}


def _urls(ctx: PhaseContext) -> list[str]:
    out = []
    for host, port in _web_targets(ctx):
        scheme = "https" if port in (443, 8443) else "http"
        out.append(f"{scheme}://{host}:{port}")
    return out


class VulnPhase(Phase):
    name = "vuln"
    number = 3
    description = "Vulnerability assessment: nuclei templates, gated sqlmap"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        result.tools_available = {
            "nuclei": ctx.runner.available("nuclei"),
            "sqlmap": ctx.runner.available("sqlmap"),
        }
        urls = _urls(ctx)
        if not urls:
            result.notes.append("No web URLs to assess.")
            return

        if result.tools_available["nuclei"]:
            self._nuclei(ctx, result, urls)
        else:
            result.notes.append("nuclei not installed: skipping template scan (no fabrication).")

        self._sqlmap(ctx, result, urls)

    # --- nuclei ---
    def _nuclei(self, ctx: PhaseContext, result: PhaseResult, urls: list[str]) -> None:
        cmd = ["nuclei", "-jsonl", "-silent", "-no-color"]
        for u in urls:
            cmd += ["-u", u]
        if ctx.safe_mode:
            # exclude intrusive/dos template categories in safe mode
            cmd += ["-etags", "dos,intrusive,fuzz"]
        ev = ctx.runner.run(cmd, tool="nuclei", timeout=900)
        count = 0
        for line in ev.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info", {}) or {}
            sev = _NUCLEI_SEV.get(str(info.get("severity", "info")).lower(), Severity.INFO)
            tid = obj.get("template-id") or obj.get("templateID") or "nuclei"
            matched = obj.get("matched-at") or obj.get("matched_at") or obj.get("host") or ""
            name = info.get("name", tid)
            refs = info.get("reference") or []
            if isinstance(refs, str):
                refs = [refs]
            from ..cvss import from_nuclei_info
            meta = {"template_id": tid, "nuclei_severity": info.get("severity")}
            cvss = from_nuclei_info(info)
            if cvss:
                meta["cvss"] = cvss
            result.findings.append(Finding(
                title=f"{name} [{tid}]", severity=sev,
                description=(info.get("description") or f"nuclei template {tid} matched.").strip(),
                evidence_ids=[ev.id], target=ctx.target, phase=self.name,
                location=matched, references=list(refs), metadata=meta,
            ))
            count += 1
        if count == 0 and ev.returncode not in (0,):
            result.notes.append(f"nuclei exited {ev.returncode}: {ev.stderr[:200]}")
        else:
            result.notes.append(f"nuclei reported {count} match(es).")

    # --- sqlmap (gated) ---
    def _sqlmap(self, ctx: PhaseContext, result: PhaseResult, urls: list[str]) -> None:
        target_url = ctx.options.get("sqlmap_url")
        if not result.tools_available["sqlmap"]:
            if target_url or not ctx.safe_mode:
                result.notes.append("sqlmap requested but not installed.")
            return
        # Gating: only run if explicitly targeted, or safe mode is off.
        if not target_url and ctx.safe_mode:
            result.notes.append(
                "sqlmap skipped (safe mode). Provide an injectable URL or use --no-safe-mode to enable.")
            return
        candidates = [target_url] if target_url else urls
        for u in candidates:
            cmd = ["sqlmap", "-u", u, "--batch", "--level", "1", "--risk", "1",
                   "--disable-coloring", "--flush-session"]
            ev = ctx.runner.run(cmd, tool="sqlmap", timeout=600)
            out = ev.stdout.lower()
            if "is vulnerable" in out or "identified the following injection point" in out:
                result.findings.append(Finding(
                    title="SQL injection confirmed by sqlmap", severity=Severity.CRITICAL,
                    description=f"sqlmap confirmed an injectable parameter at {u}.",
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=u,
                    recommendation="Use parameterized queries / an ORM; validate and bind all inputs.",
                ))
            else:
                result.notes.append(f"sqlmap: no injection confirmed at {u}.")
