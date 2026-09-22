"""Human-readable console report. Every finding is printed with the evidence
id(s) that back it, so the report is auditable against the raw command output."""
from __future__ import annotations

from ..models import PhaseResult, Severity

_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_LABEL = {
    Severity.CRITICAL: "CRIT", Severity.HIGH: "HIGH", Severity.MEDIUM: "MED ",
    Severity.LOW: "LOW ", Severity.INFO: "INFO",
}


def render(results: list[PhaseResult]) -> str:
    lines: list[str] = []
    all_findings = [f for r in results for f in r.findings]
    all_evidence = {e.id: e for r in results for e in r.evidence}

    lines.append("=" * 70)
    lines.append("SENTARI ASSESSMENT REPORT")
    lines.append("=" * 70)

    for r in results:
        lines.append(f"\n── Phase: {r.phase} ──")
        if r.tools_available:
            avail = ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in r.tools_available.items())
            lines.append(f"   tools: {avail}")
        for note in r.notes:
            lines.append(f"   note: {note}")
        if r.error:
            lines.append(f"   ERROR: {r.error}")
        lines.append(f"   findings: {len(r.findings)} | evidence: {len(r.evidence)}")

    lines.append("\n" + "-" * 70)
    lines.append("FINDINGS (most severe first)")
    lines.append("-" * 70)
    if not all_findings:
        lines.append("No findings.")
    for f in sorted(all_findings, key=lambda x: -x.severity.rank):
        lines.append(f"\n[{_LABEL[f.severity]}] {f.title}")
        if f.location:
            lines.append(f"        where: {f.location}")
        lines.append(f"        {f.description}")
        if f.recommendation:
            lines.append(f"        fix: {f.recommendation}")
        comp = (f.metadata or {}).get("compliance")
        if comp:
            tag = " | ".join(x for x in [
                f"OWASP {comp['owasp']}" if comp.get("owasp") else "",
                ", ".join(comp.get("cwe", [])),
                f"NIST {comp['nist']}" if comp.get("nist") else "",
            ] if x)
            if tag:
                lines.append(f"        compliance: {tag}")
        lines.append(f"        evidence: {', '.join(f.evidence_ids)}")

    lines.append("\n" + "-" * 70)
    lines.append("EVIDENCE (ground truth)")
    lines.append("-" * 70)
    for eid, ev in all_evidence.items():
        lines.append(f"  {eid}  {ev.summary()}")

    return "\n".join(lines)
