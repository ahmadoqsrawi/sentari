# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""PDF report export.

Uses reportlab when it is installed. reportlab is an optional dependency, so if
it is missing this returns a clear message instead of failing the run. The PDF
lists findings by severity with their evidence references.
"""
from __future__ import annotations

import importlib

from ..models import PhaseResult, Severity

_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_COLOR = {"critical": "#b3123b", "high": "#d64541", "medium": "#e08a1e",
          "low": "#2f7fbf", "info": "#5b6470"}


def available() -> bool:
    try:
        importlib.import_module("reportlab")
        return True
    except Exception:
        return False


def render_pdf(results: list[PhaseResult], target: str, out_path: str) -> tuple[bool, str]:
    """Write a PDF to out_path. Returns (ok, message)."""
    if not available():
        return False, "reportlab not installed (pip install reportlab); PDF skipped"

    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

    styles = getSampleStyleSheet()
    findings = sorted((f for r in results for f in r.findings),
                      key=lambda x: -x.severity.rank)
    counts = {s.value: sum(1 for f in findings if f.severity == s) for s in _ORDER}

    doc = SimpleDocTemplate(out_path, pagesize=A4, title=f"Sentari report {target}")
    story = [Paragraph("Sentari Assessment Report", styles["Title"]),
             Paragraph(f"Target: {target}", styles["Normal"]),
             Paragraph("Counts: " + ", ".join(f"{k} {v}" for k, v in counts.items()),
                       styles["Normal"]),
             Spacer(1, 6 * mm)]
    for f in findings:
        head = ParagraphStyle("h", parent=styles["Heading4"],
                              textColor=HexColor(_COLOR.get(f.severity.value, "#000000")))
        story.append(Paragraph(f"[{f.severity.value.upper()}] {_esc(f.title)}", head))
        if f.location:
            story.append(Paragraph(f"where: {_esc(f.location)}", styles["Italic"]))
        story.append(Paragraph(_esc(f.description), styles["Normal"]))
        cvss = (f.metadata or {}).get("cvss") or {}
        if cvss.get("score") is not None:
            story.append(Paragraph(f"CVSS: {cvss['score']} {_esc(cvss.get('vector',''))}",
                                   styles["Normal"]))
        story.append(Paragraph("evidence: " + ", ".join(f.evidence_ids), styles["Code"]))
        story.append(Spacer(1, 4 * mm))
    if not findings:
        story.append(Paragraph("No findings.", styles["Normal"]))
    doc.build(story)
    return True, f"PDF written to {out_path}"


def _esc(s) -> str:
    import html
    return html.escape(str(s if s is not None else ""))
