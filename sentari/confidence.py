# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Confidence: separate proven findings from scanner-reported candidates.

Sentari's rule is evidence-first, but "has evidence" is not the same as "proven
exploitable". A nuclei template match or a probe that saw an HTTP 200 is real
evidence that *something responded*, yet the vulnerability itself is unverified
until a real effect is observed (an out-of-band callback, payload execution, a
content match). Reporting an unverified template match as CRITICAL is what
produces scary false positives, so every finding is tagged:

  * confirmed - a real effect was observed (OOB callback, browser execution,
    SSTI evaluation, a content match in verification, a PoC success marker).
  * reported  - a scanner/probe flagged it but no effect was confirmed. Real,
    but a candidate that needs verification, not a proven vulnerability.

The tag drives ordering and how the report counts severity, so "confirmed" leads
and unverified candidates never dominate the headline.
"""
from __future__ import annotations

from .models import Finding, PhaseResult, Severity

CONFIRMED = "confirmed"
REPORTED = "reported"

# Phrases a proving phase leaves in a finding's description/title when a real
# effect was observed. Used as a fallback when a phase did not tag explicitly.
_PROOF_PHRASES = (
    "working proof", "working ssrf proof", "working xxe proof",
    "working command-injection proof", "call back to our listener",
    "executed", "evaluated", "confirmed by", "proof of impact",
)


def classify(f: Finding) -> str:
    """Return the confidence tag for a finding."""
    md = f.metadata or {}
    if md.get("confidence") in (CONFIRMED, REPORTED):
        return md["confidence"]
    if md.get("confirmed") is True:
        return CONFIRMED
    text = f"{f.title} {f.description}".lower()
    if any(p in text for p in _PROOF_PHRASES):
        return CONFIRMED
    return REPORTED


def apply(results: list[PhaseResult]) -> None:
    """Tag every finding with metadata['confidence'] in place."""
    for r in results:
        for f in r.findings:
            f.metadata = f.metadata or {}
            f.metadata.setdefault("confidence", classify(f))


def counts(results: list[PhaseResult]) -> dict:
    """Severity counts split by confidence, for the report headline."""
    out = {CONFIRMED: {}, REPORTED: {}}
    for r in results:
        for f in r.findings:
            conf = (f.metadata or {}).get("confidence") or classify(f)
            sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
            out[conf][sev] = out[conf].get(sev, 0) + 1
    return out


def summary_line(results: list[PhaseResult]) -> str:
    c = counts(results)
    n_conf = sum(c[CONFIRMED].values())
    n_rep = sum(c[REPORTED].values())

    def _fmt(d):
        order = ["critical", "high", "medium", "low", "info"]
        return ", ".join(f"{d[s]} {s}" for s in order if d.get(s)) or "none"

    return (f"confirmed: {n_conf} ({_fmt(c[CONFIRMED])}) | "
            f"reported/unverified: {n_rep} ({_fmt(c[REPORTED])})")
