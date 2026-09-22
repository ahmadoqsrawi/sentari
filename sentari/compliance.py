# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Compliance mapping.

Tags each REAL finding with standards references (OWASP Top 10 2021, CWE, and a
NIST 800-53 control where it's a clean fit). This is a deterministic rule engine
over the findings Sentari actually produced: it adds context to real results,
it never creates findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from .models import Finding, PhaseResult


@dataclass
class ComplianceTags:
    owasp: str = ""
    cwe: list[str] = field(default_factory=list)
    nist: str = ""

    def as_dict(self) -> dict:
        return {"owasp": self.owasp, "cwe": self.cwe, "nist": self.nist}

    def label(self) -> str:
        parts = []
        if self.owasp:
            parts.append(f"OWASP {self.owasp}")
        if self.cwe:
            parts.append(", ".join(self.cwe))
        if self.nist:
            parts.append(f"NIST {self.nist}")
        return " | ".join(parts)


# OWASP Top 10 2021 shorthands
A01 = "A01:2021 Broken Access Control"
A02 = "A02:2021 Cryptographic Failures"
A03 = "A03:2021 Injection"
A05 = "A05:2021 Security Misconfiguration"
A06 = "A06:2021 Vulnerable & Outdated Components"

# rule = (predicate, tags). First match wins.
_Rule = tuple[Callable[[Finding], bool], ComplianceTags]


def _title(sub: str) -> Callable[[Finding], bool]:
    s = sub.lower()
    return lambda f: s in f.title.lower()


_RULES: list[_Rule] = [
    (_title("content-security-policy"), ComplianceTags(A05, ["CWE-693", "CWE-1021"], "SC-18")),
    (_title("strict-transport-security"), ComplianceTags(A02, ["CWE-319"], "SC-8")),
    (_title("x-frame-options"), ComplianceTags(A05, ["CWE-1021"], "SC-18")),
    (_title("x-content-type-options"), ComplianceTags(A05, ["CWE-16", "CWE-693"], "CM-6")),
    (_title("referrer-policy"), ComplianceTags(A05, ["CWE-200"], "SC-8")),
    (_title("permissions-policy"), ComplianceTags(A05, ["CWE-693"], "CM-6")),
    (_title("missing header"), ComplianceTags(A05, ["CWE-693"], "CM-6")),
    (_title("version disclosure"), ComplianceTags(A05, ["CWE-200"], "CM-6")),
    (_title("legacy tls"), ComplianceTags(A02, ["CWE-327"], "SC-8")),
    (_title("sql injection"), ComplianceTags(A03, ["CWE-89"], "SI-10")),
    (_title("confirmed exposure"), ComplianceTags(A01, ["CWE-538", "CWE-540"], "AC-3")),
    (_title("sensitive path"), ComplianceTags(A05, ["CWE-538", "CWE-200"], "AC-3")),
]


def map_finding(f: Finding) -> Optional[ComplianceTags]:
    for pred, tags in _RULES:
        if pred(f):
            return tags
    # nuclei findings sometimes carry a CWE in metadata
    md = f.metadata or {}
    cwe = md.get("cwe") or md.get("cwe_id")
    if cwe:
        cwes = cwe if isinstance(cwe, list) else [str(cwe)]
        return ComplianceTags(A06, [c if str(c).startswith("CWE") else f"CWE-{c}" for c in cwes])
    return None


def apply(results: list[PhaseResult]) -> dict[str, int]:
    """Attach compliance tags to each finding's metadata; return an OWASP tally."""
    tally: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            tags = map_finding(f)
            if not tags:
                continue
            f.metadata = {**(f.metadata or {}), "compliance": tags.as_dict()}
            if tags.owasp:
                tally[tags.owasp] = tally.get(tags.owasp, 0) + 1
    return tally
