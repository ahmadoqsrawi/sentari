# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import unittest

from sentari.compliance import apply, map_finding
from sentari.models import Finding, PhaseResult, Severity


def _f(title):
    return Finding(title=title, severity=Severity.MEDIUM, description="d",
                   evidence_ids=["e1"], target="t", phase="scanning", location="u")


class TestCompliance(unittest.TestCase):
    def test_header_maps_to_owasp_a05(self):
        tags = map_finding(_f("Missing header: content-security-policy"))
        self.assertIsNotNone(tags)
        self.assertTrue(tags.owasp.startswith("A05"))
        self.assertIn("CWE-693", tags.cwe)

    def test_sqli_maps_to_a03(self):
        tags = map_finding(_f("SQL injection confirmed by sqlmap"))
        self.assertTrue(tags.owasp.startswith("A03"))
        self.assertIn("CWE-89", tags.cwe)

    def test_apply_attaches_metadata_and_tallies(self):
        pr = PhaseResult(phase="scanning", started_at="t", ended_at="t",
                         findings=[_f("Missing header: x-frame-options")])
        tally = apply([pr])
        self.assertIn("compliance", pr.findings[0].metadata)
        self.assertTrue(any(k.startswith("A05") for k in tally))


if __name__ == "__main__":
    unittest.main()
