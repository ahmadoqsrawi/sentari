# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import unittest

from sentari.cvss import compute_base_score, severity_from_score, from_nuclei_info
from sentari.models import Finding, PhaseResult, Severity
from sentari.reporting.xml import render_xml


class TestCVSS(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(compute_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(severity_from_score(9.8), "critical")
        low = compute_base_score("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
        self.assertLess(low, 4.0)

    def test_bad_vector_is_none(self):
        self.assertIsNone(compute_base_score("garbage"))

    def test_from_nuclei_info(self):
        info = {"classification": {"cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                   "cve-id": "CVE-2024-1234"}}
        out = from_nuclei_info(info)
        self.assertEqual(out["score"], 9.8)
        self.assertEqual(out["cve"], ["CVE-2024-1234"])


class TestXML(unittest.TestCase):
    def test_render(self):
        f = Finding(title="SQLi", severity=Severity.CRITICAL, description="d",
                    evidence_ids=["e1"], target="x", phase="vuln", location="u",
                    metadata={"cvss": {"score": 9.8, "vector": "V"},
                              "compliance": {"owasp": "A03", "cwe": ["CWE-89"]}})
        pr = PhaseResult(phase="vuln", started_at="t", ended_at="t", findings=[f])
        xml = render_xml([pr], "x")
        self.assertIn("<finding", xml)
        self.assertIn("9.8", xml)
        self.assertIn("CWE-89", xml)


if __name__ == "__main__":
    unittest.main()
