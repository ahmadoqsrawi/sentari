# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import unittest

from sentari.models import Finding, Severity
from sentari.retest import compare, findings_from_payload


def _f(title, loc):
    return Finding(title=title, severity=Severity.MEDIUM, description="d",
                   evidence_ids=["e1"], target="t", phase="scanning", location=loc)


class TestRetest(unittest.TestCase):
    def test_compare(self):
        baseline = [
            {"phase": "scanning", "title": "Missing header: x", "location": "u"},
            {"phase": "scanning", "title": "Sensitive path: /.git", "location": "u/.git"},
        ]
        current = [_f("Missing header: x", "u"), _f("New issue", "u")]
        rr = compare(baseline, current)
        self.assertEqual(len(rr.fixed), 1)          # /.git gone
        self.assertEqual(len(rr.still_present), 1)   # missing header remains
        self.assertEqual(len(rr.new), 1)            # new issue

    def test_findings_from_payload_shapes(self):
        payload = {"results": [{"findings": [{"title": "a"}]}]}
        self.assertEqual(len(findings_from_payload(payload)), 1)
        self.assertEqual(len(findings_from_payload([{"findings": [{"title": "a"}]}])), 1)


if __name__ == "__main__":
    unittest.main()
