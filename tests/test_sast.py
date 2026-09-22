# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import json
import unittest

from sentari.sast import SEV_MAP, parse_semgrep


class TestParseSemgrep(unittest.TestCase):
    def test_parses_results(self):
        s = json.dumps({"results": [
            {"check_id": "rule.exec", "path": "a.py", "start": {"line": 42},
             "extra": {"severity": "ERROR", "message": "Detected exec.",
                       "metadata": {"cwe": ["CWE-95"], "owasp": ["A03:2021"]}}}]})
        rows = parse_semgrep(s)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(rows[0]["line"], 42)
        self.assertEqual(rows[0]["cwe"], ["CWE-95"])
        self.assertEqual(rows[0]["owasp"], ["A03:2021"])

    def test_severity_map(self):
        self.assertEqual(SEV_MAP["ERROR"], "high")
        self.assertEqual(SEV_MAP["WARNING"], "medium")
        self.assertEqual(SEV_MAP["INFO"], "low")

    def test_string_cwe_normalized_to_list(self):
        s = json.dumps({"results": [
            {"check_id": "r", "path": "a", "start": {"line": 1},
             "extra": {"severity": "WARNING", "metadata": {"cwe": "CWE-79"}}}]})
        self.assertEqual(parse_semgrep(s)[0]["cwe"], ["CWE-79"])

    def test_bad_json_is_empty(self):
        self.assertEqual(parse_semgrep("not json"), [])

    def test_empty_results(self):
        self.assertEqual(parse_semgrep(json.dumps({"results": []})), [])


class TestSASTPhase(unittest.TestCase):
    def test_noop_without_path(self):
        from sentari.phases.base import PhaseContext
        from sentari.phases.sast import SASTPhase
        from sentari.runner import ToolRunner
        ctx = PhaseContext(target="x", runner=ToolRunner(5), options={})
        self.assertEqual(len(SASTPhase().run(ctx).findings), 0)

    def test_graceful_without_semgrep(self):
        from sentari.phases.base import PhaseContext
        from sentari.phases.sast import SASTPhase
        from sentari.runner import ToolRunner
        r = ToolRunner(5)
        if r.available("semgrep"):
            self.skipTest("semgrep installed here")
        ctx = PhaseContext(target="x", runner=r, options={"sast_path": "."})
        res = SASTPhase().run(ctx)
        self.assertEqual(len(res.findings), 0)
        self.assertTrue(any("semgrep not installed" in n for n in res.notes))


if __name__ == "__main__":
    unittest.main()
