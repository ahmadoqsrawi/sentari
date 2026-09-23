# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import tempfile
import unittest

from sentari import runstate
from sentari.models import Evidence, Finding, PhaseResult, Severity


def _phase():
    ev = Evidence("e1", ["nmap", "-sV"], 0, "out", "", "t", "t", 0.5, "nmap")
    f = Finding("Open port", Severity.MEDIUM, "port 22 open", ["e1"], "t", "recon",
                location="t:22", metadata={"confidence": "reported"})
    return PhaseResult("recon", "t", "t", findings=[f], evidence=[ev],
                       tools_available={"nmap": True}, notes=["ran nmap"])


class TestModelRoundtrip(unittest.TestCase):
    def test_phase_result_roundtrip(self):
        pr = _phase()
        pr2 = PhaseResult.from_dict(pr.to_dict())
        self.assertEqual(pr2.phase, "recon")
        self.assertEqual(len(pr2.findings), 1)
        self.assertEqual(pr2.findings[0].severity, Severity.MEDIUM)
        self.assertEqual(pr2.findings[0].location, "t:22")
        self.assertEqual(pr2.findings[0].metadata["confidence"], "reported")
        self.assertEqual(len(pr2.evidence), 1)
        self.assertEqual(pr2.evidence[0].tool, "nmap")
        self.assertEqual(pr2.tools_available, {"nmap": True})

    def test_finding_from_dict_ignores_unknown_keys(self):
        d = {**{"title": "x", "severity": "low", "description": "d",
                "evidence_ids": ["e1"], "target": "t", "phase": "vuln"},
             "extra_key": "ignored"}
        f = Finding.from_dict(d)
        self.assertEqual(f.title, "x")


class TestRunState(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_save_load_roundtrip(self):
        payload = {"results": [_phase().to_dict()]}
        runstate.save("myrun", payload, self.dir)
        loaded = runstate.load("myrun", self.dir)
        self.assertEqual(len(loaded["results"]), 1)
        pr = PhaseResult.from_dict(loaded["results"][0])
        self.assertEqual(pr.phase, "recon")

    def test_load_missing_returns_none(self):
        self.assertIsNone(runstate.load("nope", self.dir))

    def test_name_is_slugified(self):
        runstate.save("a/b c:d", {"results": []}, self.dir)
        # a sanitized directory is created and reloadable under the same name
        self.assertIsNotNone(runstate.load("a/b c:d", self.dir))

    def test_clear(self):
        runstate.save("r", {"results": []}, self.dir)
        runstate.clear("r", self.dir)
        self.assertIsNone(runstate.load("r", self.dir))


if __name__ == "__main__":
    unittest.main()
