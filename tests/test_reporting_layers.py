# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import json
import unittest

from sentari import confidence, coverage, threatmodel
from sentari.models import Evidence, Finding, PhaseResult, Severity
from sentari.reporting import narrative, sarif


def _ev():
    return Evidence("e1", ["nuclei"], 0, "out", "", "t", "t", 0.1, "nuclei")


def _results():
    ev = _ev()
    confirmed = Finding("SSRF proof", Severity.HIGH,
                        "injected a URL that called back to our listener, working proof",
                        ["e1"], "t", "injection", location="http://t/p", metadata={})
    scanner = Finding("Postgresql Empty Password", Severity.CRITICAL,
                      "nuclei template matched", ["e1"], "t", "vuln",
                      location="t:5432", metadata={})
    inj = PhaseResult("injection", "t", "t", findings=[confirmed], evidence=[ev])
    vuln = PhaseResult("vuln", "t", "t", findings=[scanner], evidence=[ev])
    return [inj, vuln]


class TestConfidence(unittest.TestCase):
    def test_classify_proof_vs_scanner(self):
        res = _results()
        confidence.apply(res)
        f_conf = res[0].findings[0]
        f_rep = res[1].findings[0]
        self.assertEqual(f_conf.metadata["confidence"], "confirmed")
        self.assertEqual(f_rep.metadata["confidence"], "reported")

    def test_counts_split_by_confidence(self):
        res = _results()
        confidence.apply(res)
        c = confidence.counts(res)
        self.assertEqual(c["confirmed"]["high"], 1)
        self.assertEqual(c["reported"]["critical"], 1)

    def test_explicit_metadata_wins(self):
        f = Finding("x", Severity.LOW, "d", ["e1"], "t", "vuln",
                    metadata={"confidence": "confirmed"})
        self.assertEqual(confidence.classify(f), "confirmed")


class TestCoverage(unittest.TestCase):
    def test_build_surfaces_and_gaps(self):
        res = _results()
        confidence.apply(res)
        cov = coverage.build(res, {"injection": True, "oob_host": "127.0.0.1"})
        self.assertEqual(cov["summary"]["surfaces_reviewed"], 2)
        # phases not run become gaps, plus the authenticated + localhost-OOB gaps
        self.assertGreater(cov["summary"]["gaps"], 0)
        surfaces = {s["phase"]: s["outcome"] for s in cov["surfaces"]}
        self.assertEqual(surfaces["injection"], coverage.ISSUE)         # confirmed
        self.assertEqual(surfaces["vuln"], coverage.NEEDS_FOLLOW_UP)    # reported only

    def test_agent_mode_single_surface(self):
        res = [PhaseResult("agent", "t", "t", findings=[], evidence=[])]
        cov = coverage.build(res, {}, agent_mode=True)
        self.assertEqual(cov["surfaces"][0]["phase"], "agent")


class TestSarif(unittest.TestCase):
    def test_valid_sarif_structure(self):
        res = _results()
        confidence.apply(res)
        doc = json.loads(sarif.render_sarif(res, "t"))
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(len(run["results"]), 2)
        levels = {r["level"] for r in run["results"]}
        self.assertIn("error", levels)  # high/critical -> error
        confs = {r["properties"]["confidence"] for r in run["results"]}
        self.assertEqual(confs, {"confirmed", "reported"})


class TestNarrative(unittest.TestCase):
    def test_markdown_has_sections_and_is_grounded(self):
        res = _results()
        confidence.apply(res)
        cov = coverage.build(res, {"injection": True})
        md = narrative.render_markdown(res, "t", cov)
        for section in ("Executive summary", "Methodology", "Recommendations",
                        "Coverage gaps"):
            self.assertIn(section, md)
        self.assertIn("SSRF proof", md)          # confirmed finding surfaced
        self.assertIn("confirmed", md.lower())


class TestThreatModel(unittest.TestCase):
    def test_attribute_maps_phases_to_assessors(self):
        res = _results()
        confidence.apply(res)
        tm = threatmodel.attribute(res, {"injection": True})
        names = {a["name"]: a for a in tm["assessors"]}
        self.assertEqual(names["Injection Assessor"]["confirmed"], 1)
        self.assertEqual(names["Known-Vulnerability Assessor"]["reported"], 1)
        # authorization assessor has no identities -> gap
        self.assertTrue(any(g["assessor"] == "Authorization Assessor" for g in tm["gaps"]))

    def test_enabled_options_and_phases(self):
        opts = threatmodel.enabled_options({})
        self.assertTrue(opts["injection"] and opts["framework"] and opts["api_tests"])
        self.assertIn("framework", threatmodel.all_phases())


if __name__ == "__main__":
    unittest.main()
