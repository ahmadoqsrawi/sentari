# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import unittest

from sentari import correlation, prioritize, threatintel, trends
from sentari.classify import classify
from sentari.models import Evidence, Finding, PhaseResult, Severity


def _ev(cmd="probe"):
    return Evidence(id="e1", command=[cmd], returncode=0, stdout="out", stderr="",
                    started_at="t", ended_at="t", duration_sec=0.1, tool=cmd)


def _finding(title="X", sev=Severity.HIGH, target="a.com", meta=None):
    return Finding(title=title, severity=sev, description="d", evidence_ids=["e1"],
                   target=target, phase="vuln", location=target, metadata=meta or {})


def _result(findings):
    r = PhaseResult(phase="vuln", started_at="t", ended_at="t")
    r.evidence.append(_ev())
    r.findings.extend(findings)
    return r


class TestClassify(unittest.TestCase):
    def test_by_port(self):
        self.assertEqual(classify(443), "web")
        self.assertEqual(classify(5432), "database")
        self.assertEqual(classify(22), "remote-access")

    def test_service_name_wins(self):
        self.assertEqual(classify(9999, "nginx http"), "web")
        self.assertEqual(classify(9999, "OpenSSH"), "remote-access")

    def test_unknown(self):
        self.assertEqual(classify(65000), "unknown")
        self.assertEqual(classify(None, None), "unknown")


class TestPrioritize(unittest.TestCase):
    def test_business_impact_scales_with_asset_value(self):
        results = [_result([_finding(meta={"cvss": {"score": 5.0}})])]
        prioritize.apply_business_impact(results, "critical")
        bi = results[0].findings[0].metadata["business_impact"]
        self.assertEqual(bi["asset_value"], "critical")
        self.assertEqual(bi["score"], 9.0)  # 5.0 * 1.8
        self.assertEqual(bi["impact"], "critical")

    def test_business_impact_caps_at_ten(self):
        results = [_result([_finding(meta={"cvss": {"score": 9.0}})])]
        prioritize.apply_business_impact(results, "critical")
        self.assertEqual(results[0].findings[0].metadata["business_impact"]["score"], 10.0)

    def test_risk_known_exploited_is_critical_likelihood(self):
        results = [_result([_finding(sev=Severity.MEDIUM, meta={"known_exploited": True})])]
        prioritize.apply_risk(results)
        self.assertEqual(results[0].findings[0].metadata["risk"]["likelihood"], "critical")

    def test_risk_matrix_renders(self):
        results = [_result([_finding(sev=Severity.HIGH)])]
        prioritize.apply_risk(results)
        out = prioritize.risk_matrix(results)
        self.assertIn("RISK MATRIX", out)

    def test_risk_matrix_empty_when_no_findings(self):
        self.assertEqual(prioritize.risk_matrix([_result([])]), "")


class TestCorrelation(unittest.TestCase):
    def test_same_finding_across_targets(self):
        runs = {
            "r1": {"results": [{"findings": [{"title": "Missing CSP", "severity": "medium",
                                              "target": "a.com"}]}]},
            "r2": {"results": [{"findings": [{"title": "Missing CSP", "severity": "medium",
                                              "target": "b.com"}]}]},
        }
        rows = correlation.correlate(runs)
        self.assertEqual(len(rows), 1)
        self.assertEqual(sorted(rows[0]["targets"]), ["a.com", "b.com"])

    def test_single_target_not_reported(self):
        runs = {"r1": {"results": [{"findings": [{"title": "X", "target": "a.com"}]}]}}
        self.assertEqual(correlation.correlate(runs), [])


class TestTrends(unittest.TestCase):
    def test_rows_count_by_severity(self):
        runs = {"20240101": {"results": [{"findings": [
            {"severity": "high"}, {"severity": "high"}, {"severity": "low"}]}]}}
        rows = trends.trend_rows(runs)
        self.assertEqual(rows[0]["total"], 3)
        self.assertEqual(rows[0]["high"], 2)
        self.assertEqual(rows[0]["low"], 1)

    def test_render_handles_empty(self):
        self.assertIn("No stored runs", trends.render([]))


class TestThreatIntel(unittest.TestCase):
    def test_parse_extracts_cveids(self):
        data = {"vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "cve-2020-0001"}]}
        kev = threatintel._parse(data)
        self.assertIn("CVE-2021-44228", kev)
        self.assertIn("CVE-2020-0001", kev)  # upcased

    def test_apply_tags_known_exploited(self):
        results = [_result([_finding(meta={"cvss": {"score": 9, "cve": ["CVE-2021-44228"]}})])]
        # inject a fake KEV set without hitting the network
        orig = threatintel.load_kev
        threatintel.load_kev = lambda *a, **k: {"CVE-2021-44228"}
        try:
            flagged = threatintel.apply(results)
        finally:
            threatintel.load_kev = orig
        self.assertEqual(flagged, 1)
        self.assertTrue(results[0].findings[0].metadata["known_exploited"])


class TestOpenVASGraceful(unittest.TestCase):
    def test_missing_env_returns_note(self):
        from sentari import openvas
        rows, err = openvas.fetch_results("1.2.3.4")
        self.assertEqual(rows, [])
        self.assertIsNotNone(err)  # either "not installed" or "set GVM_*"


class TestPostExploitGating(unittest.TestCase):
    def test_disabled_in_safe_mode(self):
        from sentari.phases.base import PhaseContext
        from sentari.phases.postexploit import PostExploitPhase
        from sentari.runner import ToolRunner
        ctx = PhaseContext(target="127.0.0.1", runner=ToolRunner(5), safe_mode=True,
                           options={"postexploit": {"username": "u"}})
        result = PostExploitPhase().run(ctx)
        self.assertEqual(len(result.findings), 0)
        self.assertTrue(any("disabled" in n for n in result.notes))


if __name__ == "__main__":
    unittest.main()
