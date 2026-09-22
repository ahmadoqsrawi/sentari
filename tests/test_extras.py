import unittest

from sentari import anomaly, metrics
from sentari.ai.catalog import list_models
from sentari.models import Evidence, Finding, PhaseResult, Severity
from sentari.siem.exporters import _events


def _ev(eid, stdout=""):
    return Evidence(id=eid, command=["x"], returncode=0, stdout=stdout, stderr="",
                    started_at="t", ended_at="t", duration_sec=0.0, tool="x")


def _f(title, eid, sev=Severity.LOW, meta=None):
    return Finding(title=title, severity=sev, description="d", evidence_ids=[eid],
                   target="t", phase="scanning", location="u", metadata=meta or {})


class TestSiemEvents(unittest.TestCase):
    def test_events_shape(self):
        payload = {"results": [{"findings": [
            {"severity": "high", "title": "a", "phase": "scanning", "location": "u"},
            {"severity": "low", "title": "b", "phase": "scanning", "location": "u"},
        ]}]}
        evs = _events(payload, "example.com")
        self.assertEqual(len(evs), 3)  # 2 findings + 1 summary
        self.assertEqual(evs[-1]["type"], "summary")
        self.assertEqual(evs[-1]["counts"], {"high": 1, "low": 1})


class TestMetrics(unittest.TestCase):
    def test_render(self):
        runs = {"r1": {"results": [{"findings": [
            {"severity": "high"}, {"severity": "low"}]}]}}
        out = metrics.render_metrics(runs)
        self.assertIn("sentari_scans_total 1", out)
        self.assertIn('sentari_findings_total{severity="high"} 1', out)
        self.assertIn("sentari_findings_all 2", out)


class TestCatalog(unittest.TestCase):
    def test_has_providers(self):
        m = list_models()
        self.assertIn("openai", m)
        self.assertTrue(all(isinstance(v, list) and v for v in m.values()))


class TestAnomaly(unittest.TestCase):
    def test_flags_large_response_outlier(self):
        ev = [_ev("e1", "x"), _ev("e2", "x"), _ev("e3", "x"),
              _ev("e4", "x"), _ev("big", "A" * 5000)]
        findings = [_f("a", "e1"), _f("b", "e2"), _f("c", "e3"),
                    _f("d", "e4"), _f("huge", "big")]
        pr = PhaseResult(phase="scanning", started_at="t", ended_at="t",
                         findings=findings, evidence=ev)
        flagged = anomaly.apply([pr])
        self.assertGreaterEqual(flagged, 1)
        self.assertIn("anomaly", findings[-1].metadata)

    def test_no_findings_no_error(self):
        pr = PhaseResult(phase="scanning", started_at="t", ended_at="t")
        self.assertEqual(anomaly.apply([pr]), 0)


if __name__ == "__main__":
    unittest.main()
