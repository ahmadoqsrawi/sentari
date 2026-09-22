import unittest

from sentari.models import Evidence, Finding, PhaseResult, Severity


def _ev():
    return Evidence(id="e1", command=["x"], returncode=0, stdout="o", stderr="",
                    started_at="t", ended_at="t", duration_sec=0.0, tool="x")


class TestModels(unittest.TestCase):
    def test_finding_requires_evidence(self):
        with self.assertRaises(ValueError):
            Finding(title="x", severity=Severity.LOW, description="d",
                    evidence_ids=[], target="t", phase="p")

    def test_finding_with_evidence_ok(self):
        f = Finding(title="x", severity=Severity.HIGH, description="d",
                    evidence_ids=["e1"], target="t", phase="p")
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertTrue(f.id)

    def test_severity_rank_order(self):
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        self.assertEqual([s.rank for s in order], [0, 1, 2, 3, 4])

    def test_phaseresult_to_dict_serializes_severity(self):
        f = Finding(title="x", severity=Severity.MEDIUM, description="d",
                    evidence_ids=["e1"], target="t", phase="p")
        pr = PhaseResult(phase="p", started_at="t", ended_at="t", findings=[f], evidence=[_ev()])
        d = pr.to_dict()
        self.assertEqual(d["findings"][0]["severity"], "medium")


if __name__ == "__main__":
    unittest.main()
