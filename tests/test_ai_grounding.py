import unittest

from sentari.ai.analyst import GroundedAnalyst
from sentari.ai.providers import LLMProvider
from sentari.models import Evidence, Finding, PhaseResult, Severity


class _StubLLM(LLMProvider):
    name = "stub"

    def __init__(self, payload):
        super().__init__(model="stub")
        self._payload = payload

    def available(self):
        return (True, "")

    def complete(self, system, user, max_tokens=1500):
        return self._payload


def _results():
    ev = Evidence(id="ev1", command=["x"], returncode=0, stdout="proof", stderr="",
                  started_at="t", ended_at="t", duration_sec=0.0, tool="x")
    f = Finding(title="Real", severity=Severity.MEDIUM, description="d",
                evidence_ids=["ev1"], target="t", phase="scanning", id="REAL01")
    return [PhaseResult(phase="scanning", started_at="t", ended_at="t",
                        findings=[f], evidence=[ev])]


class TestGrounding(unittest.TestCase):
    def test_invented_references_dropped(self):
        payload = ('{"summary":"s","prioritized":["REAL01","FAKE"],'
                   '"chains":[{"name":"c","finding_ids":["REAL01","FAKE"],"rationale":"r"}],'
                   '"remediation":{"REAL01":"fix","FAKE":"nope"}}')
        a = GroundedAnalyst(_StubLLM(payload)).analyze(_results())
        self.assertEqual(a.prioritized, ["REAL01"])
        self.assertEqual(a.chains[0]["finding_ids"], ["REAL01"])
        self.assertNotIn("FAKE", a.remediation)
        self.assertEqual(a.dropped_references, 3)

    def test_unparseable_output_is_error_not_crash(self):
        a = GroundedAnalyst(_StubLLM("not json at all")).analyze(_results())
        self.assertIsNotNone(a.error)


if __name__ == "__main__":
    unittest.main()
