# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import unittest

from sentari.agent.tools import ToolDispatcher
from sentari.runner import ToolRunner


def _disp(safe_mode=True):
    runner = ToolRunner(default_timeout=5)
    return ToolDispatcher(runner, "127.0.0.1", safe_mode), runner


class TestAgentTools(unittest.TestCase):
    def test_record_finding_requires_real_evidence(self):
        disp, runner = _disp()
        # no evidence yet -> record_finding must refuse
        msg = disp.dispatch("record_finding", {"evidence_id": "nope", "title": "SQLi",
                                               "severity": "critical", "description": "x"})
        self.assertIn("error", msg)
        self.assertEqual(len(disp.findings), 0)

    def test_record_finding_with_valid_evidence(self):
        disp, runner = _disp()
        ev = runner.record_internal(["http-get", "http://x/"], 0, "HTTP 200\nserver: nginx")
        msg = disp.dispatch("record_finding", {"evidence_id": ev.id, "title": "Missing CSP",
                                               "severity": "medium", "description": "no CSP"})
        self.assertIn("recorded finding", msg)
        self.assertEqual(len(disp.findings), 1)
        self.assertEqual(disp.findings[0].evidence_ids, [ev.id])
        self.assertEqual(disp.findings[0].metadata["authored_by"], "agent")

    def test_record_finding_needs_title(self):
        disp, runner = _disp()
        ev = runner.record_internal(["http-get", "http://x/"], 0, "HTTP 200")
        msg = disp.dispatch("record_finding", {"evidence_id": ev.id, "severity": "low"})
        self.assertIn("error", msg)
        self.assertEqual(len(disp.findings), 0)

    def test_unknown_tool_is_safe(self):
        disp, _ = _disp()
        self.assertIn("unknown tool", disp.dispatch("rm_rf_slash", {}))

    def test_sqlmap_gated_in_safe_mode(self):
        disp, _ = _disp(safe_mode=True)
        self.assertIn("safe mode", disp.dispatch("run_sqlmap", {"path": "/x"}))


if __name__ == "__main__":
    unittest.main()
