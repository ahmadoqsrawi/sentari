# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import unittest

from sentari import events
from sentari.livetui import _Monitor


class TestEvents(unittest.TestCase):
    def test_emit_is_noop_without_bus(self):
        events.set_current(None)
        events.emit("tool", "x", "y")  # must not raise

    def test_bus_delivers_to_subscribers(self):
        bus = events.EventBus()
        got = []
        bus.subscribe(got.append)
        bus.emit(events.Event("phase_start", "recon", "d"))
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].source, "recon")

    def test_emit_uses_current_bus(self):
        bus = events.EventBus()
        got = []
        bus.subscribe(got.append)
        events.set_current(bus)
        try:
            events.emit("finding", "vuln", "SQLi", severity="high")
        finally:
            events.set_current(None)
        self.assertEqual(got[0].kind, "finding")
        self.assertEqual(got[0].data["severity"], "high")

    def test_subscriber_exception_does_not_break_emit(self):
        bus = events.EventBus()
        bus.subscribe(lambda ev: (_ for _ in ()).throw(RuntimeError("boom")))
        ok = []
        bus.subscribe(ok.append)
        bus.emit(events.Event("tool", "x"))
        self.assertEqual(len(ok), 1)


class TestCancel(unittest.TestCase):
    def test_should_cancel_reflects_bus(self):
        events.set_current(None)
        self.assertFalse(events.should_cancel())
        bus = events.EventBus()
        events.set_current(bus)
        try:
            self.assertFalse(events.should_cancel())
            bus.cancel.set()
            self.assertTrue(events.should_cancel())
        finally:
            events.set_current(None)

    def test_engine_stops_when_cancelled(self):
        import pathlib
        import tempfile
        from sentari.authorization import AuditLog, Scope
        from sentari.engine import run_assessment
        bus = events.EventBus()
        bus.cancel.set()                      # cancel before it starts
        events.set_current(bus)
        try:
            audit = AuditLog(pathlib.Path(tempfile.mktemp()))
            res = run_assessment("127.0.0.1", Scope.from_items(["127.0.0.1"]),
                                 True, audit, phases={"recon", "scanning"})
            self.assertEqual(res, [])          # no phases ran
        finally:
            events.set_current(None)

    def test_runner_reports_timeout(self):
        from sentari.runner import ToolRunner
        ev = ToolRunner(10).run(["sleep", "5"], tool="sleep", timeout=1)
        self.assertEqual(ev.returncode, 124)
        self.assertIn("timeout", ev.stderr)


class TestMonitor(unittest.TestCase):
    def _mon(self):
        return _Monitor({"target": "t", "mode": "scan", "model": ""})

    def test_counts_requests_findings_tokens_cost(self):
        m = self._mon()
        m.on_event(events.Event("tool", "builtin", "http-get"))
        m.on_event(events.Event("tool", "nuclei", "run"))
        m.on_event(events.Event("finding", "vuln", "x", {"severity": "low"}))
        m.on_event(events.Event("usage", "gpt-5", "+100 tok",
                                {"total": 100, "cost": 0.01}))
        self.assertEqual(m.requests, 2)
        self.assertEqual(m.findings, 1)
        self.assertEqual(m.tokens, 100)
        self.assertAlmostEqual(m.cost, 0.01)
        self.assertEqual(m.model, "gpt-5")

    def test_roster_status_transitions(self):
        m = self._mon()
        m.on_event(events.Event("phase_start", "recon", "d"))
        self.assertEqual(m.roster["recon"]["status"], "running")
        m.on_event(events.Event("phase_done", "recon", "d", {"findings": 3}))
        self.assertEqual(m.roster["recon"]["status"], "done")
        self.assertEqual(m.roster["recon"]["findings"], 3)
        m.on_event(events.Event("phase_start", "vuln", "d"))
        m.on_event(events.Event("phase_done", "vuln", "d", {"error": True}))
        self.assertEqual(m.roster["vuln"]["status"], "failed")

    def test_run_done_marks_done(self):
        m = self._mon()
        m.on_event(events.Event("phase_start", "recon", "d"))
        m.on_event(events.Event("run_done", "engine", ""))
        self.assertTrue(m.done)
        self.assertEqual(m.roster["recon"]["status"], "done")


if __name__ == "__main__":
    unittest.main()
