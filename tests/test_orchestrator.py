# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import unittest

from sentari import events, orchestrator, threatmodel


class TestOrchestrator(unittest.TestCase):
    def _capture(self):
        bus = events.EventBus()
        seen = {"agent": [], "todo": [], "plan": 0}

        def cap(ev):
            if ev.kind == "agent":
                seen["agent"].append((ev.source, ev.data.get("status")))
            elif ev.kind == "todo":
                seen["todo"].append(ev.data.get("items"))
            elif ev.kind == "plan":
                seen["plan"] += 1
        bus.subscribe(cap)
        return bus, seen

    def test_plan_and_agents_spawned_on_attach(self):
        bus, seen = self._capture()
        orchestrator.attach(bus, "https://x")
        self.assertEqual(seen["plan"], 1)
        # Root Agent + every assessor is announced
        names = {s for s, _ in seen["agent"]}
        self.assertIn("Root Agent", names)
        self.assertTrue({a["name"] for a in threatmodel.ASSESSORS} <= names)
        self.assertTrue(seen["todo"])  # an initial todo list was emitted

    def test_phase_events_drive_assessor_status(self):
        bus, seen = self._capture()
        orchestrator.attach(bus, "https://x")
        bus.emit(events.Event("phase_start", "recon", ""))
        bus.emit(events.Event("phase_start", "scanning", ""))
        bus.emit(events.Event("phase_done", "scanning", "", {"findings": 2}))
        statuses = [st for s, st in seen["agent"] if s == "Recon & Perimeter Mapper"]
        self.assertIn("running", statuses)
        self.assertIn("done", statuses)   # done when its last phase (scanning) finishes

    def test_run_done_completes_root_and_todos(self):
        bus, seen = self._capture()
        orchestrator.attach(bus, "https://x")
        bus.emit(events.Event("phase_start", "vuln", ""))
        bus.emit(events.Event("run_done", "engine", ""))
        self.assertIn(("Root Agent", "done"), seen["agent"])
        # the vuln assessor that started is marked done at run_done
        self.assertIn(("Known-Vulnerability Assessor", "done"), seen["agent"])
        # final todo snapshot has no 'running' left
        last = seen["todo"][-1]
        self.assertTrue(all(t["status"] in ("pending", "done") for t in last))

    def test_run_llm_dispatches_reasoning_subagents(self):
        import pathlib
        import tempfile
        from sentari.authorization import AuditLog, Scope

        class FakeProvider:
            name = "fake"

            def available(self):
                return (True, "")

            def supports_tools(self):
                return False

            def complete(self, system, user, max_tokens=350):
                return "Plan: recon first, then the specialized assessors."

        bus, seen = self._capture()
        thinking = []
        bus.subscribe(lambda ev: thinking.append(ev.source) if ev.kind == "thinking" else None)
        events.set_current(bus)
        try:
            audit = AuditLog(pathlib.Path(tempfile.mktemp()))
            ar = orchestrator.run_llm("http://127.0.0.1:9", Scope.from_items(["127.0.0.1"]),
                                      True, audit, FakeProvider(), options={}, max_steps=1)
        finally:
            events.set_current(None)
        self.assertIn("Root Agent", thinking)          # real root plan emitted as thinking
        spawned = [s for s, _ in seen["agent"] if s != "Root Agent"]
        self.assertIn("Recon & Perimeter Mapper", spawned)
        self.assertEqual(len(ar.results), 6)           # one result per dispatched sub-agent
        self.assertIn(("Root Agent", "done"), seen["agent"])

    def test_assessor_for_phase(self):
        self.assertEqual(threatmodel.assessor_for_phase("injection")["name"],
                         "Injection Assessor")
        self.assertIsNone(threatmodel.assessor_for_phase("nonexistent"))


if __name__ == "__main__":
    unittest.main()
