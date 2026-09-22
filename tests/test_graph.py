# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import tempfile
import unittest
from pathlib import Path

from sentari import graph
from sentari.authorization import AuditLog, Scope
from sentari.phases import PHASES


class TestGraph(unittest.TestCase):
    def _audit(self):
        d = tempfile.mkdtemp()
        return AuditLog(Path(d) / "audit.log")

    def test_nodes_reference_real_phases(self):
        names = {p.name for p in PHASES}
        for _node, phases in graph.NODES:
            for p in phases:
                self.assertIn(p, names, f"node phase {p} not registered")

    def test_unauthorized_targets_error_gracefully(self):
        # authorization fails before any network work, so this is offline & fast.
        graphs, correlated, coordination = graph.run_graph_targets(
            ["example.com", "example.org"], Scope.from_items([]), False, self._audit(),
            timeout=2)
        self.assertEqual(len(graphs), 2)
        self.assertTrue(all(g.error for g in graphs))
        self.assertEqual(correlated, [])
        self.assertIsNone(coordination)  # no provider given

    def test_results_sorted_by_target(self):
        graphs, _, _ = graph.run_graph_targets(
            ["b.example", "a.example"], Scope.from_items([]), False, self._audit(), timeout=2)
        self.assertEqual([g.target for g in graphs], ["a.example", "b.example"])


if __name__ == "__main__":
    unittest.main()
