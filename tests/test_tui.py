# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from sentari import tui


def _runs():
    return {"run1": {"results": [{
        "findings": [
            {"title": "SQLi", "severity": "critical", "location": "u", "evidence_ids": ["e1"],
             "description": "d", "metadata": {}},
            {"title": "CSP missing", "severity": "medium", "evidence_ids": [], "description": "d"},
            {"title": "port open", "severity": "info", "evidence_ids": [], "description": "d"}],
        "evidence": [{"id": "e1", "command": ["nuclei"], "returncode": 0, "stdout": "hit"}]}]}}


class TestTui(unittest.TestCase):
    def test_flatten_sorts_by_severity_and_maps_evidence(self):
        findings, evmap = tui._flatten(_runs())
        self.assertEqual([f["severity"] for f in findings], ["critical", "medium", "info"])
        self.assertIn("e1", evmap)

    def test_counts(self):
        findings, _ = tui._flatten(_runs())
        c = tui._counts(findings)
        self.assertEqual(c["critical"], 1)
        self.assertEqual(c["medium"], 1)

    def test_plain_fallback_renders(self):
        findings, evmap = tui._flatten(_runs())
        buf = io.StringIO()
        with redirect_stdout(buf):
            tui._plain(findings, evmap)
        out = buf.getvalue()
        self.assertIn("SQLi", out)
        self.assertIn("3 finding(s)", out)
        self.assertIn("evidence e1", out)

    def test_load_from_json_file(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.write(fd, json.dumps(_runs()["run1"]).encode())
        os.close(fd)
        self.addCleanup(os.remove, path)
        runs = tui.load(path, None, None)
        self.assertEqual(len(runs), 1)


if __name__ == "__main__":
    unittest.main()
