# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import unittest

from sentari.phases.recon import target_port
from sentari.phases.scanning import _web_targets
from sentari.phases.verify import _SIGNATURES
from sentari.phases.base import PhaseContext
from sentari.runner import ToolRunner


class TestTargetPort(unittest.TestCase):
    def test_parsing(self):
        self.assertEqual(target_port("http://127.0.0.1:3200"), 3200)
        self.assertEqual(target_port("127.0.0.1:3001"), 3001)
        self.assertEqual(target_port("https://example.com"), 443)
        self.assertEqual(target_port("http://example.com"), 80)
        self.assertIsNone(target_port("example.com"))


class TestWebTargets(unittest.TestCase):
    def _ctx(self, target, open_ports):
        ctx = PhaseContext(target=target, runner=ToolRunner())
        ctx.shared["open_ports"] = open_ports
        return ctx

    def test_explicit_port_always_scanned(self):
        # recon found :3001, but the target is :3200 -> both must be scanned
        ctx = self._ctx("http://127.0.0.1:3200", [3001])
        ports = {p for _, p in _web_targets(ctx)}
        self.assertIn(3200, ports)

    def test_bare_hostport_honored(self):
        ctx = self._ctx("127.0.0.1:3200", [])
        self.assertEqual({p for _, p in _web_targets(ctx)}, {3200})

    def test_default_when_nothing(self):
        ctx = self._ctx("example.com", [])
        self.assertEqual({p for _, p in _web_targets(ctx)}, {80, 443})


class TestSvnSignature(unittest.TestCase):
    def test_svn_not_confirmed_on_html(self):
        rx = [s[1] for s in _SIGNATURES if s[0] == "/.svn/entries"][0]
        self.assertIsNone(rx.search("<!doctype html><html>catch-all page</html>"))
        self.assertIsNotNone(rx.search("12\n"))   # a real entries format line


if __name__ == "__main__":
    unittest.main()
