# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from sentari.ai import providers
from sentari.cli import _completions, _shape_run_args, build_parser


def _parse(argv):
    return build_parser().parse_args(argv)


class TestScanShaping(unittest.TestCase):
    def test_mode_quick_limits_phases(self):
        args = _parse(["t", "-m", "quick"])
        self.assertIsNone(_shape_run_args(args))
        self.assertEqual(args.phases, "osint,recon,scanning")

    def test_mode_standard_enables_api(self):
        args = _parse(["t", "-m", "standard"])
        _shape_run_args(args)
        self.assertIn("vuln", args.phases)
        self.assertTrue(args.api_tests)

    def test_mode_deep_enables_bundle(self):
        args = _parse(["t", "-m", "deep"])
        _shape_run_args(args)
        self.assertTrue(args.injection and args.framework and args.browser)

    def test_mode_does_not_override_explicit_phases(self):
        args = _parse(["t", "-m", "quick", "--phases", "recon"])
        _shape_run_args(args)
        self.assertEqual(args.phases, "recon")

    def test_instruction_sets_goal(self):
        args = _parse(["t", "--instruction", "focus on IDOR"])
        _shape_run_args(args)
        self.assertEqual(args.goal, "focus on IDOR")

    def test_instruction_file_read(self):
        fd, path = tempfile.mkstemp()
        os.write(fd, b"look at the admin panel")
        os.close(fd)
        self.addCleanup(os.remove, path)
        args = _parse(["t", "--instruction-file", path])
        _shape_run_args(args)
        self.assertEqual(args.goal, "look at the admin panel")

    def test_target_list_enables_graph(self):
        fd, path = tempfile.mkstemp()
        os.write(fd, b"a.example.com\n# comment\nb.example.com\n")
        os.close(fd)
        self.addCleanup(os.remove, path)
        args = _parse(["--target-list", path])
        _shape_run_args(args)
        self.assertTrue(args.graph)
        self.assertEqual(args.target, "a.example.com")
        self.assertIn("b.example.com", args.graph_target)


class TestBudget(unittest.TestCase):
    class _Resp:
        class usage:
            prompt_tokens = 1_000_000
            completion_tokens = 1_000_000

    def test_spend_accumulates_and_resets(self):
        providers.reset_spend()
        providers._emit_usage("gpt-4o", self._Resp())
        self.assertGreater(providers.spent_cost(), 0)
        self.assertEqual(providers.spent_tokens(), 2_000_000)
        providers.reset_spend()
        self.assertEqual(providers.spent_cost(), 0.0)

    def test_unknown_model_has_tokens_but_no_cost(self):
        providers.reset_spend()
        providers._emit_usage("some-unlisted-model", self._Resp())
        self.assertEqual(providers.spent_cost(), 0.0)
        self.assertEqual(providers.spent_tokens(), 2_000_000)


class TestCompletions(unittest.TestCase):
    def test_bash_completion_lists_flags(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            _completions(["bash"])
        out = buf.getvalue()
        self.assertIn("complete -F _sentari sentari", out)
        self.assertIn("--web-pentest", out)
        self.assertIn("wizard", out)

    def test_zsh_completion(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            _completions(["zsh"])
        self.assertIn("#compdef sentari", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
