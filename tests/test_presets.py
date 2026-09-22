# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import unittest

from sentari.cli import _expand_presets, build_parser


def _parse(argv):
    return build_parser().parse_args(argv)


class TestPresets(unittest.TestCase):
    def test_code_review_is_static_only_and_authorized(self):
        args = _parse(["--code-review", "src/"])
        _expand_presets(args)
        self.assertEqual(args.sast, "src/")
        self.assertEqual(args.phases, "sast")
        self.assertTrue(args.suggest_patches)
        self.assertTrue(args.authorized)
        # target/scope use a stable label so the host-based scope check matches
        self.assertEqual(args.target, "src")
        self.assertEqual(args.scope, ["src"])
        self.assertEqual(args.autofix_repo, "src/")
        # a purely static, local workflow enables no live network testing
        self.assertFalse(args.injection)
        self.assertFalse(args.browser)

    def test_web_pentest_bundles_live_tests_but_keeps_authorization_explicit(self):
        args = _parse(["--web-pentest", "https://app.example.com/"])
        _expand_presets(args)
        self.assertEqual(args.target, "https://app.example.com/")
        self.assertEqual(args.scope, ["app.example.com"])
        self.assertTrue(args.injection)
        self.assertTrue(args.browser)
        self.assertTrue(args.api_tests)
        # authorization is never auto-attested for a live target
        self.assertFalse(args.authorized)
        # access control stays off until an identity is supplied
        self.assertFalse(args.access_control)

    def test_web_pentest_enables_access_control_with_identity(self):
        args = _parse(["--web-pentest", "https://app.example.com/",
                       "--identity", "alice:Cookie:session=abc"])
        _expand_presets(args)
        self.assertTrue(args.access_control)

    def test_web_pentest_respects_explicit_scope(self):
        args = _parse(["--web-pentest", "https://app.example.com/",
                       "--scope", "10.0.0.0/24"])
        _expand_presets(args)
        self.assertEqual(args.scope, ["10.0.0.0/24"])


if __name__ == "__main__":
    unittest.main()
