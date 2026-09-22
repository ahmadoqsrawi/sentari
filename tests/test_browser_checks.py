# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import unittest


class TestClickjacking(unittest.TestCase):
    def test_flags_when_headers_absent(self):
        from sentari.browser import _clickjacking
        out = _clickjacking({}, "http://x")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["type"], "clickjacking")

    def test_silent_with_xframe_options(self):
        from sentari.browser import _clickjacking
        self.assertEqual(_clickjacking({"X-Frame-Options": "DENY"}, "http://x"), [])

    def test_silent_with_csp_frame_ancestors(self):
        from sentari.browser import _clickjacking
        h = {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}
        self.assertEqual(_clickjacking(h, "http://x"), [])


class TestBrowserFixMap(unittest.TestCase):
    def test_fixes_present_for_new_types(self):
        from sentari.phases.browser import _fix
        for t in ("dom-xss", "prototype-pollution", "clickjacking", "csrf"):
            self.assertTrue(_fix(t), f"missing fix for {t}")


class TestWithParamProto(unittest.TestCase):
    def test_proto_pollution_param_encoded(self):
        from sentari.browser import _with_param
        u = _with_param("http://x/a", "__proto__[sentari_pp]", "m")
        self.assertIn("__proto__", u)
        self.assertIn("sentari_pp", u)


if __name__ == "__main__":
    unittest.main()
