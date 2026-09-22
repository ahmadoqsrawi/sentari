import unittest

from sentari import deserial, injection, sessionfix, workflow


class TestDeserial(unittest.TestCase):
    def test_detects_formats(self):
        self.assertEqual(deserial.detect("rO0ABXNyABc"), "java")
        self.assertEqual(deserial.detect('O:8:"stdClass":0:{}'), "php")
        self.assertEqual(deserial.detect("gASVaaaa"), "python-pickle")
        self.assertEqual(deserial.detect("BAh7Bg"), "ruby-marshal")
        self.assertIsNone(deserial.detect("just a normal value"))

    def test_scan_param(self):
        issues = deserial.scan("http://x/?data=rO0ABXNyfoo&q=1", {})
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["format"], "java")

    def test_scan_setcookie(self):
        issues = deserial.scan_setcookie("http://x/", ["sess=rO0ABXNy; Path=/"])
        self.assertEqual(len(issues), 1)
        self.assertIn("cookie", issues[0]["where"])


class TestInjectionPayloads(unittest.TestCase):
    def test_cmdi_and_ssti_and_params(self):
        self.assertTrue(all("curl" in p or "wget" in p for p in injection.cmdi_payloads("http://o/t")))
        self.assertTrue(any("7*7" in p for p in injection.ssti_payloads("M")))
        self.assertEqual(injection.candidate_params(["foo"]), ["foo"])
        self.assertIn("q", injection.candidate_params([]))


class TestWorkflow(unittest.TestCase):
    def test_should_fail_that_succeeds_is_flagged(self):
        spec = {"steps": [{"name": "buy_neg", "url": "http://x/buy", "method": "POST",
                           "should_fail": True}]}
        issues, trace = workflow.run(spec, lambda u, m, h, d: (200, "ok"))
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["severity"], "high")

    def test_expect_status_mismatch(self):
        spec = {"steps": [{"name": "admin", "url": "http://x/admin", "expect_status": 403}]}
        issues, _ = workflow.run(spec, lambda u, m, h, d: (200, "panel"))
        self.assertEqual(issues[0]["severity"], "medium")

    def test_capture_and_substitute(self):
        spec = {"steps": [
            {"name": "login", "url": "http://x/login", "method": "POST",
             "capture": {"tok": r'"token":"([^"]+)"'}, "expect_status": 200},
            {"name": "use", "url": "http://x/u?t={{tok}}", "expect_status": 200}]}
        seen = {}

        def fetch(u, m, h, d):
            seen["last"] = u
            return (200, '{"token":"ABC"}') if "login" in u else (200, "ok")
        issues, trace = workflow.run(spec, fetch)
        self.assertEqual(issues, [])
        self.assertIn("t=ABC", seen["last"])

    def test_no_finding_when_should_fail_actually_fails(self):
        spec = {"steps": [{"name": "x", "url": "http://x/x", "should_fail": True}]}
        issues, _ = workflow.run(spec, lambda u, m, h, d: (403, "no"))
        self.assertEqual(issues, [])


class TestSessionFixValue(unittest.TestCase):
    def test_picks_session_like_cookie(self):
        name, val = sessionfix._session_value(["PHPSESSID=abc123; Path=/"], None)
        self.assertEqual(name, "PHPSESSID")
        self.assertEqual(val, "abc123")

    def test_named_cookie(self):
        name, val = sessionfix._session_value(["sid=xyz; Path=/", "other=1"], "sid")
        self.assertEqual(name, "sid")
        self.assertEqual(val, "xyz")

    def test_no_session_cookie(self):
        name, val = sessionfix._session_value(["theme=dark"], None)
        self.assertIsNone(val)


if __name__ == "__main__":
    unittest.main()
