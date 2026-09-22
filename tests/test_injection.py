import unittest
import urllib.request

from sentari import injection, oob


class TestInjectionHelpers(unittest.TestCase):
    def test_behavior_changed_on_status(self):
        self.assertTrue(injection.behavior_changed((200, "x" * 100), (500, "x" * 100)))

    def test_behavior_changed_on_dissimilar_body(self):
        self.assertTrue(injection.behavior_changed((200, "a" * 100), (200, "b" * 100)))

    def test_behavior_unchanged_when_similar(self):
        self.assertFalse(injection.behavior_changed((200, "a" * 100), (200, "a" * 100)))

    def test_behavior_unchanged_on_failed_request(self):
        self.assertFalse(injection.behavior_changed((200, "a" * 100), (0, "")))

    def test_nosqli_variants(self):
        variants = injection.nosqli_variants()
        self.assertIn(("[$ne]", "x"), variants)
        self.assertTrue(any(s == "[$regex]" for s, _ in variants))

    def test_xxe_payload_contains_entity_and_url(self):
        p = injection.xxe_payload("http://listener/tok")
        self.assertIn("SYSTEM", p)
        self.assertIn("http://listener/tok", p)
        self.assertIn("<!DOCTYPE", p)

    def test_ssrf_params_present(self):
        self.assertIn("url", injection.SSRF_PARAMS)
        self.assertIn("redirect", injection.SSRF_PARAMS)


class TestOOBListener(unittest.TestCase):
    def test_records_a_real_callback(self):
        with oob.OOBListener(host="127.0.0.1") as lis:
            token = lis.token()
            self.assertFalse(lis.hit(token))
            urllib.request.urlopen(lis.url(token), timeout=5).read()
            self.assertTrue(lis.hit(token))
            self.assertEqual(len(lis.hits(token)), 1)

    def test_distinct_tokens_isolated(self):
        with oob.OOBListener(host="127.0.0.1") as lis:
            t1, t2 = lis.token(), lis.token()
            urllib.request.urlopen(lis.url(t1), timeout=5).read()
            self.assertTrue(lis.hit(t1))
            self.assertFalse(lis.hit(t2))


class TestStoredXSSMap(unittest.TestCase):
    def test_fix_present(self):
        from sentari.phases.browser import _fix
        self.assertTrue(_fix("stored-xss"))


if __name__ == "__main__":
    unittest.main()
