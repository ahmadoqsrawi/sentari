import unittest

from sentari.accesscontrol import ANON, analyze

_PRIV = "ACCOUNT balance 12345 private " + "z" * 400
_PUB = "PUBLIC same for everyone " + "p" * 400


class TestAccessControl(unittest.TestCase):
    def test_missing_authentication(self):
        samples = {"http://x/pub": {ANON: (200, _PUB), "alice": (200, _PUB)}}
        issues = [i["issue"] for i in analyze(samples)]
        self.assertIn("Resource accessible without authentication", issues)

    def test_idor_same_resource_two_users(self):
        samples = {"http://x/acct": {ANON: (302, ""), "alice": (200, _PRIV),
                                     "bob": (200, _PRIV)}}
        issues = [i["issue"] for i in analyze(samples)]
        self.assertIn("Possible IDOR: same resource served to different users", issues)

    def test_proper_control_no_finding(self):
        # anon blocked, bob forbidden -> access control works
        samples = {"http://x/acct": {ANON: (302, ""), "alice": (200, _PRIV),
                                     "bob": (403, "forbidden")}}
        self.assertEqual(analyze(samples), [])

    def test_distinct_per_user_data_no_idor(self):
        samples = {"http://x/me": {ANON: (302, ""),
                                   "alice": (200, "alice private " + "a" * 400),
                                   "bob": (200, "bob private " + "b" * 400)}}
        self.assertEqual(analyze(samples), [])

    def test_tiny_bodies_ignored(self):
        # identical but trivially short -> not enough to claim a shared resource
        samples = {"http://x/acct": {ANON: (302, ""), "alice": (200, "ok"),
                                     "bob": (200, "ok")}}
        self.assertEqual(analyze(samples), [])

    def test_no_idor_when_anon_also_sees_it(self):
        # if anon sees it too, it is "missing auth", not IDOR
        samples = {"http://x/acct": {ANON: (200, _PRIV), "alice": (200, _PRIV),
                                     "bob": (200, _PRIV)}}
        issues = [i["issue"] for i in analyze(samples)]
        self.assertIn("Resource accessible without authentication", issues)
        self.assertNotIn("Possible IDOR: same resource served to different users", issues)


class TestACPhase(unittest.TestCase):
    def test_noop_without_identities(self):
        from sentari.phases.accesscontrol import AccessControlPhase
        from sentari.phases.base import PhaseContext
        from sentari.runner import ToolRunner
        ctx = PhaseContext(target="http://a", runner=ToolRunner(5),
                           options={"access_control": True, "identities": []})
        res = AccessControlPhase().run(ctx)
        self.assertEqual(len(res.findings), 0)
        self.assertTrue(any("no --identity" in n for n in res.notes))


if __name__ == "__main__":
    unittest.main()
