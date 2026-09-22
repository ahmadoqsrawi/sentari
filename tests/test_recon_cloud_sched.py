import os
import unittest

from sentari import cloud_assets
from sentari.phases.osint import OSINTPhase, _HOST_RE
from sentari.retest import delta_dicts
from sentari.tasks import scheduled_retest_sync


class TestOSINT(unittest.TestCase):
    def test_phase_registered(self):
        self.assertEqual(OSINTPhase.number, 0)
        self.assertEqual(OSINTPhase.name, "osint")

    def test_host_regex(self):
        self.assertTrue(_HOST_RE.search("found sub.example.com in results"))
        self.assertIsNone(_HOST_RE.search("no host here 12345"))


class TestCloud(unittest.TestCase):
    def test_graceful_without_sdk(self):
        r = cloud_assets.discover("aws")
        # boto3 may be absent in this env -> error path; if present, no crash
        self.assertEqual(r.provider, "aws")

    def test_unknown_provider(self):
        r = cloud_assets.discover("nope")
        self.assertIsNotNone(r.error)


class TestDelta(unittest.TestCase):
    def test_delta_dicts(self):
        base = [{"phase": "s", "title": "a", "location": "u"},
                {"phase": "s", "title": "b", "location": "u"}]
        cur = [{"phase": "s", "title": "a", "location": "u"},
               {"phase": "s", "title": "c", "location": "u"}]
        d = delta_dicts(base, cur)
        self.assertEqual(len(d["fixed"]), 1)   # b gone
        self.assertEqual(len(d["still"]), 1)   # a
        self.assertEqual(len(d["new"]), 1)     # c


class TestScheduled(unittest.TestCase):
    def test_no_target_env(self):
        os.environ.pop("SENTARI_SCHEDULE_TARGET", None)
        self.assertIn("error", scheduled_retest_sync())


if __name__ == "__main__":
    unittest.main()
