# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import unittest


class _StubProvider:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def complete(self, system, user, max_tokens=1500):
        self.calls.append((system, user))
        return self.reply


class TestNexposeGraceful(unittest.TestCase):
    def test_missing_env_returns_note(self):
        import os

        from sentari import nexpose
        for k in ("NEXPOSE_HOST", "NEXPOSE_USER", "NEXPOSE_PASS"):
            os.environ.pop(k, None)
        rows, err = nexpose.fetch_results("1.2.3.4")
        self.assertEqual(rows, [])
        self.assertIn("NEXPOSE_HOST", err)


class TestPrivesc(unittest.TestCase):
    def test_paramiko_absent_is_graceful(self):
        from sentari import privesc
        if privesc._paramiko() is not None:
            self.skipTest("paramiko is installed here")
        rows, err = privesc.enumerate_linux("127.0.0.1", "root", password="x")
        self.assertEqual(rows, [])
        self.assertIn("paramiko", err)

    def test_assess_detects_nopasswd(self):
        from sentari.privesc import _assess
        vec, sev = _assess("nopasswd", "User may run: (root) NOPASSWD: /usr/bin/find")
        self.assertIsNotNone(vec)
        self.assertEqual(sev, "high")

    def test_assess_detects_dangerous_suid(self):
        from sentari.privesc import _assess
        vec, sev = _assess("suid", "-rwsr-xr-x 1 root root /usr/bin/find\n/usr/bin/vim")
        self.assertIn("find", vec)
        self.assertEqual(sev, "high")

    def test_assess_writable_passwd_is_critical(self):
        from sentari.privesc import _assess
        vec, sev = _assess("passwd_writable", "-rw-rw-rw- 1 root root 2000 /etc/passwd")
        self.assertEqual(sev, "critical")

    def test_assess_clean_output_no_vector(self):
        from sentari.privesc import _assess
        vec, sev = _assess("suid", "-rwsr-xr-x 1 root root /usr/bin/passwd")
        self.assertIsNone(vec)
        self.assertEqual(sev, "info")


class TestAIOsint(unittest.TestCase):
    def test_extract_list_from_json(self):
        from sentari.ai.osint import _extract_list
        self.assertEqual(_extract_list('junk ["dev","api"] tail'), ["dev", "api"])

    def test_extract_list_fallback(self):
        from sentari.ai.osint import _extract_list
        self.assertEqual([s.strip() for s in _extract_list("dev, api\nvpn")],
                         ["dev", "api", "vpn"])

    def test_seed_subdomains_filters_invalid(self):
        from sentari.ai import osint
        prov = _StubProvider('["dev", "API.example.com", "bad label", "vpn"]')
        labels = osint.seed_subdomains(prov, "example.com")
        # api extracted from the dotted form; "bad label" dropped (space)
        self.assertIn("dev", labels)
        self.assertIn("vpn", labels)
        self.assertIn("api", labels)
        self.assertNotIn("bad label", labels)

    def test_summarize_uses_only_given_assets(self):
        from sentari.ai import osint
        prov = _StubProvider("Two subdomains and one exposed port.")
        out = osint.summarize(prov, "example.com", ["dev.example.com"], [443])
        self.assertTrue(out)
        # the real asset must appear in the payload sent to the model
        self.assertIn("dev.example.com", prov.calls[0][1])

    def test_summarize_empty_when_nothing_found(self):
        from sentari.ai import osint
        self.assertEqual(osint.summarize(_StubProvider("x"), "e.com", [], []), "")


class TestDashboard(unittest.TestCase):
    def _run(self):
        return {"results": [{"findings": [
            {"title": "XSS", "severity": "high", "target": "a.com",
             "metadata": {"risk": {"likelihood": "high", "impact": "high"},
                          "compliance": {"owasp": "A03:2021"}, "known_exploited": True}},
            {"title": "CSP", "severity": "medium", "target": "a.com",
             "metadata": {"risk": {"likelihood": "medium", "impact": "low"}}}]}]}

    def test_dashboard_has_kpis_and_charts(self):
        from sentari.web.server import _dashboard
        html = _dashboard({"20240101-a": self._run()})
        for probe in ["Executive Dashboard", "<svg", "matrix", "known exploited", "A03:2021"]:
            self.assertIn(probe.lower(), html.lower())

    def test_dashboard_empty_is_safe(self):
        from sentari.web.server import _dashboard
        html = _dashboard({})
        self.assertIn("No runs", html)


if __name__ == "__main__":
    unittest.main()
