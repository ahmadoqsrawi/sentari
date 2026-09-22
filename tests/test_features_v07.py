# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import unittest

from sentari.models import Finding, PhaseResult, Severity


def _result(findings):
    r = PhaseResult(phase="vuln", started_at="t", ended_at="t")
    r.findings.extend(findings)
    return r


def _finding(**kw):
    kw.setdefault("severity", Severity.MEDIUM)
    kw.setdefault("description", "d")
    kw.setdefault("evidence_ids", ["e1"])
    kw.setdefault("target", "a.com")
    kw.setdefault("phase", "vuln")
    return Finding(**kw)


class TestOpenAPI(unittest.TestCase):
    def test_openapi3(self):
        from sentari.openapi import extract_endpoints
        spec = {"openapi": "3.0.0", "info": {}, "servers": [{"url": "https://api.x.com/v1"}],
                "paths": {"/a": {}, "/b/{id}": {}}}
        self.assertEqual(extract_endpoints(spec),
                         ["https://api.x.com/v1/a", "https://api.x.com/v1/b/{id}"])

    def test_swagger2(self):
        from sentari.openapi import extract_endpoints
        spec = {"swagger": "2.0", "host": "x.com", "basePath": "/v2",
                "schemes": ["https"], "paths": {"/login": {}}}
        self.assertEqual(extract_endpoints(spec), ["https://x.com/v2/login"])

    def test_postman_nested(self):
        from sentari.openapi import extract_endpoints
        spec = {"info": {}, "item": [
            {"request": {"url": {"raw": "https://x.com/ping?a=1"}}},
            {"item": [{"request": {"url": "https://x.com/deep"}}]}]}
        self.assertEqual(extract_endpoints(spec), ["https://x.com/ping", "https://x.com/deep"])

    def test_base_url_override_and_hosts(self):
        from sentari.openapi import extract_endpoints, hosts_of
        spec = {"openapi": "3.0.0", "info": {}, "paths": {"/a": {}}}
        urls = extract_endpoints(spec, "https://staging.x.com")
        self.assertEqual(urls, ["https://staging.x.com/a"])
        self.assertEqual(hosts_of(urls), {"staging.x.com"})


class TestSandbox(unittest.TestCase):
    def test_wrap_builds_docker_run(self):
        from sentari.sandbox import Sandbox
        self.assertEqual(Sandbox(image="img:1").wrap(["msfconsole", "-q"]),
                         ["docker", "run", "--rm", "--network", "host", "img:1",
                          "msfconsole", "-q"])

    def test_runner_available_true_in_sandbox(self):
        from sentari.runner import ToolRunner
        from sentari.sandbox import Sandbox
        self.assertFalse(ToolRunner().available("no-such-tool-xyz"))
        self.assertTrue(ToolRunner(sandbox=Sandbox()).available("no-such-tool-xyz"))

    def test_dry_run_wraps_command_evidence(self):
        from sentari.runner import ToolRunner
        from sentari.sandbox import Sandbox
        r = ToolRunner(dry_run=True, sandbox=Sandbox(image="img:1"))
        ev = r.run(["msfconsole"], tool="msfconsole")
        self.assertEqual(ev.command[:3], ["docker", "run", "--rm"])


class TestBrowser(unittest.TestCase):
    def test_with_param(self):
        from sentari.browser import _with_param
        self.assertIn("sentari_xss=", _with_param("http://x/a", "sentari_xss", "p"))
        self.assertTrue(_with_param("http://x/a?b=1", "k", "v").count("?") == 1)

    def test_run_checks_graceful_without_playwright(self):
        from sentari import browser
        if browser.available():
            self.skipTest("playwright installed here")
        rows, err = browser.run_checks(["http://x"])
        self.assertEqual(rows, [])
        self.assertIn("Playwright", err)

    def test_phase_noop_when_not_requested(self):
        from sentari.phases.base import PhaseContext
        from sentari.phases.browser import BrowserPhase
        from sentari.runner import ToolRunner
        ctx = PhaseContext(target="http://a.com", runner=ToolRunner(5),
                           safe_mode=True, options={})
        res = BrowserPhase().run(ctx)
        self.assertEqual(len(res.findings), 0)


class TestAutofix(unittest.TestCase):
    def test_build_report_groups_by_severity(self):
        from sentari import autofix
        res = [_result([
            _finding(title="RCE", severity=Severity.CRITICAL, location="https://a.com/x"),
            _finding(title="Missing CSP", severity=Severity.MEDIUM,
                     recommendation="Add a Content-Security-Policy header.")])]
        md = autofix.build_report(res)
        self.assertIn("CRITICAL (1)", md)
        self.assertIn("MEDIUM (1)", md)
        self.assertIn("Content-Security-Policy", md)
        self.assertIn("does not apply them", md)

    def test_open_draft_pr_non_repo(self):
        from sentari import autofix
        ok, msg = autofix.open_draft_pr("# x", "/tmp", "a.com")
        self.assertFalse(ok)
        self.assertIn("not a git repository", msg)


if __name__ == "__main__":
    unittest.main()
