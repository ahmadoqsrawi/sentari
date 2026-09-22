# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import json
import os
import tempfile
import unittest

from sentari import domainverify, loginrec, nethdr, repo, spec as spec_mod
from sentari.authorization import AuditLog, AuthorizationError, Scope, authorize
from sentari.cli import _expand_presets, build_parser


def _parse(argv):
    return build_parser().parse_args(argv)


class TestHeaders(unittest.TestCase):
    def test_parse_header_ok(self):
        self.assertEqual(nethdr.parse_header("X-API-Key: abc"), ("X-API-Key", "abc"))
        self.assertEqual(nethdr.parse_header("Authorization: Bearer x.y.z"),
                         ("Authorization", "Bearer x.y.z"))

    def test_parse_header_rejects_malformed(self):
        with self.assertRaises(ValueError):
            nethdr.parse_header("no-colon-here")

    def test_parse_headers_last_wins(self):
        h = nethdr.parse_headers(["A: 1", "A: 2", "B: 3"])
        self.assertEqual(h, {"A": "2", "B": "3"})

    def test_install_records_current(self):
        nethdr.install({"X-Token": "t"})
        self.assertEqual(nethdr.current(), {"X-Token": "t"})
        nethdr.install({})
        self.assertEqual(nethdr.current(), {})


class TestScopeExclude(unittest.TestCase):
    def test_excludes_wins_over_scope(self):
        s = Scope.from_items(["10.0.0.0/8"], exclude=["10.0.0.5"])
        self.assertTrue(s.contains("10.0.0.5"))
        self.assertTrue(s.excludes("10.0.0.5"))

    def test_authorize_refuses_off_limits(self):
        audit = AuditLog(__import__("pathlib").Path(
            tempfile.mkdtemp()) / "audit.log")
        s = Scope.from_items(["10.0.0.0/8"], exclude=["10.0.0.5"])
        with self.assertRaises(AuthorizationError):
            authorize("10.0.0.5", s, True, audit)
        authorize("10.0.0.6", s, True, audit)  # in scope, not excluded -> ok

    def test_cli_builds_exclude(self):
        args = _parse(["--exclude", "admin.example.com"])
        self.assertEqual(args.exclude, ["admin.example.com"])


class TestRepo(unittest.TestCase):
    def test_is_repo_url(self):
        self.assertTrue(repo.is_repo_url("https://github.com/me/app"))
        self.assertTrue(repo.is_repo_url("git@gitlab.com:me/app.git"))
        self.assertTrue(repo.is_repo_url("https://bitbucket.org/me/app"))
        self.assertFalse(repo.is_repo_url("./src"))
        self.assertFalse(repo.is_repo_url("/home/me/project"))

    def test_label(self):
        self.assertEqual(repo.label("https://github.com/me/app.git"), "app")
        self.assertEqual(repo.label("https://gitlab.com/me/app/"), "app")


class TestDomainVerify(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.environ["SENTARI_HOME"] = self.home

    def tearDown(self):
        os.environ.pop("SENTARI_HOME", None)

    def test_token_is_stable_per_domain(self):
        t1 = domainverify.token_for("example.com")
        t2 = domainverify.token_for("example.com")
        self.assertEqual(t1, t2)
        self.assertNotEqual(t1, domainverify.token_for("other.com"))

    def test_instructions_contain_token(self):
        t = domainverify.token_for("example.com")
        msg = domainverify.instructions("example.com", t)
        self.assertIn("sentari-verify=" + t, msg)


class TestLoginRec(unittest.TestCase):
    def test_cookie_header_builds_from_cookies(self):
        h = loginrec._cookie_header(
            [{"name": "session", "value": "abc"}, {"name": "csrf", "value": "z"},
             {"name": "", "value": "skip"}])
        self.assertEqual(h, "session=abc; csrf=z")

    def test_record_without_playwright_degrades(self):
        if loginrec.available():
            self.skipTest("Playwright installed; degradation path not exercised")
        rec = loginrec.record_login("https://x/login", "u", "p")
        self.assertFalse(rec.verified)
        self.assertIsNotNone(rec.error)
        self.assertEqual(rec.cookie_header, "")

    def test_recorded_user_maps_to_identity(self):
        # a user dict with the extra login_verified flag still maps cleanly
        user = {"name": "alice", "header": "Cookie", "value": "session=abc",
                "login_verified": True}
        idents, warns = spec_mod._identity_specs([user])
        self.assertEqual(idents, ["alice:Cookie:session=abc"])
        self.assertEqual(warns, [])


class TestSpec(unittest.TestCase):
    def _spec(self):
        return {
            "mode": "web-pentest",
            "target": "https://app.example.com",
            "api_specs": ["openapi.json"],
            "scope": {"attack": ["app.example.com"], "exclude": ["admin.example.com"]},
            "repositories": ["https://github.com/me/app"],
            "access": {"users": [{"name": "alice", "header": "Cookie", "value": "s=1"}],
                       "headers": {"X-API-Key": "k"}},
            "context": {"instructions": "focus on IDOR"},
            "safe_mode": False,
            "authorized": True,
        }

    def test_apply_maps_all_fields(self):
        args = _parse([])
        spec_mod.apply(self._spec(), args)
        self.assertEqual(args.web_pentest, "https://app.example.com")
        self.assertEqual(args.scope, ["app.example.com"])
        self.assertEqual(args.exclude, ["admin.example.com"])
        self.assertEqual(args.openapi, "openapi.json")
        self.assertEqual(args.sast, "https://github.com/me/app")
        self.assertIn("alice:Cookie:s=1", args.identity)
        self.assertIn("X-API-Key: k", args.header)
        self.assertEqual(args.goal, "focus on IDOR")
        self.assertTrue(args.no_safe_mode)
        self.assertTrue(args.authorized)
        # after expansion the live bundle is enabled
        _expand_presets(args)
        self.assertTrue(args.injection and args.browser and args.api_tests)

    def test_apply_code_review_mode(self):
        s = {"mode": "code-review", "repositories": ["https://github.com/me/app"]}
        args = _parse([])
        spec_mod.apply(s, args)
        self.assertEqual(args.code_review, "https://github.com/me/app")

    def test_roundtrip_save_load(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.addCleanup(os.remove, path)
        spec_mod.save(path, self._spec())
        loaded = spec_mod.load(path)
        self.assertEqual(loaded["target"], "https://app.example.com")

    def test_summary_redacts_headers(self):
        out = spec_mod.summary(self._spec())
        self.assertIn("app.example.com", out)
        self.assertIn("X-API-Key: ***", out)
        self.assertNotIn(": k", out)


if __name__ == "__main__":
    unittest.main()
