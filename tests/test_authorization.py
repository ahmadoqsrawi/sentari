import tempfile
import unittest
from pathlib import Path

from sentari.authorization import AuditLog, AuthorizationError, Scope, authorize, host_only


class TestHostOnly(unittest.TestCase):
    def test_variants(self):
        self.assertEqual(host_only("example.com"), "example.com")
        self.assertEqual(host_only("example.com:8080"), "example.com")
        self.assertEqual(host_only("https://example.com:443/x"), "example.com")
        self.assertEqual(host_only("10.0.0.5:22"), "10.0.0.5")


class TestScope(unittest.TestCase):
    def test_host_match(self):
        s = Scope.from_items(["example.com"])
        self.assertTrue(s.contains("example.com"))
        self.assertTrue(s.contains("example.com:8080"))
        self.assertFalse(s.contains("evil.com"))

    def test_cidr_match(self):
        s = Scope.from_items(["10.0.0.0/24"])
        self.assertTrue(s.contains("10.0.0.5"))
        self.assertFalse(s.contains("10.0.1.5"))

    def test_empty(self):
        self.assertTrue(Scope.from_items([]).is_empty())


class TestAuthorize(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = AuditLog(Path(self.tmp.name) / "audit.log")

    def tearDown(self):
        self.tmp.cleanup()

    def test_empty_scope_denied(self):
        with self.assertRaises(AuthorizationError):
            authorize("example.com", Scope.from_items([]), True, self.audit)

    def test_no_attestation_denied(self):
        with self.assertRaises(AuthorizationError):
            authorize("example.com", Scope.from_items(["example.com"]), False, self.audit)

    def test_out_of_scope_denied(self):
        with self.assertRaises(AuthorizationError):
            authorize("evil.com", Scope.from_items(["example.com"]), True, self.audit)

    def test_authorized_in_scope_ok(self):
        authorize("example.com", Scope.from_items(["example.com"]), True, self.audit)  # no raise


if __name__ == "__main__":
    unittest.main()
