# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import json
import unittest

from sentari import cloudaudit, pocrunner


class TestProwlerParse(unittest.TestCase):
    def test_fail_only(self):
        data = json.dumps([
            {"Status": "FAIL", "Severity": "critical", "CheckID": "s3_public",
             "CheckTitle": "S3 public", "StatusExtended": "bucket x public",
             "ResourceId": "arn:x", "Region": "us-east-1", "ServiceName": "s3"},
            {"Status": "PASS", "Severity": "high", "CheckID": "iam_mfa"},
        ])
        rows = cloudaudit.parse_prowler(data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "critical")
        self.assertEqual(rows[0]["resource"], "arn:x")

    def test_findings_wrapper(self):
        data = json.dumps({"findings": [
            {"status": "FAILED", "severity": "medium", "check_title": "open sg",
             "resource_uid": "sg-1"}]})
        rows = cloudaudit.parse_prowler(data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "medium")

    def test_bad_json_empty(self):
        self.assertEqual(cloudaudit.parse_prowler("nope"), [])

    def test_informational_maps_to_info(self):
        data = json.dumps([{"Status": "FAIL", "Severity": "informational",
                            "CheckTitle": "note"}])
        self.assertEqual(cloudaudit.parse_prowler(data)[0]["severity"], "info")


class TestPocRunner(unittest.TestCase):
    def test_docker_command(self):
        cmd = pocrunner.docker_command("/tmp/p.py", "http://t", "python:3-slim")
        self.assertEqual(cmd[:5], ["docker", "run", "--rm", "--network", "host"])
        self.assertIn("-v", cmd)
        self.assertEqual(cmd[-3:], ["python", "/poc.py", "http://t"])

    def test_missing_script_graceful(self):
        class R:
            def run(self, *a, **k):
                raise AssertionError("should not run for a missing script")
        ev, ok, note = pocrunner.run_poc(R(), "/no/such/poc.py", "t")
        self.assertIsNone(ev)
        self.assertFalse(ok)
        self.assertIn("not found", note)

    def test_success_marker_constant(self):
        self.assertEqual(pocrunner.SUCCESS_MARKER, "SENTARI_POC_SUCCESS")


if __name__ == "__main__":
    unittest.main()
