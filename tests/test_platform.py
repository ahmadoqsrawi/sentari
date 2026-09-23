# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import json
import tempfile
import threading
import unittest
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer

from sentari.platform.api import dispatch, make_handler, make_submit
from sentari.platform.store import PlatformStore, hash_token


class TestStore(unittest.TestCase):
    def setUp(self):
        self.s = PlatformStore(tempfile.mktemp(suffix=".db"))
        self.addCleanup(self.s.close)

    def test_token_is_hashed_not_stored_raw(self):
        user, token = self.s.add_user("a@x.com")
        row = self.s.conn.execute("SELECT token_hash FROM users WHERE id=?",
                                  (user.id,)).fetchone()
        self.assertEqual(row["token_hash"], hash_token(token))
        self.assertNotEqual(row["token_hash"], token)

    def test_duplicate_email_rejected(self):
        self.s.add_user("dup@x.com")
        with self.assertRaises(ValueError):
            self.s.add_user("dup@x.com")

    def test_user_by_token(self):
        user, token = self.s.add_user("b@x.com")
        self.assertEqual(self.s.user_by_token(token).id, user.id)
        self.assertIsNone(self.s.user_by_token("wrong"))

    def test_scans_are_tenant_isolated(self):
        alice, _ = self.s.add_user("alice@x.com")
        bob, _ = self.s.add_user("bob@x.com")
        sid = self.s.create_scan(alice.id, "x.com")
        self.assertIsNotNone(self.s.get_scan(alice.id, sid))
        self.assertIsNone(self.s.get_scan(bob.id, sid))      # bob cannot read it
        self.assertEqual(self.s.list_scans(bob.id), [])       # nor list it


class TestDispatch(unittest.TestCase):
    def setUp(self):
        self.s = PlatformStore(tempfile.mktemp(suffix=".db"))
        self.addCleanup(self.s.close)
        self.alice, self.ta = self.s.add_user("alice@x.com")
        self.bob, self.tb = self.s.add_user("bob@x.com")
        self.calls = []
        self.submit = lambda *a: self.calls.append(a)

    def d(self, *a):
        return dispatch(*a, self.s, self.submit)

    def test_health_needs_no_auth(self):
        self.assertEqual(self.d("GET", "/api/health", None, None)[0], 200)

    def test_missing_token_401(self):
        self.assertEqual(self.d("GET", "/api/scans", None, None)[0], 401)

    def test_authorized_attestation_required(self):
        code, resp = self.d("POST", "/api/scans", self.ta, {"target": "x.com"})
        self.assertEqual(code, 400)
        self.assertIn("authorized", resp["error"])

    def test_create_and_isolation(self):
        code, resp = self.d("POST", "/api/scans", self.ta,
                            {"target": "x.com", "scope": ["x.com"], "authorized": True})
        self.assertEqual(code, 202)
        self.assertEqual(len(self.calls), 1)
        sid = resp["id"]
        self.assertEqual(self.d("GET", f"/api/scans/{sid}", self.tb, None)[0], 404)
        self.assertEqual(self.d("GET", f"/api/scans/{sid}", self.ta, None)[0], 200)

    def test_unknown_route_404(self):
        self.assertEqual(self.d("GET", "/api/nope", self.ta, None)[0], 404)


class TestLiveHTTP(unittest.TestCase):
    def test_round_trip_over_http(self):
        store = PlatformStore(tempfile.mktemp(suffix=".db"))
        self.addCleanup(store.close)
        _, token = store.add_user("live@x.com")
        executor = ThreadPoolExecutor(max_workers=1)
        self.addCleanup(lambda: executor.shutdown(wait=False))
        # a submit that just marks the scan done (no real engine run in the test)
        def submit(user_id, sid, *a):
            store.update_scan(sid, status="done", findings=0)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store, submit))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        base = f"http://127.0.0.1:{httpd.server_address[1]}"

        req = urllib.request.Request(
            base + "/api/scans", method="POST",
            data=json.dumps({"target": "x.com", "scope": ["x.com"],
                             "authorized": True}).encode(),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            self.assertEqual(r.status, 202)
            sid = json.loads(r.read())["id"]

        req2 = urllib.request.Request(
            base + f"/api/scans/{sid}",
            headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req2, timeout=5) as r:
            body = json.loads(r.read())
            self.assertEqual(body["id"], sid)


if __name__ == "__main__":
    unittest.main()
