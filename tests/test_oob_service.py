# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
import threading
import unittest
import urllib.request

from sentari import oob


class TestOOBFactory(unittest.TestCase):
    def test_make_local_vs_remote(self):
        self.assertIsInstance(oob.make({"oob_host": "127.0.0.1"}), oob.OOBListener)
        r = oob.make({"oob_service": "http://collab:8611"})
        self.assertIsInstance(r, oob.RemoteOOB)
        self.assertEqual(r.url("oobX"), "http://collab:8611/oobX")

    def test_remote_hit_graceful_without_server(self):
        r = oob.RemoteOOB("http://127.0.0.1:1")  # nothing listening
        self.assertFalse(r.hit("oobX"))
        self.assertEqual(r.hits("oobX"), [])


class TestHostedOOBRoundTrip(unittest.TestCase):
    def test_callback_recorded_and_polled(self):
        httpd = oob.make_oob_server("127.0.0.1", 0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        port = httpd.server_address[1]
        client = oob.RemoteOOB(f"http://127.0.0.1:{port}")
        token = client.token()

        # before any callback: no hit
        self.assertFalse(client.hit(token))
        # the "target" fetches the injected callback URL
        with urllib.request.urlopen(client.url(token), timeout=5) as r:
            self.assertEqual(r.status, 200)
        # now the scan can confirm it
        self.assertTrue(client.hit(token))
        self.assertEqual(len(client.hits(token)), 1)


if __name__ == "__main__":
    unittest.main()
