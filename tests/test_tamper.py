import unittest

from sentari import tamper


class TestTamper(unittest.TestCase):
    def test_request_from_flow(self):
        flow = {"request": {"method": "POST", "url": "http://x/a", "headers": {"H": "1"},
                            "content": "body"}}
        req = tamper.request_from_flow(flow)
        self.assertEqual(req["method"], "POST")
        self.assertEqual(req["headers"], {"H": "1"})
        self.assertEqual(req["body"], "body")

    def test_apply_mutations_params_and_headers(self):
        req = {"method": "GET", "url": "http://x/a?id=1", "headers": {"Cookie": "s=1"}, "body": ""}
        m = tamper.apply_mutations(req, set_headers={"X": "9"},
                                   set_params={"id": "99", "role": "admin"})
        self.assertIn("id=99", m["url"])
        self.assertIn("role=admin", m["url"])
        self.assertEqual(m["headers"]["X"], "9")
        self.assertEqual(m["headers"]["Cookie"], "s=1")  # original preserved

    def test_apply_mutations_body(self):
        req = {"method": "POST", "url": "http://x", "headers": {}, "body": "old"}
        self.assertEqual(tamper.apply_mutations(req, set_body="new")["body"], "new")

    def test_mutations_do_not_change_original(self):
        req = {"method": "GET", "url": "http://x/a?id=1", "headers": {"A": "1"}, "body": ""}
        tamper.apply_mutations(req, set_headers={"B": "2"}, set_params={"id": "2"})
        self.assertEqual(req["headers"], {"A": "1"})
        self.assertEqual(req["url"], "http://x/a?id=1")

    def test_diff(self):
        d = tamper.diff("a\nb\n", "a\nc\n")
        self.assertIn("-b", d)
        self.assertIn("+c", d)

    def test_diff_identical_empty(self):
        self.assertEqual(tamper.diff("same\n", "same\n"), "")


if __name__ == "__main__":
    unittest.main()
