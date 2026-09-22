import base64
import hashlib
import hmac
import json
import os
import tempfile
import unittest

from sentari import proxy


def _weak_jwt():
    def b(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    si = f'{b({"alg":"HS256"})}.{b({"user":"a"})}'
    sig = base64.urlsafe_b64encode(
        hmac.new(b"secret", si.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{si}.{sig}"


class TestAnalyzeFlows(unittest.TestCase):
    def _write(self, text):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.write(fd, text.encode())
        os.close(fd)
        self.addCleanup(os.remove, path)
        return path

    def test_jsonl_detects_issues(self):
        tok = _weak_jwt()
        flow = {"request": {"method": "GET",
                            "url": "http://app.test/login?password=hunter2",
                            "headers": {"Authorization": "Basic dXNlcjpwYXNz"}, "content": ""},
                "response": {"status_code": 200,
                             "headers": {"Set-Cookie": "session=abc; Path=/"},
                             "content": json.dumps({"jwt": tok})}}
        path = self._write(json.dumps(flow))
        issues = {i["issue"] for i in proxy.analyze_flows(path)}
        self.assertIn("Credentials sent over cleartext HTTP", issues)
        self.assertIn("Secret in URL over HTTP", issues)
        self.assertIn("Insecure cookie flags", issues)
        self.assertTrue(any("JWT weakness" in i for i in issues))

    def test_https_basic_auth_not_flagged(self):
        flow = {"request": {"method": "GET", "url": "https://app.test/x",
                            "headers": {"Authorization": "Basic dXNlcjpwYXNz"}, "content": ""},
                "response": {"status_code": 200, "headers": {}, "content": ""}}
        path = self._write(json.dumps(flow))
        issues = {i["issue"] for i in proxy.analyze_flows(path)}
        self.assertNotIn("Credentials sent over cleartext HTTP", issues)

    def test_har_format(self):
        har = {"log": {"entries": [
            {"request": {"method": "GET", "url": "http://app.test/x?token=abc",
                         "headers": [{"name": "Host", "value": "app.test"}]},
             "response": {"status": 200,
                          "headers": [{"name": "Set-Cookie", "value": "s=1; Secure; HttpOnly"}],
                          "content": {"text": ""}}}]}}
        path = self._write(json.dumps(har))
        issues = {i["issue"] for i in proxy.analyze_flows(path)}
        self.assertIn("Secret in URL over HTTP", issues)
        # cookie is Secure+HttpOnly -> not flagged
        self.assertNotIn("Insecure cookie flags", issues)

    def test_addon_text_is_valid_python(self):
        compile(proxy.ADDON, "addon", "exec")


if __name__ == "__main__":
    unittest.main()
