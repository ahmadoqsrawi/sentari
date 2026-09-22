import base64
import hashlib
import hmac
import json
import time
import unittest

from sentari import jwt_audit


def _mk(header, payload, secret=None):
    def b(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    si = f"{b(header)}.{b(payload)}"
    if secret is None:
        return si + "."
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), si.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{si}.{sig}"


class TestJWTAudit(unittest.TestCase):
    def test_decode_valid(self):
        h, p, err = jwt_audit.decode(_mk({"alg": "HS256"}, {"u": 1}, "k"))
        self.assertIsNone(err)
        self.assertEqual(h["alg"], "HS256")
        self.assertEqual(p["u"], 1)

    def test_decode_invalid(self):
        _, _, err = jwt_audit.decode("not.a.jwt.token")
        self.assertIsNotNone(err)

    def test_alg_none_flagged(self):
        issues = {i["issue"] for i in jwt_audit.audit(_mk({"alg": "none"}, {"exp": 9e9}))}
        self.assertIn("alg=none accepted", issues)

    def test_weak_secret_cracked(self):
        issues = {i["issue"] for i in jwt_audit.audit(_mk({"alg": "HS256"}, {"exp": 9e9}, "secret"))}
        self.assertIn("weak HMAC secret", issues)

    def test_strong_secret_and_exp_clean(self):
        tok = _mk({"alg": "HS256"}, {"exp": int(time.time()) + 9999},
                  "a-very-long-unguessable-secret-9f8e7d")
        self.assertEqual(jwt_audit.audit(tok), [])

    def test_missing_exp_flagged(self):
        issues = {i["issue"] for i in jwt_audit.audit(
            _mk({"alg": "HS256"}, {"u": 1}, "a-very-long-unguessable-secret-9f8e7d"))}
        self.assertIn("no expiry (exp)", issues)

    def test_sensitive_payload_flagged(self):
        tok = _mk({"alg": "HS256"}, {"password": "p", "exp": 9e9},
                  "a-very-long-unguessable-secret-9f8e7d")
        issues = {i["issue"] for i in jwt_audit.audit(tok)}
        self.assertIn("sensitive data in payload", issues)

    def test_verify_hs256(self):
        tok = _mk({"alg": "HS256"}, {"u": 1}, "topsecret")
        self.assertTrue(jwt_audit.verify_hs256(tok, "topsecret"))
        self.assertFalse(jwt_audit.verify_hs256(tok, "wrong"))

    def test_custom_wordlist(self):
        tok = _mk({"alg": "HS256"}, {"exp": 9e9}, "hunter2")
        self.assertEqual(jwt_audit.crack_hs256(tok, ["nope", "hunter2"]), "hunter2")
        self.assertIsNone(jwt_audit.crack_hs256(tok, ["nope"]))


class TestAPIPhase(unittest.TestCase):
    def test_jwt_regex_matches(self):
        from sentari.phases.apitest import _JWT_RE
        tok = _mk({"alg": "HS256"}, {"u": 1}, "k")
        self.assertTrue(_JWT_RE.search(f'{{"token":"{tok}"}}'))

    def test_noop_without_flags(self):
        from sentari.phases.apitest import APITestPhase
        from sentari.phases.base import PhaseContext
        from sentari.runner import ToolRunner
        ctx = PhaseContext(target="http://a.com", runner=ToolRunner(5), options={})
        res = APITestPhase().run(ctx)
        self.assertEqual(len(res.findings), 0)

    def test_supplied_jwt_audited_without_endpoints(self):
        from sentari.phases.apitest import APITestPhase
        from sentari.phases.base import PhaseContext
        from sentari.runner import ToolRunner
        ctx = PhaseContext(target="http://a.com", runner=ToolRunner(5),
                           options={"jwt": _mk({"alg": "none"}, {"u": 1})})
        res = APITestPhase().run(ctx)
        self.assertTrue(any("alg=none" in f.title or "alg=none" in f.description
                            for f in res.findings))


if __name__ == "__main__":
    unittest.main()
