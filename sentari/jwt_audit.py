"""JWT auditing (read-only, offline).

Decodes a JSON Web Token and checks it for well-known weaknesses: the `alg=none`
bypass, a weak HMAC secret (tested against a small wordlist), a missing or past
expiry, and obviously sensitive data in the payload. Everything here operates on
the token you already hold; it decodes and verifies, it does not forge tokens or
attack a server.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Optional

# A tiny list of secrets that show up in real misconfigurations. Operators can
# pass a larger wordlist; this is only a fast first pass.
_COMMON_SECRETS = [
    "secret", "password", "changeme", "jwt_secret", "your-256-bit-secret",
    "supersecret", "admin", "test", "key", "private", "s3cr3t", "12345678",
]


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def decode(token: str) -> tuple[Optional[dict], Optional[dict], Optional[str]]:
    """Return (header, payload, error). Does not verify the signature."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None, None, "not a three-part JWT"
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, None
    except Exception as e:
        return None, None, f"could not decode: {type(e).__name__}: {e}"


def verify_hs256(token: str, secret: str) -> bool:
    """True if the token's signature matches an HS256 secret."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return False
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    try:
        actual = _b64url_decode(parts[2])
    except Exception:
        return False
    return hmac.compare_digest(expected, actual)


def crack_hs256(token: str, wordlist: Optional[list[str]] = None) -> Optional[str]:
    """Return the secret if one in the wordlist verifies the token, else None."""
    for secret in (wordlist or _COMMON_SECRETS):
        if verify_hs256(token, secret):
            return secret
    return None


_SENSITIVE_KEYS = {"password", "passwd", "secret", "ssn", "credit_card",
                   "creditcard", "card_number", "cvv", "api_key", "apikey"}


def audit(token: str, wordlist: Optional[list[str]] = None) -> list[dict]:
    """Return a list of issues: each {issue, severity, detail}."""
    header, payload, err = decode(token)
    if err:
        return [{"issue": "invalid JWT", "severity": "info", "detail": err}]
    issues: list[dict] = []
    alg = str(header.get("alg", "")).lower()

    if alg == "none":
        issues.append({"issue": "alg=none accepted", "severity": "critical",
                       "detail": "The token declares alg=none; a server honoring it "
                                 "trusts unsigned tokens (auth bypass)."})
    elif alg.startswith("hs"):
        secret = crack_hs256(token, wordlist)
        if secret:
            issues.append({"issue": "weak HMAC secret", "severity": "critical",
                           "detail": f"The HS* signature is signed with a guessable "
                                     f"secret ('{secret}'); tokens can be forged."})

    exp = payload.get("exp")
    if exp is None:
        issues.append({"issue": "no expiry (exp)", "severity": "medium",
                       "detail": "The token has no exp claim; it never expires."})
    elif isinstance(exp, (int, float)) and exp < time.time():
        issues.append({"issue": "expired token", "severity": "info",
                       "detail": f"exp is in the past ({int(exp)})."})

    hits = sorted(k for k in payload if k.lower() in _SENSITIVE_KEYS)
    if hits:
        issues.append({"issue": "sensitive data in payload", "severity": "medium",
                       "detail": f"Payload contains sensitive claim(s): {', '.join(hits)}. "
                                 "JWT payloads are readable by anyone holding the token."})
    return issues
