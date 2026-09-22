"""HTTP proxy capture and analysis.

Two parts:

  * A mitmproxy addon (written out with `write_addon`) that records each flow as
    one JSON line. Run it with `mitmdump -s <addon> --listen-port <port>` and
    route a browser or app through the proxy to capture real traffic.
  * `analyze_flows`, which reads that capture (JSONL, or a browser HAR export)
    and reports issues it can prove from the captured request/response pairs:
    JWT weaknesses, credentials or tokens sent in the clear, and insecure
    cookies.

It analyzes traffic you captured; it does not itself attack anything.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from . import jwt_audit

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_SECRET_PARAM = re.compile(r"(?i)\b(password|passwd|pwd|token|api_?key|secret|access_token)=")

ADDON = '''\
"""Sentari mitmproxy addon: write each flow as one JSON line to SENTARI_PROXY_OUT."""
import json, os
OUT = os.getenv("SENTARI_PROXY_OUT", "sentari-flows.jsonl")
def response(flow):
    try:
        rec = {
            "request": {
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": dict(flow.request.headers),
                "content": flow.request.get_text(strict=False)[:4096],
            },
            "response": {
                "status_code": flow.response.status_code,
                "headers": dict(flow.response.headers),
                "content": flow.response.get_text(strict=False)[:2048],
            },
        }
        with open(OUT, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\\n")
    except Exception:
        pass
'''


def write_addon(path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(ADDON)


def _load(path: str) -> list[dict]:
    """Load flows from JSONL (our addon) or a HAR file into a common shape."""
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()
    # HAR?
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and "log" in data:
            flows = []
            for e in data["log"].get("entries", []):
                req, resp = e.get("request", {}), e.get("response", {})
                flows.append({
                    "request": {"method": req.get("method", ""), "url": req.get("url", ""),
                                "headers": {h["name"]: h["value"] for h in req.get("headers", [])},
                                "content": (req.get("postData", {}) or {}).get("text", "")},
                    "response": {"status_code": resp.get("status", 0),
                                 "headers": {h["name"]: h["value"] for h in resp.get("headers", [])},
                                 "content": (resp.get("content", {}) or {}).get("text", "")},
                })
            return flows
    except ValueError:
        pass
    # JSONL
    flows = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                flows.append(json.loads(line))
            except ValueError:
                continue
    return flows


def analyze_flows(path: str) -> list[dict]:
    """Return issues found in captured traffic: {issue, severity, detail, location}."""
    issues: list[dict] = []
    seen_jwt: set[str] = set()
    for flow in _load(path):
        req = flow.get("request", {}) or {}
        resp = flow.get("response", {}) or {}
        url = req.get("url", "")
        is_http = urlparse(url).scheme == "http"
        req_headers = {k.lower(): v for k, v in (req.get("headers", {}) or {}).items()}
        blob = " ".join([url, json.dumps(req.get("headers", {})), req.get("content", ""),
                         json.dumps(resp.get("headers", {})), resp.get("content", "")])

        for tok in _JWT_RE.findall(blob):
            if tok in seen_jwt:
                continue
            seen_jwt.add(tok)
            for iss in jwt_audit.audit(tok):
                if iss["severity"] != "info":
                    issues.append({"issue": f"JWT weakness: {iss['issue']}",
                                   "severity": iss["severity"], "detail": iss["detail"],
                                   "location": url})

        auth = req_headers.get("authorization", "")
        if is_http and auth.lower().startswith("basic "):
            issues.append({"issue": "Credentials sent over cleartext HTTP",
                           "severity": "high",
                           "detail": "An HTTP Basic Authorization header was sent over http://.",
                           "location": url})
        if is_http and _SECRET_PARAM.search(url):
            issues.append({"issue": "Secret in URL over HTTP", "severity": "medium",
                           "detail": "A password/token appears in a query string sent over http://.",
                           "location": url})

        for cookie in _set_cookies(resp.get("headers", {}) or {}):
            low = cookie.lower()
            if "secure" not in low or "httponly" not in low:
                issues.append({"issue": "Insecure cookie flags", "severity": "low",
                               "detail": f"Set-Cookie missing Secure/HttpOnly: {cookie.split('=')[0]}",
                               "location": url})
    return issues


def _set_cookies(headers: dict) -> list[str]:
    return [v for k, v in headers.items() if k.lower() == "set-cookie"]
