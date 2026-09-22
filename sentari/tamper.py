"""Request tamper and replay.

Manipulate and resend captured HTTP requests: override headers, query parameters
or the body, replay the request, and diff the new response against the original.
`fuzz` sends a parameter through a list of values and reports how the response
changes, so a difference stands out. This is the scriptable side of request
manipulation; `mitmweb` (launched from the CLI) gives the fully interactive,
point-and-edit version. It resends requests you supply; it decides nothing on
its own.
"""
from __future__ import annotations

import difflib
import ssl
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def request_from_flow(flow: dict) -> dict:
    """Turn a captured flow (proxy JSONL/HAR shape) into a request dict."""
    req = flow.get("request", {}) or {}
    return {"method": req.get("method", "GET"), "url": req.get("url", ""),
            "headers": dict(req.get("headers", {}) or {}), "body": req.get("content", "")}


def apply_mutations(request: dict, set_headers: dict | None = None,
                    set_params: dict | None = None, set_body: str | None = None) -> dict:
    """Return a copy of the request with the given overrides applied."""
    out = {"method": request.get("method", "GET"), "url": request.get("url", ""),
           "headers": dict(request.get("headers", {})), "body": request.get("body", "")}
    if set_headers:
        out["headers"].update(set_headers)
    if set_params:
        p = urlparse(out["url"])
        q = dict(parse_qsl(p.query))
        q.update(set_params)
        out["url"] = urlunparse(p._replace(query=urlencode(q)))
    if set_body is not None:
        out["body"] = set_body
    return out


def send(request: dict, timeout: int = 15) -> tuple[int, dict, str]:
    """Send a request dict. Returns (status, headers, body)."""
    sslctx = ssl.create_default_context()
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    body = request.get("body") or None
    data = body.encode() if isinstance(body, str) and body else None
    # drop hop-by-hop / length headers that urllib recomputes
    headers = {k: v for k, v in request.get("headers", {}).items()
               if k.lower() not in ("content-length", "host", "connection")}
    req = urllib.request.Request(request["url"], method=request.get("method", "GET"),
                                 data=data, headers={"User-Agent": "Sentari/0.12", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=sslctx) as resp:
            return resp.status, dict(resp.headers.items()), resp.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()) if e.headers else {}, \
            (e.read(8000).decode("utf-8", "replace") if hasattr(e, "read") else "")
    except Exception as e:
        return 0, {}, f"{type(e).__name__}: {e}"


def diff(original_body: str, new_body: str, context: int = 2) -> str:
    """A short unified diff of two response bodies."""
    o = (original_body or "").splitlines()
    n = (new_body or "").splitlines()
    lines = list(difflib.unified_diff(o, n, "original", "tampered", n=context, lineterm=""))
    return "\n".join(lines[:60])


def fuzz(request: dict, param: str, values: list[str], timeout: int = 15) -> list[dict]:
    """Send the request once per value of `param`; return response signatures."""
    out = []
    for v in values:
        mutated = apply_mutations(request, set_params={param: v})
        status, _headers, body = send(mutated, timeout)
        out.append({"value": v, "status": status, "length": len(body)})
    return out
