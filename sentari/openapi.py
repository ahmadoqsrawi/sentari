# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""API spec ingestion: OpenAPI v3, Swagger v2, and Postman collections.

Reads a spec (a local file or a URL) and extracts the concrete request URLs it
describes, so the API surface an app publishes becomes scan targets instead of
being guessed. JSON is parsed with the standard library; YAML specs need pyyaml
(pip install "sentari[api]"). It reads the spec; it invents no endpoints.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Optional
from urllib.parse import urljoin, urlparse


def load_spec(src: str) -> tuple[Optional[dict], Optional[str]]:
    """Load a spec from a path or URL. Returns (spec, error)."""
    try:
        if src.startswith(("http://", "https://")):
            with urllib.request.urlopen(src, timeout=20) as resp:
                raw = resp.read().decode("utf-8", "replace")
        else:
            with open(src, encoding="utf-8") as fh:
                raw = fh.read()
    except Exception as e:
        return None, f"could not read spec: {type(e).__name__}: {e}"
    try:
        return json.loads(raw), None
    except ValueError:
        pass
    try:
        import yaml  # optional
    except Exception:
        return None, "spec is not JSON and pyyaml is not installed (pip install \"sentari[api]\")"
    try:
        return yaml.safe_load(raw), None
    except Exception as e:
        return None, f"could not parse YAML spec: {e}"


def extract_endpoints(spec: dict, base_url: Optional[str] = None) -> list[str]:
    """Return absolute request URLs described by the spec, de-duplicated."""
    if not isinstance(spec, dict):
        return []
    if "swagger" in spec and "paths" in spec:
        urls = _from_swagger2(spec, base_url)
    elif "openapi" in spec or ("paths" in spec and "info" in spec):
        urls = _from_openapi3(spec, base_url)
    elif "item" in spec and "info" in spec:
        urls = _from_postman(spec)
    else:
        urls = _from_openapi3(spec, base_url)  # best effort
    seen, out = set(), []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _from_openapi3(spec: dict, base_url: Optional[str]) -> list[str]:
    servers = [s.get("url", "") for s in (spec.get("servers") or []) if s.get("url")]
    bases = [base_url] if base_url else (servers or [""])
    out = []
    for path in (spec.get("paths") or {}):
        for b in bases:
            out.append(_joinpath(b, path))
    return out


def _from_swagger2(spec: dict, base_url: Optional[str]) -> list[str]:
    if base_url:
        base = base_url
    else:
        scheme = (spec.get("schemes") or ["https"])[0]
        host = spec.get("host", "")
        basepath = spec.get("basePath", "")
        base = f"{scheme}://{host}{basepath}" if host else basepath
    return [_joinpath(base, path) for path in (spec.get("paths") or {})]


def _from_postman(spec: dict) -> list[str]:
    out: list[str] = []

    def walk(items):
        for it in items or []:
            if "item" in it:
                walk(it["item"])
                continue
            url = ((it.get("request") or {}).get("url"))
            if isinstance(url, dict):
                raw = url.get("raw") or ""
            else:
                raw = url or ""
            raw = raw.split("?")[0].replace("{{baseUrl}}", "").strip()
            if raw:
                out.append(raw)

    walk(spec.get("item"))
    return out


def _joinpath(base: str, path: str) -> str:
    if not base:
        return path
    if base.endswith("/") and path.startswith("/"):
        return base[:-1] + path
    if not base.endswith("/") and not path.startswith("/"):
        return base + "/" + path
    return base + path


def hosts_of(urls: list[str]) -> set[str]:
    """The distinct hostnames the endpoints touch (for scope review)."""
    return {urlparse(u).hostname for u in urls if urlparse(u).hostname}
