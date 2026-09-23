# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Out-of-band interaction listener.

A small HTTP server used to confirm blind vulnerabilities (SSRF, XXE) by proof:
Sentari injects a unique URL that points back here, and if the target actually
fetches it, this listener records the hit. A finding is raised only on a real
callback, so it is evidence (the server reached us), not an inference.

For a local target, bind to 127.0.0.1. For a remote (external) target, the
callback must be reachable from the public internet, so advertise a public host
(``host``) on a fixed ``port`` you have opened in the firewall, and bind to all
interfaces (``bind='0.0.0.0'``). ``detect_public_host`` finds the VPS public IP.
"""
from __future__ import annotations

import json
import socket
import threading
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def detect_public_host(timeout: int = 5) -> str | None:
    """Best-effort public IP of this host, for OOB callbacks from the internet.

    Tries a few echo services, then falls back to the outbound-socket address.
    Returns None if nothing works (e.g. no network)."""
    import urllib.request
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip",
                "https://icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                ip = r.read().decode().strip()
                if ip and len(ip) <= 45:
                    return ip
        except Exception:
            continue
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


class OOBListener:
    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 bind: str | None = None) -> None:
        self.host = host              # advertised in the callback URL
        self.port = port              # 0 picks a random free port
        self.bind = bind or host      # interface actually listened on
        self._hits: dict[str, list[dict]] = {}
        self._httpd = None
        self._thread = None

    def __enter__(self) -> "OOBListener":
        hits = self._hits

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _record(self):
                token = self.path.strip("/").split("/")[0].split("?")[0]
                hits.setdefault(token, []).append(
                    {"path": self.path, "from": self.client_address[0],
                     "ua": self.headers.get("User-Agent", "")})
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def do_GET(self):
                self._record()

            def do_POST(self):
                self._record()

        # bind IPv6 when the bind address is an IPv6 literal; default is IPv4
        class _Server(ThreadingHTTPServer):
            address_family = socket.AF_INET6 if ":" in self.bind else socket.AF_INET
            allow_reuse_address = True

        self._httpd = _Server((self.bind, self.port), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *a) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()

    def token(self) -> str:
        return "oob" + uuid.uuid4().hex[:12]

    def url(self, token: str) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host  # bracket IPv6
        return f"http://{host}:{self.port}/{token}"

    def hit(self, token: str) -> bool:
        return token in self._hits

    def hits(self, token: str) -> list[dict]:
        return list(self._hits.get(token, []))


class RemoteOOB:
    """Client for a shared, hosted OOB service (`sentari serve-oob`).

    Same interface as OOBListener, but callbacks land on a central collaborator
    that all scans/tenants share, so no per-scan port needs opening. Tokens map
    to `<base>/<token>`; hits are polled from `<base>/api/hits/<token>`."""
    def __init__(self, base_url: str) -> None:
        self.base = base_url.rstrip("/")

    def __enter__(self) -> "RemoteOOB":
        return self

    def __exit__(self, *a) -> None:
        pass

    def token(self) -> str:
        return "oob" + uuid.uuid4().hex[:12]

    def url(self, token: str) -> str:
        return f"{self.base}/{token}"

    def _fetch(self, token: str) -> list[dict]:
        try:
            with urllib.request.urlopen(f"{self.base}/api/hits/{token}", timeout=10) as r:
                return json.loads(r.read()).get("hits", []) or []
        except Exception:
            return []

    def hit(self, token: str) -> bool:
        return bool(self._fetch(token))

    def hits(self, token: str) -> list[dict]:
        return self._fetch(token)


def make(options: dict | None = None):
    """Return an OOB listener/client for a run: a shared hosted service when
    options['oob_service'] is set, otherwise a local in-process listener."""
    options = options or {}
    svc = options.get("oob_service")
    if svc:
        return RemoteOOB(svc)
    return OOBListener(host=options.get("oob_host", "127.0.0.1"),
                       port=int(options.get("oob_port", 0)),
                       bind=options.get("oob_bind"))


def make_oob_server(host: str, port: int) -> ThreadingHTTPServer:
    """Build (but do not start) the shared OOB collaborator HTTP server."""
    hits: dict[str, list[dict]] = {}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _record(self):
            token = self.path.strip("/").split("/")[0].split("?")[0]
            with lock:
                hits.setdefault(token, []).append(
                    {"path": self.path, "from": self.client_address[0],
                     "ua": self.headers.get("User-Agent", "")})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def do_GET(self):
            if self.path.startswith("/api/hits/"):
                tok = self.path[len("/api/hits/"):].strip("/")
                with lock:
                    data = json.dumps({"token": tok, "hits": hits.get(tok, [])}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            self._record()

        def do_POST(self):
            self._record()

    class _Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        allow_reuse_address = True

    return _Server((host, port), Handler)


def serve_oob(host: str = "0.0.0.0", port: int = 8611) -> None:
    """Run a persistent, shared OOB collaborator service.

    Any request to `/<token>` is recorded as a callback for that token; a scan
    polls `GET /api/hits/<token>` to confirm an SSRF/XXE/command-injection hit.
    Hits are held in memory (one long-running process); front it with TLS and
    keep the callback port reachable from the internet."""
    httpd = make_oob_server(host, port)
    print(f"Sentari OOB collaborator on http://{host}:{port}  "
          f"(callbacks -> /<token>, poll /api/hits/<token>)")
    print("Point scans at it with --oob-service http://<public-host>:%d" % port)
    print("Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
