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

import socket
import threading
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
