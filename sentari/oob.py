# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Out-of-band interaction listener.

A small HTTP server used to confirm blind vulnerabilities (SSRF, XXE) by proof:
Sentari injects a unique URL that points back here, and if the target actually
fetches it, this listener records the hit. A finding is raised only on a real
callback, so it is evidence (the server reached us), not an inference.

For a local target, bind to 127.0.0.1. For a remote target, bind to an address
the target can reach (set host explicitly) so the callback can arrive.
"""
from __future__ import annotations

import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class OOBListener:
    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.port = port
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

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
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
        return f"http://{self.host}:{self.port}/{token}"

    def hit(self, token: str) -> bool:
        return token in self._hits

    def hits(self, token: str) -> list[dict]:
        return list(self._hits.get(token, []))
