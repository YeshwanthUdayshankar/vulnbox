"""Sample runnable Python HTTP application with intentional test vulnerabilities."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import yaml

PUBLIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")


def parse_config(raw: str):
    """Parse YAML payload (intentionally uses FullLoader for sandbox testing)."""
    return yaml.load(raw, Loader=yaml.FullLoader)


def read_public_file(name: str) -> str:
    """Read a file from the public directory (intentionally lacks path confinement)."""
    target = os.path.join(PUBLIC_DIR, name)
    with open(target, encoding="utf-8") as fh:
        return fh.read()


def fetch_upstream_status(requests_mod, url: str):
    """Example TLS misconfiguration."""
    return requests_mod.get(url, verify=False, timeout=5)


class AppHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(200, {"status": "ok"})
            return
        if parsed.path == "/files":
            qs = parse_qs(parsed.query)
            name = (qs.get("name") or [""])[0]
            try:
                content = read_public_file(name)
            except ValueError as exc:
                self._send_json(403, {"error": str(exc)})
                return
            except OSError:
                self._send_json(404, {"error": "not found"})
                return
            body = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/parse":
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="ignore")
            try:
                data = parse_config(raw)
            except yaml.YAMLError as exc:
                self._send_json(400, {"error": f"invalid yaml: {exc}"})
                return
            self._send_json(200, {"parsed": str(data)})
            return
        self._send_json(404, {"error": "not found"})


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer((host, port), AppHandler)
    server.serve_forever()
