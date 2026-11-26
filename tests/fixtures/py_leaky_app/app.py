"""Sample Python app with dynamic getattr dispatch, unbounded cache leak, and FD leak."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DATA_FILE = Path(__file__).resolve().parent / "data.txt"
RESPONSE_CACHE: dict[str, str] = {}
_OPEN_REF_RING: list[object] = []


class Actions:
    @staticmethod
    def store_item(key: str) -> str:
        payload = "X" * 16384
        RESPONSE_CACHE[key] = payload
        return str(len(RESPONSE_CACHE))


def dispatch_action(action: str, key: str) -> str:
    """Dynamic getattr dispatch — unresolved by pure AST, captured by sys.monitoring."""
    fn = getattr(Actions, action)
    return fn(key)


def read_data_file() -> str:
    """Intentionally opens a file handle outside `with` (leaks OS FDs)."""
    fh = open(DATA_FILE, encoding="utf-8")
    if len(_OPEN_REF_RING) >= 512:
        _OPEN_REF_RING.pop(0)
    _OPEN_REF_RING.append(fh)
    return fh.read()


class LeakyHandler(BaseHTTPRequestHandler):
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
        if parsed.path == "/cache":
            qs = parse_qs(parsed.query)
            key = (qs.get("k") or ["default"])[0]
            count = dispatch_action("store_item", key)
            self._send_json(200, {"stored": key, "count": count})
            return
        if parsed.path == "/read":
            content = read_data_file()
            self._send_json(200, {"length": len(content)})
            return
        self._send_json(404, {"error": "not found"})


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer((host, port), LeakyHandler)
    server.serve_forever()
