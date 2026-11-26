"""Sample integrated HTTP app exercising outbound APIs, Redis, HS256 JWT auth, and SSRF."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


def _load_dotenv() -> None:
    env_file = Path(__file__).resolve().with_name(".env")
    if not env_file.is_file():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        k, v = stripped.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _verify_hs256_jwt(token: str, secret: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    actual_sig = _b64url_decode(sig_b64)
    if not hmac.compare_digest(expected_sig, actual_sig):
        return None
    return json.loads(_b64url_decode(payload_b64).decode("utf-8"))


def _redis_roundtrip(host: str, port: int) -> str:
    with socket.create_connection((host, port), timeout=2.0) as sock:
        sock.sendall(b"*3\r\n$3\r\nSET\r\n$6\r\nvb_key\r\n$5\r\nhello\r\n")
        _ = sock.recv(1024)
        sock.sendall(b"*2\r\n$3\r\nGET\r\n$6\r\nvb_key\r\n")
        reply = sock.recv(1024).decode("utf-8", errors="ignore")
    lines = reply.splitlines()
    return lines[1] if len(lines) >= 2 else ""


class IntegratedHandler(BaseHTTPRequestHandler):
    def _json_response(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._json_response(200, {"ok": True})
            return

        if parsed.path == "/cache":
            rhost = os.environ.get("REDIS_HOST", "127.0.0.1")
            rport = int(os.environ.get("REDIS_PORT", "6379"))
            val = _redis_roundtrip(rhost, rport)
            self._json_response(200, {"cached": val})
            return

        if parsed.path == "/admin":
            auth = self.headers.get("Authorization") or ""
            if not auth.startswith("Bearer "):
                self._json_response(401, {"error": "missing_bearer"})
                return
            secret = os.environ.get("JWT_SECRET", "")
            claims = _verify_hs256_jwt(auth.removeprefix("Bearer ").strip(), secret)
            if claims is None:
                self._json_response(401, {"error": "invalid_token"})
                return
            self._json_response(200, {"sub": claims.get("sub"), "role": claims.get("role")})
            return

        if parsed.path == "/fetch":
            qs = parse_qs(parsed.query)
            target = (qs.get("url") or [""])[0]
            with urllib.request.urlopen(target, timeout=3) as resp:
                body = resp.read(256).decode("utf-8", errors="ignore")
            self._json_response(200, {"fetched": True, "excerpt": body[:100]})
            return

        self._json_response(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/checkout":
            with urllib.request.urlopen("https://api.stripe.com/v1/charges", timeout=3) as resp:
                charge = json.loads(resp.read().decode("utf-8"))
            self._json_response(
                200,
                {
                    "charge_id": charge["id"],
                    "charge_status": charge["charge_status"],
                    "amount": charge["amount"],
                },
            )
            return
        self._json_response(404, {"error": "not_found"})

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


def main() -> None:
    _load_dotenv()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8088"))
    server = ThreadingHTTPServer((host, port), IntegratedHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
