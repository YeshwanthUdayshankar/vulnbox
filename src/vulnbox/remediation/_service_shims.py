"""Zero-container stdlib loopback service shims (Redis RESP2 + SMTP sink).

Runs strictly on 127.0.0.1:<ephemeral_port> inside the sandbox during active probes
so apps expecting a Redis cache or SMTP mailer boot and serve requests cleanly inside
`--network=none` without requiring external containers.
"""

from __future__ import annotations

import socketserver
import threading
from collections import OrderedDict
from typing import Any

MAX_REDIS_KEYS = 512
MAX_SMTP_MESSAGES = 64


def _read_resp_command(rfile: Any) -> list[str] | None:
    """Parse one RESP2 array or inline command from a socket file-like stream."""
    line = rfile.readline(65536)
    if not line:
        return None
    if line.startswith(b"*"):
        try:
            count = int(line[1:].strip())
        except ValueError:
            return []
        args: list[str] = []
        for _ in range(max(0, min(count, 64))):
            len_line = rfile.readline(65536)
            if not len_line or not len_line.startswith(b"$"):
                break
            try:
                blen = int(len_line[1:].strip())
            except ValueError:
                break
            if blen < 0:
                args.append("")
                continue
            payload = rfile.read(blen + 2)
            args.append(payload[:blen].decode("utf-8", errors="ignore"))
        return args
    decoded = line.decode("utf-8", errors="ignore").strip()
    return decoded.split() if decoded else []


class _ReuseTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TinyRedisShim:
    """Minimal stdlib RESP2 Redis emulator bound to 127.0.0.1 with bounded O(1) memory."""

    def __init__(self, port: int = 0) -> None:
        self._requested_port = port
        self._lock = threading.Lock()
        self._store: OrderedDict[str, str] = OrderedDict()
        self._server: _ReuseTCPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int = port

    def _set_key(self, key: str, value: str) -> None:
        with self._lock:
            self._store[key] = value
            self._store.move_to_end(key)
            while len(self._store) > MAX_REDIS_KEYS:
                self._store.popitem(last=False)

    def _get_key(self, key: str) -> str | None:
        with self._lock:
            return self._store.get(key)

    def _del_keys(self, keys: list[str]) -> int:
        removed = 0
        with self._lock:
            for k in keys:
                if k in self._store:
                    del self._store[k]
                    removed += 1
        return removed

    def _incr_key(self, key: str) -> int:
        with self._lock:
            cur = self._store.get(key, "0")
            try:
                val = int(cur) + 1
            except ValueError:
                val = 1
            self._store[key] = str(val)
            self._store.move_to_end(key)
            while len(self._store) > MAX_REDIS_KEYS:
                self._store.popitem(last=False)
            return val

    def start(self) -> int:
        shim = self

        class RedisHandler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                while True:
                    try:
                        cmd_parts = _read_resp_command(self.rfile)
                    except OSError:
                        break
                    if cmd_parts is None:
                        break
                    if not cmd_parts:
                        continue
                    op = cmd_parts[0].upper()
                    if op == "PING":
                        if len(cmd_parts) > 1:
                            msg = cmd_parts[1].encode("utf-8")
                            self.wfile.write(f"${len(msg)}\r\n".encode("ascii") + msg + b"\r\n")
                        else:
                            self.wfile.write(b"+PONG\r\n")
                    elif op == "SET" and len(cmd_parts) >= 3:
                        shim._set_key(cmd_parts[1], cmd_parts[2])
                        self.wfile.write(b"+OK\r\n")
                    elif op == "GET" and len(cmd_parts) >= 2:
                        val = shim._get_key(cmd_parts[1])
                        if val is None:
                            self.wfile.write(b"$-1\r\n")
                        else:
                            raw = val.encode("utf-8")
                            self.wfile.write(f"${len(raw)}\r\n".encode("ascii") + raw + b"\r\n")
                    elif op == "DEL":
                        n = shim._del_keys(cmd_parts[1:])
                        self.wfile.write(f":{n}\r\n".encode("ascii"))
                    elif op == "EXISTS" and len(cmd_parts) >= 2:
                        exists = 1 if shim._get_key(cmd_parts[1]) is not None else 0
                        self.wfile.write(f":{exists}\r\n".encode("ascii"))
                    elif op == "INCR" and len(cmd_parts) >= 2:
                        nv = shim._incr_key(cmd_parts[1])
                        self.wfile.write(f":{nv}\r\n".encode("ascii"))
                    elif op in ("EXPIRE", "PEXPIRE", "TTL", "PTTL"):
                        self.wfile.write(b":1\r\n")
                    elif op == "INFO":
                        info = b"# Server\r\nredis_version:7.0.0-vulnbox-shim\r\n"
                        self.wfile.write(f"${len(info)}\r\n".encode("ascii") + info + b"\r\n")
                    elif op == "QUIT":
                        self.wfile.write(b"+OK\r\n")
                        break
                    else:
                        self.wfile.write(b"+OK\r\n")
                    self.wfile.flush()

        self._server = _ReuseTCPServer(("127.0.0.1", self._requested_port), RedisHandler)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except OSError:
                pass
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None


class TinySmtpShim:
    """Minimal stdlib RFC 5321 SMTP sink bound to 127.0.0.1 (discards mail safely)."""

    def __init__(self, port: int = 0) -> None:
        self._requested_port = port
        self._lock = threading.Lock()
        self._received_count = 0
        self._server: _ReuseTCPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int = port

    @property
    def received_count(self) -> int:
        with self._lock:
            return self._received_count

    def start(self) -> int:
        shim = self

        class SmtpHandler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                self.wfile.write(b"220 vulnbox-smtp-shim ESMTP Ready\r\n")
                self.wfile.flush()
                in_data = False
                while True:
                    try:
                        raw_line = self.rfile.readline(65536)
                    except OSError:
                        break
                    if not raw_line:
                        break
                    if in_data:
                        if raw_line.strip() == b".":
                            in_data = False
                            with shim._lock:
                                if shim._received_count < MAX_SMTP_MESSAGES:
                                    shim._received_count += 1
                            self.wfile.write(b"250 OK queued\r\n")
                            self.wfile.flush()
                        continue
                    upper = raw_line.decode("utf-8", errors="ignore").strip().upper()
                    if upper.startswith(("EHLO", "HELO")):
                        self.wfile.write(b"250-vulnbox-smtp-shim\r\n250 OK\r\n")
                    elif upper.startswith("DATA"):
                        in_data = True
                        self.wfile.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    elif upper.startswith("QUIT"):
                        self.wfile.write(b"221 Bye\r\n")
                        self.wfile.flush()
                        break
                    else:
                        self.wfile.write(b"250 OK\r\n")
                    self.wfile.flush()

        self._server = _ReuseTCPServer(("127.0.0.1", self._requested_port), SmtpHandler)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except OSError:
                pass
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
