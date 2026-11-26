"""In-sandbox loopback HTTP mock server and SSRF canary logger.

Runs on 127.0.0.1:<port> inside the air-gapped sandbox so outbound HTTP/HTTPS calls
rerouted by the Python/Node preload hooks receive HTTP 200 responses with the exact
JSON data expected by the target code, while every intercepted host/path is recorded
as an SSRF canary log.
"""

from __future__ import annotations

import fnmatch
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

MAX_OUTBOUND_LOG_ENTRIES = 256


def _match_rule(
    rules: list[dict[str, Any]],
    host: str,
    path: str,
    method: str,
    source_filter: set[str] | None = None,
) -> dict[str, Any] | None:
    low_host = host.lower().split(":")[0]
    upper_method = method.upper()
    for rule in rules:
        if source_filter is not None and rule.get("source", "user") not in source_filter:
            continue
        r_method = str(rule.get("method", "*")).upper()
        if r_method != "*" and r_method != upper_method:
            continue
        h_pat = str(rule.get("host_pattern", "*")).lower()
        if h_pat != "*" and not fnmatch.fnmatch(low_host, h_pat):
            continue
        p_pref = str(rule.get("path_prefix", "/"))
        if p_pref != "/" and not path.startswith(p_pref):
            continue
        return rule
    return None


def _builtin_protocol_response(path: str, mock_base_url: str) -> tuple[int, dict[str, Any]] | None:
    if path.startswith("/.well-known/openid-configuration"):
        return 200, {
            "issuer": mock_base_url,
            "authorization_endpoint": f"{mock_base_url}/oauth/authorize",
            "token_endpoint": f"{mock_base_url}/oauth/token",
            "userinfo_endpoint": f"{mock_base_url}/oauth/userinfo",
            "jwks_uri": f"{mock_base_url}/.well-known/jwks.json",
            "response_types_supported": ["code", "token", "id_token"],
        }
    if path.startswith("/.well-known/jwks.json"):
        return 200, {"keys": []}
    if path.startswith(("/oauth/token", "/oauth2/token")):
        return 200, {
            "access_token": "vb_mock_access_token_0123456789",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read write",
        }
    return None


class VulnBoxMockServer:
    """Threaded loopback HTTP mock server with bounded SSRF canary call recording."""

    def __init__(
        self,
        port: int,
        rules: list[dict[str, Any]],
        strict: bool = False,
        log_file: Path | None = None,
    ) -> None:
        self.port = port
        self.rules = rules
        self.strict = strict
        self.log_file = log_file
        self.mock_base_url = f"http://127.0.0.1:{port}"
        self._lock = threading.Lock()
        self._calls: list[dict[str, Any]] = []
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def outbound_calls(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._calls)

    def _record_call(
        self,
        method: str,
        host: str,
        path: str,
        matched_rule: str | None,
        status_code: int,
    ) -> None:
        entry = {
            "timestamp": round(time.time(), 3),
            "method": method,
            "host": host,
            "path": path,
            "matched_rule": matched_rule,
            "status_code": status_code,
        }
        with self._lock:
            if len(self._calls) < MAX_OUTBOUND_LOG_ENTRIES:
                self._calls.append(entry)
            if self.log_file is not None:
                try:
                    self.log_file.write_text(json.dumps(self._calls), encoding="utf-8")
                except OSError:
                    pass

    def resolve_response(
        self, method: str, host: str, path: str
    ) -> tuple[int, dict[str, str], bytes, str]:
        # Priority 1: explicit user rules (--mocks)
        rule = _match_rule(self.rules, host, path, method, source_filter={"user"})
        # Priority 2: specific inferred rules (host or non-root path)
        if rule is None:
            specific = [
                r
                for r in self.rules
                if r.get("source") == "inferred"
                and (r.get("host_pattern", "*") != "*" or r.get("path_prefix", "/") != "/")
            ]
            rule = _match_rule(specific, host, path, method)
        # Priority 3: well-known OIDC/JWKS/OAuth protocol endpoints
        if rule is None:
            proto = _builtin_protocol_response(path, self.mock_base_url)
            if proto is not None:
                st, payload = proto
                return (
                    st,
                    {"Content-Type": "application/json", "X-VulnBox-Mocked": "true"},
                    json.dumps(payload).encode("utf-8"),
                    "builtin_protocol",
                )
        # Priority 4: inferred catch-all expected-shape rule (unless --mocks-strict)
        if rule is None and not self.strict:
            rule = _match_rule(self.rules, host, path, method, source_filter={"inferred_default"})

        if rule is not None:
            status = int(rule.get("status", 200))
            hdrs = {"Content-Type": "application/json", "X-VulnBox-Mocked": "true"}
            for k, v in (rule.get("headers") or {}).items():
                hdrs[str(k)] = str(v)
            if rule.get("text_body") is not None:
                raw_body = str(rule["text_body"]).encode("utf-8")
                hdrs.setdefault("Content-Type", "text/plain; charset=utf-8")
            else:
                raw_body = json.dumps(rule.get("json_body") or {"ok": True}).encode("utf-8")
            label = f"{rule.get('source', 'rule')}:{rule.get('host_pattern', '*')}{rule.get('path_prefix', '/')}"
            return status, hdrs, raw_body, label

        if self.strict:
            payload = {"error": "unmocked_outbound_request", "host": host, "path": path}
            return (
                502,
                {"Content-Type": "application/json", "X-VulnBox-Mocked": "strict"},
                json.dumps(payload).encode("utf-8"),
                "strict_reject",
            )

        fallback = {"ok": True, "status": "ok", "mocked_by": "vulnbox", "host": host, "path": path}
        return (
            200,
            {"Content-Type": "application/json", "X-VulnBox-Mocked": "true"},
            json.dumps(fallback).encode("utf-8"),
            "default_200",
        )

    def start(self) -> None:
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                content_len = int(self.headers.get("Content-Length") or 0)
                if content_len > 0:
                    self.rfile.read(min(content_len, 65536))
                target_host = (
                    self.headers.get("X-VulnBox-Target-Host")
                    or self.headers.get("Host")
                    or "unknown"
                )
                target_path = self.headers.get("X-VulnBox-Target-Path") or self.path
                if target_path.startswith(("http://", "https://")):
                    parsed_proxy = urlparse(target_path)
                    if parsed_proxy.hostname and target_host in ("unknown", f"127.0.0.1:{parent.port}"):
                        target_host = parsed_proxy.netloc or parsed_proxy.hostname
                    target_path = parsed_proxy.path or "/"
                    if parsed_proxy.query:
                        target_path = f"{target_path}?{parsed_proxy.query}"
                status, hdrs, body, matched_rule = parent.resolve_response(
                    self.command, target_host, target_path
                )
                parent._record_call(self.command, target_host, target_path, matched_rule, status)
                self.send_response(status)
                for hk, hv in hdrs.items():
                    self.send_header(hk, hv)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                self._handle()

            def do_POST(self) -> None:  # noqa: N802
                self._handle()

            def do_PUT(self) -> None:  # noqa: N802
                self._handle()

            def do_PATCH(self) -> None:  # noqa: N802
                self._handle()

            def do_DELETE(self) -> None:  # noqa: N802
                self._handle()

            def do_HEAD(self) -> None:  # noqa: N802
                self._handle()

            def do_OPTIONS(self) -> None:  # noqa: N802
                self._handle()

            def log_message(self, format: str, *args: Any) -> None:
                return

        self._httpd = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except OSError:
                pass
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
