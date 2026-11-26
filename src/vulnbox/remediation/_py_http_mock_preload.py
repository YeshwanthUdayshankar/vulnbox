"""Zero-edit Python outbound HTTP/HTTPS preload hook for air-gapped mocking.

Installed as `sitecustomize.py` inside a temporary directory prepended to PYTHONPATH
only during active sandbox probes. Redirects non-loopback `http.client`, `urllib`,
`requests`, and `httpx` requests to `VULNBOX_MOCK_URL` on 127.0.0.1 while tagging
`X-VulnBox-Target-Host` and `X-VulnBox-Target-Path` for expected-shape mocking and
SSRF canary detection.
"""

from __future__ import annotations

import http.client
import os
import socket
from typing import Any
from urllib.parse import urlparse

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _install_http_mock_hooks() -> None:
    mock_url = os.environ.get("VULNBOX_MOCK_URL")
    if not mock_url:
        return

    parsed_mock = urlparse(mock_url)
    mock_host = parsed_mock.hostname or "127.0.0.1"
    mock_port = parsed_mock.port or 18080

    # 1. Patch stdlib http.client.HTTPConnection & HTTPSConnection (covers urllib & http.client)
    orig_http_init = http.client.HTTPConnection.__init__
    orig_http_putrequest = http.client.HTTPConnection.putrequest
    orig_http_endheaders = http.client.HTTPConnection.endheaders
    orig_https_init = http.client.HTTPSConnection.__init__
    orig_https_connect = http.client.HTTPSConnection.connect

    def _patched_http_init(
        self: Any, host: str, port: int | None = None, *args: Any, **kwargs: Any
    ) -> None:
        clean_host = (host or "").strip("[]").lower()
        if clean_host and clean_host not in _LOOPBACK_HOSTS:
            self._vb_orig_host = f"{host}:{port}" if port else host
            self._vb_rerouted = True
            orig_http_init(self, mock_host, mock_port, *args, **kwargs)
        else:
            self._vb_rerouted = False
            orig_http_init(self, host, port, *args, **kwargs)

    def _patched_https_init(
        self: Any, host: str, port: int | None = None, *args: Any, **kwargs: Any
    ) -> None:
        clean_host = (host or "").strip("[]").lower()
        if clean_host and clean_host not in _LOOPBACK_HOSTS:
            orig_https_init(self, mock_host, mock_port, *args, **kwargs)
            self._vb_orig_host = f"{host}:{port}" if port else host
            self._vb_rerouted = True
        else:
            orig_https_init(self, host, port, *args, **kwargs)
            self._vb_rerouted = False

    def _patched_https_connect(self: Any) -> None:
        if getattr(self, "_vb_rerouted", False):
            self.sock = socket.create_connection((mock_host, mock_port), self.timeout)
            return
        orig_https_connect(self)

    def _patched_putrequest(
        self: Any, method: str, url: str, *args: Any, **kwargs: Any
    ) -> None:
        if getattr(self, "_vb_rerouted", False):
            self._vb_target_path = url
        orig_http_putrequest(self, method, url, *args, **kwargs)

    def _patched_endheaders(self: Any, *args: Any, **kwargs: Any) -> None:
        if getattr(self, "_vb_rerouted", False):
            self.putheader("X-VulnBox-Target-Host", getattr(self, "_vb_orig_host", "unknown"))
            self.putheader("X-VulnBox-Target-Path", getattr(self, "_vb_target_path", "/"))
        orig_http_endheaders(self, *args, **kwargs)

    http.client.HTTPConnection.__init__ = _patched_http_init  # type: ignore[method-assign]
    http.client.HTTPSConnection.__init__ = _patched_https_init  # type: ignore[method-assign]
    http.client.HTTPSConnection.connect = _patched_https_connect  # type: ignore[method-assign]
    http.client.HTTPConnection.putrequest = _patched_putrequest  # type: ignore[method-assign]
    http.client.HTTPConnection.endheaders = _patched_endheaders  # type: ignore[method-assign]

    # 2. Patch requests.Session.request if installed
    try:
        import requests  # type: ignore[import-not-found]

        orig_req = requests.Session.request

        def _patched_requests_request(
            self: Any, method: str, url: str, *args: Any, **kwargs: Any
        ) -> Any:
            p = urlparse(str(url))
            if p.scheme in ("http", "https") and (p.hostname or "").lower() not in _LOOPBACK_HOSTS:
                headers = dict(kwargs.get("headers") or {})
                headers["X-VulnBox-Target-Host"] = p.netloc or p.hostname or "unknown"
                target_path = p.path or "/"
                if p.query:
                    target_path = f"{target_path}?{p.query}"
                headers["X-VulnBox-Target-Path"] = target_path
                kwargs["headers"] = headers
                url = f"http://{mock_host}:{mock_port}{target_path}"
            return orig_req(self, method, url, *args, **kwargs)

        requests.Session.request = _patched_requests_request  # type: ignore[method-assign]
    except Exception:
        pass

    # 3. Patch httpx.Client.send & httpx.AsyncClient.send if installed
    try:
        import httpx  # type: ignore[import-not-found]

        orig_send = httpx.Client.send

        def _rewrite_httpx_request(request: Any) -> Any:
            host = (request.url.host or "").lower()
            if host and host not in _LOOPBACK_HOSTS:
                raw_path = request.url.raw_path.decode("ascii", errors="ignore") or "/"
                request.headers["X-VulnBox-Target-Host"] = host
                request.headers["X-VulnBox-Target-Path"] = raw_path
                request.url = httpx.URL(f"http://{mock_host}:{mock_port}{raw_path}")
            return request

        def _patched_httpx_send(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
            return orig_send(self, _rewrite_httpx_request(request), *args, **kwargs)

        httpx.Client.send = _patched_httpx_send  # type: ignore[method-assign]

        orig_async_send = httpx.AsyncClient.send

        async def _patched_httpx_async_send(
            self: Any, request: Any, *args: Any, **kwargs: Any
        ) -> Any:
            return await orig_async_send(self, _rewrite_httpx_request(request), *args, **kwargs)

        httpx.AsyncClient.send = _patched_httpx_async_send  # type: ignore[method-assign]
    except Exception:
        pass


_install_http_mock_hooks()
