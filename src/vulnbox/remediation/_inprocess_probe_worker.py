"""In-process ASGI/WSGI (FastAPI/Starlette/Flask) probe worker executed inside the sandbox.

Fallback when a Python repository has no standalone server `start_cmd` or cannot
boot a full TCP server, yet exposes a FastAPI/Starlette/Flask `app` instance that
can be probed directly in-process via `TestClient` / `app.test_client()`.
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

_CANDIDATE_FILES = (
    "app.py",
    "main.py",
    "server.py",
    "api.py",
    "wsgi.py",
    "asgi.py",
    "src/app.py",
    "src/main.py",
    "app/main.py",
)
_CANDIDATE_ATTRS = ("app", "application", "api")


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _discover_app(cwd: Path) -> tuple[Any, str] | None:
    if str(cwd) not in sys.path:
        sys.path.insert(0, str(cwd))
    for rel in _CANDIDATE_FILES:
        fpath = cwd / rel
        if not fpath.is_file():
            continue
        mod_name = f"_vb_inproc_{fpath.stem}"
        spec = importlib.util.spec_from_file_location(mod_name, str(fpath))
        if spec is None or spec.loader is None:
            continue
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for attr in _CANDIDATE_ATTRS:
            obj = getattr(mod, attr, None)
            if obj is None:
                continue
            cls_mod = type(obj).__module__.lower()
            if any(fw in cls_mod for fw in ("fastapi", "starlette", "flask")):
                return obj, f"{rel}:{attr}"
    return None


def _dispatch_request(
    app: Any,
    method: str,
    path: str,
    headers: dict[str, str],
    body: str | None,
) -> tuple[int, dict[str, str], str]:
    cls_mod = type(app).__module__.lower()
    if "flask" in cls_mod:
        client = app.test_client()
        resp = client.open(
            path,
            method=method,
            headers=headers,
            data=body.encode("utf-8") if body is not None else None,
        )
        res_headers = {k.lower(): v for k, v in resp.headers.items()}
        return int(resp.status_code), res_headers, resp.get_data(as_text=True)[:1000]

    # FastAPI / Starlette
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        from starlette.testclient import TestClient

    with TestClient(app) as client:
        resp = client.request(
            method=method,
            url=path,
            headers=headers,
            content=body.encode("utf-8") if body is not None else None,
        )
        res_headers = {k.lower(): v for k, v in resp.headers.items()}
        return int(resp.status_code), res_headers, resp.text[:1000]


def main(cfg_path: str) -> None:
    cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    method: str = cfg["method"]
    path: str = cfg["path"]
    headers: dict[str, str] = cfg.get("headers") or {}
    body: str | None = cfg.get("body")
    marker_file: str | None = cfg.get("setup_marker_file")
    marker_content: str = cfg.get("setup_marker_content") or ""
    mock_integrations: bool = bool(cfg.get("mock_integrations", True))
    mock_rules: list[dict[str, Any]] = cfg.get("mock_rules") or []
    mocks_strict: bool = bool(cfg.get("mocks_strict", False))

    cwd = Path.cwd()
    created_marker: Path | None = None
    if marker_file:
        mp = Path(marker_file)
        if not mp.is_absolute():
            mp = cwd / mp
        mp.parent.mkdir(parents=True, exist_ok=True)
        mp.write_text(marker_content, encoding="utf-8")
        created_marker = mp

    mock_server: Any = None
    redis_shim: Any = None
    smtp_shim: Any = None

    result: dict[str, Any] = {
        "status_code": None,
        "response_headers": {},
        "response_body_excerpt": "",
        "outbound_calls": [],
        "probe_mode": "in_process",
        "error": None,
    }

    try:
        if mock_integrations:
            mock_mod_path = cwd / ".vulnbox_mock_server.py"
            if mock_mod_path.is_file():
                spec = importlib.util.spec_from_file_location("_vb_mock_srv", str(mock_mod_path))
                if spec and spec.loader:
                    mmod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mmod)
                    mport = _pick_free_port()
                    mock_server = mmod.VulnBoxMockServer(
                        port=mport, rules=mock_rules, strict=mocks_strict
                    )
                    mock_server.start()
                    os.environ["VULNBOX_MOCK_URL"] = f"http://127.0.0.1:{mport}"

            preload_path = cwd / ".vulnbox_http_preload" / "sitecustomize.py"
            if preload_path.is_file():
                pspec = importlib.util.spec_from_file_location("_vb_preload", str(preload_path))
                if pspec and pspec.loader:
                    pmod = importlib.util.module_from_spec(pspec)
                    pspec.loader.exec_module(pmod)

            shims_path = cwd / ".vulnbox_service_shims.py"
            if shims_path.is_file():
                sspec = importlib.util.spec_from_file_location("_vb_shims", str(shims_path))
                if sspec and sspec.loader:
                    smod = importlib.util.module_from_spec(sspec)
                    sspec.loader.exec_module(smod)
                    redis_shim = smod.TinyRedisShim(port=0)
                    rport = redis_shim.start()
                    smtp_shim = smod.TinySmtpShim(port=0)
                    sport = smtp_shim.start()
                    os.environ.setdefault("REDIS_URL", f"redis://127.0.0.1:{rport}/0")
                    os.environ.setdefault("REDIS_HOST", "127.0.0.1")
                    os.environ.setdefault("REDIS_PORT", str(rport))
                    os.environ.setdefault("SMTP_HOST", "127.0.0.1")
                    os.environ.setdefault("SMTP_PORT", str(sport))

        discovered = _discover_app(cwd)
        if discovered is None:
            result["error"] = "No FastAPI/Starlette/Flask app instance discovered for in-process probe"
        else:
            app_obj, _origin = discovered
            sc, hdrs, excerpt = _dispatch_request(app_obj, method, path, headers, body)
            result["status_code"] = sc
            result["response_headers"] = hdrs
            result["response_body_excerpt"] = excerpt
    except Exception as exc:
        result["error"] = f"In-process probe error ({type(exc).__name__}): {exc}"
    finally:
        if mock_server is not None:
            result["outbound_calls"] = mock_server.outbound_calls
            mock_server.stop()
        if redis_shim is not None:
            redis_shim.stop()
        if smtp_shim is not None:
            smtp_shim.stop()
        if created_marker and created_marker.exists():
            try:
                created_marker.unlink()
            except OSError:
                pass

    print(json.dumps(result))


if __name__ == "__main__":
    main(sys.argv[1])
