"""Standalone stdlib worker executed inside the sandbox to run a loopback HTTP probe.

Starts optional in-sandbox HTTP mock server + Redis/SMTP shims + Python/Node outbound
HTTP preload interceptors, boots the target server on 127.0.0.1:<port>, polls the health
endpoint, sends a loopback curl/urllib request, records intercepted outbound calls
(SSRF canary), tears down all processes cleanly, and emits JSON.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _load_local_module(mod_name: str, file_path: Path) -> Any | None:
    if not file_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(mod_name, str(file_path))
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def parse_curl_http_output(raw: str) -> tuple[int | None, dict[str, str], str]:
    """Parse raw `curl -i` output into (status_code, headers, body)."""
    parts = raw.replace("\r\n", "\n").split("\n\n")
    header_idx = 0
    for idx, block in enumerate(parts):
        if block.startswith("HTTP/"):
            header_idx = idx
    header_block = parts[header_idx] if parts else ""
    body_text = "\n\n".join(parts[header_idx + 1 :]) if len(parts) > header_idx + 1 else ""
    lines = header_block.splitlines()
    status_code: int | None = None
    if lines:
        tokens = lines[0].split()
        if len(tokens) >= 2 and tokens[1].isdigit():
            status_code = int(tokens[1])
    hdrs: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return status_code, hdrs, body_text


def main(cfg_path: str) -> None:
    cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    start_cmd: str = cfg["start_cmd"]
    port = int(cfg["port"])
    health_path: str = cfg["health_path"]
    method: str = cfg["method"]
    path: str = cfg["path"]
    headers: dict[str, str] = cfg.get("headers") or {}
    body: str | None = cfg.get("body")
    marker_file: str | None = cfg.get("setup_marker_file")
    marker_content: str = cfg.get("setup_marker_content") or ""
    mock_integrations: bool = bool(cfg.get("mock_integrations", True))
    mock_rules: list[dict[str, Any]] = cfg.get("mock_rules") or []
    mocks_strict: bool = bool(cfg.get("mocks_strict", False))
    extra_env: dict[str, str] = cfg.get("extra_env") or {}

    cwd = Path.cwd()
    base_url = f"http://127.0.0.1:{port}"
    created_marker: Path | None = None
    if marker_file:
        mp = Path(marker_file)
        if not mp.is_absolute():
            mp = cwd / mp
        mp.parent.mkdir(parents=True, exist_ok=True)
        mp.write_text(marker_content, encoding="utf-8")
        created_marker = mp

    env = os.environ.copy()
    env.update(extra_env)
    env["HOST"] = "127.0.0.1"
    env["PORT"] = str(port)

    mock_server: Any = None
    redis_shim: Any = None
    smtp_shim: Any = None

    if mock_integrations:
        mock_mod = _load_local_module("_vb_mock_srv", cwd / ".vulnbox_mock_server.py")
        if mock_mod is not None:
            mock_port = _pick_free_port()
            mock_server = mock_mod.VulnBoxMockServer(
                port=mock_port,
                rules=mock_rules,
                strict=mocks_strict,
            )
            mock_server.start()
            mock_url = f"http://127.0.0.1:{mock_port}"
            env["VULNBOX_MOCK_URL"] = mock_url
            env["HTTP_PROXY"] = mock_url
            env["NO_PROXY"] = "127.0.0.1,localhost,::1"

            py_preload_dir = cwd / ".vulnbox_http_preload"
            if py_preload_dir.is_dir():
                existing_pp = env.get("PYTHONPATH", "")
                env["PYTHONPATH"] = (
                    f"{py_preload_dir}{os.pathsep}{existing_pp}"
                    if existing_pp
                    else str(py_preload_dir)
                )

            node_preload = cwd / ".vulnbox_http_mock_preload.mjs"
            if node_preload.is_file():
                existing_no = env.get("NODE_OPTIONS", "").strip()
                import_flag = f"--import={node_preload}"
                env["NODE_OPTIONS"] = f"{existing_no} {import_flag}".strip()

        shims_mod = _load_local_module("_vb_shims", cwd / ".vulnbox_service_shims.py")
        if shims_mod is not None:
            # Start lightweight Redis + SMTP shims only when real sidecar env isn't already provided
            if "REDIS_URL" not in extra_env:
                redis_shim = shims_mod.TinyRedisShim(port=0)
                rport = redis_shim.start()
                env["REDIS_URL"] = f"redis://127.0.0.1:{rport}/0"
                env["REDIS_HOST"] = "127.0.0.1"
                env["REDIS_PORT"] = str(rport)
            if "SMTP_HOST" not in extra_env:
                smtp_shim = shims_mod.TinySmtpShim(port=0)
                sport = smtp_shim.start()
                env["SMTP_HOST"] = "127.0.0.1"
                env["SMTP_PORT"] = str(sport)

    proc = subprocess.Popen(
        ["/bin/sh", "-c", start_cmd],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )

    result: dict[str, Any] = {
        "status_code": None,
        "response_headers": {},
        "response_body_excerpt": "",
        "outbound_calls": [],
        "probe_mode": "http_server",
        "error": None,
    }

    try:
        ready = False
        deadline = time.monotonic() + 10.0
        health_url = f"{base_url}{health_path}"
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                out, err = proc.communicate(timeout=1)
                result["error"] = f"Server exited early (rc={proc.returncode}): {err or out}"
                break
            try:
                with urllib.request.urlopen(health_url, timeout=0.5) as resp:
                    if resp.status < 500:
                        ready = True
                        break
            except urllib.error.HTTPError as he:
                if he.code < 500:
                    ready = True
                    break
            except (urllib.error.URLError, OSError):
                time.sleep(0.1)

        if not ready and not result["error"]:
            result["error"] = f"Server did not become ready on {health_url} within 10s"

        if ready:
            target_url = f"{base_url}{path}"
            curl_bin = shutil.which("curl")
            if curl_bin:
                cmd = [curl_bin, "-sS", "-i", "--max-time", "8", "-X", method]
                for hk, hv in headers.items():
                    cmd.extend(["-H", f"{hk}: {hv}"])
                if body is not None:
                    cmd.extend(["--data", body])
                cmd.append(target_url)
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
                if cp.returncode != 0:
                    result["error"] = f"curl failed (rc={cp.returncode}): {cp.stderr.strip()}"
                else:
                    sc, hdrs, btxt = parse_curl_http_output(cp.stdout)
                    result["status_code"] = sc
                    result["response_headers"] = hdrs
                    result["response_body_excerpt"] = btxt[:1000]
            else:
                req = urllib.request.Request(
                    target_url,
                    data=body.encode("utf-8") if body is not None else None,
                    headers=headers,
                    method=method,
                )
                try:
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        result["status_code"] = resp.status
                        result["response_headers"] = {k.lower(): v for k, v in resp.headers.items()}
                        result["response_body_excerpt"] = resp.read(1000).decode(
                            "utf-8", errors="ignore"
                        )
                except urllib.error.HTTPError as he:
                    result["status_code"] = he.code
                    result["response_headers"] = {k.lower(): v for k, v in he.headers.items()}
                    result["response_body_excerpt"] = he.read(1000).decode(
                        "utf-8", errors="ignore"
                    )
    finally:
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except OSError:
                    pass
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
