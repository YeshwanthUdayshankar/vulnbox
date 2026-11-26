"""Standalone stdlib worker executed inside the sandbox to run a loopback HTTP probe.

Starts the target server on 127.0.0.1:<port>, polls the health endpoint, sends a single
loopback curl/urllib request, tears down the server process group cleanly, and emits JSON.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


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

    base_url = f"http://127.0.0.1:{port}"
    created_marker: Path | None = None
    if marker_file:
        mp = Path(marker_file)
        if not mp.is_absolute():
            mp = Path.cwd() / mp
        mp.parent.mkdir(parents=True, exist_ok=True)
        mp.write_text(marker_content, encoding="utf-8")
        created_marker = mp

    env = os.environ.copy()
    env["HOST"] = "127.0.0.1"
    env["PORT"] = str(port)

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
        if created_marker and created_marker.exists():
            try:
                created_marker.unlink()
            except OSError:
                pass

    print(json.dumps(result))


if __name__ == "__main__":
    main(sys.argv[1])
