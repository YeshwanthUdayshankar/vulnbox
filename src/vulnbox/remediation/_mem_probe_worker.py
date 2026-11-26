"""Standalone stdlib sandbox worker for active loopback memory & FD leak stress probing.

Boots the target server directly (`exec <start_cmd>`) on 127.0.0.1:<port> with Python
tracemalloc/gc or Node.js --expose-gc/HeapProfiler preload instrumentation, runs warmup
requests, then runs N measurement requests while sampling heap, RSS, and /proc/<pid>/fd.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def _read_proc_rss_and_fds(pid: int) -> tuple[int, int]:
    rss_bytes = 0
    open_fds = 0
    status_path = Path(f"/proc/{pid}/status")
    if status_path.is_file():
        try:
            for line in status_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        rss_bytes = int(parts[1]) * 1024
                    break
        except OSError:
            pass
    fd_dir = Path(f"/proc/{pid}/fd")
    if fd_dir.is_dir():
        try:
            open_fds = len(os.listdir(fd_dir))
        except OSError:
            pass
    return rss_bytes, open_fds


def _trigger_snapshot(pid: int, snap_file: Path, expected_seq: int) -> dict[str, Any] | None:
    try:
        os.kill(pid, signal.SIGUSR1)
    except OSError:
        return None
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if snap_file.is_file():
            try:
                data = json.loads(snap_file.read_text(encoding="utf-8"))
                if int(data.get("seq", 0)) >= expected_seq:
                    return data
            except (OSError, ValueError):
                pass
        time.sleep(0.05)
    return None


def _ols_slope_and_r2(xs: list[float], ys: list[float]) -> tuple[float, float]:
    n = len(xs)
    if n < 2:
        return 0.0, 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    ss_xx = sum((x - mean_x) ** 2 for x in xs)
    ss_yy = sum((y - mean_y) ** 2 for y in ys)
    if ss_xx <= 0:
        return 0.0, 0.0
    ss_xy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
    slope = ss_xy / ss_xx
    if ss_yy <= 0:
        return slope, 0.0
    r2 = (ss_xy ** 2) / (ss_xx * ss_yy)
    return float(slope), float(min(1.0, max(0.0, r2)))


def _send_http(url: str, method: str, headers: dict[str, str], body: str | None) -> None:
    req = urllib.request.Request(
        url,
        data=body.encode("utf-8") if body is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read(4096)
    except (urllib.error.HTTPError, urllib.error.URLError, OSError):
        pass


def _build_request_url(base_url: str, path: str, vary_param: str | None, idx: int) -> str:
    full = f"{base_url}{path}"
    if not vary_param:
        return full
    parsed = urllib.parse.urlsplit(full)
    qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    qs = [(k, v) for k, v in qs if k != vary_param]
    qs.append((vary_param, f"vb_{idx}"))
    new_query = urllib.parse.urlencode(qs)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))


def main(cfg_path: str) -> None:
    cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    start_cmd: str = cfg["start_cmd"]
    port = int(cfg["port"])
    health_path: str = cfg["health_path"]
    method: str = cfg["method"]
    path: str = cfg["path"]
    headers: dict[str, str] = cfg.get("headers") or {}
    body: str | None = cfg.get("body")
    vary_param: str | None = cfg.get("vary_query_param")
    warmup = int(cfg.get("warmup_requests", 10))
    measure = int(cfg.get("measure_requests", 60))
    interval = max(1, int(cfg.get("sample_interval", 15)))
    min_bpr = int(cfg.get("min_bytes_per_request", 1024))
    min_r2 = float(cfg.get("min_r_squared", 0.70))
    max_fd_delta = int(cfg.get("max_allowed_fd_delta", 5))
    snap_file = Path(cfg["snap_file"])
    py_preload_dir: str | None = cfg.get("py_preload_dir")
    node_preload_file: str | None = cfg.get("node_preload_file")
    use_sigusr1: bool = bool(cfg.get("use_sigusr1", True))
    ws_dir: str = cfg["workspace_dir"]

    env = os.environ.copy()
    env["HOST"] = "127.0.0.1"
    env["PORT"] = str(port)
    env["VULNBOX_MEM_SNAP_FILE"] = str(snap_file)
    env["VULNBOX_MEM_WORKSPACE"] = ws_dir

    if py_preload_dir:
        prev_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{py_preload_dir}:{ws_dir}:{prev_pp}" if prev_pp else f"{py_preload_dir}:{ws_dir}"
    if node_preload_file:
        prev_no = env.get("NODE_OPTIONS", "")
        inject = f"--expose-gc --import file://{node_preload_file}"
        env["NODE_OPTIONS"] = f"{prev_no} {inject}".strip()

    # Use `exec` so proc.pid is the actual Python/Node server process for SIGUSR1 & /proc/<pid>/fd
    proc = subprocess.Popen(
        ["/bin/sh", "-c", f"exec {start_cmd}"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )

    result: dict[str, Any] = {
        "samples": [],
        "bytes_per_request_slope": 0.0,
        "r_squared": 0.0,
        "total_heap_growth_bytes": 0,
        "rss_growth_bytes": 0,
        "fd_delta": 0,
        "gc_garbage_delta": 0,
        "top_allocations": [],
        "retainer_summary": "",
        "leak_detected": False,
        "error": None,
    }

    base_url = f"http://127.0.0.1:{port}"
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
            # 1. Warmup loop (+ prime snapshot handler once so profiler buffers are pre-allocated)
            for i in range(warmup):
                _send_http(_build_request_url(base_url, path, vary_param, i), method, headers, body)
            if use_sigusr1:
                _trigger_snapshot(proc.pid, snap_file, 1)

            # 2. Baseline snapshot S0
            seq = 2
            snap0 = _trigger_snapshot(proc.pid, snap_file, seq) if use_sigusr1 else None
            rss0, fd0 = _read_proc_rss_and_fds(proc.pid)
            heap0 = int(snap0["heap_bytes"]) if snap0 else rss0
            rss0 = int(snap0.get("rss_bytes", rss0)) if snap0 else rss0
            gc0 = int(snap0.get("gc_uncollectable", 0)) if snap0 else 0
            samples: list[dict[str, Any]] = [
                {
                    "iteration": 0,
                    "heap_bytes": heap0,
                    "rss_bytes": rss0,
                    "open_fds": fd0,
                    "gc_uncollectable": gc0,
                }
            ]

            last_snap = snap0
            # 3. Stress & sampling loop
            for step in range(1, measure + 1):
                _send_http(
                    _build_request_url(base_url, path, vary_param, warmup + step),
                    method,
                    headers,
                    body,
                )
                if step % interval == 0 or step == measure:
                    seq += 1
                    snap = _trigger_snapshot(proc.pid, snap_file, seq) if use_sigusr1 else None
                    rss, fds = _read_proc_rss_and_fds(proc.pid)
                    heap = int(snap["heap_bytes"]) if snap else rss
                    rss = int(snap.get("rss_bytes", rss)) if snap else rss
                    gc_u = int(snap.get("gc_uncollectable", 0)) if snap else 0
                    samples.append(
                        {
                            "iteration": step,
                            "heap_bytes": heap,
                            "rss_bytes": rss,
                            "open_fds": fds,
                            "gc_uncollectable": gc_u,
                        }
                    )
                    if snap:
                        last_snap = snap

            xs = [float(s["iteration"]) for s in samples]
            ys = [float(s["heap_bytes"]) for s in samples]
            slope, r2 = _ols_slope_and_r2(xs, ys)
            total_heap_growth = samples[-1]["heap_bytes"] - samples[0]["heap_bytes"]
            rss_growth = samples[-1]["rss_bytes"] - samples[0]["rss_bytes"]
            fd_delta = samples[-1]["open_fds"] - samples[0]["open_fds"]
            gc_delta = samples[-1]["gc_uncollectable"] - samples[0]["gc_uncollectable"]

            min_total_growth = min_bpr * max(5, measure // 4)
            heap_leaked = slope >= min_bpr and r2 >= min_r2 and total_heap_growth >= min_total_growth
            fd_leaked = fd_delta > max_fd_delta
            gc_leaked = gc_delta > 0

            result["samples"] = samples
            result["bytes_per_request_slope"] = round(slope, 2)
            result["r_squared"] = round(r2, 4)
            result["total_heap_growth_bytes"] = int(total_heap_growth)
            result["rss_growth_bytes"] = int(rss_growth)
            result["fd_delta"] = int(fd_delta)
            result["gc_garbage_delta"] = int(gc_delta)
            result["top_allocations"] = (last_snap or {}).get("top_allocations", [])
            result["retainer_summary"] = (last_snap or {}).get("retainer_summary", "")
            result["leak_detected"] = bool(heap_leaked or fd_leaked or gc_leaked)
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

    print(json.dumps(result))


if __name__ == "__main__":
    main(sys.argv[1])
