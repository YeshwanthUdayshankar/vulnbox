"""Host-side orchestrator for active sandbox memory & FD leak stress probes."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import socket
import sys
from pathlib import Path
from typing import Any

from vulnbox.models import (
    AllocationHotspot,
    Finding,
    MemoryLeakProbeResult,
    MemoryLeakProbeSpec,
    MemorySample,
)
from vulnbox.registry import PluginRegistry, default_registry
from vulnbox.sandbox.base import SandboxBackend, SandboxPolicy

_MEM_WORKER_SRC = Path(__file__).resolve().with_name("_mem_probe_worker.py")
_PY_PRELOAD_SRC = Path(__file__).resolve().with_name("_py_mem_preload.py")
_NODE_PRELOAD_SRC = Path(__file__).resolve().with_name("_node_mem_preload.mjs")

_QUERY_PARAM_RE = re.compile(
    r"""(?:qs\.get|searchParams\.get|req\.query)\s*(?:\(\s*['"]([A-Za-z0-9_-]+)['"]|\.([A-Za-z0-9_-]+))"""
)


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _infer_query_param(workspace_dir: Path, file_path: str) -> str | None:
    target = workspace_dir / file_path
    if not target.is_file():
        return None
    src = target.read_text(encoding="utf-8", errors="ignore")
    m = _QUERY_PARAM_RE.search(src)
    if m:
        return m.group(1) or m.group(2)
    return None


@default_registry.register_memory_probe("MEM-PY-001", "MEM-PY-002", "MEM-JS-001", "MEM-JS-002")
def _infer_heap_leak_probe(
    finding: Finding, workspace_dir: Path, call_graph: Any | None = None
) -> MemoryLeakProbeSpec | None:
    route = finding.metadata.get("route")
    if not route and call_graph is not None:
        route = call_graph.find_route_for_location(finding.file_path, finding.start_line)
    if not route or not str(route).startswith("/"):
        return None
    vary_param = _infer_query_param(workspace_dir, finding.file_path) or "k"
    return MemoryLeakProbeSpec(
        probe_id=f"mem-probe-{finding.finding_id}",
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        description=f"Active loopback heap-slope stress probe on {route} for {finding.rule_id}",
        method="GET",
        path=str(route),
        vary_query_param=vary_param,
        warmup_requests=70,
        measure_requests=60,
        sample_interval=15,
        min_bytes_per_request=2048,
        min_r_squared=0.70,
    )


@default_registry.register_memory_probe("MEM-PY-003", "MEM-JS-004")
def _infer_fd_leak_probe(
    finding: Finding, workspace_dir: Path, call_graph: Any | None = None
) -> MemoryLeakProbeSpec | None:
    route = finding.metadata.get("route")
    if not route and call_graph is not None:
        route = call_graph.find_route_for_location(finding.file_path, finding.start_line)
    if not route or not str(route).startswith("/"):
        return None
    return MemoryLeakProbeSpec(
        probe_id=f"fd-probe-{finding.finding_id}",
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        description=f"Active loopback file-descriptor leak probe on {route} for {finding.rule_id}",
        method="GET",
        path=str(route),
        warmup_requests=5,
        measure_requests=30,
        sample_interval=10,
        min_bytes_per_request=4096,
        max_allowed_fd_delta=5,
    )


def infer_memory_probe_for_finding(
    finding: Finding,
    workspace_dir: Path,
    call_graph: Any | None = None,
    registry: PluginRegistry | None = None,
) -> MemoryLeakProbeSpec | None:
    """Resolve a dynamic memory/FD leak probe spec for `finding` via the plugin registry."""
    reg = registry or default_registry
    inferrer = reg.get_memory_probe_inferrer(finding)
    if inferrer is None:
        return None
    return inferrer(finding, workspace_dir, call_graph)


def run_memory_leak_probe(
    workspace_dir: Path,
    backend: SandboxBackend,
    start_cmd: str,
    spec: MemoryLeakProbeSpec,
    health_path: str = "/health",
    policy: SandboxPolicy | None = None,
) -> MemoryLeakProbeResult:
    """Execute a loopback memory & FD stress probe inside the isolated sandbox."""
    if not spec.path.startswith("/"):
        raise ValueError(f"Memory probe path must be relative to 127.0.0.1: {spec.path!r}")

    pol = policy or SandboxPolicy()
    port = _pick_free_port()
    is_docker = backend.name == "docker"
    ws_in_sb = "/workspace" if is_docker else str(workspace_dir)

    probe_dir = workspace_dir / ".vulnbox_memprobe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe_dir_sb = "/workspace/.vulnbox_memprobe" if is_docker else str(probe_dir)

    worker_file = probe_dir / "_mem_probe_worker.py"
    shutil.copy2(_MEM_WORKER_SRC, worker_file)
    worker_sb = f"{probe_dir_sb}/_mem_probe_worker.py"

    py_preload_dir_sb: str | None = None
    node_preload_sb: str | None = None
    effective_start = start_cmd

    if "node" in start_cmd.split()[0]:
        node_preload = probe_dir / "_node_mem_preload.mjs"
        shutil.copy2(_NODE_PRELOAD_SRC, node_preload)
        node_preload_sb = f"{probe_dir_sb}/_node_mem_preload.mjs"
    else:
        py_dir = probe_dir / "pypreload"
        py_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(_PY_PRELOAD_SRC, py_dir / "sitecustomize.py")
        py_preload_dir_sb = f"{probe_dir_sb}/pypreload"
        if not is_docker and effective_start.startswith("python3 "):
            effective_start = f"{shlex.quote(sys.executable)} {effective_start[len('python3 ') :]}"

    snap_file_sb = f"{probe_dir_sb}/snap.json"
    cfg_file = probe_dir / "cfg.json"
    cfg_sb = f"{probe_dir_sb}/cfg.json"
    cfg_file.write_text(
        json.dumps(
            {
                "start_cmd": effective_start,
                "port": port,
                "health_path": health_path,
                "method": spec.method,
                "path": spec.path,
                "headers": spec.headers,
                "body": spec.body,
                "vary_query_param": spec.vary_query_param,
                "warmup_requests": spec.warmup_requests,
                "measure_requests": spec.measure_requests,
                "sample_interval": spec.sample_interval,
                "min_bytes_per_request": spec.min_bytes_per_request,
                "min_r_squared": spec.min_r_squared,
                "max_allowed_fd_delta": spec.max_allowed_fd_delta,
                "snap_file": snap_file_sb,
                "py_preload_dir": py_preload_dir_sb,
                "node_preload_file": node_preload_sb,
                "workspace_dir": ws_in_sb,
            }
        ),
        encoding="utf-8",
    )

    py_exe = "python3" if is_docker else sys.executable
    cmd = f"{shlex.quote(py_exe)} {shlex.quote(worker_sb)} {shlex.quote(cfg_sb)}"

    try:
        res = backend.run(workspace_dir, cmd, policy=pol)
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)

    raw_line = ""
    for line in reversed(res.stdout.splitlines()):
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            raw_line = stripped
            break

    if not raw_line:
        return MemoryLeakProbeResult(
            probe_id=spec.probe_id,
            endpoint=f"{spec.method} {spec.path}",
            error=f"Memory probe worker produced no JSON (rc={res.exit_code}): {res.stderr.strip() or res.stdout.strip()}",
        )

    data = json.loads(raw_line)
    return MemoryLeakProbeResult(
        probe_id=spec.probe_id,
        endpoint=f"{spec.method} {spec.path}",
        samples=[MemorySample.model_validate(s) for s in data.get("samples", ())],
        bytes_per_request_slope=float(data.get("bytes_per_request_slope", 0.0)),
        r_squared=float(data.get("r_squared", 0.0)),
        total_heap_growth_bytes=int(data.get("total_heap_growth_bytes", 0)),
        rss_growth_bytes=int(data.get("rss_growth_bytes", 0)),
        fd_delta=int(data.get("fd_delta", 0)),
        gc_garbage_delta=int(data.get("gc_garbage_delta", 0)),
        top_allocations=[AllocationHotspot.model_validate(a) for a in data.get("top_allocations", ())],
        retainer_summary=str(data.get("retainer_summary", "")),
        leak_detected=bool(data.get("leak_detected", False)),
        error=data.get("error"),
    )
