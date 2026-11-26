"""Pluggable, fault-tolerant memory & FD profiler adapters with graceful degradation.

Adapters are checked in priority order via `PluginRegistry`:
  1. `python-tracemalloc` (priority 100): Python stdlib tracemalloc + gc + /proc/<pid>/fd
  2. `node-v8-inspector`  (priority 100): Node.js >=20.6 --expose-gc + V8 HeapProfiler + /proc/<pid>/fd
  3. `os-proc-fallback`   (priority  10): Runtime-agnostic Linux /proc VmRSS + /proc/<pid>/fd

If no profiler is compatible with the host OS or target runtime (e.g. local sandbox on
Windows without SIGUSR1 or /proc), VulnBox degrades gracefully with `skipped=True`
instead of failing scans or patch verification.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from vulnbox.registry import PluginRegistry, default_registry

_PY_PRELOAD_SRC = Path(__file__).resolve().with_name("_py_mem_preload.py")
_NODE_PRELOAD_SRC = Path(__file__).resolve().with_name("_node_mem_preload.mjs")


def _posix_local_supported() -> tuple[bool, str]:
    if not hasattr(signal, "SIGUSR1"):
        return False, "SIGUSR1 is unavailable on this OS (use --backend docker for memory profiling)"
    if not Path("/bin/sh").exists():
        return False, "/bin/sh is unavailable on this OS (use --backend docker)"
    return True, "ok"


def _node_supports_import_flag() -> tuple[bool, str]:
    node_bin = shutil.which("node")
    if not node_bin:
        return False, "node binary not found on PATH"
    try:
        proc = subprocess.run(
            [node_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        m = re.match(r"v?(\d+)\.(\d+)", proc.stdout.strip())
        if not m:
            return False, f"unrecognized node version output: {proc.stdout.strip()!r}"
        major, minor = int(m.group(1)), int(m.group(2))
        if (major, minor) < (20, 6):
            return False, f"Node v{major}.{minor} does not support --import preload (requires >=20.6)"
        return True, "ok"
    except OSError as exc:
        return False, f"unable to probe node version: {exc}"


class PythonTracemallocProfiler:
    """Memory & FD profiler for Python apps using stdlib tracemalloc + gc + SIGUSR1."""

    name = "python-tracemalloc"
    priority = 100

    def check_compatibility(self, start_cmd: str, backend_name: str) -> tuple[bool, str]:
        tokens = shlex.split(start_cmd) if start_cmd.strip() else []
        if not tokens:
            return False, "empty start command"
        exe = Path(tokens[0]).name.lower()
        if not (exe.startswith("python") or exe in ("uvicorn", "gunicorn", "flask")):
            return False, f"not a Python command ({exe})"
        if backend_name != "docker":
            ok, reason = _posix_local_supported()
            if not ok:
                return False, reason
        return True, "compatible"

    def prepare_sandbox(
        self,
        probe_dir: Path,
        probe_dir_sb: str,
        start_cmd: str,
        is_docker: bool,
    ) -> dict[str, Any]:
        py_dir = probe_dir / "pypreload"
        py_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(_PY_PRELOAD_SRC, py_dir / "sitecustomize.py")
        effective_start = start_cmd
        if not is_docker and effective_start.startswith("python3 "):
            effective_start = f"{shlex.quote(sys.executable)} {effective_start[len('python3 ') :]}"
        return {
            "start_cmd": effective_start,
            "py_preload_dir": f"{probe_dir_sb}/pypreload",
            "node_preload_file": None,
            "use_sigusr1": True,
        }


class NodeV8Profiler:
    """Memory & FD profiler for Node.js apps using --expose-gc + node:inspector HeapProfiler."""

    name = "node-v8-inspector"
    priority = 100

    def check_compatibility(self, start_cmd: str, backend_name: str) -> tuple[bool, str]:
        tokens = shlex.split(start_cmd) if start_cmd.strip() else []
        if not tokens:
            return False, "empty start command"
        exe = Path(tokens[0]).name.lower()
        if exe not in ("node", "nodejs"):
            return False, f"not a Node.js command ({exe})"
        if backend_name != "docker":
            ok, reason = _posix_local_supported()
            if not ok:
                return False, reason
            n_ok, n_reason = _node_supports_import_flag()
            if not n_ok:
                return False, n_reason
        return True, "compatible"

    def prepare_sandbox(
        self,
        probe_dir: Path,
        probe_dir_sb: str,
        start_cmd: str,
        is_docker: bool,
    ) -> dict[str, Any]:
        shutil.copy2(_NODE_PRELOAD_SRC, probe_dir / "_node_mem_preload.mjs")
        return {
            "start_cmd": start_cmd,
            "py_preload_dir": None,
            "node_preload_file": f"{probe_dir_sb}/_node_mem_preload.mjs",
            "use_sigusr1": True,
        }


class OSProcFallbackProfiler:
    """Language-agnostic fallback monitoring Linux /proc/<pid>/status (VmRSS) and /proc/<pid>/fd."""

    name = "os-proc-fallback"
    priority = 10

    def check_compatibility(self, start_cmd: str, backend_name: str) -> tuple[bool, str]:
        if not start_cmd.strip():
            return False, "empty start command"
        if backend_name == "docker":
            return True, "compatible (Linux Docker /proc)"
        if os.name != "posix" or not Path("/proc/self/status").is_file() or not Path("/bin/sh").exists():
            return False, "/proc filesystem not available on this host OS"
        return True, "compatible (Linux host /proc)"

    def prepare_sandbox(
        self,
        probe_dir: Path,
        probe_dir_sb: str,
        start_cmd: str,
        is_docker: bool,
    ) -> dict[str, Any]:
        return {
            "start_cmd": start_cmd,
            "py_preload_dir": None,
            "node_preload_file": None,
            "use_sigusr1": False,
        }


def register_builtin_memory_profilers(registry: PluginRegistry = default_registry) -> None:
    """Register default pluggable memory profiler adapters."""
    registry.register_memory_profiler(PythonTracemallocProfiler())
    registry.register_memory_profiler(NodeV8Profiler())
    registry.register_memory_profiler(OSProcFallbackProfiler())


register_builtin_memory_profilers(default_registry)
