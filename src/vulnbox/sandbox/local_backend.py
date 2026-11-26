"""Isolated local subprocess sandbox backend with process-group teardown and temp cleanup."""

from __future__ import annotations

import os
import resource
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from vulnbox.sandbox.base import ExecResult, SandboxBackend, SandboxPolicy


def _build_sanitized_env(tmp_home: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Construct a minimal environment stripped of host secrets/credentials."""
    py_bin_dir = str(Path(sys.executable).parent)
    default_path = f"{py_bin_dir}:/usr/local/bin:/usr/bin:/bin"
    env: dict[str, str] = {
        "PATH": default_path,
        "HOME": str(tmp_home),
        "TMPDIR": str(tmp_home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "VULNBOX_SANDBOX": "local",
    }
    if os.environ.get("VIRTUAL_ENV"):
        env["VIRTUAL_ENV"] = os.environ["VIRTUAL_ENV"]
    if extra:
        env.update(extra)
    return env


def _make_preexec(policy: SandboxPolicy):
    def _apply_limits() -> None:
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
            target = (
                min(policy.timeout_sec, hard)
                if hard != resource.RLIM_INFINITY
                else policy.timeout_sec
            )
            resource.setrlimit(resource.RLIMIT_CPU, (target, hard))
        except (ValueError, OSError):
            pass
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            target_nofile = 512
            if hard != resource.RLIM_INFINITY:
                target_nofile = min(target_nofile, hard)
            resource.setrlimit(resource.RLIMIT_NOFILE, (target_nofile, hard))
        except (ValueError, OSError):
            pass

    return _apply_limits


class LocalSandboxBackend(SandboxBackend):
    """Executes commands in an ephemeral scrubbed workspace with stripped env, rlimits, and PG cleanup."""

    name = "local"

    def is_available(self) -> bool:
        return True

    def run(
        self,
        workspace_dir: Path,
        command: str,
        env: dict[str, str] | None = None,
        policy: SandboxPolicy | None = None,
    ) -> ExecResult:
        pol = policy or SandboxPolicy()
        start = time.monotonic()

        with tempfile.TemporaryDirectory(prefix="vulnbox-home-") as tmp_home_str:
            sanitized_env = _build_sanitized_env(Path(tmp_home_str), extra=env)
            proc = subprocess.Popen(
                ["/bin/sh", "-c", command],
                cwd=str(Path(workspace_dir).resolve()),
                env=sanitized_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
                preexec_fn=_make_preexec(pol),
            )
            try:
                stdout, stderr = proc.communicate(timeout=pol.timeout_sec)
                elapsed = int((time.monotonic() - start) * 1000)
                return ExecResult(
                    command=command,
                    exit_code=proc.returncode or 0,
                    stdout=stdout,
                    stderr=stderr,
                    duration_ms=elapsed,
                    timed_out=False,
                )
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    proc.kill()
                try:
                    stdout, stderr = proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    stdout, stderr = "", "Sandbox execution timed out"
                elapsed = int((time.monotonic() - start) * 1000)
                return ExecResult(
                    command=command,
                    exit_code=124,
                    stdout=stdout or "",
                    stderr=stderr or "Sandbox execution timed out",
                    duration_ms=elapsed,
                    timed_out=True,
                )
