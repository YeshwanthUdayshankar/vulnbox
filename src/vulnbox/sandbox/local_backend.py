"""Isolated local subprocess sandbox backend (fallback when Docker is unavailable)."""

from __future__ import annotations

import os
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from vulnbox.sandbox.base import ExecResult, SandboxBackend, SandboxPolicy


def _build_sanitized_env(workspace_dir: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Construct a minimal environment stripped of host secrets/credentials."""
    tmp_home = Path(tempfile.mkdtemp(prefix="vulnbox-home-"))
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
    # Preserve VIRTUAL_ENV only if running inside project's venv so pytest/pyyaml resolve
    if os.environ.get("VIRTUAL_ENV"):
        env["VIRTUAL_ENV"] = os.environ["VIRTUAL_ENV"]
    if extra:
        env.update(extra)
    return env


def _make_preexec(policy: SandboxPolicy):
    def _apply_limits() -> None:
        os.setsid()
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
            target = min(policy.timeout_sec, hard) if hard != resource.RLIM_INFINITY else policy.timeout_sec
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
    """Executes commands in an ephemeral scrubbed workspace with stripped env and rlimits."""

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
        sanitized_env = _build_sanitized_env(workspace_dir, extra=env)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                ["/bin/sh", "-c", command],
                cwd=str(Path(workspace_dir).resolve()),
                env=sanitized_env,
                capture_output=True,
                text=True,
                timeout=pol.timeout_sec,
                preexec_fn=_make_preexec(pol),
                check=False,
            )
            elapsed = int((time.monotonic() - start) * 1000)
            return ExecResult(
                command=command,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_ms=elapsed,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = int((time.monotonic() - start) * 1000)
            return ExecResult(
                command=command,
                exit_code=124,
                stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "Sandbox execution timed out")
                if isinstance(exc.stderr, str)
                else "Sandbox execution timed out",
                duration_ms=elapsed,
                timed_out=True,
            )
