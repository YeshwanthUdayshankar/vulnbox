"""Hardened Docker sandbox backend."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

from vulnbox.sandbox.base import ExecResult, SandboxBackend, SandboxPolicy


class DockerSandboxBackend(SandboxBackend):
    """Runs commands inside ephemeral, least-privilege Docker containers."""

    name = "docker"

    def __init__(self, image: str = "vulnbox-sandbox:latest") -> None:
        self.default_image = image

    def is_available(self) -> bool:
        if not shutil.which("docker"):
            return False
        try:
            proc = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return proc.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def build_command(
        self,
        workspace_dir: Path,
        command: str,
        env: dict[str, str] | None = None,
        policy: SandboxPolicy | None = None,
    ) -> list[str]:
        """Construct the hardened docker run command list."""
        pol = policy or SandboxPolicy(image=self.default_image)
        image = pol.image or self.default_image
        ws = str(Path(workspace_dir).resolve())

        uid = os.getuid() if hasattr(os, "getuid") else 1000
        gid = os.getgid() if hasattr(os, "getgid") else 1000
        user_spec = f"{uid}:{gid}" if uid != 0 else "1000:1000"

        cmd = [
            "docker",
            "run",
            "--rm",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=256m",
            f"--memory={pol.memory_mb}m",
            f"--cpus={pol.cpus}",
            f"--pids-limit={pol.pids_limit}",
            "--user",
            user_spec,
            "-e",
            "HOME=/tmp",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            "-v",
            f"{ws}:/workspace:rw",
            "-w",
            "/workspace",
        ]

        if not pol.network_enabled:
            cmd.append("--network=none")

        for k, v in (env or {}).items():
            cmd.extend(["-e", f"{k}={v}"])

        cmd.extend([image, "/bin/sh", "-c", command])
        return cmd

    def run(
        self,
        workspace_dir: Path,
        command: str,
        env: dict[str, str] | None = None,
        policy: SandboxPolicy | None = None,
    ) -> ExecResult:
        pol = policy or SandboxPolicy(image=self.default_image)
        docker_cmd = self.build_command(workspace_dir, command, env=env, policy=pol)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=pol.timeout_sec,
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
