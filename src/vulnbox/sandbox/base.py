"""Base sandbox backend interface and execution policy."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from pydantic import BaseModel


class SandboxPolicy(BaseModel):
    """Resource and isolation constraints applied to sandbox executions."""

    network_enabled: bool = False
    timeout_sec: int = 120
    memory_mb: int = 1024
    cpus: float = 1.0
    pids_limit: int = 128
    image: str = "vulnbox-sandbox:latest"


class ExecResult(BaseModel):
    """Captured output of a command executed inside a sandbox."""

    command: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    timed_out: bool = False


class SandboxBackend(ABC):
    """Abstract interface implemented by Docker and local isolated sandboxes."""

    name: str = "base"

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this backend can execute commands right now."""

    @abstractmethod
    def run(
        self,
        workspace_dir: Path,
        command: str,
        env: dict[str, str] | None = None,
        policy: SandboxPolicy | None = None,
    ) -> ExecResult:
        """Execute a shell command inside the sandbox against workspace_dir."""
