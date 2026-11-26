"""Sandbox backend selection helpers."""

from __future__ import annotations

from vulnbox.sandbox.base import ExecResult, SandboxBackend, SandboxPolicy
from vulnbox.sandbox.docker_backend import DockerSandboxBackend
from vulnbox.sandbox.local_backend import LocalSandboxBackend


def select_backend(
    preference: str = "auto",
    image: str = "vulnbox-sandbox:latest",
) -> SandboxBackend:
    """Select the requested sandbox backend ('auto', 'docker', or 'local')."""
    pref = preference.lower().strip()
    if pref == "local":
        return LocalSandboxBackend()
    if pref == "docker":
        backend = DockerSandboxBackend(image=image)
        if not backend.is_available():
            raise RuntimeError(
                "Docker backend requested but Docker daemon is not reachable. "
                "Start Docker or run with --backend local."
            )
        return backend
    if pref == "auto":
        docker_backend = DockerSandboxBackend(image=image)
        if docker_backend.is_available():
            return docker_backend
        return LocalSandboxBackend()
    raise ValueError(f"Unsupported sandbox backend: {preference!r}")


__all__ = [
    "DockerSandboxBackend",
    "ExecResult",
    "LocalSandboxBackend",
    "SandboxBackend",
    "SandboxPolicy",
    "select_backend",
]
