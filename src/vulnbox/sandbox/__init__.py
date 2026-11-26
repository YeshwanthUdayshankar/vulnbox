"""Sandbox backend selection and dependency-image helpers."""

from __future__ import annotations

from pathlib import Path

from vulnbox.sandbox.base import ExecResult, SandboxBackend, SandboxPolicy
from vulnbox.sandbox.dep_builder import (
    compute_dependency_hash,
    ensure_dependency_image,
    prune_dependency_images,
)
from vulnbox.sandbox.docker_backend import DockerSandboxBackend
from vulnbox.sandbox.local_backend import LocalSandboxBackend, find_target_venv_bin
from vulnbox.sandbox.sidecars import SUPPORTED_SIDECARS, AirGappedSidecars


def select_backend(
    preference: str = "auto",
    image: str = "vulnbox-sandbox:latest",
    target_repo_path: Path | None = None,
    network_override: str | None = None,
) -> SandboxBackend:
    """Select the requested sandbox backend ('auto', 'docker', or 'local')."""
    pref = preference.lower().strip()
    if pref == "local":
        return LocalSandboxBackend(target_repo_path=target_repo_path)
    if pref == "docker":
        backend = DockerSandboxBackend(image=image, network_override=network_override)
        if not backend.is_available():
            raise RuntimeError(
                "Docker backend requested but Docker daemon is not reachable. "
                "Start Docker or run with --backend local."
            )
        return backend
    if pref == "auto":
        docker_backend = DockerSandboxBackend(image=image, network_override=network_override)
        if docker_backend.is_available():
            return docker_backend
        return LocalSandboxBackend(target_repo_path=target_repo_path)
    raise ValueError(f"Unsupported sandbox backend: {preference!r}")


__all__ = [
    "AirGappedSidecars",
    "DockerSandboxBackend",
    "ExecResult",
    "LocalSandboxBackend",
    "SUPPORTED_SIDECARS",
    "SandboxBackend",
    "SandboxPolicy",
    "compute_dependency_hash",
    "ensure_dependency_image",
    "find_target_venv_bin",
    "prune_dependency_images",
    "select_backend",
]
