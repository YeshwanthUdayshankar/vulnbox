"""Opt-in live Docker integration tests for Phase 1 dep-layer caching & Phase 3 sidecars.

Automatically skipped when the Docker daemon is unavailable or `vulnbox-sandbox:latest`
has not been built locally.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vulnbox.sandbox import (
    AirGappedSidecars,
    DockerSandboxBackend,
    ensure_dependency_image,
    prune_dependency_images,
)


def _docker_ready_with_sandbox_image() -> bool:
    if not DockerSandboxBackend().is_available():
        return False
    res = subprocess.run(
        ["docker", "image", "inspect", "vulnbox-sandbox:latest"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )
    return res.returncode == 0


@pytest.mark.docker
@pytest.mark.skipif(
    not _docker_ready_with_sandbox_image(),
    reason="Docker daemon or vulnbox-sandbox:latest image not available",
)
def test_live_docker_dep_layer_build_cache_and_prune(tmp_path: Path):
    repo = tmp_path / "dep_repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("# empty manifest to verify fast layer caching\n", encoding="utf-8")

    tag1 = ensure_dependency_image(repo, base_image="vulnbox-sandbox:latest")
    assert tag1.startswith("vulnbox-deps:")
    # Second call must hit local cache immediately
    tag2 = ensure_dependency_image(repo, base_image="vulnbox-sandbox:latest")
    assert tag2 == tag1

    backend = DockerSandboxBackend(image=tag1)
    res = backend.run(repo, "python3 -c 'print(\"DEP_LAYER_OK\")'")
    assert res.exit_code == 0
    assert "DEP_LAYER_OK" in res.stdout

    removed = prune_dependency_images()
    assert tag1 in removed


@pytest.mark.docker
@pytest.mark.skipif(
    not _docker_ready_with_sandbox_image(),
    reason="Docker daemon or vulnbox-sandbox:latest image not available",
)
def test_live_docker_airgapped_redis_sidecar_roundtrip(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    with AirGappedSidecars(["redis"]) as (net_name, svc_env):
        assert net_name is not None and net_name.startswith("vulnbox-net-")
        assert svc_env["REDIS_HOST"] == "redis"

        backend = DockerSandboxBackend(image="vulnbox-sandbox:latest", network_override=net_name)
        py_cmd = (
            "python3 -c \""
            "import socket; "
            "s=socket.create_connection(('redis', 6379), timeout=3); "
            "s.sendall(b'PING\\r\\n'); "
            "print(s.recv(64).decode().strip())\""
        )
        res = backend.run(ws, py_cmd, env=svc_env)
        assert res.exit_code == 0
        assert "+PONG" in res.stdout
