"""Unit tests for hardened DockerSandboxBackend command construction."""

from pathlib import Path

from vulnbox.sandbox.base import SandboxPolicy
from vulnbox.sandbox.docker_backend import DockerSandboxBackend


def test_docker_backend_enforces_hardening_flags(tmp_path: Path):
    backend = DockerSandboxBackend(image="vulnbox-sandbox:latest")
    policy = SandboxPolicy(
        network_enabled=False,
        memory_mb=512,
        cpus=0.5,
        pids_limit=64,
    )
    cmd = backend.build_command(
        workspace_dir=tmp_path,
        command="pytest -q",
        env={"PORT": "8080"},
        policy=policy,
    )

    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "--network=none" in cmd
    assert "--cap-drop=ALL" in cmd
    assert "--security-opt=no-new-privileges:true" in cmd
    assert "--read-only" in cmd
    assert "--memory=512m" in cmd
    assert "--cpus=0.5" in cmd
    assert "--pids-limit=64" in cmd
    assert "--user" in cmd
    user_arg = cmd[cmd.index("--user") + 1]
    assert user_arg != "0:0" and ":" in user_arg
    assert "HOME=/tmp" in cmd
    assert "PORT=8080" in cmd
    assert cmd[-3:] == ["/bin/sh", "-c", "pytest -q"]
