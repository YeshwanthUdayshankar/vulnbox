"""Opt-in air-gapped Docker sidecar manager (`--services postgres,redis`).

Creates an ephemeral Docker `--internal` network (strictly zero internet egress),
launches pinned sidecar containers (`postgres:16-alpine`, `redis:7-alpine`), waits
until ready, yields `(network_name, service_env_vars)`, and guarantees cleanup.
"""

from __future__ import annotations

import subprocess
import time
import uuid

SUPPORTED_SIDECARS = {
    "postgres": "postgres:16-alpine",
    "redis": "redis:7-alpine",
}


class AirGappedSidecars:
    """Context manager managing ephemeral `--internal` Docker sidecars."""

    def __init__(self, services: list[str] | None = None, startup_timeout_sec: int = 20) -> None:
        normalized = [s.strip().lower() for s in (services or []) if s.strip()]
        invalid = [s for s in normalized if s not in SUPPORTED_SIDECARS]
        if invalid:
            raise ValueError(
                f"Unsupported sidecar service(s): {', '.join(invalid)}. "
                f"Supported: {', '.join(sorted(SUPPORTED_SIDECARS))}"
            )
        self.services = sorted(set(normalized))
        self.startup_timeout_sec = startup_timeout_sec
        self.network_name: str | None = None
        self._container_names: list[str] = []
        self.env_vars: dict[str, str] = {}

    def _run_docker(self, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def _wait_ready(self, service: str, container_name: str) -> None:
        deadline = time.monotonic() + self.startup_timeout_sec
        check_args = (
            ["exec", container_name, "pg_isready", "-U", "vulnbox"]
            if service == "postgres"
            else ["exec", container_name, "redis-cli", "ping"]
        )
        while time.monotonic() < deadline:
            res = self._run_docker(check_args, timeout=5)
            if res.returncode == 0:
                return
            time.sleep(0.4)
        raise RuntimeError(f"Sidecar {service!r} ({container_name}) did not become ready in time.")

    def __enter__(self) -> tuple[str | None, dict[str, str]]:
        if not self.services:
            return None, {}

        suffix = uuid.uuid4().hex[:10]
        net_name = f"vulnbox-net-{suffix}"
        create_net = self._run_docker(["network", "create", "--internal", net_name])
        if create_net.returncode != 0:
            raise RuntimeError(
                f"Failed to create internal Docker network {net_name}: {create_net.stderr.strip()}"
            )
        self.network_name = net_name

        try:
            for svc in self.services:
                cname = f"vulnbox-svc-{svc}-{suffix}"
                image = SUPPORTED_SIDECARS[svc]
                cmd = [
                    "run",
                    "-d",
                    "--rm",
                    "--name",
                    cname,
                    "--network",
                    net_name,
                    "--network-alias",
                    svc,
                    "--memory=256m",
                    "--cpus=0.5",
                    "--pids-limit=64",
                ]
                if svc == "postgres":
                    cmd.extend(
                        [
                            "-e",
                            "POSTGRES_USER=vulnbox",
                            "-e",
                            "POSTGRES_PASSWORD=vulnbox",
                            "-e",
                            "POSTGRES_DB=vulnbox",
                        ]
                    )
                    self.env_vars.update(
                        {
                            "DATABASE_URL": "postgresql://vulnbox:vulnbox@postgres:5432/vulnbox",
                            "POSTGRES_HOST": "postgres",
                            "POSTGRES_PORT": "5432",
                            "POSTGRES_USER": "vulnbox",
                            "POSTGRES_PASSWORD": "vulnbox",
                            "POSTGRES_DB": "vulnbox",
                        }
                    )
                elif svc == "redis":
                    self.env_vars.update(
                        {
                            "REDIS_URL": "redis://redis:6379/0",
                            "REDIS_HOST": "redis",
                            "REDIS_PORT": "6379",
                        }
                    )
                cmd.append(image)
                started = self._run_docker(cmd, timeout=60)
                if started.returncode != 0:
                    raise RuntimeError(
                        f"Failed to start sidecar {svc!r} ({image}): {started.stderr.strip()}"
                    )
                self._container_names.append(cname)

            for svc, cname in zip(self.services, self._container_names, strict=True):
                self._wait_ready(svc, cname)
        except Exception:
            self.cleanup()
            raise

        return self.network_name, dict(self.env_vars)

    def cleanup(self) -> None:
        for cname in self._container_names:
            try:
                self._run_docker(["rm", "-f", cname], timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                pass
        self._container_names.clear()
        if self.network_name:
            try:
                self._run_docker(["network", "rm", self.network_name], timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                pass
            self.network_name = None

    def __exit__(self, *exc_info: object) -> None:
        self.cleanup()
