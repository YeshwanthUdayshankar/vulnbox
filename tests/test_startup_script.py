"""Tests for the cross-OS VulnBox Web UI startup scripts (Linux, macOS, Windows)."""

from __future__ import annotations

import importlib.util
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
START_UI_PY = REPO_ROOT / "scripts" / "start_ui.py"


def _load_start_ui_module():
    spec = importlib.util.spec_from_file_location("vulnbox_start_ui", START_UI_PY)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_find_venv_python_handles_windows_and_posix(tmp_path: Path) -> None:
    mod = _load_start_ui_module()

    win_py = tmp_path / ".venv" / "Scripts" / "python.exe"
    win_py.parent.mkdir(parents=True)
    win_py.write_text("", encoding="utf-8")

    posix_py = tmp_path / ".venv" / "bin" / "python"
    posix_py.parent.mkdir(parents=True)
    posix_py.write_text("", encoding="utf-8")

    assert mod.find_venv_python(tmp_path, is_windows=True) == win_py
    assert mod.find_venv_python(tmp_path, is_windows=False) == posix_py


def test_build_repo_local_env_pins_all_venvs_and_caches_inside_repo(tmp_path: Path) -> None:
    mod = _load_start_ui_module()

    dirty_env = {
        "PATH": "/usr/bin",
        "VIRTUAL_ENV": "/some/external/venv",
        "PYTHONHOME": "/some/external/python",
        "PIP_TARGET": "/global/target",
        "PIP_USER": "1",
    }
    env = mod.build_repo_local_env(tmp_path, base_env=dirty_env, is_windows=False)

    assert env["VIRTUAL_ENV"] == str(tmp_path / ".venv")
    assert env["UV_PROJECT_ENVIRONMENT"] == str(tmp_path / ".venv")
    assert env["UV_CACHE_DIR"] == str(tmp_path / ".vulnbox-cache" / "uv")
    assert env["UV_PYTHON_INSTALL_DIR"] == str(tmp_path / ".vulnbox-cache" / "python")
    assert env["PIP_CACHE_DIR"] == str(tmp_path / ".vulnbox-cache" / "pip")
    assert env["PIP_USER"] == "0"
    assert env["PIP_REQUIRE_VIRTUALENV"] == "1"
    assert env["PYTHONNOUSERSITE"] == "1"
    assert env["PYTHONPATH"] == str(tmp_path / "src")
    assert "PYTHONHOME" not in env
    assert "PIP_TARGET" not in env


def test_resolve_launch_command_stays_repo_local(tmp_path: Path) -> None:
    mod = _load_start_ui_module()

    # 1. Prefers local .venv when importable (Windows path simulation)
    win_py = tmp_path / ".venv" / "Scripts" / "python.exe"
    win_py.parent.mkdir(parents=True)
    win_py.write_text("", encoding="utf-8")

    cmd, env = mod.resolve_launch_command(
        tmp_path,
        host="127.0.0.1",
        port=9090,
        no_browser=True,
        is_windows=True,
        can_import=lambda p, _: p == win_py,
        which=lambda _: "/usr/local/bin/uv",
    )
    assert cmd == [str(win_py), "-m", "vulnbox.cli", "ui", "--host", "127.0.0.1", "--port", "9090", "--no-browser"]
    assert env["VIRTUAL_ENV"] == str(tmp_path / ".venv")
    assert env["UV_CACHE_DIR"] == str(tmp_path / ".vulnbox-cache" / "uv")
    assert env["PYTHONNOUSERSITE"] == "1"

    # 2. Falls back to repo-pinned `uv run` when .venv is missing or unusable
    cmd_uv, uv_env = mod.resolve_launch_command(
        tmp_path,
        host="127.0.0.1",
        port=8787,
        no_browser=False,
        is_windows=False,
        can_import=lambda *_: False,
        which=lambda name: "/usr/local/bin/uv" if name == "uv" else None,
    )
    assert cmd_uv == ["/usr/local/bin/uv", "run", "--project", str(tmp_path), "vulnbox", "ui", "--host", "127.0.0.1", "--port", "8787"]
    assert uv_env["UV_PROJECT_ENVIRONMENT"] == str(tmp_path / ".venv")
    assert uv_env["UV_CACHE_DIR"] == str(tmp_path / ".vulnbox-cache" / "uv")

    # 3. Never falls back to global system Python when neither local .venv nor uv is ready
    with pytest.raises(RuntimeError, match="Local repository environment not ready"):
        mod.resolve_launch_command(
            tmp_path,
            is_windows=False,
            can_import=lambda *_: False,
            which=lambda _: None,
        )


def test_cross_os_wrapper_scripts_exist_and_dry_run_works() -> None:
    sh_script = REPO_ROOT / "start-ui.sh"
    ps1_script = REPO_ROOT / "start-ui.ps1"
    bat_script = REPO_ROOT / "start-ui.bat"

    for script in (START_UI_PY, sh_script, ps1_script, bat_script):
        assert script.is_file(), f"Missing startup script: {script}"
        content = script.read_text(encoding="utf-8")
        assert "start_ui.py" in content
        assert "UV_CACHE_DIR" in content
        assert "PYTHONNOUSERSITE" in content

    # Test dry-run via Python script with env var overrides
    env = os.environ.copy()
    env["VULNBOX_UI_PORT"] = "8910"
    env["VULNBOX_NO_BROWSER"] = "1"
    proc = subprocess.run(
        [sys.executable, str(START_UI_PY), "--dry-run"],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "--port 8910" in proc.stdout
    assert "--no-browser" in proc.stdout

    # Test bash wrapper on POSIX
    if os.name != "nt":
        assert os.access(sh_script, os.X_OK), "start-ui.sh must be executable"
        bash_proc = subprocess.run(
            [str(sh_script), "--port", "8911", "--no-browser", "--dry-run"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        assert "--port 8911" in bash_proc.stdout
        assert "--no-browser" in bash_proc.stdout


def test_startup_script_launches_live_ui_and_stops_cleanly() -> None:
    port = _pick_free_port()
    proc = subprocess.Popen(
        [sys.executable, str(START_UI_PY), "--host", "127.0.0.1", "--port", str(port), "--no-browser"],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 15.0
        body = ""
        csp = ""
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                out, err = proc.communicate(timeout=2)
                raise AssertionError(f"start_ui.py exited early ({proc.returncode}): {out}\n{err}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as resp:
                    body = resp.read().decode("utf-8")
                    csp = resp.headers.get("Content-Security-Policy", "")
                    break
            except Exception:
                time.sleep(0.15)
        assert "VulnBox" in body
        assert "unsafe-inline" not in csp
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
