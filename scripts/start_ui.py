#!/usr/bin/env python3
"""Cross-OS startup launcher for the VulnBox local Web UI (Linux, macOS, Windows).

All setup, virtual environment creation, and package caches stay strictly local to
this repository (`.venv/` and `.vulnbox-cache/`) — nothing is installed globally or
into user site-packages.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787
REPO_ROOT = Path(__file__).resolve().parent.parent


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_port(name: str, default: int = DEFAULT_PORT) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        port = int(raw.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid {name}={raw!r}: expected integer 0..65535") from exc
    if not (0 <= port <= 65535):
        raise ValueError(f"Invalid {name}={port}: expected 0..65535")
    return port


def find_venv_python(repo_root: Path, *, is_windows: bool | None = None) -> Path | None:
    """Locate the repository's local `.venv` Python executable on Windows, macOS, or Linux."""
    win = (os.name == "nt") if is_windows is None else is_windows
    candidates = (
        [repo_root / ".venv" / "Scripts" / "python.exe", repo_root / ".venv" / "bin" / "python"]
        if win
        else [repo_root / ".venv" / "bin" / "python", repo_root / ".venv" / "Scripts" / "python.exe"]
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def build_repo_local_env(
    repo_root: Path,
    *,
    base_env: dict[str, str] | None = None,
    is_windows: bool | None = None,
) -> dict[str, str]:
    """Return an environment that confines venvs, uv/pip caches, and Python imports to `repo_root`."""
    win = (os.name == "nt") if is_windows is None else is_windows
    env = dict(os.environ if base_env is None else base_env)

    venv_dir = repo_root / ".venv"
    cache_root = repo_root / ".vulnbox-cache"
    venv_bin = venv_dir / ("Scripts" if win else "bin")

    # Strip any external virtualenv / Python home bleed-through
    env.pop("PYTHONHOME", None)
    env.pop("PIP_TARGET", None)
    env.pop("PIP_PREFIX", None)

    # Pin virtualenv & caches strictly inside the repository
    env["VIRTUAL_ENV"] = str(venv_dir)
    env["UV_PROJECT_ENVIRONMENT"] = str(venv_dir)
    env["UV_CACHE_DIR"] = str(cache_root / "uv")
    env["UV_PYTHON_INSTALL_DIR"] = str(cache_root / "python")
    env["PIP_CACHE_DIR"] = str(cache_root / "pip")
    env["PIP_USER"] = "0"
    env["PIP_REQUIRE_VIRTUALENV"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONPATH"] = str(repo_root / "src")

    if venv_bin.is_dir():
        existing_path = env.get("PATH", "")
        env["PATH"] = f"{venv_bin}{os.pathsep}{existing_path}" if existing_path else str(venv_bin)

    return env


def python_can_import_vulnbox(python_bin: Path, repo_root: Path) -> bool:
    """Return True if `python_bin` can import vulnbox and its runtime dependencies locally."""
    env = build_repo_local_env(repo_root)
    probe = "import pydantic, rich, typer, yaml, jsonschema, vulnbox"
    try:
        proc = subprocess.run(
            [str(python_bin), "-c", probe],
            cwd=str(repo_root),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
        return proc.returncode == 0
    except OSError:
        return False


def _ui_args(host: str, port: int, no_browser: bool) -> list[str]:
    args = ["ui", "--host", host, "--port", str(port)]
    if no_browser:
        args.append("--no-browser")
    return args


def resolve_launch_command(
    repo_root: Path,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    no_browser: bool = False,
    which: Callable[[str], str | None] = shutil.which,
    is_windows: bool | None = None,
    can_import: Callable[[Path, Path], bool] | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Resolve the strictly repo-local cross-OS command and environment to launch VulnBox UI."""
    if not (0 <= port <= 65535):
        raise ValueError(f"Port must be between 0 and 65535, got {port}.")

    checker = python_can_import_vulnbox if can_import is None else can_import
    ui_args = _ui_args(host, port, no_browser)
    env = build_repo_local_env(repo_root, is_windows=is_windows)

    # 1. Prefer the repository's local `.venv` when ready
    venv_py = find_venv_python(repo_root, is_windows=is_windows)
    if venv_py is not None and checker(venv_py, repo_root):
        return [str(venv_py), "-m", "vulnbox.cli", *ui_args], env

    # 2. Fall back to `uv run`, pinned to `<repo>/.venv` and `<repo>/.vulnbox-cache/uv`
    uv_bin = which("uv")
    if uv_bin:
        return [uv_bin, "run", "--project", str(repo_root), "vulnbox", *ui_args], env

    raise RuntimeError(
        f"Local repository environment not ready at {repo_root / '.venv'}.\n"
        "Run without `--no-install` (or pass `--install`) to set up `.venv` locally inside the repo."
    )


def bootstrap_environment(repo_root: Path) -> None:
    """Install VulnBox dependencies strictly inside `<repo>/.venv` and `<repo>/.vulnbox-cache`."""
    cache_root = repo_root / ".vulnbox-cache"
    cache_root.mkdir(parents=True, exist_ok=True)
    env = build_repo_local_env(repo_root)

    uv_bin = shutil.which("uv")
    if uv_bin:
        print(f"[vulnbox] Syncing repo-local environment at {repo_root / '.venv'} via uv...")
        subprocess.run(
            [uv_bin, "sync", "--project", str(repo_root)],
            cwd=str(repo_root),
            env=env,
            check=True,
        )
        return

    venv_dir = repo_root / ".venv"
    venv_py = find_venv_python(repo_root)
    if venv_py is None:
        print(f"[vulnbox] Creating repo-local virtual environment at {venv_dir}...")
        # `venv` creation itself needs system Python outside the nonexistent venv
        create_env = os.environ.copy()
        create_env.pop("VIRTUAL_ENV", None)
        create_env.pop("PYTHONHOME", None)
        create_env["PYTHONNOUSERSITE"] = "1"
        subprocess.run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            cwd=str(repo_root),
            env=create_env,
            check=True,
        )
        venv_py = find_venv_python(repo_root)
        if venv_py is None:
            raise RuntimeError(f"Virtual environment created at {venv_dir}, but python executable was not found.")

    env = build_repo_local_env(repo_root)
    print(f"[vulnbox] Installing vulnbox locally into {venv_dir} (cache: {cache_root / 'pip'})...")
    subprocess.run(
        [str(venv_py), "-m", "pip", "install", "-e", str(repo_root)],
        cwd=str(repo_root),
        env=env,
        check=True,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="start_ui.py",
        description="Start the VulnBox local Web UI on Linux, macOS, or Windows (100% repo-local setup).",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("VULNBOX_UI_HOST", DEFAULT_HOST),
        help=f"Bind host (default: {DEFAULT_HOST}; env: VULNBOX_UI_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help=f"Port to serve the Web UI (default: {DEFAULT_PORT}; env: VULNBOX_UI_PORT)",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        default=_env_flag("VULNBOX_NO_BROWSER", False),
        help="Do not automatically open the browser (env: VULNBOX_NO_BROWSER=1)",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Force repo-local dependency sync/install into .venv before launching the UI",
    )
    parser.add_argument(
        "--no-install",
        action="store_true",
        help="Fail instead of auto-creating .venv locally if dependencies are missing",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the resolved launch command and exit without installing or starting the server",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        port = _env_port("VULNBOX_UI_PORT", DEFAULT_PORT) if args.port is None else args.port
        if args.install and not args.dry_run:
            bootstrap_environment(REPO_ROOT)

        try:
            cmd, env = resolve_launch_command(
                REPO_ROOT,
                host=args.host,
                port=port,
                no_browser=args.no_browser,
            )
        except RuntimeError:
            if args.dry_run or args.no_install:
                raise
            bootstrap_environment(REPO_ROOT)
            cmd, env = resolve_launch_command(
                REPO_ROOT,
                host=args.host,
                port=port,
                no_browser=args.no_browser,
            )
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"[vulnbox] Error: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(" ".join(cmd))
        return 0

    try:
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, check=False)
        return int(proc.returncode)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
