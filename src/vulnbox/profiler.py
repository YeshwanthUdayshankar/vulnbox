"""Read-only repository profiler for Python and Node.js repositories."""

from __future__ import annotations

import json
from pathlib import Path

from vulnbox.models import Ecosystem, RepoProfile

IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "vulnbox-out",
}


def _iter_repo_files(root: Path, max_depth: int = 4) -> list[Path]:
    """Yield repo files up to max_depth while skipping build/VCS directories."""
    results: list[Path] = []
    root_parts = len(root.parts)
    for path in sorted(root.rglob("*")):
        rel_parts = path.relative_to(root).parts
        if any(part in IGNORED_DIRS for part in rel_parts):
            continue
        if len(path.parts) - root_parts > max_depth:
            continue
        if path.is_file():
            results.append(path)
    return results


def _detect_python_details(
    root: Path, files: list[Path]
) -> tuple[list[str], list[str], str | None, str | None]:
    manifests: list[str] = []
    frameworks: list[str] = []
    test_cmd: str | None = None
    start_cmd: str | None = None

    rel_map = {str(p.relative_to(root)): p for p in files}
    for name in ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile"):
        if name in rel_map:
            manifests.append(name)

    py_files = [p for p in files if p.suffix == ".py"]
    if not manifests and not py_files:
        return manifests, frameworks, test_cmd, start_cmd

    combined_manifest_text = ""
    for m in manifests:
        try:
            combined_manifest_text += rel_map[m].read_text(encoding="utf-8", errors="ignore") + "\n"
        except OSError:
            pass

    lower_manifest = combined_manifest_text.lower()
    for fw in ("fastapi", "flask", "django", "starlette", "aiohttp"):
        if fw in lower_manifest:
            frameworks.append(fw)

    has_tests_dir = (root / "tests").is_dir() or any(
        p.name.startswith("test_") for p in py_files
    )
    if has_tests_dir:
        test_cmd = "python3 -m pytest -q"

    # Detect runnable entrypoint for active loopback verification
    for candidate in ("app.py", "server.py", "main.py", "src/app.py", "src/server.py"):
        if candidate in rel_map:
            try:
                content = rel_map[candidate].read_text(encoding="utf-8", errors="ignore")
            except OSError:
                content = ""
            if "HTTPServer" in content or "ThreadingHTTPServer" in content or "__main__" in content:
                if "fastapi" in content.lower() and "uvicorn" in lower_manifest:
                    mod = candidate.removesuffix(".py").replace("/", ".")
                    start_cmd = f"python3 -m uvicorn {mod}:app --host 127.0.0.1 --port $PORT"
                else:
                    start_cmd = f"python3 {candidate}"
                if "http.server" in content and "stdlib-http" not in frameworks:
                    frameworks.append("stdlib-http")
                break

    return manifests, frameworks, test_cmd, start_cmd


def _detect_node_details(
    root: Path, files: list[Path]
) -> tuple[list[str], list[str], str | None, str | None]:
    manifests: list[str] = []
    frameworks: list[str] = []
    test_cmd: str | None = None
    start_cmd: str | None = None

    rel_map = {str(p.relative_to(root)): p for p in files}
    for name in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        if name in rel_map:
            manifests.append(name)

    pkg_data: dict = {}
    if "package.json" in rel_map:
        try:
            pkg_data = json.loads(rel_map["package.json"].read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pkg_data = {}

    deps = {
        **(pkg_data.get("dependencies") or {}),
        **(pkg_data.get("devDependencies") or {}),
    }
    for fw in ("express", "fastify", "koa", "next", "hono"):
        if fw in deps:
            frameworks.append(fw)

    scripts = pkg_data.get("scripts") or {}
    if isinstance(scripts.get("test"), str) and scripts["test"].strip():
        test_script = scripts["test"].strip()
        if "no test specified" not in test_script.lower():
            if "node --test" in test_script:
                test_cmd = test_script
            else:
                test_cmd = "npm test"
    elif any(
        p.name.endswith((".test.js", ".test.mjs", ".test.cjs"))
        for p in files
    ):
        test_cmd = "node --test"

    if isinstance(scripts.get("start"), str) and scripts["start"].strip():
        start_cmd = scripts["start"].strip()
    else:
        for candidate in ("server.js", "server.mjs", "app.js", "index.js", "src/server.js"):
            if candidate in rel_map:
                try:
                    content = rel_map[candidate].read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    content = ""
                if "createServer" in content or ".listen(" in content:
                    start_cmd = f"node {candidate}"
                    if "node:http" in content or "require('http')" in content or 'require("http")' in content:
                        if "node-http" not in frameworks:
                            frameworks.append("node-http")
                    break

    return manifests, frameworks, test_cmd, start_cmd


def profile_repo(repo_path: str | Path) -> RepoProfile:
    """Profile a local repository without mutating it."""
    root = Path(repo_path).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Repository directory not found: {root}")

    files = _iter_repo_files(root)

    py_manifests, py_frameworks, py_test, py_start = _detect_python_details(root, files)
    node_manifests, node_frameworks, node_test, node_start = _detect_node_details(root, files)

    has_py = bool(py_manifests) or any(p.suffix == ".py" for p in files)
    has_node = bool(node_manifests) or any(
        p.suffix in (".js", ".mjs", ".cjs", ".ts") for p in files
    )

    ecosystem: Ecosystem
    if has_py and has_node:
        ecosystem = "mixed"
    elif has_py:
        ecosystem = "python"
    elif has_node:
        ecosystem = "node"
    else:
        ecosystem = "unknown"

    test_commands: dict[str, str] = {}
    if py_test:
        test_commands["python"] = py_test
    if node_test:
        test_commands["node"] = node_test

    dockerfiles = [
        str(p.relative_to(root))
        for p in files
        if p.name == "Dockerfile" or p.name.startswith("Dockerfile.")
    ]
    env_files = [
        str(p.relative_to(root))
        for p in files
        if p.name == ".env" or p.name.startswith(".env.")
    ]

    start_cmd = py_start or node_start
    frameworks = sorted(set(py_frameworks + node_frameworks))

    return RepoProfile(
        repo_path=str(root),
        ecosystem=ecosystem,
        manifests=py_manifests + node_manifests,
        dockerfiles=dockerfiles,
        frameworks=frameworks,
        test_commands=test_commands,
        start_command=start_cmd,
        health_path="/health",
        env_files=env_files,
    )
