"""Two-phase air-gapped Docker dependency layer builder and local image cache manager.

Phase 1 (Build-time only): copies ONLY manifest/lockfiles (never app source code), installs
Python packages and runs `npm ci --ignore-scripts` into a cached image `vulnbox-deps:<sha256>`.
Phase 2 (Execution-time): untrusted repo code executes inside that cached image with
`--network=none`, `--read-only`, and `--cap-drop=ALL`.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

MANIFEST_NAMES: tuple[str, ...] = (
    "requirements.txt",
    "pyproject.toml",
    "uv.lock",
    "package.json",
    "package-lock.json",
)
DEP_IMAGE_PREFIX = "vulnbox-deps"


def discover_top_level_manifests(repo_path: Path) -> list[Path]:
    """Return top-level dependency manifests present in `repo_path`."""
    root = Path(repo_path).resolve()
    found: list[Path] = []
    for name in MANIFEST_NAMES:
        cand = root / name
        if cand.is_file():
            found.append(cand)
    return found


def compute_dependency_hash(
    repo_path: Path,
    base_image: str = "vulnbox-sandbox:latest",
) -> tuple[str, list[Path]]:
    """Compute a deterministic 12-char SHA-256 hash over manifests and base image."""
    manifests = discover_top_level_manifests(repo_path)
    if not manifests:
        return "", []
    h = hashlib.sha256()
    h.update(f"base:{base_image}\n".encode())
    for mf in manifests:
        h.update(f"file:{mf.name}\n".encode())
        h.update(mf.read_bytes())
        h.update(b"\n---\n")
    return h.hexdigest()[:12], manifests


def prepare_manifest_build_context(
    repo_path: Path,
    build_dir: Path,
    base_image: str = "vulnbox-sandbox:latest",
) -> tuple[Path, list[str]]:
    """Copy ONLY manifests into `build_dir` and emit a hardened Dockerfile."""
    _, manifests = compute_dependency_hash(repo_path, base_image=base_image)
    build_dir.mkdir(parents=True, exist_ok=True)

    copied_names: list[str] = []
    for mf in manifests:
        shutil.copy2(mf, build_dir / mf.name)
        copied_names.append(mf.name)

    has_req = "requirements.txt" in copied_names
    has_pyproject = "pyproject.toml" in copied_names
    has_pkg = "package.json" in copied_names
    has_pkg_lock = "package-lock.json" in copied_names

    lines: list[str] = [
        f"FROM {base_image}",
        "USER root",
        "WORKDIR /deps",
    ]
    if has_req:
        lines.extend(
            [
                "COPY requirements.txt /deps/requirements.txt",
                "RUN pip install --no-cache-dir -r /deps/requirements.txt || true",
            ]
        )
    elif has_pyproject:
        lines.extend(
            [
                "COPY pyproject.toml /deps/pyproject.toml",
                'RUN python3 -c "import tomllib, subprocess, sys; '
                "d=tomllib.loads(open('/deps/pyproject.toml').read()); "
                "deps=d.get('project',{}).get('dependencies',[]); "
                "subprocess.check_call([sys.executable,'-m','pip','install','--no-cache-dir',*deps]) if deps else None\" || true",
            ]
        )

    if has_pkg:
        lines.append("COPY package.json /deps/node/package.json")
        if has_pkg_lock:
            lines.append("COPY package-lock.json /deps/node/package-lock.json")
            lines.append(
                "RUN cd /deps/node && npm ci --ignore-scripts --omit=dev --no-audit --no-fund || true"
            )
        else:
            lines.append(
                "RUN cd /deps/node && npm install --ignore-scripts --omit=dev --no-audit --no-fund || true"
            )
        lines.append("ENV NODE_PATH=/deps/node/node_modules")

    lines.extend(["USER sandbox", "WORKDIR /workspace", ""])
    dockerfile = build_dir / "Dockerfile"
    dockerfile.write_text("\n".join(lines), encoding="utf-8")
    return dockerfile, copied_names


def _docker_image_exists(tag: str) -> bool:
    if not shutil.which("docker"):
        return False
    proc = subprocess.run(
        ["docker", "image", "inspect", tag],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    return proc.returncode == 0


def ensure_dependency_image(
    repo_path: Path,
    base_image: str = "vulnbox-sandbox:latest",
) -> str:
    """Return a cached `vulnbox-deps:<hash>` Docker image tag, building once if needed."""
    dep_hash, manifests = compute_dependency_hash(repo_path, base_image=base_image)
    if not dep_hash or not manifests:
        return base_image

    tag = f"{DEP_IMAGE_PREFIX}:{dep_hash}"
    if _docker_image_exists(tag):
        return tag

    if not shutil.which("docker"):
        return base_image

    with tempfile.TemporaryDirectory(prefix="vulnbox-depbuild-") as tmp_dir:
        build_dir = Path(tmp_dir)
        prepare_manifest_build_context(repo_path, build_dir, base_image=base_image)
        proc = subprocess.run(
            ["docker", "build", "-t", tag, "-f", str(build_dir / "Dockerfile"), str(build_dir)],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"Failed to build dependency sandbox image {tag}: {proc.stderr.strip() or proc.stdout.strip()}"
            )
    return tag


def prune_dependency_images() -> list[str]:
    """Remove all cached `vulnbox-deps:*` Docker images and return removed tags."""
    if not shutil.which("docker"):
        return []
    ls_proc = subprocess.run(
        [
            "docker",
            "images",
            "--filter",
            f"reference={DEP_IMAGE_PREFIX}:*",
            "--format",
            "{{.Repository}}:{{.Tag}}",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if ls_proc.returncode != 0:
        return []
    tags = [ln.strip() for ln in ls_proc.stdout.splitlines() if ln.strip() and not ln.endswith(":<none>")]
    removed: list[str] = []
    for tag in tags:
        rm = subprocess.run(
            ["docker", "rmi", "-f", tag],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if rm.returncode == 0:
            removed.append(tag)
    return removed
