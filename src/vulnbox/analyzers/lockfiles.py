"""Lockfile-accurate dependency extraction and PEP 440 / SemVer 2.0 version comparison.

Supports:
  - Node.js: package-lock.json (v1/v2/v3), yarn.lock (v1 & Berry), pnpm-lock.yaml (v6/v9),
    falling back to package.json when no lockfile is present in the same directory.
  - Python: poetry.lock, uv.lock, requirements.txt, pyproject.toml.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from packaging.version import InvalidVersion, Version

from vulnbox.analyzers.base import SKIP_DIRS
from vulnbox.constants import is_test_or_fixture_path

REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(==|<=|>=|~=|!=|<|>)\s*([0-9][A-Za-z0-9_.*+-]*)"
)
PYPROJECT_DEP_RE = re.compile(
    r'"([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(==|<=|>=|~=|!=|<|>)\s*([0-9][A-Za-z0-9_.*+-]*)'
)
SEMVER_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)
YARN_HEADER_RE = re.compile(r'^"?((?:@[^/@\s]+/)?[^/@\s",:]+)@(?:npm:)?[^":,]+')
YARN_VERSION_RE = re.compile(r'^\s+version[:\s]+"?([^"\s]+)"?')
PNPM_KEY_RE = re.compile(r"^/?((?:@[^/@]+/)?[^/@]+)@([0-9][^(_\s]*)")


@dataclass(frozen=True)
class InstalledPackage:
    """A single dependency extracted from a lockfile or manifest."""

    ecosystem: str  # "python" or "node"
    name: str
    version: str
    manifest: str
    line_no: int = 1
    is_lockfile: bool = False
    raw_spec: str = ""


def _parse_semver(ver: str) -> tuple[int, int, int, int, tuple[tuple[int, int | str], ...]] | None:
    """Parse a SemVer 2.0 version string with proper pre-release ordering.

    Pre-release versions sort strictly lower than the corresponding release
    (e.g. `4.17.21-rc.1 < 4.17.21`, `1.0.0-alpha.1 < 1.0.0-alpha.2 < 1.0.0-beta`).
    """
    cleaned = ver.strip().lstrip("^~>=<")
    # Handle compound ranges like ">=1.2.3 <2.0.0" or "1.2.3 || 2.0.0" by taking the lower bound
    cleaned = cleaned.split("||")[0].strip().split()[0].strip()
    m = SEMVER_RE.match(cleaned)
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    prerelease = m.group(4)
    if not prerelease:
        return (major, minor, patch, 1, ())
    pre_parts: list[tuple[int, int | str]] = []
    for part in prerelease.split("."):
        if part.isdigit():
            pre_parts.append((0, int(part)))
        else:
            pre_parts.append((1, part))
    return (major, minor, patch, 0, tuple(pre_parts))


def compare_versions(a: str, b: str, ecosystem: str = "python") -> int:
    """Compare two version strings using PEP 440 (Python) or SemVer 2.0 (Node/Go).

    Returns -1 if `a < b`, 0 if `a == b`, or 1 if `a > b`.
    """
    if ecosystem in ("node", "go"):
        sv_a = _parse_semver(a)
        sv_b = _parse_semver(b)
        if sv_a is not None and sv_b is not None:
            return -1 if sv_a < sv_b else (1 if sv_a > sv_b else 0)

    try:
        v_a = Version(a.strip().lstrip("^~>=<v"))
        v_b = Version(b.strip().lstrip("^~>=<v"))
        return -1 if v_a < v_b else (1 if v_a > v_b else 0)
    except InvalidVersion:
        sv_a = _parse_semver(a)
        sv_b = _parse_semver(b)
        if sv_a is not None and sv_b is not None:
            return -1 if sv_a < sv_b else (1 if sv_a > sv_b else 0)
        nums_a = tuple(int(x) for x in re.findall(r"\d+", a)[:4]) or (0,)
        nums_b = tuple(int(x) for x in re.findall(r"\d+", b)[:4]) or (0,)
        return -1 if nums_a < nums_b else (1 if nums_a > nums_b else 0)


def is_version_below(installed: str, threshold: str, ecosystem: str = "python") -> bool:
    """Accurately compare `installed < threshold` using PEP 440 (Python) or SemVer 2.0 (Node/Go)."""
    return compare_versions(installed, threshold, ecosystem=ecosystem) < 0


def is_version_in_ranges(
    installed: str,
    ranges: list[dict[str, str]],
    ecosystem: str = "python",
) -> tuple[bool, str | None]:
    """Check whether `installed` falls inside any OSV version range `{introduced, fixed?, last_affected?}`.

    Returns `(is_affected, matching_fixed_version)` for the specific affected branch so
    multi-branch fixes (e.g. Django 3.2.20 vs 4.2.3) never falsely flag already-patched branches.
    """
    for rng in ranges:
        intro = str(rng.get("introduced") or "0").strip()
        fixed = str(rng.get("fixed") or "").strip()
        last_aff = str(rng.get("last_affected") or "").strip()

        if intro and intro != "0":
            if compare_versions(installed, intro, ecosystem=ecosystem) < 0:
                continue
        if fixed:
            if compare_versions(installed, fixed, ecosystem=ecosystem) >= 0:
                continue
        if last_aff:
            if compare_versions(installed, last_aff, ecosystem=ecosystem) > 0:
                continue
        return True, (fixed or None)
    return False, None


def _iter_manifest_files(workspace_dir: Path, names: tuple[str, ...]) -> list[Path]:
    found: list[Path] = []
    for path in sorted(workspace_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(workspace_dir)
        if any(part in SKIP_DIRS for part in rel.parts) or is_test_or_fixture_path(rel):
            continue
        if len(rel.parts) <= 4 and path.name in names:
            found.append(path)
    return found


def _find_line_no(lines: list[str], needle: str) -> int:
    for idx, line in enumerate(lines, start=1):
        if needle in line:
            return idx
    return 1


def _parse_package_lock_json(lock_file: Path, workspace_dir: Path) -> list[InstalledPackage]:
    rel = str(lock_file.relative_to(workspace_dir))
    try:
        raw = lock_file.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    lines = raw.splitlines()
    found: dict[tuple[str, str], InstalledPackage] = {}

    # lockfileVersion 2 & 3: "packages": { "node_modules/lodash": {"version": "4.17.20"} }
    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_path, entry in packages.items():
            if not pkg_path or not isinstance(entry, dict):
                continue
            ver = entry.get("version")
            if not isinstance(ver, str) or not ver:
                continue
            if "node_modules/" in pkg_path:
                pkg_name = pkg_path.rsplit("node_modules/", 1)[-1].lower()
            else:
                pkg_name = str(entry.get("name") or pkg_path).lower()
            key = (pkg_name, ver)
            if key not in found:
                found[key] = InstalledPackage(
                    ecosystem="node",
                    name=pkg_name,
                    version=ver,
                    manifest=rel,
                    line_no=_find_line_no(lines, f'"{pkg_path}"'),
                    is_lockfile=True,
                    raw_spec=ver,
                )

    # lockfileVersion 1 fallback: "dependencies": { "lodash": {"version": "4.17.20"} }
    if not found and isinstance(data.get("dependencies"), dict):
        def _walk_v1(dep_map: dict[str, Any]) -> None:
            for pkg_name, entry in dep_map.items():
                if not isinstance(entry, dict):
                    continue
                ver = entry.get("version")
                if isinstance(ver, str) and ver:
                    key = (pkg_name.lower(), ver)
                    if key not in found:
                        found[key] = InstalledPackage(
                            ecosystem="node",
                            name=pkg_name.lower(),
                            version=ver,
                            manifest=rel,
                            line_no=_find_line_no(lines, f'"{pkg_name}"'),
                            is_lockfile=True,
                            raw_spec=ver,
                        )
                nested = entry.get("dependencies")
                if isinstance(nested, dict):
                    _walk_v1(nested)

        _walk_v1(data["dependencies"])

    return list(found.values())


def _parse_yarn_lock(lock_file: Path, workspace_dir: Path) -> list[InstalledPackage]:
    rel = str(lock_file.relative_to(workspace_dir))
    try:
        lines = lock_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    found: dict[tuple[str, str], InstalledPackage] = {}
    current_pkg: str | None = None
    current_line = 1

    for idx, line in enumerate(lines, start=1):
        if not line or line.startswith("#") or line.startswith("__metadata"):
            continue
        if not line[0].isspace():
            m_hdr = YARN_HEADER_RE.match(line.strip())
            current_pkg = m_hdr.group(1).lower() if m_hdr else None
            current_line = idx
        elif current_pkg:
            m_ver = YARN_VERSION_RE.match(line)
            if m_ver:
                ver = m_ver.group(1).strip()
                key = (current_pkg, ver)
                if key not in found:
                    found[key] = InstalledPackage(
                        ecosystem="node",
                        name=current_pkg,
                        version=ver,
                        manifest=rel,
                        line_no=current_line,
                        is_lockfile=True,
                        raw_spec=ver,
                    )
                current_pkg = None
    return list(found.values())


def _parse_pnpm_lock(lock_file: Path, workspace_dir: Path) -> list[InstalledPackage]:
    rel = str(lock_file.relative_to(workspace_dir))
    try:
        raw = lock_file.read_text(encoding="utf-8", errors="ignore")
        data = yaml.safe_load(raw)
    except (OSError, yaml.YAMLError):
        return []
    if not isinstance(data, dict):
        return []

    lines = raw.splitlines()
    found: dict[tuple[str, str], InstalledPackage] = {}
    for section_name in ("packages", "snapshots"):
        section = data.get(section_name)
        if not isinstance(section, dict):
            continue
        for pkg_key in section:
            if not isinstance(pkg_key, str):
                continue
            m = PNPM_KEY_RE.match(pkg_key.strip("'\""))
            if not m:
                continue
            pkg_name, ver = m.group(1).lower(), m.group(2)
            key = (pkg_name, ver)
            if key not in found:
                found[key] = InstalledPackage(
                    ecosystem="node",
                    name=pkg_name,
                    version=ver,
                    manifest=rel,
                    line_no=_find_line_no(lines, pkg_key),
                    is_lockfile=True,
                    raw_spec=ver,
                )
    return list(found.values())


def _parse_toml_lockfile(lock_file: Path, workspace_dir: Path) -> list[InstalledPackage]:
    """Parse `poetry.lock` or `uv.lock` `[[package]]` entries via stdlib tomllib."""
    rel = str(lock_file.relative_to(workspace_dir))
    try:
        raw = lock_file.read_text(encoding="utf-8", errors="ignore")
        data = tomllib.loads(raw)
    except (OSError, tomllib.TOMLDecodeError):
        return []

    lines = raw.splitlines()
    packages = data.get("package")
    if not isinstance(packages, list):
        return []

    out: list[InstalledPackage] = []
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        ver = entry.get("version")
        if isinstance(name, str) and isinstance(ver, str) and name and ver:
            out.append(
                InstalledPackage(
                    ecosystem="python",
                    name=name.lower(),
                    version=ver,
                    manifest=rel,
                    line_no=_find_line_no(lines, f'name = "{name}"'),
                    is_lockfile=True,
                    raw_spec=f"=={ver}",
                )
            )
    return out


def parse_python_dependencies(workspace_dir: Path) -> list[InstalledPackage]:
    """Extract Python dependencies, preferring lockfiles (`uv.lock`, `poetry.lock`) over manifests."""
    deps: list[InstalledPackage] = []
    locked_dirs: set[Path] = set()
    locked_pkgs: set[str] = set()

    for lock_file in _iter_manifest_files(workspace_dir, ("uv.lock", "poetry.lock")):
        parsed = _parse_toml_lockfile(lock_file, workspace_dir)
        if parsed:
            deps.extend(parsed)
            locked_dirs.add(lock_file.parent)
            locked_pkgs.update(p.name for p in parsed)

    def _is_covered_by_lockfile(path: Path, pkg: str) -> bool:
        if path.parent in locked_dirs:
            return True
        return pkg in locked_pkgs and any(anc in locked_dirs for anc in path.parents)

    for req_file in _iter_manifest_files(workspace_dir, ("requirements.txt",)):
        if req_file.parent in locked_dirs:
            continue
        rel = str(req_file.relative_to(workspace_dir))
        for idx, line in enumerate(
            req_file.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1
        ):
            stripped = line.split("#", 1)[0].strip()
            if not stripped or stripped.startswith("-"):
                continue
            m = REQ_LINE_RE.match(stripped)
            if m:
                pkg, op, ver = m.group(1).lower(), m.group(2), m.group(3)
                if _is_covered_by_lockfile(req_file, pkg):
                    continue
                deps.append(
                    InstalledPackage(
                        ecosystem="python",
                        name=pkg,
                        version=ver,
                        manifest=rel,
                        line_no=idx,
                        is_lockfile=(op == "=="),
                        raw_spec=f"{op}{ver}",
                    )
                )

    for pyproj in _iter_manifest_files(workspace_dir, ("pyproject.toml",)):
        if pyproj.parent in locked_dirs:
            continue
        rel = str(pyproj.relative_to(workspace_dir))
        for idx, line in enumerate(
            pyproj.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1
        ):
            for m in PYPROJECT_DEP_RE.finditer(line):
                pkg, op, ver = m.group(1).lower(), m.group(2), m.group(3)
                if op in ("==", "<=", "<", "~="):
                    if _is_covered_by_lockfile(pyproj, pkg):
                        continue
                    deps.append(
                        InstalledPackage(
                            ecosystem="python",
                            name=pkg,
                            version=ver,
                            manifest=rel,
                            line_no=idx,
                            is_lockfile=(op == "=="),
                            raw_spec=f"{op}{ver}",
                        )
                    )

    return deps


def parse_node_dependencies(workspace_dir: Path) -> list[InstalledPackage]:
    """Extract Node.js dependencies, preferring exact lockfile versions over package.json ranges."""
    deps: list[InstalledPackage] = []
    locked_dirs: set[Path] = set()

    for lock_file in _iter_manifest_files(
        workspace_dir, ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
    ):
        if lock_file.name == "package-lock.json":
            parsed = _parse_package_lock_json(lock_file, workspace_dir)
        elif lock_file.name == "yarn.lock":
            parsed = _parse_yarn_lock(lock_file, workspace_dir)
        else:
            parsed = _parse_pnpm_lock(lock_file, workspace_dir)
        if parsed:
            deps.extend(parsed)
            locked_dirs.add(lock_file.parent)

    for pkg_file in _iter_manifest_files(workspace_dir, ("package.json",)):
        if pkg_file.parent in locked_dirs:
            continue
        rel = str(pkg_file.relative_to(workspace_dir))
        try:
            raw = pkg_file.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError):
            continue
        lines = raw.splitlines()
        for section in ("dependencies", "devDependencies"):
            entries = data.get(section) or {}
            if not isinstance(entries, dict):
                continue
            for pkg, ver in entries.items():
                if not isinstance(ver, str) or not ver.strip():
                    continue
                is_exact = bool(SEMVER_RE.match(ver.strip()))
                deps.append(
                    InstalledPackage(
                        ecosystem="node",
                        name=pkg.lower(),
                        version=ver.strip(),
                        manifest=rel,
                        line_no=_find_line_no(lines, f'"{pkg}"'),
                        is_lockfile=is_exact,
                        raw_spec=ver.strip(),
                    )
                )

    return deps


_GO_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_./-]+)\s+(v[0-9][^\s/]*)(?:\s*//.*)?$")
_GO_REPLACE_RE = re.compile(
    r"^\s*([A-Za-z0-9_./-]+)(?:\s+v[^\s]+)?\s*=>\s*([A-Za-z0-9_./-]+)\s+(v[0-9][^\s/]*)(?:\s*//.*)?$"
)


def parse_go_mod(workspace_dir: Path) -> list[InstalledPackage]:
    """Parse `go.mod` module requirements (single-line, block `require (...)`, and `replace`)."""
    deps: list[InstalledPackage] = []
    for mod_file in _iter_manifest_files(workspace_dir, ("go.mod",)):
        rel = str(mod_file.relative_to(workspace_dir))
        try:
            lines = mod_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        in_require = False
        in_replace = False
        reqs: dict[str, tuple[str, int]] = {}
        replaces: dict[str, tuple[str, str]] = {}

        for idx, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            if stripped.startswith("require ("):
                in_require = True
                continue
            if stripped.startswith("replace ("):
                in_replace = True
                continue
            if stripped == ")":
                in_require = False
                in_replace = False
                continue

            if stripped.startswith("require ") and not in_require:
                m = _GO_REQ_LINE_RE.match(stripped[len("require ") :])
                if m:
                    reqs[m.group(1)] = (m.group(2), idx)
            elif in_require:
                m = _GO_REQ_LINE_RE.match(stripped)
                if m:
                    reqs[m.group(1)] = (m.group(2), idx)
            elif stripped.startswith("replace ") and not in_replace:
                rm = _GO_REPLACE_RE.match(stripped[len("replace ") :])
                if rm:
                    replaces[rm.group(1)] = (rm.group(2), rm.group(3))
            elif in_replace:
                rm = _GO_REPLACE_RE.match(stripped)
                if rm:
                    replaces[rm.group(1)] = (rm.group(2), rm.group(3))

        for mod_path, (ver, line_no) in reqs.items():
            eff_mod, eff_ver = replaces.get(mod_path, (mod_path, ver))
            deps.append(
                InstalledPackage(
                    ecosystem="go",
                    name=eff_mod,
                    version=eff_ver.lstrip("v"),
                    manifest=rel,
                    line_no=line_no,
                    is_lockfile=True,
                    raw_spec=eff_ver,
                )
            )
    return deps
