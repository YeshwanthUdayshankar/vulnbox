"""Dependency CVE reachability & safe pinned upgrade analyzer (Python & Node.js)."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from vulnbox.analyzers.base import SKIP_DIRS, iter_source_files, make_finding_id
from vulnbox.models import Finding, ReachabilityStatus, Severity


class Advisory(BaseModel):
    """Normalized dependency vulnerability advisory."""

    advisory_id: str
    ecosystem: str  # "python" or "node"
    package: str
    affected_below: str
    fixed_version: str
    severity: Severity = "high"
    cwe_id: str = "CWE-1104"
    title: str
    imports: list[str] = Field(default_factory=list)
    vulnerable_symbols: list[str] = Field(default_factory=list)


BUILTIN_ADVISORIES: list[Advisory] = [
    Advisory(
        advisory_id="CVE-2020-14343",
        ecosystem="python",
        package="pyyaml",
        affected_below="5.4",
        fixed_version="6.0.2",
        severity="critical",
        cwe_id="CWE-502",
        title="PyYAML Arbitrary Code Execution via FullLoader/load",
        imports=["yaml"],
        vulnerable_symbols=["yaml.load", "yaml.full_load", "FullLoader"],
    ),
    Advisory(
        advisory_id="CVE-2023-45803",
        ecosystem="python",
        package="urllib3",
        affected_below="2.0.7",
        fixed_version="2.2.3",
        severity="medium",
        cwe_id="CWE-200",
        title="urllib3 Request Body Not Stripped on Cross-Origin Redirect",
        imports=["urllib3"],
        vulnerable_symbols=["PoolManager", "HTTPConnectionPool", "request"],
    ),
    Advisory(
        advisory_id="CVE-2021-23337",
        ecosystem="node",
        package="lodash",
        affected_below="4.17.21",
        fixed_version="4.17.21",
        severity="high",
        cwe_id="CWE-78",
        title="lodash Command Injection in template()",
        imports=["lodash"],
        vulnerable_symbols=["template"],
    ),
    Advisory(
        advisory_id="CVE-2021-44906",
        ecosystem="node",
        package="minimist",
        affected_below="1.2.6",
        fixed_version="1.2.8",
        severity="critical",
        cwe_id="CWE-1321",
        title="minimist Prototype Pollution",
        imports=["minimist"],
        vulnerable_symbols=[],
    ),
    Advisory(
        advisory_id="CVE-2024-29041",
        ecosystem="node",
        package="express",
        affected_below="4.19.2",
        fixed_version="4.21.2",
        severity="medium",
        cwe_id="CWE-601",
        title="Express Open Redirect via Malformed URL in res.redirect()",
        imports=["express"],
        vulnerable_symbols=["redirect"],
    ),
]

VERSION_NUM_RE = re.compile(r"(\d+)")
REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(==|<=|>=|~=|!=|<|>)\s*([0-9][A-Za-z0-9_.*+-]*)")


def _parse_version(ver: str) -> tuple[int, ...]:
    cleaned = ver.strip().lstrip("^~>=<v")
    parts = [int(m) for m in VERSION_NUM_RE.findall(cleaned)]
    return tuple(parts[:4]) if parts else (0,)


def _is_version_below(installed: str, threshold: str) -> bool:
    return _parse_version(installed) < _parse_version(threshold)


UV_LOCK_PKG_RE = re.compile(r'^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', re.MULTILINE)
PYPROJECT_DEP_RE = re.compile(r'"([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(==|<=|>=|~=|!=|<|>)\s*([0-9][A-Za-z0-9_.*+-]*)')


def _iter_manifest_files(workspace_dir: Path, names: tuple[str, ...]) -> list[Path]:
    found: list[Path] = []
    for path in sorted(workspace_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(workspace_dir)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if len(rel.parts) <= 4 and path.name in names:
            found.append(path)
    return found


def _parse_python_dependencies(workspace_dir: Path) -> list[tuple[str, str, str, int]]:
    """Return list of (package_lower, version, manifest_rel_path, line_no) across monorepo."""
    deps: list[tuple[str, str, str, int]] = []
    seen_keys: set[tuple[str, str]] = set()

    for req_file in _iter_manifest_files(workspace_dir, ("requirements.txt",)):
        rel = str(req_file.relative_to(workspace_dir))
        for idx, line in enumerate(req_file.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            stripped = line.split("#", 1)[0].strip()
            if not stripped:
                continue
            m = REQ_LINE_RE.match(stripped)
            if m:
                pkg = m.group(1).lower()
                deps.append((pkg, m.group(3), rel, idx))
                seen_keys.add((pkg, rel))

    for lock_file in _iter_manifest_files(workspace_dir, ("uv.lock",)):
        rel = str(lock_file.relative_to(workspace_dir))
        raw = lock_file.read_text(encoding="utf-8", errors="ignore")
        for m in UV_LOCK_PKG_RE.finditer(raw):
            pkg, ver = m.group(1).lower(), m.group(2)
            line_no = raw[: m.start()].count("\n") + 1
            deps.append((pkg, ver, rel, line_no))
            seen_keys.add((pkg, rel))

    for pyproj in _iter_manifest_files(workspace_dir, ("pyproject.toml",)):
        rel = str(pyproj.relative_to(workspace_dir))
        for idx, line in enumerate(pyproj.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            for m in PYPROJECT_DEP_RE.finditer(line):
                pkg, op, ver = m.group(1).lower(), m.group(2), m.group(3)
                if op in ("==", "<=", "<", "~="):
                    deps.append((pkg, ver, rel, idx))
                    seen_keys.add((pkg, rel))

    return deps


def _parse_node_dependencies(workspace_dir: Path) -> list[tuple[str, str, str, int]]:
    deps: list[tuple[str, str, str, int]] = []
    for pkg_file in _iter_manifest_files(workspace_dir, ("package.json",)):
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
                if not isinstance(ver, str):
                    continue
                line_no = 1
                needle = f'"{pkg}"'
                for i, line in enumerate(lines, start=1):
                    if needle in line:
                        line_no = i
                        break
                deps.append((pkg.lower(), ver, rel, line_no))
    return deps


def _check_python_reachability(
    workspace_dir: Path,
    import_names: list[str],
    vulnerable_symbols: list[str],
) -> tuple[ReachabilityStatus, list[str]]:
    """Perform deterministic Python AST import & symbol call-graph reachability."""
    imported_files: list[str] = []
    symbol_citations: list[str] = []
    targets = set(import_names)
    sym_tails = {s.split(".")[-1] for s in vulnerable_symbols}

    for py_file in iter_source_files(workspace_dir, (".py",)):
        try:
            src = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(src, filename=str(py_file))
        except (OSError, SyntaxError):
            continue

        rel = str(py_file.relative_to(workspace_dir))
        aliases: set[str] = set()
        direct_syms: set[str] = set()
        file_imports = False

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    if root_mod in targets:
                        file_imports = True
                        aliases.add(alias.asname or root_mod)
            elif isinstance(node, ast.ImportFrom) and node.module:
                root_mod = node.module.split(".")[0]
                if root_mod in targets:
                    file_imports = True
                    for alias in node.names:
                        direct_syms.add(alias.asname or alias.name)
                        if alias.name in sym_tails:
                            symbol_citations.append(f"{rel}:{node.lineno} (import {alias.name})")

        if not file_imports:
            continue
        imported_files.append(rel)

        if not vulnerable_symbols:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id in aliases and node.attr in sym_tails:
                    symbol_citations.append(f"{rel}:{node.lineno} ({node.value.id}.{node.attr})")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in direct_syms and node.func.id in sym_tails:
                    symbol_citations.append(f"{rel}:{node.lineno} ({node.func.id}())")

    if not imported_files:
        return "not_reachable", []
    if not vulnerable_symbols:
        return "under_investigation", imported_files
    if symbol_citations:
        return "reachable", sorted(set(symbol_citations))
    return "not_reachable", imported_files


def _check_node_reachability(
    workspace_dir: Path,
    import_names: list[str],
    vulnerable_symbols: list[str],
) -> tuple[ReachabilityStatus, list[str]]:
    """Perform deterministic JS/TS import/require & symbol reachability."""
    imported_files: list[str] = []
    symbol_citations: list[str] = []

    for js_file in iter_source_files(workspace_dir, (".js", ".mjs", ".cjs", ".ts")):
        try:
            src = js_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(js_file.relative_to(workspace_dir))
        lines = src.splitlines()
        file_imports = False
        for pkg in import_names:
            pattern = re.compile(
                rf"""(?:require\s*\(\s*['"]{re.escape(pkg)}['"]\s*\)|from\s+['"]{re.escape(pkg)}['"])"""
            )
            if pattern.search(src):
                file_imports = True
                break
        if not file_imports:
            continue
        imported_files.append(rel)
        if not vulnerable_symbols:
            continue
        for idx, line in enumerate(lines, start=1):
            for sym in vulnerable_symbols:
                if re.search(rf"\b{re.escape(sym)}\s*\(", line):
                    symbol_citations.append(f"{rel}:{idx} ({sym})")

    if not imported_files:
        return "not_reachable", []
    if not vulnerable_symbols:
        return "under_investigation", imported_files
    if symbol_citations:
        return "reachable", sorted(set(symbol_citations))
    return "not_reachable", imported_files


def load_advisories(advisories_path: Path | None = None) -> list[Advisory]:
    """Load built-in advisories plus optional user-provided JSON advisory file."""
    advisories = list(BUILTIN_ADVISORIES)
    if advisories_path and advisories_path.is_file():
        raw: Any = json.loads(advisories_path.read_text(encoding="utf-8"))
        items = raw if isinstance(raw, list) else raw.get("advisories", [])
        for item in items:
            advisories.append(Advisory.model_validate(item))
    return advisories


class DependencyReachabilityAnalyzer:
    """Checks manifests against advisories and verifies static code reachability."""

    name = "dependency-reachability"

    def __init__(self, advisories_path: Path | None = None) -> None:
        self.advisories = load_advisories(advisories_path)

    def analyze(self, workspace_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        py_deps = _parse_python_dependencies(workspace_dir)
        node_deps = _parse_node_dependencies(workspace_dir)

        for adv in self.advisories:
            target_deps = py_deps if adv.ecosystem == "python" else node_deps
            for pkg, installed_ver, manifest, line_no in target_deps:
                if pkg != adv.package.lower():
                    continue
                if not _is_version_below(installed_ver, adv.affected_below):
                    continue

                if adv.ecosystem == "python":
                    reachability, citations = _check_python_reachability(
                        workspace_dir, adv.imports or [adv.package], adv.vulnerable_symbols
                    )
                else:
                    reachability, citations = _check_node_reachability(
                        workspace_dir, adv.imports or [adv.package], adv.vulnerable_symbols
                    )

                rule_id = f"DEP-{adv.advisory_id}"
                cite_text = f" Citations: {', '.join(citations)}." if citations else ""
                findings.append(
                    Finding(
                        finding_id=make_finding_id(rule_id, manifest, line_no),
                        rule_id=rule_id,
                        cwe_id=adv.cwe_id,
                        title=f"{adv.title} ({adv.package} {installed_ver})",
                        category="dependency",
                        severity=adv.severity,
                        file_path=manifest,
                        start_line=line_no,
                        end_line=line_no,
                        snippet=f"{manifest}:{line_no}: {pkg} ({installed_ver})",
                        message=(
                            f"Dependency '{adv.package}' version '{installed_ver}' is affected by "
                            f"{adv.advisory_id} (< {adv.affected_below}). Reachability: {reachability}.{cite_text}"
                        ),
                        reachability=reachability,
                        recommended_fix=f"Upgrade '{adv.package}' in {manifest} to >= {adv.fixed_version}.",
                        metadata={
                            "ecosystem": adv.ecosystem,
                            "package": adv.package,
                            "installed_version": installed_ver,
                            "fixed_version": adv.fixed_version,
                            "advisory_id": adv.advisory_id,
                            "citations": citations,
                        },
                    )
                )

        return findings
