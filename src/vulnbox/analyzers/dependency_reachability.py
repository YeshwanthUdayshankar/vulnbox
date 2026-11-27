"""Dependency CVE reachability & safe pinned upgrade analyzer (Python & Node.js)."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from vulnbox.analyzers.advisory_feed import (
    PYPI_IMPORT_ALIASES,
    load_offline_enrichment,
    load_offline_osv_advisories,
)
from vulnbox.analyzers.base import iter_source_files, make_finding_id, safe_ast_parse
from vulnbox.analyzers.lockfiles import (
    InstalledPackage,
    compute_reverse_dependents,
    is_version_below,
    is_version_in_ranges,
    parse_node_dependencies,
    parse_python_dependencies,
)
from vulnbox.models import Finding, ReachabilityStatus, Severity


class Advisory(BaseModel):
    """Normalized dependency vulnerability advisory."""

    advisory_id: str
    ecosystem: str  # "python", "node", or "go"
    package: str
    affected_below: str = ""
    fixed_version: str = ""
    affected_ranges: list[dict[str, str]] = Field(default_factory=list)
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

def _is_version_below(installed: str, threshold: str, ecosystem: str = "python") -> bool:
    return is_version_below(installed, threshold, ecosystem=ecosystem)


def _parse_python_dependencies(workspace_dir: Path) -> list[InstalledPackage]:
    return parse_python_dependencies(workspace_dir)


def _parse_node_dependencies(workspace_dir: Path) -> list[InstalledPackage]:
    return parse_node_dependencies(workspace_dir)


def _build_python_ast_index(workspace_dir: Path) -> list[tuple[str, ast.AST]]:
    index: list[tuple[str, ast.AST]] = []
    for py_file in iter_source_files(workspace_dir, (".py",)):
        try:
            src = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = safe_ast_parse(src, filename=str(py_file))
        except (OSError, SyntaxError):
            continue
        index.append((str(py_file.relative_to(workspace_dir)), tree))
    return index


def _build_node_source_index(workspace_dir: Path) -> list[tuple[str, str, list[str]]]:
    index: list[tuple[str, str, list[str]]] = []
    for js_file in iter_source_files(workspace_dir, (".js", ".mjs", ".cjs", ".ts")):
        low = js_file.name.lower()
        if low.endswith((".min.js", ".min.mjs", ".bundle.js", "-bundle.js", ".chunk.js")):
            continue
        try:
            src = js_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if len(src) > 250_000:
            continue
        index.append((str(js_file.relative_to(workspace_dir)), src, src.splitlines()))
    return index


def _check_python_reachability(
    workspace_dir: Path,
    import_names: list[str],
    vulnerable_symbols: list[str],
    py_index: list[tuple[str, ast.AST]] | None = None,
) -> tuple[ReachabilityStatus, list[str]]:
    """Perform deterministic Python AST import & symbol call-graph reachability."""
    imported_files: list[str] = []
    symbol_citations: list[str] = []
    targets = set(import_names)
    sym_tails = {s.split(".")[-1] for s in vulnerable_symbols}

    entries = py_index if py_index is not None else _build_python_ast_index(workspace_dir)
    for rel, tree in entries:
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
        # Never claim `not_reachable` merely because a package is not directly imported:
        # it may be pulled in transitively (e.g. urllib3 via requests) or use a non-obvious import alias.
        return "under_investigation", []
    if not vulnerable_symbols:
        return "under_investigation", imported_files
    if symbol_citations:
        return "reachable", sorted(set(symbol_citations))
    # Direct import confirmed, explicit vulnerable_symbols known, and zero vulnerable symbols invoked
    return "not_reachable", imported_files


def _check_node_reachability(
    workspace_dir: Path,
    import_names: list[str],
    vulnerable_symbols: list[str],
    js_index: list[tuple[str, str, list[str]]] | None = None,
) -> tuple[ReachabilityStatus, list[str]]:
    """Perform deterministic JS/TS import/require & symbol reachability."""
    imported_files: list[str] = []
    symbol_citations: list[str] = []
    import_patterns = [
        re.compile(
            rf"""(?:require\s*\(\s*['"]{re.escape(pkg)}['"]\s*\)|from\s+['"]{re.escape(pkg)}['"])"""
        )
        for pkg in import_names
    ]
    sym_patterns = [(sym, re.compile(rf"\b{re.escape(sym)}\s*\(")) for sym in vulnerable_symbols]

    entries = js_index if js_index is not None else _build_node_source_index(workspace_dir)
    for rel, src, lines in entries:
        file_imports = any(pat.search(src) for pat in import_patterns)
        if not file_imports:
            continue
        imported_files.append(rel)
        if not sym_patterns:
            continue
        for idx, line in enumerate(lines, start=1):
            for sym, spat in sym_patterns:
                if spat.search(line):
                    symbol_citations.append(f"{rel}:{idx} ({sym})")

    if not imported_files:
        # Never claim `not_reachable` merely because a package is not directly imported:
        # it may be pulled in transitively (e.g. urllib3 via requests) or use a non-obvious import alias.
        return "under_investigation", []
    if not vulnerable_symbols:
        return "under_investigation", imported_files
    if symbol_citations:
        return "reachable", sorted(set(symbol_citations))
    # Direct import confirmed, explicit vulnerable_symbols known, and zero vulnerable symbols invoked
    return "not_reachable", imported_files


def load_advisories(
    advisories_path: Path | None = None,
    cache_dir: Path | None = None,
) -> list[Advisory]:
    """Load built-in advisories + offline cached OSV.dev feed + optional user JSON file."""
    advisories: list[Advisory] = list(BUILTIN_ADVISORIES)
    seen: set[tuple[str, str, str]] = {
        (a.advisory_id, a.ecosystem, a.package.lower()) for a in advisories
    }

    for cached in load_offline_osv_advisories(cache_dir):
        try:
            adv = Advisory.model_validate(cached)
        except Exception:
            continue
        key = (adv.advisory_id, adv.ecosystem, adv.package.lower())
        if key not in seen:
            seen.add(key)
            advisories.append(adv)

    if advisories_path and advisories_path.is_file():
        raw: Any = json.loads(advisories_path.read_text(encoding="utf-8"))
        items = raw if isinstance(raw, list) else raw.get("advisories", [])
        for item in items:
            adv = Advisory.model_validate(item)
            key = (adv.advisory_id, adv.ecosystem, adv.package.lower())
            if key not in seen:
                seen.add(key)
                advisories.append(adv)
    return advisories


class DependencyReachabilityAnalyzer:
    """Checks lockfiles/manifests against advisories and verifies static/hybrid reachability."""

    name = "dependency-reachability"

    def __init__(
        self,
        advisories_path: Path | None = None,
        cache_dir: Path | None = None,
    ) -> None:
        self.cache_dir = cache_dir
        self.advisories = load_advisories(advisories_path, cache_dir=cache_dir)

    def analyze(self, workspace_dir: Path, call_graph: Any | None = None) -> list[Finding]:
        findings: list[Finding] = []
        py_deps = _parse_python_dependencies(workspace_dir)
        node_deps = _parse_node_dependencies(workspace_dir)
        kev_cves, epss_scores = load_offline_enrichment(self.cache_dir)

        py_index: list[tuple[str, ast.AST]] | None = None
        js_index: list[tuple[str, str, list[str]]] | None = None
        py_rev_deps, py_graph_known = compute_reverse_dependents(workspace_dir, "python")
        node_rev_deps, node_graph_known = compute_reverse_dependents(workspace_dir, "node")

        for adv in self.advisories:
            if adv.ecosystem not in ("python", "node"):
                continue
            target_deps = py_deps if adv.ecosystem == "python" else node_deps
            rev_deps = py_rev_deps if adv.ecosystem == "python" else node_rev_deps
            graph_known = py_graph_known if adv.ecosystem == "python" else node_graph_known
            for dep in target_deps:
                pkg = dep.name
                installed_ver = dep.version
                manifest = dep.manifest
                line_no = dep.line_no
                if pkg != adv.package.lower():
                    continue
                if adv.affected_ranges:
                    affected, branch_fixed = is_version_in_ranges(
                        installed_ver, adv.affected_ranges, ecosystem=adv.ecosystem
                    )
                    if not affected:
                        continue
                    effective_fixed = branch_fixed or adv.fixed_version or ""
                else:
                    if not adv.affected_below or not _is_version_below(
                        installed_ver, adv.affected_below, ecosystem=adv.ecosystem
                    ):
                        continue
                    effective_fixed = adv.fixed_version or adv.affected_below

                # Merge any known PyPI distribution -> import module aliases
                import_candidates = list(adv.imports or [])
                if adv.ecosystem == "python":
                    for alias_imp in PYPI_IMPORT_ALIASES.get(adv.package.lower(), []):
                        if alias_imp not in import_candidates:
                            import_candidates.append(alias_imp)
                if not import_candidates:
                    import_candidates = [adv.package.lower().replace("-", "_")]

                if adv.ecosystem == "python":
                    if py_index is None:
                        py_index = _build_python_ast_index(workspace_dir)
                    reachability, citations = _check_python_reachability(
                        workspace_dir,
                        import_candidates,
                        adv.vulnerable_symbols,
                        py_index=py_index,
                    )
                else:
                    if js_index is None:
                        js_index = _build_node_source_index(workspace_dir)
                    reachability, citations = _check_node_reachability(
                        workspace_dir,
                        import_candidates,
                        adv.vulnerable_symbols,
                        js_index=js_index,
                    )

                call_path: list[str] = []
                call_path_provenance: list[str] = []
                if call_graph is not None:
                    pkg_prefixes = [f"external::{imp}" for imp in import_candidates]
                    sym_tails = [s.split(".")[-1] for s in adv.vulnerable_symbols]

                    def _matches_vuln(node_id: str, prefixes=pkg_prefixes, tails=sym_tails) -> bool:
                        if not any(node_id.startswith(p) for p in prefixes):
                            return False
                        if not tails:
                            return True
                        return any(node_id.endswith(f".{t}") or node_id.endswith(f"::{t}") for t in tails)

                    cg_hit = call_graph.shortest_path_from_entrypoints(_matches_vuln)
                    if cg_hit is not None:
                        cand_path, cand_prov = cg_hit
                        # Guard against cross-ecosystem external symbol collisions (e.g. npm `uuid` matching Python stdlib `uuid`)
                        caller_id = cand_path[0] if cand_path else ""
                        caller_file = caller_id.split("::", 1)[0].lower()
                        eco_ok = (
                            caller_file.endswith(".py")
                            if adv.ecosystem == "python"
                            else caller_file.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx"))
                        )
                        if eco_ok:
                            call_path, call_path_provenance = cand_path, cand_prov
                            if reachability != "reachable":
                                reachability = "reachable"

                # Soundness gate: even when app code only calls safe symbols directly,
                # another dependency in the lockfile (e.g. `requests` calling `urllib3.PoolManager`)
                # may still call the vulnerable code internally. Only keep `not_reachable` when
                # we can prove zero other dependencies depend on this package.
                pkg_dependents = sorted(rev_deps.get(adv.package.lower(), set()))
                other_deps_present = len({d.name for d in target_deps} - {adv.package.lower()}) > 0
                has_potential_dependents = (
                    bool(pkg_dependents) if graph_known else other_deps_present
                )
                if reachability == "not_reachable" and has_potential_dependents:
                    reachability = "under_investigation"
                    reach_basis = "imported_safe_symbols_but_has_dependents"
                elif reachability == "reachable":
                    reach_basis = "symbol_call_confirmed"
                elif reachability == "not_reachable":
                    reach_basis = "imported_safe_symbols_no_dependents"
                elif citations:
                    reach_basis = "imported_no_symbol_metadata"
                else:
                    reach_basis = "not_directly_imported"

                rule_id = f"DEP-{adv.advisory_id}"
                cite_text = f" Citations: {', '.join(citations)}." if citations else ""
                path_text = f" Call path: {' -> '.join(call_path)}." if call_path else ""
                is_kev = adv.advisory_id in kev_cves
                epss_info = epss_scores.get(adv.advisory_id)
                risk_tags: list[str] = []
                if is_kev:
                    risk_tags.append("CISA-KEV")
                if epss_info:
                    risk_tags.append(f"EPSS={epss_info['epss']:.3f}")
                risk_text = f" Risk intel: {', '.join(risk_tags)}." if risk_tags else ""

                meta: dict[str, Any] = {
                    "ecosystem": adv.ecosystem,
                    "package": adv.package,
                    "installed_version": installed_ver,
                    "version_source": "lockfile" if dep.is_lockfile else "manifest_range",
                    "fixed_version": effective_fixed,
                    "advisory_id": adv.advisory_id,
                    "citations": citations,
                    "reachability_basis": reach_basis,
                    "cisa_kev": is_kev,
                }
                if pkg_dependents:
                    meta["reverse_dependents"] = pkg_dependents
                if epss_info:
                    meta["epss_score"] = epss_info["epss"]
                    meta["epss_percentile"] = epss_info["percentile"]
                if call_path:
                    meta["call_path"] = call_path
                    meta["call_path_provenance"] = call_path_provenance

                fix_clause = f"fix: >= {effective_fixed}" if effective_fixed else "no upstream fix published yet"
                rec_fix = (
                    f"Upgrade '{adv.package}' in {manifest} to >= {effective_fixed}."
                    if effective_fixed
                    else f"No fixed version of '{adv.package}' is published yet for {adv.advisory_id}; apply vendor mitigations or consider an alternative package."
                )

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
                            f"Dependency '{adv.package}' version '{installed_ver}' "
                            f"({'lockfile' if dep.is_lockfile else 'manifest range'}) is affected by "
                            f"{adv.advisory_id} ({fix_clause}). Reachability: {reachability}."
                            f"{risk_text}{cite_text}{path_text}"
                        ),
                        reachability=reachability,
                        recommended_fix=rec_fix,
                        metadata=meta,
                    )
                )

        return findings
