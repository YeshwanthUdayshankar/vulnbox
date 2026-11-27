"""Go security & OSV symbol-level reachability analyzer plugin for VulnBox.

Capabilities:
  1. Function-scoped Go SAST (ignoring comments/strings, distinguishing HTTP handlers / `main`
     as `reachable` vs non-handler helpers as `under_investigation`):
     - GO-CMD-001 (CWE-78): Shell command execution via exec.Command("sh"|"bash", "-c", dynamic)
     - GO-SQL-001 (CWE-89): SQL query built via fmt.Sprintf / string concatenation
     - GO-TLS-001 (CWE-295): tls.Config{InsecureSkipVerify: true}
     - GO-PATH-001 (CWE-22): filepath.Join() + os.ReadFile()/os.Open() without separator-enforced prefix confinement
     - GO-SSRF-001 (CWE-918): http.Get() / http.NewRequest() fed from r.URL.Query() / r.FormValue()
  2. `go.mod` + Go OSV symbol-level dependency reachability:
     - Parses `go.mod` (`require`, block `require (...)`, `replace`)
     - Matches against offline OSV advisories (`ecosystem="go"`) + curated built-in Go advisories
     - Parses Go `import` blocks to map local package aliases to full import paths and verifies
       whether OSV `ecosystem_specific.imports[].symbols` are actually invoked in `.go` source.
     - Follows strict VEX soundness: unimported/transitive modules stay `under_investigation`,
       imported modules with zero vulnerable symbol calls become `not_reachable` (`not_affected`),
       and confirmed vulnerable symbol calls become `reachable` (`affected`).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vulnbox.analyzers.advisory_feed import load_offline_enrichment, load_offline_osv_advisories
from vulnbox.analyzers.base import extract_snippet, iter_source_files, make_finding_id
from vulnbox.analyzers.dependency_reachability import Advisory
from vulnbox.analyzers.lockfiles import is_version_below, is_version_in_ranges, parse_go_mod
from vulnbox.models import Finding, ReachabilityStatus
from vulnbox.registry import AnalysisContext

_GO_SHELL_CMD_RE = re.compile(
    r"""exec\.Command(?:Context)?\s*\([^)]*["'](?:sh|bash|/bin/sh|/bin/bash)["']\s*,\s*["']-c["']\s*,\s*([^)]+)\)"""
)
_GO_SQL_FMT_RE = re.compile(
    r"""\.(?:Query|QueryRow|Exec)(?:Context)?\s*\([^)]*(?:fmt\.Sprintf\s*\(\s*["'`][^"'`]*(?:SELECT|INSERT|UPDATE|DELETE)|["'`][^"'`]*(?:SELECT|INSERT|UPDATE|DELETE)[^"'`]*["'`]\s*\+)""",
    re.IGNORECASE,
)
_GO_TLS_SKIP_RE = re.compile(r"""InsecureSkipVerify\s*:\s*true\b""")
_GO_SSRF_RE = re.compile(
    r"""http\.(?:Get|Post|Head|NewRequest)\s*\([^)]*(?:r\.URL\.Query\(\)\.Get|r\.FormValue|targetURL|userURL)""",
)
_GO_PATH_JOIN_RE = re.compile(r"""filepath\.Join\s*\(""")
_GO_FILE_READ_RE = re.compile(r"""(?:os|ioutil)\.(?:ReadFile|Open)\s*\(""")
_GO_FUNC_DECL_RE = re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
_GO_HANDLER_SIG_RE = re.compile(
    r"http\.ResponseWriter|\*http\.Request|\*gin\.Context|echo\.Context|\*fiber\.Ctx"
)
_GO_SINGLE_IMPORT_RE = re.compile(r'^\s*import\s+(?:([A-Za-z_][A-Za-z0-9_]*|\.)\s+)?"([^"]+)"')
_GO_BLOCK_IMPORT_ENTRY_RE = re.compile(r'^\s*(?:([A-Za-z_][A-Za-z0-9_]*|\.)\s+)?"([^"]+)"')

BUILTIN_GO_ADVISORIES: list[Advisory] = [
    Advisory(
        advisory_id="GO-2023-2102",
        ecosystem="go",
        package="golang.org/x/net",
        affected_below="0.17.0",
        fixed_version="0.17.0",
        affected_ranges=[{"introduced": "0", "fixed": "0.17.0"}],
        severity="high",
        cwe_id="CWE-400",
        title="HTTP/2 Rapid Reset DoS in golang.org/x/net/http2",
        imports=["golang.org/x/net/http2"],
        vulnerable_symbols=["ConfigureServer", "Server.ServeConn"],
    ),
    Advisory(
        advisory_id="GO-2024-2687",
        ecosystem="go",
        package="golang.org/x/net",
        affected_below="0.23.0",
        fixed_version="0.23.0",
        affected_ranges=[{"introduced": "0", "fixed": "0.23.0"}],
        severity="medium",
        cwe_id="CWE-400",
        title="Excessive memory allocation in golang.org/x/net/http2",
        imports=["golang.org/x/net/http2"],
        vulnerable_symbols=["ConfigureServer", "Framer.ReadFrame"],
    ),
]


def _extract_go_functions(lines: list[str]) -> list[tuple[str, str, int, int]]:
    """Extract `(func_name, signature, start_line, end_line)` using brace depth tracking."""
    funcs: list[tuple[str, str, int, int]] = []
    n = len(lines)
    i = 0
    while i < n:
        m = _GO_FUNC_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        fname, sig = m.group(1), m.group(2)
        start_line = i + 1
        depth = 0
        opened = False
        j = i
        while j < n:
            code = lines[j].split("//", 1)[0]
            for ch in code:
                if ch == "{":
                    depth += 1
                    opened = True
                elif ch == "}":
                    depth -= 1
            if opened and depth <= 0:
                break
            j += 1
        funcs.append((fname, sig, start_line, j + 1))
        i = j + 1
    return funcs


def _func_reachability(
    lineno: int,
    funcs: list[tuple[str, str, int, int]],
) -> tuple[ReachabilityStatus, str]:
    """Classify Go SAST finding reachability based on enclosing function signature."""
    for fname, sig, sline, eline in funcs:
        if sline <= lineno <= eline:
            if fname == "main" or _GO_HANDLER_SIG_RE.search(sig):
                return "reachable", fname
            return "under_investigation", fname
    return "under_investigation", "<package>"


def _parse_go_imports(source: str) -> dict[str, str]:
    """Return mapping `{local_pkg_alias: full_import_path}` for all imports in a `.go` file."""
    imports: dict[str, str] = {}
    in_block = False
    for raw_line in source.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("import ("):
            in_block = True
            continue
        if in_block:
            if line == ")":
                in_block = False
                continue
            bm = _GO_BLOCK_IMPORT_ENTRY_RE.match(line)
            if bm:
                alias, imp_path = bm.group(1), bm.group(2)
                if alias == "_":
                    continue
                local = alias or imp_path.rsplit("/", 1)[-1]
                imports[local] = imp_path
        else:
            sm = _GO_SINGLE_IMPORT_RE.match(line)
            if sm:
                alias, imp_path = sm.group(1), sm.group(2)
                if alias == "_":
                    continue
                local = alias or imp_path.rsplit("/", 1)[-1]
                imports[local] = imp_path
    return imports


def _check_go_symbol_reachability(
    go_sources: list[tuple[str, str, dict[str, str]]],
    import_paths: list[str],
    module_path: str,
    vulnerable_symbols: list[str],
) -> tuple[ReachabilityStatus, list[str], str]:
    """Check Go package import + OSV symbol-level reachability across `.go` source files."""
    imported_files: list[str] = []
    symbol_citations: list[str] = []
    target_paths = set(import_paths)

    # Normalize OSV Go symbols (e.g. `Server.ServeConn` -> `ServeConn`, `ConfigureServer` -> `ConfigureServer`)
    sym_tails = [s.rsplit(".", 1)[-1] for s in vulnerable_symbols if s]
    sym_patterns = [(s, re.compile(rf"\b{re.escape(s)}\s*\(")) for s in sym_tails]

    for rel, source, imp_map in go_sources:
        matched_aliases: list[str] = []
        for alias, imp_path in imp_map.items():
            if (
                imp_path in target_paths
                or imp_path == module_path
                or imp_path.startswith(f"{module_path}/")
                or any(imp_path.startswith(f"{tp}/") for tp in target_paths)
            ):
                matched_aliases.append(alias)

        if not matched_aliases:
            continue
        imported_files.append(rel)

        if not sym_patterns:
            continue

        lines = source.splitlines()
        for idx, raw_line in enumerate(lines, start=1):
            code = raw_line.split("//", 1)[0]
            for sym, pat in sym_patterns:
                # Match either `alias.Symbol(` or method call `.Symbol(` when package is imported
                if any(
                    re.search(rf"\b{re.escape(alias)}\.{re.escape(sym)}\s*\(", code)
                    for alias in matched_aliases
                    if alias != "."
                ) or pat.search(code):
                    symbol_citations.append(f"{rel}:{idx} ({sym})")

    if not imported_files:
        return "under_investigation", [], "not_directly_imported"
    if not vulnerable_symbols:
        return "under_investigation", imported_files, "imported_no_symbol_metadata"
    if symbol_citations:
        return "reachable", sorted(set(symbol_citations)), "symbol_call_confirmed"
    return "not_reachable", imported_files, "imported_safe_symbols_only"


class GoSASTAnalyzer:
    """Function-scoped Go SAST & `go.mod` OSV symbol-level reachability analyzer."""

    name = "go-sast"

    def analyze(
        self,
        workspace_dir: Path,
        advisory_cache_dir: Path | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        go_sources: list[tuple[str, str, dict[str, str]]] = []

        for go_file in iter_source_files(workspace_dir, (".go",)):
            if go_file.name.endswith("_test.go"):
                continue
            try:
                source = go_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(go_file.relative_to(workspace_dir))
            lines = source.splitlines()
            funcs = _extract_go_functions(lines)
            go_sources.append((rel, source, _parse_go_imports(source)))

            for lineno, line in enumerate(lines, start=1):
                code_part = line.split("//", 1)[0]
                if not code_part.strip():
                    continue
                reach, fn_name = _func_reachability(lineno, funcs)

                m_cmd = _GO_SHELL_CMD_RE.search(code_part)
                if m_cmd and not re.match(r"""^["'`][^"'`]*["'`]$""", m_cmd.group(1).strip()):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("GO-CMD-001", rel, lineno),
                            rule_id="GO-CMD-001",
                            cwe_id="CWE-78",
                            title="Go Shell Command Injection via exec.Command",
                            category="sast",
                            severity="critical",
                            file_path=rel,
                            start_line=lineno,
                            end_line=lineno,
                            snippet=extract_snippet(lines, lineno, lineno),
                            message="Dynamic input passed to exec.Command('sh', '-c', ...) allows shell command injection.",
                            reachability=reach,
                            recommended_fix="Invoke the target binary directly via exec.Command(bin, arg1, arg2) without a shell.",
                            metadata={"function": fn_name},
                        )
                    )

                if _GO_SQL_FMT_RE.search(code_part):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("GO-SQL-001", rel, lineno),
                            rule_id="GO-SQL-001",
                            cwe_id="CWE-89",
                            title="Go SQL Query String Interpolation",
                            category="sast",
                            severity="high",
                            file_path=rel,
                            start_line=lineno,
                            end_line=lineno,
                            snippet=extract_snippet(lines, lineno, lineno),
                            message="SQL query constructed with fmt.Sprintf() or string concatenation instead of placeholders.",
                            reachability=reach,
                            recommended_fix="Use parameterized queries: db.Query('SELECT ... WHERE id = $1', id).",
                            metadata={"function": fn_name},
                        )
                    )

                if _GO_TLS_SKIP_RE.search(code_part):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("GO-TLS-001", rel, lineno),
                            rule_id="GO-TLS-001",
                            cwe_id="CWE-295",
                            title="Go TLS Certificate Verification Disabled",
                            category="sast",
                            severity="medium",
                            file_path=rel,
                            start_line=lineno,
                            end_line=lineno,
                            snippet=extract_snippet(lines, lineno, lineno),
                            message="tls.Config sets InsecureSkipVerify: true, disabling TLS certificate validation.",
                            reachability=reach,
                            recommended_fix="Remove InsecureSkipVerify: true or provide a custom RootCAs cert pool.",
                            metadata={"function": fn_name},
                        )
                    )

                if _GO_SSRF_RE.search(code_part):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id("GO-SSRF-001", rel, lineno),
                            rule_id="GO-SSRF-001",
                            cwe_id="CWE-918",
                            title="Go Server-Side Request Forgery (SSRF)",
                            category="sast",
                            severity="high",
                            file_path=rel,
                            start_line=lineno,
                            end_line=lineno,
                            snippet=extract_snippet(lines, lineno, lineno),
                            message="User-controlled HTTP request input passed directly to net/http client.",
                            reachability=reach,
                            recommended_fix="Validate URL scheme/host against an allowlist and block private/metadata IP ranges in a custom DialContext.",
                            metadata={"function": fn_name},
                        )
                    )

            # Function-scoped check for unconstrained filepath.Join + os.ReadFile / os.Open
            for fname, sig, sline, eline in funcs:
                fn_lines = lines[sline - 1 : eline]
                fn_body = "\n".join(fn_lines)
                if not (_GO_PATH_JOIN_RE.search(fn_body) and _GO_FILE_READ_RE.search(fn_body)):
                    continue
                has_confine = (
                    "strings.HasPrefix(" in fn_body
                    and ("filepath.Abs(" in fn_body or "filepath.Rel(" in fn_body)
                    and ("os.PathSeparator" in fn_body or '+ "/"' in fn_body)
                )
                if has_confine:
                    continue
                reach_fn: ReachabilityStatus = (
                    "reachable"
                    if (fname == "main" or _GO_HANDLER_SIG_RE.search(sig))
                    else "under_investigation"
                )
                for offset, fline in enumerate(fn_lines):
                    if _GO_PATH_JOIN_RE.search(fline.split("//", 1)[0]):
                        lineno = sline + offset
                        findings.append(
                            Finding(
                                finding_id=make_finding_id("GO-PATH-001", rel, lineno),
                                rule_id="GO-PATH-001",
                                cwe_id="CWE-22",
                                title="Go Unconstrained filepath.Join Before File Read",
                                category="sast",
                                severity="high",
                                file_path=rel,
                                start_line=lineno,
                                end_line=lineno,
                                snippet=extract_snippet(lines, lineno, lineno),
                                message=f"Function '{fname}' reads filepath.Join() result without separator-enforced root confinement.",
                                reachability=reach_fn,
                                recommended_fix="Resolve with filepath.Abs() and verify strings.HasPrefix(target, baseDir + string(os.PathSeparator)).",
                                metadata={"function": fname},
                            )
                        )
                        break

        # 2. `go.mod` + Go OSV symbol-level dependency reachability
        findings.extend(self._analyze_go_dependencies(workspace_dir, go_sources, advisory_cache_dir))
        return findings

    def _analyze_go_dependencies(
        self,
        workspace_dir: Path,
        go_sources: list[tuple[str, str, dict[str, str]]],
        advisory_cache_dir: Path | None,
    ) -> list[Finding]:
        go_deps = parse_go_mod(workspace_dir)
        if not go_deps:
            return []

        advisories: list[Advisory] = list(BUILTIN_GO_ADVISORIES)
        seen: set[tuple[str, str]] = {(a.advisory_id, a.package) for a in advisories}
        for cached in load_offline_osv_advisories(advisory_cache_dir):
            if str(cached.get("ecosystem") or "").lower() != "go":
                continue
            try:
                adv = Advisory.model_validate(cached)
            except Exception:
                continue
            key = (adv.advisory_id, adv.package)
            if key not in seen:
                seen.add(key)
                advisories.append(adv)

        kev_cves, epss_scores = load_offline_enrichment(advisory_cache_dir)
        findings: list[Finding] = []

        for adv in advisories:
            for dep in go_deps:
                if dep.name != adv.package:
                    continue
                if adv.affected_ranges:
                    affected, branch_fixed = is_version_in_ranges(
                        dep.version, adv.affected_ranges, ecosystem="go"
                    )
                    if not affected:
                        continue
                    effective_fixed = branch_fixed or adv.fixed_version or "latest patched"
                else:
                    if not adv.affected_below or not is_version_below(
                        dep.version, adv.affected_below, ecosystem="go"
                    ):
                        continue
                    effective_fixed = adv.fixed_version or adv.affected_below

                reachability, citations, basis = _check_go_symbol_reachability(
                    go_sources,
                    adv.imports or [adv.package],
                    adv.package,
                    adv.vulnerable_symbols,
                )
                rule_id = f"DEP-{adv.advisory_id}"
                is_kev = adv.advisory_id in kev_cves
                epss_info = epss_scores.get(adv.advisory_id)
                cite_text = f" Citations: {', '.join(citations)}." if citations else ""
                meta: dict[str, Any] = {
                    "ecosystem": "go",
                    "package": adv.package,
                    "installed_version": dep.version,
                    "version_source": "lockfile",
                    "fixed_version": effective_fixed,
                    "advisory_id": adv.advisory_id,
                    "citations": citations,
                    "reachability_basis": basis,
                    "cisa_kev": is_kev,
                }
                if epss_info:
                    meta["epss_score"] = epss_info["epss"]
                    meta["epss_percentile"] = epss_info["percentile"]

                findings.append(
                    Finding(
                        finding_id=make_finding_id(rule_id, dep.manifest, dep.line_no),
                        rule_id=rule_id,
                        cwe_id=adv.cwe_id,
                        title=f"{adv.title} ({adv.package} v{dep.version})",
                        category="dependency",
                        severity=adv.severity,
                        file_path=dep.manifest,
                        start_line=dep.line_no,
                        end_line=dep.line_no,
                        snippet=f"{dep.manifest}:{dep.line_no}: {dep.name} v{dep.version}",
                        message=(
                            f"Go module '{adv.package}' v{dep.version} (go.mod) is affected by "
                            f"{adv.advisory_id} (fix: >= v{effective_fixed}). Reachability: {reachability}.{cite_text}"
                        ),
                        reachability=reachability,
                        recommended_fix=f"Run `go get {adv.package}@v{effective_fixed} && go mod tidy`.",
                        metadata=meta,
                    )
                )

        return findings


class GoSASTPlugin:
    """VulnBox AnalyzerPlugin adapter for GoSASTAnalyzer."""

    name = "go-sast"

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        return GoSASTAnalyzer().analyze(
            ctx.workspace_dir,
            advisory_cache_dir=ctx.advisory_cache_dir,
        )
