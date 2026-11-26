"""Registry-backed deterministic patch generators (diff utilities live in diff_utils.py)."""

from __future__ import annotations

import re
from pathlib import Path

from vulnbox.models import Finding, PatchCandidate, PatchStrategy
from vulnbox.registry import PluginRegistry, default_registry
from vulnbox.remediation.diff_utils import apply_unified_diff, make_unified_diff


def _build_candidate(
    finding: Finding,
    workspace_dir: Path,
    transform,
    description: str,
    strategy: PatchStrategy = "minimal_code_fix",
) -> PatchCandidate | None:
    target = workspace_dir / finding.file_path
    if not target.is_file():
        return None
    old_text = target.read_text(encoding="utf-8", errors="ignore")
    new_text = transform(old_text, finding)
    if not new_text or new_text == old_text:
        return None
    diff_text = make_unified_diff(finding.file_path, old_text, new_text)
    if not diff_text.strip():
        return None
    return PatchCandidate(
        patch_id=f"patch-{finding.finding_id}",
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        strategy=strategy,
        description=description,
        unified_diff=diff_text,
    )


def _insert_python_import(source: str, import_stmt: str) -> str:
    """Insert a Python import after any module docstring and __future__ imports."""
    if import_stmt.strip() in source:
        return source
    lines = source.splitlines(keepends=True)
    insert_idx = 0
    for idx, ln in enumerate(lines):
        stripped = ln.strip()
        if stripped.startswith("from __future__ import"):
            insert_idx = idx + 1
        elif stripped.startswith(("import ", "from ")) and insert_idx == 0:
            insert_idx = idx
            break
    return "".join(lines[:insert_idx] + [import_stmt] + lines[insert_idx:])


@default_registry.register_patcher("PY-YAML-001")
def _patch_py_yaml(finding: Finding, ws: Path) -> PatchCandidate | None:
    def _tx(old: str, _f: Finding) -> str:
        updated = re.sub(r"yaml\.(?:unsafe_load|full_load)\s*\(", "yaml.safe_load(", old)
        updated = re.sub(r"yaml\.load\s*\(([^,)]+),\s*Loader\s*=\s*[^)]+\)", r"yaml.safe_load(\1)", updated)
        return re.sub(r"yaml\.load\s*\(([^,)]+)\)", r"yaml.safe_load(\1)", updated)

    return _build_candidate(finding, ws, _tx, "Replace unsafe yaml.load()/full_load() with yaml.safe_load().")


@default_registry.register_patcher("PY-TLS-001")
def _patch_py_tls(finding: Finding, ws: Path) -> PatchCandidate | None:
    return _build_candidate(
        finding,
        ws,
        lambda old, _f: re.sub(r"\bverify\s*=\s*False\b", "verify=True", old),
        "Enable TLS certificate verification (verify=True).",
    )


@default_registry.register_patcher("PY-DEBUG-001")
def _patch_py_debug(finding: Finding, ws: Path) -> PatchCandidate | None:
    return _build_candidate(
        finding,
        ws,
        lambda old, _f: re.sub(r"\bdebug\s*=\s*True\b", "debug=False", old),
        "Disable debug mode (debug=False).",
    )


@default_registry.register_patcher("PY-HASH-001")
def _patch_py_hash(finding: Finding, ws: Path) -> PatchCandidate | None:
    return _build_candidate(
        finding,
        ws,
        lambda old, _f: re.sub(r"\bhashlib\.(?:md5|sha1)\s*\(", "hashlib.sha256(", old),
        "Upgrade weak hash algorithm to hashlib.sha256().",
    )


@default_registry.register_patcher("PY-PATH-001")
def _patch_py_path(finding: Finding, ws: Path) -> PatchCandidate | None:
    def _tx(old: str, f: Finding) -> str:
        lines = old.splitlines(keepends=True)
        if f.start_line < 1 or f.start_line > len(lines):
            return old
        m = re.match(
            r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*os\.path\.join\(([^,]+),\s*([^)]+)\)\s*$",
            lines[f.start_line - 1],
        )
        if not m:
            return old
        indent, var_name, base_expr, rel_expr = m.groups()
        guard_lines = [
            f"{indent}_base_dir = Path({base_expr.strip()}).resolve()\n",
            f"{indent}{var_name} = (_base_dir / {rel_expr.strip()}).resolve()\n",
            f"{indent}if not {var_name}.is_relative_to(_base_dir):\n",
            f'{indent}    raise ValueError("Path escapes allowed base directory")\n',
        ]
        updated = "".join(lines[: f.start_line - 1] + guard_lines + lines[f.start_line :])
        return _insert_python_import(updated, "from pathlib import Path\n")

    return _build_candidate(
        finding, ws, _tx, "Enforce Path.resolve() and is_relative_to() base-directory confinement."
    )


@default_registry.register_patcher("JS-TLS-001")
def _patch_js_tls(finding: Finding, ws: Path) -> PatchCandidate | None:
    return _build_candidate(
        finding,
        ws,
        lambda old, _f: re.sub(r"rejectUnauthorized\s*:\s*false", "rejectUnauthorized: true", old),
        "Enable TLS certificate validation (rejectUnauthorized: true).",
    )


@default_registry.register_patcher("JS-CORS-001")
def _patch_js_cors(finding: Finding, ws: Path) -> PatchCandidate | None:
    def _tx(old: str, _f: Finding) -> str:
        updated = re.sub(
            r"""res\.setHeader\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*(?:['"]\*['"]|req\.headers\.origin(?:\s*\|\|\s*['"]\*['"])?)\s*\);""",
            (
                'const _allowedOrigins = new Set(["http://localhost:3000"]);\n'
                "  const _safeOrigin = _allowedOrigins.has(req.headers.origin) ? req.headers.origin : null;\n"
                "  if (_safeOrigin) {\n"
                '    res.setHeader("Access-Control-Allow-Origin", _safeOrigin);\n'
                "  }"
            ),
            old,
        )
        return re.sub(
            r"cors\s*\(\s*\{\s*origin\s*:\s*(?:['\"]\*['\"]|true)\s*,\s*credentials\s*:\s*true\s*\}\s*\)",
            'cors({ origin: ["http://localhost:3000"], credentials: true })',
            updated,
        )

    return _build_candidate(
        finding, ws, _tx, "Restrict Access-Control-Allow-Origin to an explicit origin allowlist."
    )


@default_registry.register_patcher("JS-PATH-001")
def _patch_js_path(finding: Finding, ws: Path) -> PatchCandidate | None:
    def _tx(old: str, f: Finding) -> str:
        lines = old.splitlines(keepends=True)
        if f.start_line < 1 or f.start_line > len(lines):
            return old
        m = re.match(
            r"^(\s*)(const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*path\.join\(([^,]+),\s*([^)]+)\);?\s*$",
            lines[f.start_line - 1],
        )
        if not m:
            return old
        indent, decl, var_name, base_expr, rel_expr = m.groups()
        guard_lines = [
            f"{indent}const _baseDir = path.resolve({base_expr.strip()});\n",
            f"{indent}{decl} {var_name} = path.resolve(_baseDir, {rel_expr.strip()});\n",
            f"{indent}if ({var_name} !== _baseDir && !{var_name}.startsWith(_baseDir + path.sep)) {{\n",
            f'{indent}  throw new Error("Path escapes allowed base directory");\n',
            f"{indent}}}\n",
        ]
        return "".join(lines[: f.start_line - 1] + guard_lines + lines[f.start_line :])

    return _build_candidate(
        finding, ws, _tx, "Enforce path.resolve() and startsWith() base-directory confinement."
    )


@default_registry.register_patcher("CFG-DOCKER-001", "CFG-DOCKER-002")
def _patch_docker_config(finding: Finding, ws: Path) -> PatchCandidate | None:
    def _tx(old: str, f: Finding) -> str:
        if f.rule_id == "CFG-DOCKER-002":
            updated = re.sub(r"(?im)^(FROM\s+python)(?::latest)?(\s|$)", r"\1:3.12-slim\2", old)
            return re.sub(r"(?im)^(FROM\s+node)(?::latest)?(\s|$)", r"\1:22-slim\2", updated)
        lines = old.splitlines(keepends=True)
        insert_idx = len(lines)
        for idx, line in enumerate(lines):
            if re.match(r"^\s*(?:CMD|ENTRYPOINT)\b", line, re.IGNORECASE):
                insert_idx = idx
                break
        snippet = ["RUN useradd --create-home --uid 1000 appuser\n", "USER appuser\n"]
        cleaned = [
            ln
            for ln in lines[:insert_idx]
            if not re.match(r"^\s*USER\s+(?:root|0)\b", ln, re.IGNORECASE)
        ]
        return "".join(cleaned + snippet + lines[insert_idx:])

    return _build_candidate(finding, ws, _tx, finding.recommended_fix, strategy="config_hardening")


@default_registry.register_patcher(category="dependency")
def _patch_dep_upgrade(finding: Finding, ws: Path) -> PatchCandidate | None:
    def _tx(old: str, f: Finding) -> str:
        pkg = str(f.metadata.get("package", ""))
        fixed = str(f.metadata.get("fixed_version", ""))
        if not pkg or not fixed:
            return old
        if f.file_path.endswith("requirements.txt"):
            return re.sub(
                rf"(?im)^(\s*{re.escape(pkg)}\s*)(?:==|<=|>=|~=|!=|<|>)\s*[0-9][A-Za-z0-9_.*+-]*",
                rf"\1>={fixed}",
                old,
            )
        if f.file_path.endswith("package.json"):
            return re.sub(
                rf'("{re.escape(pkg)}"\s*:\s*")[^"]+(")',
                rf"\1^{fixed}\2",
                old,
                flags=re.IGNORECASE,
            )
        return old

    desc = f"Upgrade {finding.metadata.get('package')} to >= {finding.metadata.get('fixed_version')}."
    return _build_candidate(finding, ws, _tx, desc, strategy="dependency_bump")


def generate_patch_for_finding(
    finding: Finding,
    workspace_dir: Path,
    registry: PluginRegistry | None = None,
) -> PatchCandidate | None:
    """Dispatch finding remediation via the plugin registry."""
    reg = registry or default_registry
    patcher = reg.get_patcher(finding)
    if patcher is None:
        return None
    return patcher(finding, workspace_dir)


__all__ = [
    "apply_unified_diff",
    "generate_patch_for_finding",
    "make_unified_diff",
]
