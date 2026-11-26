"""Deterministic unified diff patch generator and pure-Python patch applier."""

from __future__ import annotations

import difflib
import re
from pathlib import Path

from vulnbox.models import Finding, PatchCandidate

HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def make_unified_diff(rel_path: str, old_text: str, new_text: str) -> str:
    """Create a standard git-compatible unified diff between old_text and new_text."""
    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{rel_path}",
        tofile=f"b/{rel_path}",
        n=3,
    )
    return "".join(diff)


def apply_unified_diff(workspace_dir: Path, unified_diff: str) -> list[str]:
    """Apply a unified diff to files under workspace_dir without requiring git.

    Returns the list of modified relative file paths. Raises ValueError on mismatch.
    """
    lines = unified_diff.splitlines(keepends=True)
    i = 0
    modified_files: list[str] = []

    while i < len(lines):
        line = lines[i]
        if line.startswith("--- "):
            if i + 1 >= len(lines) or not lines[i + 1].startswith("+++ "):
                raise ValueError("Malformed unified diff: missing +++ header")
            new_header = lines[i + 1][4:].strip().split("\t", 1)[0]
            rel_path = new_header[2:] if new_header.startswith("b/") else new_header
            i += 2

            target = (workspace_dir / rel_path).resolve()
            if not target.is_relative_to(workspace_dir.resolve()):
                raise ValueError(f"Refusing path outside workspace: {rel_path}")
            if not target.is_file():
                raise ValueError(f"Patch target file does not exist: {rel_path}")

            orig_lines = target.read_text(encoding="utf-8").splitlines(keepends=True)
            out_lines: list[str] = []
            orig_idx = 0

            while i < len(lines) and lines[i].startswith("@@ "):
                m = HUNK_HEADER_RE.match(lines[i])
                if not m:
                    raise ValueError(f"Invalid hunk header: {lines[i]!r}")
                old_start = max(int(m.group(1)) - 1, 0)
                i += 1

                if old_start < orig_idx:
                    raise ValueError(f"Overlapping hunks in {rel_path}")
                out_lines.extend(orig_lines[orig_idx:old_start])
                orig_idx = old_start

                while i < len(lines) and not lines[i].startswith(("@@ ", "--- ", "diff --git ")):
                    hline = lines[i]
                    if hline.startswith("\\ No newline"):
                        i += 1
                        continue
                    tag = hline[0]
                    content = hline[1:]
                    if tag == " ":
                        if orig_idx >= len(orig_lines) or orig_lines[orig_idx].rstrip("\r\n") != content.rstrip("\r\n"):
                            raise ValueError(
                                f"Context mismatch in {rel_path} near line {orig_idx + 1}"
                            )
                        out_lines.append(orig_lines[orig_idx])
                        orig_idx += 1
                    elif tag == "-":
                        if orig_idx >= len(orig_lines) or orig_lines[orig_idx].rstrip("\r\n") != content.rstrip("\r\n"):
                            raise ValueError(
                                f"Deletion mismatch in {rel_path} near line {orig_idx + 1}"
                            )
                        orig_idx += 1
                    elif tag == "+":
                        out_lines.append(content)
                    else:
                        raise ValueError(f"Unexpected diff line prefix {tag!r} in {rel_path}")
                    i += 1

            out_lines.extend(orig_lines[orig_idx:])
            target.write_text("".join(out_lines), encoding="utf-8")
            modified_files.append(rel_path)
        else:
            i += 1

    if not modified_files:
        raise ValueError("Unified diff contained no applicable file hunks")
    return modified_files


def _patch_python_yaml(old_text: str) -> str:
    updated = re.sub(
        r"yaml\.(?:unsafe_load|full_load)\s*\(",
        "yaml.safe_load(",
        old_text,
    )
    updated = re.sub(
        r"yaml\.load\s*\(([^,)]+),\s*Loader\s*=\s*[^)]+\)",
        r"yaml.safe_load(\1)",
        updated,
    )
    updated = re.sub(
        r"yaml\.load\s*\(([^,)]+)\)",
        r"yaml.safe_load(\1)",
        updated,
    )
    return updated


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


def _patch_python_path(old_text: str, target_line: int) -> str:
    lines = old_text.splitlines(keepends=True)
    if target_line < 1 or target_line > len(lines):
        return old_text
    line = lines[target_line - 1]
    m = re.match(
        r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*os\.path\.join\(([^,]+),\s*([^)]+)\)\s*$",
        line,
    )
    if not m:
        return old_text
    indent, var_name, base_expr, rel_expr = m.groups()
    guard_lines = [
        f"{indent}_base_dir = Path({base_expr.strip()}).resolve()\n",
        f"{indent}{var_name} = (_base_dir / {rel_expr.strip()}).resolve()\n",
        f"{indent}if not {var_name}.is_relative_to(_base_dir):\n",
        f'{indent}    raise ValueError("Path escapes allowed base directory")\n',
    ]
    new_lines = lines[: target_line - 1] + guard_lines + lines[target_line:]
    updated = "".join(new_lines)
    return _insert_python_import(updated, "from pathlib import Path\n")


def _patch_node_path(old_text: str, target_line: int) -> str:
    lines = old_text.splitlines(keepends=True)
    if target_line < 1 or target_line > len(lines):
        return old_text
    line = lines[target_line - 1]
    m = re.match(
        r"^(\s*)(const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*path\.join\(([^,]+),\s*([^)]+)\);?\s*$",
        line,
    )
    if not m:
        return old_text
    indent, decl, var_name, base_expr, rel_expr = m.groups()
    guard_lines = [
        f"{indent}const _baseDir = path.resolve({base_expr.strip()});\n",
        f"{indent}{decl} {var_name} = path.resolve(_baseDir, {rel_expr.strip()});\n",
        f"{indent}if ({var_name} !== _baseDir && !{var_name}.startsWith(_baseDir + path.sep)) {{\n",
        f'{indent}  throw new Error("Path escapes allowed base directory");\n',
        f"{indent}}}\n",
    ]
    return "".join(lines[: target_line - 1] + guard_lines + lines[target_line:])


def _patch_node_cors(old_text: str) -> str:
    # Handle res.setHeader("Access-Control-Allow-Origin", "*" | req.headers.origin) + credentials
    updated = re.sub(
        r"""res\.setHeader\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*(?:['"]\*['"]|req\.headers\.origin(?:\s*\|\|\s*['"]\*['"])?)\s*\);""",
        (
            'const _allowedOrigins = new Set(["http://localhost:3000"]);\n'
            "  const _safeOrigin = _allowedOrigins.has(req.headers.origin) ? req.headers.origin : null;\n"
            "  if (_safeOrigin) {\n"
            '    res.setHeader("Access-Control-Allow-Origin", _safeOrigin);\n'
            "  }"
        ),
        old_text,
    )
    updated = re.sub(
        r"cors\s*\(\s*\{\s*origin\s*:\s*(?:['\"]\*['\"]|true)\s*,\s*credentials\s*:\s*true\s*\}\s*\)",
        'cors({ origin: ["http://localhost:3000"], credentials: true })',
        updated,
    )
    return updated


def _patch_dockerfile(old_text: str, rule_id: str) -> str:
    if rule_id == "CFG-DOCKER-002":
        updated = re.sub(
            r"(?im)^(FROM\s+python)(?::latest)?(\s|$)",
            r"\1:3.12-slim\2",
            old_text,
        )
        updated = re.sub(
            r"(?im)^(FROM\s+node)(?::latest)?(\s|$)",
            r"\1:22-slim\2",
            updated,
        )
        return updated

    if rule_id == "CFG-DOCKER-001":
        lines = old_text.splitlines(keepends=True)
        # Insert non-root user creation before CMD/ENTRYPOINT or at end
        insert_idx = len(lines)
        for idx, line in enumerate(lines):
            if re.match(r"^\s*(?:CMD|ENTRYPOINT)\b", line, re.IGNORECASE):
                insert_idx = idx
                break
        snippet = [
            "RUN useradd --create-home --uid 1000 appuser\n",
            "USER appuser\n",
        ]
        # Remove explicit USER root if present
        cleaned = [ln for ln in lines[:insert_idx] if not re.match(r"^\s*USER\s+(?:root|0)\b", ln, re.IGNORECASE)]
        return "".join(cleaned + snippet + lines[insert_idx:])

    return old_text


def _patch_dependency(old_text: str, finding: Finding) -> str:
    pkg = str(finding.metadata.get("package", ""))
    fixed = str(finding.metadata.get("fixed_version", ""))
    if not pkg or not fixed:
        return old_text

    if finding.file_path.endswith("requirements.txt"):
        return re.sub(
            rf"(?im)^(\s*{re.escape(pkg)}\s*)(?:==|<=|>=|~=|!=|<|>)\s*[0-9][A-Za-z0-9_.*+-]*",
            rf"\1>={fixed}",
            old_text,
        )
    if finding.file_path.endswith("package.json"):
        return re.sub(
            rf'("{re.escape(pkg)}"\s*:\s*")[^"]+(")',
            rf"\1^{fixed}\2",
            old_text,
            flags=re.IGNORECASE,
        )
    return old_text


def generate_patch_for_finding(
    finding: Finding,
    workspace_dir: Path,
) -> PatchCandidate | None:
    """Generate a minimal unified diff patch candidate for a supported finding."""
    target = workspace_dir / finding.file_path
    if not target.is_file():
        return None
    old_text = target.read_text(encoding="utf-8", errors="ignore")
    new_text = old_text
    strategy = "minimal_code_fix"
    desc = finding.recommended_fix

    if finding.rule_id == "PY-YAML-001":
        new_text = _patch_python_yaml(old_text)
        desc = "Replace unsafe yaml.load()/full_load() with yaml.safe_load()."
    elif finding.rule_id == "PY-TLS-001":
        new_text = re.sub(r"\bverify\s*=\s*False\b", "verify=True", old_text)
        desc = "Enable TLS certificate verification (verify=True)."
    elif finding.rule_id == "PY-DEBUG-001":
        new_text = re.sub(r"\bdebug\s*=\s*True\b", "debug=False", old_text)
        desc = "Disable debug mode (debug=False)."
    elif finding.rule_id == "PY-HASH-001":
        new_text = re.sub(r"\bhashlib\.(?:md5|sha1)\s*\(", "hashlib.sha256(", old_text)
        desc = "Upgrade weak hash algorithm to hashlib.sha256()."
    elif finding.rule_id == "PY-PATH-001":
        new_text = _patch_python_path(old_text, finding.start_line)
        desc = "Enforce Path.resolve() and is_relative_to() base-directory confinement."
    elif finding.rule_id == "JS-TLS-001":
        new_text = re.sub(r"rejectUnauthorized\s*:\s*false", "rejectUnauthorized: true", old_text)
        desc = "Enable TLS certificate validation (rejectUnauthorized: true)."
    elif finding.rule_id == "JS-CORS-001":
        new_text = _patch_node_cors(old_text)
        desc = "Restrict Access-Control-Allow-Origin to an explicit origin allowlist."
    elif finding.rule_id == "JS-PATH-001":
        new_text = _patch_node_path(old_text, finding.start_line)
        desc = "Enforce path.resolve() and startsWith() base-directory confinement."
    elif finding.rule_id in ("CFG-DOCKER-001", "CFG-DOCKER-002"):
        strategy = "config_hardening"
        new_text = _patch_dockerfile(old_text, finding.rule_id)
    elif finding.category == "dependency":
        strategy = "dependency_bump"
        new_text = _patch_dependency(old_text, finding)
        desc = f"Upgrade {finding.metadata.get('package')} to >= {finding.metadata.get('fixed_version')}."
    else:
        return None

    if new_text == old_text:
        return None

    diff_text = make_unified_diff(finding.file_path, old_text, new_text)
    if not diff_text.strip():
        return None

    return PatchCandidate(
        patch_id=f"patch-{finding.finding_id}",
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        strategy=strategy,  # type: ignore[arg-type]
        description=desc,
        unified_diff=diff_text,
    )
