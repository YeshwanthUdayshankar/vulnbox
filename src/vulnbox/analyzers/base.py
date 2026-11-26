"""Shared utilities and protocol for VulnBox security analyzers."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Protocol

from vulnbox.models import Finding

SKIP_DIRS = {
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


class Analyzer(Protocol):
    """Common interface for all VulnBox analyzers."""

    name: str

    def analyze(self, workspace_dir: Path) -> list[Finding]: ...


def make_finding_id(rule_id: str, file_path: str, start_line: int) -> str:
    """Create a deterministic, short finding identifier."""
    digest = hashlib.sha256(f"{rule_id}:{file_path}:{start_line}".encode()).hexdigest()[:8]
    return f"{rule_id}-{digest}"


def extract_snippet(lines: list[str], start_line: int, end_line: int, context: int = 1) -> str:
    """Extract a 1-indexed code snippet with optional surrounding context lines."""
    if not lines:
        return ""
    lo = max(1, start_line - context)
    hi = min(len(lines), end_line + context)
    return "\n".join(f"{idx}: {lines[idx - 1]}" for idx in range(lo, hi + 1))


def iter_source_files(
    root: Path,
    extensions: tuple[str, ...],
    skip_tests: bool = True,
) -> list[Path]:
    """Iterate source files with given extensions, skipping vendor and optional test dirs."""
    matched: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if skip_tests:
            if "tests" in rel.parts or "__tests__" in rel.parts:
                continue
            name_lower = path.name.lower()
            if (
                name_lower.startswith("test_")
                or name_lower.endswith(("_test.py", ".test.js", ".test.mjs", ".test.ts", ".spec.js", ".spec.ts"))
            ):
                continue
        if path.suffix.lower() in extensions:
            matched.append(path)
    return matched
