"""Shared repository traversal and exclusion constants."""

from __future__ import annotations

from pathlib import Path

DEFAULT_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".venv",
        ".vulnbox-cache",
        ".yarn",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        "vulnbox-out",
    }
)

TEST_DIR_NAMES: frozenset[str] = frozenset({"tests", "test", "__tests__", "fixtures"})

TEST_FILE_SUFFIXES: tuple[str, ...] = (
    "_test.py",
    ".test.js",
    ".test.mjs",
    ".test.cjs",
    ".test.ts",
    ".spec.js",
    ".spec.ts",
)


def is_test_or_fixture_path(rel_path: Path) -> bool:
    """Return True if rel_path resides in a test/fixture directory or matches test file naming."""
    if any(part in TEST_DIR_NAMES for part in rel_path.parts):
        return True
    name_lower = rel_path.name.lower()
    return name_lower.startswith("test_") or name_lower.endswith(TEST_FILE_SUFFIXES)
