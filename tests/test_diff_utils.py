"""Edge-case unit tests for pure-Python unified diff generation and application."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnbox.remediation.diff_utils import apply_unified_diff, make_unified_diff


def test_apply_multi_hunk_diff_and_multi_file_diff(tmp_path: Path):
    file_a = tmp_path / "a.py"
    file_b = tmp_path / "b.py"
    old_a = "\n".join(f"line_{i} = {i}" for i in range(1, 21)) + "\n"
    new_a = old_a.replace("line_2 = 2", "line_2 = 200").replace("line_18 = 18", "line_18 = 1800")
    old_b = "x = False\n"
    new_b = "x = True\n"
    file_a.write_text(old_a, encoding="utf-8")
    file_b.write_text(old_b, encoding="utf-8")

    combined = make_unified_diff("a.py", old_a, new_a) + make_unified_diff("b.py", old_b, new_b)
    modified = apply_unified_diff(tmp_path, combined)
    assert modified == ["a.py", "b.py"]
    assert file_a.read_text(encoding="utf-8") == new_a
    assert file_b.read_text(encoding="utf-8") == new_b


def test_apply_diff_with_minor_line_offset_alignment(tmp_path: Path):
    target = tmp_path / "app.py"
    target.write_text("header = 1\n\na = 1\nb = 2\nc = 3\n", encoding="utf-8")
    # Off-by-2 hunk header (claims line 1 instead of line 3)
    shifted_diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,3 +1,3 @@\n"
        " a = 1\n"
        "-b = 2\n"
        "+b = 22\n"
        " c = 3\n"
    )
    modified = apply_unified_diff(tmp_path, shifted_diff)
    assert modified == ["app.py"]
    assert target.read_text(encoding="utf-8") == "header = 1\n\na = 1\nb = 22\nc = 3\n"


def test_apply_diff_rejects_path_escape_and_context_mismatch(tmp_path: Path):
    escape_diff = "--- a/../escape.py\n+++ b/../escape.py\n@@ -1 +1 @@\n-a\n+b\n"
    with pytest.raises(ValueError, match="Refusing path outside workspace"):
        apply_unified_diff(tmp_path, escape_diff)

    (tmp_path / "app.py").write_text("a = 1\n", encoding="utf-8")
    mismatch_diff = "--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n-zzz = 9\n+a = 2\n"
    with pytest.raises(ValueError, match="Deletion mismatch"):
        apply_unified_diff(tmp_path, mismatch_diff)
