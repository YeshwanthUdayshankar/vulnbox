"""Pure-Python git-compatible unified diff generator and alignment-aware applier."""

from __future__ import annotations

import difflib
import re
from pathlib import Path

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


def _hunk_matches_at(
    pos: int,
    min_idx: int,
    expected_old: list[str],
    orig_lines: list[str],
) -> bool:
    if pos < min_idx or pos + len(expected_old) > len(orig_lines):
        return False
    return all(
        orig_lines[pos + k].rstrip("\r\n") == expected_old[k]
        for k in range(len(expected_old))
    )


def apply_unified_diff(workspace_dir: Path, unified_diff: str) -> list[str]:
    """Apply a unified diff to files under workspace_dir without requiring git.

    Returns the list of modified relative file paths. Raises ValueError on mismatch or escape.
    """
    lines = unified_diff.splitlines(keepends=True)
    i = 0
    modified_files: list[str] = []
    ws_resolved = workspace_dir.resolve()

    while i < len(lines):
        line = lines[i]
        if line.startswith("--- "):
            if i + 1 >= len(lines) or not lines[i + 1].startswith("+++ "):
                raise ValueError("Malformed unified diff: missing +++ header")
            new_header = lines[i + 1][4:].strip().split("\t", 1)[0]
            rel_path = new_header[2:] if new_header.startswith("b/") else new_header
            i += 2

            target = (ws_resolved / rel_path).resolve()
            if not target.is_relative_to(ws_resolved):
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

                hunk_lines: list[str] = []
                while i < len(lines) and not lines[i].startswith(("@@ ", "--- ", "diff --git ")):
                    if lines[i].startswith("\\ No newline"):
                        i += 1
                        continue
                    hunk_lines.append(lines[i])
                    i += 1

                expected_old = [
                    hl[1:].rstrip("\r\n") for hl in hunk_lines if hl and hl[0] in (" ", "-")
                ]
                aligned_start = old_start
                if expected_old and not _hunk_matches_at(
                    aligned_start, orig_idx, expected_old, orig_lines
                ):
                    for delta in range(1, 12):
                        found = None
                        for cand in (old_start - delta, old_start + delta):
                            if _hunk_matches_at(cand, orig_idx, expected_old, orig_lines):
                                found = cand
                                break
                        if found is not None:
                            aligned_start = found
                            break

                if aligned_start < orig_idx:
                    raise ValueError(f"Overlapping hunks in {rel_path}")
                out_lines.extend(orig_lines[orig_idx:aligned_start])
                orig_idx = aligned_start

                for hline in hunk_lines:
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

            out_lines.extend(orig_lines[orig_idx:])
            target.write_text("".join(out_lines), encoding="utf-8")
            modified_files.append(rel_path)
        else:
            i += 1

    if not modified_files:
        raise ValueError("Unified diff contained no applicable file hunks")
    return modified_files
