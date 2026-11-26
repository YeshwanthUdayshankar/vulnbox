"""Tree-sitter parser helpers with per-grammar graceful degradation."""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache
from typing import Any

try:
    from tree_sitter import Language, Node, Parser, Tree
except ImportError:  # pragma: no cover - optional degraded mode
    Language = None  # type: ignore[assignment]
    Node = Any  # type: ignore[assignment]
    Parser = None  # type: ignore[assignment]
    Tree = Any  # type: ignore[assignment]


def _load_grammar(ext: str) -> Any | None:
    if Language is None or Parser is None:
        return None
    low = ext.lower()
    try:
        if low == ".py":
            import tree_sitter_python as ts_py

            return Language(ts_py.language())
        if low in (".js", ".mjs", ".cjs", ".jsx"):
            import tree_sitter_javascript as ts_js

            return Language(ts_js.language())
        if low == ".ts":
            import tree_sitter_typescript as ts_ts

            return Language(ts_ts.language_typescript())
        if low == ".tsx":
            import tree_sitter_typescript as ts_ts

            return Language(ts_ts.language_tsx())
    except (ImportError, OSError, RuntimeError):
        return None
    return None


@lru_cache(maxsize=8)
def get_parser_for_ext(ext: str) -> Any | None:
    """Return a cached Tree-sitter Parser for `ext`, or None if grammar is unavailable."""
    lang = _load_grammar(ext)
    if lang is None or Parser is None:
        return None
    return Parser(lang)


def available_tree_sitter_languages() -> list[str]:
    """Return list of languages whose Tree-sitter grammar loaded cleanly."""
    found: list[str] = []
    for label, ext in (("python", ".py"), ("javascript", ".js"), ("typescript", ".ts")):
        if get_parser_for_ext(ext) is not None:
            found.append(label)
    return found


def parse_source(source: str | bytes, ext: str) -> tuple[Any | None, bytes]:
    """Parse source text into a Tree-sitter CST and return (tree, raw_bytes)."""
    raw = source.encode("utf-8", errors="ignore") if isinstance(source, str) else source
    parser = get_parser_for_ext(ext)
    if parser is None:
        return None, raw
    return parser.parse(raw), raw


def node_text(node: Any, raw: bytes) -> str:
    """Decode the exact source text for a Tree-sitter node."""
    return raw[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def walk_nodes(root: Any) -> Iterator[Any]:
    """Iterative pre-order traversal over all Tree-sitter nodes."""
    stack: list[Any] = [root]
    while stack:
        curr = stack.pop()
        yield curr
        children: Any = curr.children
        if children:
            stack.extend(reversed(children))
