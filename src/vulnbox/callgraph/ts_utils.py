"""Tree-sitter parser helpers for Python, JavaScript, and TypeScript."""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache
from typing import Any

import tree_sitter_javascript as ts_js
import tree_sitter_python as ts_py
import tree_sitter_typescript as ts_ts
from tree_sitter import Language, Node, Parser, Tree


@lru_cache(maxsize=8)
def get_parser_for_ext(ext: str) -> Parser | None:
    """Return a cached Tree-sitter Parser for the given file extension."""
    low = ext.lower()
    if low == ".py":
        return Parser(Language(ts_py.language()))
    if low in (".js", ".mjs", ".cjs", ".jsx"):
        return Parser(Language(ts_js.language()))
    if low == ".ts":
        return Parser(Language(ts_ts.language_typescript()))
    if low == ".tsx":
        return Parser(Language(ts_ts.language_tsx()))
    return None


def parse_source(source: str | bytes, ext: str) -> tuple[Tree | None, bytes]:
    """Parse source text into a Tree-sitter CST and return (tree, raw_bytes)."""
    raw = source.encode("utf-8", errors="ignore") if isinstance(source, str) else source
    parser = get_parser_for_ext(ext)
    if parser is None:
        return None, raw
    return parser.parse(raw), raw


def node_text(node: Node, raw: bytes) -> str:
    """Decode the exact source text for a Tree-sitter node."""
    return raw[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def walk_nodes(root: Node) -> Iterator[Node]:
    """Iterative pre-order traversal over all Tree-sitter nodes."""
    stack: list[Node] = [root]
    while stack:
        curr = stack.pop()
        yield curr
        children: Any = curr.children
        if children:
            stack.extend(reversed(children))
