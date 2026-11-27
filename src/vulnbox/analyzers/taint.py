"""Intra-procedural source-to-sink taint tracking for Python AST and JS/TS Tree-sitter.

Replaces fragile file-wide string checks (e.g. `"resolve(" in src`) with per-variable
taint propagation and explicit sink-scoped sanitizer barriers (`path`, `ssrf`, `redirect`,
`xss`, `sql`, `nosql`).
"""

from __future__ import annotations

import ast
import re
from typing import Any

from vulnbox.callgraph.ts_utils import node_text, walk_nodes

_PY_HTTP_SOURCE_ATTRS = frozenset(
    {
        "args",
        "form",
        "values",
        "json",
        "headers",
        "cookies",
        "data",
        "query_params",
        "path_params",
        "GET",
        "POST",
        "FILES",
        "body",
    }
)
_PY_HTTP_SOURCE_CALLS = frozenset(
    {
        "request.get_json",
        "request.get_data",
        "parse_qs",
        "urllib.parse.parse_qs",
        "input",
    }
)
_PY_ROUTE_DECORATOR_HINTS = (
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "api_view",
)
_PY_TAINTED_PARAM_NAMES = frozenset(
    {
        "filename",
        "filepath",
        "file_path",
        "user_path",
        "rel_path",
        "url",
        "target_url",
        "next_url",
        "redirect_url",
        "template",
        "user_input",
        "xml_data",
        "payload",
        "query",
    }
)
_PY_PATH_SANITIZER_CALLS = frozenset(
    {
        "os.path.basename",
        "basename",
        "secure_filename",
        "werkzeug.utils.secure_filename",
    }
)
_PY_XSS_SANITIZER_CALLS = frozenset(
    {
        "html.escape",
        "escape",
        "markupsafe.escape",
    }
)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _expr_names(node: ast.AST) -> set[str]:
    return {sub.id for sub in ast.walk(node) if isinstance(sub, ast.Name)}


class PythonTaintTracker:
    """Intra-procedural source -> sink taint tracker over a Python function AST."""

    def __init__(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.func = func
        self.is_route_handler = self._detect_route_handler(func)
        self.tainted: dict[str, str] = {}
        self.sanitized: dict[str, set[str]] = {
            "path": set(),
            "ssrf": set(),
            "redirect": set(),
            "xss": set(),
            "nosql": set(),
        }
        self._resolved_path_vars: set[str] = set()
        self._analyze()

    @staticmethod
    def _detect_route_handler(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        if func.name in ("do_GET", "do_POST", "do_PUT", "do_DELETE", "do_PATCH"):
            return True
        for dec in func.decorator_list:
            dname = _dotted(dec.func if isinstance(dec, ast.Call) else dec).lower()
            if any(dname.endswith(f".{h}") or dname == h for h in _PY_ROUTE_DECORATOR_HINTS):
                return True
        return False

    def _direct_source(self, expr: ast.AST) -> str | None:
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Attribute):
                d = _dotted(sub)
                if d.startswith(("request.", "req.")) and sub.attr in _PY_HTTP_SOURCE_ATTRS:
                    return d
                if d == "self.path" and self.func.name.startswith("do_"):
                    return "self.path"
            elif isinstance(sub, ast.Call):
                cname = _dotted(sub.func)
                if cname in _PY_HTTP_SOURCE_CALLS or cname.endswith(".get_json"):
                    return cname
                if (
                    cname.startswith(("request.", "req."))
                    and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr in ("get_json", "get_data")
                ):
                    return cname
        return None

    def _check_sanitizer_call(self, expr: ast.AST) -> set[str]:
        kinds: set[str] = set()
        if isinstance(expr, ast.Call):
            cname = _dotted(expr.func)
            if cname in _PY_PATH_SANITIZER_CALLS:
                kinds.add("path")
            if cname in _PY_XSS_SANITIZER_CALLS:
                kinds.add("xss")
            if cname in ("is_fetch_url_allowed", "validate_loopback_url"):
                kinds.add("ssrf")
        elif isinstance(expr, ast.Attribute) and expr.attr == "name":
            # Path(x).name strips directory components
            if isinstance(expr.value, ast.Call) and _dotted(expr.value.func).endswith("Path"):
                kinds.add("path")
        return kinds

    def _is_path_resolve_expr(self, expr: ast.AST) -> bool:
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Call):
                cname = _dotted(sub.func)
                if cname.endswith((".resolve", "os.path.realpath", "os.path.abspath", "realpath", "abspath")):
                    return True
        return False

    def _record_guard_barriers(self, test_expr: ast.AST) -> None:
        for sub in ast.walk(test_expr):
            if isinstance(sub, ast.Call):
                cname = _dotted(sub.func)
                names = _expr_names(sub)
                # Path confinement: target.is_relative_to(base), os.path.commonpath([...]),
                # resolved.startswith(base), re.fullmatch(r'[A-Za-z0-9_-]+', x)
                if cname.endswith(".is_relative_to") or cname == "is_relative_to" or cname in ("os.path.commonpath", "commonpath"):
                    self.sanitized["path"].update(names)
                elif cname.endswith(".startswith") or cname == "startswith":
                    recv = sub.func.value if isinstance(sub.func, ast.Attribute) else None
                    recv_name = recv.id if isinstance(recv, ast.Name) else None
                    if recv_name and recv_name in self._resolved_path_vars:
                        self.sanitized["path"].add(recv_name)
                    elif recv is not None and self._is_path_resolve_expr(recv):
                        self.sanitized["path"].update(_expr_names(recv))
                    if sub.args and isinstance(sub.args[0], ast.Constant) and sub.args[0].value == "/":
                        if recv_name:
                            self.sanitized["redirect"].add(recv_name)
                elif cname in ("re.fullmatch", "re.match") or cname.endswith("_RE.match"):
                    self.sanitized["path"].update(names)
                elif cname in ("is_fetch_url_allowed", "validate_loopback_url", "is_safe_url"):
                    self.sanitized["ssrf"].update(names)
                    self.sanitized["redirect"].update(names)
            elif isinstance(sub, ast.Compare):
                names = _expr_names(sub)
                src_names = {
                    _dotted(s) for s in ast.walk(sub) if isinstance(s, ast.Attribute)
                }
                if any(s.endswith(".hostname") or s.endswith(".netloc") for s in src_names):
                    self.sanitized["ssrf"].update(names)
                    self.sanitized["redirect"].update(names)

    def _analyze(self) -> None:
        # Seed function parameters
        all_args = list(self.func.args.posonlyargs) + list(self.func.args.args) + list(self.func.args.kwonlyargs)
        for arg in all_args:
            if arg.arg in ("self", "cls"):
                continue
            if self.is_route_handler:
                self.tainted[arg.arg] = f"route_param:{arg.arg}"
            elif arg.arg.lower() in _PY_TAINTED_PARAM_NAMES:
                self.tainted[arg.arg] = f"param:{arg.arg}"

        # Two-pass intra-procedural propagation over statements in order
        for _ in range(2):
            for node in ast.walk(self.func):
                if isinstance(node, ast.If):
                    self._record_guard_barriers(node.test)
                elif isinstance(node, ast.Call):
                    # Bare validation call statements like validate_loopback_url(url)
                    cname = _dotted(node.func)
                    if cname in ("validate_loopback_url", "is_fetch_url_allowed", "is_safe_url"):
                        names = _expr_names(node)
                        self.sanitized["ssrf"].update(names)
                        self.sanitized["redirect"].update(names)
                elif isinstance(node, ast.Assign):
                    val = node.value
                    src = self._direct_source(val)
                    val_names = _expr_names(val)
                    propagated = src or next((self.tainted[n] for n in val_names if n in self.tainted), None)
                    sanitized_kinds = self._check_sanitizer_call(val)
                    is_resolved = self._is_path_resolve_expr(val)

                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            if is_resolved:
                                self._resolved_path_vars.add(tgt.id)
                            if sanitized_kinds:
                                for sk in sanitized_kinds:
                                    self.sanitized[sk].add(tgt.id)
                            if propagated and not sanitized_kinds:
                                self.tainted[tgt.id] = propagated
                                # Inherit sanitizer state if all tainted inputs were sanitized
                                for svars in self.sanitized.values():
                                    tainted_inputs = [n for n in val_names if n in self.tainted]
                                    if tainted_inputs and all(n in svars for n in tainted_inputs):
                                        svars.add(tgt.id)
                        elif isinstance(tgt, (ast.Tuple, ast.List)) and propagated:
                            for elt in tgt.elts:
                                if isinstance(elt, ast.Name):
                                    self.tainted[elt.id] = propagated

    def is_tainted(
        self,
        expr: ast.AST,
        sink_kind: str,
        require_http: bool = False,
    ) -> str | None:
        """Return taint source if `expr` is tainted and NOT sanitized for `sink_kind`."""
        sanitized_vars = self.sanitized.get(sink_kind, set())
        if sink_kind in self._check_sanitizer_call(expr):
            return None
        direct = self._direct_source(expr)
        if direct:
            return direct
        for name in _expr_names(expr):
            if name in self.tainted and name not in sanitized_vars:
                src = self.tainted[name]
                if require_http and src.startswith("param:"):
                    continue
                return src
        return None


_JS_TAINT_SOURCE_RE = re.compile(
    r"\b(?:req|request)\.(?:query|params|body|headers|cookies|url|originalUrl|path)\b"
    r"|\b(?:location|window\.location|document\.location)\.(?:search|hash|href)\b"
    r"|\bnew\s+URLSearchParams\s*\(\s*(?:(?:window\.|document\.)?location\.(?:search|hash|href)|(?:req|request)\.(?:url|originalUrl|query))"
)
_JS_IDENT_RE = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")


class JsTaintTracker:
    """Intra-procedural taint tracker over a Tree-sitter JS/TS function or module scope."""

    def __init__(self, scope_node: Any, raw: bytes) -> None:
        self.scope_node = scope_node
        self.raw = raw
        self.scope_text = node_text(scope_node, raw)
        self.tainted: dict[str, str] = {}
        self.sanitized: dict[str, set[str]] = {
            "path": set(),
            "ssrf": set(),
            "redirect": set(),
            "xss": set(),
            "nosql": set(),
        }
        self._analyze()

    def _analyze(self) -> None:
        # Single AST walk to collect declarators and if-statement guards
        declarators: list[tuple[Any, str, set[str]]] = []
        if_conds: list[str] = []
        for node in walk_nodes(self.scope_node):
            if node.type == "variable_declarator":
                name_n = node.child_by_field_name("name")
                val_n = node.child_by_field_name("value")
                if name_n and val_n:
                    vtxt = node_text(val_n, self.raw)
                    declarators.append((name_n, vtxt, set(_JS_IDENT_RE.findall(vtxt))))
            elif node.type == "if_statement":
                cond = node.child_by_field_name("condition")
                if cond:
                    if_conds.append(node_text(cond, self.raw))

        # Two-pass propagation using O(1) identifier set intersection
        for _ in range(2):
            for name_n, vtxt, v_idents in declarators:
                src_m = _JS_TAINT_SOURCE_RE.search(vtxt)
                src = src_m.group(0) if src_m else None
                if src is None and self.tainted:
                    for ident in v_idents:
                        origin = self.tainted.get(ident)
                        if origin is not None:
                            src = origin
                            break
                is_path_san = "path.basename(" in vtxt
                is_xss_san = any(tok in vtxt for tok in ("DOMPurify.sanitize(", "escapeHtml(", "encodeURIComponent("))
                if name_n.type == "identifier":
                    var = node_text(name_n, self.raw)
                    if is_path_san:
                        self.sanitized["path"].add(var)
                    if is_xss_san:
                        self.sanitized["xss"].add(var)
                    if src:
                        self.tainted[var] = src
                elif name_n.type == "object_pattern" and src:
                    for sub in walk_nodes(name_n):
                        if sub.type in ("shorthand_property_identifier_pattern", "identifier"):
                            self.tainted[node_text(sub, self.raw)] = src

        # Record per-variable guard barriers inside if conditions
        has_path_resolve = "path.resolve(" in self.scope_text
        for ctxt in if_conds:
            idents = set(_JS_IDENT_RE.findall(ctxt))
            if ".startsWith(" in ctxt and (has_path_resolve or "path.relative(" in ctxt):
                self.sanitized["path"].update(idents)
            if "startsWith('/')" in ctxt or 'startsWith("/")' in ctxt:
                self.sanitized["redirect"].update(idents)
            if any(tok in ctxt for tok in ("allowedHosts", "allowedOrigins", "isAllowedUrl", "ALLOWED_HOSTS")):
                self.sanitized["ssrf"].update(idents)
                self.sanitized["redirect"].update(idents)

    def is_sanitized(self, expr_node: Any, sink_kind: str) -> bool:
        etxt = node_text(expr_node, self.raw)
        if sink_kind == "path" and "path.basename(" in etxt:
            return True
        if sink_kind == "xss" and any(
            tok in etxt for tok in ("DOMPurify.sanitize(", "escapeHtml(", "encodeURIComponent(")
        ):
            return True
        san = self.sanitized.get(sink_kind, set())
        if not san:
            return False
        idents = set(_JS_IDENT_RE.findall(etxt))
        return bool(idents) and idents.issubset(san)

    def is_tainted(self, expr_node: Any, sink_kind: str) -> str | None:
        etxt = node_text(expr_node, self.raw)
        if sink_kind == "path" and "path.basename(" in etxt:
            return None
        if sink_kind == "xss" and any(tok in etxt for tok in ("DOMPurify.sanitize(", "escapeHtml(", "encodeURIComponent(")):
            return None
        m = _JS_TAINT_SOURCE_RE.search(etxt)
        if m:
            return m.group(0)
        if not self.tainted:
            return None
        san = self.sanitized.get(sink_kind, set())
        for ident in _JS_IDENT_RE.findall(etxt):
            if ident not in san:
                origin = self.tainted.get(ident)
                if origin is not None:
                    return origin
        return None
