"""Flow-sensitive intra-procedural source-to-sink taint tracking for Python AST and JS/TS Tree-sitter.

Replaces fragile file-wide string checks with branch-scoped, assignment-aware taint
propagation and explicit sink-scoped sanitizer barriers (`path`, `ssrf`, `redirect`,
`xss`, `nosql`).
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
_PY_NON_TAINTED_ANNOTATIONS = frozenset(
    {
        "Request",
        "WebSocket",
        "Response",
        "BackgroundTasks",
        "Session",
        "AsyncSession",
        "Connection",
        "Engine",
    }
)
_PY_DI_CALLS = frozenset({"Depends", "Security", "fastapi.Depends", "fastapi.Security"})
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
_SINK_KINDS = ("path", "ssrf", "redirect", "xss", "nosql")


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _expr_names(node: ast.AST) -> set[str]:
    return {sub.id for sub in ast.walk(node) if isinstance(sub, ast.Name)}


def _is_di_default(default_expr: ast.AST | None) -> bool:
    if default_expr is None:
        return False
    if isinstance(default_expr, ast.Call):
        cname = _dotted(default_expr.func)
        return cname in _PY_DI_CALLS or cname.endswith((".Depends", ".Security"))
    return False


def _is_non_tainted_annotation(ann: ast.AST | None) -> bool:
    if ann is None:
        return False
    # Handle Annotated[User, Depends(get_current_user)]
    for sub in ast.walk(ann):
        if isinstance(sub, ast.Call):
            cname = _dotted(sub.func)
            if cname in _PY_DI_CALLS or cname.endswith((".Depends", ".Security")):
                return True
    name = _dotted(ann)
    tail = name.rsplit(".", 1)[-1] if name else ""
    return tail in _PY_NON_TAINTED_ANNOTATIONS


def _has_trailing_path_separator(arg: ast.AST) -> bool:
    """Return True iff `arg` enforces a directory boundary separator (e.g. `base + os.sep` or `f'{base}/'`).

    Plain `resolved.startswith(base)` without a separator allows sibling-directory bypass
    (`/srv/data2` passes `.startswith('/srv/data')`).
    """
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value.endswith(("/", "\\"))
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        right = arg.right
        if isinstance(right, ast.Constant) and isinstance(right.value, str) and right.value in ("/", "\\"):
            return True
        if _dotted(right) in ("os.sep", "os.path.sep", "sep"):
            return True
    if isinstance(arg, ast.JoinedStr) and arg.values:
        last = arg.values[-1]
        if isinstance(last, ast.Constant) and isinstance(last.value, str) and last.value.endswith(("/", "\\")):
            return True
        if isinstance(last, ast.FormattedValue) and _dotted(last.value) in ("os.sep", "os.path.sep", "sep"):
            return True
    if isinstance(arg, ast.Call) and _dotted(arg.func) == "os.path.join" and arg.args:
        last_arg = arg.args[-1]
        if isinstance(last_arg, ast.Constant) and last_arg.value == "":
            return True
    return False


def _is_full_anchored_regex(pattern_arg: ast.AST) -> bool:
    if isinstance(pattern_arg, ast.Constant) and isinstance(pattern_arg.value, str):
        p = pattern_arg.value
        return p.endswith("$") or p.endswith(r"\Z")
    return False


def _block_always_exits(stmts: list[ast.stmt]) -> bool:
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.If) and last.orelse:
        return _block_always_exits(last.body) and _block_always_exits(last.orelse)
    return False


def _clone_sanitized(san: dict[str, set[str]]) -> dict[str, set[str]]:
    return {k: set(v) for k, v in san.items()}


class PythonTaintTracker:
    """Flow-sensitive intra-procedural source -> sink taint tracker over a Python function AST."""

    def __init__(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.func = func
        self.is_route_handler = self._detect_route_handler(func)
        self.tainted: dict[str, str] = {}
        self.sanitized: dict[str, set[str]] = {k: set() for k in _SINK_KINDS}
        self._node_tainted: dict[int, dict[str, str]] = {}
        self._node_sanitized: dict[int, dict[str, set[str]]] = {}
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
            if isinstance(expr.value, ast.Call) and _dotted(expr.value.func).endswith("Path"):
                kinds.add("path")
        return kinds

    def _is_path_resolve_expr(self, expr: ast.AST) -> bool:
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Call):
                cname = _dotted(sub.func)
                if cname.endswith(
                    (".resolve", "os.path.realpath", "os.path.abspath", "realpath", "abspath")
                ):
                    return True
        return False

    def _extract_atomic_guards(
        self,
        expr: ast.AST,
        resolved_vars: set[str],
    ) -> dict[str, set[str]]:
        """Extract sink barriers implied when `expr` evaluates to True (positive polarity)."""
        guards: dict[str, set[str]] = {k: set() for k in _SINK_KINDS}
        if isinstance(expr, ast.BoolOp) and isinstance(expr.op, ast.And):
            for val in expr.values:
                sub_g = self._extract_atomic_guards(val, resolved_vars)
                for k, vs in sub_g.items():
                    guards[k].update(vs)
            return guards

        if isinstance(expr, ast.Call):
            cname = _dotted(expr.func)
            names = _expr_names(expr)
            if cname.endswith(".is_relative_to") or cname == "is_relative_to":
                guards["path"].update(names)
            elif cname.endswith(".startswith") or cname == "startswith":
                recv = expr.func.value if isinstance(expr.func, ast.Attribute) else None
                recv_name = recv.id if isinstance(recv, ast.Name) else None
                # Path confinement requires a resolved path AND a trailing separator (`+ os.sep` / `'/'`)
                if expr.args and _has_trailing_path_separator(expr.args[0]):
                    if recv_name and recv_name in resolved_vars:
                        guards["path"].add(recv_name)
                    elif recv is not None and self._is_path_resolve_expr(recv):
                        guards["path"].update(_expr_names(recv))
                # Open-redirect guard: target.startswith("/")
                if expr.args and isinstance(expr.args[0], ast.Constant) and expr.args[0].value == "/":
                    if recv_name:
                        guards["redirect"].add(recv_name)
            elif cname == "re.fullmatch":
                if len(expr.args) >= 2:
                    guards["path"].update(_expr_names(expr.args[1]))
            elif cname == "re.match":
                # re.match only checks a prefix unless explicitly end-anchored with `$` or `\Z`
                if len(expr.args) >= 2 and _is_full_anchored_regex(expr.args[0]):
                    guards["path"].update(_expr_names(expr.args[1]))
            elif cname.endswith("_RE.fullmatch"):
                if expr.args:
                    guards["path"].update(_expr_names(expr.args[0]))
            elif cname in ("is_fetch_url_allowed", "validate_loopback_url", "is_safe_url"):
                guards["ssrf"].update(names)
                guards["redirect"].update(names)
        elif isinstance(expr, ast.Compare):
            # os.path.commonpath([base, target]) == base
            if (
                len(expr.ops) == 1
                and isinstance(expr.ops[0], ast.Eq)
                and isinstance(expr.left, ast.Call)
                and _dotted(expr.left.func) in ("os.path.commonpath", "commonpath")
            ):
                guards["path"].update(_expr_names(expr.left))
            else:
                names = _expr_names(expr)
                src_names = {_dotted(s) for s in ast.walk(expr) if isinstance(s, ast.Attribute)}
                if any(s.endswith(".hostname") or s.endswith(".netloc") for s in src_names):
                    guards["ssrf"].update(names)
                    guards["redirect"].update(names)
        return guards

    def _extract_test_guards(
        self,
        test: ast.AST,
        resolved_vars: set[str],
    ) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
        """Return `(true_branch_guards, false_branch_guards)` for an `if <test>:` condition."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            # `if not <safe_cond>:` -> `<safe_cond>` holds in the FALSE branch (and after early-exit)
            return {k: set() for k in _SINK_KINDS}, self._extract_atomic_guards(
                test.operand, resolved_vars
            )
        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
            # `if not A or not B: raise` -> both A and B hold in the FALSE branch
            false_g: dict[str, set[str]] = {k: set() for k in _SINK_KINDS}
            for val in test.values:
                if isinstance(val, ast.UnaryOp) and isinstance(val.op, ast.Not):
                    sub_g = self._extract_atomic_guards(val.operand, resolved_vars)
                    for k, vs in sub_g.items():
                        false_g[k].update(vs)
            return {k: set() for k in _SINK_KINDS}, false_g
        return self._extract_atomic_guards(test, resolved_vars), {k: set() for k in _SINK_KINDS}

    def _snapshot_subtree(
        self,
        node: ast.AST,
        tainted: dict[str, str],
        sanitized: dict[str, set[str]],
    ) -> None:
        t_snap = dict(tainted)
        s_snap = _clone_sanitized(sanitized)
        for sub in ast.walk(node):
            self._node_tainted[id(sub)] = t_snap
            self._node_sanitized[id(sub)] = s_snap

    def _apply_guards(
        self,
        sanitized: dict[str, set[str]],
        guards: dict[str, set[str]],
    ) -> None:
        for k, vs in guards.items():
            sanitized[k].update(vs)

    def _seed_parameters(self) -> dict[str, str]:
        tainted: dict[str, str] = {}
        pos_args = list(self.func.args.posonlyargs) + list(self.func.args.args)
        defaults = list(self.func.args.defaults)
        pad = len(pos_args) - len(defaults)
        aligned_defaults: list[ast.AST | None] = [*([None] * max(0, pad)), *defaults]

        all_pairs: list[tuple[ast.arg, ast.AST | None]] = list(
            zip(pos_args, aligned_defaults, strict=False)
        )
        all_pairs.extend(
            zip(self.func.args.kwonlyargs, self.func.args.kw_defaults, strict=False)
        )

        for arg, default_expr in all_pairs:
            if arg.arg in ("self", "cls"):
                continue
            if _is_di_default(default_expr) or _is_non_tainted_annotation(arg.annotation):
                continue
            if self.is_route_handler:
                tainted[arg.arg] = f"route_param:{arg.arg}"
            elif arg.arg.lower() in _PY_TAINTED_PARAM_NAMES:
                tainted[arg.arg] = f"param:{arg.arg}"
        return tainted

    def _handle_assignment(
        self,
        targets: list[ast.expr],
        val: ast.expr,
        tainted: dict[str, str],
        sanitized: dict[str, set[str]],
        resolved_vars: set[str],
    ) -> None:
        src = self._direct_source(val)
        val_names = _expr_names(val)
        propagated = src or next((tainted[n] for n in val_names if n in tainted), None)
        sanitized_kinds = self._check_sanitizer_call(val)
        is_resolved = self._is_path_resolve_expr(val)

        for tgt in targets:
            if isinstance(tgt, ast.Name):
                var = tgt.id
                # Reassignment invalidates any prior sanitization or resolution state on `var`
                for svars in sanitized.values():
                    svars.discard(var)
                resolved_vars.discard(var)

                if is_resolved:
                    resolved_vars.add(var)
                if sanitized_kinds:
                    for sk in sanitized_kinds:
                        sanitized[sk].add(var)

                if propagated:
                    tainted[var] = propagated
                    # Inherit sanitizer state only if NOT a fresh direct source and ALL tainted inputs were sanitized
                    if src is None:
                        tainted_inputs = [n for n in val_names if n in tainted and n != var]
                        if tainted_inputs:
                            for svars in sanitized.values():
                                if all(n in svars for n in tainted_inputs):
                                    svars.add(var)
                else:
                    tainted.pop(var, None)
            elif isinstance(tgt, (ast.Tuple, ast.List)):
                for elt in tgt.elts:
                    if isinstance(elt, ast.Name):
                        for svars in sanitized.values():
                            svars.discard(elt.id)
                        if propagated:
                            tainted[elt.id] = propagated
                        else:
                            tainted.pop(elt.id, None)

    def _walk_stmts(
        self,
        stmts: list[ast.stmt],
        tainted: dict[str, str],
        sanitized: dict[str, set[str]],
        resolved_vars: set[str],
    ) -> None:
        for stmt in stmts:
            # Skip nested function/class definitions (analyzed with their own tracker)
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue

            if isinstance(stmt, ast.If):
                self._snapshot_subtree(stmt.test, tainted, sanitized)
                true_g, false_g = self._extract_test_guards(stmt.test, resolved_vars)

                body_t, body_s, body_r = dict(tainted), _clone_sanitized(sanitized), set(resolved_vars)
                self._apply_guards(body_s, true_g)
                self._walk_stmts(stmt.body, body_t, body_s, body_r)

                else_t, else_s, else_r = dict(tainted), _clone_sanitized(sanitized), set(resolved_vars)
                self._apply_guards(else_s, false_g)
                self._walk_stmts(stmt.orelse, else_t, else_s, else_r)

                body_exits = _block_always_exits(stmt.body)
                else_exits = _block_always_exits(stmt.orelse)
                if body_exits and not else_exits:
                    # Guarded early exit (`if not safe: raise/return`): false_g holds for remaining block
                    tainted.clear()
                    tainted.update(else_t)
                    for k in _SINK_KINDS:
                        sanitized[k] = set(else_s[k])
                    resolved_vars.clear()
                    resolved_vars.update(else_r)
                elif else_exits and not body_exits:
                    tainted.clear()
                    tainted.update(body_t)
                    for k in _SINK_KINDS:
                        sanitized[k] = set(body_s[k])
                    resolved_vars.clear()
                    resolved_vars.update(body_r)
                else:
                    # Merge: taint is union (conservative); sanitization is intersection (must hold on ALL paths)
                    for var, origin in body_t.items():
                        tainted.setdefault(var, origin)
                    for var, origin in else_t.items():
                        tainted.setdefault(var, origin)
                    for k in _SINK_KINDS:
                        sanitized[k] = body_s[k] & else_s[k]
                continue

            if isinstance(stmt, ast.Assign):
                self._snapshot_subtree(stmt.value, tainted, sanitized)
                self._handle_assignment(stmt.targets, stmt.value, tainted, sanitized, resolved_vars)
                self._snapshot_subtree(stmt, tainted, sanitized)
                continue

            if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                self._snapshot_subtree(stmt.value, tainted, sanitized)
                self._handle_assignment([stmt.target], stmt.value, tainted, sanitized, resolved_vars)
                self._snapshot_subtree(stmt, tainted, sanitized)
                continue

            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                self._snapshot_subtree(stmt, tainted, sanitized)
                cname = _dotted(stmt.value.func)
                if cname in ("validate_loopback_url", "is_fetch_url_allowed", "is_safe_url"):
                    names = _expr_names(stmt.value)
                    sanitized["ssrf"].update(names)
                    sanitized["redirect"].update(names)
                continue

            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    self._snapshot_subtree(item.context_expr, tainted, sanitized)
                self._walk_stmts(stmt.body, tainted, sanitized, resolved_vars)
                continue

            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                if isinstance(stmt, (ast.For, ast.AsyncFor)):
                    self._snapshot_subtree(stmt.iter, tainted, sanitized)
                else:
                    self._snapshot_subtree(stmt.test, tainted, sanitized)
                self._walk_stmts(stmt.body, tainted, sanitized, resolved_vars)
                self._walk_stmts(stmt.orelse, tainted, sanitized, resolved_vars)
                continue

            if isinstance(stmt, ast.Try):
                self._walk_stmts(stmt.body, tainted, sanitized, resolved_vars)
                for handler in stmt.handlers:
                    self._walk_stmts(handler.body, dict(tainted), _clone_sanitized(sanitized), set(resolved_vars))
                self._walk_stmts(stmt.orelse, tainted, sanitized, resolved_vars)
                self._walk_stmts(stmt.finalbody, tainted, sanitized, resolved_vars)
                continue

            # All other statements (Return, Raise, Assert, etc.)
            if isinstance(stmt, ast.Assert):
                self._snapshot_subtree(stmt, tainted, sanitized)
                pos_g, _ = self._extract_test_guards(stmt.test, resolved_vars)
                self._apply_guards(sanitized, pos_g)
            else:
                self._snapshot_subtree(stmt, tainted, sanitized)

    def _analyze(self) -> None:
        tainted = self._seed_parameters()
        sanitized: dict[str, set[str]] = {k: set() for k in _SINK_KINDS}
        resolved_vars: set[str] = set()
        self._walk_stmts(self.func.body, tainted, sanitized, resolved_vars)
        self.tainted = tainted
        self.sanitized = sanitized

    def is_var_sanitized(
        self,
        var_name: str,
        sink_kind: str,
        at_node: ast.AST | None = None,
    ) -> bool:
        san = (
            self._node_sanitized.get(id(at_node), self.sanitized)
            if at_node is not None
            else self.sanitized
        )
        return var_name in san.get(sink_kind, set())

    def is_tainted(
        self,
        expr: ast.AST,
        sink_kind: str,
        require_http: bool = False,
        at_node: ast.AST | None = None,
    ) -> str | None:
        """Return taint source if `expr` is tainted and NOT sanitized for `sink_kind` at `at_node`."""
        ref = at_node if at_node is not None else expr
        tainted_map = self._node_tainted.get(id(ref), self.tainted)
        sanitized_vars = self._node_sanitized.get(id(ref), self.sanitized).get(sink_kind, set())

        if sink_kind in self._check_sanitizer_call(expr):
            return None
        direct = self._direct_source(expr)
        if direct:
            return direct
        for name in _expr_names(expr):
            if name in tainted_map and name not in sanitized_vars:
                src = tainted_map[name]
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


def _js_block_exits(stmt_node: Any, raw: bytes) -> bool:
    txt = node_text(stmt_node, raw)
    return bool(re.search(r"\b(?:return|throw)\b", txt))


class JsTaintTracker:
    """Flow-aware intra-procedural taint tracker over a Tree-sitter JS/TS scope."""

    def __init__(self, scope_node: Any, raw: bytes) -> None:
        self.scope_node = scope_node
        self.raw = raw
        self.scope_text = node_text(scope_node, raw)
        self.tainted: dict[str, str] = {}
        self.sanitized: dict[str, set[str]] = {k: set() for k in _SINK_KINDS}
        self._guard_ranges: list[tuple[int, int, str, set[str]]] = []
        self._analyze()

    def _analyze(self) -> None:
        has_path_resolve = "path.resolve(" in self.scope_text
        # Single AST walk in source order to handle declarations, reassignments, and scoped if-guards
        for node in walk_nodes(self.scope_node):
            if node.type == "variable_declarator":
                name_n = node.child_by_field_name("name")
                val_n = node.child_by_field_name("value")
                if not name_n or not val_n:
                    continue
                self._record_assignment(name_n, val_n)
            elif node.type == "assignment_expression":
                left_n = node.child_by_field_name("left")
                right_n = node.child_by_field_name("right")
                if left_n and right_n and left_n.type == "identifier":
                    self._record_assignment(left_n, right_n)
            elif node.type == "if_statement":
                cond = node.child_by_field_name("condition")
                cons = node.child_by_field_name("consequence")
                if not cond or not cons:
                    continue
                ctxt = node_text(cond, self.raw)
                idents = set(_JS_IDENT_RE.findall(ctxt))
                is_negated = ctxt.lstrip("( \t").startswith("!")
                cons_exits = _js_block_exits(cons, self.raw)

                # Scope guard to either the `consequence` block or, if negated early-exit, rest of parent block
                if is_negated and cons_exits and node.parent is not None:
                    start_b = cons.end_byte
                    end_b = node.parent.end_byte
                elif not is_negated:
                    start_b = cons.start_byte
                    end_b = cons.end_byte
                else:
                    continue

                # Path startsWith requires a trailing separator (`+ path.sep` / `+ '/'` / `'/...'`)
                if (
                    ".startsWith(" in ctxt
                    and (has_path_resolve or "path.relative(" in ctxt)
                    and ("path.sep" in ctxt or "+ '/'" in ctxt or '+ "/"' in ctxt or "/')" in ctxt or '/")' in ctxt)
                ):
                    self._guard_ranges.append((start_b, end_b, "path", idents))
                if "startsWith('/')" in ctxt or 'startsWith("/")' in ctxt:
                    self._guard_ranges.append((start_b, end_b, "redirect", idents))
                if any(tok in ctxt for tok in ("allowedHosts", "allowedOrigins", "isAllowedUrl", "ALLOWED_HOSTS")):
                    self._guard_ranges.append((start_b, end_b, "ssrf", idents))
                    self._guard_ranges.append((start_b, end_b, "redirect", idents))

    def _record_assignment(self, name_n: Any, val_n: Any) -> None:
        vtxt = node_text(val_n, self.raw)
        v_idents = set(_JS_IDENT_RE.findall(vtxt))
        src_m = _JS_TAINT_SOURCE_RE.search(vtxt)
        src = src_m.group(0) if src_m else None
        if src is None and self.tainted:
            for ident in v_idents:
                origin = self.tainted.get(ident)
                if origin is not None:
                    src = origin
                    break
        is_path_san = "path.basename(" in vtxt
        is_xss_san = any(
            tok in vtxt for tok in ("DOMPurify.sanitize(", "escapeHtml(", "encodeURIComponent(")
        )
        if name_n.type == "identifier":
            var = node_text(name_n, self.raw)
            # Invalidate prior sanitization on reassignment
            for svars in self.sanitized.values():
                svars.discard(var)
            if is_path_san:
                self.sanitized["path"].add(var)
            if is_xss_san:
                self.sanitized["xss"].add(var)
            if src:
                self.tainted[var] = src
            else:
                self.tainted.pop(var, None)
        elif name_n.type == "object_pattern" and src:
            for sub in walk_nodes(name_n):
                if sub.type in ("shorthand_property_identifier_pattern", "identifier"):
                    v = node_text(sub, self.raw)
                    for svars in self.sanitized.values():
                        svars.discard(v)
                    self.tainted[v] = src

    def _active_sanitized(self, expr_node: Any, sink_kind: str) -> set[str]:
        san = set(self.sanitized.get(sink_kind, set()))
        pos = getattr(expr_node, "start_byte", -1)
        if pos >= 0:
            for start_b, end_b, kind, idents in self._guard_ranges:
                if kind == sink_kind and start_b <= pos <= end_b:
                    san.update(idents)
        return san

    def is_sanitized(self, expr_node: Any, sink_kind: str) -> bool:
        etxt = node_text(expr_node, self.raw)
        if sink_kind == "path" and "path.basename(" in etxt:
            return True
        if sink_kind == "xss" and any(
            tok in etxt for tok in ("DOMPurify.sanitize(", "escapeHtml(", "encodeURIComponent(")
        ):
            return True
        san = self._active_sanitized(expr_node, sink_kind)
        if not san:
            return False
        idents = set(_JS_IDENT_RE.findall(etxt))
        return bool(idents) and idents.issubset(san)

    def is_tainted(self, expr_node: Any, sink_kind: str) -> str | None:
        etxt = node_text(expr_node, self.raw)
        if sink_kind == "path" and "path.basename(" in etxt:
            return None
        if sink_kind == "xss" and any(
            tok in etxt for tok in ("DOMPurify.sanitize(", "escapeHtml(", "encodeURIComponent(")
        ):
            return None
        m = _JS_TAINT_SOURCE_RE.search(etxt)
        if m:
            return m.group(0)
        if not self.tainted:
            return None
        san = self._active_sanitized(expr_node, sink_kind)
        for ident in _JS_IDENT_RE.findall(etxt):
            if ident not in san:
                origin = self.tainted.get(ident)
                if origin is not None:
                    return origin
        return None
