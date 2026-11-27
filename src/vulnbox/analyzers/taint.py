"""Flow-sensitive intra-procedural source-to-sink taint tracking for Python AST and JS/TS Tree-sitter.

Both Python (`PythonTaintTracker`) and JavaScript/TypeScript (`JsTaintTracker`) walk real
syntax trees (`ast` / Tree-sitter) with branch-scoped, polarity-aware guard extraction,
per-variable path-resolution tracking, and assignment-driven sanitization invalidation.
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
_PY_EARLY_EXIT_CALLS = frozenset(
    {
        "abort",
        "flask.abort",
        "werkzeug.exceptions.abort",
        "sys.exit",
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
_SINK_KINDS = ("path", "ssrf", "redirect", "xss", "nosql")

# Safe allowlist-only regex tokens for path segment validation (no `.`, `/`, `\`, or negated classes `[^...]`)
_SAFE_PATH_REGEX_BODY_RE = re.compile(
    r"^(?:\\w|\\d|[A-Za-z0-9_-]|\[[A-Za-z0-9_-]+\]|[+*?{}0-9,()|])+$"
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
    for sub in ast.walk(ann):
        if isinstance(sub, ast.Call):
            cname = _dotted(sub.func)
            if cname in _PY_DI_CALLS or cname.endswith((".Depends", ".Security")):
                return True
    name = _dotted(ann)
    tail = name.rsplit(".", 1)[-1] if name else ""
    return tail in _PY_NON_TAINTED_ANNOTATIONS


def _has_trailing_path_separator(arg: ast.AST) -> bool:
    """Return True iff `arg` enforces a directory boundary separator (e.g. `base + os.sep` or `f'{base}/'`)."""
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return len(arg.value) > 1 and arg.value.endswith(("/", "\\"))
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


def _is_safe_path_regex(pattern_arg: ast.AST, *, require_end_anchor: bool = False) -> bool:
    """Return True only when `pattern_arg` is a restrictive allowlist regex that cannot match `/` or `..`."""
    if not (isinstance(pattern_arg, ast.Constant) and isinstance(pattern_arg.value, str)):
        return False
    p = pattern_arg.value
    if require_end_anchor and not (p.endswith("$") or p.endswith(r"\Z")):
        return False
    body = p
    if body.startswith("^"):
        body = body[1:]
    elif body.startswith(r"\A"):
        body = body[2:]
    if body.endswith("$"):
        body = body[:-1]
    elif body.endswith(r"\Z"):
        body = body[:-2]
    if not body:
        return False
    if "." in body or "/" in body or "[^" in body:
        return False
    return bool(_SAFE_PATH_REGEX_BODY_RE.fullmatch(body))


def _startswith_prefixes(arg: ast.AST) -> set[str]:
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return {arg.value}
    if isinstance(arg, (ast.Tuple, ast.List)):
        return {
            elt.value
            for elt in arg.elts
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
        }
    return set()


def _extract_startswith_info(expr: ast.AST) -> tuple[str | None, set[str]]:
    if isinstance(expr, ast.Call):
        cname = _dotted(expr.func)
        if (cname.endswith(".startswith") or cname == "startswith") and expr.args:
            recv = expr.func.value if isinstance(expr.func, ast.Attribute) else None
            if isinstance(recv, ast.Name):
                return recv.id, _startswith_prefixes(expr.args[0])
    return None, set()


def _has_host_or_netloc_attr(expr: ast.AST) -> bool:
    return any(
        isinstance(s, ast.Attribute) and s.attr in ("hostname", "netloc")
        for s in ast.walk(expr)
    )


def _rejected_second_chars_for_var(expr: ast.AST, var_name: str, *, negated: bool = False) -> set[str]:
    """Extract characters rejected at index 1 (or via startswith '//' / '/\\') for `var_name`.

    When `negated=False`: returns chars guaranteed NOT to be at `var_name[1]` when `expr` is True.
    When `negated=True`: returns chars guaranteed NOT to be at `var_name[1]` when `expr` is False.
    """
    rejected: set[str] = set()
    # Pattern 1: `not x.startswith(("//", "/\\"))` (when negated=False) or `x.startswith(...)` (when negated=True)
    target = expr.operand if (not negated and isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not)) else (expr if negated else None)
    if target is not None:
        recv_name, prefixes = _extract_startswith_info(target)
        if recv_name == var_name:
            if "//" in prefixes:
                rejected.add("/")
            if "/\\" in prefixes:
                rejected.add("\\")

    # Pattern 2: strictly index 1 comparison (`x[1] != "/"` / `x[1] not in ("/", "\\")` when negated=False,
    # or `x[1] == "/"` / `x[1] in ("/", "\\")` when negated=True)
    if isinstance(expr, ast.Compare) and len(expr.ops) == 1 and isinstance(expr.left, ast.Subscript):
        sub = expr.left
        if (
            isinstance(sub.value, ast.Name)
            and sub.value.id == var_name
            and isinstance(sub.slice, ast.Constant)
            and sub.slice.value == 1
        ):
            op = expr.ops[0]
            comp = expr.comparators[0]
            if (not negated and isinstance(op, (ast.NotEq, ast.NotIn))) or (
                negated and isinstance(op, (ast.Eq, ast.In))
            ):
                if isinstance(comp, ast.Constant) and isinstance(comp.value, str):
                    for ch in comp.value:
                        if ch in ("/", "\\"):
                            rejected.add(ch)
                elif isinstance(comp, (ast.Tuple, ast.List, ast.Set)):
                    for elt in comp.elts:
                        if isinstance(elt, ast.Constant) and elt.value in ("/", "\\"):
                            rejected.add(elt.value)

    # Pattern 3: `not urlparse(x).netloc` / `urlparse(x).netloc == ""`
    if not negated:
        if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
            if isinstance(expr.operand, ast.Attribute) and expr.operand.attr == "netloc":
                if var_name in _expr_names(expr.operand):
                    return {"/", "\\"}
        if isinstance(expr, ast.Compare) and len(expr.ops) == 1 and isinstance(expr.ops[0], ast.Eq):
            if any(isinstance(s, ast.Attribute) and s.attr == "netloc" for s in ast.walk(expr)) and var_name in _expr_names(expr):
                if any(isinstance(c, ast.Constant) and c.value == "" for c in expr.comparators):
                    return {"/", "\\"}
    else:
        if isinstance(expr, ast.Attribute) and expr.attr == "netloc" and var_name in _expr_names(expr):
            return {"/", "\\"}

    return rejected


def _block_always_exits(stmts: list[ast.stmt]) -> bool:
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        cname = _dotted(last.value.func)
        if cname in _PY_EARLY_EXIT_CALLS or cname.endswith(".abort"):
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
            slash_vars: set[str] = set()
            for val in expr.values:
                sub_g = self._extract_atomic_guards(val, resolved_vars)
                for k, vs in sub_g.items():
                    guards[k].update(vs)
                recv_name, prefixes = _extract_startswith_info(val)
                if recv_name and "/" in prefixes:
                    slash_vars.add(recv_name)
            # Open-redirect requires `/` prefix AND rejection of BOTH `//` AND `/\` (or netloc == "")
            for v in slash_vars:
                rej: set[str] = set()
                for val in expr.values:
                    rej.update(_rejected_second_chars_for_var(val, v, negated=False))
                if {"/", "\\"}.issubset(rej):
                    guards["redirect"].add(v)
            return guards

        if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
            if isinstance(expr.operand, ast.Attribute) and expr.operand.attr == "netloc":
                guards["redirect"].update(_expr_names(expr.operand))
            return guards

        if isinstance(expr, ast.Call):
            cname = _dotted(expr.func)
            names = _expr_names(expr)
            if cname.endswith(".is_relative_to") or cname == "is_relative_to":
                guards["path"].update(names)
            elif cname.endswith(".startswith") or cname == "startswith":
                recv = expr.func.value if isinstance(expr.func, ast.Attribute) else None
                recv_name = recv.id if isinstance(recv, ast.Name) else None
                if expr.args and _has_trailing_path_separator(expr.args[0]):
                    if recv_name and recv_name in resolved_vars:
                        guards["path"].add(recv_name)
                    elif recv is not None and self._is_path_resolve_expr(recv):
                        guards["path"].update(_expr_names(recv))
            elif cname == "re.fullmatch":
                if len(expr.args) >= 2 and _is_safe_path_regex(expr.args[0], require_end_anchor=False):
                    guards["path"].update(_expr_names(expr.args[1]))
            elif cname == "re.match":
                if len(expr.args) >= 2 and _is_safe_path_regex(expr.args[0], require_end_anchor=True):
                    guards["path"].update(_expr_names(expr.args[1]))
            elif cname.endswith("_RE.fullmatch"):
                if expr.args:
                    guards["path"].update(_expr_names(expr.args[0]))
            elif cname in ("is_fetch_url_allowed", "validate_loopback_url", "is_safe_url"):
                guards["ssrf"].update(names)
                guards["redirect"].update(names)
        elif isinstance(expr, ast.Compare) and len(expr.ops) == 1:
            op = expr.ops[0]
            if (
                isinstance(op, ast.Eq)
                and isinstance(expr.left, ast.Call)
                and _dotted(expr.left.func) in ("os.path.commonpath", "commonpath")
            ):
                guards["path"].update(_expr_names(expr.left))
            elif isinstance(op, (ast.Eq, ast.In)):
                if _has_host_or_netloc_attr(expr):
                    names = _expr_names(expr)
                    is_empty_netloc = isinstance(op, ast.Eq) and any(
                        isinstance(c, ast.Constant) and c.value == "" for c in expr.comparators
                    )
                    if is_empty_netloc:
                        guards["redirect"].update(names)
                    else:
                        guards["ssrf"].update(names)
                        guards["redirect"].update(names)
        return guards

    def _extract_test_guards(
        self,
        test: ast.AST,
        resolved_vars: set[str],
    ) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
        """Return `(true_branch_guards, false_branch_guards)` for an `if <test>:` condition."""
        empty_true: dict[str, set[str]] = {k: set() for k in _SINK_KINDS}
        empty_false: dict[str, set[str]] = {k: set() for k in _SINK_KINDS}

        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return empty_true, self._extract_atomic_guards(test.operand, resolved_vars)

        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.NotIn)
        ):
            if _has_host_or_netloc_attr(test):
                names = _expr_names(test)
                empty_false["ssrf"].update(names)
                empty_false["redirect"].update(names)
                return empty_true, empty_false

        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
            slash_vars_false: set[str] = set()
            rejected_chars_false: dict[str, set[str]] = {}
            for val in test.values:
                if isinstance(val, ast.UnaryOp) and isinstance(val.op, ast.Not):
                    sub_g = self._extract_atomic_guards(val.operand, resolved_vars)
                    for k, vs in sub_g.items():
                        empty_false[k].update(vs)
                    rname, prefixes = _extract_startswith_info(val.operand)
                    if rname and "/" in prefixes:
                        slash_vars_false.add(rname)
                else:
                    if (
                        isinstance(val, ast.Compare)
                        and len(val.ops) == 1
                        and isinstance(val.ops[0], ast.NotIn)
                    ):
                        _, fg = self._extract_test_guards(val, resolved_vars)
                        for k, vs in fg.items():
                            empty_false[k].update(vs)
                    elif isinstance(val, ast.Attribute) and val.attr == "netloc":
                        empty_false["redirect"].update(_expr_names(val))
                    for vname in _expr_names(val):
                        rej = _rejected_second_chars_for_var(val, vname, negated=True)
                        if rej:
                            rejected_chars_false.setdefault(vname, set()).update(rej)
            for v in slash_vars_false:
                if {"/", "\\"}.issubset(rejected_chars_false.get(v, set())):
                    empty_false["redirect"].add(v)
            return empty_true, empty_false

        return self._extract_atomic_guards(test, resolved_vars), empty_false

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


def _js_unwrap_parens(node: Any) -> Any:
    while node is not None and node.type == "parenthesized_expression" and node.named_children:
        node = node.named_children[0]
    return node


def _js_unquote_string(node: Any, raw: bytes) -> str | None:
    if node is None:
        return None
    if node.type == "string":
        txt = node_text(node, raw).strip()
        if len(txt) >= 2 and txt[0] == txt[-1] and txt[0] in ("'", '"'):
            inner = txt[1:-1]
            # Decode common JS string escapes (`\\` -> `\`)
            return inner.replace("\\\\", "\\")
    return None


def _js_is_path_resolve_node(node: Any, raw: bytes) -> bool:
    for sub in walk_nodes(node):
        if sub.type == "call_expression":
            fn = sub.child_by_field_name("function")
            if fn and node_text(fn, raw) in ("path.resolve", "fs.realpathSync", "realpathSync", "resolve"):
                return True
    return False


def _js_arg_has_path_separator(arg_node: Any, raw: bytes) -> bool:
    """Return True iff the Tree-sitter AST arg enforces a non-trivial trailing path separator."""
    arg_node = _js_unwrap_parens(arg_node)
    if arg_node is None:
        return False
    sval = _js_unquote_string(arg_node, raw)
    if sval is not None:
        return len(sval) > 1 and sval.endswith(("/", "\\"))
    if arg_node.type == "binary_expression":
        op = arg_node.child_by_field_name("operator")
        right = arg_node.child_by_field_name("right")
        if op and node_text(op, raw) == "+" and right is not None:
            rtxt = node_text(right, raw).strip()
            rsval = _js_unquote_string(right, raw)
            return rtxt in ("path.sep", "sep") or rsval in ("/", "\\")
    if arg_node.type == "template_string":
        txt = node_text(arg_node, raw)
        return txt.endswith(("/`", "\\`", "${path.sep}`")) and len(txt) > 3
    return False


def _js_call_parts(node: Any, raw: bytes) -> tuple[Any | None, str, list[Any]]:
    """For a Tree-sitter `call_expression`, return `(receiver_node, method_or_fn_name, arg_nodes)`."""
    node = _js_unwrap_parens(node)
    if node is None or node.type != "call_expression":
        return None, "", []
    fn = node.child_by_field_name("function")
    args = node.child_by_field_name("arguments")
    arg_nodes = list(args.named_children) if args else []
    if fn is None:
        return None, "", arg_nodes
    if fn.type == "member_expression":
        obj = fn.child_by_field_name("object")
        prop = fn.child_by_field_name("property")
        return obj, node_text(prop, raw) if prop else "", arg_nodes
    return None, node_text(fn, raw), arg_nodes


def _js_flatten_logical(node: Any, raw: bytes, op_tok: str) -> list[Any]:
    node = _js_unwrap_parens(node)
    if node is not None and node.type == "binary_expression":
        op = node.child_by_field_name("operator")
        if op and node_text(op, raw) == op_tok:
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            return _js_flatten_logical(left, raw, op_tok) + _js_flatten_logical(right, raw, op_tok)
    return [node] if node is not None else []


def _js_is_negation(node: Any, raw: bytes) -> Any | None:
    node = _js_unwrap_parens(node)
    if node is not None and node.type == "unary_expression":
        op = node.child_by_field_name("operator")
        arg = node.child_by_field_name("argument")
        if op and node_text(op, raw) == "!" and arg is not None:
            return _js_unwrap_parens(arg)
    return None


def _js_rejected_second_chars(node: Any, raw: bytes, var_name: str, *, negated: bool = False) -> set[str]:
    """Extract characters guaranteed NOT at `var_name[1]` from a Tree-sitter condition node."""
    node = _js_unwrap_parens(node)
    rejected: set[str] = set()
    if node is None:
        return rejected

    # `!u.startsWith('//')` (negated=False) or `u.startsWith('//')` (negated=True)
    inner = _js_is_negation(node, raw) if not negated else node
    if inner is not None:
        recv, mname, args = _js_call_parts(inner, raw)
        if mname == "startsWith" and recv is not None and node_text(recv, raw) == var_name and args:
            sval = _js_unquote_string(args[0], raw)
            if sval == "//":
                rejected.add("/")
            elif sval == "/\\":
                rejected.add("\\")

    # `u[1] !== '/'` / `u[1] !== '\\'` (negated=False) or `u[1] === '/'` (negated=True)
    if node.type == "binary_expression":
        op = node.child_by_field_name("operator")
        left = _js_unwrap_parens(node.child_by_field_name("left"))
        right = _js_unwrap_parens(node.child_by_field_name("right"))
        op_txt = node_text(op, raw) if op else ""
        if left is not None and left.type == "subscript_expression" and right is not None:
            obj = left.child_by_field_name("object")
            idx = left.child_by_field_name("index")
            if obj and node_text(obj, raw) == var_name and idx and node_text(idx, raw).strip() == "1":
                sval = _js_unquote_string(right, raw)
                if sval in ("/", "\\") and (
                    (not negated and op_txt in ("!==", "!="))
                    or (negated and op_txt in ("===", "=="))
                ):
                    rejected.add(sval)

    return rejected


def _js_block_exits(stmt_node: Any, raw: bytes) -> bool:
    if stmt_node is None:
        return False
    if stmt_node.type in ("return_statement", "throw_statement"):
        return True
    if stmt_node.type == "statement_block" and stmt_node.named_children:
        last = stmt_node.named_children[-1]
        if last.type in ("return_statement", "throw_statement"):
            return True
    return False


class JsTaintTracker:
    """Tree-sitter AST-walking intra-procedural taint tracker for JS/TS scopes."""

    def __init__(self, scope_node: Any, raw: bytes) -> None:
        self.scope_node = scope_node
        self.raw = raw
        self.tainted: dict[str, str] = {}
        self.sanitized: dict[str, set[str]] = {k: set() for k in _SINK_KINDS}
        self._resolved_vars: set[str] = set()
        self._guard_ranges: list[tuple[int, int, str, set[str]]] = []
        self._analyze()

    def _extract_js_atomic_guards(self, cond_node: Any) -> dict[str, set[str]]:
        """Extract sink barriers implied when `cond_node` evaluates to True (Tree-sitter AST)."""
        guards: dict[str, set[str]] = {k: set() for k in _SINK_KINDS}
        cond_node = _js_unwrap_parens(cond_node)
        if cond_node is None:
            return guards

        conjuncts = _js_flatten_logical(cond_node, self.raw, "&&")
        if len(conjuncts) > 1:
            slash_vars: set[str] = set()
            for part in conjuncts:
                sub_g = self._extract_js_atomic_guards(part)
                for k, vs in sub_g.items():
                    guards[k].update(vs)
                recv, mname, args = _js_call_parts(part, self.raw)
                if mname == "startsWith" and recv is not None and recv.type == "identifier" and args:
                    if _js_unquote_string(args[0], self.raw) == "/":
                        slash_vars.add(node_text(recv, self.raw))
            for v in slash_vars:
                rej: set[str] = set()
                for part in conjuncts:
                    rej.update(_js_rejected_second_chars(part, self.raw, v, negated=False))
                if {"/", "\\"}.issubset(rej):
                    guards["redirect"].add(v)
            return guards

        # Single atomic predicate:
        # 1. Path guard: `<resolved_var>.startsWith(base + path.sep)` (ONLY if receiver is resolved!)
        recv, mname, args = _js_call_parts(cond_node, self.raw)
        if mname == "startsWith" and recv is not None and args:
            if _js_arg_has_path_separator(args[0], self.raw):
                if recv.type == "identifier":
                    rname = node_text(recv, self.raw)
                    if rname in self._resolved_vars:
                        guards["path"].add(rname)
                elif _js_is_path_resolve_node(recv, self.raw):
                    guards["path"].update(_JS_IDENT_RE.findall(node_text(recv, self.raw)))

        # 2. SSRF / Redirect allowlist calls: `allowedHosts.includes(host)`, `allowedOrigins.has(o)`, `isAllowedUrl(u)`
        if mname in ("includes", "has") and recv is not None and args:
            rtxt = node_text(recv, self.raw)
            if any(tok in rtxt for tok in ("allowedHosts", "allowedOrigins", "ALLOWED_HOSTS", "ALLOWLIST")):
                arg_idents = set(_JS_IDENT_RE.findall(node_text(args[0], self.raw)))
                guards["ssrf"].update(arg_idents)
                guards["redirect"].update(arg_idents)
        elif mname in ("isAllowedUrl", "isSafeUrl", "isSafeRedirect") and args:
            arg_idents = set(_JS_IDENT_RE.findall(node_text(args[0], self.raw)))
            guards["ssrf"].update(arg_idents)
            guards["redirect"].update(arg_idents)

        # 3. Positive equality on parsed URL origin/hostname (`parsed.origin === ...` / `parsed.hostname === ...`)
        if cond_node.type == "binary_expression":
            op = cond_node.child_by_field_name("operator")
            left = cond_node.child_by_field_name("left")
            right = cond_node.child_by_field_name("right")
            if op and node_text(op, self.raw) in ("===", "==") and left is not None and right is not None:
                ltxt = node_text(left, self.raw)
                rtxt = node_text(right, self.raw)
                if any(tok in ltxt or tok in rtxt for tok in (".origin", ".hostname", ".host")):
                    idents = set(_JS_IDENT_RE.findall(ltxt)) | set(_JS_IDENT_RE.findall(rtxt))
                    guards["ssrf"].update(idents)
                    guards["redirect"].update(idents)

        return guards

    def _extract_js_if_guards(
        self, cond_node: Any
    ) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
        """Return `(true_branch_guards, false_branch_guards)` by walking Tree-sitter AST."""
        empty_true: dict[str, set[str]] = {k: set() for k in _SINK_KINDS}
        empty_false: dict[str, set[str]] = {k: set() for k in _SINK_KINDS}
        cond_node = _js_unwrap_parens(cond_node)
        if cond_node is None:
            return empty_true, empty_false

        neg_inner = _js_is_negation(cond_node, self.raw)
        if neg_inner is not None:
            return empty_true, self._extract_js_atomic_guards(neg_inner)

        disjuncts = _js_flatten_logical(cond_node, self.raw, "||")
        if len(disjuncts) > 1:
            # In `if (!A || !B || u.startsWith('//') || u.startsWith('/\\')) return;`,
            # the FALSE branch (after early exit) guarantees A && B && !startsWith('//') && !startsWith('/\\')!
            slash_vars_false: set[str] = set()
            rejected_false: dict[str, set[str]] = {}
            for part in disjuncts:
                inner = _js_is_negation(part, self.raw)
                if inner is not None:
                    sub_g = self._extract_js_atomic_guards(inner)
                    for k, vs in sub_g.items():
                        empty_false[k].update(vs)
                    recv, mname, args = _js_call_parts(inner, self.raw)
                    if mname == "startsWith" and recv is not None and recv.type == "identifier" and args:
                        if _js_unquote_string(args[0], self.raw) == "/":
                            slash_vars_false.add(node_text(recv, self.raw))
                else:
                    for vname in _JS_IDENT_RE.findall(node_text(part, self.raw)):
                        rej = _js_rejected_second_chars(part, self.raw, vname, negated=True)
                        if rej:
                            rejected_false.setdefault(vname, set()).update(rej)
            for v in slash_vars_false:
                if {"/", "\\"}.issubset(rejected_false.get(v, set())):
                    empty_false["redirect"].add(v)
            # Positive `||` branch cannot guarantee either disjunct -> true_g stays EMPTY!
            return empty_true, empty_false

        return self._extract_js_atomic_guards(cond_node), empty_false

    def _analyze(self) -> None:
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
                alt = node.child_by_field_name("alternative")
                if not cond or not cons:
                    continue
                true_g, false_g = self._extract_js_if_guards(cond)
                for kind, idents in true_g.items():
                    if idents:
                        self._guard_ranges.append((cons.start_byte, cons.end_byte, kind, idents))
                if alt is not None:
                    for kind, idents in false_g.items():
                        if idents:
                            self._guard_ranges.append((alt.start_byte, alt.end_byte, kind, idents))
                if _js_block_exits(cons, self.raw) and node.parent is not None:
                    for kind, idents in false_g.items():
                        if idents:
                            self._guard_ranges.append((cons.end_byte, node.parent.end_byte, kind, idents))

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
        is_resolved = _js_is_path_resolve_node(val_n, self.raw)

        if name_n.type == "identifier":
            var = node_text(name_n, self.raw)
            for svars in self.sanitized.values():
                svars.discard(var)
            self._resolved_vars.discard(var)
            if is_resolved:
                self._resolved_vars.add(var)
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
                    self._resolved_vars.discard(v)
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
