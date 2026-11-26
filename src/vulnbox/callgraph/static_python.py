"""Cross-file Python AST call graph builder with FastAPI/Flask/stdlib HTTP route & DI extraction."""

from __future__ import annotations

import ast
from pathlib import Path

from vulnbox.analyzers.base import iter_source_files
from vulnbox.callgraph.graph import CallGraph
from vulnbox.models import CallEdge, CallNode, UnresolvedCallSite

ROUTE_DECORATOR_METHODS = frozenset({"get", "post", "put", "delete", "patch", "route", "api_route"})


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _extract_decorator_route(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for dec in func.decorator_list:
        if isinstance(dec, ast.Call):
            dname = _dotted(dec.func)
            method = dname.rsplit(".", 1)[-1] if dname else ""
            if method in ROUTE_DECORATOR_METHODS:
                if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                    return dec.args[0].value
                return "/"
    return None


def _extract_handler_routes(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Extract literal HTTP route paths checked inside BaseHTTPRequestHandler.do_GET/do_POST."""
    if func.name not in ("do_GET", "do_POST", "do_PUT", "do_DELETE"):
        return []
    routes: list[str] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Compare):
            for comp in [node.left, *node.comparators]:
                if (
                    isinstance(comp, ast.Constant)
                    and isinstance(comp.value, str)
                    and comp.value.startswith("/")
                    and comp.value != "/health"
                ):
                    if comp.value not in routes:
                        routes.append(comp.value)
    return routes


def _extract_depends_targets(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[str, int]]:
    """Extract FastAPI `Depends(fn)` dependency provider references."""
    deps: list[tuple[str, int]] = []
    all_defaults = list(func.args.defaults) + [d for d in func.args.kw_defaults if d is not None]
    for default in all_defaults:
        if isinstance(default, ast.Call):
            cname = _dotted(default.func)
            if cname == "Depends" or cname.endswith(".Depends"):
                if default.args:
                    dep_name = _dotted(default.args[0])
                    if dep_name:
                        deps.append((dep_name, getattr(default, "lineno", func.lineno)))
    return deps


def _module_name_for_rel(rel: str) -> str:
    p = Path(rel)
    parts = list(p.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def build_python_static_call_graph(workspace_dir: Path) -> CallGraph:
    """Build a cross-file Python call graph and record unresolved dynamic call sites."""
    cg = CallGraph()
    py_files = list(iter_source_files(workspace_dir, (".py",)))

    # Pass 1: parse all files and index modules, functions, classes, methods
    parsed: list[tuple[str, ast.Module]] = []
    module_to_rel: dict[str, str] = {}
    file_symbols: dict[str, dict[str, str]] = {}  # rel -> {symbol: node_id}
    class_methods: dict[tuple[str, str], dict[str, str]] = {}  # (rel, cls) -> {method: node_id}
    class_bases: dict[tuple[str, str], list[str]] = {}

    for py_file in py_files:
        try:
            src = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(src)
        except (OSError, SyntaxError):
            continue
        rel = str(py_file.relative_to(workspace_dir))
        parsed.append((rel, tree))
        mod_name = _module_name_for_rel(rel)
        if mod_name:
            module_to_rel[mod_name] = rel
            # Also support short suffix matching (e.g., src.pkg.mod -> pkg.mod)
            parts = mod_name.split(".")
            if len(parts) >= 2 and parts[0] == "src":
                module_to_rel[".".join(parts[1:])] = rel

        mod_node_id = f"{rel}::<module>"
        cg.add_node(CallNode(node_id=mod_node_id, file_path=rel, symbol="<module>", line=1, language="python"))
        syms: dict[str, str] = {}

        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nid = f"{rel}::{stmt.name}"
                route = _extract_decorator_route(stmt)
                is_entry = route is not None or stmt.name == "main"
                cg.add_node(
                    CallNode(
                        node_id=nid,
                        file_path=rel,
                        symbol=stmt.name,
                        line=stmt.lineno,
                        language="python",
                        is_entrypoint=is_entry,
                        route=route,
                    )
                )
                syms[stmt.name] = nid
            elif isinstance(stmt, ast.ClassDef):
                bases = [_dotted(b) for b in stmt.bases if _dotted(b)]
                class_bases[(rel, stmt.name)] = bases
                methods: dict[str, str] = {}
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qsym = f"{stmt.name}.{item.name}"
                        nid = f"{rel}::{qsym}"
                        route = _extract_decorator_route(item)
                        handler_routes = _extract_handler_routes(item)
                        eff_route = route or (handler_routes[0] if handler_routes else None)
                        is_entry = eff_route is not None or item.name in ("do_GET", "do_POST", "do_PUT", "do_DELETE")
                        cg.add_node(
                            CallNode(
                                node_id=nid,
                                file_path=rel,
                                symbol=qsym,
                                line=item.lineno,
                                language="python",
                                is_entrypoint=is_entry,
                                route=eff_route,
                            )
                        )
                        methods[item.name] = nid
                        syms[qsym] = nid
                class_methods[(rel, stmt.name)] = methods
                syms[stmt.name] = f"{rel}::{stmt.name}"

        file_symbols[rel] = syms

    # Pass 2: resolve imports and calls per file
    for rel, tree in parsed:
        # Build local import alias table: local_name -> (target_rel_or_None, external_or_symbol_name)
        imports: dict[str, tuple[str | None, str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    target_rel = module_to_rel.get(alias.name)
                    imports[local] = (target_rel, alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                target_rel = module_to_rel.get(node.module)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    if target_rel:
                        imports[local] = (target_rel, alias.name)
                    else:
                        imports[local] = (None, f"{node.module}.{alias.name}")

        def _resolve_target(
            name: str,
            cur_rel: str,
            cur_cls: str | None,
            _imports: dict[str, tuple[str | None, str]] = imports,
        ) -> str | None:
            if not name:
                return None
            # self.method
            if cur_cls and name.startswith("self."):
                mname = name.split(".", 1)[1]
                if "." not in mname:
                    m_map = class_methods.get((cur_rel, cur_cls), {})
                    if mname in m_map:
                        return m_map[mname]
                    for base in class_bases.get((cur_rel, cur_cls), ()):
                        bm = class_methods.get((cur_rel, base), {})
                        if mname in bm:
                            return bm[mname]
            # Local function/class in same file
            local_syms = file_symbols.get(cur_rel, {})
            if name in local_syms:
                return local_syms[name]
            # Direct import match
            head, *rest = name.split(".")
            if head in _imports:
                t_rel, t_sym = _imports[head]
                if t_rel is not None:
                    full_sym = ".".join([t_sym, *rest]) if rest else t_sym
                    t_syms = file_symbols.get(t_rel, {})
                    if full_sym in t_syms:
                        return t_syms[full_sym]
                    if rest and rest[-1] in t_syms:
                        return t_syms[rest[-1]]
                    return f"{t_rel}::{full_sym}"
                ext_sym = ".".join([t_sym, *rest]) if rest else t_sym
                return f"external::{ext_sym}"
            return None

        def _visit_scope(
            scope_node: ast.AST,
            caller_id: str,
            cur_rel: str,
            cur_cls: str | None,
            route_branches: dict[str, str] | None = None,
        ) -> None:
            # Track local variables assigned via `getattr(obj, expr)`
            getattr_vars: set[str] = set()
            for child in ast.walk(scope_node):
                if isinstance(child, ast.Assign) and isinstance(child.value, ast.Call):
                    if _dotted(child.value.func) == "getattr":
                        for tgt in child.targets:
                            if isinstance(tgt, ast.Name):
                                getattr_vars.add(tgt.id)

            # FastAPI Depends() edges
            if isinstance(scope_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dep_name, dep_line in _extract_depends_targets(scope_node):
                    resolved_dep = _resolve_target(dep_name, cur_rel, cur_cls)
                    if resolved_dep:
                        cg.add_edge(
                            CallEdge(
                                caller=caller_id,
                                callee=resolved_dep,
                                file_path=cur_rel,
                                line=dep_line,
                                provenance="framework_introspected",
                            )
                        )

            # Track per-route branch calls for BaseHTTPRequestHandler
            if route_branches and isinstance(scope_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for sub in ast.walk(scope_node):
                    if isinstance(sub, ast.If):
                        test_src = ast.unparse(sub.test) if hasattr(ast, "unparse") else ""
                        matched_route = next((r for r in route_branches if f'"{r}"' in test_src or f"'{r}'" in test_src), None)
                        if matched_route:
                            route_nid = f"{cur_rel}::route:{matched_route}"
                            cg.add_node(
                                CallNode(
                                    node_id=route_nid,
                                    file_path=cur_rel,
                                    symbol=f"route:{matched_route}",
                                    line=sub.lineno,
                                    language="python",
                                    is_entrypoint=True,
                                    route=matched_route,
                                )
                            )
                            cg.add_edge(
                                CallEdge(
                                    caller=caller_id,
                                    callee=route_nid,
                                    file_path=cur_rel,
                                    line=sub.lineno,
                                    provenance="framework_introspected",
                                )
                            )
                            for bcall in ast.walk(ast.Module(body=sub.body, type_ignores=[])):
                                if isinstance(bcall, ast.Call):
                                    cname = _dotted(bcall.func)
                                    rt = _resolve_target(cname, cur_rel, cur_cls)
                                    if rt:
                                        cg.add_edge(
                                            CallEdge(
                                                caller=route_nid,
                                                callee=rt,
                                                file_path=cur_rel,
                                                line=getattr(bcall, "lineno", sub.lineno),
                                                provenance="static_exact",
                                            )
                                        )

            for child in ast.walk(scope_node):
                if not isinstance(child, ast.Call):
                    continue
                lineno = getattr(child, "lineno", 1)
                func_expr = child.func

                # Detect dynamic getattr() calls: getattr(obj, expr)(...) or fn = getattr(...); fn(...)
                if isinstance(func_expr, ast.Call) and _dotted(func_expr.func) == "getattr":
                    cg.add_unresolved(
                        UnresolvedCallSite(
                            caller=caller_id,
                            file_path=cur_rel,
                            line=lineno,
                            expression=ast.unparse(child)[:120],
                            reason="dynamic_getattr",
                        )
                    )
                    continue
                if isinstance(func_expr, ast.Name) and func_expr.id in getattr_vars:
                    cg.add_unresolved(
                        UnresolvedCallSite(
                            caller=caller_id,
                            file_path=cur_rel,
                            line=lineno,
                            expression=ast.unparse(child)[:120],
                            reason="dynamic_getattr",
                        )
                    )
                    continue
                # Detect subscript dispatch: handlers[action](...) or globals()[name](...)
                if isinstance(func_expr, ast.Subscript):
                    cg.add_unresolved(
                        UnresolvedCallSite(
                            caller=caller_id,
                            file_path=cur_rel,
                            line=lineno,
                            expression=ast.unparse(child)[:120],
                            reason="subscript_dispatch",
                        )
                    )
                    continue

                cname = _dotted(func_expr)
                if cname in ("importlib.import_module", "__import__"):
                    cg.add_unresolved(
                        UnresolvedCallSite(
                            caller=caller_id,
                            file_path=cur_rel,
                            line=lineno,
                            expression=ast.unparse(child)[:120],
                            reason="dynamic_import",
                        )
                    )
                    continue

                resolved = _resolve_target(cname, cur_rel, cur_cls)
                if resolved and resolved != caller_id:
                    cg.add_edge(
                        CallEdge(
                            caller=caller_id,
                            callee=resolved,
                            file_path=cur_rel,
                            line=lineno,
                            provenance="static_exact",
                        )
                    )

        # Walk top-level statements, functions, and class methods
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _visit_scope(stmt, f"{rel}::{stmt.name}", rel, None)
            elif isinstance(stmt, ast.ClassDef):
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        routes = _extract_handler_routes(item)
                        rb = {r: r for r in routes} if routes else None
                        _visit_scope(item, f"{rel}::{stmt.name}.{item.name}", rel, stmt.name, rb)
            else:
                _visit_scope(stmt, f"{rel}::<module>", rel, None)

    return cg
