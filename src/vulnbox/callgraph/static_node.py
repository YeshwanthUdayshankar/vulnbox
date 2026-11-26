"""Cross-file JavaScript/TypeScript Tree-sitter call graph builder."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vulnbox.analyzers.base import iter_source_files
from vulnbox.callgraph.graph import CallGraph
from vulnbox.callgraph.ts_utils import node_text, parse_source, walk_nodes
from vulnbox.models import CallEdge, CallNode, CallNodeLanguage, UnresolvedCallSite

JS_EXTS = (".js", ".mjs", ".cjs", ".ts", ".tsx")
ROUTE_METHODS = frozenset({"get", "post", "put", "delete", "patch", "all", "use"})
ROUTE_LITERAL_RE = re.compile(r"""['"](/[A-Za-z0-9_./:-]*)['"]""")


def _resolve_relative_js_module(workspace_dir: Path, cur_file: Path, spec: str) -> str | None:
    if not spec.startswith("."):
        return None
    base = (cur_file.parent / spec).resolve()
    candidates = [base]
    for ext in JS_EXTS:
        candidates.append(base.with_suffix(ext))
        candidates.append(base / f"index{ext}")
    for cand in candidates:
        if cand.is_file():
            try:
                return str(cand.relative_to(workspace_dir))
            except ValueError:
                return None
    return None


def _strip_quotes(text: str) -> str:
    s = text.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"', "`"):
        return s[1:-1]
    return s


def build_node_static_call_graph(workspace_dir: Path) -> CallGraph:
    """Build a cross-file JS/TS call graph using Tree-sitter CSTs."""
    cg = CallGraph()
    js_files = list(iter_source_files(workspace_dir, JS_EXTS))

    parsed: list[tuple[Path, str, CallNodeLanguage, Any, bytes]] = []
    file_symbols: dict[str, dict[str, str]] = {}

    # Pass 1: parse files and index functions/methods/handlers
    for js_file in js_files:
        try:
            src = js_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        tree, raw = parse_source(src, js_file.suffix)
        if tree is None:
            continue
        rel = str(js_file.relative_to(workspace_dir))
        lang: CallNodeLanguage = "typescript" if js_file.suffix in (".ts", ".tsx") else "javascript"
        parsed.append((js_file, rel, lang, tree, raw))

        cg.add_node(CallNode(node_id=f"{rel}::<module>", file_path=rel, symbol="<module>", line=1, language=lang))
        syms: dict[str, str] = {}

        for node in walk_nodes(tree.root_node):
            if node.type == "function_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    fname = node_text(name_node, raw)
                    nid = f"{rel}::{fname}"
                    cg.add_node(
                        CallNode(
                            node_id=nid,
                            file_path=rel,
                            symbol=fname,
                            line=node.start_point[0] + 1,
                            language=lang,
                        )
                    )
                    syms[fname] = nid
            elif node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                val_node = node.child_by_field_name("value")
                if name_node and val_node and val_node.type in ("arrow_function", "function_expression"):
                    fname = node_text(name_node, raw)
                    nid = f"{rel}::{fname}"
                    cg.add_node(
                        CallNode(
                            node_id=nid,
                            file_path=rel,
                            symbol=fname,
                            line=node.start_point[0] + 1,
                            language=lang,
                        )
                    )
                    syms[fname] = nid
            elif node.type == "method_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    mname = node_text(name_node, raw)
                    nid = f"{rel}::{mname}"
                    cg.add_node(
                        CallNode(
                            node_id=nid,
                            file_path=rel,
                            symbol=mname,
                            line=node.start_point[0] + 1,
                            language=lang,
                        )
                    )
                    syms[mname] = nid

        file_symbols[rel] = syms

    # Pass 2: resolve imports, routes, calls, and unresolved dynamic sites
    for js_file, rel, lang, tree, raw in parsed:
        # local_name -> (target_rel_or_None, external_or_symbol)
        imports: dict[str, tuple[str | None, str]] = {}

        for node in walk_nodes(tree.root_node):
            # ES imports: import x from './foo'; import { a as b } from 'pkg'
            if node.type == "import_statement":
                src_node = node.child_by_field_name("source")
                if not src_node:
                    continue
                mod_spec = _strip_quotes(node_text(src_node, raw))
                t_rel = _resolve_relative_js_module(workspace_dir, js_file, mod_spec)
                for sub in walk_nodes(node):
                    if sub.type == "import_specifier":
                        orig = sub.child_by_field_name("name")
                        alias = sub.child_by_field_name("alias")
                        if orig:
                            orig_name = node_text(orig, raw)
                            local_name = node_text(alias, raw) if alias else orig_name
                            imports[local_name] = (t_rel, orig_name if t_rel else f"{mod_spec}.{orig_name}")
                    elif sub.type == "identifier" and sub.parent and sub.parent.type in ("import_clause", "namespace_import"):
                        local_name = node_text(sub, raw)
                        imports[local_name] = (t_rel, local_name if t_rel else mod_spec)

            # CommonJS require: const x = require('pkg')
            elif node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                val_node = node.child_by_field_name("value")
                if name_node and val_node and val_node.type == "call_expression":
                    fn = val_node.child_by_field_name("function")
                    args = val_node.child_by_field_name("arguments")
                    if fn and node_text(fn, raw) == "require" and args and args.named_children:
                        mod_spec = _strip_quotes(node_text(args.named_children[0], raw))
                        t_rel = _resolve_relative_js_module(workspace_dir, js_file, mod_spec)
                        if name_node.type == "identifier":
                            lname = node_text(name_node, raw)
                            imports[lname] = (t_rel, lname if t_rel else mod_spec)
                        elif name_node.type == "object_pattern":
                            for sub in walk_nodes(name_node):
                                if sub.type == "shorthand_property_identifier_pattern":
                                    lname = node_text(sub, raw)
                                    imports[lname] = (t_rel, lname if t_rel else f"{mod_spec}.{lname}")

        def _enclosing_caller(node, _rel: str = rel, _raw: bytes = raw) -> str:
            curr = node.parent
            while curr is not None:
                if curr.type == "function_declaration":
                    nn = curr.child_by_field_name("name")
                    if nn:
                        return f"{_rel}::{node_text(nn, _raw)}"
                elif curr.type == "method_definition":
                    nn = curr.child_by_field_name("name")
                    if nn:
                        return f"{_rel}::{node_text(nn, _raw)}"
                elif curr.type == "variable_declarator":
                    nn = curr.child_by_field_name("name")
                    vn = curr.child_by_field_name("value")
                    if nn and vn and vn.type in ("arrow_function", "function_expression"):
                        return f"{_rel}::{node_text(nn, _raw)}"
                curr = curr.parent
            return f"{_rel}::<module>"

        def _resolve_js_target(
            expr: str,
            _rel: str = rel,
            _imports: dict[str, tuple[str | None, str]] = imports,
        ) -> str | None:
            local_syms = file_symbols.get(_rel, {})
            if expr in local_syms:
                return local_syms[expr]
            head, *rest = expr.split(".")
            if head in _imports:
                t_rel, t_sym = _imports[head]
                if t_rel is not None:
                    t_syms = file_symbols.get(t_rel, {})
                    if rest and rest[-1] in t_syms:
                        return t_syms[rest[-1]]
                    if t_sym in t_syms:
                        return t_syms[t_sym]
                    return f"{t_rel}::{rest[-1] if rest else t_sym}"
                ext_sym = ".".join([t_sym, *rest]) if rest else t_sym
                return f"external::{ext_sym}"
            return None

        for node in walk_nodes(tree.root_node):
            if node.type != "call_expression":
                continue
            fn_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if fn_node is None:
                continue
            lineno = node.start_point[0] + 1
            caller = _enclosing_caller(node)
            fn_txt = node_text(fn_node, raw)

            # Computed dynamic dispatch: handlers[action](...)
            if fn_node.type == "subscript_expression":
                cg.add_unresolved(
                    UnresolvedCallSite(
                        caller=caller,
                        file_path=rel,
                        line=lineno,
                        expression=node_text(node, raw)[:120],
                        reason="subscript_dispatch",
                    )
                )
                continue

            if fn_txt in ("eval", "Function") or fn_node.type == "import":
                cg.add_unresolved(
                    UnresolvedCallSite(
                        caller=caller,
                        file_path=rel,
                        line=lineno,
                        expression=node_text(node, raw)[:120],
                        reason="dynamic_eval_or_import",
                    )
                )
                continue

            # Detect http.createServer((req, res) => { ... }) and route branches inside
            if fn_txt.endswith(".createServer") and args_node and args_node.named_children:
                cb = args_node.named_children[0]
                cb_text = node_text(cb, raw)
                for m in ROUTE_LITERAL_RE.finditer(cb_text):
                    rpath = m.group(1)
                    if rpath == "/health":
                        continue
                    route_nid = f"{rel}::route:{rpath}"
                    cg.add_node(
                        CallNode(
                            node_id=route_nid,
                            file_path=rel,
                            symbol=f"route:{rpath}",
                            line=cb.start_point[0] + 1,
                            language=lang,
                            is_entrypoint=True,
                            route=rpath,
                        )
                    )
                    cg.add_edge(
                        CallEdge(
                            caller=caller,
                            callee=route_nid,
                            file_path=rel,
                            line=lineno,
                            provenance="framework_introspected",
                        )
                    )
                # Also map calls inside `if (pathname === "/x") { fn() }` to the route node
                for sub in walk_nodes(cb):
                    if sub.type == "if_statement":
                        cond = sub.child_by_field_name("condition")
                        conseq = sub.child_by_field_name("consequence")
                        if cond and conseq:
                            rm = ROUTE_LITERAL_RE.search(node_text(cond, raw))
                            if rm and rm.group(1) != "/health":
                                r_nid = f"{rel}::route:{rm.group(1)}"
                                for inner in walk_nodes(conseq):
                                    if inner.type == "call_expression":
                                        ifn = inner.child_by_field_name("function")
                                        if ifn:
                                            rt = _resolve_js_target(node_text(ifn, raw))
                                            if rt:
                                                cg.add_edge(
                                                    CallEdge(
                                                        caller=r_nid,
                                                        callee=rt,
                                                        file_path=rel,
                                                        line=inner.start_point[0] + 1,
                                                        provenance="static_exact",
                                                    )
                                                )

            # Detect Express/Fastify routes: app.get('/path', handler)
            if fn_node.type == "member_expression" and args_node and args_node.named_children:
                prop = fn_node.child_by_field_name("property")
                method = node_text(prop, raw) if prop else ""
                if method in ROUTE_METHODS:
                    first_arg = args_node.named_children[0]
                    first_txt = node_text(first_arg, raw)
                    if first_arg.type == "string":
                        rpath = _strip_quotes(first_txt)
                        route_nid = f"{rel}::route:{rpath}"
                        cg.add_node(
                            CallNode(
                                node_id=route_nid,
                                file_path=rel,
                                symbol=f"route:{rpath}",
                                line=lineno,
                                language=lang,
                                is_entrypoint=True,
                                route=rpath,
                            )
                        )
                        for handler_arg in args_node.named_children[1:]:
                            if handler_arg.type == "identifier":
                                ht = _resolve_js_target(node_text(handler_arg, raw))
                                if ht:
                                    cg.add_edge(
                                        CallEdge(
                                            caller=route_nid,
                                            callee=ht,
                                            file_path=rel,
                                            line=lineno,
                                            provenance="framework_introspected",
                                        )
                                    )

            resolved = _resolve_js_target(fn_txt)
            if resolved and resolved != caller:
                cg.add_edge(
                    CallEdge(
                        caller=caller,
                        callee=resolved,
                        file_path=rel,
                        line=lineno,
                        provenance="static_exact",
                    )
                )

    return cg
